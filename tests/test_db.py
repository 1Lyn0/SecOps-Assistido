"""Testes automatizados da camada de persistência SQLite e modelos de tabelas (MAO-9).

Valida:
1. Inicialização automática de schema, tabelas e índices (`timestamp`, `is_anomaly`, `final_severity`).
2. Performance de bulk insert e leitura filtrada (< 100ms para 5.000 registros).
3. Idempotência em reprocessamento de event_id (sem duplicação).
4. Consultas com filtros multidimensionais e paginação.
5. Atualização de laudos de IA (ai_explanation).
6. View security_alerts e compatibilidade com fluxo legado de anomalias.
"""

import time
from pathlib import Path
import pytest

from secops_core.config import settings
from secops_core.db import (
    ProcessedLogRecord,
    SecurityAlertRecord,
    bulk_insert,
    get_anomalies,
    get_connection,
    get_db_stats,
    get_processed_log_by_event_id,
    get_processed_logs,
    get_security_alerts,
    init_db,
    save_anomalies,
    update_ai_explanation,
)


def test_schema_initialization_tables_and_indices(tmp_path: Path, monkeypatch):
    """Critério 1: Inicialização automática do SQLite, tabelas e índices de busca."""
    test_db = tmp_path / "test_schema.db"
    monkeypatch.setattr(settings, "sqlite_db_path", str(test_db))

    init_db()

    conn = get_connection()
    cursor = conn.cursor()

    # Valida tabelas e view criadas
    cursor.execute("SELECT name, type FROM sqlite_master WHERE type IN ('table', 'view')")
    objects = {row["name"]: row["type"] for row in cursor.fetchall()}

    assert "processed_logs" in objects, "Tabela processed_logs não foi criada"
    assert "security_alerts" in objects, "View security_alerts não foi criada"
    assert "anomalies" in objects, "Tabela anomalies de compatibilidade não foi criada"

    # Valida existência dos índices obrigatórios
    cursor.execute("SELECT name FROM sqlite_master WHERE type = 'index'")
    indices = {row["name"] for row in cursor.fetchall()}

    assert "idx_processed_logs_timestamp" in indices, "Índice timestamp ausente"
    assert "idx_processed_logs_is_anomaly" in indices, "Índice is_anomaly ausente"
    assert "idx_processed_logs_final_severity" in indices, "Índice final_severity ausente"
    assert "idx_processed_logs_event_id" in indices, "Índice event_id ausente"

    conn.close()


def test_idempotence_and_no_duplicates(tmp_path: Path, monkeypatch):
    """Critério 3: Suporte a idempotência (evitar duplicação do mesmo event_id ao reprocessar)."""
    test_db = tmp_path / "test_idempotency.db"
    monkeypatch.setattr(settings, "sqlite_db_path", str(test_db))

    initial_record = {
        "event_id": "evt-idempotent-001",
        "timestamp": "2026-11-12T12:00:00Z",
        "event_name": "ConsoleLogin",
        "event_source": "signin.amazonaws.com",
        "user_name": "analyst_sec",
        "source_ip": "192.168.1.10",
        "status": "Success",
        "final_severity": "LOW",
        "is_anomaly": False,
        "ai_explanation": None,
    }

    # Primeira inserção
    bulk_insert([initial_record])
    log1 = get_processed_log_by_event_id("evt-idempotent-001")
    assert log1 is not None
    assert log1["final_severity"] == "LOW"
    assert log1["is_anomaly"] is False

    # Reprocessamento com alteração de severidade e inclusão de anomalia / laudo
    updated_record = {
        "event_id": "evt-idempotent-001",
        "timestamp": "2026-11-12T12:00:00Z",
        "event_name": "ConsoleLogin",
        "event_source": "signin.amazonaws.com",
        "user_name": "analyst_sec",
        "source_ip": "192.168.1.10",
        "status": "Success",
        "final_severity": "HIGH",
        "is_anomaly": True,
        "ai_explanation": "Acesso após horário comercial com escalonamento de privilégio.",
    }

    bulk_insert([updated_record])

    # Valida que não gerou duplicata no banco
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) AS total FROM processed_logs WHERE event_id = ?", ("evt-idempotent-001",))
    count = cursor.fetchone()["total"]
    conn.close()

    assert count == 1, f"Idempotência falhou: esperado 1 registro, encontrado {count}"

    # Valida que os dados foram atualizados corretamente
    log2 = get_processed_log_by_event_id("evt-idempotent-001")
    assert log2["final_severity"] == "HIGH"
    assert log2["is_anomaly"] is True
    assert log2["ai_explanation"] == "Acesso após horário comercial com escalonamento de privilégio."


def test_bulk_insert_and_filtered_read_performance_under_100ms(tmp_path: Path, monkeypatch):
    """Critério 2: Inserção em lote e leitura filtrada executando em menos de 100ms para 5.000 registros."""
    test_db = tmp_path / "test_perf.db"
    monkeypatch.setattr(settings, "sqlite_db_path", str(test_db))

    total_records = 5000
    mock_batch = []
    for i in range(total_records):
        is_anom = (i % 20 == 0)  # 5% de anomalias
        severity = "CRITICAL" if (i % 100 == 0) else ("HIGH" if is_anom else "LOW")
        mock_batch.append(
            {
                "event_id": f"perf-evt-{i:05d}",
                "timestamp": f"2026-11-12T{10 + (i % 12):02d}:{i % 60:02d}:00Z",
                "event_name": "AssumeRole" if is_anom else "DescribeInstances",
                "event_source": "sts.amazonaws.com" if is_anom else "ec2.amazonaws.com",
                "user_name": f"user_{i % 50}",
                "source_ip": f"10.0.{i % 255}.{(i * 7) % 255}",
                "status": "Failure" if is_anom else "Success",
                "request_count": 1 + (i % 10),
                "bytes_transferred": i * 15,
                "zscore_value": 3.8 if is_anom else 0.5,
                "is_zscore_anomaly": is_anom,
                "iforest_score": -0.35 if is_anom else 0.12,
                "is_iforest_anomaly": is_anom,
                "cloudtrail_rules_triggered": ["OffHoursPrivilegeEscalation"] if (i % 100 == 0) else [],
                "final_severity": severity,
                "is_anomaly": is_anom,
                "ai_explanation": None,
            }
        )

    # 1. Mede tempo de inserção em lote (bulk_insert)
    start_insert = time.perf_counter()
    inserted_count = bulk_insert(mock_batch)
    elapsed_insert = time.perf_counter() - start_insert

    assert inserted_count == total_records

    # 2. Mede tempo de leitura filtrada usando índices
    start_read = time.perf_counter()
    filtered_results = get_processed_logs(
        is_anomaly=True,
        final_severity="CRITICAL",
        limit=100,
    )
    elapsed_read = time.perf_counter() - start_read

    total_elapsed = elapsed_insert + elapsed_read

    # Validações dos dados retornados
    assert len(filtered_results) == 50  # 5000 / 100 = 50 registros CRITICAL
    assert all(r["is_anomaly"] is True for r in filtered_results)
    assert all(r["final_severity"] == "CRITICAL" for r in filtered_results)

    # Critério de Aceitação: < 100ms (0.10s)
    # Exibe métricas para transparência
    print(f"\n[BENCHMARK 5000 REGISTROS]")
    print(f"Tempo Bulk Insert:    {elapsed_insert * 1000:.2f} ms")
    print(f"Tempo Leitura Filtro: {elapsed_read * 1000:.2f} ms")
    print(f"Tempo Total:          {total_elapsed * 1000:.2f} ms (limite: 100 ms)")

    assert total_elapsed < 0.100, f"Tempo total ({total_elapsed * 1000:.2f}ms) excedeu o critério de 100ms"


def test_crud_models_and_filtered_queries(tmp_path: Path, monkeypatch):
    """Testa inserção com Pydantic models, paginação e filtros temporais."""
    test_db = tmp_path / "test_crud.db"
    monkeypatch.setattr(settings, "sqlite_db_path", str(test_db))

    records = [
        ProcessedLogRecord(
            event_id="model-001",
            timestamp="2026-11-12T08:00:00Z",
            event_name="CreateUser",
            user_name="admin",
            source_ip="1.2.3.4",
            final_severity="MEDIUM",
            is_anomaly=True,
            cloudtrail_rules_triggered=["IAMCreateUser"],
        ),
        ProcessedLogRecord(
            event_id="model-002",
            timestamp="2026-11-12T09:00:00Z",
            event_name="ListBuckets",
            user_name="readonly",
            source_ip="10.0.0.1",
            final_severity="LOW",
            is_anomaly=False,
        ),
    ]

    bulk_insert(records)

    # Teste de filtro por severidade
    meds = get_processed_logs(final_severity="MEDIUM")
    assert len(meds) == 1
    assert meds[0]["event_id"] == "model-001"
    assert meds[0]["cloudtrail_rules_triggered"] == ["IAMCreateUser"]

    # Teste de view security_alerts
    alerts = get_security_alerts()
    assert len(alerts) == 1
    assert alerts[0]["event_id"] == "model-001"
    assert alerts[0]["is_anomaly"] is True

    # Teste de atualização de IA
    updated = update_ai_explanation("model-001", "Laudo: criação anômala de usuário fora de horário.")
    assert updated is True

    item = get_processed_log_by_event_id("model-001")
    assert item["ai_explanation"] == "Laudo: criação anômala de usuário fora de horário."


def test_compatibility_with_save_anomalies_and_stats(tmp_path: Path, monkeypatch):
    """Testa compatibilidade com o fluxo existente de pipeline e get_db_stats."""
    test_db = tmp_path / "test_compat.db"
    monkeypatch.setattr(settings, "sqlite_db_path", str(test_db))

    class MockAnomalyResult:
        detector_name = "ZScore"
        anomaly_score = 4.2
        is_anomaly = True
        severity = "HIGH"
        scenario = "VolumetricAnomaly"

        def model_dump(self):
            return {"detector": "ZScore", "score": 4.2}

    class MockConsolidated:
        event_id = "anom-compat-001"
        timestamp = "2026-11-12T10:00:00Z"
        event_name = "DeleteBucket"
        user_name = "mallory"
        source_ip = "45.33.32.156"
        detectors_triggered = ["ZScore"]
        max_score = 4.2
        max_severity = "HIGH"
        scenario = "SuspiciousDeletion"
        explanation = "Laudo analítico inicial"
        detector_results = [MockAnomalyResult()]

    saved = save_anomalies([MockConsolidated()])
    assert saved == 1

    # Verifica na tabela anomalies
    legacy_list = get_anomalies(severity="HIGH")
    assert len(legacy_list) == 1
    assert legacy_list[0]["event_id"] == "anom-compat-001"

    # Verifica na tabela processed_logs sincronizada
    modern_item = get_processed_log_by_event_id("anom-compat-001")
    assert modern_item is not None
    assert modern_item["zscore_value"] == 4.2
    assert modern_item["is_zscore_anomaly"] is True
    assert modern_item["final_severity"] == "HIGH"
    assert modern_item["ai_explanation"] == "Laudo analítico inicial"

    # Verifica stats
    stats = get_db_stats()
    assert stats["total_anomalies"] == 1
    assert stats["total_processed_logs"] == 1
    assert stats["severity_distribution"]["HIGH"] == 1
