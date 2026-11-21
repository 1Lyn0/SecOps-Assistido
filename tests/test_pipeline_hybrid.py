"""Testes automatizados para o pipeline híbrido de detecção e consolidação (MAO-14).

Critérios de Aceitação:
- Execução de ponta a ponta: logs_simulados.jsonl -> LGMS -> Z-Score + Isolation Forest + CloudTrail Rules -> SQLite.
- Cálculo de severidade combinada e justificativa técnica estruturada de quais detectores dispararam.
- CLI / script de execução rápida funcional via python -m secops_core.pipeline.
"""

from pathlib import Path
import subprocess
import sys
import pandas as pd
import pytest
from secops_core.config import settings
from secops_core.db import get_anomalies, get_processed_logs, init_db
from secops_core.detectors.base import AnomalyResult
from secops_core.detectors.engine import DetectionEngine
from secops_core.generator import generate_simulated_logs
from secops_core.pipeline import run_pipeline


@pytest.fixture
def hybrid_dataset_path(tmp_path: Path):
    """Gera um arquivo JSONL de logs simulados para teste do pipeline."""
    log_file = tmp_path / "hybrid_logs.jsonl"
    generate_simulated_logs(count=120, anomaly_rate=0.25, seed=42, output_path=str(log_file))
    return str(log_file)


def test_pipeline_end_to_end_execution(hybrid_dataset_path, tmp_path: Path, monkeypatch):
    """Valida execução completa: logs_simulados.jsonl -> LGMS -> Detectores -> SQLite."""
    test_db = tmp_path / "hybrid_pipeline.db"
    monkeypatch.setattr(settings, "sqlite_db_path", str(test_db))

    res = run_pipeline(
        log_file=hybrid_dataset_path,
        save_to_db=True,
        explain_critical=False,
    )

    assert res["status"] == "success"
    assert res["total_logs"] >= 100
    assert res["valid_logs"] >= 100
    assert res["total_anomalies_detected"] > 0
    assert res["saved_to_db"] == res["total_anomalies_detected"]

    # Verifica se os dados foram gravados no SQLite
    db_anomalies = get_anomalies(db_path=str(test_db))
    assert len(db_anomalies) == res["total_anomalies_detected"]

    # Verifica se a tabela processed_logs contém todos os logs processados (120) e as anomalias filtradas
    db_processed = get_processed_logs(limit=200, db_path=str(test_db))
    assert len(db_processed) == res["valid_logs"]

    db_processed_anomalies = get_processed_logs(is_anomaly=True, limit=200, db_path=str(test_db))
    assert len(db_processed_anomalies) == res["total_anomalies_detected"]


def test_combined_severity_and_technical_justification():
    """Valida regra de consolidação de severidade e geração de justificativa técnica estruturada."""
    engine = DetectionEngine()

    # Cria baseline de eventos normais para que a distribuição tenha desvio padrão e amostras suficientes
    data = [
        {
            "event_id": f"baseline_norm_{i}",
            "timestamp": "2026-11-05T14:00:00Z",
            "event_name": "DescribeInstances",
            "event_source": "ec2.amazonaws.com",
            "user_name": "developer",
            "source_ip": "10.0.1.50",
            "hour": 14,
            "day_of_week": 2,
            "is_weekend": 0,
            "is_off_hours": 0,
            "is_login": 0,
            "is_iam": 0,
            "is_trail_mgmt": 0,
            "is_s3": 0,
            "is_error": 0,
            "is_suspicious_ip": 0,
            "request_count": 2.0,
            "bytes_transferred": 200.0,
            "log_bytes_transferred": 5.3,
            "ip_frequency": 20.0,
            "user_frequency": 20.0,
            "scenario": "normal",
        }
        for i in range(25)
    ]

    # Injeta evento composto (dispara ZScore + Rules)
    data.append({
        "event_id": "compound_critical_event",
        "timestamp": "2026-11-05T14:00:00Z",
        "event_name": "DeleteTrail",
        "event_source": "cloudtrail.amazonaws.com",
        "user_name": "root",
        "source_ip": "185.220.101.5",
        "hour": 14,
        "day_of_week": 2,
        "is_weekend": 0,
        "is_off_hours": 0,
        "is_login": 0,
        "is_iam": 0,
        "is_trail_mgmt": 1,
        "is_s3": 0,
        "is_error": 0,
        "is_suspicious_ip": 1,
        "request_count": 8000.0,  # Dispara ZScore (> 50x a média)
        "bytes_transferred": 500000000.0,
        "log_bytes_transferred": 20.0,
        "ip_frequency": 1.0,
        "user_frequency": 1.0,
        "scenario": "defense_evasion",
    })

    df_test = pd.DataFrame(data)

    consolidated = engine.run_and_consolidate(df_test)
    anom_ids = [c.event_id for c in consolidated]
    assert "compound_critical_event" in anom_ids

    anom = next(c for c in consolidated if c.event_id == "compound_critical_event")

    # Múltiplos detectores devem ter sido acionados (ZScore + Regras)
    assert len(anom.detectors_triggered) >= 2
    # Severidade deve ser CRITICAL
    assert anom.max_severity == "CRITICAL"
    # Justificativa técnica estruturada deve estar presente e detalhada
    assert anom.technical_justification is not None
    assert "Consolidação de evidências" in anom.technical_justification
    assert "DeleteTrail" in anom.technical_justification or "CloudTrail" in anom.technical_justification


def test_pipeline_cli_execution(hybrid_dataset_path, tmp_path: Path, monkeypatch):
    """Testa a execução rápida via CLI (python -m secops_core.pipeline)."""
    test_db = tmp_path / "cli_pipeline.db"
    env = {**subprocess.os.environ, "SQLITE_DB_PATH": str(test_db)}

    cmd = [
        sys.executable,
        "-m",
        "secops_core.pipeline",
        "--file",
        hybrid_dataset_path,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, env=env)
    assert result.returncode == 0
    assert "Pipeline concluído com sucesso" in result.stdout
    assert "Anomalias detectadas" in result.stdout
