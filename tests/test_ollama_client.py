"""Testes unitários dedicados ao cliente Ollama local e fallback resiliente (MAO-17).

Critérios de Aceitação:
- Gera explicações reais via Ollama local quando o serviço está ativo e persiste no SQLite.
- Quando o Ollama está desligado ou inacessível, aciona automaticamente o fallback sem lançar exceção não tratada.
- Testes unitários com mock da resposta do Ollama e teste do modo fallback.
"""

from pathlib import Path
from unittest.mock import MagicMock, patch
import httpx
import pytest
from secops_core.db import get_anomaly_by_event_id, init_db, save_anomalies
from secops_core.detectors.base import AnomalyResult
from secops_core.detectors.engine import ConsolidatedAnomaly
from secops_core.explainer.ollama_client import OllamaClient


@pytest.fixture
def sample_db_with_anomaly(tmp_path: Path):
    """Cria banco SQLite temporário com uma anomalia registrada."""
    test_db = tmp_path / "ollama_test.db"
    init_db(str(test_db))

    anom = ConsolidatedAnomaly(
        event_id="evt_test_ollama",
        timestamp="2026-11-20T15:00:00Z",
        event_name="DeleteTrail",
        user_name="intruder",
        source_ip="185.220.101.5",
        detectors_triggered=["CloudTrailRulesEngine"],
        max_score=1.0,
        max_severity="CRITICAL",
        scenario="defense_evasion",
    )
    save_anomalies([anom], db_path=str(test_db))
    return str(test_db)


def test_ollama_generate_success_and_persist_to_sqlite(sample_db_with_anomaly):
    """Valida que resposta bem-sucedida do Ollama é formatada e persistida no SQLite."""
    client = OllamaClient(base_url="http://localhost:11434", model="llama3.2")

    mock_response_text = (
        "#### 1) O que aconteceu (Resumo Simples)\n"
        "O usuário intruder tentou apagar a trilha CloudTrail.\n\n"
        "#### 2) Por que foi considerado anômalo\n"
        "Ação crítica DeleteTrail viola políticas de conformidade.\n\n"
        "#### 3) Risco Potencial\n"
        "Evasão de defesa (T1562.001).\n\n"
        "#### 4) Ação Recomendada\n"
        "1. Bloquear IP\n2. Reativar log\n3. Revogar chaves"
    )

    mock_http_response = MagicMock()
    mock_http_response.status_code = 200
    mock_http_response.json.return_value = {"response": mock_response_text}

    context = {
        "event_id": "evt_test_ollama",
        "timestamp": "2026-11-20T15:00:00Z",
        "event_name": "DeleteTrail",
        "user_name": "intruder",
        "source_ip": "185.220.101.5",
        "severity": "CRITICAL",
        "cloudtrail_rules": ["RULE_TRAIL_TAMPERING"],
    }

    with patch("httpx.Client.post", return_value=mock_http_response):
        explanation = client.explain_and_persist(
            event_id="evt_test_ollama",
            context=context,
            db_path=sample_db_with_anomaly,
        )

    assert "Laudo emitido por LLM Local (llama3.2 via Ollama)" in explanation
    assert "intruder" in explanation

    # Valida que o SQLite foi atualizado
    updated_record = get_anomaly_by_event_id("evt_test_ollama", db_path=sample_db_with_anomaly)
    assert updated_record is not None
    assert updated_record.get("explanation") == explanation or updated_record.get("ai_explanation") == explanation


def test_ollama_offline_triggers_fallback_without_exception(sample_db_with_anomaly):
    """Valida que quando o Ollama está desligado (ConnectError), o fallback Jinja2 é acionado sem exceção."""
    client = OllamaClient(base_url="http://localhost:11434", model="llama3.2")

    context = {
        "event_id": "evt_test_ollama",
        "timestamp": "2026-11-20T15:00:00Z",
        "event_name": "DeleteTrail",
        "user_name": "intruder",
        "source_ip": "185.220.101.5",
        "severity": "CRITICAL",
        "cloudtrail_rules": ["RULE_TRAIL_TAMPERING"],
    }

    with patch("httpx.Client.post", side_effect=httpx.ConnectError("Connection refused")):
        # Não deve lançar ConnectError
        explanation = client.explain_and_persist(
            event_id="evt_test_ollama",
            context=context,
            db_path=sample_db_with_anomaly,
        )

    assert "Motor Analítico de Contingência SecOps" in explanation
    assert "Fallback Jinja2" in explanation
    assert "1) O que aconteceu (Resumo Simples)" in explanation
    assert "4) Ação Recomendada" in explanation

    # Valida persistência do fallback no SQLite
    updated_record = get_anomaly_by_event_id("evt_test_ollama", db_path=sample_db_with_anomaly)
    assert updated_record is not None
    assert "Fallback Jinja2" in (updated_record.get("explanation") or updated_record.get("ai_explanation") or "")


def test_ollama_timeout_triggers_fallback():
    """Valida acionamento do fallback em caso de TimeoutException."""
    client = OllamaClient()
    context = {
        "event_id": "evt_timeout",
        "event_name": "PutUserPolicy",
        "user_name": "dev_hacked",
        "source_ip": "203.0.113.1",
        "severity": "HIGH",
    }

    with patch("httpx.Client.post", side_effect=httpx.TimeoutException("Timeout")):
        explanation = client.explain_anomaly(context)

    assert "Fallback Jinja2" in explanation
    assert "PutUserPolicy" in explanation


def test_ollama_check_health():
    """Valida o método check_health()."""
    client = OllamaClient(base_url="http://localhost:11434")

    # Caso ativo (200 OK)
    mock_resp_ok = MagicMock()
    mock_resp_ok.status_code = 200
    with patch("httpx.Client.get", return_value=mock_resp_ok):
        assert client.check_health() is True
        assert client.is_alive() is True

    # Caso inativo (exceção de conexão)
    with patch("httpx.Client.get", side_effect=httpx.ConnectError("Failed")):
        assert client.check_health() is False
        assert client.is_alive() is False
