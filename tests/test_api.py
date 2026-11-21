"""Testes automatizados completos para os endpoints da API REST (MAO-18)."""

from pathlib import Path
from fastapi.testclient import TestClient
import pytest
from api.main import app
from secops_core.config import settings
from secops_core.generator import generate_simulated_logs
from secops_core.pipeline import run_pipeline


@pytest.fixture
def client(tmp_path: Path, monkeypatch):
    test_db = tmp_path / "api_test.db"
    test_logs = tmp_path / "api_logs.jsonl"
    monkeypatch.setattr(settings, "sqlite_db_path", str(test_db))

    # Prepara base com dados reais para testes
    generate_simulated_logs(count=100, anomaly_rate=0.2, seed=77, output_path=str(test_logs))
    run_pipeline(log_file=str(test_logs), save_to_db=True, explain_critical=False)

    return TestClient(app)


def test_api_health(client):
    """Testa o endpoint /health com status do SQLite e conectividade com Ollama."""
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] in ("ok", "degraded")
    assert data["database"] == "connected"
    assert data["ollama"] in ("connected", "disconnected")
    assert data["service"] == "secops-api"


def test_api_stats(client):
    """Testa o endpoint /stats com métricas executivas completas."""
    resp = client.get("/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert "total_anomalies" in data
    assert "total_logs_analyzed" in data
    assert "anomaly_rate" in data
    assert "severity_distribution" in data
    assert "detector_distribution" in data
    assert "top_anomalous_events" in data
    assert "top_suspicious_ips" in data
    assert data["total_anomalies"] > 0
    assert data["total_logs_analyzed"] >= 100


def test_api_list_logs_pagination_and_filters(client):
    """Testa o endpoint GET /logs com paginação e filtros combinados."""
    # Listagem geral
    resp = client.get("/logs?limit=20&offset=0")
    assert resp.status_code == 200
    data = resp.json()
    assert "total" in data
    assert "items" in data
    assert len(data["items"]) <= 20
    assert data["total"] >= 100

    # Filtro por is_anomaly = true
    resp_anom = client.get("/logs?is_anomaly=true")
    assert resp_anom.status_code == 200
    items_anom = resp_anom.json()["items"]
    assert all(it["is_anomaly"] is True for it in items_anom)

    # Filtro por severidade
    resp_crit = client.get("/logs?severity=CRITICAL")
    assert resp_crit.status_code == 200
    items_crit = resp_crit.json()["items"]
    assert all(it["final_severity"] == "CRITICAL" for it in items_crit)

    # Filtro por detector_type = zscore
    resp_z = client.get("/logs?detector_type=zscore")
    assert resp_z.status_code == 200
    items_z = resp_z.json()["items"]
    assert all(it["is_zscore_anomaly"] is True for it in items_z)


def test_api_list_anomalies(client):
    """Testa o endpoint GET /anomalies com paginação e filtros."""
    resp = client.get("/anomalies?limit=10")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] > 0
    assert len(data["items"]) <= 10


def test_api_get_anomaly_details_and_not_found(client):
    """Testa detalhes de anomalia existente e retorno 404 para ID inexistente."""
    list_resp = client.get("/anomalies?limit=1")
    items = list_resp.json()["items"]
    assert len(items) > 0
    event_id = items[0]["event_id"]

    # Detalhes com 200 OK
    detail_resp = client.get(f"/anomalies/{event_id}")
    assert detail_resp.status_code == 200
    assert detail_resp.json()["event_id"] == event_id

    # Event ID inexistente com 404 NOT FOUND
    not_found_resp = client.get("/anomalies/non-existent-event-id-99999")
    assert not_found_resp.status_code == 404
    assert "não encontrada" in not_found_resp.json()["detail"]


def test_api_explain_anomaly_and_not_found(client):
    """Testa geração/recuperação de laudo de explicabilidade e 404 para ID inválido."""
    list_resp = client.get("/anomalies?limit=1")
    event_id = list_resp.json()["items"][0]["event_id"]

    # Explicabilidade para evento existente
    explain_resp = client.post(f"/anomalies/{event_id}/explain")
    assert explain_resp.status_code == 200
    exp_data = explain_resp.json()
    assert exp_data["event_id"] == event_id
    assert len(exp_data["explanation"]) > 20

    # Explicabilidade para evento inexistente
    not_found_resp = client.post("/anomalies/fake-event-id/explain")
    assert not_found_resp.status_code == 404


def test_api_validation_error_422(client):
    """Testa erro de validação 422 para limites de paginação inválidos."""
    # limit = 0 (deve ser >= 1)
    resp_zero = client.get("/logs?limit=0")
    assert resp_zero.status_code == 422

    # limit > 500 (deve ser <= 500)
    resp_high = client.get("/logs?limit=1000")
    assert resp_high.status_code == 422


def test_api_docs_swagger_accessible(client):
    """Garante que a documentação Swagger UI está acessível em /docs."""
    resp = client.get("/docs")
    assert resp.status_code == 200
    assert "swagger" in resp.text.lower() or "html" in resp.headers.get("content-type", "").lower()
