"""Testes automatizados para os endpoints da API REST."""

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

    # Prepara base com dados reais
    generate_simulated_logs(count=100, anomaly_rate=0.2, seed=77, output_path=str(test_logs))
    run_pipeline(log_file=str(test_logs), save_to_db=True, explain_critical=False)

    return TestClient(app)


def test_api_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_api_stats(client):
    resp = client.get("/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert "total_anomalies" in data
    assert data["total_anomalies"] > 0


def test_api_list_anomalies(client):
    resp = client.get("/anomalies?limit=10")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] > 0
    assert len(data["items"]) <= 10


def test_api_get_anomaly_and_explain(client):
    # Obtém uma anomalia existente
    list_resp = client.get("/anomalies?limit=1")
    items = list_resp.json()["items"]
    assert len(items) > 0
    event_id = items[0]["event_id"]

    # Detalhes
    detail_resp = client.get(f"/anomalies/{event_id}")
    assert detail_resp.status_code == 200
    assert detail_resp.json()["event_id"] == event_id

    # Explicabilidade
    explain_resp = client.post(f"/anomalies/{event_id}/explain")
    assert explain_resp.status_code == 200
    exp_data = explain_resp.json()
    assert exp_data["event_id"] == event_id
    assert "MITRE ATT&CK" in exp_data["explanation"]
