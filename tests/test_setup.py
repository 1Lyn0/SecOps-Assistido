"""Testes de validação da infraestrutura básica e setup do repositório."""

import os
from pathlib import Path
import pytest
import secops_core
from secops_core.config import settings
from secops_core.db import get_connection, init_db


def test_package_import():
    """Valida se o pacote secops_core pode ser importado e possui versão definida."""
    assert secops_core.__version__ == "0.1.0"


def test_settings_defaults():
    """Valida se as configurações carregam defaults seguros e funcionais."""
    assert settings.sqlite_db_path is not None
    assert settings.ollama_base_url.startswith("http")
    assert settings.ollama_model != ""
    assert settings.api_base_url.startswith("http")


def test_sqlite_db_initialization(tmp_path: Path, monkeypatch):
    """Valida a conexão com o SQLite e execução do schema inicial em diretório temporário."""
    test_db = tmp_path / "test_secops.db"
    monkeypatch.setattr(settings, "sqlite_db_path", str(test_db))

    init_db()
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='anomalies'")
    row = cursor.fetchone()
    conn.close()

    assert row is not None
    assert row["name"] == "anomalies"


def test_api_scaffold():
    """Valida se a API FastAPI inicializa e responde ao health check."""
    from fastapi.testclient import TestClient
    from api.main import app

    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "secops-api"
