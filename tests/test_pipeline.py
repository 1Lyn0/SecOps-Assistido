"""Testes de integração do pipeline de ponta a ponta e persistência."""

from pathlib import Path
import pytest
from secops_core.config import settings
from secops_core.db import get_anomalies, get_db_stats
from secops_core.generator import generate_simulated_logs
from secops_core.pipeline import run_pipeline


def test_full_pipeline_execution(tmp_path: Path, monkeypatch):
    test_db = tmp_path / "pipeline_test.db"
    test_logs = tmp_path / "pipeline_logs.jsonl"
    monkeypatch.setattr(settings, "sqlite_db_path", str(test_db))

    # 1. Gera logs de teste
    generate_simulated_logs(count=150, anomaly_rate=0.15, seed=42, output_path=str(test_logs))

    # 2. Executa o pipeline completo
    result = run_pipeline(
        log_file=str(test_logs),
        save_to_db=True,
        explain_critical=True,
    )

    assert result["status"] == "success"
    assert result["valid_logs"] >= 150
    assert result["total_anomalies_detected"] > 0
    assert result["saved_to_db"] == result["total_anomalies_detected"]

    # 3. Valida no SQLite
    db_items = get_anomalies(limit=200)
    assert len(db_items) == result["total_anomalies_detected"]

    stats = get_db_stats()
    assert stats["total_anomalies"] == result["total_anomalies_detected"]
