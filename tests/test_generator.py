"""Testes de validação do gerador de logs simulados."""

import json
from pathlib import Path
import pytest
from secops_core.generator import generate_simulated_logs


def test_generate_simulated_logs_format(tmp_path: Path):
    """Verifica se o gerador produz um arquivo JSONL válido com todos os campos canônicos."""
    output_file = tmp_path / "test_logs.jsonl"
    logs = generate_simulated_logs(
        count=150,
        anomaly_rate=0.20,
        seed=123,
        output_path=str(output_file),
    )

    assert output_file.exists()
    assert len(logs) >= 150

    required_fields = {
        "timestamp",
        "event_id",
        "event_name",
        "event_source",
        "user_identity",
        "source_ip",
        "aws_region",
        "status",
        "error_code",
        "request_count",
        "bytes_transferred",
        "metadata",
    }

    # Validação linha a linha lida do arquivo físico gerado
    with output_file.open("r", encoding="utf-8") as f:
        lines = f.readlines()

    assert len(lines) == len(logs)

    for line in lines:
        record = json.loads(line)
        assert required_fields.issubset(record.keys()), f"Campos faltantes em: {record.keys()}"
        assert isinstance(record["user_identity"], dict)
        assert "userName" in record["user_identity"]
        assert record["status"] in ("Success", "Failure")


def test_generator_anomaly_scenarios_coverage(tmp_path: Path):
    """Verifica se pelo menos 5 cenários distintos de anomalias são gerados no dataset."""
    output_file = tmp_path / "test_anomalies.jsonl"
    logs = generate_simulated_logs(
        count=500,
        anomaly_rate=0.40,
        seed=999,
        output_path=str(output_file),
    )

    scenarios = set()
    for log in logs:
        meta = log.get("metadata", {})
        if meta.get("is_anomaly_ground_truth"):
            scenarios.add(meta.get("scenario"))

    # Cenários esperados: brute_force, off_hours, defense_evasion, privilege_escalation, data_exfiltration, suspicious_ip
    expected_scenarios = {
        "brute_force",
        "off_hours",
        "defense_evasion",
        "privilege_escalation",
        "data_exfiltration",
        "suspicious_ip",
    }

    intersected = scenarios.intersection(expected_scenarios)
    assert len(intersected) >= 5, f"Esperado pelo menos 5 cenários de anomalia, obtido {len(intersected)}: {scenarios}"
