"""Testes de validação para o parser LGMS, resiliência a falhas e feature engineering."""

import json
from pathlib import Path
import pytest
from secops_core.lgms import (
    CanonicalLog,
    extract_features,
    get_feature_matrix,
    parse_log_line,
    parse_logs_file,
)


def test_parse_valid_canonical_log():
    """Valida conversão de dicionário JSON para modelo Pydantic CanonicalLog."""
    raw = json.dumps({
        "event_id": "test-uuid-001",
        "timestamp": "2026-11-05T14:30:00Z",
        "event_name": "GetObject",
        "event_source": "s3.amazonaws.com",
        "user_identity": {"type": "IAMUser", "userName": "analyst"},
        "source_ip": "10.0.1.50",
        "aws_region": "us-east-1",
        "status": "Success",
        "error_code": None,
        "request_count": 10,
        "bytes_transferred": 2048,
    })

    log = parse_log_line(raw)
    assert log is not None
    assert isinstance(log, CanonicalLog)
    assert log.event_id == "test-uuid-001"
    assert log.user_identity.userName == "analyst"
    assert log.timestamp.hour == 14
    assert log.bytes_transferred == 2048


def test_corrupted_lines_resilience(tmp_path: Path):
    """Valida se linhas corrompidas ou malformadas são descartadas com log de warning sem derrubar a execução."""
    file_path = tmp_path / "mixed_logs.jsonl"
    with file_path.open("w", encoding="utf-8") as f:
        # Linha 1 válida
        f.write(json.dumps({
            "event_id": "1",
            "timestamp": "2026-11-05T10:00:00Z",
            "event_name": "ListBuckets",
            "event_source": "s3.amazonaws.com",
            "user_identity": {"userName": "user1"},
            "source_ip": "10.0.0.1",
        }) + "\n")
        # Linha 2 corrompida (JSON quebrado)
        f.write("{ INVALID JSON TEXT HERE ... \n")
        # Linha 3 vazia
        f.write("\n")
        # Linha 4 válida
        f.write(json.dumps({
            "event_id": "2",
            "timestamp": "2026-11-05T11:00:00Z",
            "event_name": "DescribeInstances",
            "event_source": "ec2.amazonaws.com",
            "user_identity": {"userName": "user2"},
            "source_ip": "10.0.0.2",
        }) + "\n")

    logs, summary = parse_logs_file(file_path)

    assert len(logs) == 2
    assert summary.valid_logs == 2
    assert summary.corrupted_lines == 1
    assert logs[0].event_id == "1"
    assert logs[1].event_id == "2"


def test_feature_extraction_pipeline():
    """Valida a extração de features numéricas e temporais para consumo pelos detectores."""
    raw_logs = [
        CanonicalLog(
            event_id="e1",
            timestamp="2026-11-05T02:30:00Z",  # Madrugada (is_off_hours = 1)
            event_name="ConsoleLogin",
            event_source="signin.amazonaws.com",
            user_identity={"userName": "admin"},
            source_ip="185.220.101.5",  # IP suspeito
            status="Failure",
            error_code="BadCredentials",
            request_count=5,
            bytes_transferred=500,
        ),
        CanonicalLog(
            event_id="e2",
            timestamp="2026-11-05T14:15:00Z",  # Horário comercial
            event_name="GetObject",
            event_source="s3.amazonaws.com",
            user_identity={"userName": "bob"},
            source_ip="10.0.1.15",
            status="Success",
            request_count=1,
            bytes_transferred=2000,
        ),
    ]

    df = extract_features(raw_logs)

    assert len(df) == 2
    assert "hour" in df.columns
    assert "is_off_hours" in df.columns
    assert "is_error" in df.columns
    assert "is_suspicious_ip" in df.columns
    assert "log_bytes_transferred" in df.columns
    assert "ip_frequency" in df.columns

    # Validações dos valores extraídos para e1 (anomalia simulada)
    row_e1 = df[df["event_id"] == "e1"].iloc[0]
    assert row_e1["is_off_hours"] == 1
    assert row_e1["is_error"] == 1
    assert row_e1["is_suspicious_ip"] == 1
    assert row_e1["is_login"] == 1

    # Validação da matriz numérica para scikit-learn
    X, feature_cols = get_feature_matrix(df)
    assert not X.empty
    assert X.shape[0] == 2
    assert len(feature_cols) >= 10
    # Todos os tipos em X devem ser numéricos (sem strings)
    assert X.dtypes.apply(lambda dt: dt.kind in "iufcb").all()
