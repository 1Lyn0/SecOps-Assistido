"""Testes unitários para os detectores Z-Score, Isolation Forest, Regras e Engine."""

import pandas as pd
import pytest
from secops_core.detectors.engine import DetectionEngine
from secops_core.detectors.isolation_forest import IsolationForestDetector
from secops_core.detectors.rules import RuleBasedDetector
from secops_core.detectors.zscore import ZScoreDetector


@pytest.fixture
def sample_feature_df():
    """Cria um DataFrame sintético simulando a saída do módulo LGMS."""
    data = [
        # Eventos normais
        {
            "event_id": f"norm_{i}",
            "timestamp": "2026-11-05T14:00:00Z",
            "event_name": "DescribeInstances",
            "event_source": "ec2.amazonaws.com",
            "user_name": "alice",
            "source_ip": "10.0.1.15",
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
            "bytes_transferred": 1000.0,
            "log_bytes_transferred": 6.9,
            "ip_frequency": 20.0,
            "user_frequency": 20.0,
            "scenario": "normal",
        }
        for i in range(40)
    ]

    # Injeta anomalia de volumetria (para o Z-Score)
    data.append({
        "event_id": "anom_zscore",
        "timestamp": "2026-11-05T14:10:00Z",
        "event_name": "GetObject",
        "event_source": "s3.amazonaws.com",
        "user_name": "alice",
        "source_ip": "10.0.1.15",
        "hour": 14,
        "day_of_week": 2,
        "is_weekend": 0,
        "is_off_hours": 0,
        "is_login": 0,
        "is_iam": 0,
        "is_trail_mgmt": 0,
        "is_s3": 1,
        "is_error": 0,
        "is_suspicious_ip": 0,
        "request_count": 1500.0,  # Pico brutal
        "bytes_transferred": 500000000.0,
        "log_bytes_transferred": 20.0,
        "ip_frequency": 20.0,
        "user_frequency": 20.0,
        "scenario": "data_exfiltration",
    })

    # Injeta anomalia de regra (DeleteTrail)
    data.append({
        "event_id": "anom_rule",
        "timestamp": "2026-11-05T15:00:00Z",
        "event_name": "DeleteTrail",
        "event_source": "cloudtrail.amazonaws.com",
        "user_name": "attacker",
        "source_ip": "185.220.101.5",
        "hour": 15,
        "day_of_week": 2,
        "is_weekend": 0,
        "is_off_hours": 0,
        "is_login": 0,
        "is_iam": 0,
        "is_trail_mgmt": 1,
        "is_s3": 0,
        "is_error": 0,
        "is_suspicious_ip": 1,
        "request_count": 1.0,
        "bytes_transferred": 200.0,
        "log_bytes_transferred": 5.3,
        "ip_frequency": 1.0,
        "user_frequency": 1.0,
        "scenario": "defense_evasion",
    })

    return pd.DataFrame(data)


def test_zscore_detector(sample_feature_df):
    detector = ZScoreDetector(threshold=3.0)
    results = detector.detect(sample_feature_df)

    assert len(results) >= 1
    event_ids = [r.event_id for r in results]
    assert "anom_zscore" in event_ids

    anom = next(r for r in results if r.event_id == "anom_zscore")
    assert anom.severity in ("HIGH", "CRITICAL")
    assert anom.anomaly_score >= 3.0


def test_rule_based_detector(sample_feature_df):
    detector = RuleBasedDetector()
    results = detector.detect(sample_feature_df)

    assert len(results) >= 1
    event_ids = [r.event_id for r in results]
    assert "anom_rule" in event_ids

    anom = next(r for r in results if r.event_id == "anom_rule")
    assert anom.severity == "CRITICAL"
    assert "T1562.001" in anom.details["mitre_technique"]


def test_isolation_forest_detector(sample_feature_df):
    detector = IsolationForestDetector(contamination=0.1, random_state=42)
    results = detector.detect(sample_feature_df)

    # O Isolation Forest deve classificar pontos aberrantes
    assert len(results) > 0
    for r in results:
        assert 0.0 <= r.anomaly_score <= 1.0


def test_detection_engine_consolidation(sample_feature_df):
    engine = DetectionEngine()
    consolidated = engine.run_and_consolidate(sample_feature_df)

    assert len(consolidated) >= 2
    # Garante que os IDs esperados foram consolidados
    event_ids = [c.event_id for c in consolidated]
    assert "anom_rule" in event_ids
    assert "anom_zscore" in event_ids

    # O evento de DeleteTrail deve ter severidade CRITICAL
    rule_anom = next(c for c in consolidated if c.event_id == "anom_rule")
    assert rule_anom.max_severity == "CRITICAL"
