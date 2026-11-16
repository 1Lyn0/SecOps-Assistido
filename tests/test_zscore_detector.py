"""Testes unitários dedicados ao detector estatístico Z-Score (MAO-11).

Critérios de Aceitação:
- Calcula corretamente o Z-Score e identifica outliers em séries simuladas com picos de eventos.
- Limiar (threshold) configurável via parâmetro/ambiente.
- Testes cobrindo distribuição normal, pico extremo e desvio padrão zero.
- Não alteração dos dados originais do evento (apenas anexar score e flag).
"""

import numpy as np
import pandas as pd
import pytest
from secops_core.detectors.zscore_detector import ZScoreDetector


@pytest.fixture
def normal_distribution_df():
    """Gera uma série com distribuição aproximadamente normal em torno da média."""
    np.random.seed(42)
    request_counts = np.random.normal(loc=100.0, scale=5.0, size=50)
    data = [
        {
            "event_id": f"evt_norm_{i}",
            "timestamp": "2026-11-05T10:00:00Z",
            "event_name": "DescribeInstances",
            "user_name": "developer",
            "source_ip": "10.0.1.50",
            "request_count": float(rc),
            "log_bytes_transferred": 5.0,
            "bytes_transferred": 500.0,
            "ip_frequency": 50.0,
            "user_frequency": 50.0,
        }
        for i, rc in enumerate(request_counts)
    ]
    return pd.DataFrame(data)


@pytest.fixture
def extreme_spike_df():
    """Gera um conjunto basal com um pico extremo de volumetria."""
    np.random.seed(42)
    data = [
        {
            "event_id": f"evt_base_{i}",
            "timestamp": "2026-11-05T10:00:00Z",
            "event_name": "DescribeInstances",
            "user_name": "developer",
            "source_ip": "10.0.1.50",
            "request_count": 10.0 + np.random.uniform(-1, 1),
            "log_bytes_transferred": 4.0,
            "bytes_transferred": 200.0,
            "ip_frequency": 20.0,
            "user_frequency": 20.0,
        }
        for i in range(30)
    ]
    # Injeta evento extremo (outlier maciço)
    data.append({
        "event_id": "evt_extreme_spike",
        "timestamp": "2026-11-05T10:05:00Z",
        "event_name": "GetObject",
        "user_name": "exfiltrator",
        "source_ip": "185.220.101.5",
        "request_count": 5000.0,  # 500x a média
        "log_bytes_transferred": 25.0,
        "bytes_transferred": 1000000000.0,
        "ip_frequency": 1.0,
        "user_frequency": 1.0,
        "scenario": "data_exfiltration",
    })
    return pd.DataFrame(data)


@pytest.fixture
def zero_variance_df():
    """Gera um DataFrame onde todos os valores de volumetria são idênticos (std = 0)."""
    data = [
        {
            "event_id": f"evt_flat_{i}",
            "timestamp": "2026-11-05T12:00:00Z",
            "event_name": "GetItem",
            "user_name": "service_account",
            "source_ip": "10.0.2.1",
            "request_count": 5.0,
            "log_bytes_transferred": 3.0,
            "bytes_transferred": 150.0,
            "ip_frequency": 10.0,
            "user_frequency": 10.0,
        }
        for i in range(20)
    ]
    return pd.DataFrame(data)


def test_zscore_normal_distribution_no_false_positives(normal_distribution_df):
    """Verifica que uma distribuição normal sem anomalias extremas não dispara falsos positivos (limiar padrão 3.0)."""
    detector = ZScoreDetector(threshold=3.0)
    results = detector.detect(normal_distribution_df)
    assert len(results) == 0, f"Esperava 0 anomalias para distribuição normal com threshold 3.0, obteve {len(results)}"


def test_zscore_extreme_spike_detection(extreme_spike_df):
    """Verifica que pico extremo é detectado com Z-score elevado e severidade adequada."""
    detector = ZScoreDetector(threshold=3.0)
    results = detector.detect(extreme_spike_df)

    assert len(results) >= 1
    outlier_ids = [r.event_id for r in results]
    assert "evt_extreme_spike" in outlier_ids

    outlier = next(r for r in results if r.event_id == "evt_extreme_spike")
    assert outlier.is_anomaly is True
    assert outlier.anomaly_score >= 3.0
    assert outlier.severity in ("HIGH", "CRITICAL")
    assert "request_count" in outlier.details["triggered_metrics"]


def test_zscore_zero_standard_deviation_protection(zero_variance_df):
    """Garante proteção contra divisão por zero quando sigma = 0, sem lançar exceção nem gerar falsos positivos."""
    detector = ZScoreDetector(threshold=3.0)
    # Não deve lançar ZeroDivisionError
    results = detector.detect(zero_variance_df)
    assert results == []

    # Testa o annotate_dataframe diretamente
    annotated = detector.annotate_dataframe(zero_variance_df)
    assert "z_request_count" in annotated.columns
    assert (annotated["z_request_count"] == 0.0).all()
    assert (annotated["is_zscore_anomaly"] == False).all()


def test_zscore_threshold_configurable_via_parameter(extreme_spike_df):
    """Testa que o threshold pode ser ajustado via parâmetro do construtor."""
    strict_detector = ZScoreDetector(threshold=100.0)
    sensitive_detector = ZScoreDetector(threshold=1.5)

    results_strict = strict_detector.detect(extreme_spike_df)
    results_sensitive = sensitive_detector.detect(extreme_spike_df)

    # O detector sensível deve detectar o outlier (e potencialmente mais itens)
    assert len(results_sensitive) >= 1
    # O detector com threshold 100 não deve disparar se max_z < 100
    assert len(results_strict) <= len(results_sensitive)


def test_zscore_threshold_configurable_via_environment(monkeypatch, extreme_spike_df):
    """Testa que o threshold é configurado dinamicamente via variável de ambiente ZSCORE_THRESHOLD."""
    monkeypatch.setenv("ZSCORE_THRESHOLD", "4.5")
    detector = ZScoreDetector()
    assert detector.threshold == 4.5

    monkeypatch.setenv("ZSCORE_THRESHOLD", "2.2")
    detector2 = ZScoreDetector()
    assert detector2.threshold == 2.2


def test_zscore_original_dataframe_not_mutated(normal_distribution_df):
    """Garante que a execução do cálculo de Z-score não modifica as colunas do DataFrame original."""
    original_cols = list(normal_distribution_df.columns)
    original_shape = normal_distribution_df.shape

    detector = ZScoreDetector(threshold=3.0)
    _ = detector.detect(normal_distribution_df)

    assert list(normal_distribution_df.columns) == original_cols
    assert normal_distribution_df.shape == original_shape


def test_zscore_annotate_dataframe_adds_score_and_flag(extreme_spike_df):
    """Garante que o método annotate_dataframe anexa colunas zscore e flag booleana sem alterar colunas originais."""
    detector = ZScoreDetector(threshold=3.0)
    annotated = detector.annotate_dataframe(extreme_spike_df)

    assert "max_zscore" in annotated.columns
    assert "is_zscore_anomaly" in annotated.columns
    assert annotated.loc[annotated["event_id"] == "evt_extreme_spike", "is_zscore_anomaly"].values[0] == True
    assert annotated.loc[annotated["event_id"] == "evt_base_0", "is_zscore_anomaly"].values[0] == False
