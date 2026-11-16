"""Testes unitários dedicados ao detector multivariado Isolation Forest (MAO-12).

Critérios de Aceitação:
- O modelo treina e infere sobre o lote de logs LGMS retornando score contínuo e classificação binária para cada evento.
- Reprodutibilidade garantida através de random_state fixo.
- Validação de que eventos multivariados anômalos recebem scores mais anômalos que o tráfego basal.
- Parametrização de contamination, n_estimators e random_state.
- Pré-processamento com escalonamento numérico e encoding de variáveis.
"""

import numpy as np
import pandas as pd
import pytest
from secops_core.detectors.isolation_forest import IsolationForestDetector


@pytest.fixture
def multivariate_lgms_dataset():
    """Cria dataset sintético representativo da saída do LGMS com tráfego basal e anomalia multivariada sutil.

    Tráfego basal: horário comercial (10h-16h), usuário padrão, IP interno, sem erro, volume normal.
    Anomalia multivariada: madrugada (03h), final de semana, IP externo, falha, volume moderado mas raro.
    """
    np.random.seed(42)
    rows = []
    # 50 eventos basais (normais)
    for i in range(50):
        rows.append({
            "event_id": f"normal_log_{i}",
            "timestamp": "2026-11-05T14:30:00Z",
            "event_name": "DescribeInstances",
            "event_source": "ec2.amazonaws.com",
            "user_name": "alice_dev",
            "source_ip": "10.0.1.25",
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
            "request_count": 2.0 + np.random.uniform(-0.5, 0.5),
            "bytes_transferred": 500.0,
            "log_bytes_transferred": 6.2,
            "ip_frequency": 50.0,
            "user_frequency": 50.0,
            "scenario": "normal",
        })

    # Anomalia multivariada sutil (não é pico extremo de volume, mas combinação anômala multidimensional)
    rows.append({
        "event_id": "multivariate_stealth_anomaly",
        "timestamp": "2026-11-08T03:15:00Z",
        "event_name": "CreateAccessKey",
        "event_source": "iam.amazonaws.com",
        "user_name": "unknown_actor",
        "source_ip": "198.51.100.4",
        "hour": 3,               # Madrugada
        "day_of_week": 6,        # Domingo
        "is_weekend": 1,         # Fim de semana
        "is_off_hours": 1,       # Fora do expediente
        "is_login": 0,
        "is_iam": 1,             # Ação de IAM
        "is_trail_mgmt": 0,
        "is_s3": 0,
        "is_error": 1,           # Erro
        "is_suspicious_ip": 1,   # IP suspeito
        "request_count": 8.0,    # Volume moderado, não é pico absurdo
        "bytes_transferred": 1200.0,
        "log_bytes_transferred": 7.1,
        "ip_frequency": 1.0,     # IP raríssimo
        "user_frequency": 1.0,   # Usuário raríssimo
        "scenario": "stealth_attack",
    })

    return pd.DataFrame(rows)


def test_isolation_forest_continuous_score_and_binary_classification(multivariate_lgms_dataset):
    """Verifica que o detector treina e infere retornando score contínuo e classificação binária para cada evento."""
    detector = IsolationForestDetector(contamination=0.05, random_state=42)
    annotated = detector.annotate_dataframe(multivariate_lgms_dataset)

    assert "is_iforest_anomaly" in annotated.columns
    assert "iforest_score" in annotated.columns
    assert "decision_function" in annotated.columns
    assert "raw_prediction" in annotated.columns

    # Todos os eventos recebem classificação binária (True/False)
    assert annotated["is_iforest_anomaly"].dtype == bool
    assert set(annotated["raw_prediction"].unique()).issubset({-1, 1})

    # Scores contínuos normalizados no intervalo [0.0, 1.0]
    scores = annotated["iforest_score"].values
    assert (scores >= 0.0).all() and (scores <= 1.0).all()


def test_isolation_forest_reproducibility_with_fixed_random_state(multivariate_lgms_dataset):
    """Garante que instâncias com mesmo random_state geram exatamente as mesmas predições e scores."""
    det1 = IsolationForestDetector(contamination=0.05, n_estimators=100, random_state=42)
    det2 = IsolationForestDetector(contamination=0.05, n_estimators=100, random_state=42)

    df1 = det1.annotate_dataframe(multivariate_lgms_dataset)
    df2 = det2.annotate_dataframe(multivariate_lgms_dataset)

    pd.testing.assert_series_equal(df1["is_iforest_anomaly"], df2["is_iforest_anomaly"])
    pd.testing.assert_series_equal(df1["iforest_score"], df2["iforest_score"])
    pd.testing.assert_series_equal(df1["decision_function"], df2["decision_function"])


def test_isolation_forest_multivariate_outlier_scores_higher_than_baseline(multivariate_lgms_dataset):
    """Valida que o evento multivariado anômalo recebe score mais anômalo que o tráfego basal."""
    detector = IsolationForestDetector(contamination=0.05, random_state=42)
    annotated = detector.annotate_dataframe(multivariate_lgms_dataset)

    anom_row = annotated[annotated["event_id"] == "multivariate_stealth_anomaly"].iloc[0]
    baseline_rows = annotated[annotated["event_id"].str.startswith("normal_log_")]

    mean_baseline_score = baseline_rows["iforest_score"].mean()
    anom_score = anom_row["iforest_score"]

    # O score de anomalia do evento multivariado deve ser significativamente maior que a média do tráfego basal
    assert anom_score > mean_baseline_score, (
        f"Score anômalo ({anom_score}) deveria ser maior que média basal ({mean_baseline_score})"
    )

    # A função de decisão para pontos anômalos no Isolation Forest é menor (mais negativa)
    anom_decision = anom_row["decision_function"]
    mean_baseline_decision = baseline_rows["decision_function"].mean()
    assert anom_decision < mean_baseline_decision, (
        f"Decision function anômala ({anom_decision}) deveria ser menor que a basal ({mean_baseline_decision})"
    )

    # E deve ser classificado como anomalia via detect()
    results = detector.detect(multivariate_lgms_dataset)
    detected_ids = [r.event_id for r in results]
    assert "multivariate_stealth_anomaly" in detected_ids


def test_isolation_forest_parametrization():
    """Valida que contamination, n_estimators e random_state são configuráveis via construtor e env."""
    det = IsolationForestDetector(contamination=0.12, n_estimators=75, random_state=99)
    assert det.contamination == 0.12
    assert det.n_estimators == 75
    assert det.random_state == 99
    assert det.model.contamination == 0.12
    assert det.model.n_estimators == 75
    assert det.model.random_state == 99


def test_isolation_forest_preprocessing_with_categorical_and_scaling(multivariate_lgms_dataset):
    """Valida que o pré-processamento executa escalonamento numérico e codificação de frequência."""
    detector = IsolationForestDetector(random_state=42)
    X_clean, X_scaled, feature_cols = detector.preprocess(multivariate_lgms_dataset)

    assert X_scaled.shape[0] == len(multivariate_lgms_dataset)
    assert X_scaled.shape[1] == len(feature_cols)

    # Verifica que o StandardScaler normalizou (média próxima de zero)
    col_means = np.abs(X_scaled.mean(axis=0))
    for mean_val in col_means:
        assert mean_val < 1e-6 or np.isclose(mean_val, 0.0, atol=1e-5)
