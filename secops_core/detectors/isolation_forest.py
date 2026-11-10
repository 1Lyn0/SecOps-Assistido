"""Detector de Machine Learning multivariado baseado em Isolation Forest."""

from typing import List, Optional
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from secops_core.detectors.base import AnomalyResult, BaseDetector
from secops_core.lgms import get_feature_matrix


class IsolationForestDetector(BaseDetector):
    """Detector de Machine Learning multivariado não supervisionado.

    Identifica anomalias multidimensionais e comportamentais sutis
    isolando observações através de partições aleatórias em hiperplanos.
    """

    def __init__(
        self,
        contamination: float = 0.05,
        random_state: int = 42,
        name: str = "IsolationForestDetector",
    ):
        super().__init__(name=name)
        self.contamination = contamination
        self.random_state = random_state
        self.model = IsolationForest(
            contamination=self.contamination,
            random_state=self.random_state,
            n_estimators=100,
        )

    def _calculate_severity(self, normalized_score: float) -> str:
        """Determina a severidade com base no score normalizado de anomalia (0 a 1)."""
        if normalized_score >= 0.85:
            return "CRITICAL"
        if normalized_score >= 0.70:
            return "HIGH"
        if normalized_score >= 0.55:
            return "MEDIUM"
        return "LOW"

    def detect(self, df: pd.DataFrame) -> List[AnomalyResult]:
        """Treina e infere anomalias na matriz numérica de features."""
        if df.empty or len(df) < 5:
            return []

        # Extrai estritamente a matriz numérica compatível com o scikit-learn
        X, feature_cols = get_feature_matrix(df)
        if X.empty:
            return []

        # Trata possíveis NaNs ou infinitos por segurança
        X_clean = X.fillna(0.0).replace([np.inf, -np.inf], 0.0)

        # Ajusta o modelo e obtém predições (-1 = anomalia, 1 = normal)
        preds = self.model.fit_predict(X_clean)
        # decision_function retorna valores onde valores menores/negativos são mais anômalos
        decisions = self.model.decision_function(X_clean)

        # Inverte e normaliza scores para o intervalo [0.0, 1.0]
        # (onde 1.0 = maior probabilidade de anomalia)
        min_dec = decisions.min()
        max_dec = decisions.max()
        if max_dec > min_dec:
            anomaly_scores = (max_dec - decisions) / (max_dec - min_dec)
        else:
            anomaly_scores = np.zeros(len(decisions))

        results: List[AnomalyResult] = []

        for i, (pred, raw_score) in enumerate(zip(preds, anomaly_scores)):
            is_anomaly = pred == -1

            if is_anomaly:
                row = df.iloc[i]
                norm_score = float(round(raw_score, 4))
                severity = self._calculate_severity(norm_score)

                # Identifica as principais features com valores incomuns nessa linha
                top_features = {}
                for col in feature_cols:
                    val = float(X_clean.iloc[i][col])
                    col_mean = float(X_clean[col].mean())
                    if abs(val - col_mean) > 0.01:
                        top_features[col] = round(val, 2)

                results.append(
                    AnomalyResult(
                        event_id=str(row.get("event_id", "")),
                        timestamp=str(row.get("timestamp", "")),
                        event_name=str(row.get("event_name", "Unknown")),
                        user_name=str(row.get("user_name", "Unknown")),
                        source_ip=str(row.get("source_ip", "Unknown")),
                        detector_name=self.name,
                        anomaly_score=norm_score,
                        is_anomaly=True,
                        severity=severity,
                        scenario=row.get("scenario") if pd.notna(row.get("scenario")) else None,
                        details={
                            "contamination": self.contamination,
                            "normalized_score": norm_score,
                            "top_features": top_features,
                        },
                    )
                )

        return results
