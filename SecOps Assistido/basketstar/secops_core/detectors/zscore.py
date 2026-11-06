"""Detector estatístico univariado baseado em Z-Score para métricas volumétricas."""

from typing import List, Optional
import numpy as np
import pandas as pd
from secops_core.detectors.base import AnomalyResult, BaseDetector


class ZScoreDetector(BaseDetector):
    """Detecta anomalias estatísticas volumétricas usando desvio padrão normalizado (Z-Score).

    Métricas analisadas por padrão:
    - 'request_count': picos repentinos de quantidade de requisições.
    - 'log_bytes_transferred': picos massivos de volume de dados transferidos.
    """

    def __init__(
        self,
        threshold: float = 3.0,
        target_columns: Optional[List[str]] = None,
        name: str = "ZScoreDetector",
    ):
        super().__init__(name=name)
        self.threshold = threshold
        self.target_columns = target_columns or ["request_count", "log_bytes_transferred"]

    def _calculate_severity(self, max_z: float) -> str:
        """Determina a severidade do alerta com base na magnitude do desvio padrão."""
        if max_z >= 5.0:
            return "CRITICAL"
        if max_z >= 4.0:
            return "HIGH"
        return "MEDIUM"

    def detect(self, df: pd.DataFrame) -> List[AnomalyResult]:
        """Aplica o cálculo de Z-score nas colunas alvo do DataFrame."""
        if df.empty:
            return []

        results: List[AnomalyResult] = []
        df_work = df.copy()

        # Calcula z-score para as colunas presentes
        z_cols = []
        for col in self.target_columns:
            if col in df_work.columns:
                mean = df_work[col].mean()
                std = df_work[col].std(ddof=0)
                z_col = f"z_{col}"
                if std > 0:
                    df_work[z_col] = (df_work[col] - mean) / std
                else:
                    df_work[z_col] = 0.0
                z_cols.append((col, z_col))

        if not z_cols:
            return []

        for _, row in df_work.iterrows():
            max_z = 0.0
            triggered_metrics = {}

            for raw_col, z_col in z_cols:
                z_val = abs(float(row[z_col]))
                if z_val > max_z:
                    max_z = z_val
                if z_val >= self.threshold:
                    triggered_metrics[raw_col] = {
                        "value": float(row[raw_col]),
                        "z_score": round(z_val, 2),
                    }

            is_anomaly = max_z >= self.threshold

            if is_anomaly:
                severity = self._calculate_severity(max_z)
                results.append(
                    AnomalyResult(
                        event_id=str(row.get("event_id", "")),
                        timestamp=str(row.get("timestamp", "")),
                        event_name=str(row.get("event_name", "Unknown")),
                        user_name=str(row.get("user_name", "Unknown")),
                        source_ip=str(row.get("source_ip", "Unknown")),
                        detector_name=self.name,
                        anomaly_score=round(max_z, 4),
                        is_anomaly=True,
                        severity=severity,
                        scenario=row.get("scenario") if pd.notna(row.get("scenario")) else None,
                        details={
                            "triggered_metrics": triggered_metrics,
                            "threshold": self.threshold,
                            "max_z_score": round(max_z, 2),
                        },
                    )
                )

        return results
