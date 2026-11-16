"""Detector estatístico univariado baseado em Z-Score para anomalias volumétricas e temporais."""

import os
from typing import Any, Dict, List, Optional
import numpy as np
import pandas as pd
from secops_core.config import settings
from secops_core.detectors.base import AnomalyResult, BaseDetector


class ZScoreDetector(BaseDetector):
    """Detecta anomalias estatísticas volumétricas e temporais usando desvio padrão normalizado (Z-Score).

    Fórmula: Z = (x - mu) / sigma

    Métricas analisadas por padrão:
    - 'request_count': picos repentinos de quantidade de requisições.
    - 'log_bytes_transferred': volume logarítmico de dados transferidos.
    - 'bytes_transferred': volume bruto de bytes transferidos (exfiltração).
    - 'ip_frequency': taxa/volume de eventos por IP de origem.
    - 'user_frequency': taxa/volume de eventos por usuário.

    Possui proteção total contra divisão por zero quando sigma = 0.
    O limiar (threshold) é configurável via parâmetro do construtor ou variável de ambiente ZSCORE_THRESHOLD.
    """

    def __init__(
        self,
        threshold: Optional[float] = None,
        target_columns: Optional[List[str]] = None,
        name: str = "ZScoreDetector",
    ):
        super().__init__(name=name)
        # Prioridade de threshold: parâmetro explícito -> env var ZSCORE_THRESHOLD -> settings.zscore_threshold (3.0)
        if threshold is not None:
            self.threshold = float(threshold)
        else:
            env_val = os.getenv("ZSCORE_THRESHOLD")
            if env_val is not None:
                self.threshold = float(env_val)
            else:
                self.threshold = float(getattr(settings, "zscore_threshold", 3.0))

        self.target_columns = target_columns or [
            "request_count",
            "log_bytes_transferred",
            "bytes_transferred",
            "ip_frequency",
            "user_frequency",
        ]

    def _calculate_severity(self, max_z: float) -> str:
        """Determina a severidade do alerta com base na magnitude do desvio padrão."""
        if max_z >= 5.0:
            return "CRITICAL"
        if max_z >= 4.0:
            return "HIGH"
        return "MEDIUM"

    def calculate_zscore(
        self, df: pd.DataFrame, columns: Optional[List[str]] = None
    ) -> pd.DataFrame:
        """Calcula o Z-Score para as colunas selecionadas sem modificar o DataFrame original.

        Retorna uma cópia do DataFrame contendo as novas colunas 'z_<coluna>'.
        Trata divisão por zero definindo Z = 0.0 caso sigma = 0.
        """
        if df.empty:
            return df.copy()

        df_work = df.copy()
        cols = columns or self.target_columns

        # Se houver métricas agregadas necessárias ausentes, calcula dinamicamente
        if "ip_frequency" in cols and "ip_frequency" not in df_work.columns and "source_ip" in df_work.columns:
            df_work["ip_frequency"] = df_work["source_ip"].map(df_work["source_ip"].value_counts()).astype(float)
        if "user_frequency" in cols and "user_frequency" not in df_work.columns and "user_name" in df_work.columns:
            df_work["user_frequency"] = df_work["user_name"].map(df_work["user_name"].value_counts()).astype(float)

        for col in cols:
            if col in df_work.columns and pd.api.types.is_numeric_dtype(df_work[col]):
                mean = df_work[col].mean()
                std = df_work[col].std(ddof=0)
                z_col = f"z_{col}"
                if std > 0:
                    df_work[z_col] = (df_work[col] - mean) / std
                else:
                    df_work[z_col] = 0.0

        return df_work

    def annotate_dataframe(
        self, df: pd.DataFrame, columns: Optional[List[str]] = None
    ) -> pd.DataFrame:
        """Anexa scores estatísticos e flags de anomalia ao DataFrame sem alterar colunas originais."""
        df_annotated = self.calculate_zscore(df, columns=columns)
        cols = columns or self.target_columns
        z_cols = [f"z_{c}" for c in cols if f"z_{c}" in df_annotated.columns]

        if not z_cols:
            df_annotated["max_zscore"] = 0.0
            df_annotated["is_zscore_anomaly"] = False
            return df_annotated

        df_annotated["max_zscore"] = df_annotated[z_cols].abs().max(axis=1)
        df_annotated["is_zscore_anomaly"] = df_annotated["max_zscore"] >= self.threshold
        return df_annotated

    def detect(self, df: pd.DataFrame) -> List[AnomalyResult]:
        """Aplica o cálculo de Z-score nas colunas alvo e retorna lista padronizada de anomalias."""
        if df.empty:
            return []

        df_work = self.calculate_zscore(df)
        cols = self.target_columns
        z_cols = [(col, f"z_{col}") for col in cols if f"z_{col}" in df_work.columns]

        if not z_cols:
            return []

        results: List[AnomalyResult] = []

        for _, row in df_work.iterrows():
            max_z = 0.0
            triggered_metrics: Dict[str, Any] = {}

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
                            "is_zscore_anomaly": True,
                        },
                    )
                )

        return results
