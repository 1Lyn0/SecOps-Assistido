"""Detector de Machine Learning multivariado baseado em Isolation Forest."""

import os
from typing import Any, Dict, List, Optional, Tuple
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from secops_core.config import settings
from secops_core.detectors.base import AnomalyResult, BaseDetector
from secops_core.lgms import get_feature_matrix


class IsolationForestDetector(BaseDetector):
    """Detector de Machine Learning multivariado não supervisionado baseado em Isolation Forest.

    Identifica anomalias multidimensionais e comportamentais sutis
    isolando observações através de partições aleatórias em hiperplanos.

    Pré-processamento:
    - Extração de matriz de features pelo LGMS
    - Codificação de frequência para variáveis categóricas
    - Escalonamento numérico robusto via StandardScaler
    - Conversão da predição (-1 para anomalia, 1 para normal) em is_iforest_anomaly (bool)
    - Cálculo de score contínuo normalizado e decision_function
    """

    def __init__(
        self,
        contamination: Optional[float] = None,
        n_estimators: Optional[int] = None,
        random_state: Optional[int] = None,
        name: str = "IsolationForestDetector",
    ):
        super().__init__(name=name)

        # Configuração com fallback: parâmetro -> env var -> settings -> default
        if contamination is not None:
            self.contamination = float(contamination)
        else:
            env_val = os.getenv("IFOREST_CONTAMINATION")
            self.contamination = (
                float(env_val)
                if env_val is not None
                else float(getattr(settings, "iforest_contamination", 0.05))
            )

        if n_estimators is not None:
            self.n_estimators = int(n_estimators)
        else:
            env_val = os.getenv("IFOREST_N_ESTIMATORS")
            self.n_estimators = (
                int(env_val)
                if env_val is not None
                else int(getattr(settings, "iforest_n_estimators", 100))
            )

        if random_state is not None:
            self.random_state = int(random_state)
        else:
            env_val = os.getenv("IFOREST_RANDOM_STATE")
            self.random_state = (
                int(env_val)
                if env_val is not None
                else int(getattr(settings, "iforest_random_state", 42))
            )

        self.scaler = StandardScaler()
        self.model = IsolationForest(
            contamination=self.contamination,
            n_estimators=self.n_estimators,
            random_state=self.random_state,
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

    def preprocess(self, df: pd.DataFrame) -> Tuple[pd.DataFrame, np.ndarray, List[str]]:
        """Pré-processa as features do LGMS com codificação categórica e escalonamento numérico.

        Returns:
            Tuple com:
            - DataFrame limpo (X_clean)
            - Matriz numpy normalizada/escalonada (X_scaled)
            - Lista de nomes das colunas de features
        """
        X, feature_cols = get_feature_matrix(df)
        if X.empty:
            return pd.DataFrame(), np.empty((0, 0)), []

        X_work = X.copy()

        # Frequência das variáveis categóricas se presentes no df e não em X
        for cat_col in ["event_name", "user_name", "source_ip", "event_source"]:
            freq_col = f"{cat_col}_freq"
            if cat_col in df.columns and freq_col not in X_work.columns:
                counts = df[cat_col].value_counts()
                X_work[freq_col] = df[cat_col].map(counts).astype(float)
                feature_cols.append(freq_col)

        # Trata possíveis NaNs ou infinitos
        X_clean = X_work.fillna(0.0).replace([np.inf, -np.inf], 0.0)

        # Escalonamento numérico padrão
        X_scaled = self.scaler.fit_transform(X_clean)

        return X_clean, X_scaled, list(X_clean.columns)

    def annotate_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """Treina e infere sobre o DataFrame retornando uma cópia com os scores e flags."""
        if df.empty or len(df) < 5:
            df_out = df.copy()
            df_out["is_iforest_anomaly"] = False
            df_out["iforest_score"] = 0.0
            df_out["decision_function"] = 0.0
            df_out["raw_prediction"] = 1
            return df_out

        X_clean, X_scaled, _ = self.preprocess(df)
        if X_scaled.shape[0] == 0:
            df_out = df.copy()
            df_out["is_iforest_anomaly"] = False
            df_out["iforest_score"] = 0.0
            df_out["decision_function"] = 0.0
            df_out["raw_prediction"] = 1
            return df_out

        preds = self.model.fit_predict(X_scaled)
        decisions = self.model.decision_function(X_scaled)

        # Inverte e normaliza scores para o intervalo [0.0, 1.0]
        min_dec = decisions.min()
        max_dec = decisions.max()
        if max_dec > min_dec:
            anomaly_scores = (max_dec - decisions) / (max_dec - min_dec)
        else:
            anomaly_scores = np.zeros(len(decisions))

        df_out = df.copy()
        df_out["raw_prediction"] = preds
        df_out["is_iforest_anomaly"] = preds == -1
        df_out["decision_function"] = decisions
        df_out["iforest_score"] = np.round(anomaly_scores, 4)

        return df_out

    def detect(self, df: pd.DataFrame) -> List[AnomalyResult]:
        """Treina e infere anomalias na matriz numérica de features.

        Retorna lista de AnomalyResult para cada evento anômalo detectado.
        """
        if df.empty or len(df) < 5:
            return []

        X_clean, X_scaled, feature_cols = self.preprocess(df)
        if X_scaled.shape[0] == 0:
            return []

        # Ajusta o modelo e obtém predições (-1 = anomalia, 1 = normal)
        preds = self.model.fit_predict(X_scaled)
        # decision_function retorna valores onde valores menores/negativos são mais anômalos
        decisions = self.model.decision_function(X_scaled)

        # Inverte e normaliza scores para o intervalo [0.0, 1.0] (1.0 = maior probabilidade de anomalia)
        min_dec = decisions.min()
        max_dec = decisions.max()
        if max_dec > min_dec:
            anomaly_scores = (max_dec - decisions) / (max_dec - min_dec)
        else:
            anomaly_scores = np.zeros(len(decisions))

        results: List[AnomalyResult] = []

        for i, (pred, raw_score, dec_val) in enumerate(zip(preds, anomaly_scores, decisions)):
            is_anomaly = (pred == -1)

            if is_anomaly:
                row = df.iloc[i]
                norm_score = float(round(raw_score, 4))
                severity = self._calculate_severity(norm_score)

                # Identifica features com maior desvio em relação à média do lote
                top_features: Dict[str, float] = {}
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
                            "n_estimators": self.n_estimators,
                            "random_state": self.random_state,
                            "normalized_score": norm_score,
                            "decision_function": float(round(dec_val, 4)),
                            "raw_prediction": int(pred),
                            "is_iforest_anomaly": True,
                            "top_features": top_features,
                        },
                    )
                )

        return results
