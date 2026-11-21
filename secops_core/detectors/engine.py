"""Motor central de orquestração e consolidação de múltiplos detectores."""

from typing import Dict, List, Optional
import pandas as pd
from pydantic import BaseModel, Field
from secops_core.detectors.base import AnomalyResult, BaseDetector
from secops_core.detectors.isolation_forest import IsolationForestDetector
from secops_core.detectors.rules import RuleBasedDetector
from secops_core.detectors.zscore import ZScoreDetector


class ConsolidatedAnomaly(BaseModel):
    """Visão unificada de um evento anômalo com múltiplos detectores agregados."""
    event_id: str
    timestamp: str
    event_name: str
    user_name: str
    source_ip: str
    detectors_triggered: List[str]
    max_score: float
    max_severity: str
    scenario: Optional[str] = None
    explanation: Optional[str] = None
    technical_justification: Optional[str] = None
    detector_results: List[AnomalyResult] = Field(default_factory=list)


class DetectionEngine:
    """Orquestrador do ensemble de detectores de SecOps."""

    SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

    def __init__(self, detectors: Optional[List[BaseDetector]] = None):
        if detectors is not None:
            self.detectors = detectors
        else:
            self.detectors = [
                ZScoreDetector(threshold=3.0),
                IsolationForestDetector(contamination=0.05, random_state=42),
                RuleBasedDetector(),
            ]

    def run_all(self, df: pd.DataFrame) -> List[AnomalyResult]:
        """Executa todos os detectores cadastrados e retorna a lista combinada de resultados."""
        all_results: List[AnomalyResult] = []
        for detector in self.detectors:
            results = detector.detect(df)
            all_results.extend(results)
        return all_results

    def _build_technical_justification(
        self, items: List[AnomalyResult], final_severity: str
    ) -> str:
        """Constrói justificativa técnica estruturada com base nas evidências dos detectores."""
        reasons = []
        for it in items:
            d_name = it.detector_name
            details = it.details or {}
            if "triggered_metrics" in details:
                metrics_desc = ", ".join(
                    [f"{k} (z={v.get('z_score', 0)})" for k, v in details["triggered_metrics"].items()]
                )
                reasons.append(f"{d_name}: métrica(s) volumétrica(s) {metrics_desc}")
            elif "rule_codes" in details or "primary_rule" in details:
                rule_name = details.get("primary_rule") or details.get("rule_codes", ["Regra"])[0]
                tech_reason = details.get("technical_reason", "Violação de política CloudTrail")
                reasons.append(f"{d_name}: disparou {rule_name} ({tech_reason})")
            elif "top_features" in details:
                feats = ", ".join([f"{k}={v}" for k, v in list(details["top_features"].items())[:3]])
                reasons.append(f"{d_name}: anomalia multivariada com score {it.anomaly_score} (features: {feats})")
            else:
                reasons.append(f"{d_name}: anomalia detectada com score {it.anomaly_score}")

        justification = (
            f"Consolidação de evidências ({final_severity}): "
            + "; ".join(reasons)
        )
        if len(items) >= 2:
            justification += ". Consenso multi-detector: severidade combinada elevada."
        return justification

    def run_and_consolidate(self, df: pd.DataFrame) -> List[ConsolidatedAnomaly]:
        """Executa todos os detectores e agrupa as anomalias por event_id unificado."""
        raw_results = self.run_all(df)
        grouped: Dict[str, List[AnomalyResult]] = {}

        for item in raw_results:
            grouped.setdefault(item.event_id, []).append(item)

        consolidated: List[ConsolidatedAnomaly] = []

        for event_id, items in grouped.items():
            first = items[0]
            detectors_triggered = [it.detector_name for it in items]
            max_score = max(it.anomaly_score for it in items)

            # Encontra a maior severidade observada
            max_sev = "LOW"
            highest_weight = 0
            for it in items:
                w = self.SEVERITY_ORDER.get(it.severity, 1)
                if w > highest_weight:
                    highest_weight = w
                    max_sev = it.severity

            # Se mais de 2 detectores dispararem juntos, eleva no mínimo para HIGH
            if len(detectors_triggered) >= 2 and highest_weight < 3:
                max_sev = "HIGH"

            scenario = next((it.scenario for it in items if it.scenario), None)
            technical_justification = self._build_technical_justification(items, max_sev)

            consolidated.append(
                ConsolidatedAnomaly(
                    event_id=event_id,
                    timestamp=first.timestamp,
                    event_name=first.event_name,
                    user_name=first.user_name,
                    source_ip=first.source_ip,
                    detectors_triggered=detectors_triggered,
                    max_score=round(max_score, 4),
                    max_severity=max_sev,
                    scenario=scenario,
                    technical_justification=technical_justification,
                    detector_results=items,
                )
            )

        # Ordena da maior severidade e score para a menor
        consolidated.sort(
            key=lambda c: (self.SEVERITY_ORDER.get(c.max_severity, 1), c.max_score),
            reverse=True,
        )

        return consolidated
