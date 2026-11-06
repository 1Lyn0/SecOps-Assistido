"""Classes base e estruturas de dados para detectores de anomalias de SecOps."""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
import pandas as pd
from pydantic import BaseModel, Field


class AnomalyResult(BaseModel):
    """Representação padronizada do resultado de detecção de anomalia."""
    event_id: str
    timestamp: str
    event_name: str
    user_name: str
    source_ip: str
    detector_name: str
    anomaly_score: float = Field(..., description="Score contínuo de anomalia (0.0 a 1.0 ou Z-score)")
    is_anomaly: bool
    severity: str = Field(default="LOW", description="LOW, MEDIUM, HIGH, CRITICAL")
    scenario: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)


class BaseDetector(ABC):
    """Interface abstrata obrigatória para todos os detectores do SecOps."""

    def __init__(self, name: str):
        self.name = name

    @abstractmethod
    def detect(self, df: pd.DataFrame) -> List[AnomalyResult]:
        """Processa o DataFrame de features e retorna a lista de anomalias encontradas."""
        pass
