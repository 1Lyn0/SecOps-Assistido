"""Schemas Pydantic para a API REST de SecOps."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: str = "ok"
    version: str = "0.1.0"
    service: str = "secops-api"


class AnomalyItem(BaseModel):
    id: Optional[int] = None
    event_id: str
    timestamp: str
    event_name: str
    user_name: str
    source_ip: str
    detectors_triggered: List[str]
    max_score: float
    severity: str
    scenario: Optional[str] = None
    explanation: Optional[str] = None
    details: Optional[Any] = None
    created_at: Optional[str] = None


class AnomalyListResponse(BaseModel):
    total: int
    items: List[AnomalyItem]


class PipelineRunRequest(BaseModel):
    log_file: str = "data/logs_simulados.jsonl"
    explain_critical: bool = False


class PipelineRunResponse(BaseModel):
    status: str
    file_processed: str
    total_logs: int
    valid_logs: int
    corrupted_lines: int
    total_anomalies_detected: int
    saved_to_db: int
    severity_distribution: Dict[str, int]


class ExplainResponse(BaseModel):
    event_id: str
    explanation: str
