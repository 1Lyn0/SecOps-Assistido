"""Schemas Pydantic para validação e documentação Swagger da API REST de SecOps."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    """Status de saúde da API, banco SQLite e conectividade com o Ollama."""
    status: str = Field(default="ok", description="Status geral da API")
    database: str = Field(default="connected", description="Status da conexão SQLite ('connected' ou 'error')")
    ollama: str = Field(default="connected", description="Status de conectividade com Ollama ('connected' ou 'disconnected')")
    version: str = Field(default="0.1.0", description="Versão da API")
    service: str = Field(default="secops-api", description="Nome do serviço")


class StatsResponse(BaseModel):
    """Resumo estatístico consolidado e métricas executivas de SecOps."""
    total_logs_analyzed: int = Field(..., description="Total de logs analisados no histórico")
    total_anomalies: int = Field(..., description="Total de anomalias confirmadas detectadas")
    anomaly_rate: float = Field(..., description="Taxa percentual de anomalias (%)")
    severity_distribution: Dict[str, int] = Field(..., description="Contagem de alertas por severidade (LOW, MEDIUM, HIGH, CRITICAL)")
    detector_distribution: Dict[str, int] = Field(..., description="Contagem de alertas por detector (ZScore, IsolationForest, Rules)")
    top_anomalous_events: Dict[str, int] = Field(..., description="Top 5 ações de API mais frequentes em incidentes")
    top_suspicious_ips: Dict[str, int] = Field(..., description="Top 5 endereços IP associados a anomalias")


class LogItem(BaseModel):
    """Modelo canônico enriquecido de um log processado."""
    id: Optional[int] = None
    event_id: str
    timestamp: str
    event_name: str
    event_source: Optional[str] = ""
    user_name: str
    source_ip: str
    aws_region: Optional[str] = "us-east-1"
    status: Optional[str] = "Success"
    error_code: Optional[str] = None
    request_count: Optional[int] = 1
    bytes_transferred: Optional[int] = 0
    zscore_value: Optional[float] = 0.0
    is_zscore_anomaly: Optional[bool] = False
    iforest_score: Optional[float] = 0.0
    is_iforest_anomaly: Optional[bool] = False
    cloudtrail_rules_triggered: Optional[List[str]] = Field(default_factory=list)
    final_severity: Optional[str] = "LOW"
    is_anomaly: Optional[bool] = False
    ai_explanation: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class LogListResponse(BaseModel):
    """Resposta paginada da listagem de logs."""
    total: int
    limit: int
    offset: int
    items: List[LogItem]


class AnomalyItem(BaseModel):
    """Detalhes completos de uma anomalia consolidada."""
    id: Optional[int] = None
    event_id: str
    timestamp: str
    event_name: str
    user_name: str
    source_ip: str
    detectors_triggered: List[str] = Field(default_factory=list)
    max_score: float
    severity: str
    scenario: Optional[str] = None
    explanation: Optional[str] = None
    details: Optional[Any] = None
    created_at: Optional[str] = None


class AnomalyListResponse(BaseModel):
    """Lista de anomalias registradas."""
    total: int
    items: List[AnomalyItem]


class PipelineRunRequest(BaseModel):
    """Payload de solicitação para disparo do pipeline de auditoria."""
    log_file: str = Field(default="data/logs_simulados.jsonl", description="Caminho do arquivo JSONL")
    explain_critical: bool = Field(default=False, description="Gera laudos via IA para eventos CRITICAL/HIGH")


class PipelineRunResponse(BaseModel):
    """Relatório quantitativo da execução do pipeline."""
    status: str
    file_processed: str
    total_logs: int
    valid_logs: int
    corrupted_lines: int
    total_anomalies_detected: int
    saved_to_db: int
    severity_distribution: Dict[str, int]


class ExplainResponse(BaseModel):
    """Laudo pericial e plano de mitigação gerado por IA."""
    event_id: str
    explanation: str
