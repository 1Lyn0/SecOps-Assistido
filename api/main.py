"""Ponto de entrada FastAPI para o serviço SecOps Assistido."""

import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from typing import List, Optional
from fastapi import FastAPI, HTTPException, Query, status
from api.schemas import (
    AnomalyItem,
    AnomalyListResponse,
    ExplainResponse,
    HealthResponse,
    LogItem,
    LogListResponse,
    PipelineRunRequest,
    PipelineRunResponse,
    StatsResponse,
)
from secops_core.config import settings
from secops_core.db import (
    count_processed_logs,
    get_anomalies,
    get_anomaly_by_event_id,
    get_connection,
    get_db_stats,
    get_processed_log_by_event_id,
    get_processed_logs,
    update_anomaly_explanation,
)
from secops_core.explainer.ollama_client import OllamaClient
from secops_core.pipeline import run_pipeline

app = FastAPI(
    title="SecOps Assistido API",
    description="API de auditoria de segurança em nuvem, detecção de anomalias (Z-Score, Isolation Forest & Regras) e explicabilidade com LLM",
    version="0.1.0",
)


@app.get("/health", response_model=HealthResponse, tags=["Infra"], summary="Verificação de integridade da API, SQLite e Ollama")
def health_check() -> HealthResponse:
    """Verifica a integridade da API, testando a conexão com o banco SQLite e com o serviço Ollama local."""
    # 1. Checagem do Banco SQLite
    db_status = "connected"
    try:
        with get_connection() as conn:
            conn.execute("SELECT 1").fetchone()
    except Exception:
        db_status = "error"

    # 2. Checagem do Ollama Local
    ollama_client = OllamaClient()
    ollama_status = "connected" if ollama_client.check_health() else "disconnected"

    return HealthResponse(
        status="ok" if db_status == "connected" else "degraded",
        database=db_status,
        ollama=ollama_status,
        version="0.1.0",
        service="secops-api",
    )


@app.get("/stats", response_model=StatsResponse, tags=["Auditoria"], summary="Resumo executivo consolidado de SecOps")
def stats() -> StatsResponse:
    """Retorna métricas consolidadas: total de logs, total de anomalias, taxa percentual, distribuições e top riscos."""
    raw_stats = get_db_stats()
    return StatsResponse(
        total_logs_analyzed=raw_stats.get("total_logs_analyzed", 0),
        total_anomalies=raw_stats.get("total_anomalies", 0),
        anomaly_rate=raw_stats.get("anomaly_rate", 0.0),
        severity_distribution=raw_stats.get("severity_distribution", {}),
        detector_distribution=raw_stats.get("detector_distribution", {}),
        top_anomalous_events=raw_stats.get("top_anomalous_events", {}),
        top_suspicious_ips=raw_stats.get("top_suspicious_ips", {}),
    )


@app.get("/logs", response_model=LogListResponse, tags=["Auditoria"], summary="Listagem paginada de logs com filtros combinados")
def list_logs(
    is_anomaly: Optional[bool] = Query(None, description="Filtrar apenas anomalias (true) ou normais (false)"),
    severity: Optional[str] = Query(None, description="Filtrar por severidade: LOW, MEDIUM, HIGH, CRITICAL"),
    event_name: Optional[str] = Query(None, description="Filtro parcial por nome do evento de API"),
    user: Optional[str] = Query(None, description="Filtro parcial por usuário/identidade"),
    source_ip: Optional[str] = Query(None, description="Filtro parcial por endereço IP"),
    detector_type: Optional[str] = Query(None, description="Filtrar por tipo de detector: zscore, iforest, rule"),
    limit: int = Query(50, ge=1, le=500, description="Quantidade máxima de itens por página"),
    offset: int = Query(0, ge=0, description="Offset de paginação"),
) -> LogListResponse:
    """Consulta os logs processados e enriquecidos com filtros combinados e paginação."""
    total_matches = count_processed_logs(
        is_anomaly=is_anomaly,
        final_severity=severity,
        event_name=event_name,
        user_name=user,
        source_ip=source_ip,
        detector_type=detector_type,
    )
    raw_items = get_processed_logs(
        is_anomaly=is_anomaly,
        final_severity=severity,
        event_name=event_name,
        user_name=user,
        source_ip=source_ip,
        detector_type=detector_type,
        limit=limit,
        offset=offset,
    )
    return LogListResponse(
        total=total_matches,
        limit=limit,
        offset=offset,
        items=[LogItem(**it) for it in raw_items],
    )


@app.get("/anomalies", response_model=AnomalyListResponse, tags=["Auditoria"], summary="Listagem de anomalias consolidadas")
def list_anomalies(
    severity: Optional[str] = Query(None, description="Filtrar por severidade: LOW, MEDIUM, HIGH, CRITICAL"),
    detector: Optional[str] = Query(None, description="Filtrar por detector: ZScore, IsolationForest, Rule"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> AnomalyListResponse:
    """Lista anomalias detectadas com suporte a filtros e paginação."""
    items = get_anomalies(severity=severity, detector=detector, limit=limit, offset=offset)
    return AnomalyListResponse(total=len(items), items=[AnomalyItem(**it) for it in items])


@app.get("/anomalies/{event_id}", response_model=AnomalyItem, tags=["Auditoria"], summary="Detalhes completos de uma anomalia")
def get_anomaly_details(event_id: str) -> AnomalyItem:
    """Recupera detalhes completos de um alerta específico, incluindo scores e explicação da IA."""
    item = get_anomaly_by_event_id(event_id)
    if not item:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Anomalia com event_id '{event_id}' não encontrada.",
        )
    return AnomalyItem(**item)


@app.post("/anomalies/{event_id}/explain", response_model=ExplainResponse, tags=["Explicabilidade"], summary="Gera laudo técnico via LLM")
def explain_anomaly_endpoint(event_id: str, force: bool = Query(False)) -> ExplainResponse:
    """Gera ou recupera a explicação técnica detalhada via LLM (Ollama ou Fallback Jinja2) para uma anomalia."""
    item = get_anomaly_by_event_id(event_id)
    if not item:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Anomalia com event_id '{event_id}' não encontrada.",
        )

    # Se já houver laudo gerado e não foi forçado reprocessamento, retorna o existente
    if item.get("explanation") and not force:
        return ExplainResponse(event_id=event_id, explanation=item["explanation"])

    # Dispara geração pelo OllamaClient com Fallback Inteligente Jinja2
    ollama_client = OllamaClient()
    context = {
        "event_id": item["event_id"],
        "timestamp": item["timestamp"],
        "event_name": item["event_name"],
        "user_name": item["user_name"],
        "source_ip": item["source_ip"],
        "severity": item["severity"],
        "detectors_triggered": item.get("detectors_triggered", []),
        "max_score": item.get("max_score", 0.0),
        "scenario": item.get("scenario"),
        "details": item.get("details"),
    }
    explanation = ollama_client.explain_and_persist(event_id, context)

    return ExplainResponse(event_id=event_id, explanation=explanation)


@app.post("/pipeline/run", response_model=PipelineRunResponse, tags=["Pipeline"], summary="Executa o pipeline completo de detecção")
def execute_pipeline(payload: PipelineRunRequest) -> PipelineRunResponse:
    """Executa o pipeline completo de detecção de anomalias sobre arquivo JSONL."""
    try:
        res = run_pipeline(
            log_file=payload.log_file,
            save_to_db=True,
            explain_critical=payload.explain_critical,
        )
        return PipelineRunResponse(
            status=res["status"],
            file_processed=res["file_processed"],
            total_logs=res["total_logs"],
            valid_logs=res["valid_logs"],
            corrupted_lines=res["corrupted_lines"],
            total_anomalies_detected=res["total_anomalies_detected"],
            saved_to_db=res["saved_to_db"],
            severity_distribution=res["severity_distribution"],
        )
    except FileNotFoundError as err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err))
    except Exception as err:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Erro interno no pipeline: {err}")


@app.get("/", tags=["Infra"], summary="Raiz da API")
def root():
    return {
        "message": "SecOps Assistido API está ativa.",
        "docs": "/docs",
        "health": "/health",
    }
