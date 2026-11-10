"""Ponto de entrada FastAPI para o serviço SecOps Assistido."""

import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from typing import List, Optional
from fastapi import FastAPI, HTTPException, Query
from api.schemas import (
    AnomalyItem,
    AnomalyListResponse,
    ExplainResponse,
    HealthResponse,
    PipelineRunRequest,
    PipelineRunResponse,
)
from secops_core.config import settings
from secops_core.db import (
    get_anomalies,
    get_anomaly_by_event_id,
    get_db_stats,
    update_anomaly_explanation,
)
from secops_core.explainer.llm_explainer import LLMExplainer
from secops_core.pipeline import run_pipeline

app = FastAPI(
    title="SecOps Assistido API",
    description="API de auditoria de segurança, detecção de anomalias (Z-Score & ML) e explicabilidade com LLM",
    version="0.1.0",
)


@app.get("/health", response_model=HealthResponse, tags=["Infra"])
def health_check() -> HealthResponse:
    """Verifica a integridade e prontidão da API."""
    return HealthResponse()


@app.get("/stats", tags=["Auditoria"])
def stats():
    """Retorna estatísticas consolidadas das anomalias registradas."""
    return get_db_stats()


@app.post("/pipeline/run", response_model=PipelineRunResponse, tags=["Pipeline"])
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
        raise HTTPException(status_code=404, detail=str(err))
    except Exception as err:
        raise HTTPException(status_code=500, detail=f"Erro interno no pipeline: {err}")


@app.get("/anomalies", response_model=AnomalyListResponse, tags=["Auditoria"])
def list_anomalies(
    severity: Optional[str] = Query(None, description="Filtrar por severidade: LOW, MEDIUM, HIGH, CRITICAL"),
    detector: Optional[str] = Query(None, description="Filtrar por detector: ZScore, IsolationForest, Rule"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> AnomalyListResponse:
    """Lista anomalias detectadas com suporte a filtros e paginação."""
    items = get_anomalies(severity=severity, detector=detector, limit=limit, offset=offset)
    return AnomalyListResponse(total=len(items), items=items)


@app.get("/anomalies/{event_id}", response_model=AnomalyItem, tags=["Auditoria"])
def get_anomaly_details(event_id: str) -> AnomalyItem:
    """Recupera detalhes de uma anomalia específica por event_id."""
    item = get_anomaly_by_event_id(event_id)
    if not item:
        raise HTTPException(status_code=404, detail=f"Anomalia '{event_id}' não encontrada.")
    return AnomalyItem(**item)


@app.post("/anomalies/{event_id}/explain", response_model=ExplainResponse, tags=["Explicabilidade"])
def explain_anomaly_endpoint(event_id: str, force: bool = Query(False)) -> ExplainResponse:
    """Gera ou recupera a explicação técnica detalhada via LLM para uma anomalia."""
    item = get_anomaly_by_event_id(event_id)
    if not item:
        raise HTTPException(status_code=404, detail=f"Anomalia '{event_id}' não encontrada.")

    # Se já houver laudo gerado e não foi forçado reprocessamento, retorna o existente
    if item.get("explanation") and not force:
        return ExplainResponse(event_id=event_id, explanation=item["explanation"])

    # Dispara a geração pelo LLM Explainer
    explainer = LLMExplainer()
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
    explanation = explainer.explain_anomaly(context)

    # Atualiza o laudo no banco SQLite
    update_anomaly_explanation(event_id, explanation)

    return ExplainResponse(event_id=event_id, explanation=explanation)


@app.get("/", tags=["Infra"])
def root():
    return {
        "message": "SecOps Assistido API está ativa.",
        "docs": "/docs",
        "health": "/health",
    }
