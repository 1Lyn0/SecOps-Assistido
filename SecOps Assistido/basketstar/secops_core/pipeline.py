"""Pipeline de ponta a ponta: Ingestão LGMS -> Feature Engineering -> Detectores -> Persistência."""

import argparse
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional
from secops_core.db import save_anomalies, update_anomaly_explanation
from secops_core.detectors.engine import ConsolidatedAnomaly, DetectionEngine
from secops_core.explainer.llm_explainer import LLMExplainer
from secops_core.lgms import extract_features, parse_logs_file

logger = logging.getLogger("secops_core.pipeline")


def run_pipeline(
    log_file: str = "data/logs_simulados.jsonl",
    save_to_db: bool = True,
    explain_critical: bool = False,
    engine: Optional[DetectionEngine] = None,
) -> Dict[str, Any]:
    """Executa o pipeline completo de detecção e auditoria de SecOps.

    Etapas:
    1. Parse e validação canônica de logs via LGMS.
    2. Extração de features temporais, categóricas e volumétricas.
    3. Execução do ensemble de detectores (Z-Score, Isolation Forest, Regras).
    4. Consolidação de alertas multidimensionais.
    5. Opcional: Geração de laudo analítico via LLM para alertas críticos.
    6. Persistência dos resultados no SQLite.

    Returns:
        Dicionário com métricas de execução e anomalias consolidadas.
    """
    path = Path(log_file)
    if not path.is_file():
        raise FileNotFoundError(f"Arquivo de logs não encontrado em: {path}")

    # 1. Parse de Logs via LGMS
    logs, summary = parse_logs_file(path)
    if not logs:
        return {
            "total_logs": 0,
            "anomalies_detected": 0,
            "anomalies": [],
            "summary": summary.model_dump(),
        }

    # 2. Extração de Features
    df_features = extract_features(logs)

    # 3 & 4. Execução e Consolidação de Detectores
    detector_engine = engine or DetectionEngine()
    consolidated_anomalies = detector_engine.run_and_consolidate(df_features)

    # 5. Opcional: Laudos por IA para eventos Críticos/Altos
    if explain_critical:
        explainer = LLMExplainer()
        for anom in consolidated_anomalies:
            if anom.max_severity in ("CRITICAL", "HIGH"):
                ctx = {
                    "event_id": anom.event_id,
                    "timestamp": anom.timestamp,
                    "event_name": anom.event_name,
                    "user_name": anom.user_name,
                    "source_ip": anom.source_ip,
                    "severity": anom.max_severity,
                    "detectors_triggered": anom.detectors_triggered,
                    "max_score": anom.max_score,
                    "scenario": anom.scenario,
                }
                laudo = explainer.explain_anomaly(ctx)
                # Anexa temporariamente no objeto consolidado
                setattr(anom, "explanation", laudo)

    # 6. Persistência no Banco SQLite
    saved_count = 0
    if save_to_db:
        saved_count = save_anomalies(consolidated_anomalies)

    # Distribuição de severidade
    sev_counts: Dict[str, int] = {}
    for anom in consolidated_anomalies:
        sev_counts[anom.max_severity] = sev_counts.get(anom.max_severity, 0) + 1

    return {
        "status": "success",
        "file_processed": str(path),
        "total_logs": summary.total_lines,
        "valid_logs": summary.valid_logs,
        "corrupted_lines": summary.corrupted_lines,
        "total_anomalies_detected": len(consolidated_anomalies),
        "saved_to_db": saved_count,
        "severity_distribution": sev_counts,
        "anomalies": consolidated_anomalies,
    }


def main() -> None:
    """Interface CLI para rodar o pipeline no terminal."""
    parser = argparse.ArgumentParser(description="Pipeline de auditoria e detecção de SecOps")
    parser.add_argument("--file", type=str, default="data/logs_simulados.jsonl", help="Caminho do arquivo JSONL")
    parser.add_argument("--explain", action="store_true", help="Gera laudos explicativos para eventos críticos")
    parser.add_argument("--no-db", action="store_true", help="Não grava os resultados no SQLite")

    args = parser.parse_args()

    print(f"🛡️ Executando pipeline em '{args.file}'...")
    res = run_pipeline(
        log_file=args.file,
        save_to_db=not args.no_db,
        explain_critical=args.explain,
    )

    print("\n✅ Pipeline concluído com sucesso!")
    print(f"   Logs processados:       {res['valid_logs']}")
    print(f"   Anomalias detectadas:   {res['total_anomalies_detected']}")
    print(f"   Distribuição:           {res['severity_distribution']}")
    print(f"   Gravadas no SQLite:     {res['saved_to_db']}")


if __name__ == "__main__":
    main()
