"""Pipeline de ponta a ponta: Ingestão LGMS -> Feature Engineering -> Detectores -> Persistência."""

import argparse
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional
from secops_core.db import bulk_insert, save_anomalies, update_anomaly_explanation
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

    # 6. Persistência no Banco SQLite (Logs Processados e Alertas Consolidados)
    saved_count = 0
    if save_to_db:
        # Prepara mapeamento das anomalias consolidadas por event_id
        anom_map: Dict[str, ConsolidatedAnomaly] = {a.event_id: a for a in consolidated_anomalies}

        # Constrói registros enriquecidos para todos os logs ingeridos
        all_processed_records: List[Dict[str, Any]] = []
        for log in logs:
            anom = anom_map.get(log.event_id)
            is_anom = anom is not None

            zscore_val = 0.0
            is_zscore = False
            iforest_val = 0.0
            is_iforest = False
            rules_triggered: List[str] = []

            if is_anom:
                for r in anom.detector_results:
                    dname = r.detector_name
                    if "ZScore" in dname:
                        zscore_val = float(r.anomaly_score)
                        is_zscore = True
                    elif "IsolationForest" in dname:
                        iforest_val = float(r.anomaly_score)
                        is_iforest = True
                    elif "Rule" in dname or "CloudTrail" in dname:
                        rules_triggered.extend(r.details.get("rule_codes", [r.scenario or dname]))

                all_processed_records.append({
                    "event_id": log.event_id,
                    "timestamp": str(log.timestamp),
                    "event_name": log.event_name,
                    "event_source": log.event_source,
                    "user_name": log.user_identity.userName,
                    "user_arn": log.user_identity.arn,
                    "source_ip": log.source_ip,
                    "aws_region": log.aws_region,
                    "status": log.status,
                    "error_code": log.error_code,
                    "request_count": log.request_count,
                    "bytes_transferred": log.bytes_transferred,
                    "metadata": log.metadata,
                    "zscore_value": zscore_val,
                    "is_zscore_anomaly": is_zscore,
                    "iforest_score": iforest_val,
                    "is_iforest_anomaly": is_iforest,
                    "cloudtrail_rules_triggered": list(set(rules_triggered)),
                    "final_severity": anom.max_severity,
                    "is_anomaly": True,
                    "ai_explanation": getattr(anom, "explanation", None),
                })
            else:
                all_processed_records.append({
                    "event_id": log.event_id,
                    "timestamp": str(log.timestamp),
                    "event_name": log.event_name,
                    "event_source": log.event_source,
                    "user_name": log.user_identity.userName,
                    "user_arn": log.user_identity.arn,
                    "source_ip": log.source_ip,
                    "aws_region": log.aws_region,
                    "status": log.status,
                    "error_code": log.error_code,
                    "request_count": log.request_count,
                    "bytes_transferred": log.bytes_transferred,
                    "metadata": log.metadata,
                    "zscore_value": 0.0,
                    "is_zscore_anomaly": False,
                    "iforest_score": 0.0,
                    "is_iforest_anomaly": False,
                    "cloudtrail_rules_triggered": [],
                    "final_severity": "LOW",
                    "is_anomaly": False,
                    "ai_explanation": None,
                })

        # Insere todos os logs na tabela processed_logs
        bulk_insert(all_processed_records)
        # Salva anomalias consolidadas na tabela anomalies
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
    parser.add_argument("--output", type=str, default=None, help="Caminho para exportar o sumário JSON do resultado")

    args = parser.parse_args()

    print(f"🛡️ Executando pipeline em '{args.file}'...")
    res = run_pipeline(
        log_file=args.file,
        save_to_db=not args.no_db,
        explain_critical=args.explain,
    )

    if args.output:
        import json
        with open(args.output, "w", encoding="utf-8") as f:
            clean_res = {k: v for k, v in res.items() if k != "anomalies"}
            json.dump(clean_res, f, indent=2, ensure_ascii=False)
        print(f"📄 Resultado exportado para: {args.output}")

    print("\n✅ Pipeline concluído com sucesso!")
    print(f"   Logs processados:       {res['valid_logs']}")
    print(f"   Anomalias detectadas:   {res['total_anomalies_detected']}")
    print(f"   Distribuição:           {res['severity_distribution']}")
    print(f"   Gravadas no SQLite:     {res['saved_to_db']}")


if __name__ == "__main__":
    main()
