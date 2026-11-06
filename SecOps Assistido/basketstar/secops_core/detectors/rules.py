"""Detector determinístico baseado em assinaturas e regras heurísticas de SecOps."""

from typing import Any, Dict, List
import pandas as pd
from secops_core.detectors.base import AnomalyResult, BaseDetector


class RuleBasedDetector(BaseDetector):
    """Detector baseado em regras e assinaturas de segurança alinhadas ao MITRE ATT&CK.

    Regras aplicadas:
    1. DEFENSE_EVASION: Tentativas de deletar ou desativar trilhas de auditoria (DeleteTrail, StopLogging).
    2. PRIVILEGE_ESCALATION: Alteração de políticas de permissão (PutUserPolicy, AttachUserPolicy).
    3. BRUTE_FORCE: Tentativas de login falhas ou com credenciais inválidas.
    4. OFF_HOURS_ACCESS: Ações sensíveis fora do horário comercial (madrugadas e fins de semana).
    5. SUSPICIOUS_IP: Requisições com origem em blocos de IP maliciosos conhecidos ou rede Tor.
    """

    def __init__(self, name: str = "RuleBasedDetector"):
        super().__init__(name=name)

    def detect(self, df: pd.DataFrame) -> List[AnomalyResult]:
        """Avalia cada linha do DataFrame com base em regras heurísticas de segurança."""
        if df.empty:
            return []

        results: List[AnomalyResult] = []

        for _, row in df.iterrows():
            event_name = str(row.get("event_name", "")).strip()
            event_name_lower = event_name.lower()
            event_src = str(row.get("event_source", "")).lower()

            is_error = int(row.get("is_error", 0)) == 1
            is_off_hours = int(row.get("is_off_hours", 0)) == 1
            is_suspicious_ip = int(row.get("is_suspicious_ip", 0)) == 1

            matched_rules: List[Dict[str, Any]] = []

            # Regra 1: Evasão de defesa (Crítica)
            if any(action in event_name for action in ["DeleteTrail", "StopLogging", "UpdateTrail"]) or "cloudtrail" in event_src and "delete" in event_name_lower:
                matched_rules.append({
                    "rule_id": "SEC-R001",
                    "title": "Defense Evasion - CloudTrail Tampering",
                    "severity": "CRITICAL",
                    "score": 1.0,
                    "mitre_technique": "T1562.001 - Impair Defenses: Disable Cloud Logs",
                })

            # Regra 2: Escalação de privilégios IAM (Alta)
            if any(action in event_name for action in ["PutUserPolicy", "AttachUserPolicy", "CreateAccessKey"]) or ("iam" in event_src and "policy" in event_name_lower):
                matched_rules.append({
                    "rule_id": "SEC-R002",
                    "title": "Privilege Escalation - IAM Policy Manipulation",
                    "severity": "HIGH",
                    "score": 0.88,
                    "mitre_technique": "T1098 - Account Manipulation",
                })

            # Regra 3: Falha de autenticação / Login suspeito (Alta)
            if ("login" in event_name_lower or "signin" in event_src) and is_error:
                matched_rules.append({
                    "rule_id": "SEC-R003",
                    "title": "Credential Access - ConsoleLogin Failure",
                    "severity": "HIGH",
                    "score": 0.82,
                    "mitre_technique": "T1110 - Brute Force / Password Guessing",
                })

            # Regra 4: Operação de infraestrutura em horário atípico (Média)
            if is_off_hours and event_name in ["AuthorizeSecurityGroupIngress", "DescribeKeyPairs", "CreateKeyPair"]:
                matched_rules.append({
                    "rule_id": "SEC-R004",
                    "title": "Initial Access - Off-Hours Sensitive Activity",
                    "severity": "MEDIUM",
                    "score": 0.70,
                    "mitre_technique": "T1078 - Valid Accounts / Off-Hours Use",
                })

            # Regra 5: IP malicioso conhecido (Média/Alta)
            if is_suspicious_ip:
                matched_rules.append({
                    "rule_id": "SEC-R005",
                    "title": "Command & Control - Known Suspicious / Tor IP",
                    "severity": "MEDIUM",
                    "score": 0.65,
                    "mitre_technique": "T1090 - Proxy / Tor Exit Node",
                })

            if matched_rules:
                # Prioriza a regra com maior severidade e score
                severity_weights = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
                matched_rules.sort(
                    key=lambda r: (severity_weights.get(r["severity"], 1), r["score"]),
                    reverse=True,
                )
                top_rule = matched_rules[0]

                results.append(
                    AnomalyResult(
                        event_id=str(row.get("event_id", "")),
                        timestamp=str(row.get("timestamp", "")),
                        event_name=event_name,
                        user_name=str(row.get("user_name", "Unknown")),
                        source_ip=str(row.get("source_ip", "Unknown")),
                        detector_name=self.name,
                        anomaly_score=top_rule["score"],
                        is_anomaly=True,
                        severity=top_rule["severity"],
                        scenario=row.get("scenario") if pd.notna(row.get("scenario")) else None,
                        details={
                            "matched_rules": matched_rules,
                            "primary_rule": top_rule["rule_id"],
                            "mitre_technique": top_rule["mitre_technique"],
                        },
                    )
                )

        return results
