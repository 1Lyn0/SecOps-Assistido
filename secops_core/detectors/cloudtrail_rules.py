"""Motor e catálogo modular de regras determinísticas de segurança para AWS CloudTrail."""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Union
import pandas as pd
from secops_core.detectors.base import AnomalyResult, BaseDetector


# ============================================================================
# 1. Interface Base Abstrata para Regras Modulares
# ============================================================================

class BaseCloudTrailRule(ABC):
    """Classe base abstrata para regras determinísticas de segurança CloudTrail."""

    rule_code: str
    rule_name: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    description: str
    mitre_technique: str

    @abstractmethod
    def evaluate(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Avalia um único evento CloudTrail.

        Returns:
            Dict com os detalhes da violação caso o evento viole a regra,
            ou None se o evento estiver em conformidade.
        """
        pass

    def to_dict(self) -> Dict[str, Any]:
        """Retorna metadados da regra documentada."""
        return {
            "rule_code": self.rule_code,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "description": self.description,
            "mitre_technique": self.mitre_technique,
        }


# ============================================================================
# 2. Catálogo de Regras Determinísticas de CloudTrail
# ============================================================================

class RuleTrailTampering(BaseCloudTrailRule):
    """Regra 1: Detecta adulteração, desativação ou exclusão de trilhas de auditoria."""

    rule_code = "RULE_TRAIL_TAMPERING"
    rule_name = "CloudTrail Tampering / Deletion"
    severity = "CRITICAL"
    description = (
        "Detecta tentativas de desativar (StopLogging), deletar (DeleteTrail) ou "
        "modificar filtros/configurações críticas de trilhas de auditoria CloudTrail."
    )
    mitre_technique = "T1562.001 - Impair Defenses: Disable Cloud Logs"

    TAMPERING_ACTIONS = {
        "deletetrail",
        "stoplogging",
        "updatetrail",
        "puteventselectors",
        "deleteeventselectors",
    }

    def evaluate(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        event_name = str(event.get("event_name", "")).strip().lower()
        event_source = str(event.get("event_source", "")).strip().lower()

        if event_name in self.TAMPERING_ACTIONS or ("cloudtrail" in event_source and "delete" in event_name):
            return {
                "rule_code": self.rule_code,
                "rule_name": self.rule_name,
                "severity": self.severity,
                "technical_reason": f"Ação hostil de auditoria detectada: {event.get('event_name')} no serviço {event.get('event_source')}.",
                "mitre_technique": self.mitre_technique,
            }
        return None


class RuleIAMPrivilegeEscalation(BaseCloudTrailRule):
    """Regra 2: Detecta escalação de privilégios e alteração sensível de permissões IAM."""

    rule_code = "RULE_IAM_PRIVILEGE_ESCALATION"
    rule_name = "IAM Privilege Escalation / Sensitive Policy Tampering"
    severity = "HIGH"
    description = (
        "Identifica criação ou vinculação de políticas inline/administrador, "
        "criação de Access Keys não autorizadas ou alteração de Trust Relationships."
    )
    mitre_technique = "T1098 - Account Manipulation"

    ESCALATION_ACTIONS = {
        "putuserpolicy",
        "attachuserpolicy",
        "putrolepolicy",
        "attachrolepolicy",
        "putgrouppolicy",
        "attachgrouppolicy",
        "createaccesskey",
        "createloginprofile",
        "updateassumerolepolicy",
        "addusertogroup",
    }

    def evaluate(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        event_name = str(event.get("event_name", "")).strip().lower()
        event_source = str(event.get("event_source", "")).strip().lower()

        if event_name in self.ESCALATION_ACTIONS or ("iam" in event_source and ("policy" in event_name or "accesskey" in event_name)):
            return {
                "rule_code": self.rule_code,
                "rule_name": self.rule_name,
                "severity": self.severity,
                "technical_reason": f"Modificação de privilégios IAM detectada via '{event.get('event_name')}'.",
                "mitre_technique": self.mitre_technique,
            }
        return None


class RuleRootActivity(BaseCloudTrailRule):
    """Regra 3: Detecta qualquer atividade originada diretamente da conta Root da AWS."""

    rule_code = "RULE_ROOT_ACTIVITY"
    rule_name = "AWS Root Account Direct Activity"
    severity = "CRITICAL"
    description = (
        "O uso da conta root da AWS viola as melhores práticas do CIS AWS Benchmark. "
        "Qualquer chamada de API ou login de console feito como Root deve gerar alerta crítico imediato."
    )
    mitre_technique = "T1078.004 - Valid Accounts: Cloud Accounts (Root)"

    def evaluate(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        user_name = str(event.get("user_name", "")).strip().lower()
        user_identity = event.get("user_identity", {})

        is_root = False
        if user_name in ("root", "aws-root"):
            is_root = True
        elif isinstance(user_identity, dict) and str(user_identity.get("type", "")).lower() == "root":
            is_root = True

        if is_root:
            return {
                "rule_code": self.rule_code,
                "rule_name": self.rule_name,
                "severity": self.severity,
                "technical_reason": f"Uso direto detectado da credencial Root da conta AWS para o evento '{event.get('event_name')}'.",
                "mitre_technique": self.mitre_technique,
            }
        return None


class RuleBruteForceConsole(BaseCloudTrailRule):
    """Regra 4: Detecta tentativas de login falhas ou força bruta no console AWS."""

    rule_code = "RULE_BRUTE_FORCE_CONSOLE"
    rule_name = "Console Login Failure / Brute Force Guessing"
    severity = "HIGH"
    description = (
        "Detecta tentativas falhas de login de console (ConsoleLogin com Failure) "
        "indicando adivinhação de senhas ou força bruta contra identidades IAM."
    )
    mitre_technique = "T1110 - Brute Force / Credential Guessing"

    def evaluate(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        event_name = str(event.get("event_name", "")).strip().lower()
        event_source = str(event.get("event_source", "")).strip().lower()
        status = str(event.get("status", "")).strip().lower()
        error_code = str(event.get("error_code", "")).strip().lower()
        is_error = int(event.get("is_error", 0)) == 1

        is_login = "login" in event_name or "signin" in event_source
        has_failed = (
            status in ("failure", "failed")
            or is_error
            or any(err in error_code for err in ["failedauth", "unauthorized", "accessdenied"])
        )

        if is_login and has_failed:
            return {
                "rule_code": self.rule_code,
                "rule_name": self.rule_name,
                "severity": self.severity,
                "technical_reason": f"Falha de autenticação detectada no console para '{event.get('user_name', 'Unknown')}'.",
                "mitre_technique": self.mitre_technique,
            }
        return None


class RuleUnauthorizedAPIBurst(BaseCloudTrailRule):
    """Regra 5: Detecta erros repetidos de acesso negado ou chamadas não autorizadas."""

    rule_code = "RULE_UNAUTHORIZED_API_BURST"
    rule_name = "Unauthorized API Calls / AccessDenied Burst"
    severity = "MEDIUM"
    description = (
        "Identifica eventos com erro explícito de autorização (AccessDenied ou UnauthorizedOperation), "
        "comum em varreduras de superfície de ataque ou enumeração de recursos."
    )
    mitre_technique = "T1087 - Account / Permission Discovery"

    def evaluate(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        status = str(event.get("status", "")).strip().lower()
        error_code = str(event.get("error_code", "")).strip().lower()
        event_name = str(event.get("event_name", "")).strip().lower()

        # Ignora falhas de login que são capturadas pela regra de força bruta
        if "login" in event_name or "signin" in str(event.get("event_source", "")).lower():
            return None

        is_unauth = (
            "accessdenied" in error_code
            or "unauthorizedoperation" in error_code
            or (status in ("failure", "failed") and "client." in error_code)
        )

        if is_unauth:
            return {
                "rule_code": self.rule_code,
                "rule_name": self.rule_name,
                "severity": self.severity,
                "technical_reason": f"Chamada de API '{event.get('event_name')}' rejeitada por falta de privilégios ({event.get('error_code')}).",
                "mitre_technique": self.mitre_technique,
            }
        return None


class RuleSensitiveS3PublicAccess(BaseCloudTrailRule):
    """Regra 6: Detecta desativação de proteção pública em buckets S3 ou alteração de ACLs."""

    rule_code = "RULE_SENSITIVE_S3_PUBLIC_ACCESS"
    rule_name = "S3 Public Access Block Removal / Sensitive Bucket ACL"
    severity = "HIGH"
    description = (
        "Detecta ações que expõem buckets S3 publicamente à internet, como remoção "
        "de Block Public Access ou aplicação de políticas permissivas (PutBucketAcl / PutBucketPolicy)."
    )
    mitre_technique = "T1530 - Data from Cloud Storage Object"

    S3_SENSITIVE_ACTIONS = {
        "deletebucketpublicaccessblock",
        "putbucketpublicaccessblock",
        "putbucketacl",
        "putbucketpolicy",
        "deletebucketpolicy",
        "putaccountpublicaccessblock",
    }

    def evaluate(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        event_name = str(event.get("event_name", "")).strip().lower()
        event_source = str(event.get("event_source", "")).strip().lower()

        if event_name in self.S3_SENSITIVE_ACTIONS or ("s3" in event_source and "publicaccessblock" in event_name):
            return {
                "rule_code": self.rule_code,
                "rule_name": self.rule_name,
                "severity": self.severity,
                "technical_reason": f"Alteração crítica de segurança de acesso público no Amazon S3 via '{event.get('event_name')}'.",
                "mitre_technique": self.mitre_technique,
            }
        return None


class RuleNetworkPerimeterTampering(BaseCloudTrailRule):
    """Regra 7 (Bônus): Detecta enfraquecimento de firewalls / grupos de segurança."""

    rule_code = "RULE_NETWORK_PERIMETER_TAMPERING"
    rule_name = "Security Group / Firewall Ingress Tampering"
    severity = "MEDIUM"
    description = (
        "Detecta abertura de regras de entrada permissivas em grupos de segurança EC2 "
        "ou desativação de VPC Flow Logs."
    )
    mitre_technique = "T1562.007 - Impair Defenses: Disable Cloud Firewalls"

    NETWORK_ACTIONS = {
        "authorizesecuritygroupingress",
        "revokesecuritygroupegress",
        "deleteflowlogs",
        "createflowlogs",
    }

    def evaluate(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        event_name = str(event.get("event_name", "")).strip().lower()

        if event_name in self.NETWORK_ACTIONS:
            return {
                "rule_code": self.rule_code,
                "rule_name": self.rule_name,
                "severity": self.severity,
                "technical_reason": f"Modificação de perímetro de rede/firewall detectada via '{event.get('event_name')}'.",
                "mitre_technique": self.mitre_technique,
            }
        return None


class RuleSuspiciousIP(BaseCloudTrailRule):
    """Regra 8 (Heurística): Detecta requisições de IPs suspeitos ou de rede de anonimização/Tor."""

    rule_code = "RULE_SUSPICIOUS_IP"
    rule_name = "Suspicious / Tor Exit Node IP"
    severity = "MEDIUM"
    description = "Detecta conexões de infraestruturas conhecidas de proxy/Tor ou IPs de reputação maliciosa."
    mitre_technique = "T1090 - Proxy / Multi-hop Proxy"

    def evaluate(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        is_suspicious_ip = int(event.get("is_suspicious_ip", 0)) == 1
        if is_suspicious_ip:
            return {
                "rule_code": self.rule_code,
                "rule_name": self.rule_name,
                "severity": self.severity,
                "technical_reason": f"IP de origem suspeito/anônimo: {event.get('source_ip', 'Unknown')}.",
                "mitre_technique": self.mitre_technique,
            }
        return None


class RuleOffHoursActivity(BaseCloudTrailRule):
    """Regra 9 (Heurística): Acesso a infraestrutura crítica fora do horário comercial."""

    rule_code = "RULE_OFF_HOURS_ACTIVITY"
    rule_name = "Off-Hours Sensitive Activity"
    severity = "MEDIUM"
    description = "Detecta atividades sensíveis em horários não comerciais (madrugada ou fins de semana)."
    mitre_technique = "T1078 - Valid Accounts / Off-Hours Use"

    SENSITIVE_ACTIONS = {
        "authorizesecuritygroupingress",
        "describekeypairs",
        "createkeypair",
        "createaccesskey",
    }

    def evaluate(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        is_off_hours = int(event.get("is_off_hours", 0)) == 1
        event_name = str(event.get("event_name", "")).strip().lower()

        if is_off_hours and event_name in self.SENSITIVE_ACTIONS:
            return {
                "rule_code": self.rule_code,
                "rule_name": self.rule_name,
                "severity": self.severity,
                "technical_reason": f"Operação sensível '{event.get('event_name')}' realizada fora do expediente comercial.",
                "mitre_technique": self.mitre_technique,
            }
        return None


# ============================================================================
# 3. Motor Central Extensível de Regras CloudTrail
# ============================================================================

class CloudTrailRulesEngine(BaseDetector):
    """Motor de execução e avaliação modular de regras determinísticas de CloudTrail.

    Permite estender e registrar novas regras sem alterar o motor principal
    através do método `register_rule`.
    """

    SEVERITY_WEIGHTS = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    SEVERITY_SCORES = {"CRITICAL": 1.0, "HIGH": 0.85, "MEDIUM": 0.70, "LOW": 0.50}

    def __init__(
        self,
        rules: Optional[List[BaseCloudTrailRule]] = None,
        name: str = "CloudTrailRulesEngine",
    ):
        super().__init__(name=name)
        if rules is not None:
            self.rules: List[BaseCloudTrailRule] = list(rules)
        else:
            self.rules = [
                RuleTrailTampering(),
                RuleIAMPrivilegeEscalation(),
                RuleRootActivity(),
                RuleBruteForceConsole(),
                RuleUnauthorizedAPIBurst(),
                RuleSensitiveS3PublicAccess(),
                RuleNetworkPerimeterTampering(),
            ]

    def register_rule(self, rule: BaseCloudTrailRule) -> None:
        """Registra uma nova regra determinística no motor sem alterar o core."""
        self.rules.append(rule)

    def evaluate_log(self, event: Union[Dict[str, Any], pd.Series]) -> List[Dict[str, Any]]:
        """Avalia um log e retorna a lista de regras violadas (ou vazia se nenhuma for disparada)."""
        event_dict = event.to_dict() if isinstance(event, pd.Series) else dict(event)
        violations: List[Dict[str, Any]] = []

        for rule in self.rules:
            violation = rule.evaluate(event_dict)
            if violation is not None:
                violations.append(violation)

        return violations

    def annotate_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """Anexa violações de regras a cada linha do DataFrame sem alterar colunas originais."""
        df_out = df.copy()
        all_violations = []
        is_violated = []

        for _, row in df_out.iterrows():
            violations = self.evaluate_log(row)
            all_violations.append(violations)
            is_violated.append(len(violations) > 0)

        df_out["violated_rules"] = all_violations
        df_out["is_rule_violated"] = is_violated
        return df_out

    def detect(self, df: pd.DataFrame) -> List[AnomalyResult]:
        """Processa o DataFrame e retorna a lista de anomalias com as regras violadas."""
        if df.empty:
            return []

        results: List[AnomalyResult] = []

        for _, row in df.iterrows():
            event_dict = row.to_dict()
            violations = self.evaluate_log(event_dict)

            if violations:
                # Ordena violações pela maior severidade
                violations.sort(
                    key=lambda v: self.SEVERITY_WEIGHTS.get(v["severity"], 1),
                    reverse=True,
                )
                top_violation = violations[0]
                top_severity = top_violation["severity"]
                score = self.SEVERITY_SCORES.get(top_severity, 0.7)

                event_name = str(row.get("event_name", "Unknown"))
                user_name = str(row.get("user_name", "Unknown"))
                source_ip = str(row.get("source_ip", "Unknown"))

                results.append(
                    AnomalyResult(
                        event_id=str(row.get("event_id", "")),
                        timestamp=str(row.get("timestamp", "")),
                        event_name=event_name,
                        user_name=user_name,
                        source_ip=source_ip,
                        detector_name=self.name,
                        anomaly_score=score,
                        is_anomaly=True,
                        severity=top_severity,
                        scenario=row.get("scenario") if pd.notna(row.get("scenario")) else None,
                        details={
                            "matched_rules": violations,
                            "violated_rules": violations,
                            "primary_rule": top_violation["rule_code"],
                            "rule_codes": [v["rule_code"] for v in violations],
                            "technical_reason": top_violation["technical_reason"],
                            "mitre_technique": top_violation["mitre_technique"],
                        },
                    )
                )

        return results
