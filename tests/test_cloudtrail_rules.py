"""Testes unitários dedicados ao motor de regras determinísticas de CloudTrail (MAO-13).

Critérios de Aceitação:
- Pelo menos 6 regras determinísticas de CloudTrail implementadas e documentadas.
- Cada log avaliado recebe a lista de regras violadas (ou lista vazia se nenhuma regra for disparada).
- Testes unitários garantindo 100% de precisão nos eventos que violam cada regra.
- Retorno de código da regra, nome amigável, severidade (LOW, MEDIUM, HIGH, CRITICAL) e motivo técnico.
- Extensibilidade modular sem modificar o motor principal.
"""

import pandas as pd
import pytest
from secops_core.detectors.cloudtrail_rules import (
    BaseCloudTrailRule,
    CloudTrailRulesEngine,
    RuleBruteForceConsole,
    RuleIAMPrivilegeEscalation,
    RuleNetworkPerimeterTampering,
    RuleOffHoursActivity,
    RuleRootActivity,
    RuleSensitiveS3PublicAccess,
    RuleSuspiciousIP,
    RuleTrailTampering,
    RuleUnauthorizedAPIBurst,
)


def test_catalog_has_at_least_6_documented_rules():
    """Garante que pelo menos 6 regras determinísticas estão implementadas e documentadas."""
    engine = CloudTrailRulesEngine()
    assert len(engine.rules) >= 6

    for rule in engine.rules:
        meta = rule.to_dict()
        assert meta["rule_code"].startswith("RULE_")
        assert meta["rule_name"]
        assert meta["severity"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
        assert len(meta["description"]) > 10
        assert "T" in meta["mitre_technique"]  # Alinhamento ao MITRE ATT&CK


def test_rule_trail_tampering_precision():
    """Valida 100% de precisão para a regra RULE_TRAIL_TAMPERING."""
    rule = RuleTrailTampering()

    # Violações
    assert rule.evaluate({"event_name": "DeleteTrail", "event_source": "cloudtrail.amazonaws.com"}) is not None
    assert rule.evaluate({"event_name": "StopLogging", "event_source": "cloudtrail.amazonaws.com"}) is not None
    assert rule.evaluate({"event_name": "UpdateTrail", "event_source": "cloudtrail.amazonaws.com"}) is not None

    violation = rule.evaluate({"event_name": "DeleteTrail", "event_source": "cloudtrail.amazonaws.com"})
    assert violation["rule_code"] == "RULE_TRAIL_TAMPERING"
    assert violation["severity"] == "CRITICAL"
    assert "Ação hostil" in violation["technical_reason"]

    # Não violações
    assert rule.evaluate({"event_name": "DescribeTrails", "event_source": "cloudtrail.amazonaws.com"}) is None
    assert rule.evaluate({"event_name": "GetTrailStatus", "event_source": "cloudtrail.amazonaws.com"}) is None
    assert rule.evaluate({"event_name": "LookupEvents", "event_source": "cloudtrail.amazonaws.com"}) is None


def test_rule_iam_privilege_escalation_precision():
    """Valida 100% de precisão para a regra RULE_IAM_PRIVILEGE_ESCALATION."""
    rule = RuleIAMPrivilegeEscalation()

    # Violações
    assert rule.evaluate({"event_name": "PutUserPolicy", "event_source": "iam.amazonaws.com"}) is not None
    assert rule.evaluate({"event_name": "AttachUserPolicy", "event_source": "iam.amazonaws.com"}) is not None
    assert rule.evaluate({"event_name": "CreateAccessKey", "event_source": "iam.amazonaws.com"}) is not None
    assert rule.evaluate({"event_name": "CreateLoginProfile", "event_source": "iam.amazonaws.com"}) is not None

    violation = rule.evaluate({"event_name": "PutUserPolicy", "event_source": "iam.amazonaws.com"})
    assert violation["rule_code"] == "RULE_IAM_PRIVILEGE_ESCALATION"
    assert violation["severity"] == "HIGH"
    assert "Modificação de privilégios IAM" in violation["technical_reason"]

    # Não violações
    assert rule.evaluate({"event_name": "GetUser", "event_source": "iam.amazonaws.com"}) is None
    assert rule.evaluate({"event_name": "ListUsers", "event_source": "iam.amazonaws.com"}) is None
    assert rule.evaluate({"event_name": "GetRole", "event_source": "iam.amazonaws.com"}) is None


def test_rule_root_activity_precision():
    """Valida 100% de precisão para a regra RULE_ROOT_ACTIVITY."""
    rule = RuleRootActivity()

    # Violações
    assert rule.evaluate({"event_name": "DescribeInstances", "user_name": "root"}) is not None
    assert rule.evaluate({"event_name": "GetCallerIdentity", "user_identity": {"type": "Root"}}) is not None

    violation = rule.evaluate({"event_name": "DescribeInstances", "user_name": "root"})
    assert violation["rule_code"] == "RULE_ROOT_ACTIVITY"
    assert violation["severity"] == "CRITICAL"
    assert "Root" in violation["technical_reason"]

    # Não violações
    assert rule.evaluate({"event_name": "DescribeInstances", "user_name": "alice_dev"}) is None
    assert rule.evaluate({"event_name": "GetObject", "user_identity": {"type": "IAMUser", "userName": "bob"}}) is None


def test_rule_brute_force_console_precision():
    """Valida 100% de precisão para a regra RULE_BRUTE_FORCE_CONSOLE."""
    rule = RuleBruteForceConsole()

    # Violações
    assert rule.evaluate({
        "event_name": "ConsoleLogin",
        "event_source": "signin.amazonaws.com",
        "status": "Failure",
        "error_code": "FailedAuthentication",
    }) is not None

    violation = rule.evaluate({
        "event_name": "ConsoleLogin",
        "event_source": "signin.amazonaws.com",
        "status": "Failure",
    })
    assert violation["rule_code"] == "RULE_BRUTE_FORCE_CONSOLE"
    assert violation["severity"] == "HIGH"

    # Não violações
    assert rule.evaluate({
        "event_name": "ConsoleLogin",
        "event_source": "signin.amazonaws.com",
        "status": "Success",
        "error_code": None,
    }) is None


def test_rule_unauthorized_api_burst_precision():
    """Valida 100% de precisão para a regra RULE_UNAUTHORIZED_API_BURST."""
    rule = RuleUnauthorizedAPIBurst()

    # Violações
    assert rule.evaluate({
        "event_name": "DescribeSecurityGroups",
        "event_source": "ec2.amazonaws.com",
        "error_code": "AccessDenied",
    }) is not None
    assert rule.evaluate({
        "event_name": "ListBuckets",
        "event_source": "s3.amazonaws.com",
        "error_code": "UnauthorizedOperation",
    }) is not None

    violation = rule.evaluate({"event_name": "DescribeKeyPairs", "error_code": "AccessDenied"})
    assert violation["rule_code"] == "RULE_UNAUTHORIZED_API_BURST"
    assert violation["severity"] == "MEDIUM"

    # Não violações (chamadas normais de API com sucesso)
    assert rule.evaluate({
        "event_name": "DescribeSecurityGroups",
        "event_source": "ec2.amazonaws.com",
        "status": "Success",
        "error_code": None,
    }) is None


def test_rule_sensitive_s3_public_access_precision():
    """Valida 100% de precisão para a regra RULE_SENSITIVE_S3_PUBLIC_ACCESS."""
    rule = RuleSensitiveS3PublicAccess()

    # Violações
    assert rule.evaluate({"event_name": "DeleteBucketPublicAccessBlock", "event_source": "s3.amazonaws.com"}) is not None
    assert rule.evaluate({"event_name": "PutBucketAcl", "event_source": "s3.amazonaws.com"}) is not None
    assert rule.evaluate({"event_name": "PutBucketPolicy", "event_source": "s3.amazonaws.com"}) is not None

    violation = rule.evaluate({"event_name": "DeleteBucketPublicAccessBlock"})
    assert violation["rule_code"] == "RULE_SENSITIVE_S3_PUBLIC_ACCESS"
    assert violation["severity"] == "HIGH"

    # Não violações
    assert rule.evaluate({"event_name": "GetObject", "event_source": "s3.amazonaws.com"}) is None
    assert rule.evaluate({"event_name": "ListObjectsV2", "event_source": "s3.amazonaws.com"}) is None


def test_engine_evaluates_log_returns_empty_or_violations_list():
    """Cada log avaliado recebe a lista de regras violadas (ou lista vazia se nenhuma regra for disparada)."""
    engine = CloudTrailRulesEngine()

    # Log seguro: não dispara nenhuma regra -> lista vazia
    safe_log = {
        "event_name": "DescribeInstances",
        "event_source": "ec2.amazonaws.com",
        "user_name": "developer",
        "status": "Success",
        "error_code": None,
    }
    violations_safe = engine.evaluate_log(safe_log)
    assert violations_safe == []

    # Log composto: conta Root executando DeleteTrail -> dispara tanto RootActivity quanto TrailTampering
    critical_compound_log = {
        "event_name": "DeleteTrail",
        "event_source": "cloudtrail.amazonaws.com",
        "user_name": "root",
        "status": "Success",
    }
    violations_comp = engine.evaluate_log(critical_compound_log)
    assert len(violations_comp) >= 2
    codes = [v["rule_code"] for v in violations_comp]
    assert "RULE_TRAIL_TAMPERING" in codes
    assert "RULE_ROOT_ACTIVITY" in codes


def test_engine_detect_dataframe_integration():
    """Verifica que o método detect() processa um DataFrame e gera AnomalyResult padronizado."""
    engine = CloudTrailRulesEngine()
    df = pd.DataFrame([
        {
            "event_id": "evt_safe",
            "timestamp": "2026-11-05T12:00:00Z",
            "event_name": "DescribeInstances",
            "event_source": "ec2.amazonaws.com",
            "user_name": "alice",
            "source_ip": "10.0.0.1",
            "status": "Success",
        },
        {
            "event_id": "evt_iam_tamper",
            "timestamp": "2026-11-05T12:01:00Z",
            "event_name": "PutUserPolicy",
            "event_source": "iam.amazonaws.com",
            "user_name": "bob",
            "source_ip": "10.0.0.2",
            "status": "Success",
        },
    ])

    results = engine.detect(df)
    assert len(results) == 1
    assert results[0].event_id == "evt_iam_tamper"
    assert results[0].severity == "HIGH"
    assert results[0].details["primary_rule"] == "RULE_IAM_PRIVILEGE_ESCALATION"


def test_engine_modular_extensibility():
    """Garante que novas regras podem ser registradas no motor sem modificar o código interno."""
    class CustomZeroDayRule(BaseCloudTrailRule):
        rule_code = "RULE_CUSTOM_ZERO_DAY"
        rule_name = "Zero Day Test Rule"
        severity = "CRITICAL"
        description = "Regra de teste para validação de extensibilidade dinâmica."
        mitre_technique = "T1203 - Exploitation for Client Execution"

        def evaluate(self, event):
            if event.get("event_name") == "ZeroDayExploit":
                return {
                    "rule_code": self.rule_code,
                    "rule_name": self.rule_name,
                    "severity": self.severity,
                    "technical_reason": "Zero day detectado",
                    "mitre_technique": self.mitre_technique,
                }
            return None

    engine = CloudTrailRulesEngine()
    initial_rule_count = len(engine.rules)

    # Registra a regra customizada
    engine.register_rule(CustomZeroDayRule())
    assert len(engine.rules) == initial_rule_count + 1

    # Testa a execução da nova regra
    violations = engine.evaluate_log({"event_name": "ZeroDayExploit"})
    assert len(violations) == 1
    assert violations[0]["rule_code"] == "RULE_CUSTOM_ZERO_DAY"
    assert violations[0]["severity"] == "CRITICAL"
