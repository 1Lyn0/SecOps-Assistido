"""Testes unitários dedicados aos templates Jinja2 de contextualização de alertas (MAO-16).

Critérios de Aceitação:
- Renderização do template Jinja2 testada com diferentes combinações de anomalias (apenas estatística, apenas ML, apenas regra ou híbrida).
- Prompt resultante estruturado, determinístico e otimizado para modelos locais leves.
- Presença das 4 seções:
  1) O que aconteceu (Resumo Simples)
  2) Por que foi considerado anômalo
  3) Risco Potencial
  4) Ação Recomendada
"""

import pytest
from secops_core.explainer.templates import (
    render_alert_prompt,
    render_fallback_explanation,
)


def test_render_alert_prompt_only_stats():
    """Valida renderização de prompt para anomalia puramente estatística (Z-Score)."""
    context = {
        "event_id": "evt_stat_only",
        "timestamp": "2026-11-20T10:00:00Z",
        "event_name": "GetObject",
        "event_source": "s3.amazonaws.com",
        "user_name": "analyst_bob",
        "source_ip": "10.0.1.20",
        "severity": "HIGH",
        "zscore": 4.85,
        "details": {
            "triggered_metrics": {"request_count": {"value": 850.0, "z_score": 4.85}},
            "max_z_score": 4.85,
        },
    }

    prompt = render_alert_prompt(context)

    assert "evt_stat_only" in prompt
    assert "analyst_bob" in prompt
    assert "Detecção Estatística (Z-Score)" in prompt
    assert "request_count" in prompt
    # Não deve renderizar blocos vazios de regras nem ML
    assert "Regras Determinísticas CloudTrail" not in prompt

    # Verifica os 4 cabeçalhos obrigatórios no formato exigido
    assert "1) O que aconteceu (Resumo Simples)" in prompt
    assert "2) Por que foi considerado anômalo" in prompt
    assert "3) Risco Potencial" in prompt
    assert "4) Ação Recomendada" in prompt


def test_render_alert_prompt_only_ml():
    """Valida renderização de prompt para anomalia puramente de ML (Isolation Forest)."""
    context = {
        "event_id": "evt_ml_only",
        "timestamp": "2026-11-20T03:30:00Z",
        "event_name": "DescribeInstances",
        "event_source": "ec2.amazonaws.com",
        "user_name": "service_account",
        "source_ip": "198.51.100.9",
        "severity": "MEDIUM",
        "iforest_score": 0.88,
        "details": {
            "normalized_score": 0.88,
            "top_features": {"hour": 3.0, "is_off_hours": 1.0, "ip_frequency": 1.0},
        },
    }

    prompt = render_alert_prompt(context)

    assert "evt_ml_only" in prompt
    assert "Detecção Multivariada (Isolation Forest)" in prompt
    assert "0.88" in prompt
    assert "hour" in prompt
    assert "Detecção Estatística (Z-Score)" not in prompt
    assert "Regras Determinísticas CloudTrail" not in prompt

    assert "1) O que aconteceu (Resumo Simples)" in prompt
    assert "2) Por que foi considerado anômalo" in prompt
    assert "3) Risco Potencial" in prompt
    assert "4) Ação Recomendada" in prompt


def test_render_alert_prompt_only_rule():
    """Valida renderização de prompt para anomalia puramente baseada em regra determinística."""
    context = {
        "event_id": "evt_rule_only",
        "timestamp": "2026-11-20T12:00:00Z",
        "event_name": "DeleteTrail",
        "event_source": "cloudtrail.amazonaws.com",
        "user_name": "root",
        "source_ip": "185.220.101.5",
        "severity": "CRITICAL",
        "cloudtrail_rules": ["RULE_TRAIL_TAMPERING", "RULE_ROOT_ACTIVITY"],
        "details": {
            "rule_codes": ["RULE_TRAIL_TAMPERING", "RULE_ROOT_ACTIVITY"],
            "technical_reason": "Tentativa de desativação de auditoria CloudTrail",
            "mitre_technique": "T1562.001 - Impair Defenses",
        },
    }

    prompt = render_alert_prompt(context)

    assert "evt_rule_only" in prompt
    assert "Regras Determinísticas CloudTrail" in prompt
    assert "RULE_TRAIL_TAMPERING" in prompt
    assert "T1562.001" in prompt
    assert "Detecção Estatística (Z-Score)" not in prompt
    assert "Detecção Multivariada (Isolation Forest)" not in prompt

    assert "1) O que aconteceu (Resumo Simples)" in prompt
    assert "2) Por que foi considerado anômalo" in prompt
    assert "3) Risco Potencial" in prompt
    assert "4) Ação Recomendada" in prompt


def test_render_alert_prompt_hybrid_combination():
    """Valida renderização de prompt híbrido (fusão de estatística, ML e regras)."""
    context = {
        "event_id": "evt_hybrid_all",
        "timestamp": "2026-11-20T18:00:00Z",
        "event_name": "PutUserPolicy",
        "event_source": "iam.amazonaws.com",
        "user_name": "compromised_admin",
        "source_ip": "45.145.67.1",
        "severity": "CRITICAL",
        "zscore": 5.2,
        "iforest_score": 0.95,
        "cloudtrail_rules": ["RULE_IAM_PRIVILEGE_ESCALATION"],
        "details": {
            "triggered_metrics": {"request_count": {"value": 1200.0, "z_score": 5.2}},
            "top_features": {"is_iam": 1.0, "is_suspicious_ip": 1.0},
            "technical_reason": "Escalação não autorizada de privilégios IAM",
            "mitre_technique": "T1098 - Account Manipulation",
        },
    }

    prompt = render_alert_prompt(context)

    # Todos os motores devem constar no prompt
    assert "Detecção Estatística (Z-Score)" in prompt
    assert "Detecção Multivariada (Isolation Forest)" in prompt
    assert "Regras Determinísticas CloudTrail" in prompt
    assert "T1098" in prompt

    assert "1) O que aconteceu (Resumo Simples)" in prompt
    assert "2) Por que foi considerado anômalo" in prompt
    assert "3) Risco Potencial" in prompt
    assert "4) Ação Recomendada" in prompt


def test_render_fallback_explanation_template():
    """Valida renderização do template de fallback Jinja2."""
    context = {
        "event_id": "evt_fallback",
        "event_name": "DeleteTrail",
        "user_name": "attacker",
        "source_ip": "1.2.3.4",
        "severity": "CRITICAL",
        "detectors_triggered": ["CloudTrailRulesEngine"],
    }
    explanation = render_fallback_explanation(
        context=context,
        diagnostics="Exclusão forçada de trilhas de auditoria.",
        tatica="Defense Evasion",
        tecnica="T1562.001",
        actions=["Reativar logging", "Revogar credenciais", "Bloquear IP"],
    )

    assert "Fallback Jinja2" in explanation
    assert "CRITICAL" in explanation
    assert "1. Reativar logging" in explanation
    assert "2. Revogar credenciais" in explanation
    assert "3. Bloquear IP" in explanation
