"""Testes para o motor de explicabilidade com IA e contingência offline."""

import pytest
from secops_core.explainer.llm_explainer import LLMExplainer


def test_explainer_prompt_rendering():
    explainer = LLMExplainer()
    context = {
        "event_id": "test-uuid-001",
        "timestamp": "2026-11-05T03:00:00Z",
        "event_name": "DeleteTrail",
        "event_source": "cloudtrail.amazonaws.com",
        "user_name": "attacker",
        "source_ip": "185.220.101.5",
        "severity": "CRITICAL",
        "detectors_triggered": ["RuleBasedDetector"],
        "max_score": 1.0,
        "details": {"rule": "SEC-R001"},
    }

    prompt = explainer.build_prompt(context)
    assert "test-uuid-001" in prompt
    assert "DeleteTrail" in prompt
    assert "RuleBasedDetector" in prompt
    assert "MITRE ATT&CK" in prompt


def test_explainer_offline_fallback():
    # Aponta para uma porta inexistente para forçar fallback offline
    explainer = LLMExplainer(base_url="http://127.0.0.1:54321", timeout=0.5)
    context = {
        "event_id": "test-uuid-002",
        "timestamp": "2026-11-05T03:00:00Z",
        "event_name": "DeleteTrail",
        "event_source": "cloudtrail.amazonaws.com",
        "user_name": "attacker",
        "source_ip": "185.220.101.5",
        "severity": "CRITICAL",
        "detectors_triggered": ["RuleBasedDetector"],
        "max_score": 1.0,
        "scenario": "defense_evasion",
    }

    laudo = explainer.explain_anomaly(context)
    assert laudo is not None
    assert "Motor Analítico de Contingência" in laudo
    assert "Defense Evasion" in laudo
    assert "T1562.001" in laudo
    assert "Ações Imediatas de Contenção & Remediação" in laudo
