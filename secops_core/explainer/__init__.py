"""Subpacote de explicabilidade e integração com LLMs locais (Ollama e Templates Jinja2)."""

from secops_core.explainer.llm_explainer import LLMExplainer
from secops_core.explainer.ollama_client import OllamaClient
from secops_core.explainer.templates import (
    render_alert_prompt,
    render_fallback_explanation,
)

__all__ = [
    "LLMExplainer",
    "OllamaClient",
    "render_alert_prompt",
    "render_fallback_explanation",
]
