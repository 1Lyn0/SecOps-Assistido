"""Camada de explicabilidade de anomalias com integração a LLM local (Ollama) e fallback."""

from typing import Any, Dict, Optional
from secops_core.explainer.ollama_client import OllamaClient
from secops_core.explainer.templates import render_alert_prompt


class LLMExplainer(OllamaClient):
    """Gera laudos explicativos e planos de ação para anomalias de SecOps.

    Herda e estende OllamaClient, fornecendo interface compatível com todo o ecossistema.
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        timeout: float = 12.0,
    ):
        super().__init__(base_url=base_url, model=model, timeout=timeout)

    def build_prompt(self, context: Dict[str, Any]) -> str:
        """Renderiza o prompt contextualizado usando Jinja2."""
        return render_alert_prompt(context)


__all__ = ["LLMExplainer", "OllamaClient"]
