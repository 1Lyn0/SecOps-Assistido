"""Sistema de templates Jinja2 para contextualização e explicação de alertas de SecOps."""

from pathlib import Path
from typing import Any, Dict, List, Optional
from jinja2 import Environment, FileSystemLoader, select_autoescape

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"

env = Environment(
    loader=FileSystemLoader(str(TEMPLATES_DIR)),
    autoescape=select_autoescape(disabled_extensions=("j2",)),
    trim_blocks=True,
    lstrip_blocks=True,
)

alert_template = env.get_template("alert_explanation.j2")
fallback_template = env.get_template("fallback_explanation.j2")

# Retrocompatibilidade com imports existentes
jinja_template = alert_template


def render_alert_prompt(context: Dict[str, Any]) -> str:
    """Renderiza o prompt contextualizado estruturado para o LLM via Jinja2."""
    return alert_template.render(event=context)


def render_fallback_explanation(
    context: Dict[str, Any],
    diagnostics: str,
    tatica: str,
    tecnica: str,
    actions: List[str],
) -> str:
    """Renderiza o laudo de contingência determinístico via Jinja2."""
    return fallback_template.render(
        event=context,
        diagnostics=diagnostics,
        tatica=tatica,
        tecnica=tecnica,
        actions=actions,
    )
