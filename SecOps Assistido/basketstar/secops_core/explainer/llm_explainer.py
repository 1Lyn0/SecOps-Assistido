"""Camada de explicabilidade de anomalias com integração a LLM local (Ollama) e fallback."""

import json
import logging
from typing import Any, Dict, Optional
import httpx
from secops_core.config import settings
from secops_core.explainer.templates import jinja_template

logger = logging.getLogger("secops_core.explainer")


class LLMExplainer:
    """Gera laudos explicativos e planos de ação para anomalias de SecOps.

    Tenta comunicar-se com o modelo local servido via Ollama. Caso o serviço
    esteja desligado ou inacessível, ativa um motor analítico de contingência
    com regras de conhecimento MITRE ATT&CK para garantir resiliência operacional.
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        timeout: float = 12.0,
    ):
        self.base_url = (base_url or settings.ollama_base_url).rstrip("/")
        self.model = model or settings.ollama_model
        self.timeout = timeout

    def build_prompt(self, context: Dict[str, Any]) -> str:
        """Renderiza o prompt contextualizado usando Jinja2."""
        return jinja_template.render(event=context)

    def explain_anomaly(self, context: Dict[str, Any]) -> str:
        """Gera laudo explicativo da anomalia via Ollama ou contingência."""
        prompt = self.build_prompt(context)

        # 1. Tenta acionar o Ollama local
        try:
            url = f"{self.base_url}/api/generate"
            payload = {
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.2,
                    "top_p": 0.9,
                },
            }
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(url, json=payload)
                if resp.status_code == 200:
                    data = resp.json()
                    response_text = data.get("response", "").strip()
                    if response_text:
                        return f"> [!NOTE]\n> **Laudo emitido por LLM Local ({self.model} via Ollama)**\n\n{response_text}"
        except (httpx.ConnectError, httpx.TimeoutException, httpx.HTTPError) as err:
            logger.info("Ollama indisponível (%s). Ativando laudo por motor de contingência.", err)

        # 2. Ativa o motor analítico contextual de fallback
        return self._generate_fallback_explanation(context)

    def _generate_fallback_explanation(self, context: Dict[str, Any]) -> str:
        """Gera laudo técnico contextualizado baseado na taxonomia de ameaças da anomalia."""
        event_name = context.get("event_name", "Desconhecido")
        user = context.get("user_name", "Desconhecido")
        ip = context.get("source_ip", "Desconhecido")
        detectors = ", ".join(context.get("detectors_triggered", ["Regras"]))
        severity = context.get("severity", "HIGH")
        scenario = context.get("scenario", "")

        # Mapeamento dinâmico de inteligência de ameaças
        if "deletetrail" in event_name.lower() or "stoplogging" in event_name.lower() or scenario == "defense_evasion":
            tatica = "Defense Evasion (Evasão de Defesa)"
            tecnica = "T1562.001 - Impair Defenses: Disable Cloud Logs"
            diagnostico = (
                f"A chamada à API '{event_name}' tenta desabilitar ou apagar trilhas de auditoria "
                f"do CloudTrail. Em ambientes de nuvem, essa ação é um forte indicador de comprometimento, "
                f"onde o atacante tenta encobrir rastros antes de executar ações de maior impacto."
            )
            remedicoes = [
                f"Reativar imediatamente o logging da trilha no AWS CloudTrail afetada.",
                f"Revogar credenciais ativas e sessões STS do usuário '{user}'.",
                f"Isolar e bloquear o IP de origem '{ip}' no Security Group e AWS WAF.",
            ]
        elif "putuserpolicy" in event_name.lower() or "attachuserpolicy" in event_name.lower() or scenario == "privilege_escalation":
            tatica = "Privilege Escalation & Persistence"
            tecnica = "T1098 - Account Manipulation / T1078 - Valid Accounts"
            diagnostico = (
                f"Ação de manipulação de permissões IAM detectada ('{event_name}'). "
                f"O usuário '{user}' tentou anexar políticas com privilégios administrativos elevados, "
                f"desviando do perfil basal de autorizações do time de engenharia."
            )
            remedicoes = [
                f"Auditar e revogar políticas de IAM recém-anexadas pelo usuário '{user}'.",
                f"Exigir rotação imediata de chaves de acesso (Access Keys) da conta afetada.",
                f"Verificar histórico de logs da última hora para listar outros recursos acessados.",
            ]
        elif "login" in event_name.lower() or scenario == "brute_force":
            tatica = "Credential Access (Acesso a Credenciais)"
            tecnica = "T1110 - Brute Force / Password Guessing"
            diagnostico = (
                f"Múltiplas falhas sucessivas de autenticação no ConsoleLogin a partir do IP '{ip}'. "
                f"O padrão em rajada e a ausência de MFA indicam tentativa automatizada de adivinhação "
                f"de senhas ou credential stuffing."
            )
            remedicoes = [
                f"Bloquear o endereço IP '{ip}' na borda da rede ou no AWS WAF.",
                f"Habilitar obrigatoriedade de MFA (Multi-Factor Authentication) para o usuário '{user}'.",
                f"Verificar se alguma tentativa subsequente obteve sucesso de login.",
            ]
        elif "getobject" in event_name.lower() or scenario == "data_exfiltration":
            tatica = "Exfiltration (Exfiltração de Dados)"
            tecnica = "T1567 - Exfiltration Over Web Service / Cloud Storage"
            diagnostico = (
                f"Volume atípico de requisições e bytes transferidos identificado pelo detector Z-Score. "
                f"O usuário '{user}' efetuou download massivo de objetos em bucket S3 fora do padrão diário."
            )
            remedicoes = [
                f"Aplicar restrição temporária no bucket policy S3 para leitura a partir de IPs externos.",
                f"Confrontar a lista de arquivos baixados com a classificação de dados da empresa (LGPD/DLP).",
                f"Notificar o gestor responsável pelo usuário '{user}' para validação de atividade legítima.",
            ]
        else:
            tatica = "Initial Access / Suspicious Execution"
            tecnica = "T1078 - Valid Accounts / Anomaly Activity"
            diagnostico = (
                f"Atividade operacional incomum registrada para a API '{event_name}', acionando múltiplos "
                f"detectores ({detectors}) devido à combinação de horário atípico, IP e métricas anômalas."
            )
            remedicoes = [
                f"Confirmar com a equipe de engenharia se houve manutenção agendada ou deploy fora de horário.",
                f"Monitorar sessões ativas do usuário '{user}' em busca de outras chamadas não autorizadas.",
                f"Restringir temporariamente a política de Security Group para o IP '{ip}'.",
            ]

        actions_md = "\n".join([f"{i+1}. {act}" for i, act in enumerate(remedicoes)])

        return f"""
> [!NOTE]
> **Laudo gerado pelo Motor Analítico de Contingência SecOps** (Ollama local offline).

#### 1. Resumo Executivo
Detectada atividade com severidade **{severity}** na API **{event_name}**, originada do IP **{ip}** e associada ao usuário **{user}**. O alerta foi disparado pelos motores **{detectors}**.

#### 2. Diagnóstico Técnico & Causa Raiz
{diagnostico}

#### 3. Mapeamento MITRE ATT&CK
- **Tática**: {tatica}
- **Técnica**: `{tecnica}`

#### 4. Ações Imediatas de Contenção & Remediação
{actions_md}
""".strip()
