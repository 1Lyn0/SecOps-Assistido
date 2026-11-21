"""Cliente de integração HTTP com Ollama local e fallback resiliente Jinja2."""

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import httpx
from secops_core.config import settings
from secops_core.db import update_ai_explanation
from secops_core.explainer.templates import (
    render_alert_prompt,
    render_fallback_explanation,
)

logger = logging.getLogger("secops_core.explainer.ollama")


class OllamaClient:
    """Cliente HTTP resiliente para o servidor Ollama local com fallback automático.

    Permite:
    1. Verificação de saúde (healthcheck) do serviço Ollama local.
    2. Geração de texto via POST /api/generate com stream=False.
    3. Acionamento do Fallback Inteligente Jinja2 sem quebras quando o Ollama estiver inativo.
    4. Persistência automática da explicação gerada na coluna ai_explanation do SQLite.
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

    def check_health(self) -> bool:
        """Verifica se o serviço Ollama está ativo e respondendo na porta configurada."""
        try:
            with httpx.Client(timeout=2.0) as client:
                resp = client.get(f"{self.base_url}/api/version")
                return resp.status_code == 200
        except Exception:
            try:
                with httpx.Client(timeout=2.0) as client:
                    resp = client.get(f"{self.base_url}/")
                    return resp.status_code == 200
            except Exception:
                return False

    def is_alive(self) -> bool:
        """Alias para check_health."""
        return self.check_health()

    def generate(self, prompt: str) -> Optional[str]:
        """Envia o prompt para o Ollama local via HTTP POST com stream=False."""
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
                return data.get("response", "").strip()
            logger.warning("Ollama retornou status HTTP %s", resp.status_code)
            return None

    def generate_fallback_explanation(self, context: Dict[str, Any]) -> str:
        """Gera explicação estruturada em português via Jinja2 caso o Ollama esteja indisponível."""
        event_name = str(context.get("event_name", "Desconhecido"))
        user = str(context.get("user_name", "Desconhecido"))
        ip = str(context.get("source_ip", "Desconhecido"))
        scenario = str(context.get("scenario", "")).lower()

        # Determina tática, técnica e ações com base no tipo de evento / cenário
        if any(term in event_name.lower() for term in ["deletetrail", "stoplogging", "updatetrail"]) or "defense_evasion" in scenario:
            tatica = "Defense Evasion (Evasão de Defesa)"
            tecnica = "T1562.001 - Impair Defenses: Disable Cloud Logs"
            diagnostico = (
                f"A chamada à API '{event_name}' tenta desabilitar ou apagar trilhas de auditoria "
                f"do CloudTrail. Esta ação é um forte indicador de comprometimento para encobrir rastros."
            )
            actions = [
                f"Reativar imediatamente o logging da trilha no AWS CloudTrail afetada.",
                f"Revogar credenciais ativas e sessões STS do usuário '{user}'.",
                f"Isolar e bloquear o IP de origem '{ip}' no Security Group e AWS WAF.",
            ]
        elif any(term in event_name.lower() for term in ["putuserpolicy", "attachuserpolicy", "createaccesskey"]) or "privilege_escalation" in scenario:
            tatica = "Privilege Escalation & Persistence"
            tecnica = "T1098 - Account Manipulation / T1078 - Valid Accounts"
            diagnostico = (
                f"Ação de manipulação de permissões IAM detectada ('{event_name}'). "
                f"O usuário '{user}' tentou anexar políticas com privilégios administrativos elevados."
            )
            actions = [
                f"Auditar e revogar políticas de IAM recém-anexadas pelo usuário '{user}'.",
                f"Exigir rotação imediata de chaves de acesso (Access Keys) da conta afetada.",
                f"Verificar histórico de logs da última hora para listar outros recursos acessados.",
            ]
        elif "root" in user.lower() or "root" in scenario:
            tatica = "Privilege Escalation / Root Activity"
            tecnica = "T1078.004 - Cloud Root Account Direct Activity"
            diagnostico = (
                f"Uso direto das credenciais da conta Root da AWS para a operação '{event_name}', "
                f"violando o CIS AWS Benchmark e boas práticas fundamentais de segurança em nuvem."
            )
            actions = [
                f"Confirmar a legitimidade do acesso da conta root com o time de engenharia.",
                f"Verificar se o MFA está ativo na conta root e trocar a senha mestra imediatamente.",
                f"Restringir o acesso a credenciais root usando AWS Organizations SCPs.",
            ]
        elif "login" in event_name.lower() or "brute_force" in scenario:
            tatica = "Credential Access (Acesso a Credenciais)"
            tecnica = "T1110 - Brute Force / Password Guessing"
            diagnostico = (
                f"Múltiplas falhas sucessivas de autenticação no ConsoleLogin a partir do IP '{ip}'. "
                f"O padrão em rajada indica tentativa automatizada de força bruta ou credential stuffing."
            )
            actions = [
                f"Bloquear o endereço IP '{ip}' na borda da rede ou no AWS WAF.",
                f"Habilitar obrigatoriedade de MFA (Multi-Factor Authentication) para o usuário '{user}'.",
                f"Verificar se alguma tentativa subsequente obteve sucesso de login.",
            ]
        elif any(term in event_name.lower() for term in ["getobject", "download"]) or "exfiltration" in scenario:
            tatica = "Exfiltration (Exfiltração de Dados)"
            tecnica = "T1567 - Exfiltration Over Web Service / Cloud Storage"
            diagnostico = (
                f"Volume atípico de requisições e bytes transferidos identificado pelos detectores. "
                f"O usuário '{user}' efetuou download massivo de objetos fora do padrão histórico."
            )
            actions = [
                f"Aplicar restrição temporária no bucket policy S3 para leitura a partir de IPs externos.",
                f"Confrontar a lista de arquivos baixados com a classificação de dados da empresa.",
                f"Notificar o gestor responsável pelo usuário '{user}' para validação de atividade legítima.",
            ]
        else:
            tatica = "Initial Access / Suspicious Execution"
            tecnica = "T1078 - Valid Accounts / Anomaly Activity"
            diagnostico = (
                f"Atividade operacional incomum registrada para a API '{event_name}', acionando detectores "
                f"devido à combinação de horário atípico, IP e métricas anômalas."
            )
            actions = [
                f"Confirmar com a equipe de engenharia se houve manutenção agendada ou deploy fora de horário.",
                f"Monitorar sessões ativas do usuário '{user}' em busca de outras chamadas não autorizadas.",
                f"Restringir temporariamente a política de Security Group para o IP '{ip}'.",
            ]

        return render_fallback_explanation(
            context=context,
            diagnostics=diagnostico,
            tatica=tatica,
            tecnica=tecnica,
            actions=actions,
        )

    def explain_anomaly(self, context: Dict[str, Any]) -> str:
        """Gera laudo explicativo da anomalia via Ollama local com fallback automático para Jinja2."""
        prompt = render_alert_prompt(context)

        # 1. Tenta obter explicação do Ollama local
        try:
            response_text = self.generate(prompt)
            if response_text:
                return (
                    f"> [!NOTE]\n"
                    f"> **Laudo emitido por LLM Local ({self.model} via Ollama)**\n\n"
                    f"{response_text}"
                )
        except (httpx.ConnectError, httpx.TimeoutException, httpx.HTTPError, Exception) as err:
            logger.info("Ollama indisponível (%s). Ativando laudo por Fallback Inteligente Jinja2.", err)

        # 2. Aciona Fallback Inteligente estruturado em Jinja2
        return self.generate_fallback_explanation(context)

    def explain_and_persist(
        self,
        event_id: str,
        context: Dict[str, Any],
        db_path: Optional[Union[str, Path]] = None,
    ) -> str:
        """Gera a explicação (via Ollama ou Fallback) e atualiza a coluna ai_explanation no banco SQLite."""
        explanation = self.explain_anomaly(context)
        update_ai_explanation(event_id, explanation, db_path=db_path)
        return explanation
