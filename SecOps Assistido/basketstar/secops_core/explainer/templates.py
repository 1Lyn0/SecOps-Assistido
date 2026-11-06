"""Templates Jinja2 para geração de laudos de explicabilidade de anomalias."""

from jinja2 import Template

EXPLAINER_PROMPT_TEMPLATE = """
Você é um Especialista Sênior em Segurança da Informação e Resposta a Incidentes (SecOps Tier 3).
Analise o evento de auditoria anômalo identificado abaixo e produza um laudo técnico conciso, objetivo e acionável.

### Dados do Evento Anômalo:
- **Event ID**: {{ event.event_id }}
- **Timestamp**: {{ event.timestamp }}
- **Ação / API**: {{ event.event_name }}
- **Serviço**: {{ event.event_source or 'N/A' }}
- **Identidade / Usuário**: {{ event.user_name }}
- **IP de Origem**: {{ event.source_ip }}
- **Severidade Estimada**: {{ event.severity }}
- **Detectores que Acionaram o Alerta**: {{ event.detectors_triggered | join(', ') }}
- **Score Máximo de Anomalia**: {{ event.max_score }}
{% if event.details %}
- **Detalhes Contextuais**: {{ event.details }}
{% endif %}

---

Estruture sua resposta estritamente no seguinte formato Markdown:

#### 1. Resumo Executivo
Uma visão direta em 2 a 3 frases explicando o que aconteceu e o potencial impacto ao ambiente.

#### 2. Diagnóstico Técnico & Causa Raiz
Por que este comportamento foi considerado anômalo pelos detectores estatísticos/ML/regras.

#### 3. Mapeamento MITRE ATT&CK
- **Tática**: (Ex: Initial Access, Defense Evasion, Privilege Escalation, Exfiltration)
- **Técnica**: (Identificador e nome da técnica, ex: T1562.001)

#### 4. Ações Imediatas de Contenção & Remediação
Três ações diretas que o analista de SecOps deve tomar imediatamente no ambiente cloud.
""".strip()

jinja_template = Template(EXPLAINER_PROMPT_TEMPLATE)
