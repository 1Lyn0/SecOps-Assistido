import sys
from pathlib import Path
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable, Preformatted
)
from reportlab.pdfgen import canvas

class NumberedCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748b"))
        
        # Oculta cabeçalho e rodapé na capa (página 1)
        if self._pageNumber > 1:
            # Header
            self.drawString(54, 11 * inch - 36, "SecOps Assistido — Especificação Técnica, Tecnologias e Código")
            self.drawRightString(8.5 * inch - 54, 11 * inch - 36, "Mãos na Tech | MAO 11-18")
            self.setStrokeColor(colors.HexColor("#e2e8f0"))
            self.setLineWidth(0.5)
            self.line(54, 11 * inch - 42, 8.5 * inch - 54, 11 * inch - 42)
            
            # Footer
            self.line(54, 45, 8.5 * inch - 54, 45)
            self.drawString(54, 32, "Confidencial & Interno — Documentação Técnica do Projeto")
            page_text = f"Página {self._pageNumber} de {page_count}"
            self.drawRightString(8.5 * inch - 54, 32, page_text)
            
        self.restoreState()

def build_pdf(filename="SecOps_Assistido_Documentacao_Completa.pdf"):
    doc = SimpleDocTemplate(
        filename,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54
    )

    styles = getSampleStyleSheet()
    
    # Paleta de cores corporativa
    c_primary = colors.HexColor("#0f172a")     # Slate 900
    c_secondary = colors.HexColor("#1e293b")   # Slate 800
    c_accent = colors.HexColor("#0284c7")      # Sky 600
    c_light = colors.HexColor("#f8fafc")       # Slate 50
    c_border = colors.HexColor("#cbd5e1")      # Slate 300
    c_dark_gray = colors.HexColor("#334155")
    c_code_bg = colors.HexColor("#f1f5f9")
    
    # Estilos Tipográficos
    title_style = ParagraphStyle(
        'CoverTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=24,
        leading=30,
        textColor=c_primary,
        spaceAfter=10
    )
    
    subtitle_style = ParagraphStyle(
        'CoverSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#475569"),
        spaceAfter=20
    )
    
    meta_style = ParagraphStyle(
        'CoverMeta',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9.5,
        leading=13,
        textColor=colors.HexColor("#64748b")
    )
    
    h1_style = ParagraphStyle(
        'Heading1_Custom',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=15,
        leading=19,
        textColor=c_primary,
        spaceBefore=16,
        spaceAfter=8,
        keepWithNext=True
    )
    
    h2_style = ParagraphStyle(
        'Heading2_Custom',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=11.5,
        leading=15,
        textColor=c_accent,
        spaceBefore=12,
        spaceAfter=6,
        keepWithNext=True
    )
    
    body_style = ParagraphStyle(
        'Body_Custom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13.5,
        textColor=c_dark_gray,
        spaceAfter=6
    )

    bullet_style = ParagraphStyle(
        'Bullet_Custom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=12.5,
        textColor=c_dark_gray,
        leftIndent=14,
        spaceAfter=4
    )

    code_style = ParagraphStyle(
        'CodeBlock',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=7.5,
        leading=10.5,
        textColor=colors.HexColor("#0f172a"),
        backColor=c_code_bg,
        borderPadding=5,
        spaceBefore=4,
        spaceAfter=6
    )
    
    callout_style = ParagraphStyle(
        'CalloutText',
        parent=styles['Normal'],
        fontName='Helvetica-Oblique',
        fontSize=8.5,
        leading=12.5,
        textColor=colors.HexColor("#0369a1")
    )
    
    table_cell_style = ParagraphStyle(
        'TableCell',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        leading=10.5,
        textColor=c_dark_gray
    )

    table_header_style = ParagraphStyle(
        'TableHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8.5,
        leading=11,
        textColor=colors.white
    )

    story = []

    # ==================== CAPA / COVER ====================
    story.append(Spacer(1, 30))
    story.append(HRFlowable(width="100%", thickness=4, color=c_accent, spaceBefore=0, spaceAfter=16))
    story.append(Paragraph("SecOps Assistido por IA", title_style))
    story.append(Paragraph("Guia Técnico Completo de Arquitetura, Tecnologias, Instruções e Módulos", subtitle_style))
    story.append(Paragraph(
        "<b>Auditoria Inteligente em Cloud (AWS CloudTrail):</b> Ingestão Canônica LGMS, Ensemble Híbrido "
        "(Z-Score, Isolation Forest & Regras Determinísticas), Explicabilidade com LLMs Locais (Ollama & Jinja2), "
        "Persistência SQLite em modo WAL, API REST FastAPI e Dashboard Streamlit.",
        body_style
    ))
    story.append(Spacer(1, 18))
    
    meta_box_data = [
        [
            Paragraph("<b>Projeto:</b> SecOps-Assistido", meta_style),
            Paragraph("<b>Time:</b> Mãos na Tech (MAO)", meta_style)
        ],
        [
            Paragraph("<b>Tarefas Integradas:</b> MAO-11, 12, 13, 14, 16, 17 e 18", meta_style),
            Paragraph("<b>Data de Geração:</b> Novembro de 2026", meta_style)
        ],
        [
            Paragraph("<b>Linguagem & Runtime:</b> Python 3.14 (Virtualenv)", meta_style),
            Paragraph("<b>Cobertura de Testes:</b> 63 testes (100% de sucesso)", meta_style)
        ]
    ]
    t_meta = Table(meta_box_data, colWidths=[250, 250])
    t_meta.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), c_light),
        ('BOX', (0,0), (-1,-1), 1, c_border),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('PADDING', (0,0), (-1,-1), 6),
    ]))
    story.append(t_meta)
    story.append(Spacer(1, 20))
    
    callout_data = [[
        Paragraph(
            "<b>Finalidade deste documento:</b> Detalhar exaustivamente todas as tecnologias, conceitos, "
            "algoritmos, decisões de arquitetura e arquivos de código utilizados no desenvolvimento do SecOps Assistido, "
            "apresentando as instruções de uso e demonstrando a correlação exata de cada componente do sistema.",
            callout_style
        )
    ]]
    t_callout = Table(callout_data, colWidths=[500])
    t_callout.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#e0f2fe")),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#7dd3fc")),
        ('PADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(t_callout)
    story.append(PageBreak())

    # ==================== CAPÍTULO 1: ARQUITETURA ====================
    story.append(Paragraph("1. Visão Geral e Arquitetura do Sistema", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=c_accent, spaceBefore=2, spaceAfter=8))
    
    story.append(Paragraph(
        "O <b>SecOps Assistido</b> foi construído para resolver o problema clássico de <i>alert fatigue</i> "
        "(fadiga de alertas) em centros de operações de segurança (SOC), analisando eventos complexos de auditoria "
        "do AWS CloudTrail. Em vez de depender apenas de assinaturas estáticas ou modelos de caixa preta, a solução "
        "adota uma <b>abordagem híbrida em ensemble</b>.",
        body_style
    ))
    story.append(Paragraph(
        "O fluxo de processamento é dividido em 6 camadas funcionais integradas:",
        body_style
    ))
    
    layers_data = [
        [Paragraph("<b>Camada</b>", table_header_style), Paragraph("<b>Módulos Principais</b>", table_header_style), Paragraph("<b>Responsabilidade Técnica</b>", table_header_style)],
        [
            Paragraph("1. Ingestão & Simulação", table_cell_style),
            Paragraph("<code>generator.py</code><br/><code>data/*.jsonl</code>", table_cell_style),
            Paragraph("Geração de eventos sintéticos realistas de CloudTrail com cenários de ataque (exfiltração, evasão, força bruta, root).", table_cell_style)
        ],
        [
            Paragraph("2. Modelagem LGMS", table_cell_style),
            Paragraph("<code>secops_core/lgms.py</code>", table_cell_style),
            Paragraph("Validação canônica via Pydantic (CanonicalLog), parser resiliente em streaming e engenharia de features numéricas/temporais.", table_cell_style)
        ],
        [
            Paragraph("3. Motores de Detecção", table_cell_style),
            Paragraph("<code>zscore_detector.py</code><br/><code>isolation_forest.py</code><br/><code>cloudtrail_rules.py</code>", table_cell_style),
            Paragraph("Ensemble de detecção: Z-Score para picos univariados, Isolation Forest para anomalias multivariadas e regras determinísticas CIS/MITRE.", table_cell_style)
        ],
        [
            Paragraph("4. Orquestração Pipeline", table_cell_style),
            Paragraph("<code>secops_core/pipeline.py</code><br/><code>secops_core/detectors/engine.py</code>", table_cell_style),
            Paragraph("Orquestração unificada ponta a ponta, regra de fusão ('qualquer detector' marca anomalia), justificativa técnica e severidade combinada.", table_cell_style)
        ],
        [
            Paragraph("5. Explicabilidade IA", table_cell_style),
            Paragraph("<code>templates/alert_explanation.j2</code><br/><code>ollama_client.py</code>", table_cell_style),
            Paragraph("Contextualização rígida via Jinja2 e inferência local via Ollama (Llama 3.2), com Fallback Inteligente determinístico.", table_cell_style)
        ],
        [
            Paragraph("6. Persistência & Consumo", table_cell_style),
            Paragraph("<code>db.py</code>, <code>api/main.py</code><br/><code>dashboard/app.py</code>", table_cell_style),
            Paragraph("SQLite em modo WAL com índices analíticos, API REST completa em FastAPI (/health, /stats, /logs, /anomalies) e painel Streamlit.", table_cell_style)
        ],
    ]
    t_layers = Table(layers_data, colWidths=[90, 130, 280])
    t_layers.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), c_secondary),
        ('GRID', (0,0), (-1,-1), 0.5, c_border),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, c_light]),
        ('PADDING', (0,0), (-1,-1), 4.5),
    ]))
    story.append(t_layers)
    story.append(Spacer(1, 10))

    # ==================== CAPÍTULO 2: TABELA MESTRA ====================
    story.append(Paragraph("2. Tabela Mestra de Tecnologias, Assuntos e Local de Aplicação", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=c_accent, spaceBefore=2, spaceAfter=8))
    story.append(Paragraph(
        "A tabela a seguir consolida todas as tecnologias, bibliotecas, padrões e disciplinas de segurança "
        "empregados no projeto, especificando exatamente a finalidade e o arquivo onde foram utilizados:",
        body_style
    ))

    master_tech_data = [
        [Paragraph("<b>Tecnologia / Assunto</b>", table_header_style), Paragraph("<b>Versão / Conceito</b>", table_header_style), Paragraph("<b>Finalidade no SecOps Assistido</b>", table_header_style), Paragraph("<b>Onde foi Utilizado (Arquivo)</b>", table_header_style)],
        [
            Paragraph("<b>Python</b>", table_cell_style),
            Paragraph("3.14.9", table_cell_style),
            Paragraph("Linguagem central com tipagem forte, orientação a objetos e funções assíncronas.", table_cell_style),
            Paragraph("Todo o repositório", table_cell_style)
        ],
        [
            Paragraph("<b>Scikit-Learn</b>", table_cell_style),
            Paragraph("1.9.1 (ML)", table_cell_style),
            Paragraph("Modelo <code>IsolationForest</code> para detecção multivariada e <code>StandardScaler</code> para escalonamento.", table_cell_style),
            Paragraph("<code>secops_core/detectors/isolation_forest.py</code>", table_cell_style)
        ],
        [
            Paragraph("<b>NumPy & Pandas</b>", table_cell_style),
            Paragraph("2.5.4 / 3.1.1", table_cell_style),
            Paragraph("Transformações vetorizadas, séries temporais, matrizes numéricas e cálculo do Z-Score.", table_cell_style),
            Paragraph("<code>secops_core/lgms.py</code><br/><code>secops_core/detectors/zscore_detector.py</code>", table_cell_style)
        ],
        [
            Paragraph("<b>Pydantic v2</b>", table_cell_style),
            Paragraph("2.14.3", table_cell_style),
            Paragraph("Schemas canônicos de logs, validação de campos, contratos de API e modelos de alerta.", table_cell_style),
            Paragraph("<code>secops_core/lgms.py</code><br/><code>api/schemas.py</code>, <code>detectors/base.py</code>", table_cell_style)
        ],
        [
            Paragraph("<b>Pydantic-Settings</b>", table_cell_style),
            Paragraph("2.16.2", table_cell_style),
            Paragraph("Gerenciamento centralizado de configurações e limiares via variáveis de ambiente (.env).", table_cell_style),
            Paragraph("<code>secops_core/config.py</code>", table_cell_style)
        ],
        [
            Paragraph("<b>Jinja2</b>", table_cell_style),
            Paragraph("3.1.6", table_cell_style),
            Paragraph("Templates determinísticos para contextualização de prompts de LLM e laudos forenses.", table_cell_style),
            Paragraph("<code>secops_core/explainer/templates/</code><br/><code>secops_core/explainer/templates.py</code>", table_cell_style)
        ],
        [
            Paragraph("<b>Ollama & Llama 3.2</b>", table_cell_style),
            Paragraph("Local LLM", table_cell_style),
            Paragraph("Inferência de IA generativa 100% local para triagem de alertas críticos sem vazamento de dados.", table_cell_style),
            Paragraph("<code>secops_core/explainer/ollama_client.py</code>", table_cell_style)
        ],
        [
            Paragraph("<b>HTTPX</b>", table_cell_style),
            Paragraph("0.28.1", table_cell_style),
            Paragraph("Cliente HTTP assíncrono/síncrono para integração com o Ollama local e healthchecks.", table_cell_style),
            Paragraph("<code>secops_core/explainer/ollama_client.py</code>", table_cell_style)
        ],
        [
            Paragraph("<b>SQLite 3 (WAL Mode)</b>", table_cell_style),
            Paragraph("Nativo SQL", table_cell_style),
            Paragraph("Persistência relacional transacional, modo WAL, índices de alta performance e cláusulas UPSERT.", table_cell_style),
            Paragraph("<code>secops_core/db.py</code><br/><code>data/secops.db</code>", table_cell_style)
        ],
        [
            Paragraph("<b>FastAPI & Uvicorn</b>", table_cell_style),
            Paragraph("0.162.0 / 0.54.0", table_cell_style),
            Paragraph("Backend RESTful expondo /health, /stats, /logs, /anomalies, /explain e Swagger /docs.", table_cell_style),
            Paragraph("<code>api/main.py</code><br/><code>api/schemas.py</code>", table_cell_style)
        ],
        [
            Paragraph("<b>Streamlit & Altair</b>", table_cell_style),
            Paragraph("1.67.0 / 6.3.0", table_cell_style),
            Paragraph("Painel web operacional para SOC com KPIs de severidade, filtros e visualização de alertas.", table_cell_style),
            Paragraph("<code>dashboard/app.py</code>", table_cell_style)
        ],
        [
            Paragraph("<b>Pytest</b>", table_cell_style),
            Paragraph("9.2.0", table_cell_style),
            Paragraph("Framework de testes automatizados com 63 testes unitários e de integração (100% de sucesso).", table_cell_style),
            Paragraph("<code>tests/*.py</code>", table_cell_style)
        ],
        [
            Paragraph("<b>ReportLab</b>", table_cell_style),
            Paragraph("5.1.0", table_cell_style),
            Paragraph("Geração programática de relatórios técnicos em PDF com numeração e estilos corporativos.", table_cell_style),
            Paragraph("<code>generate_pdf_docs.py</code>", table_cell_style)
        ],
        [
            Paragraph("<b>MITRE ATT&CK</b>", table_cell_style),
            Paragraph("Framework SecOps", table_cell_style),
            Paragraph("Mapeamento de ameaças: T1562.001 (Evasão), T1098 (IAM), T1078 (Root), T1110 (Brute Force).", table_cell_style),
            Paragraph("<code>secops_core/detectors/cloudtrail_rules.py</code>", table_cell_style)
        ],
        [
            Paragraph("<b>CIS AWS Benchmark</b>", table_cell_style),
            Paragraph("Conformidade Cloud", table_cell_style),
            Paragraph("Regras rígidas para uso de conta Root, integridade de trilhas CloudTrail e restrições S3.", table_cell_style),
            Paragraph("<code>secops_core/detectors/cloudtrail_rules.py</code>", table_cell_style)
        ],
    ]
    t_master = Table(master_tech_data, colWidths=[90, 75, 185, 150])
    t_master.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), c_secondary),
        ('GRID', (0,0), (-1,-1), 0.5, c_border),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, c_light]),
        ('PADDING', (0,0), (-1,-1), 3.5),
    ]))
    story.append(t_master)
    story.append(PageBreak())

    # ==================== CAPÍTULO 3: DETALHAMENTO DAS TAREFAS ====================
    story.append(Paragraph("3. Detalhamento Técnico das Tarefas Implementadas", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=c_accent, spaceBefore=2, spaceAfter=8))

    # MAO-11
    story.append(Paragraph("3.1. MAO-11: Detector Estatístico Z-Score (secops_core/detectors/zscore_detector.py)", h2_style))
    story.append(Paragraph(
        "Focado em identificar picos de volumetria que se distanciam bruscamente da média histórica "
        "calculando <b>Z = (x - &mu;) / &sigma;</b>. Analisa métricas univariadas e agregadas (ex: <code>request_count</code>, "
        "<code>bytes_transferred</code>, <code>log_bytes_transferred</code>, <code>ip_frequency</code>, <code>user_frequency</code>).",
        body_style
    ))
    story.append(Paragraph("• <b>Proteção &sigma; = 0:</b> Quando todos os valores são homogêneos, Z é fixado em 0.0 sem divisão por zero.", bullet_style))
    story.append(Paragraph("• <b>Configurabilidade:</b> Limiar parametrizável via construtor ou variável de ambiente <code>ZSCORE_THRESHOLD</code>.", bullet_style))
    story.append(Paragraph("• <b>Imutabilidade:</b> O DataFrame original é preservado intacto através de cópias defensivas.", bullet_style))

    # MAO-12
    story.append(Paragraph("3.2. MAO-12: Detector Multivariado Isolation Forest (secops_core/detectors/isolation_forest.py)", h2_style))
    story.append(Paragraph(
        "Detecta anomalias comportamentais complexas sem supervisão prévia. Ataques furtivos combinam pequenas alterações "
        "em várias dimensões (madrugada + erro de chamada + ação incomum + IP externo).",
        body_style
    ))
    story.append(Paragraph("• <b>Pré-processamento:</b> Codificação de frequência para variáveis categóricas e escalonamento numérico via <code>StandardScaler</code>.", bullet_style))
    story.append(Paragraph("• <b>Parametrização & Reprodutibilidade:</b> Suporte a <code>contamination</code>, <code>n_estimators</code> e <code>random_state=42</code> fixo.", bullet_style))
    story.append(Paragraph("• <b>Saídas Ricas:</b> Retorna flag booleana <code>is_iforest_anomaly</code>, score normalizado contínuo [0.0, 1.0] e <code>decision_function</code>.", bullet_style))

    # MAO-13
    story.append(Paragraph("3.3. MAO-13: Motor Modular de Regras CloudTrail (secops_core/detectors/cloudtrail_rules.py)", h2_style))
    story.append(Paragraph(
        "Ameaças severas em nuvem não podem depender apenas de desvio estatístico. Foi desenvolvido um catálogo modular "
        "de 7 regras determinísticas alinhadas ao CIS AWS e MITRE ATT&CK:",
        body_style
    ))
    story.append(Paragraph("1. <code>RULE_TRAIL_TAMPERING</code> (CRITICAL - T1562.001): DeleteTrail, StopLogging, UpdateTrail.", bullet_style))
    story.append(Paragraph("2. <code>RULE_ROOT_ACTIVITY</code> (CRITICAL - T1078.004): Chamadas executadas diretamente pela credencial Root.", bullet_style))
    story.append(Paragraph("3. <code>RULE_IAM_PRIVILEGE_ESCALATION</code> (HIGH - T1098): PutUserPolicy, AttachUserPolicy, CreateAccessKey.", bullet_style))
    story.append(Paragraph("4. <code>RULE_BRUTE_FORCE_CONSOLE</code> (HIGH - T1110): Falhas sucessivas de autenticação no ConsoleLogin.", bullet_style))
    story.append(Paragraph("5. <code>RULE_SENSITIVE_S3_PUBLIC_ACCESS</code> (HIGH - T1530): Remoção de Block Public Access e alteração de ACLs.", bullet_style))
    story.append(Paragraph("6. <code>RULE_UNAUTHORIZED_API_BURST</code> (MEDIUM - T1087): Erros AccessDenied e UnauthorizedOperation.", bullet_style))
    story.append(Paragraph("7. <code>RULE_NETWORK_PERIMETER_TAMPERING</code> (MEDIUM - T1562.007): Alteração permissiva de Security Groups.", bullet_style))
    story.append(Paragraph("• <b>Extensibilidade:</b> Permite acoplar novas classes herdadas de <code>BaseCloudTrailRule</code> via <code>register_rule()</code>.", bullet_style))

    # MAO-14
    story.append(Paragraph("3.4. MAO-14: Unificação do Pipeline Híbrido e Persistência SQLite (secops_core/pipeline.py)", h2_style))
    story.append(Paragraph(
        "Orquestrador central que executa todo o fluxo de ponta a ponta: <code>logs_simulados.jsonl</code> &rarr; <code>LGMS</code> "
        "&rarr; <code>ZScore + Isolation Forest + CloudTrail Rules</code> &rarr; <code>SQLite</code>.",
        body_style
    ))
    story.append(Paragraph("• <b>Fusão de Decisão (Ensemble):</b> O evento é marcado como anomalia se qualquer um dos detectores o sinalizar.", bullet_style))
    story.append(Paragraph("• <b>Cálculo de Severidade Combinada:</b> Consenso entre 2 ou mais detectores eleva automaticamente o alerta para no mínimo HIGH.", bullet_style))
    story.append(Paragraph("• <b>Justificativa Técnica Estruturada:</b> Sintetiza o motivo de cada motor de detecção no campo <code>technical_justification</code>.", bullet_style))
    story.append(Paragraph("• <b>Persistência Completa:</b> Grava todos os logs enriquecidos em <code>processed_logs</code> e as anomalias em <code>anomalies</code>.", bullet_style))
    story.append(Paragraph("• <b>Interface CLI:</b> Executável no terminal via <code>python -m secops_core.pipeline --file ...</code> com opção de exportação JSON.", bullet_style))
    story.append(Spacer(1, 4))

    # MAO-16
    story.append(Paragraph("3.5. MAO-16: Templates Jinja2 Estruturados (secops_core/explainer/templates/)", h2_style))
    story.append(Paragraph(
        "Para garantir que o modelo de linguagem local gere laudos concisos e sem alucinações, foi criado um sistema "
        "estrito de templates em <code>secops_core/explainer/templates/alert_explanation.j2</code> e renderizador Python em <code>templates.py</code>.",
        body_style
    ))
    story.append(Paragraph("• <b>Injeção Contextual:</b> Injeta dados do evento, métricas zscore, score iforest, regras disparadas e severidade.", bullet_style))
    story.append(Paragraph("• <b>Estrutura Padronizada das 4 Seções Obrigatórias:</b>", bullet_style))
    story.append(Paragraph("&nbsp;&nbsp;&nbsp;&nbsp;<b>1) O que aconteceu (Resumo Simples)</b> — Visão executiva em 2 a 3 frases.", bullet_style))
    story.append(Paragraph("&nbsp;&nbsp;&nbsp;&nbsp;<b>2) Por que foi considerado anômalo</b> — Diagnóstico técnico do desvio estatístico/regra.", bullet_style))
    story.append(Paragraph("&nbsp;&nbsp;&nbsp;&nbsp;<b>3) Risco Potencial / Mapeamento MITRE ATT&CK</b> — Impacto real e táticas associadas.", bullet_style))
    story.append(Paragraph("&nbsp;&nbsp;&nbsp;&nbsp;<b>4) Ação Recomendada (Contenção & Remediação)</b> — Exatamente 3 ações práticas e imediatas.", bullet_style))
    story.append(Paragraph("• <b>Aderência a Diretrizes:</b> Eliminação total de concatenações de string hardcoded, operando 100% via Jinja2.", bullet_style))
    story.append(Spacer(1, 4))

    # MAO-17
    story.append(Paragraph("3.6. MAO-17: Cliente Ollama Local e Fallback Resiliente (secops_core/explainer/ollama_client.py)", h2_style))
    story.append(Paragraph(
        "Implementa a classe <code>OllamaClient</code> para comunicação HTTP com a API local do Ollama "
        "(<code>POST http://localhost:11434/api/generate</code> com <code>stream=False</code>) mantendo custo zero.",
        body_style
    ))
    story.append(Paragraph("• <b>Healthcheck & Timeout:</b> Métodos <code>check_health()</code> e <code>is_alive()</code> com timeout configurável.", bullet_style))
    story.append(Paragraph("• <b>Fallback Inteligente Jinja2:</b> Se o Ollama estiver desligado ou der timeout, o sistema ativa automaticamente o template de contingência <code>fallback_explanation.j2</code> sem lançar exceções não tratadas.", bullet_style))
    story.append(Paragraph("• <b>Persistência no SQLite:</b> O método <code>explain_and_persist()</code> atualiza a coluna <code>ai_explanation</code> simultaneamente nas tabelas <code>processed_logs</code> e <code>anomalies</code>.", bullet_style))
    story.append(Spacer(1, 4))

    # MAO-18
    story.append(Paragraph("3.7. MAO-18: Endpoints REST em FastAPI (api/main.py e api/schemas.py)", h2_style))
    story.append(Paragraph(
        "Expõe a camada de serviços através de uma API RESTful moderna, assíncrona e autodocumentada com contratos Pydantic estritos:",
        body_style
    ))
    story.append(Paragraph("• <code>GET /health</code>: Retorna status da API, integridade do banco SQLite e conectividade com o Ollama local.", bullet_style))
    story.append(Paragraph("• <code>GET /stats</code>: Resumo executivo com total analisado, total de anomalias, taxa percentual, distribuição por severidade, contagem por detector e top eventos/IPs.", bullet_style))
    story.append(Paragraph("• <code>GET /logs</code>: Listagem paginada de logs processados com filtros combinados (<code>is_anomaly</code>, <code>severity</code>, <code>event_name</code>, <code>user</code>, <code>source_ip</code>, <code>detector_type</code>, <code>limit</code>, <code>offset</code>).", bullet_style))
    story.append(Paragraph("• <code>GET /anomalies/{event_id}</code>: Detalhes completos de um alerta específico (scores e laudo IA) com retorno 404 apropriado se não encontrado.", bullet_style))
    story.append(Paragraph("• <code>POST /anomalies/{event_id}/explain</code>: Dispara ou recupera laudo técnico via LLM com persistência no banco.", bullet_style))
    story.append(Paragraph("• <code>POST /pipeline/run</code>: Disparo do pipeline de detecção sobre lote de logs com relatório quantitativo.", bullet_style))
    story.append(Paragraph("• <b>Validação & Swagger:</b> Retornos HTTP estritos (200, 404, 422 para paginação inválida) e documentação interativa em <code>/docs</code>.", bullet_style))
    story.append(PageBreak())

    # ==================== CAPÍTULO 4: GUIA DE COMANDOS ====================
    story.append(Paragraph("4. Guia Prático de Instruções e Comandos", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=c_accent, spaceBefore=2, spaceAfter=8))

    story.append(Paragraph(
        "Abaixo estão as instruções e comandos práticos para operar cada ferramenta do ecossistema SecOps Assistido "
        "no ambiente Linux:",
        body_style
    ))

    cmd_box_1 = (
        "# 1. Executar a Suíte Completa de Testes Automatizados (63 testes)\n"
        ".venv/bin/pytest -v\n\n"
        "# 2. Executar Testes Específicos por Módulo\n"
        ".venv/bin/pytest tests/test_pipeline_hybrid.py -v   # MAO-14: Pipeline Híbrido\n"
        ".venv/bin/pytest tests/test_jinja_templates.py -v    # MAO-16: Templates Jinja2\n"
        ".venv/bin/pytest tests/test_ollama_client.py -v     # MAO-17: Cliente Ollama & Fallback\n"
        ".venv/bin/pytest tests/test_api.py -v               # MAO-18: Endpoints REST FastAPI\n"
        ".venv/bin/pytest tests/test_zscore_detector.py -v   # MAO-11: Detector Z-Score\n"
        ".venv/bin/pytest tests/test_isolation_forest.py -v  # MAO-12: Isolation Forest\n"
        ".venv/bin/pytest tests/test_cloudtrail_rules.py -v  # MAO-13: Regras CloudTrail"
    )
    story.append(Preformatted(cmd_box_1, code_style))

    cmd_box_2 = (
        "# 3. Executar o Pipeline Híbrido de Detecção de Ponta a Ponta via CLI\n"
        ".venv/bin/python3 -m secops_core.pipeline --file data/logs_simulados.jsonl\n\n"
        "# 4. Executar o Pipeline com Geração de Laudos por IA para Eventos Críticos\n"
        ".venv/bin/python3 -m secops_core.pipeline --file data/logs_simulados.jsonl --explain\n\n"
        "# 5. Exportar Relatório Executivo em JSON\n"
        ".venv/bin/python3 -m secops_core.pipeline --file data/logs_simulados.jsonl --output relatorio_execucao.json"
    )
    story.append(Preformatted(cmd_box_2, code_style))

    cmd_box_3 = (
        "# 6. Iniciar o Servidor da API REST FastAPI (Swagger UI em http://localhost:8000/docs)\n"
        ".venv/bin/uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload\n\n"
        "# 7. Consultar Endpoints via Terminal (Exemplos cURL)\n"
        "curl -s http://localhost:8000/health | jq .\n"
        "curl -s http://localhost:8000/stats | jq .\n"
        "curl -s 'http://localhost:8000/logs?severity=CRITICAL&limit=5' | jq .\n\n"
        "# 8. Iniciar o Dashboard Interativo Streamlit (Interface SOC)\n"
        ".venv/bin/streamlit run dashboard/app.py --server.port 8501"
    )
    story.append(Preformatted(cmd_box_3, code_style))
    story.append(Spacer(1, 6))

    # ==================== CAPÍTULO 5: MATRIZ DE TESTES ====================
    story.append(Paragraph("5. Matriz de Qualidade e Cobertura de Testes Automatizados", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=c_accent, spaceBefore=2, spaceAfter=8))

    story.append(Paragraph(
        "A integridade de todas as entregas é assegurada por <b>63 testes automatizados</b> executados "
        "com <b>100% de sucesso</b>. A tabela abaixo sintetiza o escopo coberto por cada suíte:",
        body_style
    ))

    tests_summary_data = [
        [Paragraph("<b>Arquivo de Teste</b>", table_header_style), Paragraph("<b>Tarefa</b>", table_header_style), Paragraph("<b>Escopo e Critérios Verificados</b>", table_header_style), Paragraph("<b>Qtd</b>", table_header_style), Paragraph("<b>Status</b>", table_header_style)],
        [
            Paragraph("<code>tests/test_pipeline_hybrid.py</code>", table_cell_style),
            Paragraph("MAO-14", table_cell_style),
            Paragraph("Fluxo end-to-end, regra 'qualquer detector marca anomalia', fusão de severidade, justificativa técnica e CLI.", table_cell_style),
            Paragraph("3", table_cell_style),
            Paragraph("<font color='green'><b>PASS</b></font>", table_cell_style)
        ],
        [
            Paragraph("<code>tests/test_jinja_templates.py</code>", table_cell_style),
            Paragraph("MAO-16", table_cell_style),
            Paragraph("Renderização Jinja2: combinações estatística, ML, regras e híbrida; verificação das 4 seções obrigatórias.", table_cell_style),
            Paragraph("5", table_cell_style),
            Paragraph("<font color='green'><b>PASS</b></font>", table_cell_style)
        ],
        [
            Paragraph("<code>tests/test_ollama_client.py</code>", table_cell_style),
            Paragraph("MAO-17", table_cell_style),
            Paragraph("Mock HTTP do Ollama, acionamento automático de Fallback Jinja2 em falhas/timeout e persistência SQLite.", table_cell_style),
            Paragraph("4", table_cell_style),
            Paragraph("<font color='green'><b>PASS</b></font>", table_cell_style)
        ],
        [
            Paragraph("<code>tests/test_api.py</code>", table_cell_style),
            Paragraph("MAO-18", table_cell_style),
            Paragraph("Endpoints /health, /stats, /logs com paginação e filtros combinados, /anomalies/{id}, status 404 e 422.", table_cell_style),
            Paragraph("8", table_cell_style),
            Paragraph("<font color='green'><b>PASS</b></font>", table_cell_style)
        ],
        [
            Paragraph("<code>tests/test_zscore_detector.py</code>", table_cell_style),
            Paragraph("MAO-11", table_cell_style),
            Paragraph("Distribuição normal, pico extremo, proteção contra &sigma;=0, threshold via env/param e imutabilidade.", table_cell_style),
            Paragraph("7", table_cell_style),
            Paragraph("<font color='green'><b>PASS</b></font>", table_cell_style)
        ],
        [
            Paragraph("<code>tests/test_isolation_forest.py</code>", table_cell_style),
            Paragraph("MAO-12", table_cell_style),
            Paragraph("Treino/inferência, score contínuo, reprodutibilidade (seed 42), ranking multivariado e scaling numérico.", table_cell_style),
            Paragraph("5", table_cell_style),
            Paragraph("<font color='green'><b>PASS</b></font>", table_cell_style)
        ],
        [
            Paragraph("<code>tests/test_cloudtrail_rules.py</code>", table_cell_style),
            Paragraph("MAO-13", table_cell_style),
            Paragraph("100% de precisão para as 7 regras determinísticas CloudTrail, avaliação de logs e extensibilidade modular.", table_cell_style),
            Paragraph("10", table_cell_style),
            Paragraph("<font color='green'><b>PASS</b></font>", table_cell_style)
        ],
        [
            Paragraph("<code>tests/test_db.py</code>", table_cell_style),
            Paragraph("Core DB", table_cell_style),
            Paragraph("Tabelas SQLite, modo WAL, índices analíticos, inserção em lote < 100ms e idempotência contra duplicatas.", table_cell_style),
            Paragraph("5", table_cell_style),
            Paragraph("<font color='green'><b>PASS</b></font>", table_cell_style)
        ],
        [
            Paragraph("<code>tests/test_detectors.py</code>", table_cell_style),
            Paragraph("Core Ens.", table_cell_style),
            Paragraph("Integração cruzada dos detectores e validação de retrocompatibilidade do motor de consolidação.", table_cell_style),
            Paragraph("4", table_cell_style),
            Paragraph("<font color='green'><b>PASS</b></font>", table_cell_style)
        ],
        [
            Paragraph("<code>tests/test_lgms.py</code>", table_cell_style),
            Paragraph("LGMS", table_cell_style),
            Paragraph("Parser streaming, tolerância a corrupção em JSONL e extração de features numéricas/temporais.", table_cell_style),
            Paragraph("3", table_cell_style),
            Paragraph("<font color='green'><b>PASS</b></font>", table_cell_style)
        ],
        [
            Paragraph("<code>tests/test_explainer.py</code>", table_cell_style),
            Paragraph("Explainer", table_cell_style),
            Paragraph("Renderização de prompt e contingência analítica offline.", table_cell_style),
            Paragraph("2", table_cell_style),
            Paragraph("<font color='green'><b>PASS</b></font>", table_cell_style)
        ],
        [
            Paragraph("<code>tests/test_pipeline / generator / setup</code>", table_cell_style),
            Paragraph("Infra", table_cell_style),
            Paragraph("Pipeline end-to-end, gerador sintético e configurações globais.", table_cell_style),
            Paragraph("7", table_cell_style),
            Paragraph("<font color='green'><b>PASS</b></font>", table_cell_style)
        ],
        [
            Paragraph("<b>TOTAL GERAL</b>", table_cell_style),
            Paragraph("<b>MAO 11-18</b>", table_cell_style),
            Paragraph("<b>Cobertura Completa do Sistema SecOps Assistido</b>", table_cell_style),
            Paragraph("<b>63</b>", table_cell_style),
            Paragraph("<font color='green'><b>100% SUCESSO</b></font>", table_cell_style)
        ],
    ]
    t_test_sum = Table(tests_summary_data, colWidths=[130, 50, 215, 35, 70])
    t_test_sum.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), c_secondary),
        ('GRID', (0,0), (-1,-1), 0.5, c_border),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('ROWBACKGROUNDS', (0,1), (-1,-2), [colors.white, c_light]),
        ('BACKGROUND', (0,-1), (-1,-1), colors.HexColor("#e2e8f0")),
        ('PADDING', (0,0), (-1,-1), 3),
    ]))
    story.append(t_test_sum)
    story.append(Spacer(1, 10))

    # Box de Conclusão Final
    final_callout = [[
        Paragraph(
            "<b>Conclusão:</b> O ecossistema SecOps Assistido encontra-se completamente implementado, unificado "
            "e testado. As tarefas MAO-11, MAO-12, MAO-13, MAO-14, MAO-16, MAO-17 e MAO-18 fornecem uma solução "
            "robusta, de custo zero e pronta para ambientes de produção em larga escala.",
            callout_style
        )
    ]]
    t_fin = Table(final_callout, colWidths=[500])
    t_fin.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f0fdf4")),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#86efac")),
        ('PADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(t_fin)

    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"✅ PDF gerado com sucesso em: {filename}")

if __name__ == "__main__":
    out_file = sys.argv[1] if len(sys.argv) > 1 else "SecOps_Assistido_Documentacao_Completa.pdf"
    build_pdf(out_file)
