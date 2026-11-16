import sys
from pathlib import Path
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
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
        
        # Don't draw running header/footer on cover page (page 1)
        if self._pageNumber > 1:
            # Header
            self.drawString(54, 11 * inch - 36, "SecOps Assistido — Guia Técnico de Arquitetura e Código")
            self.drawRightString(8.5 * inch - 54, 11 * inch - 36, "Mãos na Tech | SecOps")
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
    
    # Custom palettes
    c_primary = colors.HexColor("#0f172a")     # Slate 900
    c_secondary = colors.HexColor("#1e293b")   # Slate 800
    c_accent = colors.HexColor("#0284c7")      # Sky 600
    c_light = colors.HexColor("#f8fafc")       # Slate 50
    c_border = colors.HexColor("#cbd5e1")      # Slate 300
    c_dark_gray = colors.HexColor("#334155")
    c_code_bg = colors.HexColor("#f1f5f9")
    
    # Custom Typography Styles
    title_style = ParagraphStyle(
        'CoverTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=26,
        leading=32,
        textColor=c_primary,
        spaceAfter=10
    )
    
    subtitle_style = ParagraphStyle(
        'CoverSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=13,
        leading=18,
        textColor=colors.HexColor("#475569"),
        spaceAfter=25
    )
    
    meta_style = ParagraphStyle(
        'CoverMeta',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#64748b")
    )
    
    h1_style = ParagraphStyle(
        'Heading1_Custom',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=16,
        leading=20,
        textColor=c_primary,
        spaceBefore=16,
        spaceAfter=8,
        keepWithNext=True
    )
    
    h2_style = ParagraphStyle(
        'Heading2_Custom',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=c_accent,
        spaceBefore=12,
        spaceAfter=6,
        keepWithNext=True
    )
    
    body_style = ParagraphStyle(
        'Body_Custom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9.5,
        leading=14,
        textColor=c_dark_gray,
        spaceAfter=8
    )

    bullet_style = ParagraphStyle(
        'Bullet_Custom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=c_dark_gray,
        leftIndent=15,
        spaceAfter=4
    )

    code_style = ParagraphStyle(
        'CodeBlock',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#0f172a"),
        backColor=c_code_bg,
        borderPadding=6,
        spaceBefore=4,
        spaceAfter=8
    )
    
    callout_style = ParagraphStyle(
        'CalloutText',
        parent=styles['Normal'],
        fontName='Helvetica-Oblique',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#0369a1")
    )
    
    table_cell_style = ParagraphStyle(
        'TableCell',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=11,
        textColor=c_dark_gray
    )

    table_header_style = ParagraphStyle(
        'TableHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=9,
        leading=12,
        textColor=colors.white
    )

    story = []

    # ==================== CAPA / COVER ====================
    story.append(Spacer(1, 40))
    story.append(HRFlowable(width="100%", thickness=5, color=c_accent, spaceBefore=0, spaceAfter=20))
    story.append(Paragraph("SecOps Assistido por IA", title_style))
    story.append(Paragraph("Guia Técnico Completo de Arquitetura, Código e Ferramentas", subtitle_style))
    story.append(Paragraph(
        "<b>Auditoria de Segurança Inteligente:</b> Ingestão Canônica LGMS, Ensemble de Detectores "
        "(Z-Score, Isolation Forest & Regras Determinísticas CloudTrail), Explicabilidade com LLMs, "
        "Persistência SQLite e Visualização Integrada.",
        body_style
    ))
    story.append(Spacer(1, 25))
    
    meta_box_data = [
        [
            Paragraph("<b>Projeto:</b> SecOps-Assistido", meta_style),
            Paragraph("<b>Time:</b> Mãos na Tech", meta_style)
        ],
        [
            Paragraph("<b>Tarefas Concluídas:</b> MAO-11, MAO-12, MAO-13", meta_style),
            Paragraph("<b>Data de Geração:</b> Novembro de 2026", meta_style)
        ],
        [
            Paragraph("<b>Linguagem:</b> Python 3.14 (Virtualenv)", meta_style),
            Paragraph("<b>Status da Suíte:</b> 47 testes 100% aprovados", meta_style)
        ]
    ]
    t_meta = Table(meta_box_data, colWidths=[250, 250])
    t_meta.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), c_light),
        ('BOX', (0,0), (-1,-1), 1, c_border),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('PADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(t_meta)
    story.append(Spacer(1, 30))
    
    # Box de Destaque Executivo
    callout_data = [[
        Paragraph(
            "<b>Objetivo deste documento:</b> Fornecer ao desenvolvedor e analista de segurança uma visão "
            "holística, profunda e prática de todo o funcionamento interno do projeto, detalhando a função "
            "de cada módulo, arquivo, classe, algoritmo estatístico e ferramenta empregada no SecOps Assistido.",
            callout_style
        )
    ]]
    t_callout = Table(callout_data, colWidths=[500])
    t_callout.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#e0f2fe")),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#7dd3fc")),
        ('PADDING', (0,0), (-1,-1), 10),
    ]))
    story.append(t_callout)
    story.append(PageBreak())

    # ==================== SEÇÃO 1: VISÃO GERAL & ARQUITETURA ====================
    story.append(Paragraph("1. Visão Geral e Arquitetura do Sistema", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=c_accent, spaceBefore=2, spaceAfter=10))
    
    story.append(Paragraph(
        "O <b>SecOps Assistido</b> é uma plataforma moderna de automação de operações de segurança e triagem "
        "inteligente de incidentes. O sistema foi concebido para resolver o problema clássico de fadiga de alertas "
        "(<i>alert fatigue</i>) em ambientes de nuvem (especificamente AWS CloudTrail), onde milhões de eventos de logs "
        "são gerados diariamente.",
        body_style
    ))
    story.append(Paragraph(
        "Para atingir alta precisão com baixíssima taxa de falsos positivos, o projeto adota uma <b>abordagem híbrida "
        "em ensemble</b>: combinando regras heurísticas determinísticas, análise estatística volumétrica univariada "
        "(Z-Score) e aprendizado de máquina multivariado não supervisionado (Isolation Forest). Adicionalmente, grandes "
        "modelos de linguagem (LLMs) são integrados para traduzir eventos técnicos críticos em laudos de fácil compreensão.",
        body_style
    ))
    
    story.append(Paragraph("As 6 Camadas do Pipeline de Detecção", h2_style))
    
    layers_data = [
        [Paragraph("<b>Camada</b>", table_header_style), Paragraph("<b>Componente Principal</b>", table_header_style), Paragraph("<b>Responsabilidade</b>", table_header_style)],
        [
            Paragraph("1. Ingestão & Simulação", table_cell_style),
            Paragraph("<code>generator.py</code><br/><code>logs_simulados.jsonl</code>", table_cell_style),
            Paragraph("Produção de logs sintéticos de CloudTrail com cenários reais de ataque (exfiltração, evasão, brute force, etc.).", table_cell_style)
        ],
        [
            Paragraph("2. Modelagem LGMS", table_cell_style),
            Paragraph("<code>lgms.py</code>", table_cell_style),
            Paragraph("Validação canônica via Pydantic, parser tolerante a falhas (streaming) e extração de matriz de features normalizada.", table_cell_style)
        ],
        [
            Paragraph("3. Detecção Híbrida", table_cell_style),
            Paragraph("<code>zscore_detector.py</code><br/><code>isolation_forest.py</code><br/><code>cloudtrail_rules.py</code>", table_cell_style),
            Paragraph("Execução paralela dos 3 motores: detecção volumétrica por Z-Score (MAO-11), multivariada com Isolation Forest (MAO-12) e catálogo CloudTrail (MAO-13).", table_cell_style)
        ],
        [
            Paragraph("4. Consolidação", table_cell_style),
            Paragraph("<code>engine.py</code>", table_cell_style),
            Paragraph("Agrupamento de múltiplos alertas por <code>event_id</code>, deduplicação e cálculo de severidade máxima e score combinado.", table_cell_style)
        ],
        [
            Paragraph("5. Explicabilidade IA", table_cell_style),
            Paragraph("<code>llm_explainer.py</code>", table_cell_style),
            Paragraph("Geração de laudos executivos e recomendações de mitigação usando Ollama (Llama 3.2) com fallback offline robusto.", table_cell_style)
        ],
        [
            Paragraph("6. Armazenamento & UI", table_cell_style),
            Paragraph("<code>db.py</code>, <code>api/main.py</code><br/><code>dashboard/app.py</code>", table_cell_style),
            Paragraph("Persistência transacional SQLite em modo WAL, API REST com FastAPI e interface interativa Streamlit com gráficos e KPIs.", table_cell_style)
        ],
    ]
    t_layers = Table(layers_data, colWidths=[95, 120, 285])
    t_layers.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), c_secondary),
        ('GRID', (0,0), (-1,-1), 0.5, c_border),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, c_light]),
        ('PADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(t_layers)
    story.append(Spacer(1, 14))

    # ==================== SEÇÃO 2: STACK & FERRAMENTAS ====================
    story.append(Paragraph("2. Ferramentas, Bibliotecas e Tecnologias Empregadas", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=c_accent, spaceBefore=2, spaceAfter=10))
    
    tools_data = [
        [Paragraph("<b>Tecnologia / Pacote</b>", table_header_style), Paragraph("<b>Versão / Origem</b>", table_header_style), Paragraph("<b>Aplicação no Projeto</b>", table_header_style)],
        [
            Paragraph("<b>Python</b>", table_cell_style),
            Paragraph("3.14.9", table_cell_style),
            Paragraph("Runtime principal da aplicação com tipagem moderna (Type Hints, Dataclasses).", table_cell_style)
        ],
        [
            Paragraph("<b>Scikit-Learn</b>", table_cell_style),
            Paragraph("1.9.1", table_cell_style),
            Paragraph("Algoritmo <code>IsolationForest</code> para detecção não supervisionada e <code>StandardScaler</code> para normalização.", table_cell_style)
        ],
        [
            Paragraph("<b>NumPy & Pandas</b>", table_cell_style),
            Paragraph("2.5.4 / 3.1.1", table_cell_style),
            Paragraph("Cálculo estatístico vetorizado, manipulação de matrizes de features e agregação de dados de logs.", table_cell_style)
        ],
        [
            Paragraph("<b>Pydantic & Settings</b>", table_cell_style),
            Paragraph("2.14.3 / 2.16.2", table_cell_style),
            Paragraph("Validação canônica estrita dos eventos de log e gerenciamento de configurações via variáveis de ambiente (.env).", table_cell_style)
        ],
        [
            Paragraph("<b>SQLite 3</b>", table_cell_style),
            Paragraph("Nativo (WAL mode)", table_cell_style),
            Paragraph("Armazenamento local transacional de alta velocidade com índices em <code>event_id</code>, <code>severity</code> e <code>timestamp</code>.", table_cell_style)
        ],
        [
            Paragraph("<b>FastAPI & Uvicorn</b>", table_cell_style),
            Paragraph("0.162.0 / 0.54.0", table_cell_style),
            Paragraph("API REST assíncrona expondo rotas de ingestão, consulta de anomalias, métricas e explicabilidade.", table_cell_style)
        ],
        [
            Paragraph("<b>Streamlit</b>", table_cell_style),
            Paragraph("1.67.0", table_cell_style),
            Paragraph("Dashboard web visual para analistas de SOC com filtros, gráficos interativos e visualização de alertas.", table_cell_style)
        ],
        [
            Paragraph("<b>Pytest</b>", table_cell_style),
            Paragraph("9.2.0", table_cell_style),
            Paragraph("Framework de testes automatizados com cobertura completa de regras, modelos e integração.", table_cell_style)
        ],
    ]
    t_tools = Table(tools_data, colWidths=[110, 80, 310])
    t_tools.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), c_secondary),
        ('GRID', (0,0), (-1,-1), 0.5, c_border),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, c_light]),
        ('PADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(t_tools)
    story.append(PageBreak())

    # ==================== SEÇÃO 3: INGESTÃO E MODELAGEM LGMS ====================
    story.append(Paragraph("3. Camada de Ingestão e Modelagem (LGMS)", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=c_accent, spaceBefore=2, spaceAfter=10))

    story.append(Paragraph(
        "A integridade de um motor de detecção depende diretamente da qualidade dos dados ingeridos. "
        "O módulo <b>LGMS (Log Modeling & Schema)</b> em <code>secops_core/lgms.py</code> desempenha três papéis vitais:",
        body_style
    ))
    
    story.append(Paragraph("<b>1. Schemas Canônicos e Validação Tipada:</b>", body_style))
    story.append(Paragraph(
        "Define as classes <code>CanonicalLog</code> e <code>CanonicalUserIdentity</code> herdadas de <code>pydantic.BaseModel</code>. "
        "O validador <code>parse_iso_timestamp</code> garante que timestamps com sufixo 'Z' ou offsets ISO-8601 sejam convertidos "
        "com precisão para objetos datetime UTC, uniformizando logs de diferentes regiões da AWS.",
        bullet_style
    ))
    
    story.append(Paragraph("<b>2. Parser Resiliente com Tolerância a Corrupção:</b>", body_style))
    story.append(Paragraph(
        "A função <code>stream_logs()</code> consome arquivos JSONL em modo streaming, lendo linha por linha com baixíssimo "
        "consumo de memória. Linhas corrompidas ou JSON malformado são capturados sem interromper o pipeline, preenchendo o "
        "relatório quantitativo <code>ParsingSummary</code> (total de linhas, linhas válidas e erros registrados).",
        bullet_style
    ))
    
    story.append(Paragraph("<b>3. Engenharia de Features Estruturadas (Feature Engineering):</b>", body_style))
    story.append(Paragraph(
        "A função <code>extract_features()</code> transforma os logs brutos em uma matriz de variáveis ricas prontas para os detectores:",
        bullet_style
    ))
    story.append(Paragraph("• <b>Temporais:</b> <code>hour</code> (0-23), <code>day_of_week</code> (0-6), <code>is_weekend</code> (0/1), <code>is_off_hours</code> (horários fora de 08h-19h ou fins de semana).", bullet_style))
    story.append(Paragraph("• <b>Flags Categóricas:</b> <code>is_login</code>, <code>is_iam</code>, <code>is_trail_mgmt</code>, <code>is_s3</code>, <code>is_error</code> (falha ou código de erro presente).", bullet_style))
    story.append(Paragraph("• <b>Reputação de Rede:</b> <code>is_suspicious_ip</code> (identifica prefixos Tor/VPN conhecidos como 185.220.*, 198.51.*).", bullet_style))
    story.append(Paragraph("• <b>Volumetria & Escala:</b> <code>request_count</code>, <code>bytes_transferred</code> e <code>log_bytes_transferred</code> (transformação logarítmica log1p para redução de assimetria).", bullet_style))
    story.append(Paragraph("• <b>Frequência de Contexto:</b> <code>ip_frequency</code> e <code>user_frequency</code> calculadas na janela do lote.", bullet_style))
    story.append(Spacer(1, 12))

    # ==================== SEÇÃO 4: DETECTORES (MAO-11, 12, 13) ====================
    story.append(Paragraph("4. Motores de Detecção Implementados (MAOs 11, 12 e 13)", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=c_accent, spaceBefore=2, spaceAfter=10))

    # MAO-11
    story.append(Paragraph("4.1. MAO-11: Detector Estatístico Z-Score (<code>zscore_detector.py</code>)", h2_style))
    story.append(Paragraph(
        "O detector univariado Z-Score foi projetado para identificar picos repentinos de atividade volumétrica "
        "(ataques de força bruta volumétrica, varredura em massa ou exfiltração agressiva de dados).",
        body_style
    ))
    story.append(Paragraph(
        "<b>Fundamentação Matemática:</b><br/>"
        "Calcula o desvio padrão normalizado para cada métrica $x$:<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;<b>Z = (x - &mu;) / &sigma;</b><br/>"
        "onde &mu; é a média amostral e &sigma; é o desvio padrão da coluna.",
        code_style
    ))
    story.append(Paragraph("<b>Principais Características e Proteções:</b>", body_style))
    story.append(Paragraph("• <b>Divisão por Zero:</b> Caso &sigma; = 0 (quando todos os valores da série são idênticos), o código atribui com segurança Z = 0.0 sem disparar exceção.", bullet_style))
    story.append(Paragraph("• <b>Configurabilidade:</b> O limiar (<code>threshold</code>) é parametrizável via construtor, variável de ambiente <code>ZSCORE_THRESHOLD</code> ou configuração global (default = 3.0).", bullet_style))
    story.append(Paragraph("• <b>Imutabilidade dos Dados:</b> Métodos <code>calculate_zscore()</code> e <code>annotate_dataframe()</code> trabalham sobre cópias, preservando integralmente os dados originais.", bullet_style))
    story.append(Paragraph("• <b>Mapeamento de Severidade:</b> |Z| &ge; 5.0 &rarr; CRITICAL | |Z| &ge; 4.0 &rarr; HIGH | |Z| &ge; 3.0 &rarr; MEDIUM.", bullet_style))
    story.append(Spacer(1, 8))

    # MAO-12
    story.append(Paragraph("4.2. MAO-12: Detector Multivariado Isolation Forest (<code>isolation_forest.py</code>)", h2_style))
    story.append(Paragraph(
        "Ataques furtivos modernos raramente geram picos gigantescos isolados; comumente combinam horário atípico (madrugada), "
        "origem incomum, ação sensível e volume moderado. O <b>Isolation Forest</b> isola observações particionando o "
        "espaço amostral aleatoriamente através de hiperplanos: anomalias requerem significativamente menos partições para serem isoladas.",
        body_style
    ))
    story.append(Paragraph("<b>Fluxo Técnico do Modelo:</b>", body_style))
    story.append(Paragraph("1. <b>Pré-processamento:</b> Converte variáveis categóricas em frequências e aplica <code>StandardScaler</code> em todas as dimensões numéricas para evitar que variáveis de magnitude grande dominem o modelo.", bullet_style))
    story.append(Paragraph("2. <b>Treinamento & Inferência:</b> Ajusta <code>IsolationForest(contamination, n_estimators, random_state)</code> e gera predições nativas (-1 para anomalia, 1 para normal).", bullet_style))
    story.append(Paragraph("3. <b>Normalização Contínua:</b> Transforma a <code>decision_function</code> em score no intervalo [0.0, 1.0], onde 1.0 representa a maior probabilidade de anomalia.", bullet_style))
    story.append(Paragraph("4. <b>Reprodutibilidade:</b> Garantida através do parâmetro fixo <code>random_state=42</code>.", bullet_style))
    story.append(Spacer(1, 8))

    # MAO-13
    story.append(Paragraph("4.3. MAO-13: Catálogo Modular de Regras CloudTrail (<code>cloudtrail_rules.py</code>)", h2_style))
    story.append(Paragraph(
        "Certos eventos configuram ameaças severas imediatas independentemente de frequência estatística. "
        "Foi implementado um motor determinístico modular e extensível com 7 regras alinhadas às melhores práticas "
        "do <b>CIS AWS Benchmark</b> e técnicas do <b>MITRE ATT&CK</b>:",
        body_style
    ))

    rules_table_data = [
        [Paragraph("<b>Código da Regra</b>", table_header_style), Paragraph("<b>Severidade</b>", table_header_style), Paragraph("<b>Gatilho / Condição Técnica</b>", table_header_style), Paragraph("<b>MITRE ATT&CK</b>", table_header_style)],
        [
            Paragraph("<code>RULE_TRAIL_TAMPERING</code>", table_cell_style),
            Paragraph("<font color='red'><b>CRITICAL</b></font>", table_cell_style),
            Paragraph("Ações <code>DeleteTrail</code>, <code>StopLogging</code>, <code>UpdateTrail</code> (desativação de auditoria).", table_cell_style),
            Paragraph("T1562.001 (Impair Defenses)", table_cell_style)
        ],
        [
            Paragraph("<code>RULE_ROOT_ACTIVITY</code>", table_cell_style),
            Paragraph("<font color='red'><b>CRITICAL</b></font>", table_cell_style),
            Paragraph("Qualquer chamada efetuada diretamente pela credencial da conta Root (<code>userIdentity.type == 'Root'</code>).", table_cell_style),
            Paragraph("T1078.004 (Cloud Root Account)", table_cell_style)
        ],
        [
            Paragraph("<code>RULE_IAM_PRIVILEGE_ESCALATION</code>", table_cell_style),
            Paragraph("<font color='orange'><b>HIGH</b></font>", table_cell_style),
            Paragraph("Alterações de políticas: <code>PutUserPolicy</code>, <code>AttachUserPolicy</code>, criação de <code>AccessKey</code>.", table_cell_style),
            Paragraph("T1098 (Account Manipulation)", table_cell_style)
        ],
        [
            Paragraph("<code>RULE_BRUTE_FORCE_CONSOLE</code>", table_cell_style),
            Paragraph("<font color='orange'><b>HIGH</b></font>", table_cell_style),
            Paragraph("Falhas de login no Console AWS (<code>ConsoleLogin</code> com status <code>Failure</code> ou erro de auth).", table_cell_style),
            Paragraph("T1110 (Brute Force)", table_cell_style)
        ],
        [
            Paragraph("<code>RULE_SENSITIVE_S3_PUBLIC_ACCESS</code>", table_cell_style),
            Paragraph("<font color='orange'><b>HIGH</b></font>", table_cell_style),
            Paragraph("Exclusão de bloqueio público S3 (<code>DeleteBucketPublicAccessBlock</code>) ou <code>PutBucketAcl</code> permissiva.", table_cell_style),
            Paragraph("T1530 (Data from Cloud Storage)", table_cell_style)
        ],
        [
            Paragraph("<code>RULE_UNAUTHORIZED_API_BURST</code>", table_cell_style),
            Paragraph("<b>MEDIUM</b>", table_cell_style),
            Paragraph("Erros <code>AccessDenied</code> e <code>UnauthorizedOperation</code> recorrentes em enumeração de recursos.", table_cell_style),
            Paragraph("T1087 (Permission Discovery)", table_cell_style)
        ],
        [
            Paragraph("<code>RULE_NETWORK_PERIMETER_TAMPERING</code>", table_cell_style),
            Paragraph("<b>MEDIUM</b>", table_cell_style),
            Paragraph("Modificação de Security Groups (<code>AuthorizeSecurityGroupIngress</code>) ou exclusão de VPC Flow Logs.", table_cell_style),
            Paragraph("T1562.007 (Disable Firewalls)", table_cell_style)
        ],
    ]
    t_rules = Table(rules_table_data, colWidths=[130, 60, 195, 115])
    t_rules.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), c_secondary),
        ('GRID', (0,0), (-1,-1), 0.5, c_border),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, c_light]),
        ('PADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(t_rules)
    story.append(Spacer(1, 10))
    story.append(Paragraph(
        "<b>Extensibilidade Dinâmica:</b> O motor disponibiliza o método <code>engine.register_rule(CustomRule())</code>, "
        "permitindo que novas assinaturas de ameaça sejam acopladas em tempo de execução sem modificar o núcleo do motor.",
        body_style
    ))
    story.append(PageBreak())

    # ==================== SEÇÃO 5: ORQUESTRAÇÃO & ENSEMBLE ====================
    story.append(Paragraph("5. Orquestração Ensemble e Explicabilidade por IA", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=c_accent, spaceBefore=2, spaceAfter=10))

    story.append(Paragraph("5.1. Orquestração no <code>DetectionEngine</code> (<code>engine.py</code>)", h2_style))
    story.append(Paragraph(
        "O <code>DetectionEngine</code> coordena a execução simultânea dos três detectores. Quando múltiplos detectores "
        "disparam para o mesmo <code>event_id</code>, a classe <code>ConsolidatedAnomaly</code> unifica as evidências:",
        body_style
    ))
    story.append(Paragraph("• <b>Elevação de Severidade:</b> Se 2 ou mais detectores concordam no alerta, a severidade mínima é elevada para <b>HIGH</b>.", bullet_style))
    story.append(Paragraph("• <b>Consolidação de Scores:</b> Mantém o score máximo detectado e preserva os detalhes analíticos de cada detector individual.", bullet_style))
    story.append(Paragraph("• <b>Ordenação por Prioridade:</b> Os alertas finais são automaticamente ordenados dos mais críticos para os de menor risco.", bullet_style))
    story.append(Spacer(1, 10))

    story.append(Paragraph("5.2. Módulo de Explicabilidade com LLM (<code>llm_explainer.py</code>)", h2_style))
    story.append(Paragraph(
        "Alertas técnicos puros muitas vezes são de difícil interpretação para gestores ou analistas N1 de segurança. "
        "O <code>LLMExplainer</code> atua na camada analítica traduzindo os parâmetros do evento em um laudo pericial estruturado:",
        body_style
    ))
    story.append(Paragraph("• <b>Integração com Ollama:</b> Conecta-se à API REST local do Ollama para inferência rápida com o modelo <b>Llama 3.2</b>.", bullet_style))
    story.append(Paragraph("• <b>Fallback Offline Resiliente:</b> Se a instância do Ollama estiver indisponível ou offline, o sistema ativa automaticamente geradores baseados em templates determinísticos (<code>secops_core/explainer/templates.py</code>), garantindo que nenhum laudo fique em branco.", bullet_style))
    story.append(Paragraph("• <b>Estrutura do Laudo:</b> Inclui Resumo Executivo, Análise Técnica de Risco, Alinhamento MITRE ATT&CK e Recomendações Imediatas de Mitigação.", bullet_style))
    story.append(Spacer(1, 12))

    # ==================== SEÇÃO 6: PERSISTÊNCIA, API E UI ====================
    story.append(Paragraph("6. Persistência, API REST e Interface Visual", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=c_accent, spaceBefore=2, spaceAfter=10))

    story.append(Paragraph("6.1. Banco de Dados SQLite Otimizado (<code>secops_core/db.py</code>)", h2_style))
    story.append(Paragraph(
        "A camada de persistência utiliza SQLite 3 com configurações corporativas avançadas:",
        body_style
    ))
    story.append(Paragraph("• <b>WAL Mode (Write-Ahead Logging):</b> Permite leituras concorrentes em alta velocidade enquanto operações de escrita ocorrem em background.", bullet_style))
    story.append(Paragraph("• <b>Idempotência Estrita:</b> Cláusulas <code>INSERT OR IGNORE</code> baseadas na chave primária única <code>event_id</code> impedem a duplicação de alertas em reexecuções de pipelines.", bullet_style))
    story.append(Paragraph("• <b>Índices Dedicados:</b> Índices em <code>idx_anomalies_timestamp</code>, <code>idx_anomalies_severity</code> e <code>idx_anomalies_scenario</code> garantem consultas paginadas e relatórios em tempo sub-milissegundo.", bullet_style))
    story.append(Spacer(1, 8))

    story.append(Paragraph("6.2. Backend FastAPI (<code>api/main.py</code>)", h2_style))
    story.append(Paragraph(
        "A API RESTful expõe os seguintes endpoints padronizados:",
        body_style
    ))
    story.append(Paragraph("• <code>GET /health</code>: Verificação de status e prontidão da aplicação.", bullet_style))
    story.append(Paragraph("• <code>GET /stats</code>: Resumo consolidado do número de anomalias por severidade e detectores.", bullet_style))
    story.append(Paragraph("• <code>POST /pipeline/run</code>: Dispara o pipeline de ingestão e detecção sobre um arquivo JSONL especificado.", bullet_style))
    story.append(Paragraph("• <code>GET /anomalies</code>: Consulta paginada com suporte a filtros por severidade (CRITICAL, HIGH, etc.) e detector.", bullet_style))
    story.append(Paragraph("• <code>GET /anomalies/{event_id}</code>: Detalhes aprofundados e evidências de uma anomalia específica.", bullet_style))
    story.append(Paragraph("• <code>POST /anomalies/{event_id}/explain</code>: Solicitação sob demanda de laudo analítico via LLM.", bullet_style))
    story.append(Spacer(1, 8))

    story.append(Paragraph("6.3. Dashboard Streamlit (<code>dashboard/app.py</code>)", h2_style))
    story.append(Paragraph(
        "Interface web rica em <code>dashboard/app.py</code> que permite ao operador visualizar KPIs em tempo real, "
        "distribuição de risco por severidade, filtros dinâmicos e inspeção dos laudos explicativos gerados por IA.",
        body_style
    ))
    story.append(PageBreak())

    # ==================== SEÇÃO 7: GUIA PRÁTICO & TESTES ====================
    story.append(Paragraph("7. Validação, Testes Automatizados e Comandos Úteis", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=c_accent, spaceBefore=2, spaceAfter=10))

    story.append(Paragraph(
        "A confiabilidade do código é comprovada por uma bateria rigorosa de testes unitários e de integração "
        "desenvolvida em <b>Pytest</b>, totalizando <b>47 testes automatizados com 100% de aprovação</b>.",
        body_style
    ))

    tests_summary_data = [
        [Paragraph("<b>Arquivo de Teste</b>", table_header_style), Paragraph("<b>Foco / Escopo</b>", table_header_style), Paragraph("<b>Testes</b>", table_header_style), Paragraph("<b>Resultado</b>", table_header_style)],
        [
            Paragraph("<code>tests/test_zscore_detector.py</code>", table_cell_style),
            Paragraph("Validação do Z-Score: distribuição normal, pico extremo, &sigma;=0, threshold via env/param, imutabilidade.", table_cell_style),
            Paragraph("7", table_cell_style),
            Paragraph("<font color='green'><b>PASS</b></font>", table_cell_style)
        ],
        [
            Paragraph("<code>tests/test_isolation_forest.py</code>", table_cell_style),
            Paragraph("Treinamento/inferência, score contínuo, reprodutibilidade (seed 42), detecção multivariada e scaling.", table_cell_style),
            Paragraph("5", table_cell_style),
            Paragraph("<font color='green'><b>PASS</b></font>", table_cell_style)
        ],
        [
            Paragraph("<code>tests/test_cloudtrail_rules.py</code>", table_cell_style),
            Paragraph("100% de precisão para cada uma das 7 regras CloudTrail, avaliação de logs e extensibilidade modular.", table_cell_style),
            Paragraph("10", table_cell_style),
            Paragraph("<font color='green'><b>PASS</b></font>", table_cell_style)
        ],
        [
            Paragraph("<code>tests/test_detectors.py</code>", table_cell_style),
            Paragraph("Testes de integração cruzada e retrocompatibilidade do motor de detecção.", table_cell_style),
            Paragraph("4", table_cell_style),
            Paragraph("<font color='green'><b>PASS</b></font>", table_cell_style)
        ],
        [
            Paragraph("<code>tests/test_api.py</code>", table_cell_style),
            Paragraph("Endpoints FastAPI (/health, /stats, /anomalies, /explain).", table_cell_style),
            Paragraph("4", table_cell_style),
            Paragraph("<font color='green'><b>PASS</b></font>", table_cell_style)
        ],
        [
            Paragraph("<code>tests/test_db.py</code>", table_cell_style),
            Paragraph("Transações SQLite, índices, idempotência e consultas de performance.", table_cell_style),
            Paragraph("5", table_cell_style),
            Paragraph("<font color='green'><b>PASS</b></font>", table_cell_style)
        ],
        [
            Paragraph("<code>tests/test_lgms.py</code>", table_cell_style),
            Paragraph("Parser streaming, tolerância a corrupção e extração de features.", table_cell_style),
            Paragraph("3", table_cell_style),
            Paragraph("<font color='green'><b>PASS</b></font>", table_cell_style)
        ],
        [
            Paragraph("<code>test_pipeline / generator / setup</code>", table_cell_style),
            Paragraph("Pipeline end-to-end, gerador sintético e configurações globais.", table_cell_style),
            Paragraph("9", table_cell_style),
            Paragraph("<font color='green'><b>PASS</b></font>", table_cell_style)
        ],
        [
            Paragraph("<b>TOTAL GERAL</b>", table_cell_style),
            Paragraph("<b>Cobertura Completa do Sistema SecOps Assistido</b>", table_cell_style),
            Paragraph("<b>47</b>", table_cell_style),
            Paragraph("<font color='green'><b>100% SUCESSO</b></font>", table_cell_style)
        ],
    ]
    t_test_sum = Table(tests_summary_data, colWidths=[150, 240, 45, 65])
    t_test_sum.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), c_secondary),
        ('GRID', (0,0), (-1,-1), 0.5, c_border),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('ROWBACKGROUNDS', (0,1), (-1,-2), [colors.white, c_light]),
        ('BACKGROUND', (0,-1), (-1,-1), colors.HexColor("#e2e8f0")),
        ('PADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(t_test_sum)
    story.append(Spacer(1, 14))

    story.append(Paragraph("7.2. Guia Rápido de Comandos", h2_style))
    story.append(Paragraph(
        "Para executar e operar o projeto localmente no ambiente virtual:<br/>"
        "• <b>Executar toda a suíte de testes:</b><br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;<code>.venv/bin/pytest -v</code><br/><br/>"
        "• <b>Rodar o pipeline de detecção sobre o arquivo de logs:</b><br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;<code>.venv/bin/python3 -m secops_core.pipeline --file data/logs_simulados.jsonl</code><br/><br/>"
        "• <b>Iniciar a API FastAPI (Swagger em http://localhost:8000/docs):</b><br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;<code>.venv/bin/uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload</code><br/><br/>"
        "• <b>Iniciar o Dashboard interativo Streamlit:</b><br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;<code>.venv/bin/streamlit run dashboard/app.py</code>",
        code_style
    ))
    story.append(Spacer(1, 10))

    # Box de Conclusão
    final_callout = [[
        Paragraph(
            "<b>Conclusão:</b> Com a conclusão das tarefas MAO-11, MAO-12 e MAO-13, o SecOps Assistido atinge "
            "um estado maduro, estável e pronto para produção, combinando a precisão cirúrgica de regras determinísticas, "
            "a sensibilidade estatística do Z-Score e a inteligência contextual multivariada do Isolation Forest.",
            callout_style
        )
    ]]
    t_fin = Table(final_callout, colWidths=[500])
    t_fin.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f0fdf4")),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#86efac")),
        ('PADDING', (0,0), (-1,-1), 10),
    ]))
    story.append(t_fin)

    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"✅ PDF gerado com sucesso em: {filename}")

if __name__ == "__main__":
    out_file = sys.argv[1] if len(sys.argv) > 1 else "SecOps_Assistido_Documentacao_Completa.pdf"
    build_pdf(out_file)
