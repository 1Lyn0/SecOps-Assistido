# 🛡️ SecOps Assistido

Plataforma integrada de auditoria, modelagem canônica de logs (LGMS), detecção de anomalias (estatística com Z-Score, Machine Learning com Isolation Forest e Regras Heurísticas MITRE ATT&CK), orquestração de pipeline, persistência em SQLite e explicabilidade contextual com LLM local (Ollama).

---

## 📁 Estrutura do Repositório

```text
basketstar/
├── .env.example              # Modelo de variáveis de ambiente
├── .gitignore                # Arquivos e diretórios ignorados pelo Git
├── pyproject.toml            # Especificação do pacote Python
├── requirements.txt          # Dependências do projeto
├── README.md                 # Documentação principal
├── api/                      # Camada de API REST (FastAPI)
│   ├── __init__.py
│   ├── main.py               # Endpoints REST (/health, /stats, /pipeline/run, /anomalies, /explain)
│   └── schemas.py            # Modelos Pydantic de requisição e resposta
├── dashboard/                # Camada de visualização (Streamlit)
│   └── app.py                # Painel interativo SOC com gráficos e laudos por IA
├── data/                     # Armazenamento de dados locais
│   ├── .gitkeep
│   ├── secops.db             # Banco de dados SQLite de auditoria
│   └── logs_simulados.jsonl  # Logs de auditoria gerados
├── secops_core/              # Pacote central de lógica e processamento
│   ├── __init__.py
│   ├── config.py             # Configurações com fallback e Pydantic Settings
│   ├── db.py                 # Persistência e gerenciamento SQLite
│   ├── generator.py          # Gerador sintético de logs de auditoria com injeção de ameaças
│   ├── lgms.py               # Log Modeling & Schema, parser streaming e feature engineering
│   ├── pipeline.py           # Pipeline unificado de ponta a ponta
│   ├── detectors/            # Motores de detecção
│   │   ├── __init__.py
│   │   ├── base.py           # Classe abstrata BaseDetector e AnomalyResult
│   │   ├── zscore.py         # Detector estatístico paramétrico (Univariate Z-Score)
│   │   ├── isolation_forest.py # Detector multivariado não supervisionado (Isolation Forest)
│   │   ├── rules.py          # Detector baseado em assinaturas de segurança e regras
│   │   └── engine.py         # Orquestrador DetectionEngine e consolidação de alertas
│   └── explainer/            # Explicabilidade com LLMs locais
│       ├── __init__.py
│       ├── templates.py      # Templates Jinja2 estruturados para SecOps
│       └── llm_explainer.py  # Integração com Ollama e contingência analítica offline
└── tests/                    # Suíte completa de testes automatizados com Pytest (20 testes)
    ├── __init__.py
    ├── test_setup.py         # Validação de setup, banco e API scaffold
    ├── test_generator.py     # Validação do gerador e cobertura de cenários
    ├── test_lgms.py          # Validação do parser, tolerância a falhas e features
    ├── test_detectors.py     # Validação dos detectores (Z-Score, Isolation Forest, Regras, Engine)
    ├── test_explainer.py     # Validação do renderizador de prompt e fallback offline
    ├── test_pipeline.py      # Validação da execução e persistência de ponta a ponta
    └── test_api.py           # Validação dos endpoints REST
```

---

## 🚀 Como Executar

### 1. Criar e Ativar o Ambiente Virtual

```bash
# Criar ambiente virtual
python3 -m venv .venv

# Ativar no Linux / macOS
source .venv/bin/activate
```

### 2. Instalar Dependências e Variáveis

```bash
pip install -r requirements.txt
cp .env.example .env
```

### 3. Gerar Dados de Auditoria e Executar o Pipeline

```bash
# 1. Gerar 1000 logs simulados com 5% de anomalias
python -m secops_core.generator --count 1000 --anomaly-rate 0.05 --seed 42 --output data/logs_simulados.jsonl

# 2. Executar o pipeline de ponta a ponta com laudos de IA
python -m secops_core.pipeline --file data/logs_simulados.jsonl --explain
```

### 4. Executar os Testes Automatizados

```bash
pytest -v
```

### 5. Iniciar a API REST (FastAPI)

```bash
uvicorn api.main:app --reload --port 8000
```
- Documentação interativa Swagger: [http://localhost:8000/docs](http://localhost:8000/docs)
- Status da API: [http://localhost:8000/health](http://localhost:8000/health)

### 6. Iniciar o Dashboard Interativo (Streamlit)

```bash
streamlit run dashboard/app.py
```
- Acesse pelo navegador: [http://localhost:8501](http://localhost:8501)

---

## 🧩 Motores de Detecção Implementados

1. **Z-Score Univariado (`ZScoreDetector`)**:
   - Detecta anomalias estatísticas de volumetria em `request_count` e `log_bytes_transferred`.
   - Threshold configurável (padrão $|Z| \ge 3.0$) com cálculo de desvios padrão e classificação automática de severidade (MEDIUM, HIGH, CRITICAL).
2. **Isolation Forest Multivariado (`IsolationForestDetector`)**:
   - Algoritmo não supervisionado que isola observações multidimensionais atípicas na matriz de features do LGMS.
   - Detecta combinações anômalas sutis (ex: chamadas IAM em horários incomuns por identidades atípicas).
3. **Regras Heurísticas e Assinaturas (`RuleBasedDetector`)**:
   - Regras determinísticas mapeadas para o framework MITRE ATT&CK:
     - `SEC-R001`: Evasão de defesa (tentativas de desativar trilhas de auditoria: `DeleteTrail`, `StopLogging`).
     - `SEC-R002`: Escalação de privilégios via API de IAM (`PutUserPolicy`, `AttachUserPolicy`).
     - `SEC-R003`: Força bruta e falhas consecutivas de login (`ConsoleLogin`).
     - `SEC-R004`: Operações sensíveis em horários atípicos / madrugadas.
     - `SEC-R005`: Acessos de nós de rede Tor ou IPs suspeitos.
4. **Orquestrador Central (`DetectionEngine`)**:
   - Agrupa e consolida detecções por `event_id`, combinando scores e elevando o grau de criticidade quando múltiplos motores concordam no alerta.

---

## 🤖 Explicabilidade com IA (LLM Explainer)

O módulo `LLMExplainer` atua como um analista de SecOps Tier 3:
- Formata o contexto técnico em templates Jinja2 estruturados.
- Tenta se comunicar com o modelo local servido pelo Ollama (`llama3.2`).
- **Resiliência Offline**: Caso o Ollama esteja desligado ou inacessível, ativa automaticamente o motor analítico de contingência com conhecimento MITRE ATT&CK, garantindo que o sistema nunca pare e produza laudos completos contendo Causa Raiz, Táticas MITRE e Ações Imediatas de Remediação.
