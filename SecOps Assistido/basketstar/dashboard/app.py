"""Painel interativo Streamlit para visualização de logs, anomalias e explicabilidade de SecOps."""

import sys
from pathlib import Path

# Garante que o diretório raiz do projeto esteja no sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import json
from datetime import datetime
import pandas as pd
import streamlit as st
from secops_core.config import settings
from secops_core.db import (
    get_anomalies,
    get_anomaly_by_event_id,
    get_db_stats,
    update_anomaly_explanation,
)
from secops_core.explainer.llm_explainer import LLMExplainer
from secops_core.generator import generate_simulated_logs
from secops_core.pipeline import run_pipeline

# Configuração da página
st.set_page_config(
    page_title="SecOps Assistido - SOC Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.title("🛡️ SecOps Assistido - Centro de Operações de Segurança (SOC)")
st.caption("Plataforma integrada de Auditoria Canônica (LGMS), Detecção (Z-Score + Isolation Forest + Regras) e Explicabilidade com IA")

# ============================================================================
# Barra Lateral (Controles e Ações)
# ============================================================================
with st.sidebar:
    st.header("⚙️ Ações e Pipeline")

    with st.expander("🎲 Gerar Novos Logs Simulados", expanded=False):
        n_logs = st.slider("Qtd de Eventos", min_value=200, max_value=3000, value=1000, step=100)
        anomaly_rate = st.slider("Taxa de Anomalias (%)", min_value=1.0, max_value=20.0, value=5.0, step=0.5) / 100.0
        if st.button("Gerar Arquivo JSONL", use_container_width=True):
            with st.spinner("Gerando dados de auditoria..."):
                logs = generate_simulated_logs(
                    count=n_logs,
                    anomaly_rate=anomaly_rate,
                    output_path="data/logs_simulados.jsonl",
                )
                st.success(f"Gerados {len(logs)} eventos em 'data/logs_simulados.jsonl'!")

    if st.button("🚀 Executar Pipeline de Detecção", type="primary", use_container_width=True):
        with st.spinner("Executando LGMS, Z-Score, Isolation Forest e Regras..."):
            try:
                res = run_pipeline(
                    log_file="data/logs_simulados.jsonl",
                    save_to_db=True,
                    explain_critical=False,
                )
                st.success(f"Pipeline concluído! {res['total_anomalies_detected']} anomalias detectadas e gravadas.")
                st.rerun()
            except Exception as e:
                st.error(f"Erro ao executar pipeline: {e}")

    st.divider()
    st.subheader("🔍 Filtros de Visualização")
    selected_severity = st.selectbox(
        "Filtrar por Severidade",
        options=["TODAS", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
        index=0,
    )
    selected_detector = st.selectbox(
        "Filtrar por Detector",
        options=["TODOS", "ZScoreDetector", "IsolationForestDetector", "RuleBasedDetector"],
        index=0,
    )

    st.divider()
    st.caption(f"**SQLite**: `{settings.sqlite_db_path}`")
    st.caption(f"**LLM Model**: `{settings.ollama_model}` via `{settings.ollama_base_url}`")

# ============================================================================
# Dados e Métricas Principais (KPIs)
# ============================================================================
stats = get_db_stats()
total_anomalies = stats["total_anomalies"]
sev_dist = stats["severity_distribution"]

crit_count = sev_dist.get("CRITICAL", 0)
high_count = sev_dist.get("HIGH", 0)
med_count = sev_dist.get("MEDIUM", 0)
low_count = sev_dist.get("LOW", 0)

kpi1, kpi2, kpi3, kpi4 = st.columns(4)
kpi1.metric("Total de Anomalias", f"{total_anomalies}", delta="Eventos no banco")
kpi2.metric("Críticas (CRITICAL)", f"{crit_count}", delta="Ação Imediata", delta_color="inverse")
kpi3.metric("Altas (HIGH)", f"{high_count}", delta="Investigação")
kpi4.metric("Médias / Baixas", f"{med_count + low_count}")

st.divider()

# ============================================================================
# Consulta de Anomalias com Filtros
# ============================================================================
sev_filter = None if selected_severity == "TODAS" else selected_severity
det_filter = None if selected_detector == "TODOS" else selected_detector

anomalies_list = get_anomalies(severity=sev_filter, detector=det_filter, limit=300)

if not anomalies_list:
    st.warning("Nenhuma anomalia encontrada com os filtros selecionados. Clique em '🚀 Executar Pipeline de Detecção' na barra lateral.")
else:
    col_chart1, col_chart2 = st.columns(2)

    with col_chart1:
        st.subheader("📊 Distribuição por Severidade")
        df_sev = pd.DataFrame(list(sev_dist.items()), columns=["Severidade", "Quantidade"])
        st.bar_chart(df_sev.set_index("Severidade"), color="#ff4b4b")

    with col_chart2:
        st.subheader("🎯 Principais Eventos / APIs Anômalas")
        df_events = pd.DataFrame(list(stats["top_anomalous_events"].items()), columns=["API", "Alertas"])
        st.bar_chart(df_events.set_index("API"))

    st.divider()

    # Tabela de Anomalias
    st.subheader(f"📋 Alertas Detectados ({len(anomalies_list)} exibidos)")

    table_data = []
    for item in anomalies_list:
        detectors_str = ", ".join(item.get("detectors_triggered", []))
        sev = item.get("severity", "LOW")
        icon = "🔴" if sev == "CRITICAL" else ("🟠" if sev == "HIGH" else ("🟡" if sev == "MEDIUM" else "🔵"))

        table_data.append({
            "Status": f"{icon} {sev}",
            "Timestamp": item.get("timestamp"),
            "API": item.get("event_name"),
            "Usuário": item.get("user_name"),
            "IP de Origem": item.get("source_ip"),
            "Detectores": detectors_str,
            "Score": f"{item.get('max_score', 0.0):.2f}",
            "Event ID": item.get("event_id"),
        })

    df_table = pd.DataFrame(table_data)
    st.dataframe(df_table, use_container_width=True, hide_index=True)

    # ========================================================================
    # Painel de Investigação e Explicabilidade com IA
    # ========================================================================
    st.divider()
    st.subheader("🤖 Investigação de Incidente & Explicabilidade com IA (LLM Explainer)")

    event_ids = [item["event_id"] for item in anomalies_list]
    event_labels = {
        item["event_id"]: f"[{item.get('severity')}] {item.get('event_name')} por {item.get('user_name')} ({item.get('event_id')[:8]}...)"
        for item in anomalies_list
    }

    selected_event_id = st.selectbox(
        "Selecione um evento anômalo para analisar:",
        options=event_ids,
        format_func=lambda eid: event_labels.get(eid, eid),
    )

    if selected_event_id:
        selected_item = get_anomaly_by_event_id(selected_event_id)

        if selected_item:
            det_col1, det_col2 = st.columns([1, 1])

            with det_col1:
                st.markdown("#### 📌 Detalhes Técnicos")
                st.write(f"**Event ID**: `{selected_item['event_id']}`")
                st.write(f"**Data / Hora**: `{selected_item['timestamp']}`")
                st.write(f"**API / Ação**: `{selected_item['event_name']}`")
                st.write(f"**Usuário**: `{selected_item['user_name']}`")
                st.write(f"**IP de Origem**: `{selected_item['source_ip']}`")
                st.write(f"**Severidade**: `{selected_item['severity']}`")
                st.write(f"**Detectores**: `{', '.join(selected_item.get('detectors_triggered', []))}`")
                st.write(f"**Score de Risco**: `{selected_item['max_score']}`")

            with det_col2:
                st.markdown("#### 🧪 Métricas dos Detectores")
                if selected_item.get("details"):
                    st.json(selected_item["details"])
                else:
                    st.info("Nenhum metadado extra disponível.")

            st.write("")
            btn_col1, btn_col2 = st.columns([1, 3])

            with btn_col1:
                trigger_explain = st.button("🤖 Gerar Laudo com IA", type="primary", use_container_width=True)

            existing_explanation = selected_item.get("explanation")

            if trigger_explain:
                with st.spinner("Gerando laudo com o LLM Explainer..."):
                    explainer = LLMExplainer()
                    ctx = {
                        "event_id": selected_item["event_id"],
                        "timestamp": selected_item["timestamp"],
                        "event_name": selected_item["event_name"],
                        "user_name": selected_item["user_name"],
                        "source_ip": selected_item["source_ip"],
                        "severity": selected_item["severity"],
                        "detectors_triggered": selected_item.get("detectors_triggered", []),
                        "max_score": selected_item.get("max_score", 0.0),
                        "scenario": selected_item.get("scenario"),
                        "details": selected_item.get("details"),
                    }
                    new_explanation = explainer.explain_anomaly(ctx)
                    update_anomaly_explanation(selected_event_id, new_explanation)
                    st.success("Laudo técnico gerado e armazenado com sucesso!")
                    st.markdown(new_explanation)
            elif existing_explanation:
                st.markdown("### 📝 Laudo de Explicabilidade Registrado:")
                st.markdown(existing_explanation)
            else:
                st.info("Clique no botão '🤖 Gerar Laudo com IA' acima para obter o diagnóstico técnico, mapeamento MITRE ATT&CK e ações de remediação recomendadas.")
