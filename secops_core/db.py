"""Gerenciamento de conexão, persistência e consultas SQLite para SecOps.

Módulo responsável por:
1. Conexão e ciclo de vida do banco SQLite local (secops.db).
2. Modelagem estrutural via Pydantic para logs processados e alertas.
3. Criação de schema com tabelas (`processed_logs`, `anomalies`), view (`security_alerts`)
   e índices de busca otimizados (timestamp, is_anomaly, final_severity, event_id).
4. Operações de repositório em lote com alta performance (bulk insert < 100ms para 5.000 registros).
5. Idempotência garantida contra duplicatas de event_id através de UPSERT (ON CONFLICT DO UPDATE).
6. Consultas filtradas e atualização de laudos de IA.
"""

from __future__ import annotations

import json
from pathlib import Path
import sqlite3
from contextlib import contextmanager
from typing import Any, Dict, Generator, List, Optional, Tuple, Union

from pydantic import BaseModel, Field

from secops_core.config import settings


# ============================================================================
# 1. Modelos Estruturais Pydantic
# ============================================================================

class ProcessedLogRecord(BaseModel):
    """Modelo tipado para logs processados e enriquecidos com scores de detectores."""
    id: Optional[int] = None
    event_id: str
    timestamp: str
    event_name: str
    event_source: str = ""
    user_name: str
    user_arn: Optional[str] = None
    source_ip: str
    aws_region: str = "us-east-1"
    status: str = "Success"
    error_code: Optional[str] = None
    request_count: int = 1
    bytes_transferred: int = 0
    metadata: Dict[str, Any] = Field(default_factory=dict)
    zscore_value: float = 0.0
    is_zscore_anomaly: bool = False
    iforest_score: float = 0.0
    is_iforest_anomaly: bool = False
    cloudtrail_rules_triggered: List[str] = Field(default_factory=list)
    final_severity: str = "LOW"
    is_anomaly: bool = False
    ai_explanation: Optional[str] = None
    processed_at: Optional[str] = None


class SecurityAlertRecord(ProcessedLogRecord):
    """Modelo tipado para alertas de segurança confirmados (is_anomaly = True)."""
    is_anomaly: bool = True


# ============================================================================
# 2. Gerenciamento de Conexão e Sessão SQLite
# ============================================================================

def _resolve_db_path(db_path: Optional[Union[str, Path]] = None) -> Path:
    """Resolve o caminho absoluto do arquivo SQLite, criando diretórios se necessário."""
    if db_path is not None:
        path = Path(db_path)
    else:
        path = settings.sqlite_db_full_path

    # Garante que o diretório pai exista
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def get_connection(db_path: Optional[Union[str, Path]] = None) -> sqlite3.Connection:
    """Cria e retorna uma conexão configurada com o banco SQLite.

    Aplica otimizações de performance:
    - row_factory para retorno como dicionário/Row
    - PRAGMA journal_mode = WAL (Write-Ahead Logging para concorrência)
    - PRAGMA synchronous = NORMAL (reduz fsync sem comprometer integridade no modo WAL)
    """
    path = _resolve_db_path(db_path)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row

    # Otimizações de I/O e concorrência para alta performance
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    conn.execute("PRAGMA foreign_keys = ON;")

    return conn


@contextmanager
def get_db_cursor(db_path: Optional[Union[str, Path]] = None) -> Generator[sqlite3.Cursor, None, None]:
    """Context manager para operações transacionais seguras com commit/rollback automático."""
    conn = get_connection(db_path)
    cursor = conn.cursor()
    try:
        yield cursor
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ============================================================================
# 3. Inicialização de Schema e Índices (DDL)
# ============================================================================

def init_db(db_path: Optional[Union[str, Path]] = None) -> None:
    """Inicializa automaticamente o arquivo SQLite, tabelas estruturais, view e índices.

    Cria:
    - Tabela `processed_logs`: persistência canônica e enriquecida de eventos e scores
    - Índices otimizados: timestamp, is_anomaly, final_severity, event_id
    - View `security_alerts`: visão filtrada dos eventos classificados como anomalia
    - Tabela de compatibilidade `anomalies`: suporte legado para pipeline e API
    """
    with get_db_cursor(db_path) as cursor:
        # 1. Tabela Principal de Logs Processados
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS processed_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT UNIQUE NOT NULL,
                timestamp TEXT NOT NULL,
                event_name TEXT NOT NULL,
                event_source TEXT DEFAULT '',
                user_name TEXT NOT NULL,
                user_arn TEXT DEFAULT '',
                source_ip TEXT NOT NULL,
                aws_region TEXT DEFAULT 'us-east-1',
                status TEXT DEFAULT 'Success',
                error_code TEXT,
                request_count INTEGER DEFAULT 1,
                bytes_transferred INTEGER DEFAULT 0,
                metadata TEXT DEFAULT '{}',
                zscore_value REAL DEFAULT 0.0,
                is_zscore_anomaly INTEGER DEFAULT 0,
                iforest_score REAL DEFAULT 0.0,
                is_iforest_anomaly INTEGER DEFAULT 0,
                cloudtrail_rules_triggered TEXT DEFAULT '[]',
                final_severity TEXT NOT NULL DEFAULT 'LOW',
                is_anomaly INTEGER NOT NULL DEFAULT 0,
                ai_explanation TEXT,
                processed_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        # Índices essenciais para consultas rápidas (< 100ms)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_processed_logs_event_id ON processed_logs(event_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_processed_logs_timestamp ON processed_logs(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_processed_logs_is_anomaly ON processed_logs(is_anomaly)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_processed_logs_final_severity ON processed_logs(final_severity)")

        # 2. View Security Alerts (alertas onde is_anomaly = 1)
        cursor.execute(
            """
            CREATE VIEW IF NOT EXISTS security_alerts AS
            SELECT * FROM processed_logs WHERE is_anomaly = 1
            """
        )

        # Trigger para permitir inserção direta transparente na view security_alerts
        cursor.execute(
            """
            CREATE TRIGGER IF NOT EXISTS trg_insert_security_alerts
            INSTEAD OF INSERT ON security_alerts
            FOR EACH ROW
            BEGIN
                INSERT INTO processed_logs (
                    event_id, timestamp, event_name, event_source, user_name, user_arn,
                    source_ip, aws_region, status, error_code, request_count, bytes_transferred,
                    metadata, zscore_value, is_zscore_anomaly, iforest_score, is_iforest_anomaly,
                    cloudtrail_rules_triggered, final_severity, is_anomaly, ai_explanation
                ) VALUES (
                    NEW.event_id, NEW.timestamp, NEW.event_name, NEW.event_source, NEW.user_name, NEW.user_arn,
                    NEW.source_ip, NEW.aws_region, NEW.status, NEW.error_code, NEW.request_count, NEW.bytes_transferred,
                    NEW.metadata, NEW.zscore_value, NEW.is_zscore_anomaly, NEW.iforest_score, NEW.is_iforest_anomaly,
                    NEW.cloudtrail_rules_triggered, NEW.final_severity, 1, NEW.ai_explanation
                ) ON CONFLICT(event_id) DO UPDATE SET
                    timestamp = excluded.timestamp,
                    event_name = excluded.event_name,
                    user_name = excluded.user_name,
                    source_ip = excluded.source_ip,
                    final_severity = excluded.final_severity,
                    is_anomaly = 1,
                    ai_explanation = COALESCE(excluded.ai_explanation, processed_logs.ai_explanation);
            END;
            """
        )

        # 3. Tabela Legada/Consolidada de Anomalias (retrocompatibilidade)
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS anomalies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT UNIQUE NOT NULL,
                timestamp TEXT NOT NULL,
                event_name TEXT NOT NULL,
                user_name TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                detectors_triggered TEXT NOT NULL,
                max_score REAL NOT NULL,
                severity TEXT NOT NULL,
                scenario TEXT,
                explanation TEXT,
                details TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_anomalies_event_id ON anomalies(event_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_anomalies_severity ON anomalies(severity)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_anomalies_timestamp ON anomalies(timestamp)")


# ============================================================================
# 4. Operações de Inserção em Lote e Idempotência (Bulk Insert)
# ============================================================================

def _normalize_record_tuple(rec: Union[Dict[str, Any], ProcessedLogRecord]) -> Tuple[Any, ...]:
    """Converte um registro (dict ou Pydantic) em tupla para executemany do SQLite."""
    if isinstance(rec, BaseModel):
        data = rec.model_dump()
    elif isinstance(rec, dict):
        data = rec
    else:
        raise TypeError(f"Tipo de registro não suportado: {type(rec)}")

    metadata_raw = data.get("metadata", {})
    metadata_json = json.dumps(metadata_raw) if isinstance(metadata_raw, dict) else str(metadata_raw or "{}")

    rules_raw = data.get("cloudtrail_rules_triggered", [])
    rules_json = json.dumps(rules_raw) if isinstance(rules_raw, list) else str(rules_raw or "[]")

    is_zscore = 1 if data.get("is_zscore_anomaly") else 0
    is_iforest = 1 if data.get("is_iforest_anomaly") else 0
    is_anomaly = 1 if data.get("is_anomaly") else 0

    return (
        str(data.get("event_id", "")),
        str(data.get("timestamp", "")),
        str(data.get("event_name", "")),
        str(data.get("event_source", "") or ""),
        str(data.get("user_name", "")),
        str(data.get("user_arn", "") or ""),
        str(data.get("source_ip", "")),
        str(data.get("aws_region", "us-east-1") or "us-east-1"),
        str(data.get("status", "Success") or "Success"),
        data.get("error_code"),
        int(data.get("request_count", 1) or 1),
        int(data.get("bytes_transferred", 0) or 0),
        metadata_json,
        float(data.get("zscore_value", 0.0) or 0.0),
        is_zscore,
        float(data.get("iforest_score", 0.0) or 0.0),
        is_iforest,
        rules_json,
        str(data.get("final_severity", "LOW") or "LOW").upper(),
        is_anomaly,
        data.get("ai_explanation"),
    )


def bulk_insert(
    records: List[Union[Dict[str, Any], ProcessedLogRecord]],
    db_path: Optional[Union[str, Path]] = None,
) -> int:
    """Insere ou atualiza múltiplos logs processados em lote com suporte a idempotência.

    Utiliza `executemany` em uma única transação e `ON CONFLICT(event_id) DO UPDATE`
    para evitar duplicações e garantir alta performance (< 100ms para 5.000 registros).

    Returns:
        Quantidade de registros processados no lote.
    """
    if not records:
        return 0

    init_db(db_path)

    tuples = [_normalize_record_tuple(r) for r in records]

    sql = """
    INSERT INTO processed_logs (
        event_id, timestamp, event_name, event_source, user_name, user_arn,
        source_ip, aws_region, status, error_code, request_count, bytes_transferred,
        metadata, zscore_value, is_zscore_anomaly, iforest_score, is_iforest_anomaly,
        cloudtrail_rules_triggered, final_severity, is_anomaly, ai_explanation
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(event_id) DO UPDATE SET
        timestamp = excluded.timestamp,
        event_name = excluded.event_name,
        event_source = excluded.event_source,
        user_name = excluded.user_name,
        user_arn = excluded.user_arn,
        source_ip = excluded.source_ip,
        aws_region = excluded.aws_region,
        status = excluded.status,
        error_code = excluded.error_code,
        request_count = excluded.request_count,
        bytes_transferred = excluded.bytes_transferred,
        metadata = excluded.metadata,
        zscore_value = excluded.zscore_value,
        is_zscore_anomaly = excluded.is_zscore_anomaly,
        iforest_score = excluded.iforest_score,
        is_iforest_anomaly = excluded.is_iforest_anomaly,
        cloudtrail_rules_triggered = excluded.cloudtrail_rules_triggered,
        final_severity = excluded.final_severity,
        is_anomaly = excluded.is_anomaly,
        ai_explanation = COALESCE(excluded.ai_explanation, processed_logs.ai_explanation),
        processed_at = CURRENT_TIMESTAMP
    """

    with get_db_cursor(db_path) as cursor:
        cursor.executemany(sql, tuples)

    return len(records)


# ============================================================================
# 5. Consultas Filtradas e Repositório (Read Queries)
# ============================================================================

def _parse_row_dict(row: sqlite3.Row) -> Dict[str, Any]:
    """Converte sqlite3.Row para dicionário decodificando campos JSON e booleans."""
    d = dict(row)

    # Decodifica JSON
    for json_field in ("metadata", "cloudtrail_rules_triggered", "detectors_triggered", "details"):
        if json_field in d and isinstance(d[json_field], str):
            try:
                d[json_field] = json.loads(d[json_field])
            except Exception:
                pass

    # Converte inteiros binários em booleans
    for bool_field in ("is_anomaly", "is_zscore_anomaly", "is_iforest_anomaly"):
        if bool_field in d and d[bool_field] is not None:
            d[bool_field] = bool(d[bool_field])

    return d


def get_processed_logs(
    is_anomaly: Optional[bool] = None,
    final_severity: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    db_path: Optional[Union[str, Path]] = None,
) -> List[Dict[str, Any]]:
    """Consulta logs processados com filtros otimizados por índice.

    Filtros suportados:
    - is_anomaly: True/False
    - final_severity: LOW, MEDIUM, HIGH, CRITICAL
    - start_time: timestamp ISO inicial
    - end_time: timestamp ISO final
    - limit / offset: paginação eficiente
    """
    init_db(db_path)
    query = "SELECT * FROM processed_logs WHERE 1=1"
    params: List[Any] = []

    if is_anomaly is not None:
        query += " AND is_anomaly = ?"
        params.append(1 if is_anomaly else 0)

    if final_severity:
        query += " AND final_severity = ?"
        params.append(final_severity.upper())

    if start_time:
        query += " AND timestamp >= ?"
        params.append(start_time)

    if end_time:
        query += " AND timestamp <= ?"
        params.append(end_time)

    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        rows = cursor.fetchall()

    return [_parse_row_dict(r) for r in rows]


def get_security_alerts(
    severity: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    db_path: Optional[Union[str, Path]] = None,
) -> List[Dict[str, Any]]:
    """Consulta alertas de segurança diretamente da view `security_alerts`."""
    init_db(db_path)
    query = "SELECT * FROM security_alerts WHERE 1=1"
    params: List[Any] = []

    if severity:
        query += " AND final_severity = ?"
        params.append(severity.upper())

    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        rows = cursor.fetchall()

    return [_parse_row_dict(r) for r in rows]


def get_processed_log_by_event_id(
    event_id: str,
    db_path: Optional[Union[str, Path]] = None,
) -> Optional[Dict[str, Any]]:
    """Recupera um log processado específico pelo seu event_id único."""
    init_db(db_path)
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM processed_logs WHERE event_id = ?", (event_id,))
        row = cursor.fetchone()

    if not row:
        return None
    return _parse_row_dict(row)


def update_ai_explanation(
    event_id: str,
    explanation: str,
    db_path: Optional[Union[str, Path]] = None,
) -> bool:
    """Atualiza o laudo explicativo da IA para um determinado event_id.

    Atualiza em `processed_logs` e em `anomalies` simultaneamente para consistência.
    """
    init_db(db_path)
    with get_db_cursor(db_path) as cursor:
        cursor.execute(
            "UPDATE processed_logs SET ai_explanation = ? WHERE event_id = ?",
            (explanation, event_id),
        )
        updated_processed = cursor.rowcount > 0

        cursor.execute(
            "UPDATE anomalies SET explanation = ? WHERE event_id = ?",
            (explanation, event_id),
        )
        updated_anomalies = cursor.rowcount > 0

        return updated_processed or updated_anomalies


# ============================================================================
# 6. Funções de Compatibilidade (Retrocompatibilidade com Pipeline e API)
# ============================================================================

def save_anomalies(
    anomalies: List[Any],
    db_path: Optional[Union[str, Path]] = None,
) -> int:
    """Persiste ou atualiza anomalias consolidadas no SQLite.

    Garante consistência gravando na tabela legada `anomalies` e simultaneamente
    na tabela moderna `processed_logs` via `bulk_insert`.
    """
    if not anomalies:
        return 0

    init_db(db_path)

    # 1. Grava na tabela legada anomalies
    with get_db_cursor(db_path) as cursor:
        for item in anomalies:
            event_id = item.event_id
            timestamp = item.timestamp
            event_name = item.event_name
            user_name = item.user_name
            source_ip = item.source_ip
            detectors_json = json.dumps(item.detectors_triggered)
            max_score = float(item.max_score)
            severity = item.max_severity
            scenario = getattr(item, "scenario", None)
            explanation = getattr(item, "explanation", None)
            details_json = json.dumps(
                [r.model_dump() for r in getattr(item, "detector_results", [])]
            )

            cursor.execute(
                """
                INSERT INTO anomalies (
                    event_id, timestamp, event_name, user_name, source_ip,
                    detectors_triggered, max_score, severity, scenario,
                    explanation, details
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(event_id) DO UPDATE SET
                    timestamp = excluded.timestamp,
                    event_name = excluded.event_name,
                    user_name = excluded.user_name,
                    source_ip = excluded.source_ip,
                    detectors_triggered = excluded.detectors_triggered,
                    max_score = excluded.max_score,
                    severity = excluded.severity,
                    scenario = excluded.scenario,
                    details = excluded.details
                """,
                (
                    event_id,
                    timestamp,
                    event_name,
                    user_name,
                    source_ip,
                    detectors_json,
                    max_score,
                    severity,
                    scenario,
                    explanation,
                    details_json,
                ),
            )

    # 2. Converte e sincroniza na tabela principal processed_logs
    modern_records: List[Dict[str, Any]] = []
    for item in anomalies:
        detector_results = getattr(item, "detector_results", [])
        zscore_val = 0.0
        is_zscore = False
        iforest_val = 0.0
        is_iforest = False
        rules: List[str] = []

        for r in detector_results:
            dname = getattr(r, "detector_name", "")
            if dname == "ZScore":
                zscore_val = float(getattr(r, "anomaly_score", 0.0))
                is_zscore = bool(getattr(r, "is_anomaly", False))
            elif dname == "IsolationForest":
                iforest_val = float(getattr(r, "anomaly_score", 0.0))
                is_iforest = bool(getattr(r, "is_anomaly", False))
            elif dname == "RuleBased" or "Rule" in dname:
                if getattr(r, "is_anomaly", False):
                    rules.append(getattr(r, "scenario", "") or dname)

        modern_records.append(
            {
                "event_id": item.event_id,
                "timestamp": item.timestamp,
                "event_name": item.event_name,
                "user_name": item.user_name,
                "source_ip": item.source_ip,
                "zscore_value": zscore_val,
                "is_zscore_anomaly": is_zscore,
                "iforest_score": iforest_val,
                "is_iforest_anomaly": is_iforest,
                "cloudtrail_rules_triggered": rules,
                "final_severity": item.max_severity,
                "is_anomaly": True,
                "ai_explanation": getattr(item, "explanation", None),
            }
        )

    bulk_insert(modern_records, db_path)
    return len(anomalies)


def get_anomalies(
    severity: Optional[str] = None,
    detector: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    db_path: Optional[Union[str, Path]] = None,
) -> List[Dict[str, Any]]:
    """Consulta anomalias no SQLite com filtros opcionais de severidade e detector."""
    init_db(db_path)
    query = "SELECT * FROM anomalies WHERE 1=1"
    params: List[Any] = []

    if severity:
        query += " AND severity = ?"
        params.append(severity.upper())

    if detector:
        query += " AND detectors_triggered LIKE ?"
        params.append(f"%{detector}%")

    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        rows = cursor.fetchall()

    return [_parse_row_dict(r) for r in rows]


def get_anomaly_by_event_id(
    event_id: str,
    db_path: Optional[Union[str, Path]] = None,
) -> Optional[Dict[str, Any]]:
    """Recupera os detalhes de uma anomalia específica por event_id."""
    init_db(db_path)
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM anomalies WHERE event_id = ?", (event_id,))
        row = cursor.fetchone()

    if not row:
        # Tenta na tabela processed_logs
        return get_processed_log_by_event_id(event_id, db_path)

    return _parse_row_dict(row)


def update_anomaly_explanation(
    event_id: str,
    explanation: str,
    db_path: Optional[Union[str, Path]] = None,
) -> bool:
    """Atualiza o laudo explicativo da anomalia no banco (alias de update_ai_explanation)."""
    return update_ai_explanation(event_id, explanation, db_path)


def get_db_stats(db_path: Optional[Union[str, Path]] = None) -> Dict[str, Any]:
    """Retorna sumário estatístico consolidado do banco de dados SQLite."""
    init_db(db_path)
    with get_connection(db_path) as conn:
        cursor = conn.cursor()

        # Total de anomalias
        cursor.execute("SELECT COUNT(*) AS total FROM anomalies")
        total = cursor.fetchone()["total"]

        # Total de logs processados
        cursor.execute("SELECT COUNT(*) AS total_logs FROM processed_logs")
        total_logs = cursor.fetchone()["total_logs"]

        cursor.execute(
            """
            SELECT severity, COUNT(*) AS count
            FROM anomalies
            GROUP BY severity
            """
        )
        severity_dist = {r["severity"]: r["count"] for r in cursor.fetchall()}

        cursor.execute(
            """
            SELECT event_name, COUNT(*) AS count
            FROM anomalies
            GROUP BY event_name
            ORDER BY count DESC
            LIMIT 5
            """
        )
        top_events = {r["event_name"]: r["count"] for r in cursor.fetchall()}

    return {
        "total_anomalies": total,
        "total_processed_logs": total_logs,
        "severity_distribution": severity_dist,
        "top_anomalous_events": top_events,
    }
