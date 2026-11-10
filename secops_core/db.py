"""Gerenciamento de conexão, persistência e consultas SQLite para SecOps."""

import json
import sqlite3
from contextlib import contextmanager
from typing import Any, Dict, Generator, List, Optional
from secops_core.config import settings


def get_connection() -> sqlite3.Connection:
    """Cria e retorna uma conexão com o banco de dados SQLite."""
    db_path = settings.sqlite_db_full_path
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    return conn


@contextmanager
def get_db_cursor() -> Generator[sqlite3.Cursor, None, None]:
    """Context manager para operações seguras no banco com commit automático."""
    conn = get_connection()
    cursor = conn.cursor()
    try:
        yield cursor
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    """Cria as tabelas estruturais de auditoria caso não existam."""
    with get_db_cursor() as cursor:
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


def save_anomalies(anomalies: List[Any]) -> int:
    """Persiste ou atualiza anomalias consolidadas no banco de dados SQLite.

    Retorna a quantidade de registros gravados.
    """
    if not anomalies:
        return 0

    init_db()

    with get_db_cursor() as cursor:
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
            details_json = json.dumps([r.model_dump() for r in item.detector_results])

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

    return len(anomalies)


def get_anomalies(
    severity: Optional[str] = None,
    detector: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> List[Dict[str, Any]]:
    """Consulta anomalias no SQLite com filtros opcionais de severidade e detector."""
    init_db()
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

    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        rows = cursor.fetchall()

    results: List[Dict[str, Any]] = []
    for r in rows:
        d = dict(r)
        try:
            d["detectors_triggered"] = json.loads(d["detectors_triggered"])
        except Exception:
            pass
        try:
            d["details"] = json.loads(d["details"])
        except Exception:
            pass
        results.append(d)

    return results


def get_anomaly_by_event_id(event_id: str) -> Optional[Dict[str, Any]]:
    """Recupera os detalhes de uma anomalia específica por event_id."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM anomalies WHERE event_id = ?", (event_id,))
        row = cursor.fetchone()

    if not row:
        return None

    d = dict(row)
    try:
        d["detectors_triggered"] = json.loads(d["detectors_triggered"])
    except Exception:
        pass
    try:
        d["details"] = json.loads(d["details"])
    except Exception:
        pass
    return d


def update_anomaly_explanation(event_id: str, explanation: str) -> bool:
    """Atualiza o laudo explicativo da anomalia no banco."""
    init_db()
    with get_db_cursor() as cursor:
        cursor.execute(
            "UPDATE anomalies SET explanation = ? WHERE event_id = ?",
            (explanation, event_id),
        )
        return cursor.rowcount > 0


def get_db_stats() -> Dict[str, Any]:
    """Retorna sumário estatístico consolidado do banco de dados."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) AS total FROM anomalies")
        total = cursor.fetchone()["total"]

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
        "severity_distribution": severity_dist,
        "top_anomalous_events": top_events,
    }
