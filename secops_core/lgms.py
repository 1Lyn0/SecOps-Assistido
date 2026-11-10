"""Módulo LGMS (Log Modeling & Schema).

Responsável por:
1. Modelagem canônica e validação tipada de logs de auditoria (via Pydantic).
2. Parser resiliente em streaming e batch com captura de linhas corrompidas.
3. Engenharia e extração de features numéricas, temporais e categóricas prontas
   para motores de Z-Score e Isolation Forest.
"""

from __future__ import annotations

import json
import logging
import math
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Generator, Iterable, List, Optional, Tuple, Union

import numpy as np
import pandas as pd
from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger("secops_core.lgms")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("[%(levelname)s] %(asctime)s - %(name)s: %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


# ============================================================================
# 1. Schemas Canônicos (LGMS Models)
# ============================================================================

class CanonicalUserIdentity(BaseModel):
    """Representação canônica e tipada da identidade de usuário/serviço."""
    type: str = "IAMUser"
    userName: str = "unknown"
    arn: Optional[str] = None


class CanonicalLog(BaseModel):
    """Modelo canônico estrutural para logs de auditoria de segurança."""
    event_id: str
    timestamp: datetime
    event_name: str
    event_source: str
    user_identity: CanonicalUserIdentity
    source_ip: str
    aws_region: str = "us-east-1"
    status: str = "Success"
    error_code: Optional[str] = None
    request_count: int = Field(default=1, ge=0)
    bytes_transferred: int = Field(default=0, ge=0)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp", mode="before")
    @classmethod
    def parse_iso_timestamp(cls, value: Any) -> datetime:
        """Converte strings ISO-8601 para datetime com timezone UTC."""
        if isinstance(value, datetime):
            return value
        if isinstance(value, str):
            # Trata 'Z' final como UTC
            clean_val = value.replace("Z", "+00:00")
            return datetime.fromisoformat(clean_val)
        raise ValueError(f"Formato de timestamp inválido: {value}")

    @field_validator("user_identity", mode="before")
    @classmethod
    def parse_user_identity(cls, value: Any) -> CanonicalUserIdentity:
        """Permite inicialização a partir de dict ou string simples de usuário."""
        if isinstance(value, CanonicalUserIdentity):
            return value
        if isinstance(value, dict):
            return CanonicalUserIdentity(**value)
        if isinstance(value, str):
            return CanonicalUserIdentity(type="IAMUser", userName=value)
        return CanonicalUserIdentity()


class ParsingSummary(BaseModel):
    """Relatório quantitativo do processo de parse de logs."""
    total_lines: int = 0
    valid_logs: int = 0
    corrupted_lines: int = 0
    error_details: List[str] = Field(default_factory=list)


# ============================================================================
# 2. Parser Resiliente (Streaming & Batch)
# ============================================================================

def parse_log_line(line: str) -> Optional[CanonicalLog]:
    """Valida e converte uma única linha JSON em um objeto canônico CanonicalLog.

    Retorna None e gera warning caso a linha seja inválida ou corrompida.
    """
    line_str = line.strip()
    if not line_str:
        return None

    try:
        data = json.loads(line_str)
        if not isinstance(data, dict):
            logger.warning("Linha JSON não representa um objeto válido: %s", line_str[:100])
            return None
        return CanonicalLog(**data)
    except (json.JSONDecodeError, ValueError) as err:
        logger.warning("Falha ao processar linha de log: %s | Conteúdo: %s", err, line_str[:120])
        return None


def stream_logs(file_path: Union[str, Path]) -> Generator[CanonicalLog, None, ParsingSummary]:
    """Lê um arquivo JSONL em streaming gerando CanonicalLog sob demanda.

    Garante baixo consumo de memória mesmo para arquivos com milhões de linhas.
    """
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Arquivo de logs não encontrado: {path}")

    summary = ParsingSummary()

    with path.open("r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, start=1):
            line_str = line.strip()
            if not line_str:
                continue
            summary.total_lines += 1
            log_item = parse_log_line(line_str)
            if log_item is not None:
                summary.valid_logs += 1
                yield log_item
            else:
                summary.corrupted_lines += 1
                summary.error_details.append(f"Linha {line_num}: formato inválido")

    return summary


def parse_logs_file(file_path: Union[str, Path]) -> Tuple[List[CanonicalLog], ParsingSummary]:
    """Carrega e valida todo o arquivo JSONL em memória, retornando a lista e o sumário."""
    valid_logs: List[CanonicalLog] = []
    generator = stream_logs(file_path)

    try:
        while True:
            valid_logs.append(next(generator))
    except StopIteration as stop:
        summary: ParsingSummary = stop.value
        return valid_logs, summary


# ============================================================================
# 3. Extrator de Features para Detectores (Z-Score & Isolation Forest)
# ============================================================================

SUSPICIOUS_IP_PREFIXES = ("185.220.", "198.51.", "203.0.", "45.145.")


def extract_features(logs: Iterable[CanonicalLog]) -> pd.DataFrame:
    """Extrai matriz estruturada de features derivadas para detecção de anomalias.

    Produz features:
    - Temporais: hour, day_of_week, is_weekend, is_off_hours
    - Categóricas/Flags: is_login, is_iam, is_trail_mgmt, is_s3, is_error, is_suspicious_ip
    - Métricas: request_count, bytes_transferred, log_bytes_transferred
    - Frequência: ip_frequency, user_frequency

    Returns:
        pd.DataFrame indexado por event_id com as features derivadas e metadados.
    """
    rows: List[Dict[str, Any]] = []

    for log in logs:
        ts = log.timestamp
        hour = ts.hour
        day_of_week = ts.weekday()  # 0=Segunda, 6=Domingo
        is_weekend = 1 if day_of_week >= 5 else 0
        # Horário fora do expediente comercial típico (antes das 08h ou depois das 19h) ou fim de semana
        is_off_hours = 1 if (hour < 8 or hour >= 19 or is_weekend == 1) else 0

        event_name = log.event_name.lower()
        event_src = log.event_source.lower()

        is_login = 1 if "login" in event_name or "signin" in event_src else 0
        is_iam = 1 if "iam" in event_src or "sts" in event_src or "userpolicy" in event_name else 0
        is_trail_mgmt = 1 if "cloudtrail" in event_src or "trail" in event_name else 0
        is_s3 = 1 if "s3" in event_src or "bucket" in event_name or "object" in event_name else 0

        is_error = 1 if (log.status.lower() == "failure" or log.error_code is not None) else 0

        # Verificação de IPs de reputação maliciosa/externa
        is_suspicious_ip = 1 if any(log.source_ip.startswith(prefix) for prefix in SUSPICIOUS_IP_PREFIXES) else 0

        # Log transform da volumetria de bytes para normalização do Z-Score e ML
        bytes_val = float(max(0, log.bytes_transferred))
        log_bytes = math.log1p(bytes_val)

        rows.append({
            "event_id": log.event_id,
            "timestamp": ts,
            "user_name": log.user_identity.userName,
            "source_ip": log.source_ip,
            "event_name": log.event_name,
            "event_source": log.event_source,
            # Features numéricas prontas para ML
            "hour": hour,
            "day_of_week": day_of_week,
            "is_weekend": is_weekend,
            "is_off_hours": is_off_hours,
            "is_login": is_login,
            "is_iam": is_iam,
            "is_trail_mgmt": is_trail_mgmt,
            "is_s3": is_s3,
            "is_error": is_error,
            "is_suspicious_ip": is_suspicious_ip,
            "request_count": float(log.request_count),
            "bytes_transferred": bytes_val,
            "log_bytes_transferred": log_bytes,
            # Ground truth para validação (se disponível nos metadados)
            "is_anomaly_ground_truth": 1 if log.metadata.get("is_anomaly_ground_truth") else 0,
            "scenario": log.metadata.get("scenario", "unknown"),
        })

    if not rows:
        return pd.DataFrame()

    df = pd.DataFrame(rows)

    # Features de frequência calculadas na janela do dataset
    ip_counts = df["source_ip"].value_counts()
    user_counts = df["user_name"].value_counts()

    df["ip_frequency"] = df["source_ip"].map(ip_counts).astype(float)
    df["user_frequency"] = df["user_name"].map(user_counts).astype(float)

    return df


def get_feature_matrix(df: pd.DataFrame) -> Tuple[pd.DataFrame, List[str]]:
    """Filtra e retorna apenas as colunas numéricas de features para os modelos de ML.

    Returns:
        (X, feature_columns) onde X é um DataFrame estritamente numérico e normalizado.
    """
    feature_cols = [
        "hour",
        "day_of_week",
        "is_weekend",
        "is_off_hours",
        "is_login",
        "is_iam",
        "is_trail_mgmt",
        "is_s3",
        "is_error",
        "is_suspicious_ip",
        "request_count",
        "log_bytes_transferred",
        "ip_frequency",
        "user_frequency",
    ]

    available_cols = [col for col in feature_cols if col in df.columns]
    X = df[available_cols].copy()
    return X, available_cols
