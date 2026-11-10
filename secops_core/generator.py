"""Gerador de logs simulados de auditoria em formato JSONL estilo CloudTrail.

Cenários de anomalia implementados e documentados:
1. Brute Force (ConsoleLogin Failure Burst): Rajadas de tentativas de login inválidas.
2. Atipical Hours Activity: Ações sensíveis no meio da madrugada ou fins de semana.
3. Defense Evasion: Tentativa de desativar trilhas de auditoria (DeleteTrail, StopLogging).
4. Privilege Escalation: Alteração de políticas de IAM (PutUserPolicy, AttachUserPolicy).
5. Data Exfiltration: Volume atípico de requisições e bytes transferidos em buckets S3.
6. Suspicious IP Access: Requisições originadas de blocos de IP externos com histórico malicioso.
"""

import argparse
import json
import random
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


# ============================================================================
# Constantes e Catálogos de Simulação
# ============================================================================

LEGIT_USERS = [
    {"type": "IAMUser", "userName": "alice.dev", "arn": "arn:aws:iam::123456789012:user/alice.dev"},
    {"type": "IAMUser", "userName": "bob.analyst", "arn": "arn:aws:iam::123456789012:user/bob.analyst"},
    {"type": "IAMUser", "userName": "charlie.eng", "arn": "arn:aws:iam::123456789012:user/charlie.eng"},
    {"type": "AssumedRole", "userName": "app-backend-role", "arn": "arn:aws:sts::123456789012:assumed-role/app-backend-role"},
]

SUSPICIOUS_USERS = [
    {"type": "IAMUser", "userName": "attacker_guest", "arn": "arn:aws:iam::123456789012:user/attacker_guest"},
    {"type": "Root", "userName": "root", "arn": "arn:aws:iam::123456789012:root"},
    {"type": "IAMUser", "userName": "temp_contractor", "arn": "arn:aws:iam::123456789012:user/temp_contractor"},
]

INTERNAL_IPS = [
    "10.0.1.15",
    "10.0.2.88",
    "192.168.1.104",
    "172.16.0.45",
    "200.18.90.12",  # IP confiável de VPN corporativa
]

SUSPICIOUS_IPS = [
    "185.220.101.5",   # Conhecido nó de saída Tor
    "198.51.100.42",   # IP não catalogado / exterior
    "203.0.113.195",   # Range reservado para testes / scanner ofensivo
    "45.145.185.10",   # Proxy anônimo
]

REGIONS = ["us-east-1", "sa-east-1", "us-west-2"]

LEGIT_ACTIONS = [
    ("DescribeInstances", "ec2.amazonaws.com"),
    ("DescribeVolumes", "ec2.amazonaws.com"),
    ("GetObject", "s3.amazonaws.com"),
    ("ListBuckets", "s3.amazonaws.com"),
    ("GetCallerIdentity", "sts.amazonaws.com"),
    ("ConsoleLogin", "signin.amazonaws.com"),
]

USER_AGENTS = [
    "AWS-SDK/Python/boto3",
    "aws-cli/2.15.0 Python/3.11.0 Linux/x86_64",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
]


# ============================================================================
# Funções Utilitárias de Geração
# ============================================================================

def _random_business_hour_timestamp(base_date: datetime) -> datetime:
    """Gera um timestamp em horário comercial legítimo (Seg-Sex, 09h às 18h)."""
    # Escolhe um dia útil (0 a 4 = seg a sex)
    day_offset = random.randint(0, 4)
    hour = random.randint(9, 17)
    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    dt = base_date + timedelta(days=day_offset, hours=hour, minutes=minute, seconds=second)
    return dt


def _random_off_hours_timestamp(base_date: datetime) -> datetime:
    """Gera um timestamp em horário atípico (Madrugada 01h às 04h ou fim de semana)."""
    # 5 = sábado, 6 = domingo
    day_offset = random.choice([5, 6])
    hour = random.randint(1, 4)
    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    dt = base_date + timedelta(days=day_offset, hours=hour, minutes=minute, seconds=second)
    return dt


def generate_normal_event(timestamp: datetime) -> Dict[str, Any]:
    """Gera um log legítimo comum de operação diária."""
    event_name, event_source = random.choice(LEGIT_ACTIONS)
    user = random.choice(LEGIT_USERS)
    source_ip = random.choice(INTERNAL_IPS)

    request_count = random.randint(1, 15)
    bytes_transferred = random.randint(500, 50_000) if "s3" in event_source else random.randint(200, 2_000)

    return {
        "timestamp": timestamp.isoformat(),
        "event_id": str(uuid.uuid4()),
        "event_name": event_name,
        "event_source": event_source,
        "user_identity": user,
        "source_ip": source_ip,
        "aws_region": random.choice(REGIONS),
        "status": "Success",
        "error_code": None,
        "request_count": request_count,
        "bytes_transferred": bytes_transferred,
        "metadata": {
            "userAgent": random.choice(USER_AGENTS),
            "scenario": "normal_traffic",
            "is_anomaly_ground_truth": False,
        },
    }


def generate_anomaly_event(base_date: datetime) -> List[Dict[str, Any]]:
    """Gera eventos anômalos baseados em 6 cenários de ameaça documentados."""
    scenario_type = random.choice([
        "brute_force",
        "off_hours",
        "defense_evasion",
        "privilege_escalation",
        "data_exfiltration",
        "suspicious_ip",
    ])

    events: List[Dict[str, Any]] = []

    if scenario_type == "brute_force":
        # Cenário 1: Rajada de tentativas de login com falha em rápida sucessão
        attacker_ip = random.choice(SUSPICIOUS_IPS)
        start_time = _random_business_hour_timestamp(base_date)
        burst_size = random.randint(5, 12)
        for i in range(burst_size):
            t = start_time + timedelta(seconds=i * 2)
            events.append({
                "timestamp": t.isoformat(),
                "event_id": str(uuid.uuid4()),
                "event_name": "ConsoleLogin",
                "event_source": "signin.amazonaws.com",
                "user_identity": {"type": "IAMUser", "userName": "admin", "arn": "arn:aws:iam::123456789012:user/admin"},
                "source_ip": attacker_ip,
                "aws_region": "us-east-1",
                "status": "Failure",
                "error_code": "BadCredentials",
                "request_count": 1,
                "bytes_transferred": 256,
                "metadata": {
                    "userAgent": "curl/7.88.1",
                    "scenario": "brute_force",
                    "is_anomaly_ground_truth": True,
                    "description": "Rajada de falhas de autenticação ConsoleLogin pelo mesmo IP",
                },
            })

    elif scenario_type == "off_hours":
        # Cenário 2: Atividade administrativa em horário incomum (madrugada/fim de semana)
        timestamp = _random_off_hours_timestamp(base_date)
        events.append({
            "timestamp": timestamp.isoformat(),
            "event_id": str(uuid.uuid4()),
            "event_name": random.choice(["DescribeKeyPairs", "AuthorizeSecurityGroupIngress", "CreateKeyPair"]),
            "event_source": "ec2.amazonaws.com",
            "user_identity": random.choice(LEGIT_USERS),
            "source_ip": random.choice(INTERNAL_IPS),
            "aws_region": "sa-east-1",
            "status": "Success",
            "error_code": None,
            "request_count": random.randint(2, 5),
            "bytes_transferred": random.randint(1_000, 5_000),
            "metadata": {
                "userAgent": "AWS-SDK/Python/boto3",
                "scenario": "off_hours",
                "is_anomaly_ground_truth": True,
                "description": "Operação de infraestrutura em horário atípico (madrugada/fim de semana)",
            },
        })

    elif scenario_type == "defense_evasion":
        # Cenário 3: Evasão de defesa - exclusão ou desativação de auditoria
        timestamp = _random_business_hour_timestamp(base_date)
        action = random.choice(["DeleteTrail", "StopLogging", "UpdateTrail"])
        events.append({
            "timestamp": timestamp.isoformat(),
            "event_id": str(uuid.uuid4()),
            "event_name": action,
            "event_source": "cloudtrail.amazonaws.com",
            "user_identity": random.choice(SUSPICIOUS_USERS),
            "source_ip": random.choice(SUSPICIOUS_IPS),
            "aws_region": "us-east-1",
            "status": "Success",
            "error_code": None,
            "request_count": 1,
            "bytes_transferred": 1024,
            "metadata": {
                "userAgent": "aws-cli/2.15.0",
                "scenario": "defense_evasion",
                "is_anomaly_ground_truth": True,
                "description": f"Tentativa de desativação de auditoria via {action}",
            },
        })

    elif scenario_type == "privilege_escalation":
        # Cenário 4: Escalação de privilégios IAM
        timestamp = _random_business_hour_timestamp(base_date)
        action = random.choice(["PutUserPolicy", "AttachUserPolicy", "CreateAccessKey"])
        events.append({
            "timestamp": timestamp.isoformat(),
            "event_id": str(uuid.uuid4()),
            "event_name": action,
            "event_source": "iam.amazonaws.com",
            "user_identity": random.choice(SUSPICIOUS_USERS),
            "source_ip": random.choice(SUSPICIOUS_IPS),
            "aws_region": "us-east-1",
            "status": "Success",
            "error_code": None,
            "request_count": 2,
            "bytes_transferred": 2048,
            "metadata": {
                "userAgent": "Python-urllib/3.10",
                "scenario": "privilege_escalation",
                "is_anomaly_ground_truth": True,
                "description": f"Escalação de privilégios através da API de IAM ({action})",
            },
        })

    elif scenario_type == "data_exfiltration":
        # Cenário 5: Exfiltração de dados / pico absurdo de download e requests S3
        timestamp = _random_business_hour_timestamp(base_date)
        events.append({
            "timestamp": timestamp.isoformat(),
            "event_id": str(uuid.uuid4()),
            "event_name": "GetObject",
            "event_source": "s3.amazonaws.com",
            "user_identity": random.choice(LEGIT_USERS),
            "source_ip": random.choice(SUSPICIOUS_IPS),
            "aws_region": "us-east-1",
            "status": "Success",
            "error_code": None,
            "request_count": random.randint(450, 1500),
            "bytes_transferred": random.randint(350_000_000, 1_800_000_000),
            "metadata": {
                "userAgent": "rclone/v1.65.0",
                "scenario": "data_exfiltration",
                "is_anomaly_ground_truth": True,
                "description": "Volume atípico de download e requisições S3 (exfiltração de dados)",
            },
        })

    else:
        # Cenário 6: Acesso legítimo em IP de reputação maliciosa (Tor / Proxy externo)
        timestamp = _random_business_hour_timestamp(base_date)
        events.append({
            "timestamp": timestamp.isoformat(),
            "event_id": str(uuid.uuid4()),
            "event_name": "DescribeInstances",
            "event_source": "ec2.amazonaws.com",
            "user_identity": random.choice(LEGIT_USERS),
            "source_ip": random.choice(SUSPICIOUS_IPS),
            "aws_region": "us-east-1",
            "status": "Success",
            "error_code": None,
            "request_count": 5,
            "bytes_transferred": 4096,
            "metadata": {
                "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "scenario": "suspicious_ip",
                "is_anomaly_ground_truth": True,
                "description": "Chamada originada de nó de saída Tor ou IP com má reputação",
            },
        })

    return events


# ============================================================================
# Função Principal e CLI
# ============================================================================

def generate_simulated_logs(
    count: int = 1000,
    anomaly_rate: float = 0.05,
    seed: Optional[int] = 42,
    output_path: str = "data/logs_simulados.jsonl",
) -> List[Dict[str, Any]]:
    """Gera logs simulados em formato JSONL contendo tráfego normal e anomalias injetadas.

    Args:
        count: Quantidade alvo aproximada de registros a serem gerados.
        anomaly_rate: Taxa percentual de eventos anômalos a injetar (ex: 0.05 = 5%).
        seed: Semente pseudoaleatória para reprodutibilidade.
        output_path: Caminho do arquivo JSON Lines de saída.

    Returns:
        Lista com todos os dicionários de logs gerados.
    """
    if seed is not None:
        random.seed(seed)

    base_date = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(days=7)
    records: List[Dict[str, Any]] = []

    while len(records) < count:
        if random.random() < anomaly_rate:
            anomaly_events = generate_anomaly_event(base_date)
            records.extend(anomaly_events)
        else:
            ts = _random_business_hour_timestamp(base_date)
            normal_event = generate_normal_event(ts)
            records.append(normal_event)

    # Ordena cronologicamente para consistência temporal de auditoria
    records.sort(key=lambda x: x["timestamp"])

    # Salva no arquivo de saída
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as f:
        for item in records:
            f.write(json.dumps(item, ensure_ascii=False) + "\n")

    return records


def main() -> None:
    """Interface CLI do gerador de logs simulados."""
    parser = argparse.ArgumentParser(
        description="Gerador de logs de auditoria simulados para SecOps Assistido"
    )
    parser.add_argument("--count", type=int, default=1000, help="Quantidade de registros (default: 1000)")
    parser.add_argument("--anomaly-rate", type=float, default=0.05, help="Taxa de anomalia injetada (default: 0.05)")
    parser.add_argument("--seed", type=int, default=42, help="Semente pseudoaleatória (default: 42)")
    parser.add_argument("--output", type=str, default="data/logs_simulados.jsonl", help="Caminho do arquivo de saída")

    args = parser.parse_args()

    print(f"🔧 Iniciando geração de logs...")
    print(f"   Alvo de registros: {args.count}")
    print(f"   Taxa de anomalias: {args.anomaly_rate * 100:.1f}%")
    print(f"   Semente (seed):    {args.seed}")
    print(f"   Arquivo de saída:  {args.output}")

    logs = generate_simulated_logs(
        count=args.count,
        anomaly_rate=args.anomaly_rate,
        seed=args.seed,
        output_path=args.output,
    )

    anomalies_count = sum(1 for log in logs if log.get("metadata", {}).get("is_anomaly_ground_truth"))
    print(f"✅ Geração concluída com sucesso!")
    print(f"   Total de registros gerados: {len(logs)}")
    print(f"   Anomalias injetadas:        {anomalies_count} ({(anomalies_count / len(logs)) * 100:.2f}%)")
    print(f"   Arquivo gravado em:         {args.output}")


if __name__ == "__main__":
    main()
