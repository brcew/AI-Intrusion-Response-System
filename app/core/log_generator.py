"""
Simulates real-time server log entries for normal, brute-force, DDoS, and mixed traffic.
"""

import random
from dataclasses import dataclass
from datetime import datetime
from typing import List, Literal

from app.config import SIM_CONFIG

TrafficMode = Literal["normal", "brute_force", "ddos", "mixed"]


@dataclass
class LogEntry:
    ip: str
    timestamp: str
    status_code: int
    failed_logins: int
    requests_per_sec: float
    traffic_type: str


def _generate_ip_pools() -> tuple:
    normal_ips = [f"192.168.1.{i}" for i in range(1, SIM_CONFIG.normal_ip_pool + 1)]
    attacker_ips = [f"10.0.0.{i}" for i in range(1, SIM_CONFIG.attacker_ip_pool + 1)]
    return normal_ips, attacker_ips


NORMAL_IPS, ATTACKER_IPS = _generate_ip_pools()


def _make_normal_log() -> LogEntry:
    return LogEntry(
        ip=random.choice(NORMAL_IPS),
        timestamp=datetime.utcnow().isoformat(),
        status_code=random.choice(SIM_CONFIG.normal_status_codes),
        failed_logins=random.randint(*SIM_CONFIG.normal_failed_logins),
        requests_per_sec=round(random.uniform(*SIM_CONFIG.normal_request_rate), 2),
        traffic_type="normal",
    )


def _make_brute_force_log() -> LogEntry:
    return LogEntry(
        ip=random.choice(ATTACKER_IPS),
        timestamp=datetime.utcnow().isoformat(),
        status_code=random.choice(SIM_CONFIG.brute_force_status_codes),
        failed_logins=random.randint(*SIM_CONFIG.brute_force_failed_logins),
        requests_per_sec=round(random.uniform(*SIM_CONFIG.brute_force_request_rate), 2),
        traffic_type="brute_force",
    )


def _make_ddos_log() -> LogEntry:
    return LogEntry(
        ip=random.choice(ATTACKER_IPS),
        timestamp=datetime.utcnow().isoformat(),
        status_code=random.choice(SIM_CONFIG.ddos_status_codes),
        failed_logins=random.randint(*SIM_CONFIG.ddos_failed_logins),
        requests_per_sec=round(random.uniform(*SIM_CONFIG.ddos_request_rate), 2),
        traffic_type="ddos",
    )


_GENERATORS = {
    "normal": _make_normal_log,
    "brute_force": _make_brute_force_log,
    "ddos": _make_ddos_log,
}


def generate_log(mode: TrafficMode) -> LogEntry:
    if mode == "mixed":
        weights = [0.6, 0.2, 0.2]
        chosen = random.choices(["normal", "brute_force", "ddos"], weights=weights)[0]
        return _GENERATORS[chosen]()
    return _GENERATORS[mode]()


def generate_batch(mode: TrafficMode, n: int) -> List[LogEntry]:
    return [generate_log(mode) for _ in range(n)]