"""
Hybrid threat scoring engine.
"""

from collections import defaultdict
from dataclasses import dataclass
from typing import Dict

from app.config import THREAT_CONFIG
from app.core.log_generator import LogEntry


@dataclass
class IPThreatRecord:
    ip: str
    score: int = 0
    ml_hits: int = 0
    brute_force_hits: int = 0
    ddos_hits: int = 0

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "score": self.score,
            "ml_hits": self.ml_hits,
            "brute_force_hits": self.brute_force_hits,
            "ddos_hits": self.ddos_hits,
        }


class ThreatEngine:
    def __init__(self):
        self._records: Dict[str, IPThreatRecord] = {}
        self._cfg = THREAT_CONFIG

    def _get_or_create(self, ip: str) -> IPThreatRecord:
        if ip not in self._records:
            self._records[ip] = IPThreatRecord(ip=ip)
        return self._records[ip]

    def update(self, log: LogEntry, ml_is_anomaly: bool) -> IPThreatRecord:
        record = self._get_or_create(log.ip)

        if ml_is_anomaly:
            record.score += self._cfg.ml_anomaly_score
            record.ml_hits += 1

        if log.failed_logins >= self._cfg.failed_login_threshold:
            record.score += self._cfg.brute_force_score
            record.brute_force_hits += 1

        if log.requests_per_sec >= self._cfg.ddos_request_threshold:
            record.score += self._cfg.ddos_score
            record.ddos_hits += 1

        return record

    def should_block(self, ip: str) -> bool:
        record = self._records.get(ip)
        if record is None:
            return False
        return record.score >= self._cfg.block_score_threshold

    def get_threat_score(self, ip: str) -> int:
        return self._records.get(ip, IPThreatRecord(ip=ip)).score

    def get_all_records(self) -> Dict[str, IPThreatRecord]:
        return dict(self._records)

    def reset(self) -> None:
        self._records.clear()