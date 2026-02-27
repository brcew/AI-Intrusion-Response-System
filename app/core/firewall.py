"""
In-memory firewall for tracking blocked IPs.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional


@dataclass
class BlockRecord:
    ip: str
    reason: str
    timestamp: str
    threat_score: int

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "reason": self.reason,
            "timestamp": self.timestamp,
            "threat_score": self.threat_score,
        }


class Firewall:
    def __init__(self):
        self._blocked: Dict[str, BlockRecord] = {}

    def block_ip(self, ip: str, reason: str, threat_score: int) -> BlockRecord:
        record = BlockRecord(
            ip=ip,
            reason=reason,
            timestamp=datetime.utcnow().isoformat(),
            threat_score=threat_score,
        )
        self._blocked[ip] = record
        return record

    def is_blocked(self, ip: str) -> bool:
        return ip in self._blocked

    def get_blocked_ips(self) -> List[BlockRecord]:
        return list(self._blocked.values())

    def unblock_ip(self, ip: str) -> bool:
        if ip in self._blocked:
            del self._blocked[ip]
            return True
        return False

    def reset_firewall(self) -> None:
        self._blocked.clear()

    def __len__(self) -> int:
        return len(self._blocked)