"""
Orchestration layer.
"""

from dataclasses import dataclass
from typing import Literal

from app.core.log_generator import LogEntry
from app.core.feature_engineering import FeatureStore
from app.core.model_manager import ModelManager
from app.core.threat_engine import ThreatEngine
from app.core.firewall import Firewall

Status = Literal["NORMAL", "ANOMALY", "BLOCKED"]


@dataclass
class AnalysisResult:
    ip: str
    status: Status
    threat_score: int
    model_used: str
    reason: str
    ml_label: int
    timestamp: str

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "status": self.status,
            "threat_score": self.threat_score,
            "model_used": self.model_used,
            "reason": self.reason,
            "ml_label": self.ml_label,
            "timestamp": self.timestamp,
        }


class IntrusionService:
    def __init__(self):
        self.feature_store = FeatureStore()
        self.model_manager = ModelManager()
        self.threat_engine = ThreatEngine()
        self.firewall = Firewall()
        self._initialized = False

    def initialize(self) -> dict:
        self.model_manager.train_models()
        metrics_df = self.model_manager.evaluate_models()
        best = self.model_manager.select_best_model()
        self._initialized = True
        return {
            "best_model": best,
            "metrics": metrics_df.reset_index().to_dict(orient="records"),
        }

    def process(self, log: LogEntry) -> AnalysisResult:
        if not self._initialized:
            raise RuntimeError("Call initialize() before processing logs.")

        if self.firewall.is_blocked(log.ip):
            return AnalysisResult(
                ip=log.ip,
                status="BLOCKED",
                threat_score=self.threat_engine.get_threat_score(log.ip),
                model_used=self.model_manager.get_best_model_name(),
                reason="IP is on firewall blocklist",
                ml_label=1,
                timestamp=log.timestamp,
            )

        features = self.feature_store.extract(log)
        ml_label, model_name = self.model_manager.predict(features)
        is_anomaly = ml_label == 1

        record = self.threat_engine.update(log, ml_is_anomaly=is_anomaly)

        if self.threat_engine.should_block(log.ip):
            reason = self._build_reason(is_anomaly, log)
            self.firewall.block_ip(log.ip, reason=reason, threat_score=record.score)
            return AnalysisResult(
                ip=log.ip,
                status="BLOCKED",
                threat_score=record.score,
                model_used=model_name,
                reason=reason,
                ml_label=ml_label,
                timestamp=log.timestamp,
            )

        status: Status = "ANOMALY" if is_anomaly else "NORMAL"
        reason = self._build_reason(is_anomaly, log) if is_anomaly else "Normal traffic"

        return AnalysisResult(
            ip=log.ip,
            status=status,
            threat_score=record.score,
            model_used=model_name,
            reason=reason,
            ml_label=ml_label,
            timestamp=log.timestamp,
        )

    def reset(self) -> None:
        self.firewall.reset_firewall()
        self.threat_engine.reset()
        self.feature_store.reset()

    @staticmethod
    def _build_reason(is_anomaly: bool, log: LogEntry) -> str:
        reasons = []
        if is_anomaly:
            reasons.append("ML anomaly detected")
        if log.failed_logins >= 5:
            reasons.append(f"high failed logins ({log.failed_logins})")
        if log.requests_per_sec >= 50:
            reasons.append(f"DDoS-level request rate ({log.requests_per_sec:.1f} req/s)")
        return "; ".join(reasons) if reasons else "Suspicious pattern"