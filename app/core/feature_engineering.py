"""
Converts raw LogEntry objects into numerical feature vectors for ML models.
Rolling statistics are maintained per-IP in a sliding window.
"""

from collections import defaultdict, deque
from typing import Dict, List
import numpy as np

from app.core.log_generator import LogEntry

FEATURE_NAMES = [
    "requests_per_sec",
    "failed_logins",
    "status_code_numeric",
    "rolling_avg_requests",
    "request_frequency_ratio",
]

_STATUS_RANK = {
    200: 0, 201: 0, 204: 0,
    301: 1, 302: 1,
    400: 2, 401: 3, 403: 3,
    404: 2,
    429: 4,
    500: 2, 503: 2,
}

_WINDOW_SIZE = 10


class FeatureStore:
    def __init__(self, window_size: int = _WINDOW_SIZE):
        self.window_size = window_size
        self._windows: Dict[str, deque] = defaultdict(lambda: deque(maxlen=window_size))

    def extract(self, log: LogEntry) -> np.ndarray:
        ip_window = self._windows[log.ip]
        ip_window.append(log.requests_per_sec)

        rolling_avg = float(np.mean(ip_window)) if ip_window else log.requests_per_sec
        global_baseline = 5.0
        freq_ratio = log.requests_per_sec / (global_baseline + 1e-9)
        status_numeric = _STATUS_RANK.get(log.status_code, 2)

        return np.array([
            log.requests_per_sec,
            log.failed_logins,
            status_numeric,
            rolling_avg,
            freq_ratio,
        ], dtype=float)

    def extract_batch(self, logs: List[LogEntry]) -> np.ndarray:
        return np.vstack([self.extract(log) for log in logs])

    def reset(self) -> None:
        self._windows.clear()