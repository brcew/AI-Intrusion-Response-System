"""
System-wide configuration.
"""

from dataclasses import dataclass, field
from typing import Dict, Any


@dataclass
class ModelConfig:
    isolation_forest: Dict[str, Any] = field(default_factory=lambda: {
        "n_estimators": 100,
        "contamination": 0.05,
        "random_state": 42,
        "max_samples": "auto",
    })
    one_class_svm: Dict[str, Any] = field(default_factory=lambda: {
        "kernel": "rbf",
        "nu": 0.05,
        "gamma": "scale",
    })
    local_outlier_factor: Dict[str, Any] = field(default_factory=lambda: {
        "n_neighbors": 20,
        "contamination": 0.05,
        "novelty": True,
    })


@dataclass
class ThreatConfig:
    ml_anomaly_score: int = 5
    brute_force_score: int = 3
    ddos_score: int = 4
    failed_login_threshold: int = 5
    ddos_request_threshold: float = 50.0
    block_score_threshold: int = 8
    score_decay_per_tick: int = 0


@dataclass
class SimulationConfig:
    normal_request_rate: tuple = (1.0, 10.0)
    normal_failed_logins: tuple = (0, 1)
    normal_status_codes: list = field(default_factory=lambda: [200, 200, 200, 301, 404])
    brute_force_request_rate: tuple = (5.0, 20.0)
    brute_force_failed_logins: tuple = (10, 50)
    brute_force_status_codes: list = field(default_factory=lambda: [401, 401, 403])
    ddos_request_rate: tuple = (80.0, 200.0)
    ddos_failed_logins: tuple = (0, 2)
    ddos_status_codes: list = field(default_factory=lambda: [200, 503, 503])
    simulation_interval_sec: float = 0.5
    normal_ip_pool: int = 20
    attacker_ip_pool: int = 5


@dataclass
class EvaluationConfig:
    normal_samples: int = 500
    brute_force_samples: int = 150
    ddos_samples: int = 150


MODEL_CONFIG = ModelConfig()
THREAT_CONFIG = ThreatConfig()
SIM_CONFIG = SimulationConfig()
EVAL_CONFIG = EvaluationConfig()