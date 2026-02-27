"""
Trains, evaluates, and selects from multiple anomaly detection models.
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score
from typing import Dict, Optional, Tuple

from app.config import MODEL_CONFIG, EVAL_CONFIG
from app.core.log_generator import generate_batch
from app.core.feature_engineering import FeatureStore


class ModelBundle:
    def __init__(self, name: str, estimator):
        self.name = name
        self.estimator = estimator
        self.scaler = StandardScaler()
        self.is_trained = False

    def fit(self, X: np.ndarray) -> None:
        X_scaled = self.scaler.fit_transform(X)
        self.estimator.fit(X_scaled)
        self.is_trained = True

    def predict(self, X: np.ndarray) -> np.ndarray:
        if not self.is_trained:
            raise RuntimeError(f"Model '{self.name}' has not been trained.")
        X_scaled = self.scaler.transform(X)
        raw = self.estimator.predict(X_scaled)
        return np.where(raw == -1, 1, 0)


class ModelManager:
    def __init__(self):
        self._feature_store = FeatureStore()
        self._models: Dict[str, ModelBundle] = self._init_models()
        self._best_model_name: Optional[str] = None
        self._comparison_table: Optional[pd.DataFrame] = None

    def _init_models(self) -> Dict[str, ModelBundle]:
        cfg = MODEL_CONFIG
        return {
            "IsolationForest": ModelBundle(
                "IsolationForest",
                IsolationForest(**cfg.isolation_forest),
            ),
            "OneClassSVM": ModelBundle(
                "OneClassSVM",
                OneClassSVM(**cfg.one_class_svm),
            ),
            "LocalOutlierFactor": ModelBundle(
                "LocalOutlierFactor",
                LocalOutlierFactor(**cfg.local_outlier_factor),
            ),
        }

    def _build_eval_dataset(self) -> Tuple[np.ndarray, np.ndarray]:
        cfg = EVAL_CONFIG
        store = FeatureStore()

        normal_logs = generate_batch("normal", cfg.normal_samples)
        bf_logs = generate_batch("brute_force", cfg.brute_force_samples)
        ddos_logs = generate_batch("ddos", cfg.ddos_samples)

        X_normal = store.extract_batch(normal_logs)
        X_bf = store.extract_batch(bf_logs)
        X_ddos = store.extract_batch(ddos_logs)

        X = np.vstack([X_normal, X_bf, X_ddos])
        y = np.concatenate([
            np.zeros(len(normal_logs)),
            np.ones(len(bf_logs)),
            np.ones(len(ddos_logs)),
        ])
        return X, y

    def train_models(self) -> None:
        normal_logs = generate_batch("normal", 1000)
        X_train = self._feature_store.extract_batch(normal_logs)
        for bundle in self._models.values():
            bundle.fit(X_train)

    def evaluate_models(self) -> pd.DataFrame:
        X_eval, y_true = self._build_eval_dataset()
        rows = []
        for name, bundle in self._models.items():
            y_pred = bundle.predict(X_eval)
            rows.append({
                "Model": name,
                "Precision": round(precision_score(y_true, y_pred, zero_division=0), 4),
                "Recall": round(recall_score(y_true, y_pred, zero_division=0), 4),
                "F1-Score": round(f1_score(y_true, y_pred, zero_division=0), 4),
                "Accuracy": round(accuracy_score(y_true, y_pred), 4),
            })
        self._comparison_table = pd.DataFrame(rows).set_index("Model")
        return self._comparison_table

    def select_best_model(self) -> str:
        if self._comparison_table is None:
            raise RuntimeError("Call evaluate_models() before select_best_model().")
        self._best_model_name = self._comparison_table["F1-Score"].idxmax()
        return self._best_model_name

    def predict(self, features: np.ndarray) -> Tuple[int, str]:
        if self._best_model_name is None:
            raise RuntimeError("Call select_best_model() before predict().")
        bundle = self._models[self._best_model_name]
        label = int(bundle.predict(features.reshape(1, -1))[0])
        return label, self._best_model_name

    def get_model_comparison_table(self) -> Optional[pd.DataFrame]:
        return self._comparison_table

    def get_best_model_name(self) -> Optional[str]:
        return self._best_model_name

    def is_ready(self) -> bool:
        return self._best_model_name is not None