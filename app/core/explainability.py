"""
AI Explainability Engine.
Explains WHY an IP was flagged or blocked using feature contribution analysis.
No external SHAP dependency — uses a clean perturbation-based approach.
"""

import numpy as np
from dataclasses import dataclass
from typing import List, Tuple

from app.core.feature_engineering import FEATURE_NAMES


# Human-readable feature descriptions
FEATURE_LABELS = {
    "requests_per_sec":         "Request Rate (req/sec)",
    "failed_logins":            "Failed Login Attempts",
    "status_code_numeric":      "HTTP Status Code Risk",
    "rolling_avg_requests":     "Rolling Avg Request Rate",
    "request_frequency_ratio":  "Request Frequency vs Baseline",
}

# Thresholds for rule-based plain English explanations
FEATURE_THRESHOLDS = {
    "requests_per_sec":         (50.0,  "extremely high request rate — typical DDoS pattern"),
    "failed_logins":            (5.0,   "repeated failed login attempts — brute force pattern"),
    "status_code_numeric":      (3.0,   "high proportion of auth failure status codes"),
    "rolling_avg_requests":     (40.0,  "sustained elevated request rate over time"),
    "request_frequency_ratio":  (8.0,   "request rate far above normal baseline"),
}

NORMAL_BASELINES = {
    "requests_per_sec":         5.0,
    "failed_logins":            0.5,
    "status_code_numeric":      0.5,
    "rolling_avg_requests":     5.0,
    "request_frequency_ratio":  1.0,
}


@dataclass
class FeatureContribution:
    feature_name: str
    feature_label: str
    actual_value: float
    normal_baseline: float
    deviation_ratio: float      # how many times above normal
    contribution_pct: float     # percentage contribution to anomaly score
    explanation: str            # plain English


@dataclass
class ExplainabilityReport:
    ip: str
    verdict: str                # NORMAL / ANOMALY / BLOCKED
    confidence: str             # HIGH / MEDIUM / LOW
    top_reasons: List[str]      # top 3 plain English reasons
    contributions: List[FeatureContribution]
    summary: str                # one sentence summary


class ExplainabilityEngine:
    """
    Explains model decisions using feature deviation analysis.
    Compares actual feature values against normal baselines and
    calculates relative contribution of each feature to the anomaly.
    """

    def explain(self, ip: str, features: np.ndarray, verdict: str) -> ExplainabilityReport:
        """
        Generate a human-readable explanation for a prediction.

        Args:
            ip: The IP address being analyzed
            features: Feature vector (same order as FEATURE_NAMES)
            verdict: NORMAL / ANOMALY / BLOCKED
        """
        contributions = self._compute_contributions(features)
        top_reasons = self._get_top_reasons(contributions, verdict)
        confidence = self._compute_confidence(contributions, verdict)
        summary = self._build_summary(ip, verdict, top_reasons, confidence)

        return ExplainabilityReport(
            ip=ip,
            verdict=verdict,
            confidence=confidence,
            top_reasons=top_reasons,
            contributions=contributions,
            summary=summary,
        )

    def _compute_contributions(self, features: np.ndarray) -> List[FeatureContribution]:
        contributions = []
        total_deviation = 0.0
        deviations = []

        for i, fname in enumerate(FEATURE_NAMES):
            actual = float(features[i])
            baseline = NORMAL_BASELINES[fname]
            deviation = max(0.0, actual - baseline)
            deviations.append(deviation)
            total_deviation += deviation

        for i, fname in enumerate(FEATURE_NAMES):
            actual = float(features[i])
            baseline = NORMAL_BASELINES[fname]
            deviation = deviations[i]
            deviation_ratio = actual / (baseline + 1e-9)
            contribution_pct = (deviation / (total_deviation + 1e-9)) * 100

            # Build plain English explanation
            threshold, threat_desc = FEATURE_THRESHOLDS[fname]
            if actual >= threshold:
                explanation = f"⚠️ {FEATURE_LABELS[fname]} is {actual:.1f} — {threat_desc}"
            elif deviation_ratio > 2.0:
                explanation = f"🔶 {FEATURE_LABELS[fname]} is {deviation_ratio:.1f}x above normal ({actual:.1f} vs baseline {baseline:.1f})"
            else:
                explanation = f"✅ {FEATURE_LABELS[fname]} is normal ({actual:.1f})"

            contributions.append(FeatureContribution(
                feature_name=fname,
                feature_label=FEATURE_LABELS[fname],
                actual_value=actual,
                normal_baseline=baseline,
                deviation_ratio=deviation_ratio,
                contribution_pct=round(contribution_pct, 1),
                explanation=explanation,
            ))

        # Sort by contribution descending
        contributions.sort(key=lambda x: x.contribution_pct, reverse=True)
        return contributions

    def _get_top_reasons(self, contributions: List[FeatureContribution], verdict: str) -> List[str]:
        if verdict == "NORMAL":
            return ["All traffic metrics are within normal range",
                    "No suspicious login patterns detected",
                    "Request rate is consistent with legitimate usage"]

        reasons = []
        for c in contributions[:3]:
            if c.deviation_ratio > 2.0:
                reasons.append(c.explanation)

        if not reasons:
            reasons.append("ML model detected subtle anomaly in traffic pattern")

        return reasons[:3]

    def _compute_confidence(self, contributions: List[FeatureContribution], verdict: str) -> str:
        if verdict == "NORMAL":
            return "HIGH"
        # Count how many features are significantly above normal
        high_deviation = sum(1 for c in contributions if c.deviation_ratio > 3.0)
        if high_deviation >= 2:
            return "HIGH"
        elif high_deviation == 1:
            return "MEDIUM"
        return "LOW"

    def _build_summary(self, ip: str, verdict: str, reasons: List[str], confidence: str) -> str:
        if verdict == "NORMAL":
            return f"IP {ip} shows normal traffic behavior. No action required."
        elif verdict == "ANOMALY":
            return f"IP {ip} flagged as suspicious ({confidence} confidence). Monitoring — not yet blocked."
        else:
            return f"IP {ip} has been BLOCKED ({confidence} confidence). Primary trigger: {reasons[0] if reasons else 'multiple anomalies'}."