"""
Phishing URL Detection Engine.
Hybrid approach: ML model (Random Forest on URL features) + rule-based pattern matching.
No external API needed — fully self-contained.
"""

import re
import math
import hashlib
import random
import numpy as np
import pandas as pd
from dataclasses import dataclass, field
from typing import List, Tuple, Dict
from urllib.parse import urlparse

from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score


# ──────────────────────────────────────────────
# Suspicious patterns (rule-based layer)
# ──────────────────────────────────────────────

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "secure", "account", "update",
    "banking", "paypal", "apple", "amazon", "microsoft", "google",
    "password", "credential", "confirm", "urgent", "suspended",
    "validate", "recover", "unlock", "alert", "warning", "click",
    "free", "prize", "winner", "lucky", "offer", "deal",
]

TRUSTED_DOMAINS = {
    "google.com", "microsoft.com", "apple.com", "amazon.com",
    "paypal.com", "facebook.com", "twitter.com", "linkedin.com",
    "github.com", "stackoverflow.com", "wikipedia.org",
}

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top",
    ".click", ".link", ".work", ".party", ".loan", ".download",
}

IP_PATTERN = re.compile(
    r"https?://(\d{1,3}\.){3}\d{1,3}"
)


# ──────────────────────────────────────────────
# Feature extraction from URLs
# ──────────────────────────────────────────────

def extract_url_features(url: str) -> np.ndarray:
    """
    Extract 20 numerical features from a URL.
    These are the features the ML model uses.
    """
    try:
        parsed = urlparse(url if url.startswith("http") else "http://" + url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        full = url.lower()
    except Exception:
        domain, path, full = "", "", url.lower()

    # 1. URL length
    url_length = len(url)

    # 2. Domain length
    domain_length = len(domain)

    # 3. Number of dots in domain
    dot_count = domain.count(".")

    # 4. Number of hyphens in domain
    hyphen_count = domain.count("-")

    # 5. Number of digits in domain
    digit_count = sum(c.isdigit() for c in domain)

    # 6. Number of special characters
    special_chars = sum(1 for c in url if c in "@?=&%#~")

    # 7. Has IP address instead of domain
    has_ip = 1 if IP_PATTERN.match(url) else 0

    # 8. URL entropy (randomness — phishing URLs often look random)
    url_entropy = _entropy(url)

    # 9. Subdomain count
    parts = domain.split(".")
    subdomain_count = max(0, len(parts) - 2)

    # 10. Path length
    path_length = len(path)

    # 11. Number of path segments
    path_segments = len([p for p in path.split("/") if p])

    # 12. Has suspicious keywords
    keyword_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in full)

    # 13. Has @ symbol (common phishing trick)
    has_at = 1 if "@" in url else 0

    # 14. Has double slash in path
    has_double_slash = 1 if "//" in path else 0

    # 15. HTTPS or not
    is_https = 1 if url.startswith("https") else 0

    # 16. Has suspicious TLD
    has_suspicious_tld = 1 if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS) else 0

    # 17. Domain impersonates trusted brand
    impersonation = _check_impersonation(domain)

    # 18. Digit ratio in URL
    digit_ratio = sum(c.isdigit() for c in url) / max(len(url), 1)

    # 19. Has port number
    has_port = 1 if ":" in domain else 0

    # 20. Query string length
    query_length = len(parsed.query) if hasattr(parsed, "query") else 0

    return np.array([
        url_length, domain_length, dot_count, hyphen_count,
        digit_count, special_chars, has_ip, url_entropy,
        subdomain_count, path_length, path_segments, keyword_count,
        has_at, has_double_slash, is_https, has_suspicious_tld,
        impersonation, digit_ratio, has_port, query_length,
    ], dtype=float)


FEATURE_NAMES_PHISHING = [
    "URL Length", "Domain Length", "Dot Count", "Hyphen Count",
    "Digit Count", "Special Chars", "Has IP", "URL Entropy",
    "Subdomain Count", "Path Length", "Path Segments", "Keyword Count",
    "Has @", "Has Double Slash", "Is HTTPS", "Suspicious TLD",
    "Brand Impersonation", "Digit Ratio", "Has Port", "Query Length",
]


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    total = len(s)
    return -sum((v/total) * math.log2(v/total) for v in freq.values())


def _check_impersonation(domain: str) -> int:
    brands = ["paypal", "apple", "amazon", "microsoft", "google",
              "facebook", "netflix", "bank", "chase", "wellsfargo"]
    for brand in brands:
        if brand in domain:
            # Check if it's NOT the real domain
            for trusted in TRUSTED_DOMAINS:
                if domain == trusted or domain.endswith("." + trusted):
                    return 0
            return 1
    return 0


# ──────────────────────────────────────────────
# Synthetic URL dataset generation
# ──────────────────────────────────────────────

LEGIT_URLS = [
    "https://www.google.com/search?q=python",
    "https://github.com/user/repo",
    "https://stackoverflow.com/questions/12345",
    "https://www.wikipedia.org/wiki/Machine_learning",
    "https://docs.python.org/3/library/os.html",
    "https://www.amazon.com/dp/B08N5WRWNW",
    "https://linkedin.com/in/username",
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    "https://news.ycombinator.com/item?id=12345",
    "https://medium.com/@author/article-title",
    "https://twitter.com/user/status/123456",
    "https://www.reddit.com/r/python/comments/abc",
    "https://microsoft.com/en-us/windows",
    "https://apple.com/iphone",
    "https://www.bbc.com/news/technology",
]

PHISHING_URLS = [
    "http://paypal-secure-login.tk/verify/account",
    "http://192.168.1.1/apple-id/signin",
    "http://amazon-update-account.xyz/login.php",
    "http://microsoft-verify.click/urgent/password",
    "http://secure-paypal-login.ml/confirm",
    "http://apple-id-suspended.ga/unlock",
    "http://www.google.com.phishing-site.tk/login",
    "http://bankofamerica-secure.xyz/verify",
    "http://login-amazon-update.ml/account/signin",
    "http://paypal.com.user-verify.tk/secure",
    "http://192.0.2.1/free-prize/winner/claim",
    "http://microsoft-alert-verify.work/account",
    "http://secure-login-paypal.gq/update",
    "http://apple-locked-account.cf/recover",
    "http://amazon-prize-offer.xyz/free/deal",
]


def _generate_synthetic_dataset(n_legit: int = 500, n_phishing: int = 500):
    """Generate synthetic labeled URL dataset for training and evaluation."""
    X_list, y_list = [], []

    for _ in range(n_legit):
        base = random.choice(LEGIT_URLS)
        # Add small variations
        url = base + "?" + "".join(random.choices("abcdefghijk", k=random.randint(0, 8)))
        X_list.append(extract_url_features(url))
        y_list.append(0)

    for _ in range(n_phishing):
        base = random.choice(PHISHING_URLS)
        url = base + "/" + "".join(random.choices("0123456789abcdef", k=random.randint(4, 12)))
        X_list.append(extract_url_features(url))
        y_list.append(1)

    return np.array(X_list), np.array(y_list)


# ──────────────────────────────────────────────
# Rule-based checker
# ──────────────────────────────────────────────

@dataclass
class RuleResult:
    triggered_rules: List[str] = field(default_factory=list)
    rule_score: float = 0.0

    def is_suspicious(self, threshold: float = 2.0) -> bool:
        return self.rule_score >= threshold


def rule_based_check(url: str) -> RuleResult:
    result = RuleResult()
    full = url.lower()
    try:
        parsed = urlparse(url if url.startswith("http") else "http://" + url)
        domain = parsed.netloc.lower()
    except Exception:
        domain = ""

    if IP_PATTERN.match(url):
        result.triggered_rules.append("⚠️ IP address used instead of domain name")
        result.rule_score += 3.0

    if not url.startswith("https"):
        result.triggered_rules.append("⚠️ No HTTPS — unsecured connection")
        result.rule_score += 1.0

    if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
        result.triggered_rules.append(f"⚠️ Suspicious top-level domain detected")
        result.rule_score += 2.0

    kws = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full]
    if len(kws) >= 2:
        result.triggered_rules.append(f"⚠️ Multiple suspicious keywords: {', '.join(kws[:4])}")
        result.rule_score += 1.5

    if _check_impersonation(domain):
        result.triggered_rules.append("🚨 Brand impersonation detected — fake trusted domain")
        result.rule_score += 4.0

    if "@" in url:
        result.triggered_rules.append("⚠️ @ symbol in URL — common phishing trick")
        result.rule_score += 2.0

    if domain.count("-") >= 2:
        result.triggered_rules.append("⚠️ Multiple hyphens in domain — suspicious pattern")
        result.rule_score += 1.0

    if len(url) > 100:
        result.triggered_rules.append(f"⚠️ Unusually long URL ({len(url)} chars)")
        result.rule_score += 1.0

    if not result.triggered_rules:
        result.triggered_rules.append("✅ No suspicious patterns detected")

    return result


# ──────────────────────────────────────────────
# ML Model Bundle
# ──────────────────────────────────────────────

@dataclass
class PhishingModelBundle:
    name: str
    model: object
    scaler: StandardScaler = field(default_factory=StandardScaler)
    is_trained: bool = False

    def fit(self, X, y):
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled, y)
        self.is_trained = True

    def predict_proba(self, X: np.ndarray) -> float:
        X_scaled = self.scaler.transform(X.reshape(1, -1))
        return float(self.model.predict_proba(X_scaled)[0][1])

    def predict(self, X: np.ndarray) -> int:
        return 1 if self.predict_proba(X) >= 0.5 else 0


# ──────────────────────────────────────────────
# Result dataclass
# ──────────────────────────────────────────────

@dataclass
class PhishingResult:
    url: str
    verdict: str            # SAFE / SUSPICIOUS / PHISHING
    confidence: float       # 0.0 - 1.0
    ml_probability: float   # raw ML phishing probability
    rule_score: float       # rule-based score
    triggered_rules: List[str]
    top_features: List[Tuple[str, float]]  # (feature_name, value)
    model_used: str
    reason: str

    def to_dict(self) -> dict:
        return {
            "url": self.url[:80] + "..." if len(self.url) > 80 else self.url,
            "verdict": self.verdict,
            "confidence": f"{self.confidence:.1%}",
            "ml_probability": f"{self.ml_probability:.1%}",
            "rule_score": self.rule_score,
            "triggered_rules": "; ".join(self.triggered_rules),
            "model_used": self.model_used,
            "reason": self.reason,
        }


# ──────────────────────────────────────────────
# Main Phishing Detector
# ──────────────────────────────────────────────

class PhishingDetector:
    """
    Hybrid phishing URL detector.
    Combines ML probability with rule-based scoring for final verdict.
    """

    def __init__(self):
        self._models: Dict[str, PhishingModelBundle] = {
            "RandomForest": PhishingModelBundle(
                "RandomForest",
                RandomForestClassifier(n_estimators=100, random_state=42, max_depth=8)
            ),
            "GradientBoosting": PhishingModelBundle(
                "GradientBoosting",
                GradientBoostingClassifier(n_estimators=100, random_state=42, max_depth=4)
            ),
            "LogisticRegression": PhishingModelBundle(
                "LogisticRegression",
                LogisticRegression(max_iter=1000, random_state=42)
            ),
        }
        self._best_model_name: str = "RandomForest"
        self._metrics: pd.DataFrame = None
        self._is_trained: bool = False
        self._history: List[PhishingResult] = []

    def train(self) -> pd.DataFrame:
        """Train all models and select best by F1. Returns metrics DataFrame."""
        X_train, y_train = _generate_synthetic_dataset(600, 600)
        X_eval, y_eval = _generate_synthetic_dataset(200, 200)

        for bundle in self._models.values():
            bundle.fit(X_train, y_train)

        rows = []
        for name, bundle in self._models.items():
            y_pred = np.array([bundle.predict(X_eval[i]) for i in range(len(X_eval))])
            rows.append({
                "Model": name,
                "Precision": round(precision_score(y_eval, y_pred, zero_division=0), 4),
                "Recall": round(recall_score(y_eval, y_pred, zero_division=0), 4),
                "F1-Score": round(f1_score(y_eval, y_pred, zero_division=0), 4),
                "Accuracy": round(accuracy_score(y_eval, y_pred), 4),
            })

        self._metrics = pd.DataFrame(rows).set_index("Model")
        self._best_model_name = self._metrics["F1-Score"].idxmax()
        self._is_trained = True
        return self._metrics

    def analyze(self, url: str) -> PhishingResult:
        """Analyze a URL using both ML and rules. Returns PhishingResult."""
        if not self._is_trained:
            raise RuntimeError("Call train() before analyze().")

        features = extract_url_features(url)
        rule_result = rule_based_check(url)

        bundle = self._models[self._best_model_name]
        ml_prob = bundle.predict_proba(features)

        # Hybrid score: 60% ML + 40% rules (normalized)
        rule_normalized = min(rule_result.rule_score / 8.0, 1.0)
        hybrid_score = 0.6 * ml_prob + 0.4 * rule_normalized

        # Verdict thresholds
        if hybrid_score >= 0.65:
            verdict = "PHISHING"
        elif hybrid_score >= 0.35:
            verdict = "SUSPICIOUS"
        else:
            verdict = "SAFE"

        # Top features by value (most suspicious)
        feat_pairs = list(zip(FEATURE_NAMES_PHISHING, features))
        top_features = sorted(feat_pairs, key=lambda x: abs(x[1]), reverse=True)[:5]

        # Build reason
        if verdict == "PHISHING":
            reason = rule_result.triggered_rules[0] if rule_result.triggered_rules else "ML model flagged as phishing"
        elif verdict == "SUSPICIOUS":
            reason = "Borderline URL — some suspicious signals detected"
        else:
            reason = "URL appears safe — no significant phishing indicators"

        result = PhishingResult(
            url=url,
            verdict=verdict,
            confidence=hybrid_score,
            ml_probability=ml_prob,
            rule_score=rule_result.rule_score,
            triggered_rules=rule_result.triggered_rules,
            top_features=top_features,
            model_used=self._best_model_name,
            reason=reason,
        )
        self._history.append(result)
        return result

    def get_metrics(self) -> pd.DataFrame:
        return self._metrics

    def get_best_model(self) -> str:
        return self._best_model_name

    def get_history(self) -> List[PhishingResult]:
        return self._history

    def clear_history(self) -> None:
        self._history.clear()