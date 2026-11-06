"""Logistic-regression phishing scorer with linear-SHAP explanations.

Why logistic regression: for a linear model the exact SHAP value of every
feature is simply coef_i * (x_i - mean_i) / std_i - no approximation, no
external explainability library, and a recruiter can audit the maths in
one sitting. The model ships as a JSON file of coefficients, so inference
needs zero dependencies and training needs only scikit-learn.

Training data is synthetic and generated in-repo
(``generate_synthetic_dataset``) from class-conditional feature
distributions a SOC analyst would recognise: phishing mail fails
authentication ~50x more often, presses urgency ~10x harder, and so on.
That keeps the repo self-contained - no external dataset download.
"""

from __future__ import annotations

import json
import random
from pathlib import Path

from .features import FEATURE_NAMES

DEFAULT_MODEL_PATH = Path(__file__).resolve().parent / "models" / "default_model.json"

# Class-conditional probabilities for binary features and means for count
# features. Honest values, not tuned to 100% - real triage has overlap.
_BINARY_P = {
    # feature: (P(1|legit), P(1|phish))
    "spf_fail": (0.01, 0.45), "spf_softfail": (0.04, 0.30),
    "dkim_fail": (0.01, 0.40), "dkim_missing": (0.08, 0.55),
    "dmarc_fail": (0.01, 0.45), "dmarc_missing": (0.10, 0.50),
    "reply_to_mismatch": (0.02, 0.50), "return_path_mismatch": (0.02, 0.45),
    "display_name_spoof": (0.01, 0.35), "lookalike_domain": (0.005, 0.40),
    "has_shortener": (0.03, 0.25), "has_ip_url": (0.005, 0.20),
    "has_punycode": (0.002, 0.10), "has_at_url": (0.005, 0.15),
    "dangerous_attachment": (0.005, 0.25), "double_ext_attachment": (0.002, 0.20),
    "caps_subject": (0.03, 0.30),
}
_COUNT_MEAN = {
    # feature: (mean|legit, mean|phish)
    "num_urls": (1.5, 4.0), "num_url_domains": (1.0, 2.5),
    "url_from_mismatch": (0.05, 0.55),
    "urgency_hits": (0.3, 3.0), "credential_hits": (0.1, 2.0),
    "num_attachments": (0.4, 0.8), "num_hops": (3.0, 5.0),
}
LABEL_NOISE = 0.02  # fraction of labels flipped - keeps the task non-trivial


def generate_synthetic_dataset(n: int = 4000, seed: int = 42):
    """Return (X, y) as nested lists following FEATURE_NAMES order."""
    rng = random.Random(seed)
    X, y = [], []
    for i in range(n):
        phish = 1 if rng.random() < 0.5 else 0
        label = 1 - phish if rng.random() < LABEL_NOISE else phish
        row = []
        for name in FEATURE_NAMES:
            if name in _BINARY_P:
                p = _BINARY_P[name][phish]
                row.append(1.0 if rng.random() < p else 0.0)
            else:
                mean = _COUNT_MEAN[name][phish]
                # overdispersed count-ish sample, clipped at 0
                val = max(0.0, rng.gauss(mean, max(0.5, mean * 0.6)))
                row.append(round(val, 3))
        X.append(row)
        y.append(label)
    return X, y


class PhishModel:
    def __init__(self, weights, bias, means, stds, metrics=None):
        if len(weights) != len(FEATURE_NAMES):
            raise ValueError("weight count does not match FEATURE_NAMES")
        self.weights = list(weights)
        self.bias = float(bias)
        self.means = list(means)
        self.stds = [s if s > 1e-9 else 1.0 for s in stds]
        self.metrics = metrics or {}

    # ---- inference ----------------------------------------------------------
    def _logit(self, features: dict) -> float:
        z = self.bias
        for i, name in enumerate(FEATURE_NAMES):
            z += self.weights[i] * (features.get(name, 0.0) - self.means[i]) / self.stds[i]
        return z

    def predict_proba(self, features: dict) -> float:
        import math
        z = self._logit(features)
        return 1.0 / (1.0 + math.exp(-z))

    def explain(self, features: dict, top: int = 5):
        """Exact linear-SHAP contributions, sorted by absolute magnitude."""
        contrib = []
        for i, name in enumerate(FEATURE_NAMES):
            c = self.weights[i] * (features.get(name, 0.0) - self.means[i]) / self.stds[i]
            contrib.append((name, round(c, 4)))
        contrib.sort(key=lambda kv: abs(kv[1]), reverse=True)
        return contrib[:top]

    # ---- serialisation --------------------------------------------------------
    def to_dict(self):
        return {
            "format": "phishscope-logreg/v1",
            "feature_names": list(FEATURE_NAMES),
            "weights": self.weights,
            "bias": self.bias,
            "means": self.means,
            "stds": self.stds,
            "metrics": self.metrics,
        }

    def save(self, path=DEFAULT_MODEL_PATH):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2))
        return path

    @classmethod
    def load(cls, path=DEFAULT_MODEL_PATH) -> "PhishModel":
        data = json.loads(Path(path).read_text())
        if data["feature_names"] != FEATURE_NAMES:
            raise ValueError("model feature order does not match this PhishScope version")
        return cls(data["weights"], data["bias"], data["means"], data["stds"],
                   data.get("metrics"))

    @classmethod
    def load_or_train(cls, path=DEFAULT_MODEL_PATH) -> "PhishModel":
        try:
            return cls.load(path)
        except (OSError, ValueError, json.JSONDecodeError):
            return cls.train()

    # ---- training ---------------------------------------------------------------
    @classmethod
    def train(cls, n: int = 4000, seed: int = 42) -> "PhishModel":
        try:
            from sklearn.linear_model import LogisticRegression
            from sklearn.model_selection import train_test_split
            from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
        except ImportError as exc:  # pragma: no cover
            raise SystemExit(
                "Training needs scikit-learn: pip install -r requirements.txt"
            ) from exc

        X, y = generate_synthetic_dataset(n=n, seed=seed)
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=seed, stratify=y)

        means = [sum(r[i] for r in X_train) / len(X_train) for i in range(len(FEATURE_NAMES))]
        stds = []
        for i in range(len(FEATURE_NAMES)):
            var = sum((r[i] - means[i]) ** 2 for r in X_train) / len(X_train)
            stds.append(var ** 0.5 or 1.0)

        def scale(row):
            return [(row[i] - means[i]) / stds[i] for i in range(len(FEATURE_NAMES))]

        clf = LogisticRegression(max_iter=1000, random_state=seed)
        clf.fit([scale(r) for r in X_train], y_train)
        pred = clf.predict([scale(r) for r in X_test])

        metrics = {
            "algorithm": "logistic-regression",
            "train_samples": len(X_train),
            "test_samples": len(X_test),
            "accuracy": round(accuracy_score(y_test, pred), 4),
            "precision": round(precision_score(y_test, pred), 4),
            "recall": round(recall_score(y_test, pred), 4),
            "f1": round(f1_score(y_test, pred), 4),
            "synthetic_seed": seed,
        }
        return cls(list(clf.coef_[0]), float(clf.intercept_[0]), means, stds, metrics)
