"""Behavioural anomaly detector.

We use ``IsolationForest`` because:

  * insider scenarios are statistically rare and distributionally weird,
    not necessarily "labelled-malicious"
  * we want to score against per-user baselines without needing
    explicit malicious training labels
  * IForest gives a continuous ``decision_function`` that we map to a
    monotone risk in [0, 1]

The detector is trained on benign baselines per role, and scored on
new activities.  Optionally, when labelled data is available, we also
expose a supervised fallback via ``GradientBoostingClassifier`` --
the unsupervised path is what runs by default.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from .events import UserActivity
from .features import UserFeatureExtractor


@dataclass
class DetectorConfig:
    n_estimators: int = 200
    contamination: float = 0.05
    random_state: int = 1337
    suspicious_threshold: float = 0.55  # mapped IForest score in [0,1]
    per_role: bool = True  # train one model per user-role, fall back to global


@dataclass
class UserVerdict:
    user_id: str
    date_key: str
    role: Optional[str]
    score: float  # mapped to [0,1]; higher = more anomalous
    suspicious: bool
    top_features: List[Tuple[str, float]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {
            "user_id": self.user_id,
            "date_key": self.date_key,
            "role": self.role,
            "score": float(self.score),
            "suspicious": bool(self.suspicious),
            "top_features": [(n, float(v)) for n, v in self.top_features],
        }


def _map_iforest_score(raw: float) -> float:
    # IForest decision_function: higher = more normal.  Anomaly score:
    # higher = more anomalous.  We map score_samples (0..1, higher=normal)
    # via 1-x to get [0,1] anomaly.  decision_function adds an offset; we
    # use score_samples directly via predict_proba-like helpers.
    # Here `raw` is the ``score_samples`` output already (lower=more anomalous,
    # typically in roughly [-0.5, 0.0]).  Map to a monotone risk in [0,1].
    # We use a simple sigmoid centred so the contamination boundary lands
    # near 0.5.
    return float(1.0 / (1.0 + math_exp(8.0 * (raw + 0.55))))


def math_exp(x: float) -> float:
    # local helper to avoid an extra import
    import math
    return math.exp(x)


class InsiderThreatDetector:
    def __init__(self, config: Optional[DetectorConfig] = None) -> None:
        self.config = config or DetectorConfig()
        self._extractor = UserFeatureExtractor()
        self._models: Dict[str, IsolationForest] = {}
        self._scalers: Dict[str, StandardScaler] = {}

    @property
    def is_fitted(self) -> bool:
        return bool(self._models)

    def _key(self, role: Optional[str]) -> str:
        if not self.config.per_role or role is None:
            return "_global"
        return role

    # ---- training ----

    def fit(self, activities: Sequence[UserActivity]) -> "InsiderThreatDetector":
        if not activities:
            raise ValueError("cannot fit on empty corpus")
        # group by role (or global)
        groups: Dict[str, List[UserActivity]] = {}
        for a in activities:
            groups.setdefault(self._key(a.role), []).append(a)
        # always have a global fallback
        if "_global" not in groups:
            groups["_global"] = list(activities)
        self._models.clear()
        self._scalers.clear()
        for role, items in groups.items():
            X = self._extractor.transform(items)
            scaler = StandardScaler().fit(X)
            Xs = scaler.transform(X)
            model = IsolationForest(
                n_estimators=self.config.n_estimators,
                contamination=self.config.contamination,
                random_state=self.config.random_state,
            ).fit(Xs)
            self._models[role] = model
            self._scalers[role] = scaler
        return self

    # ---- inference ----

    def _model_for(self, role: Optional[str]) -> Tuple[IsolationForest, StandardScaler]:
        key = self._key(role)
        if key in self._models:
            return self._models[key], self._scalers[key]
        return self._models["_global"], self._scalers["_global"]

    def predict(self, activities: Sequence[UserActivity]) -> List[UserVerdict]:
        if not self.is_fitted:
            raise RuntimeError("detector is not fitted")
        if not activities:
            return []
        out: List[UserVerdict] = []
        names = self._extractor.feature_names()
        for a in activities:
            model, scaler = self._model_for(a.role)
            x = self._extractor.transform([a])
            xs = scaler.transform(x)
            raw = float(model.score_samples(xs)[0])
            score = _map_iforest_score(raw)
            # local explanation: compare row to scaler mean, rank by |z|
            row = x[0]
            mean = scaler.mean_
            std = np.sqrt(scaler.var_) + 1e-9
            z = (row - mean) / std
            top = sorted(
                [(names[i], float(z[i])) for i in range(len(names))],
                key=lambda kv: abs(kv[1]), reverse=True,
            )[:6]
            out.append(UserVerdict(
                user_id=a.user_id,
                date_key=a.date_key,
                role=a.role,
                score=score,
                suspicious=score >= self.config.suspicious_threshold,
                top_features=top,
            ))
        return out

    # ---- persistence ----

    def save(self, path: str) -> None:
        if not self.is_fitted:
            raise RuntimeError("cannot save unfitted detector")
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        payload = {
            "config": {
                "n_estimators": self.config.n_estimators,
                "contamination": self.config.contamination,
                "random_state": self.config.random_state,
                "suspicious_threshold": self.config.suspicious_threshold,
                "per_role": self.config.per_role,
            },
            "feature_names": self._extractor.feature_names(),
            "models": self._models,
            "scalers": self._scalers,
            "schema_version": 1,
        }
        joblib.dump(payload, path)

    @classmethod
    def load(cls, path: str) -> "InsiderThreatDetector":
        payload = joblib.load(path)
        if payload.get("schema_version") != 1:
            raise ValueError("unsupported schema version")
        cfg_d = payload["config"]
        cfg = DetectorConfig(
            n_estimators=int(cfg_d["n_estimators"]),
            contamination=float(cfg_d["contamination"]),
            random_state=int(cfg_d["random_state"]),
            suspicious_threshold=float(cfg_d["suspicious_threshold"]),
            per_role=bool(cfg_d["per_role"]),
        )
        det = cls(cfg)
        if payload["feature_names"] != det._extractor.feature_names():
            raise ValueError("persisted feature schema does not match library")
        det._models = payload["models"]
        det._scalers = payload["scalers"]
        return det
