"""Session feature matrix + robust baseline for the anomaly model (PRD section 11, FR-09/FR-10, Agent 2 input:
"session features, request rates, endpoint usage").

Pure numpy; no database, no network. Input is the derived `SessionContext` (app/pipeline/sessionization.py), so
the model only ever sees the minimised, masked, deterministic session summary - never raw events.

PRD does not specify the feature list; this is the implementation assumption:
  * Behavioural volume/rate/shape features only. Automation user-agent tokens and the webdriver flag are
    deliberately NOT features: they are already explicit rule indicators (R-BEH-002), and feeding them to the
    model would just echo the rules instead of adding an independent signal.
  * `direction` says which side of the baseline is unusual: "high" (more than normal) or "low" (less than
    normal, e.g. rapid page gaps / no interaction). Only the unusual side contributes to a deviation.
  * Undefined values (e.g. no page views -> no page gap) are NaN and imputed with the baseline median, i.e.
    "no evidence of deviation", never "deviant".
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Sequence

import numpy as np

MAD_TO_SIGMA = 1.4826     # makes MAD comparable to a standard deviation for roughly normal data
IQR_TO_SIGMA = 1.349


@dataclass(frozen=True)
class FeatureSpec:
    name: str
    direction: str        # "high" | "low"
    min_scale: float      # smallest scale used for deviations, so a near-constant feature (e.g. failed logins
                          # normally 0) does not turn a single unit of change into a huge z-score
    description: str


FEATURES: tuple[FeatureSpec, ...] = (
    FeatureSpec("event_count", "high", 1.0, "events recorded in the session"),
    FeatureSpec("distinct_paths", "high", 1.0, "distinct request paths"),
    FeatureSpec("login_failures", "high", 1.0, "failed login events"),
    FeatureSpec("distinct_failed_users", "high", 1.0, "distinct accounts that failed to log in"),
    FeatureSpec("sensitive_accesses", "high", 1.0, "requests to sensitive endpoints"),
    FeatureSpec("error_ratio", "high", 0.25, "share of events with an HTTP error status"),
    FeatureSpec("peak_requests_10s", "high", 1.0, "most requests inside any 10-second window"),
    FeatureSpec("requests_per_min", "high", 1.0, "average request rate over the session"),
    FeatureSpec("median_page_gap_s", "low", 1.0, "median seconds between page views"),
    FeatureSpec("interaction_per_page", "low", 1.0, "client interaction events per page view"),
)
FEATURE_NAMES: tuple[str, ...] = tuple(f.name for f in FEATURES)
_DIRECTION_SIGN = np.array([1.0 if f.direction == "high" else -1.0 for f in FEATURES])
_MIN_SCALE = np.array([f.min_scale for f in FEATURES])


def session_features(ctx: Any) -> dict[str, float | None]:
    """Feature values for one `SessionContext` (None = undefined for this session)."""
    n = max(ctx.event_count, 1)
    return {
        "event_count": float(ctx.event_count),
        "distinct_paths": float(ctx.distinct_paths),
        "login_failures": float(ctx.login_failures),
        "distinct_failed_users": float(ctx.distinct_failed_users),
        "sensitive_accesses": float(ctx.sensitive_accesses),
        "error_ratio": ctx.error_events / n,
        "peak_requests_10s": float(ctx.peak_requests_10s),
        "requests_per_min": None if ctx.requests_per_min is None else float(ctx.requests_per_min),
        "median_page_gap_s": None if ctx.median_page_gap_s is None else float(ctx.median_page_gap_s),
        "interaction_per_page": (ctx.interaction_total / ctx.page_views) if ctx.page_views else None,
    }


def build_matrix(sessions: Sequence[Any]) -> np.ndarray:
    """(n_sessions, n_features) float matrix in FEATURE_NAMES order; undefined values are NaN."""
    rows = []
    for s in sessions:
        feats = session_features(s)
        rows.append([np.nan if feats[name] is None else feats[name] for name in FEATURE_NAMES])
    return np.array(rows, dtype=float).reshape(len(rows), len(FEATURE_NAMES))


class Baseline:
    """Robust per-feature baseline (median + robust scale) fitted on a website's own sessions."""

    def __init__(self) -> None:
        self.median: np.ndarray | None = None
        self.scale: np.ndarray | None = None

    def fit(self, X: np.ndarray) -> "Baseline":
        if X.ndim != 2 or X.shape[0] == 0 or X.shape[1] != len(FEATURES):
            raise ValueError("expected a non-empty (n_sessions, n_features) matrix")
        med = np.zeros(X.shape[1])
        for j in range(X.shape[1]):
            col = X[:, j]
            col = col[~np.isnan(col)]
            med[j] = float(np.median(col)) if col.size else 0.0
        self.median = med
        Xi = self.impute(X)
        mad = np.median(np.abs(Xi - med), axis=0)
        q1, q3 = np.percentile(Xi, [25, 75], axis=0)
        self.scale = np.maximum.reduce([MAD_TO_SIGMA * mad, (q3 - q1) / IQR_TO_SIGMA, _MIN_SCALE])
        return self

    def _need_fit(self) -> None:
        if self.median is None or self.scale is None:
            raise RuntimeError("Baseline is not fitted")

    def impute(self, X: np.ndarray) -> np.ndarray:
        """Replace NaN with the baseline median (undefined -> no evidence of deviation)."""
        if self.median is None:
            raise RuntimeError("Baseline is not fitted")
        return np.where(np.isnan(X), self.median, X)

    def deviations(self, X: np.ndarray) -> np.ndarray:
        """Robust z-scores on the *unusual side only* (>= 0): 0 means 'not unusual in the flagged direction'."""
        self._need_fit()
        z = (self.impute(X) - self.median) / self.scale * _DIRECTION_SIGN
        return np.clip(z, 0.0, None)
