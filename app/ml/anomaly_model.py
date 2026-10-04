"""Session anomaly detection (PRD FR-10, AC-07, Agent 2 inputs/outputs; section 27 'ML model: numerical anomaly
detection - deterministic and reproducible statistical signal').

Method (PRD names Isolation Forest / scikit-learn):
  1. Sessions are derived from events (sessionisation) and summarised into a small behavioural feature vector.
  2. An Isolation Forest is fitted on THIS website's own sessions in the window (fixed random_state -> same
     input gives the same output). No model file is persisted/pickled: nothing to tamper with, nothing stale.
  3. A session is reported only when two independent signals agree:
       - anomaly_score >= score_threshold                  (multivariate rarity)
       - max robust deviation >= min_deviation_z           (at least one feature is materially unusual)
     The deviations are also the explanation: they list WHICH features are unusual and by how much.

What this is NOT (and the output says so): the score is relative to the site's own baseline, it is not a
probability of attack, and the baseline can contain attack sessions. Low-volume attacks (e.g. a handful of
injection requests) are usually not behaviourally unusual at session level; they are covered by the
attack-indicator rules and, later, correlation.

Failure handling (PRD failure-handling rules): this module never raises. If the model cannot run (disabled,
too few sessions, scikit-learn missing, unexpected error) the report carries a `status` and no findings, and
deterministic rule detection is unaffected.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

import numpy as np

from app.detection.rules import MAX_EVIDENCE_IDS, FindingDraft
from app.ml.config import AnomalyConfig, get_anomaly_config
from app.ml.preprocessing import FEATURE_NAMES, FEATURES, Baseline, build_matrix, session_features
from app.pipeline.sessionization import sessionize

log = logging.getLogger("webintelx.ml")

AGENT_NAME = "anomaly_model"            # findings.agent_name (CrewAI agents write under their own names later)
FINDING_TYPE = "ml_anomaly"
RULE_ID = "M-ANOM-001"
RULE_TITLE = "Session behaviour anomaly (Isolation Forest)"
CATEGORY = "ml_session_anomaly"
_MIN_SESSIONS_HARD = 2                  # IsolationForest cannot be fitted on fewer than this


class ModelUnavailable(RuntimeError):
    pass


def _load_isolation_forest():
    """Isolated import so a missing scikit-learn degrades gracefully (and is testable)."""
    try:
        from sklearn.ensemble import IsolationForest
    except ImportError as exc:  # pragma: no cover - exercised via mock in tests
        raise ModelUnavailable("scikit-learn is not installed") from exc
    return IsolationForest


@dataclass
class SessionScore:
    key: str
    anomaly_score: float
    max_deviation_z: float
    flagged: bool
    deviations: list[dict[str, Any]]      # notable features, strongest first
    event_count: int

    def to_dict(self) -> dict[str, Any]:
        return {"session_key": self.key, "anomaly_score": round(self.anomaly_score, 4),
                "max_deviation_z": round(self.max_deviation_z, 2), "flagged": self.flagged,
                "event_count": self.event_count, "notable_deviations": self.deviations}


@dataclass
class AnomalyReport:
    status: str                           # ok | disabled | insufficient_baseline | model_unavailable | error
    error: str | None = None
    sessions_analyzed: int = 0
    training_sessions: int = 0
    scores: list[SessionScore] = field(default_factory=list)       # every analysed session, highest score first
    drafts: list[FindingDraft] = field(default_factory=list)       # one per flagged session
    model: dict[str, Any] = field(default_factory=dict)
    findings_created: int = 0             # filled by the persistence layer (app/ml/engine.py)
    findings_replaced: int = 0

    @property
    def flagged_sessions(self) -> list[str]:
        return [s.key for s in self.scores if s.flagged]

    def to_dict(self, top_n: int = 10) -> dict[str, Any]:
        return {
            "status": self.status, "error": self.error, "sessions_analyzed": self.sessions_analyzed,
            "training_sessions": self.training_sessions, "flagged_sessions": len(self.drafts),
            "findings_created": self.findings_created, "findings_replaced": self.findings_replaced,
            "model": self.model,
            "top_scored_sessions": [s.to_dict() for s in self.scores[:top_n]],
            "note": ("anomaly_score is relative to this website's own recent sessions; it is not a probability of attack. "
                     "A flag means 'statistically unusual', which can also be legitimate."),
        }


# ------------------------------------------------------------------------------------------- helpers
def _fmt(x: float) -> str:
    return f"{x:.0f}" if abs(x - round(x)) < 1e-9 else f"{x:.2f}"


def confidence_for(score: float, cfg: AnomalyConfig) -> float:
    """Configured evidence weight: threshold -> confidence.min, score 1.0 -> confidence.max. Not a probability."""
    thr, lo, hi = cfg["score_threshold"], cfg["confidence"]["min"], cfg["confidence"]["max"]
    frac = min(max((score - thr) / (1.0 - thr), 0.0), 1.0)
    return round(lo + frac * (hi - lo), 3)


def _notable(z_row: np.ndarray, values: dict[str, float | None], baseline: Baseline, cfg: AnomalyConfig) -> list[dict[str, Any]]:
    out = []
    for j, spec in enumerate(FEATURES):
        z = float(z_row[j])
        if z >= cfg["notable_feature_z"]:
            v = values[spec.name]
            out.append({
                "feature": spec.name, "description": spec.description, "direction": spec.direction,
                "value": None if v is None else round(v, 3),
                "baseline_median": round(float(baseline.median[j]), 3),
                "deviation_z": round(z, 2),
            })
    out.sort(key=lambda d: (-d["deviation_z"], d["feature"]))
    return out[: int(cfg["max_notable_features"])]


def _interpretation(score: float, n_train: int, devs: list[dict[str, Any]]) -> str:
    text = (f"This session's behaviour is statistically unusual compared with this website's own baseline of "
            f"{n_train} sessions (anomaly score {score:.2f}).")
    if devs:
        d = devs[0]
        side = "above" if d["direction"] == "high" else "below"
        text += (f" Strongest deviation: {d['feature']} = {_fmt(d['value'] if d['value'] is not None else 0)}, about "
                 f"{_fmt(d['deviation_z'])} robust deviations {side} the baseline median of {_fmt(d['baseline_median'])}.")
    return text + " This indicates unusual behaviour only; on its own it does not show that an attack occurred."


def _draft(ctx: Any, score: float, z_max: float, devs: list[dict[str, Any]], values: dict[str, float | None],
           n_train: int, cfg: AnomalyConfig, model_info: dict[str, Any]) -> FindingDraft:
    ids = list(ctx.event_ids)
    evidence = {
        "rule_id": RULE_ID, "rule_title": RULE_TITLE, "category": CATEGORY,
        "observed": {
            "session_key": ctx.key, "session_inferred_from_ip": ctx.inferred, "event_count": ctx.event_count,
            "first_seen": ctx.first_seen.isoformat(), "last_seen": ctx.last_seen.isoformat(),
            "source_ips": ctx.source_ips[:5], "event_types": ctx.event_types,
        },
        "derived_metrics": {
            "anomaly_score": round(score, 4), "max_deviation_z": round(z_max, 2),
            "notable_deviations": devs,
            "feature_values": {k: (None if v is None else round(v, 3)) for k, v in values.items()},
            "model": model_info,
        },
        "interpretation": {"text": _interpretation(score, n_train, devs), "basis": "model_output_template"},
        "event_ids": ids[:MAX_EVIDENCE_IDS], "event_ids_truncated": len(ids) > MAX_EVIDENCE_IDS,
        "limitations": [
            "The anomaly score is relative to this website's own recent sessions; it is not a probability of attack.",
            "Statistically unusual behaviour can be legitimate (load tests, power users, mistyped passwords).",
            "The baseline is fitted on all sessions in the window and can itself contain malicious sessions.",
            "Session-level behaviour only: low-volume attacks may not be behaviourally unusual.",
        ],
        "thresholds": {"score_threshold": cfg["score_threshold"], "min_deviation_z": cfg["min_deviation_z"],
                       "notable_feature_z": cfg["notable_feature_z"]},
        "mitre_reference": None,
        "config_version": cfg["version"],
    }
    # Anchor on the session's first event (deterministic); all session events are cited as evidence.
    return FindingDraft(ids[0], FINDING_TYPE, confidence_for(score, cfg), evidence, RULE_ID)


# ---------------------------------------------------------------------------------------------- API
def analyze_sessions(sessions: Mapping[str, Any], cfg: AnomalyConfig | None = None) -> AnomalyReport:
    """Score every session and build findings for the flagged ones. Never raises."""
    cfg = cfg or get_anomaly_config()
    n = len(sessions)
    if not cfg["enabled"]:
        return AnomalyReport(status="disabled", sessions_analyzed=n)
    if n < max(int(cfg["min_training_sessions"]), _MIN_SESSIONS_HARD):
        return AnomalyReport(
            status="insufficient_baseline", sessions_analyzed=n,
            error=f"{n} sessions available; at least {cfg['min_training_sessions']} are needed to form a baseline")
    try:
        isolation_forest = _load_isolation_forest()
        keys = sorted(sessions)                      # fixed order -> reproducible with a fixed random_state
        ctxs = [sessions[k] for k in keys]
        X = build_matrix(ctxs)
        baseline = Baseline().fit(X)
        Xi = baseline.impute(X)
        m = cfg.model
        forest = isolation_forest(n_estimators=m["n_estimators"], max_samples=min(m["max_samples"], n),
                                  random_state=m["random_state"], contamination="auto")
        forest.fit(Xi)
        scores = -forest.score_samples(Xi)
        Z = baseline.deviations(X)
        model_info = {"type": "IsolationForest", "n_training_sessions": n, "n_estimators": m["n_estimators"],
                      "max_samples": min(m["max_samples"], n), "random_state": m["random_state"],
                      "features": list(FEATURE_NAMES), "trained_on": "this website's own sessions in the window"}

        report = AnomalyReport(status="ok", sessions_analyzed=n, training_sessions=n, model=model_info)
        for i, key in enumerate(keys):
            score, z_max = float(scores[i]), float(Z[i].max())
            flagged = score >= cfg["score_threshold"] and z_max >= cfg["min_deviation_z"]
            values = session_features(ctxs[i])
            devs = _notable(Z[i], values, baseline, cfg)
            report.scores.append(SessionScore(key, score, z_max, flagged, devs, ctxs[i].event_count))
            if flagged:
                report.drafts.append(_draft(ctxs[i], score, z_max, devs, values, n, cfg, model_info))
        report.scores.sort(key=lambda s: (-s.anomaly_score, s.key))
        report.drafts.sort(key=lambda d: (-d.evidence["derived_metrics"]["anomaly_score"], d.event_id))
        return report
    except ModelUnavailable as exc:
        log.error("anomaly model unavailable: %s", exc)
        return AnomalyReport(status="model_unavailable", sessions_analyzed=n, error=str(exc))
    except Exception as exc:  # noqa: BLE001 - must never break the caller (PRD failure handling)
        log.error("anomaly analysis failed: %s", type(exc).__name__)
        return AnomalyReport(status="error", sessions_analyzed=n, error=f"{type(exc).__name__}: {str(exc)[:200]}")


def analyze_events(events: Iterable[Any], cfg: AnomalyConfig | None = None) -> AnomalyReport:
    """Sessionise events (app/pipeline/sessionization.py) and analyse the resulting sessions."""
    return analyze_sessions(sessionize(events), cfg)
