"""Structured, reproducible incident risk scoring (PRD section 17, FR-19, AC-16, section 35).

PRD: "Risk must be based on a documented scoring methodology rather than allowing an LLM to arbitrarily choose a
severity label", weights are "configuration-driven", "risk and confidence are separate concepts", and the UI
"should show the factors contributing to the score". Therefore:

  * The core (`score_incident`) is a pure function: same inputs + same config -> same output. No DB, no LLM, no network.
  * score = 100 * SUM(weight_i * value_i) / SUM(weight_i) with eight factors whose values in [0,1] come from documented
    formulas (config/risk.yaml). A factor without evidence adds 0 points; nothing ever subtracts, so absence of
    threat-intelligence (or ML) evidence is never turned into a claim of safety (PRD section 16 No-Evidence Rule).
  * confidence = evidence/support quality (signal diversity, finding confidence, correlation strength), reported separately.
    Both numbers are heuristics, NOT probabilities.
  * Each factor carries a plain-text basis built from recorded numbers and the finding ids it rests on (traceability).

PRD does not specify the following; using these implementation assumptions:
  * Severity levels are LOW / MEDIUM / HIGH / CRITICAL with configured minimum scores (the PRD only shows "HIGH").
  * "Asset context" is not provided to the platform, so asset impact is estimated from configured path-prefix rules.
  * Synthetic threat-intelligence results never raise real severity unless `threat_intel.count_synthetic` is set.
  * Scoring is on demand (like ML, correlation and enrichment); the orchestrator (M8) will call `run_risk`.
    A stored score is flagged `stale` on read when the incident's events or its threat-intel report changed afterwards.
"""
from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Sequence

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.correlation.engine import STAGE_ORDER, load_findings
from app.database.models import Correlation, Event, Incident
from app.risk.config import RiskConfig, get_risk_config

log = logging.getLogger("webintelx.risk")
_CHUNK = 500
METHOD_VERSION = 1
SCORE_NOTE = ("Risk is a deterministic, configuration-driven severity heuristic. Confidence reflects evidence quality. "
              "Neither is a probability, neither is proof of an attack, and no LLM chose them.")


# ------------------------------------------------------------------------------------------------ inputs
@dataclass(frozen=True)
class RiskFinding:
    finding_id: str
    agent_name: str
    finding_type: str
    category: str
    rule_id: str
    confidence: float
    anomaly_score: float | None = None


@dataclass
class RiskInputs:
    findings: Sequence[RiskFinding] = ()
    stages: dict[str, int] = field(default_factory=dict)          # stage -> number of events
    event_count: int = 0
    link_count: int = 0
    mean_link_strength: float | None = None
    affected_resources: Sequence[str] = ()
    truncated: bool = False                                        # stored links / event ids were capped
    threat_intel: dict[str, Any] | None = None                     # the stored M6 report, if any
    all_events_synthetic: bool = False


# -------------------------------------------------------------------------------------------- helpers
def _clamp(x: float) -> float:
    return max(0.0, min(1.0, x))


def _pct(v: float) -> str:
    return f"{v:.2f}"


def _factor(fid: str, label: str, weight: float, value: float, status: str, basis: str, *,
            finding_ids: Sequence[str] = (), stages: Sequence[str] = ()) -> dict[str, Any]:
    return {"factor": fid, "label": label, "weight": weight, "value": round(_clamp(value), 4), "status": status,
            "evidence_type": "derived_metric", "basis": basis, "finding_ids": list(finding_ids), "stages": list(stages)}


def _of_type(findings: Sequence[RiskFinding], ftype: str) -> list[RiskFinding]:
    return [f for f in findings if f.finding_type == ftype]


def _best(fs: Sequence[RiskFinding]) -> RiskFinding:
    return max(fs, key=lambda f: (f.confidence, f.rule_id, f.finding_id))


def _asset_value(path: str, cfg: RiskConfig) -> tuple[float, str | None]:
    """Longest configured prefix (segment boundary) wins; no match -> (default, None)."""
    p = (path or "").split("?", 1)[0].lower()
    best: tuple[int, float, str] | None = None
    for prefix, v in cfg["asset_impact"]["path_prefixes"].items():
        pl = prefix.lower().rstrip("/")
        if (p == pl or p.startswith(pl + "/")) and (best is None or len(pl) > best[0]):
            best = (len(pl), float(v), prefix)
    return (best[1], best[2]) if best else (float(cfg["asset_impact"]["default_value"]), None)


# ----------------------------------------------------------------------------------------------- factors
def _behavior(inp: RiskInputs, cfg: RiskConfig, w: float) -> dict[str, Any]:
    fs = [f for f in _of_type(inp.findings, "behavior_anomaly") if f.agent_name != "anomaly_model"]
    if not fs:
        return _factor("behavior", "Behavioural signals", w, 0, "not_observed", "No behaviour rule finding is attached to this incident.")
    b = _best(fs)
    return _factor("behavior", "Behavioural signals", w, b.confidence, "observed",
                   f"{len(fs)} behaviour rule finding(s); highest configured confidence {_pct(b.confidence)} ({b.rule_id or b.category}).",
                   finding_ids=[f.finding_id for f in fs])


def _anomaly(inp: RiskInputs, cfg: RiskConfig, w: float) -> dict[str, Any]:
    fs = [f for f in _of_type(inp.findings, "ml_anomaly") if f.anomaly_score is not None]
    if not fs:
        return _factor("anomaly", "ML session anomaly", w, 0, "not_observed",
                       "The anomaly model produced no finding for this incident (this does not mean the activity is benign).")
    top = max(fs, key=lambda f: (f.anomaly_score or 0.0, f.finding_id))
    floor = float(cfg["anomaly"]["score_floor"])
    v = _clamp((float(top.anomaly_score) - floor) / (1 - floor))
    return _factor("anomaly", "ML session anomaly", w, v, "observed",
                   f"Highest session anomaly score {_pct(float(top.anomaly_score))} (floor {floor}); value = (score - floor) / (1 - floor) = {_pct(v)}.",
                   finding_ids=[f.finding_id for f in fs])


def _attack(inp: RiskInputs, cfg: RiskConfig, w: float) -> dict[str, Any]:
    fs = _of_type(inp.findings, "attack_indicator")
    if not fs:
        return _factor("attack_indicators", "Attack-indicator evidence", w, 0, "not_observed", "No attack-indicator finding is attached to this incident.")
    b = _best(fs)
    cats = sorted({f.category for f in fs})
    bonus = float(cfg["attack_indicators"]["breadth_bonus"]) * (len(cats) - 1)
    v = _clamp(b.confidence + bonus)
    return _factor("attack_indicators", "Attack-indicator evidence", w, v, "observed",
                   f"{len(cats)} distinct attack-indicator categor{'y' if len(cats) == 1 else 'ies'}; highest confidence {_pct(b.confidence)} "
                   f"+ breadth bonus {_pct(bonus)} = {_pct(v)}.", finding_ids=[f.finding_id for f in fs])


def _auth(inp: RiskInputs, cfg: RiskConfig, w: float) -> dict[str, Any]:
    fs = _of_type(inp.findings, "auth_anomaly")
    if not fs:
        return _factor("authentication", "Authentication anomalies", w, 0, "not_observed", "No authentication-anomaly finding is attached to this incident.")
    vals = cfg["authentication"]["category_values"]
    dflt = float(cfg["authentication"]["default_value"])
    scored = [(float(vals.get(f.category, dflt)), f) for f in fs]
    v, top = max(scored, key=lambda t: (t[0], t[1].rule_id, t[1].finding_id))
    return _factor("authentication", "Authentication anomalies", w, v, "observed",
                   f"{len(fs)} authentication finding(s); strongest category '{top.category}' = {_pct(v)}.", finding_ids=[f.finding_id for f in fs])


def _sensitive(inp: RiskInputs, cfg: RiskConfig, w: float) -> dict[str, Any]:
    n = int(inp.stages.get("sensitive_access", 0))
    if n <= 0:
        return _factor("sensitive_endpoint", "Sensitive endpoint involvement", w, 0, "not_observed", "No sensitive endpoint access is part of this incident.")
    login = int(inp.stages.get("authentication_success", 0)) > 0
    c = cfg["sensitive_endpoint"]
    v = float(c["with_successful_login"] if login else c["accessed"])
    return _factor("sensitive_endpoint", "Sensitive endpoint involvement", w, v, "observed",
                   f"{n} sensitive endpoint event(s)" + (" and a successful login stage in the same incident" if login else "") + f" = {_pct(v)}.",
                   stages=["sensitive_access"] + (["authentication_success"] if login else []))


def _correlation(inp: RiskInputs, cfg: RiskConfig, w: float) -> dict[str, Any]:
    c = cfg["correlation"]
    present = [s for s in STAGE_ORDER if inp.stages.get(s, 0) > 0]
    stage_part = len(present) / len(STAGE_ORDER)
    size_part = _clamp(math.log1p(max(inp.event_count, 0)) / math.log1p(float(c["size_saturation_events"])))
    strength_part = _clamp(inp.mean_link_strength or 0.0)
    wt = float(c["stage_weight"]) + float(c["size_weight"]) + float(c["strength_weight"])
    v = (float(c["stage_weight"]) * stage_part + float(c["size_weight"]) * size_part + float(c["strength_weight"]) * strength_part) / wt
    status = "observed" if inp.event_count > 0 else "not_observed"
    return _factor("correlation", "Correlated events", w, v, status,
                   f"{len(present)}/{len(STAGE_ORDER)} attack-chain stages ({_pct(stage_part)}), {inp.event_count} correlated event(s) "
                   f"({_pct(size_part)}), mean relationship strength {_pct(strength_part)} over {inp.link_count} link(s) = {_pct(v)}.",
                   stages=present)


def _asset(inp: RiskInputs, cfg: RiskConfig, w: float) -> dict[str, Any]:
    res = [r for r in inp.affected_resources if r]
    if not res:
        return _factor("asset_impact", "Potential asset impact", w, 0, "not_observed", "No affected resource is recorded for this incident.")
    scored = [(_asset_value(r, cfg), r) for r in res]
    (v, rule), top = max(scored, key=lambda t: (t[0][0], t[1]))
    how = f"configured rule '{rule}'" if rule else "the default value (no configured rule matched)"
    return _factor("asset_impact", "Potential asset impact", w, v, "observed",
                   f"Highest-impact affected resource {top} via {how} = {_pct(v)}. Estimated from path rules; no asset inventory is available.")


def _threat_intel(inp: RiskInputs, cfg: RiskConfig, w: float) -> dict[str, Any]:
    label = "Threat-intelligence evidence"
    ti = inp.threat_intel
    if not isinstance(ti, dict) or ti.get("status") in (None, "not_run", "disabled", "error"):
        return _factor("threat_intel", label, w, 0, "not_assessed",
                       "Threat-intelligence enrichment has not been run for this incident. This adds no points and is not a claim of safety.")
    c = cfg["threat_intel"]
    ev = [r for r in ti.get("results", []) if r.get("status") == "evidence_found" and r.get("indicator_type") in ("ip", "domain", "cve")]
    real = [r for r in ev if not r.get("synthetic")]
    synth = [r for r in ev if r.get("synthetic")]
    used = real + (synth if c["count_synthetic"] else [])
    if not used:
        extra = f" {len(synth)} SYNTHETIC demo result(s) were excluded from the score." if synth else ""
        return _factor("threat_intel", label, w, 0, "excluded" if synth else "no_evidence",
                       "No usable threat-intelligence evidence was found for this incident." + extra +
                       " This adds no points and is not a claim of safety or maliciousness.")
    v = _clamp(float(c["first_evidence"]) + float(c["each_additional"]) * (len(used) - 1))
    return _factor("threat_intel", label, w, v, "observed",
                   f"{len(used)} real evidence result(s) from threat-intelligence providers = {_pct(v)} "
                   f"(first {c['first_evidence']}, +{c['each_additional']} each additional). MITRE ATT&CK mappings are context and are not counted.")


# ---------------------------------------------------------------------------------------------- confidence
def _confidence(inp: RiskInputs, cfg: RiskConfig, ti_used: bool) -> tuple[float, dict[str, Any]]:
    c = cfg["confidence"]
    kinds = {f.finding_type for f in inp.findings if f.finding_type in ("auth_anomaly", "behavior_anomaly", "attack_indicator", "ml_anomaly")}
    n_kinds = len(kinds) + (1 if ti_used else 0)
    diversity = _clamp(n_kinds / float(c["diversity_saturation"]))
    top = sorted((f.confidence for f in inp.findings), reverse=True)[: int(c["top_findings"])]
    fconf = _clamp(sum(top) / len(top)) if top else 0.0
    strength = _clamp(inp.mean_link_strength or 0.0)
    w = c["weights"]
    wt = float(sum(w.values()))
    raw = (float(w["signal_diversity"]) * diversity + float(w["finding_confidence"]) * fconf + float(w["correlation_strength"]) * strength) / wt
    penalty = float(c["truncation_penalty"]) if inp.truncated else 0.0
    val = round(_clamp(raw - penalty), 2)
    return val, {"signal_diversity": {"value": round(diversity, 4), "distinct_signal_kinds": n_kinds, "weight": w["signal_diversity"]},
                 "finding_confidence": {"value": round(fconf, 4), "findings_used": len(top), "weight": w["finding_confidence"]},
                 "correlation_strength": {"value": round(strength, 4), "weight": w["correlation_strength"]},
                 "truncation_penalty": penalty,
                 "note": "Evidence-support index in [0,1]: signal diversity, rule/model confidence (configured weights) and relationship strength. Not a probability."}


def _level(score: float, cfg: RiskConfig) -> str:
    lv = cfg["levels"]
    return "CRITICAL" if score >= lv["critical"] else "HIGH" if score >= lv["high"] else "MEDIUM" if score >= lv["medium"] else "LOW"


def _gaps(inp: RiskInputs, factors: dict[str, dict], cfg: RiskConfig) -> list[dict[str, str]]:
    g: list[dict[str, str]] = []
    ti = factors["threat_intel"]
    if ti["status"] == "not_assessed":
        g.append({"gap": "threat_intel_not_run", "text": "Threat-intelligence enrichment has not been run; no external evidence is available."})
    elif ti["status"] in ("no_evidence", "excluded"):
        g.append({"gap": "no_threat_intel_evidence", "text": "No usable threat-intelligence evidence was found. Absence of evidence is not a claim of safety or maliciousness."})
    if factors["anomaly"]["status"] == "not_observed":
        g.append({"gap": "no_ml_anomaly", "text": "The session anomaly model produced no finding; this does not mean the activity is benign."})
    g.append({"gap": "no_asset_context", "text": "No asset inventory or business-impact data is provided to the platform; asset impact is estimated from configured path rules."})
    if inp.truncated:
        g.append({"gap": "truncated_evidence", "text": "Stored links or event ids were capped, so part of the incident evidence is not reflected in the score."})
    if inp.all_events_synthetic:
        g.append({"gap": "synthetic_data", "text": "Every event in this incident is SYNTHETIC demo data; the score illustrates the method, not a real-world assessment."})
    return g


# ---------------------------------------------------------------------------------------------------- core
def score_incident(inp: RiskInputs, cfg: RiskConfig | None = None) -> dict[str, Any]:
    """Pure, deterministic scoring. Returns the structured risk object stored under `incident.details["risk"]`."""
    cfg = cfg or get_risk_config()
    wts = cfg["weights"]
    w = lambda k: float(wts.get(k, 0))  # noqa: E731
    factors = {f["factor"]: f for f in (
        _behavior(inp, cfg, w("behavior")), _anomaly(inp, cfg, w("anomaly")), _attack(inp, cfg, w("attack_indicators")),
        _auth(inp, cfg, w("authentication")), _sensitive(inp, cfg, w("sensitive_endpoint")),
        _correlation(inp, cfg, w("correlation")), _asset(inp, cfg, w("asset_impact")), _threat_intel(inp, cfg, w("threat_intel")))}
    total_w = sum(f["weight"] for f in factors.values())
    for f in factors.values():
        f["points"] = round(100.0 * f["weight"] * f["value"] / total_w, 2)
    score = round(100.0 * sum(f["weight"] * f["value"] for f in factors.values()) / total_w, 1)
    confidence, conf_parts = _confidence(inp, cfg, factors["threat_intel"]["status"] == "observed")
    ordered = sorted(factors.values(), key=lambda f: (-f["points"], f["factor"]))
    top_fs = sorted(inp.findings, key=lambda f: (-f.confidence, f.finding_id))[:10]
    return {
        "basis": "config_driven_scoring", "method_version": METHOD_VERSION, "risk_level": _level(score, cfg), "risk_score": score,
        "confidence": confidence, "confidence_components": conf_parts,
        "formula": "score = 100 * SUM(weight_i * value_i) / SUM(weight_i); factors without evidence add 0 points and never subtract",
        "factors": ordered, "max_points": 100,
        "evidence_gaps": _gaps(inp, factors, cfg),
        "supporting_findings": [{"finding_id": f.finding_id, "agent_name": f.agent_name, "category": f.category, "rule_id": f.rule_id,
                                 "confidence": round(f.confidence, 4)} for f in top_fs],
        "inputs": {"event_count": inp.event_count, "link_count": inp.link_count,
                   "mean_link_strength": None if inp.mean_link_strength is None else round(inp.mean_link_strength, 4),
                   "stages": [s for s in STAGE_ORDER if inp.stages.get(s, 0) > 0], "affected_resources": list(inp.affected_resources)[:10]},
        "contains_synthetic_data": bool(inp.all_events_synthetic),
        "config": {"version": cfg["version"], "fingerprint": cfg.fingerprint, "status": cfg.status,
                   "weights": dict(wts), "levels": dict(cfg["levels"])},
        "note": SCORE_NOTE,
    }


# ------------------------------------------------------------------------------------------------- DB layer
def _num(x: Any) -> float | None:
    return float(x) if isinstance(x, (int, float)) and not isinstance(x, bool) else None


def gather_inputs(db: Session, inc: Incident) -> RiskInputs:
    d = inc.details or {}
    ids = list(d.get("event_ids") or [])
    findings: list[RiskFinding] = []
    for f in load_findings(db, inc.website_id, ids):
        ev = f.evidence or {}
        findings.append(RiskFinding(f.finding_id, f.agent_name, f.finding_type, str(ev.get("category") or f.finding_type),
                                    str(ev.get("rule_id") or ""), float(f.confidence or 0.0),
                                    _num((ev.get("derived_metrics") or {}).get("anomaly_score"))))
    link_n, mean_s = db.execute(select(func.count(Correlation.correlation_id), func.avg(Correlation.strength))
                                .where(Correlation.website_id == inc.website_id, Correlation.incident_id == inc.incident_id)).one()
    non_synth = 0
    for i in range(0, len(ids), _CHUNK):
        non_synth += db.scalar(select(func.count(Event.event_id)).where(Event.website_id == inc.website_id, Event.event_id.in_(ids[i:i + _CHUNK]),
                                                                          Event.is_synthetic.is_(False))) or 0
    stages = {s: int((v or {}).get("event_count") or 0) for s, v in (d.get("stages") or {}).items()}
    ti = d.get("threat_intel")
    return RiskInputs(findings=findings, stages=stages, event_count=int(d.get("event_count") or len(ids)), link_count=int(link_n or 0),
                      mean_link_strength=None if mean_s is None else float(mean_s), affected_resources=list(d.get("affected_resources") or []),
                      truncated=bool(d.get("links_truncated") or d.get("event_ids_truncated")),
                      threat_intel=ti if isinstance(ti, dict) else None, all_events_synthetic=bool(ids) and non_synth == 0)


def run_risk(db: Session, incident: Incident, *, cfg: RiskConfig | None = None) -> dict[str, Any]:
    """Score one incident and store it. Never raises. Does not change the incident status (lifecycle is a later milestone)."""
    cfg = cfg or get_risk_config()
    if not cfg["enabled"]:
        return {"status": "disabled", "incident_id": incident.incident_id, "notes": ["Risk scoring is disabled in configuration; nothing was written."]}
    try:
        inp = gather_inputs(db, incident)
        risk = score_incident(inp, cfg)
        ti = inp.threat_intel or {}
        risk.update({"status": "ok", "scored_at": datetime.now(timezone.utc).isoformat(), "scored_event_count": inp.event_count,
                     "scored_threat_intel_at": ti.get("retrieved_at")})
        incident.risk_level, incident.risk_score, incident.confidence = risk["risk_level"], risk["risk_score"], risk["confidence"]
        incident.details = {**(incident.details or {}), "risk": risk}
        db.commit()
        log.info("risk for %s: %s %.1f confidence %.2f", incident.incident_id, risk["risk_level"], risk["risk_score"], risk["confidence"])
        return {"incident_id": incident.incident_id, **risk, "stale": False, "stale_reasons": []}
    except Exception as exc:  # never fail the investigation
        db.rollback()
        log.error("risk scoring failed for %s: %s", incident.incident_id, type(exc).__name__)
        return {"status": "error", "incident_id": incident.incident_id,
                "notes": [f"Risk scoring failed ({type(exc).__name__}); nothing was written."]}


def stored_risk(incident: Incident) -> dict[str, Any]:
    """The stored result plus a `stale` flag when the inputs changed after scoring."""
    d = incident.details or {}
    r = d.get("risk")
    if not isinstance(r, dict):
        return {"incident_id": incident.incident_id, "status": "not_run", "notes": ["Risk has not been scored for this incident."]}
    reasons: list[str] = []
    if r.get("scored_event_count") != int(d.get("event_count") or 0):
        reasons.append("The incident's correlated events changed after it was scored.")
    if r.get("scored_threat_intel_at") != (d.get("threat_intel") or {}).get("retrieved_at"):
        reasons.append("The incident's threat-intelligence report changed after it was scored.")
    return {"incident_id": incident.incident_id, **r, "stale": bool(reasons), "stale_reasons": reasons}


def run_risk_for_website(db: Session, website_id: str, *, limit: int = 50, cfg: RiskConfig | None = None) -> dict[str, Any]:
    incs = list(db.scalars(select(Incident).where(Incident.website_id == website_id).order_by(Incident.created_at.desc()).limit(limit)))
    results = [run_risk(db, i, cfg=cfg) for i in incs]
    by_level: dict[str, int] = {}
    for r in results:
        if r.get("status") == "ok":
            by_level[r["risk_level"]] = by_level.get(r["risk_level"], 0) + 1
    return {"website_id": website_id, "incidents": len(results), "scored": sum(1 for r in results if r.get("status") == "ok"),
            "by_level": dict(sorted(by_level.items())),
            "high_risk": by_level.get("HIGH", 0) + by_level.get("CRITICAL", 0),
            "incidents_detail": sorted(({"incident_id": r["incident_id"], "status": r["status"], "risk_level": r.get("risk_level"),
                                         "risk_score": r.get("risk_score"), "confidence": r.get("confidence")} for r in results),
                                       key=lambda x: (-(x["risk_score"] or -1), x["incident_id"])),
            "note": "Counts describe THIS website's stored data only; they are not production performance claims."}
