"""Parsing and grounding of LLM output (PRD sections 14, 19, 27, 39).

The LLM is an investigation *assistant*, not the source of truth (PRD section 27). Whatever it returns is parsed as JSON and
checked deterministically here:
  * claims must cite reference labels that exist in the evidence bundle; unsupported claims are DROPPED (PRD section 19);
  * citations to labels that do not exist are removed and counted (PRD section 39 "hallucination / invalid-evidence rate");
  * recommendations must use an allow-listed action, must cite evidence, and are always `requires_human_approval=True`,
    `status="proposed"`, `executed=False` - the model cannot change those fields (PRD section 21, AC-19);
  * overconfident wording is flagged, never rewritten.
Pure functions; no I/O.
"""
from __future__ import annotations

import json
import re
from typing import Any, Mapping, Sequence

from app.agents.evidence import EvidenceBundle

INVALID_OUTPUT = "invalid_output"
REJECTED_UNGROUNDED = "rejected_ungrounded"


class AgentOutputError(Exception):
    """Raised when model output cannot be used. `code` is one of INVALID_OUTPUT / REJECTED_UNGROUNDED."""

    def __init__(self, code: str, message: str, report: dict[str, Any] | None = None):
        super().__init__(message)
        self.code, self.message, self.report = code, message, report or {}


_FENCE = re.compile(r"^```(?:json)?\s*|\s*```$", re.IGNORECASE)


def extract_json(raw: Any) -> dict[str, Any]:
    """Parse the first JSON object in `raw` (tolerates code fences and surrounding prose). Raises AgentOutputError."""
    if isinstance(raw, Mapping):
        return dict(raw)
    text = _FENCE.sub("", str(raw or "").strip())
    if not text:
        raise AgentOutputError(INVALID_OUTPUT, "The model returned an empty response.")
    start = text.find("{")
    if start < 0:
        raise AgentOutputError(INVALID_OUTPUT, "The model response contained no JSON object.")
    try:
        obj, _ = json.JSONDecoder().raw_decode(text[start:])
    except ValueError as exc:
        raise AgentOutputError(INVALID_OUTPUT, f"The model response was not valid JSON ({exc.__class__.__name__}).") from exc
    if not isinstance(obj, dict):
        raise AgentOutputError(INVALID_OUTPUT, "The model response JSON was not an object.")
    return obj


_CTRL = re.compile(r"[\x00-\x1f\x7f]")
_WS = re.compile(r"\s+")


def _str(v: Any, n: int) -> str:
    """Model-authored text: control characters and angle brackets removed (it is rendered as plain text, never HTML), truncated."""
    if not isinstance(v, (str, int, float)) or isinstance(v, bool):
        return ""
    return _WS.sub(" ", _CTRL.sub(" ", str(v)).replace("<", "").replace(">", "")).strip()[:n]


def _as_list(v: Any) -> list[Any]:
    return v if isinstance(v, list) else []


def resolve_refs(raw_refs: Any, bundle: EvidenceBundle) -> tuple[list[str], int, list[str], list[str]]:
    """-> (valid labels, number of invalid labels removed, event ids, finding ids). Labels are matched exactly (case-sensitive)."""
    labels: list[str] = []
    invalid = 0
    for r in _as_list(raw_refs):
        if isinstance(r, str) and r.strip() in bundle.refs:
            if r.strip() not in labels:
                labels.append(r.strip())
        elif r is not None:
            invalid += 1
    event_ids: list[str] = []
    finding_ids: list[str] = []
    for lab in labels:
        ref = bundle.refs[lab]
        event_ids += [i for i in ref.get("event_ids") or [] if i not in event_ids]
        fid = ref.get("finding_id")
        finding_ids += [i for i in ([fid] if fid else []) + list(ref.get("finding_ids") or []) if i and i not in finding_ids]
    return labels, invalid, event_ids[:25], finding_ids[:25]


def overconfident_phrases(texts: Sequence[str], phrases: Sequence[str]) -> list[str]:
    blob = " ".join(texts).lower()
    return sorted({p for p in phrases if p.lower() in blob})


def _unit(v: Any) -> float | None:
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return None
    return max(0.0, min(1.0, float(v)))


def ground_investigation(obj: Mapping[str, Any], bundle: EvidenceBundle, cfg: Mapping[str, Any],
                         risk_confidence: float | None = None) -> dict[str, Any]:
    """Validate and ground the Investigation Agent output. Raises AgentOutputError(INVALID_OUTPUT | REJECTED_UNGROUNDED)."""
    lim = cfg["investigation"]
    h = obj.get("hypothesis")
    if not isinstance(h, Mapping) or not _str(h.get("statement"), 500):
        raise AgentOutputError(INVALID_OUTPUT, "The response had no hypothesis.statement.")
    invalid_total = 0
    h_labels, inv, h_events, h_findings = resolve_refs(h.get("refs"), bundle)
    invalid_total += inv

    kept: list[dict[str, Any]] = []
    received = dropped = 0
    for item in _as_list(obj.get("supporting_evidence")):
        if not isinstance(item, Mapping):
            continue
        received += 1
        claim = _str(item.get("claim"), 400)
        labels, inv, evs, fnds = resolve_refs(item.get("refs"), bundle)
        invalid_total += inv
        if not claim or not labels:          # PRD section 19: "Unsupported claims must be omitted."
            dropped += 1
            continue
        if len(kept) < lim["max_supporting_claims"]:
            kept.append({"evidence_type": "ai_inference", "claim": claim, "refs": labels, "event_ids": evs, "finding_ids": fnds})
    report = {"claims_received": received, "claims_kept": len(kept), "unsupported_claims_dropped": dropped,
              "invalid_refs_removed": invalid_total, "hypothesis_grounded": bool(h_labels)}
    if not h_labels:
        raise AgentOutputError(REJECTED_UNGROUNDED, "The hypothesis cited no evidence that exists in the evidence bundle; it was rejected.", report)
    if not kept:
        raise AgentOutputError(REJECTED_UNGROUNDED, "None of the supporting claims cited existing evidence; the investigation was rejected.", report)

    missing = []
    for m in _as_list(obj.get("missing_evidence"))[: lim["max_missing_evidence"]]:
        if isinstance(m, Mapping):
            desc = _str(m.get("description"), 300)
            if desc:
                missing.append({"evidence_type": "missing_evidence", "description": desc, "why_it_matters": _str(m.get("why_it_matters"), 300)})
        elif isinstance(m, str) and _str(m, 300):
            missing.append({"evidence_type": "missing_evidence", "description": _str(m, 300), "why_it_matters": ""})
    alts = [a for a in (_str(x, 300) for x in _as_list(obj.get("alternative_explanations"))[: lim["max_alternatives"]]) if a]

    model_conf = _unit(h.get("model_confidence"))
    conf, basis = model_conf, "AI self-assessment; not a probability"
    if model_conf is not None and risk_confidence is not None and model_conf > risk_confidence:
        conf, basis = float(risk_confidence), "AI self-assessment capped at the deterministic evidence confidence; not a probability"
    if conf is None:
        conf, basis = risk_confidence, "model gave no confidence; deterministic evidence confidence shown; not a probability"
    texts = [_str(h.get("statement"), 500)] + [k["claim"] for k in kept] + alts
    flags = overconfident_phrases(texts, cfg["guardrails"]["overconfident_phrases"])
    report["overconfident_language"] = flags
    return {
        "evidence_type": "ai_inference",
        "hypothesis": {"statement": _str(h.get("statement"), 500), "attack_category": _str(h.get("attack_category"), 80), "refs": h_labels,
                       "event_ids": h_events, "finding_ids": h_findings, "model_confidence": model_conf, "confidence": conf,
                       "confidence_basis": basis, "evidence_type": "ai_inference"},
        "supporting_evidence": kept, "missing_evidence": missing, "alternative_explanations": alts, "validation": report,
    }


def ground_recommendations(obj: Mapping[str, Any], bundle: EvidenceBundle, cfg: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the Response Agent output. Raises AgentOutputError(INVALID_OUTPUT) when nothing usable remains."""
    rcfg = cfg["response"]
    allowed = set(rcfg["allowed_actions"])
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    received = dropped = invalid_total = 0
    for item in _as_list(obj.get("recommendations")):
        if not isinstance(item, Mapping):
            continue
        received += 1
        action = _str(item.get("action"), 60).lower().replace(" ", "_").replace("-", "_")
        rationale = _str(item.get("rationale"), 400)
        labels, inv, evs, fnds = resolve_refs(item.get("refs"), bundle)
        invalid_total += inv
        if action not in allowed or not rationale or not labels or action in seen:
            dropped += 1
            continue
        seen.add(action)
        pr = item.get("priority")
        out.append({"action": action, "title": _str(item.get("title"), 120) or action.replace("_", " ").capitalize(), "rationale": rationale,
                    "priority": pr if isinstance(pr, int) and not isinstance(pr, bool) and 1 <= pr <= 3 else 2,
                    "refs": labels, "event_ids": evs, "finding_ids": fnds, "limitations": _str(item.get("limitations"), 300),
                    # Fixed by code, never by the model (PRD section 21 / AC-19):
                    "evidence_type": "recommendation", "requires_human_approval": True, "status": "proposed", "executed": False})
    out.sort(key=lambda r: (r["priority"], r["action"]))
    out = out[: rcfg["max_recommendations"]]
    report = {"recommendations_received": received, "recommendations_kept": len(out), "dropped": dropped, "invalid_refs_removed": invalid_total}
    if not out:
        raise AgentOutputError(INVALID_OUTPUT, "No recommendation used an allowed action with a rationale and existing evidence.", report)
    flags = overconfident_phrases([r["rationale"] for r in out], cfg["guardrails"]["overconfident_phrases"])
    report["overconfident_language"] = flags
    return {"evidence_type": "recommendation", "recommendations": out, "validation": report,
            "approval_note": "Recommendations only. Nothing was executed; every action requires analyst review and approval."}
