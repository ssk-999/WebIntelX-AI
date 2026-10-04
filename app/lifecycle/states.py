"""Incident lifecycle (PRD section 22, FR-23) and analyst decisions (PRD section 21, FR-22, AC-19, AC-20). PURE: no DB, no network, no LLM.

PRD section 22 draws:  DETECTED -> INVESTIGATING -> ANALYST DECISION {CONFIRMED | FALSE POSITIVE | NEEDS INVESTIGATION}
                       -> RESPONSE RECOMMENDED -> ACTION TAKEN -> RESOLVED
and says the MVP "may simplify the visible lifecycle while preserving these states in the data model". All eight states are kept here.

PRD does not specify the transition rules; using the following implementation assumptions:
  * "ANALYST DECISION" is a decision point, not a stored state: it is represented by its three outcomes.
  * An analyst may decide straight from DETECTED (the AI investigation is optional), and may revise a decision.
  * After RESPONSE_RECOMMENDED the analyst can record ACTION_TAKEN (done OUTSIDE the platform; this build executes nothing),
    RESOLVED (no action needed / rejected), or send it back to NEEDS_INVESTIGATION ("further investigate", PRD section 21).
  * RESOLVED can be reopened (-> INVESTIGATING). Every other jump is refused with a controlled error.
"""
from __future__ import annotations

import re
from typing import Mapping

DETECTED, INVESTIGATING = "DETECTED", "INVESTIGATING"
CONFIRMED, FALSE_POSITIVE, NEEDS_INVESTIGATION = "CONFIRMED", "FALSE_POSITIVE", "NEEDS_INVESTIGATION"
RESPONSE_RECOMMENDED, ACTION_TAKEN, RESOLVED = "RESPONSE_RECOMMENDED", "ACTION_TAKEN", "RESOLVED"

STATES = (DETECTED, INVESTIGATING, CONFIRMED, FALSE_POSITIVE, NEEDS_INVESTIGATION, RESPONSE_RECOMMENDED, ACTION_TAKEN, RESOLVED)
CLOSED_STATES = frozenset({RESOLVED, FALSE_POSITIVE})          # the dashboard (M9) already treats these as closed

TRANSITIONS: Mapping[str, frozenset[str]] = {
    DETECTED: frozenset({INVESTIGATING, CONFIRMED, FALSE_POSITIVE, NEEDS_INVESTIGATION}),
    INVESTIGATING: frozenset({CONFIRMED, FALSE_POSITIVE, NEEDS_INVESTIGATION}),
    NEEDS_INVESTIGATION: frozenset({INVESTIGATING, CONFIRMED, FALSE_POSITIVE}),
    CONFIRMED: frozenset({RESPONSE_RECOMMENDED, FALSE_POSITIVE, NEEDS_INVESTIGATION}),
    FALSE_POSITIVE: frozenset({RESOLVED, CONFIRMED, NEEDS_INVESTIGATION}),
    RESPONSE_RECOMMENDED: frozenset({ACTION_TAKEN, RESOLVED, NEEDS_INVESTIGATION}),
    ACTION_TAKEN: frozenset({RESOLVED}),
    RESOLVED: frozenset({INVESTIGATING}),
}

# PRD section 21 MVP feedback: "True Positive / Confirmed", "False Positive", "Needs Investigation" (+ optional comment).
DECISIONS = (CONFIRMED, FALSE_POSITIVE, NEEDS_INVESTIGATION)
_DECISION_ALIASES = {"confirmed": CONFIRMED, "true_positive": CONFIRMED, "true positive": CONFIRMED, "tp": CONFIRMED,
                     "false_positive": FALSE_POSITIVE, "false positive": FALSE_POSITIVE, "fp": FALSE_POSITIVE,
                     "needs_investigation": NEEDS_INVESTIGATION, "needs investigation": NEEDS_INVESTIGATION,
                     "further_investigation": NEEDS_INVESTIGATION, "investigate_further": NEEDS_INVESTIGATION}

# PRD section 21: the analyst can "Accept / Reject / Further Investigate" a recommended response before any action.
RECOMMENDATION_DECISIONS = {"accept": "accepted", "accepted": "accepted", "reject": "rejected", "rejected": "rejected",
                            "further_investigation": "needs_investigation", "investigate_further": "needs_investigation",
                            "needs_investigation": "needs_investigation"}

# Alert status follows the lifecycle (M8 left alert status at "open": "acknowledgement ... arrives with the lifecycle in M10").
ALERT_STATUS = {DETECTED: "open", INVESTIGATING: None, NEEDS_INVESTIGATION: "acknowledged", CONFIRMED: "acknowledged",
                RESPONSE_RECOMMENDED: "acknowledged", ACTION_TAKEN: "acknowledged", FALSE_POSITIVE: "closed", RESOLVED: "closed"}

MAX_COMMENT_CHARS = 2000
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")      # keeps \t and \n


class LifecycleError(Exception):
    """Controlled, user-facing error (mapped to HTTP 409/422 by the API layer). Never carries secrets."""

    def __init__(self, code: str, message: str, status_code: int = 409, **extra):
        super().__init__(message)
        self.code, self.message, self.status_code, self.extra = code, message, status_code, extra


def normalise_state(value: str | None) -> str:
    v = re.sub(r"[\s-]+", "_", (value or "").strip()).upper()
    if v not in STATES:
        raise LifecycleError("invalid_status", f"Unknown status. Allowed: {', '.join(STATES)}.", 422)
    return v


def normalise_decision(value: str | None) -> str:
    v = (value or "").strip().lower().replace("-", "_")
    out = _DECISION_ALIASES.get(v) or _DECISION_ALIASES.get(v.replace("_", " "))
    if out is None:
        raise LifecycleError("invalid_decision", "Unknown decision. Allowed: confirmed (true_positive), false_positive, needs_investigation.", 422)
    return out


def normalise_recommendation_decision(value: str | None) -> str:
    out = RECOMMENDATION_DECISIONS.get((value or "").strip().lower().replace("-", "_"))
    if out is None:
        raise LifecycleError("invalid_decision", "Unknown decision. Allowed: accept, reject, further_investigation.", 422)
    return out


def clean_comment(value: str | None) -> str | None:
    """Control characters stripped, trimmed, length-limited. Stored as plain text; every renderer must escape it."""
    if value is None:
        return None
    s = _CONTROL.sub("", str(value)).strip()
    if len(s) > MAX_COMMENT_CHARS:
        raise LifecycleError("comment_too_long", f"The comment is limited to {MAX_COMMENT_CHARS} characters.", 422)
    return s or None


def allowed_next(current: str | None) -> list[str]:
    cur = (current or DETECTED).upper()
    return [s for s in STATES if s in TRANSITIONS.get(cur, frozenset())]


def check_transition(current: str | None, new: str) -> None:
    cur = (current or DETECTED).upper()
    if new not in TRANSITIONS.get(cur, frozenset()):
        raise LifecycleError("invalid_transition", f"An incident in {cur} cannot move to {new}. Allowed next states: {', '.join(allowed_next(cur)) or 'none'}.",
                             409, current=cur, requested=new, allowed=allowed_next(cur))


def alert_status_for(new_state: str, current_alert_status: str | None) -> str | None:
    mapped = ALERT_STATUS.get(new_state)
    if mapped is None:                                           # INVESTIGATING: reopen a closed alert, otherwise leave it as it is
        return "open" if current_alert_status == "closed" else current_alert_status
    return mapped


def public_config() -> dict:
    return {"states": list(STATES), "closed_states": sorted(CLOSED_STATES),
            "transitions": {s: [t for t in STATES if t in TRANSITIONS[s]] for s in STATES},
            "analyst_decisions": list(DECISIONS), "decision_aliases": sorted(_DECISION_ALIASES),
            "recommendation_decisions": sorted(set(RECOMMENDATION_DECISIONS.values())),
            "notes": ["ACTION_TAKEN only records that a human took an action outside this platform; the platform executes nothing.",
                      "Recording ACTION_TAKEN requires a comment describing the action (audit trail).",
                      "A CONFIRMED decision moves the incident on to RESPONSE_RECOMMENDED automatically when AI recommendations exist."]}
