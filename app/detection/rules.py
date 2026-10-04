"""Deterministic detection rules (PRD sections 14-15, 17, 19, 35; FR-10/FR-11 rule part).

Pure functions over a list of events -> list[FindingDraft]. No database, no LLM, no network, so every
result is reproducible and unit-testable. Each finding separates (PRD section 19):
  observed          directly recorded facts (counts, ids, timestamps, matched signal names)
  derived_metrics   values calculated deterministically from those facts
  interpretation    rule-authored wording, always hedged; basis="rule_template" (NOT an LLM, NOT proof)
  limitations       what the rule cannot know
plus the event ids it rests on, the thresholds used (reproducibility) and an optional MITRE ATT&CK
reference that is context only (PRD section 16).

`confidence` is the configured evidence weight of the rule hit (config/detection.yaml), not a probability.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Any, Iterable, Sequence

from app.detection import patterns
from app.detection.config import DetectionConfig, get_detection_config
from app.pipeline.sessionization import peak_in_window, session_key

MAX_EVIDENCE_IDS = 500
MITRE_NOTE = "Reference context only; mapping a pattern to a technique is not proof the technique was used."


@dataclass(frozen=True)
class RuleMeta:
    rule_id: str
    title: str
    finding_type: str
    category: str
    description: str
    mitre: tuple[str, str] | None = None  # (technique id, name)


RULES: dict[str, RuleMeta] = {m.rule_id: m for m in [
    RuleMeta("R-AUTH-001", "Burst of failed logins", "auth_anomaly", "brute_force_indicator",
             "Many failed logins from one source in a short run.", ("T1110", "Brute Force")),
    RuleMeta("R-AUTH-002", "Failed logins across many accounts", "auth_anomaly", "multi_account_auth_failures",
             "A failed-login burst that targets many distinct accounts from one source.", ("T1110", "Brute Force")),
    RuleMeta("R-AUTH-003", "Successful login after failed-login burst", "auth_anomaly", "login_success_after_failure_burst",
             "A login succeeds from the same source shortly after a failed-login burst.", ("T1078", "Valid Accounts")),
    RuleMeta("R-BEH-001", "Abnormal request rate", "behavior_anomaly", "high_request_rate",
             "Request volume in a short window exceeds the configured limit for one session."),
    RuleMeta("R-BEH-002", "Automation indicators", "behavior_anomaly", "automation_indicator",
             "Automation user-agent token and/or browser webdriver flag observed."),
    RuleMeta("R-BEH-003", "Non-human navigation", "behavior_anomaly", "non_human_navigation",
             "Rapid page navigation with no recorded user interaction."),
    RuleMeta("R-BEH-004", "Reconnaissance path probing", "behavior_anomaly", "recon_path_probing",
             "One session requested several well-known administrative/discovery paths."),
    RuleMeta("R-ATK-001", "SQL injection indicators", "attack_indicator", "sql_injection_indicator",
             "Request target contains SQL-injection-like syntax.", ("T1190", "Exploit Public-Facing Application")),
    RuleMeta("R-ATK-002", "XSS indicators", "attack_indicator", "xss_indicator",
             "Request target contains cross-site-scripting-like markup.", ("T1190", "Exploit Public-Facing Application")),
    RuleMeta("R-ATK-003", "Path traversal indicators", "attack_indicator", "path_traversal_indicator",
             "Request target contains directory-traversal sequences or system-file names.", ("T1190", "Exploit Public-Facing Application")),
    RuleMeta("R-ATK-004", "SSRF indicators", "attack_indicator", "ssrf_indicator",
             "Query string points a URL parameter at an internal or metadata address.", ("T1190", "Exploit Public-Facing Application")),
    RuleMeta("R-ATK-005", "Multi-vector probing", "attack_indicator", "multi_vector_probing",
             "One source triggered several different attack-indicator categories in a short window."),
    RuleMeta("R-WAF-001", "WAF/security-control alert", "waf_signal", "waf_alert_observed",
             "A WAF or security control reported an alert (reported by the source, not verified here)."),
]}


@dataclass
class FindingDraft:
    event_id: str
    finding_type: str
    confidence: float
    evidence: dict[str, Any]
    rule_id: str = ""


# --------------------------------------------------------------------------------- helpers
def _entity(e) -> str | None:
    """Grouping key for per-source rules: IP (or privacy-safe representation), else session."""
    if e.source_ip:
        return e.source_ip
    return f"sid:{e.session_id}" if e.session_id else None


def _iso(dt) -> str:
    return dt.isoformat()


def _ids(events: Sequence) -> tuple[list[str], bool]:
    ids = [e.event_id for e in events]
    return ids[:MAX_EVIDENCE_IDS], len(ids) > MAX_EVIDENCE_IDS


def _draft(rule_id: str, anchor, confidence: float, cfg: DetectionConfig, *, observed: dict, derived: dict,
           interpretation: str, evidence_events: Sequence, limitations: list[str]) -> FindingDraft:
    meta = RULES[rule_id]
    ids, truncated = _ids(evidence_events)
    evidence: dict[str, Any] = {
        "rule_id": rule_id,
        "rule_title": meta.title,
        "category": meta.category,
        "observed": observed,
        "derived_metrics": derived,
        "interpretation": {"text": interpretation, "basis": "rule_template"},
        "event_ids": ids,
        "event_ids_truncated": truncated,
        "limitations": limitations,
        "thresholds": {k: v for k, v in cfg.rule(rule_id).items() if k not in ("enabled", "paths")},
        "mitre_reference": ({"technique_id": meta.mitre[0], "name": meta.mitre[1], "note": MITRE_NOTE} if meta.mitre else None),
        "config_version": cfg["version"],
    }
    return FindingDraft(anchor.event_id, meta.finding_type, round(min(max(confidence, 0.0), 1.0), 3), evidence, rule_id)


def _runs(events: Iterable, gap_s: float) -> list[list]:
    """Split time-sorted events (already one entity) into runs separated by gaps > gap_s."""
    runs: list[list] = []
    for e in events:
        if runs and (e.timestamp - runs[-1][-1].timestamp).total_seconds() <= gap_s:
            runs[-1].append(e)
        else:
            runs.append([e])
    return runs


def _failure_runs(events: Sequence, min_failures: int, gap_s: float) -> list[tuple[str, list]]:
    by_entity: dict[str, list] = defaultdict(list)
    for e in events:
        if e.event_type == "login_failure" and _entity(e):
            by_entity[_entity(e)].append(e)
    out = []
    for ent, evs in by_entity.items():
        for run in _runs(evs, gap_s):
            if len(run) >= min_failures:
                out.append((ent, run))
    return out


# --------------------------------------------------------------------------------- authentication
def rule_auth_burst(events, cfg) -> list[FindingDraft]:
    p = cfg.rule("R-AUTH-001")
    out = []
    for ent, run in _failure_runs(events, p["min_failures"], p["run_gap_s"]):
        n = len(run)
        dur = (run[-1].timestamp - run[0].timestamp).total_seconds()
        users = {e.user_id for e in run if e.user_id}
        conf = p["confidence_base"] + (p["confidence_max"] - p["confidence_base"]) * min(1.0, (n - p["min_failures"]) / (p["min_failures"] * 4))
        out.append(_draft(
            "R-AUTH-001", run[-1], conf, cfg,
            observed={"source": ent, "failed_login_count": n, "window_start": _iso(run[0].timestamp),
                      "window_end": _iso(run[-1].timestamp), "duration_s": round(dur, 3), "distinct_accounts_targeted": len(users)},
            derived={"failures_per_second": round(n / max(dur, 1.0), 2)},
            interpretation="The failed-login volume and rate are consistent with automated credential guessing (brute force, credential stuffing or password spraying). This is an indicator, not confirmation.",
            evidence_events=run,
            limitations=["Cannot tell a malicious actor from a misconfigured client or shared NAT address.",
                         "If IP_PRIVACY_MODE truncates addresses, unrelated users in one network may be grouped together."],
        ))
    return out


def rule_auth_multi_account(events, cfg) -> list[FindingDraft]:
    p = cfg.rule("R-AUTH-002")
    out = []
    for ent, run in _failure_runs(events, p["min_failures"], p["run_gap_s"]):
        users = {e.user_id for e in run if e.user_id}
        if len(users) < p["min_distinct_users"]:
            continue
        dur = (run[-1].timestamp - run[0].timestamp).total_seconds()
        out.append(_draft(
            "R-AUTH-002", run[-1], p["confidence"], cfg,
            observed={"source": ent, "failed_login_count": len(run), "distinct_accounts_targeted": len(users),
                      "duration_s": round(dur, 3)},
            derived={"failures_per_account": round(len(run) / len(users), 2)},
            interpretation="One source failing against many different accounts is consistent with credential stuffing or password spraying rather than one user mistyping a password.",
            evidence_events=run,
            limitations=["Account identifiers are those recorded by the auth source; shared service accounts or testing tools can look similar."],
        ))
    return out


def rule_login_success_after_burst(events, cfg) -> list[FindingDraft]:
    p, base = cfg.rule("R-AUTH-003"), cfg.rule("R-AUTH-001")   # burst definition always comes from R-AUTH-001 params
    bursts = _failure_runs(events, base["min_failures"], base["run_gap_s"])
    if not bursts:
        return []
    successes: dict[str, list] = defaultdict(list)
    for e in events:
        if e.event_type == "login_success" and _entity(e):
            successes[_entity(e)].append(e)
    out = []
    for ent, run in bursts:
        end = run[-1].timestamp
        users = {e.user_id for e in run if e.user_id}
        for s in successes.get(ent, []):
            delay = (s.timestamp - end).total_seconds()
            if not 0 < delay <= p["lookback_s"]:
                continue
            matched = bool(s.user_id and s.user_id in users)
            out.append(_draft(
                "R-AUTH-003", s, p["confidence_account_match"] if matched else p["confidence"], cfg,
                observed={"source": ent, "failed_login_count": len(run), "burst_end": _iso(end), "success_at": _iso(s.timestamp),
                          "account_was_targeted_in_burst": matched},
                derived={"seconds_after_burst": round(delay, 3)},
                interpretation=("A login succeeded from the same source shortly after the failed-login burst"
                                + (", for an account that was among those failing" if matched else "")
                                + ". This is consistent with possible account takeover; no independent confirmation of takeover exists in this evidence."),
                evidence_events=[*run, s],
                limitations=["The legitimate account owner could have succeeded from the same address (shared network).",
                             "Post-login behaviour is assessed by later correlation, not by this rule."],
            ))
    return out


# --------------------------------------------------------------------------------- behaviour
def _by_session(events) -> dict[str, list]:
    g: dict[str, list] = defaultdict(list)
    for e in events:
        g[session_key(e)[0]].append(e)
    return g


def rule_request_rate(events, cfg) -> list[FindingDraft]:
    p = cfg.rule("R-BEH-001")
    out = []
    for key, evs in _by_session(events).items():
        reqs = [e for e in evs if (e.features or {}).get("is_request_event")]
        times = [e.timestamp.timestamp() for e in reqs]
        count, end = peak_in_window(times, p["window_s"])
        if count < p["min_requests"]:
            continue
        window = reqs[end - count + 1: end + 1]
        out.append(_draft(
            "R-BEH-001", reqs[end], p["confidence"], cfg,
            observed={"session": key, "requests_in_peak_window": count, "window_s": p["window_s"],
                      "window_start": _iso(window[0].timestamp), "window_end": _iso(window[-1].timestamp),
                      "total_requests_in_session": len(reqs)},
            derived={"peak_requests_per_second": round(count / p["window_s"], 2), "limit": p["min_requests"]},
            interpretation="The request rate exceeds the configured limit for one session, which is consistent with automated crawling or scraping rather than human browsing.",
            evidence_events=window,
            limitations=["Legitimate crawlers, monitoring probes and API clients can exceed this limit; the limit is a heuristic, not a learned baseline (see the ML anomaly step)."],
        ))
    return out


def rule_automation(events, cfg) -> list[FindingDraft]:
    p = cfg.rule("R-BEH-002")
    out = []
    for key, evs in _by_session(events).items():
        hits, signals = [], set()
        for e in evs:
            f = e.features or {}
            sig = []
            if f.get("ua_class") in ("headless_browser", "automation_tool"):
                sig.append("automation_user_agent")
            if f.get("webdriver") is True:
                sig.append("navigator_webdriver_flag")
            if sig:
                hits.append(e)
                signals.update(sig)
        if not hits:
            continue
        anchor = hits[0]
        ua = ((anchor.processed_data or {}).get("user_agent") or "")[:200]
        conf = p["confidence_multi_signal"] if len(signals) >= 2 else p["confidence_one_signal"]
        out.append(_draft(
            "R-BEH-002", anchor, conf, cfg,
            observed={"session": key, "signals": sorted(signals), "user_agent_class": (anchor.features or {}).get("ua_class"),
                      "user_agent": ua, "events_with_signal": len(hits)},
            derived={"independent_signal_count": len(signals)},
            interpretation="The client identifies itself, or is flagged by the browser, as automated. Automation is not inherently malicious (testing, monitoring, accessibility tools).",
            evidence_events=hits,
            limitations=["User-Agent strings are client-supplied and can be spoofed; their absence proves nothing.",
                         "navigator.webdriver is only reported by SDK page views."],
        ))
    return out


def rule_non_human_navigation(events, cfg) -> list[FindingDraft]:
    p = cfg.rule("R-BEH-003")
    out = []
    for key, evs in _by_session(events).items():
        pvs = sorted((e for e in evs if e.event_type == "page_view"), key=lambda e: e.timestamp)
        if len(pvs) < p["min_page_views"]:
            continue
        interactions = sum((e.features or {}).get("interaction_total") or 0 for e in evs if e.event_type == "interaction")
        if interactions > 0:
            continue
        gaps = sorted((b.timestamp - a.timestamp).total_seconds() for a, b in zip(pvs, pvs[1:]))
        median = gaps[len(gaps) // 2] if len(gaps) % 2 else (gaps[len(gaps) // 2 - 1] + gaps[len(gaps) // 2]) / 2
        if median > p["max_median_gap_s"]:
            continue
        out.append(_draft(
            "R-BEH-003", pvs[-1], p["confidence"], cfg,
            observed={"session": key, "page_views": len(pvs), "interaction_signals_recorded": interactions},
            derived={"median_seconds_between_page_views": round(median, 3)},
            interpretation="Pages were requested in rapid succession with no recorded clicks, key presses, scrolling or mouse movement, which is atypical of a person browsing.",
            evidence_events=pvs,
            limitations=["Interaction counters come from the browser SDK; blocked or failed SDK interaction reporting would look the same.",
                         "Prefetching or very fast users can produce short gaps."],
        ))
    return out


def rule_recon_paths(events, cfg) -> list[FindingDraft]:
    p = cfg.rule("R-BEH-004")
    probes = [x.lower() for x in p["paths"]]
    out = []
    for key, evs in _by_session(events).items():
        matched: dict[str, list] = defaultdict(list)
        for e in evs:
            f = e.features or {}
            path = (f.get("path") or "").lower()
            if not f.get("is_request_event") or not path:
                continue
            for pr in probes:
                if path == pr or path.startswith(pr + "/"):
                    matched[pr].append(e)
                    break
        if len(matched) < p["min_distinct_paths"]:
            continue
        hits = sorted((e for v in matched.values() for e in v), key=lambda e: e.timestamp)
        out.append(_draft(
            "R-BEH-004", hits[-1], p["confidence"], cfg,
            observed={"session": key, "probe_paths_requested": sorted(matched), "requests": len(hits)},
            derived={"distinct_probe_paths": len(matched)},
            interpretation="One session requested several well-known administrative or discovery paths, which is consistent with reconnaissance.",
            evidence_events=hits,
            limitations=["Search-engine crawlers and uptime monitors legitimately request robots.txt, sitemap.xml and API docs.",
                         "Weak signal on its own; its value is as context for other findings."],
        ))
    return out


# --------------------------------------------------------------------------------- attack indicators
def rule_attack_patterns(events, cfg) -> list[FindingDraft]:
    out = []
    for e in events:
        if not e.endpoint:
            continue
        target = patterns.decode_target(e.endpoint)
        query = target.split("?", 1)[1] if "?" in target else ""
        for rule_id, (category, pats, scope) in patterns.CATEGORIES.items():
            if not cfg.enabled(rule_id):
                continue
            signals = patterns.match_signals(pats, target if scope == "target" else query)
            if not signals:
                continue
            base = cfg.rule(rule_id)["confidence"]
            out.append(_draft(
                rule_id, e, min(0.95, base + (0.1 if len(signals) > 1 else 0.0)), cfg,
                observed={"endpoint": e.endpoint[:300], "method": e.method, "status_code": e.status_code,
                          "source": e.source, "matched_signals": signals},
                derived={"matched_signal_count": len(signals)},
                interpretation=f"The request target contains syntax commonly associated with {RULES[rule_id].title.replace(' indicators', '')} probing. This shows the request looked like an attempt; it does not show the attempt succeeded.",
                evidence_events=[e],
                limitations=["Matched on the request path and query only; request bodies and headers are not inspected.",
                             "Security researchers, scanners and unusual-but-legitimate input can match these patterns."],
            ))
    return out


def rule_multi_vector(events, cfg, attack_drafts: Sequence[FindingDraft]) -> list[FindingDraft]:
    p = cfg.rule("R-ATK-005")
    cats: dict[str, list[str]] = defaultdict(list)
    for d in attack_drafts:
        if d.rule_id in patterns.CATEGORIES:
            cats[d.event_id].append(patterns.CATEGORIES[d.rule_id][0])
    if not cats:
        return []
    by_entity: dict[str, list] = defaultdict(list)
    for e in events:
        if e.event_id in cats and _entity(e):
            by_entity[_entity(e)].append(e)
    out = []
    for ent, evs in by_entity.items():
        evs.sort(key=lambda e: e.timestamp)
        lo, counter = 0, Counter()
        best: tuple[int, int, int, dict] | None = None        # (distinct categories, lo, hi, snapshot): widest window wins, earliest on ties
        for hi, e in enumerate(evs):
            counter.update(cats[e.event_id])
            while (e.timestamp - evs[lo].timestamp).total_seconds() > p["window_s"]:
                counter.subtract(cats[evs[lo].event_id])
                counter += Counter()          # drop zero/negative counts
                lo += 1
            if len(counter) >= p["min_categories"] and (best is None or len(counter) > best[0]):
                best = (len(counter), lo, hi, dict(counter))
        if best is None:
            continue
        n_cat, b_lo, b_hi, snap = best
        window = evs[b_lo: b_hi + 1]
        out.append(_draft(
            "R-ATK-005", evs[b_hi], p["confidence"], cfg,
            observed={"source": ent, "categories": dict(sorted(snap.items())), "indicator_events": len(window),
                      "window_start": _iso(window[0].timestamp), "window_end": _iso(window[-1].timestamp)},
            derived={"distinct_categories": n_cat, "window_limit_s": p["window_s"]},
            interpretation="One source triggered several different attack-indicator categories in a short period, which is consistent with automated vulnerability probing rather than a single odd request.",
            evidence_events=window,
            limitations=["Built only from other rule indicators; it inherits their limitations.",
                         "Authorised security scanners behave the same way."],
        ))
    return out


def rule_waf(events, cfg) -> list[FindingDraft]:
    p = cfg.rule("R-WAF-001")
    out = []
    for e in events:
        if e.event_type != "waf_alert":
            continue
        attrs = (e.processed_data or {}).get("attributes") or {}
        out.append(_draft(
            "R-WAF-001", e, p["confidence"], cfg,
            observed={"endpoint": (e.endpoint or "")[:300], "status_code": e.status_code, "waf_rule_name": attrs.get("rule_name"),
                      "waf_mode": attrs.get("mode"), "source": e.source},
            derived={},
            interpretation="A WAF or security control reported an alert for this request. The platform records the report; it has not verified the control's rule or verdict.",
            evidence_events=[e],
            limitations=["Reliability depends on the reporting control; detect-only mode means the request was not blocked."],
        ))
    return out


# --------------------------------------------------------------------------------- entry point
def evaluate(events: Sequence, cfg: DetectionConfig | None = None) -> list[FindingDraft]:
    """Run every enabled rule. `events` must carry `features` (see app/pipeline/features.py)."""
    cfg = cfg or get_detection_config()
    events = sorted(events, key=lambda e: (e.timestamp, e.event_id))
    drafts: list[FindingDraft] = []
    simple = [
        ("R-AUTH-001", rule_auth_burst), ("R-AUTH-002", rule_auth_multi_account), ("R-AUTH-003", rule_login_success_after_burst),
        ("R-BEH-001", rule_request_rate), ("R-BEH-002", rule_automation), ("R-BEH-003", rule_non_human_navigation),
        ("R-BEH-004", rule_recon_paths), ("R-WAF-001", rule_waf),
    ]
    for rule_id, fn in simple:
        if cfg.enabled(rule_id):
            drafts.extend(fn(events, cfg))
    attack = rule_attack_patterns(events, cfg)   # R-ATK-001..004 individually switchable inside
    drafts.extend(attack)
    if cfg.enabled("R-ATK-005"):
        drafts.extend(rule_multi_vector(events, cfg, attack))
    return drafts
