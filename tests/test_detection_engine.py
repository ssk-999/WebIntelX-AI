from sqlalchemy import select

from app.database import database
from app.database.models import Account, Finding, Website
from app.detection.engine import RULE_ENGINE, count_findings, load_events, run_detection, run_detection_for_events
from tests.helpers import failures


def _site(db, domain):
    acc = Account(email=f"{domain}@x.com", password_hash="x")
    db.add(acc)
    db.flush()
    site = Website(account_id=acc.account_id, domain=domain)
    db.add(site)
    db.flush()
    return site


def _save(db, site, events):
    for e in events:
        e.website_id = site.website_id
    db.add_all(events)
    db.commit()
    return events


def test_run_is_idempotent_and_only_replaces_rule_engine_findings():
    with database.SessionLocal() as db:
        site = _site(db, "a.example.com")
        evs = _save(db, site, failures(12, users=list("abcdef")))
        foreign = Finding(event_id=evs[0].event_id, agent_name="investigation_agent", finding_type="hypothesis", confidence=0.5, evidence={})
        db.add(foreign)
        db.commit()
        r1 = run_detection(db, site.website_id)
        n1 = count_findings(db, site.website_id)
        r2 = run_detection(db, site.website_id)
        n2 = count_findings(db, site.website_id)
        assert r1.findings_created == 2 and r1.findings_replaced == 0           # R-AUTH-001 + R-AUTH-002
        assert r2.findings_created == 2 and r2.findings_replaced == 2 and n1 == n2 == 3   # 2 rule_engine + 1 foreign
        assert db.get(Finding, foreign.finding_id) is not None                  # other agents' findings untouched
        assert r1.suspicious_events == 12 and r1.finding_anchor_events == 1
        assert r1.by_rule == {"R-AUTH-001": 1, "R-AUTH-002": 1}


def test_findings_are_stored_in_prd_table_shape():
    with database.SessionLocal() as db:
        site = _site(db, "a.example.com")
        _save(db, site, failures(12))
        run_detection(db, site.website_id)
        f = db.scalars(select(Finding)).one()
        assert f.agent_name == RULE_ENGINE and f.finding_type == "auth_anomaly" and 0 < f.confidence <= 1
        assert f.evidence["rule_id"] == "R-AUTH-001" and f.created_at is not None


def test_website_isolation_in_engine():
    with database.SessionLocal() as db:
        a, b = _site(db, "a.example.com"), _site(db, "b.example.com")
        _save(db, a, failures(12, ip="203.0.113.10"))
        _save(db, b, failures(12, ip="203.0.113.10"))          # same IP on another customer's site
        run_detection(db, a.website_id)
        assert count_findings(db, a.website_id) >= 1 and count_findings(db, b.website_id) == 0
        # a burst split across two customers must not be merged into one
        c, d = _site(db, "c.example.com"), _site(db, "d.example.com")
        _save(db, c, failures(6, ip="198.51.100.5"))
        _save(db, d, failures(6, 1, ip="198.51.100.5"))
        run_detection(db, c.website_id)
        run_detection(db, d.website_id)
        assert count_findings(db, c.website_id) == 0 and count_findings(db, d.website_id) == 0
        assert {e.website_id for e in load_events(db, c.website_id)} == {c.website_id}


def test_incremental_run_sees_whole_source_history_and_ignores_others():
    with database.SessionLocal() as db:
        site = _site(db, "a.example.com")
        _save(db, site, failures(8, 0, ip="203.0.113.10"))                           # earlier batch: below threshold
        other = _save(db, site, failures(12, 0, ip="203.0.113.99", sid="other"))      # unrelated source, not in the new batch
        new = _save(db, site, failures(4, 20, ip="203.0.113.10"))                    # new batch completes the burst (12 total)
        res = run_detection_for_events(db, site.website_id, new)
        assert res.events_analyzed == 12 and res.findings_created == 1
        anchored = {f.event_id for f in db.scalars(select(Finding))}
        assert anchored == {new[-1].event_id}
        assert not anchored & {e.event_id for e in other}                            # other source untouched


def test_empty_and_no_events():
    with database.SessionLocal() as db:
        site = _site(db, "a.example.com")
        assert run_detection(db, site.website_id).to_dict()["findings_created"] == 0
        assert run_detection_for_events(db, site.website_id, []).events_analyzed == 0
