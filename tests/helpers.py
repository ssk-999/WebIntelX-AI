"""Test helpers: build real (unsaved) Event rows through the REAL ingestion pipeline."""
from datetime import datetime, timedelta, timezone

from app.config import get_settings
from app.database.models import Website
from app.pipeline.pipeline import process_event

T0 = datetime(2026, 10, 3, 9, 0, 0, tzinfo=timezone.utc)
SITE = Website(website_id="web_t", account_id="acc_t", domain="t.example.com")
BROWSER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36"
HEADLESS = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/118.0.0.0 Safari/537.36"


def mk(event_type, t=0.0, *, ip="203.0.113.10", sid="s1", uid=None, ep=None, status=None, ua=BROWSER,
       attrs=None, source=None, method=None, website=SITE):
    """`t` = seconds after T0. Returns an unsaved Event (event_id assigned, features extracted, masked)."""
    raw = {"event_type": event_type, "timestamp": (T0 + timedelta(seconds=t)).isoformat(), "is_synthetic": True,
           "attributes": attrs or {}}
    if source:
        raw["source"] = source
    for k, v in (("source_ip", ip), ("session_id", sid), ("user_id", uid), ("endpoint", ep), ("status_code", status),
                 ("user_agent", ua), ("method", method)):
        if v is not None:
            raw[k] = v
    return process_event(raw, website, get_settings(), now=T0 + timedelta(hours=1))


def failures(n, start=0.0, step=1.0, *, ip="203.0.113.10", users=None, sid="s1"):
    return [mk("login_failure", start + i * step, ip=ip, sid=sid, uid=(users[i % len(users)] if users else "u-1"),
               ep="/api/login", status=401, source="auth", method="POST") for i in range(n)]


def rules_of(drafts):
    return sorted(d.rule_id for d in drafts)
