"""Deterministic SYNTHETIC demo data generator (PRD §10/§36).

Everything produced here is controlled sample data: fixed RNG seed, RFC 5737 documentation
IP ranges only (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), no real people or sites.
Every row carries `scenario` and a ground-truth `label` (for later precision/recall
evaluation, PRD §39). Those two columns are NEVER ingested; the loader strips them.

Regenerate:  python -m app.demo.generator
"""
from __future__ import annotations

import csv
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parents[2] / "data"
SEED = 42
BASE = datetime(2026, 10, 3, 9, 0, 0, tzinfo=timezone.utc)

COLUMNS = [
    "event_type", "source", "timestamp", "session_id", "user_id", "source_ip", "user_agent",
    "method", "endpoint", "status_code", "attributes", "is_synthetic", "scenario", "label",
]

BROWSER_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/118.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Mobile Safari/537.36",
]
HEADLESS_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/118.0.0.0 Safari/537.36"
SCRAPER_UA = "Scrapy/2.11.0 (+https://scrapy.org)"

PAGES = ["/", "/products", "/products/{p}", "/cart", "/about", "/contact", "/blog/{b}", "/pricing"]
ATTACKER_IP = "203.0.113.77"
SQLI_IP = "198.51.100.23"
BOT_IP = "203.0.113.140"
TARGET_ACCOUNT = "acct-4821"


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _row(t, event_type, source, ip, ua, scenario, label, *, sid=None, uid=None, method=None,
         endpoint=None, status=None, attrs=None) -> dict:
    return {
        "event_type": event_type, "source": source, "timestamp": _iso(t), "session_id": sid or "",
        "user_id": uid or "", "source_ip": ip, "user_agent": ua, "method": method or "",
        "endpoint": endpoint or "", "status_code": status if status is not None else "",
        "attributes": json.dumps(attrs or {}, sort_keys=True, separators=(",", ":")),
        "is_synthetic": "true", "scenario": scenario, "label": label,
    }


# --------------------------------------------------------------------------- normal traffic
def gen_normal(rng: random.Random, n_sessions: int = 560, window_s: int = 3600) -> list[dict]:
    rows: list[dict] = []
    pool = [f"192.0.2.{i}" for i in range(1, 255)] + [f"198.51.100.{i}" for i in range(1, 200) if i != 23]
    sc = "normal_traffic"
    for i in range(n_sessions):
        t = BASE + timedelta(seconds=rng.uniform(0, window_s - 300))
        ip, ua = rng.choice(pool), rng.choice(BROWSER_UAS)
        vid, sid = f"v-{i:04d}", f"sess-n{i:04d}"
        logs_in = rng.random() < 0.18
        login_at = rng.randint(2, 5) if logs_in else -1
        uid = vid
        n_pages = rng.randint(3, 12)
        for seq in range(1, n_pages + 1):
            page = rng.choice(PAGES).format(p=rng.randint(1, 40), b=rng.randint(1, 15))
            if seq == login_at:
                page = "/login"
            load_ms = int(rng.lognormvariate(5.8, 0.4))
            rows.append(_row(t, "page_view", "sdk", ip, ua, sc, "benign", sid=sid, uid=uid, method="GET", endpoint=page,
                             attrs={"page_seq": seq, "load_ms": load_ms, "webdriver": False, "viewport": [1280, 720]}))
            dwell = rng.lognormvariate(3.0, 0.7)
            rows.append(_row(t + timedelta(seconds=dwell * 0.9), "interaction", "sdk", ip, ua, sc, "benign", sid=sid, uid=uid,
                             attrs={"page_seq": seq, "clicks": rng.randint(0, 4), "key_events": rng.randint(0, 6),
                                    "scroll_events": rng.randint(1, 30), "mouse_moves": rng.randint(5, 200),
                                    "dwell_ms": int(dwell * 1000)}))
            t += timedelta(seconds=dwell)
            if seq == login_at:
                uid = f"u-{rng.randint(1000, 4999)}"
                if uid == TARGET_ACCOUNT:
                    uid = "u-1000"
                rows.append(_row(t, "login_success", "auth", ip, ua, sc, "benign", sid=sid, uid=uid, method="POST",
                                 endpoint="/api/login", status=200))
                sid = sid + "-a"
                t += timedelta(seconds=1)
                rows.append(_row(t, "session_created", "auth", ip, ua, sc, "benign", sid=sid, uid=uid))
                for ep in rng.sample(["/api/account/me", "/api/orders", "/api/wishlist"], rng.randint(1, 3)):
                    t += timedelta(seconds=rng.uniform(1, 6))
                    rows.append(_row(t, "api_access", "api", ip, ua, sc, "benign", sid=sid, uid=uid, method="GET",
                                     endpoint=ep, status=200))
                if rng.random() < 0.12:
                    t += timedelta(seconds=rng.uniform(2, 8))
                    rows.append(_row(t, "sensitive_endpoint_access", "api", ip, ua, sc, "benign", sid=sid, uid=uid,
                                     method="GET", endpoint="/api/account/payment-methods", status=200))
            if rng.random() < 0.02:
                rows.append(_row(t, "http_request", "app", ip, ua, sc, "benign", sid=sid, uid=uid, method="GET",
                                 endpoint=f"/old-page-{rng.randint(1, 9)}", status=404))
            if rng.random() < 0.004:
                rows.append(_row(t, "app_error", "app", ip, ua, sc, "benign", sid=sid, uid=uid, method="GET",
                                 endpoint="/api/orders", status=500, attrs={"error_class": "UpstreamTimeout"}))
        if logs_in and rng.random() < 0.5:
            t += timedelta(seconds=rng.uniform(5, 40))
            rows.append(_row(t, "session_terminated", "auth", ip, ua, sc, "benign", sid=sid, uid=uid))

    # Legitimate admin using a sensitive endpoint (keeps "sensitive == bad" from being a trivial rule).
    admin_ip = "192.0.2.250"
    for k in range(4):
        t = BASE + timedelta(minutes=10 + k * 12)
        rows.append(_row(t, "sensitive_endpoint_access", "api", admin_ip, BROWSER_UAS[0], sc, "benign", sid="sess-admin-1",
                         uid="admin-01", method="GET", endpoint="/api/admin/dashboard", status=200))

    # Hard negatives: real users who mistype a password a few times, then succeed.
    for k in range(8):
        t = BASE + timedelta(minutes=5 + k * 6, seconds=rng.uniform(0, 30))
        ip, ua, uid, sid = f"192.0.2.{200 + k}", rng.choice(BROWSER_UAS), f"u-{2000 + k}", f"sess-typo{k}"
        for _ in range(rng.randint(2, 4)):
            rows.append(_row(t, "login_failure", "auth", ip, ua, "benign_failed_logins", "benign", sid=sid, uid=uid,
                             method="POST", endpoint="/api/login", status=401, attrs={"failure_reason": "invalid_credentials"}))
            t += timedelta(seconds=rng.uniform(5, 15))
        rows.append(_row(t, "login_success", "auth", ip, ua, "benign_failed_logins", "benign", sid=sid, uid=uid,
                         method="POST", endpoint="/api/login", status=200))
    return rows


# --------------------------------------------------------------------------- hero scenario
def gen_hero(rng: random.Random) -> list[dict]:
    """Credential abuse -> unauthorized access -> suspicious API activity (PRD §25)."""
    sc, lab, ip, ua = "hero_credential_abuse", "malicious", ATTACKER_IP, HEADLESS_UA
    rows: list[dict] = []
    t = BASE + timedelta(minutes=55)
    pre = "sess-h-pre"

    # 1) abnormal navigation: rapid, headless, no human interaction
    for seq, page in enumerate(["/", "/login", "/account", "/admin", "/api/docs", "/robots.txt", "/sitemap.xml",
                                "/products", "/login", "/login"], start=1):
        rows.append(_row(t, "page_view", "sdk", ip, ua, sc, lab, sid=pre, uid="v-hero", method="GET", endpoint=page,
                         attrs={"page_seq": seq, "load_ms": rng.randint(25, 60), "webdriver": True, "viewport": [800, 600]}))
        t += timedelta(seconds=rng.uniform(0.8, 1.6))
    t += timedelta(seconds=2)

    # 2) 126 failed logins in ~18 seconds
    accounts = [f"acct-{rng.randint(1000, 4999)}" for _ in range(40)]
    accounts = [a for a in dict.fromkeys(accounts) if a != TARGET_ACCOUNT][:38]
    offsets = sorted(rng.uniform(0, 18.0) for _ in range(126))
    offsets[0], offsets[-1] = 0.0, 18.0
    start = t
    for k, off in enumerate(offsets):
        uid = TARGET_ACCOUNT if k >= 123 else rng.choice(accounts)
        rows.append(_row(start + timedelta(seconds=off), "login_failure", "auth", ip, ua, sc, lab, sid=pre, uid=uid,
                         method="POST", endpoint="/api/login", status=401, attrs={"failure_reason": "invalid_credentials"}))
    t = start + timedelta(seconds=18)

    # 3) success -> new session -> sensitive API -> suspicious request -> WAF / app signals
    t += timedelta(seconds=16)
    rows.append(_row(t, "login_success", "auth", ip, ua, sc, lab, sid=pre, uid=TARGET_ACCOUNT, method="POST",
                     endpoint="/api/login", status=200))
    t += timedelta(seconds=13)
    auth = "sess-h-auth"
    rows.append(_row(t, "session_created", "auth", ip, ua, sc, lab, sid=auth, uid=TARGET_ACCOUNT))
    t += timedelta(seconds=3)
    rows.append(_row(t, "api_access", "api", ip, ua, sc, lab, sid=auth, uid=TARGET_ACCOUNT, method="GET",
                     endpoint="/api/account/me", status=200))
    t += timedelta(seconds=8)
    rows.append(_row(t, "sensitive_endpoint_access", "api", ip, ua, sc, lab, sid=auth, uid=TARGET_ACCOUNT, method="GET",
                     endpoint="/api/admin/customers/export?format=csv", status=200, attrs={"response_bytes": 2480112}))
    t += timedelta(seconds=5)
    bad = "/api/reports/search?q=' UNION SELECT username,pass_hash FROM users--"
    rows.append(_row(t, "http_request", "api", ip, ua, sc, lab, sid=auth, uid=TARGET_ACCOUNT, method="POST",
                     endpoint=bad, status=500))
    rows.append(_row(t + timedelta(seconds=0.2), "app_error", "app", ip, ua, sc, lab, sid=auth, uid=TARGET_ACCOUNT,
                     method="POST", endpoint="/api/reports/search", status=500, attrs={"error_class": "DatabaseSyntaxError"}))
    rows.append(_row(t + timedelta(seconds=0.4), "waf_alert", "waf", ip, ua, sc, lab, sid=auth, uid=TARGET_ACCOUNT,
                     method="POST", endpoint="/api/reports/search", status=500,
                     attrs={"rule_name": "sql_injection_pattern", "mode": "detect_only"}))
    rows.append(_row(t + timedelta(seconds=0.5), "security_decision", "waf", ip, ua, sc, lab, sid=auth, uid=TARGET_ACCOUNT,
                     method="POST", endpoint="/api/reports/search", status=500, attrs={"decision": "allow", "mode": "detect_only"}))
    return rows


# --------------------------------------------------------------------------- extra scenarios
def gen_injection_probe(rng: random.Random) -> list[dict]:
    sc, lab, ip, ua = "injection_probe", "malicious", SQLI_IP, BROWSER_UAS[2]
    probes = [
        ("/products?id=1' OR '1'='1", 500), ("/products?id=1 UNION SELECT NULL,NULL--", 500),
        ("/search?q=<script>alert(1)</script>", 200), ("/search?q=\"><img src=x onerror=alert(1)>", 200),
        ("/download?file=../../etc/passwd", 403), ("/download?file=..%2F..%2Fwindows%2Fwin.ini", 403),
        ("/products?id=1; DROP TABLE users--", 500), ("/fetch?url=http://169.254.169.254/latest/meta-data/", 400),
    ]
    rows, t = [], BASE + timedelta(minutes=48)
    for ep, status in probes:
        rows.append(_row(t, "http_request", "app", ip, ua, sc, lab, sid="sess-probe-1", method="GET", endpoint=ep, status=status))
        if status in (403, 400):
            rows.append(_row(t + timedelta(seconds=0.3), "waf_alert", "waf", ip, ua, sc, lab, sid="sess-probe-1", method="GET",
                             endpoint=ep.split("?")[0], status=status, attrs={"mode": "detect_only"}))
        t += timedelta(seconds=rng.uniform(2, 9))
    return rows


def gen_bot_scraper(rng: random.Random) -> list[dict]:
    sc, lab, ip = "bot_scraper", "malicious", BOT_IP
    rows, t = [], BASE + timedelta(minutes=40)
    for n in range(300):
        rows.append(_row(t, "http_request", "app", ip, SCRAPER_UA, sc, lab, sid="sess-bot-1", method="GET",
                         endpoint=f"/products/{n % 200 + 1}", status=200))
        t += timedelta(seconds=rng.uniform(0.1, 0.3))
    return rows


# --------------------------------------------------------------------------- output
def _write_csv(path: Path, rows: list[dict]) -> None:
    rows = sorted(rows, key=lambda r: (r["timestamp"], r["event_type"], r["user_id"], r["endpoint"]))
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=COLUMNS, lineterminator="\n")
        w.writeheader()
        w.writerows(rows)


def row_to_event(row: dict) -> dict:
    """CSV row -> ingestion payload (ground-truth columns removed)."""
    ev: dict = {"event_type": row["event_type"], "source": row["source"], "timestamp": row["timestamp"],
                "attributes": json.loads(row["attributes"] or "{}"), "is_synthetic": True}
    for k in ("session_id", "user_id", "source_ip", "user_agent", "method", "endpoint"):
        if row[k]:
            ev[k] = row[k]
    if row["status_code"] != "":
        ev["status_code"] = int(row["status_code"])
    return ev


def generate(data_dir: Path = DATA_DIR) -> dict:
    data_dir.mkdir(parents=True, exist_ok=True)
    rng = random.Random(SEED)
    normal = gen_normal(rng)
    attacks = gen_hero(rng) + gen_injection_probe(rng) + gen_bot_scraper(rng)
    _write_csv(data_dir / "normal_traffic.csv", normal)
    _write_csv(data_dir / "attack_scenarios.csv", attacks)

    # sample_events.json: one curated example per event type, ready to POST to /v1/ingest.
    seen, sample = set(), []
    for r in sorted(normal + attacks, key=lambda r: r["timestamp"]):
        if r["event_type"] not in seen and r["scenario"] in ("normal_traffic", "hero_credential_abuse"):
            seen.add(r["event_type"])
            sample.append(row_to_event(r))
    (data_dir / "sample_events.json").write_text(json.dumps({"events": sample}, indent=2) + "\n", encoding="utf-8")
    return {"normal_rows": len(normal), "attack_rows": len(attacks), "sample_events": len(sample)}


if __name__ == "__main__":
    print(generate())
