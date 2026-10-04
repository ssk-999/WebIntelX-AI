# WebIntelX AI

Multi-agent AI-powered web attack investigation & security intelligence platform (hackathon MVP).
Source of truth: `WebIntelX_AI_PRD.pdf` (v1.0).

## Status — Milestone 10 (Part 1 + Part 2) WRITTEN: incident lifecycle, analyst feedback, incident report, dashboard analyst actions + report download, Dockerfile, deploy notes. Part 2 was tested (486 tests + real Streamlit/backend flow); live Groq call and Docker/Streamlit-Cloud builds are still unexecuted (see *Verification status of M10 Part 2*).
Implemented: config, SQLite schema (PRD §30), account/website/credential management (rotate/revoke),
strict event validation, normalisation, masking/minimisation, ingestion API with origin checks and
rate limiting, installation verification, website isolation, controlled DB-failure handling, tests.

**M2 adds:** the browser SDK (`sdk/web-intelx-ai.js`), SRI-protected install snippet (returned on website
creation/rotation, placeholder-key version at `GET /v1/websites/{id}/sdk-snippet`), SDK served at `/sdk/web-intelx-ai.js`,
a deterministic synthetic data generator, committed datasets in `data/`, and a demo loader
(`POST /v1/websites/{id}/demo/load`, or `python -m app.demo.loader --website-id ...`).

**M3 adds:** per-event feature extraction at ingestion (`events.features`), derived session context, 13 config-driven
deterministic detection rules writing to the PRD `findings` table, incremental detection after each ingested batch,
`POST /analyze`, `GET /findings`, `GET /sessions`, `GET /v1/detection/rules`, and a labelled offline evaluation.

**M4 adds:** a scikit-learn Isolation Forest over per-session behavioural features (`app/ml/`), a config-driven two-signal
flag (isolation score **and** a robust per-feature deviation), explainable "notable deviations" (PRD Agent 2 output), findings
written under `agent_name="anomaly_model"`, `POST /anomalies/analyze`, `GET /anomalies`, `GET /v1/anomaly/config`, and a
session-level offline evaluation.

**M5 adds:** a deterministic correlation engine (`app/correlation/`) that relates events by IP / session / account / endpoint /
behaviour / recognised attack sequence, groups them into clusters, creates `DETECTED` incident candidates, and derives a
chronological **timeline** and an evidence-traceable **attack graph**. New: `POST /correlate`, `GET /incidents/{id}/correlations|timeline|graph`,
`GET /v1/correlation/config`, `config/correlation.yaml`. No new dependencies, no schema change.

**M6 adds:** a pluggable threat-intelligence layer (`app/threat_intel/`): an IP/domain reputation provider chosen with `TI_PROVIDER`
(`otx` or the clearly-labelled `synthetic_demo`), NVD CVE lookups, and a local MITRE ATT&CK context table. Indicators are extracted from
incidents, enriched on demand, stored in `incident.details["threat_intel"]`, and a "Threat intelligence enrichment" step appears in the
timeline. New: `POST/GET /v1/incidents/{id}/threat-intel`, `POST /v1/websites/{id}/threat-intel/enrich`, `GET /v1/threat-intel/providers`,
`config/threat_intel.yaml`, `data/synthetic_threat_intel.json`. No new dependencies, no schema change.

**M7 adds:** structured, reproducible incident risk scoring (`app/risk/`): eight evidence-driven factors combined with weights from
`config/risk.yaml` into a 0-100 score and a LOW/MEDIUM/HIGH/CRITICAL level, plus a **separate** evidence-quality `confidence`, the factors that
produced the score, and deterministic evidence gaps. New: `POST/GET /v1/incidents/{id}/risk`, `POST /v1/websites/{id}/risk/score`,
`GET /v1/risk/config`, `?risk_level=` / `?sort=risk` on the incident list, a `risk` summary in the demo-load response, `python -m app.risk.evaluation`.
No new dependencies, no schema change (uses the existing `incidents.risk_level / risk_score / confidence` columns and `details["risk"]`).

**M8 adds:** the multi-agent layer (`app/agents/`, `app/crew/`): a deterministic supervisor/orchestrator that runs anomaly -> threat intel -> risk, then two **LLM-backed
CrewAI agents on Groq** (Investigation, Response), then a deterministic **incident-level alert**. New: `POST /v1/incidents/{id}/investigate`,
`GET /v1/incidents/{id}/investigation|recommendations|alert|audit`, `POST /v1/websites/{id}/investigate`, `GET /v1/websites/{id}/alerts`, `GET /v1/agents/config`,
`config/agents.yaml`, `LLM_FAST_MODEL`, an `ai_inference` timeline entry. Dependency added: `crewai[litellm]`. No schema change.

**M9 adds:** the Streamlit dashboard (`dashboard/`): sign-in / account creation, onboarding (register website, create/rotate/revoke credential, SDK snippet, verify installation, labelled synthetic demo loader), the main Security Dashboard (KPIs, incident cards, measured reduction funnel, suspicious sessions, recent events) and the Incident Investigation page (summary, timeline, attack graph, evidence + AI, threat intelligence, risk factors, response, analyst-actions placeholder). No backend change, no schema change. Dependencies added: `streamlit`, `plotly`.

**M10 Part 1 adds:** the incident lifecycle (PRD section 22, all 8 states), analyst feedback stored in the PRD `feedback` table (FR-22, AC-20), accept / reject / further-investigate
decisions on each recommended action (AC-19), alert status that follows the lifecycle, and a structured, shareable incident report (PRD section 24, FR-24, AC-21) as JSON, Markdown or HTML.
New: `GET /v1/lifecycle/config`, `GET /v1/incidents/{id}/lifecycle`, `POST /v1/incidents/{id}/status`, `POST|GET /v1/incidents/{id}/feedback`,
`POST /v1/incidents/{id}/recommendations/{action}/decision`, `GET /v1/incidents/{id}/report?format=json|markdown|html&download=`. No new dependencies, no schema change.
Small changes to earlier code: an investigation run now moves `DETECTED -> INVESTIGATING`; `GET .../recommendations` adds an `analyst_decision` field per item; `APP_VERSION` is `0.10.0-m10-part1`
(the tests no longer pin the version string). Two M8 bugs were found and fixed while running the suite for real (see *Corrections to M8*).

**M10 Part 2 adds:** the dashboard side of the above and the deployment files. The *Analyst actions* tab (decision + comment -> feedback table; accept / reject / investigate-further per recommendation; lifecycle steps; status history; stored outcomes),
a *Report* tab (Markdown / HTML / JSON download + preview), the analyst decision shown next to each recommendation in the *Response* tab, `Dockerfile`, `.dockerignore`, `docker-compose.yml`, an optional single-process mode for Streamlit Community Cloud
(`dashboard/embedded_backend.py`), and the *Deploy* section below. No backend endpoint was added or changed, no schema change, no new dependency. `ApiClient` now surfaces the backend's structured lifecycle error (`code` + `message`), which Part 1 returned but the M9 client reduced to "Request rejected".

## Run locally
```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env            # set PRIVACY_SALT; never commit .env
uvicorn app.main:app --reload   # API docs: http://127.0.0.1:8000/docs
python -m pytest -q                 # run the full suite (one suite needs Node for the SDK tests)
```

## Deploy (M10 Part 2)
Three ways to run it. None of the hosting steps below were executed by me (no Docker, no Streamlit Cloud, no Groq key in the build sandbox): the file contents are checked by `tests/test_deploy_files.py`, the rest is for you to confirm.

**A. Streamlit Community Cloud, one app (your stated target; demo with SYNTHETIC data).** Streamlit Cloud runs one process, so the dashboard can start the unchanged FastAPI app inside it (PRD section 41 allows deploying them together).
1. Push the repo to GitHub. `.env`, `*.db` and `.streamlit/secrets.toml` are git-ignored; never commit them.
2. share.streamlit.io -> *New app* -> repository, branch, **main file path `dashboard/streamlit_app.py`**. Pick a Python version that the `crewai` release you install supports (check its docs; I could not verify this here).
3. *Advanced settings -> Secrets*: paste the *Option A* block of `.streamlit/secrets.toml.example` and fill in `GROQ_API_KEY` and a long random `PRIVACY_SALT`. `WEBINTELX_EMBEDDED_BACKEND = "true"` is what switches the single-process mode on.
4. Open the app -> create account -> register website -> *Load hero scenario* (SYNTHETIC) -> Dashboard -> Investigate -> Analyst actions -> Report.

Limits of this mode (be upfront about them in the demo): the embedded backend listens on 127.0.0.1 only, so a real website's browser SDK **cannot** reach it (use *B* for that); the SQLite file is not guaranteed to survive an app restart; first load is slow because `crewai` is heavy; secrets are copied from Streamlit secrets into the process environment (names only are tracked, values are never logged).

**B. Backend hosted separately + dashboard on Streamlit Cloud (needed for real SDK telemetry).** Build the backend from the `Dockerfile` on any container host you choose (I have not verified any host or free tier). Run it with `GROQ_API_KEY`, `PRIVACY_SALT`, `PUBLIC_BASE_URL=https://<your backend>` (so the SDK snippet points at it) and a persistent volume at `/data` (`DATABASE_URL` defaults to `sqlite:////data/WebIntelXAI.db` in the image; PostgreSQL stays a later option through the same variable). In Streamlit secrets set `WEBINTELX_API_URL = "https://<your backend>"` and leave embedded mode off. Put the backend behind HTTPS; set `TRUST_FORWARDED_FOR=true` only behind a proxy you control.

**C. Local containers.** `docker compose up --build` starts the backend on :8000 and the dashboard on :8501 (values come from your shell or a local `.env`).

**Local without Docker (two terminals):** `uvicorn app.main:app --reload` and `streamlit run dashboard/streamlit_app.py`. Or one terminal: `WEBINTELX_EMBEDDED_BACKEND=true streamlit run dashboard/streamlit_app.py`.

**Google Colab (optional):** the standard Colab secrets API is `from google.colab import userdata; os.environ["GROQ_API_KEY"] = userdata.get("GROQ_API_KEY")`. Set it before importing `app.*`, because settings are read once. Do not print the key.

**Demo path (PRD section 36):** account -> website -> credential/snippet -> verify -> dashboard -> synthetic hero attack -> investigate (agents, correlation, threat intel) -> timeline + graph + evidence -> risk -> alert -> response recommendations -> *Analyst actions* (accept / reject / further investigate, decision + comment) -> *Report*. Check `/health` of the backend first: it reports `llm_configured`, the TI provider and every config status without exposing secret values.

## Lifecycle, feedback & report (M10 Part 1)
```
GET  /v1/lifecycle/config                                   states, allowed transitions, decision vocabulary (public)
GET  /v1/incidents/{id}/lifecycle                           status, allowed_next, history, latest feedback, recommendation decisions, alert status
POST /v1/incidents/{id}/feedback   {decision, comment?}     analyst outcome -> feedback table + lifecycle   (201)
GET  /v1/incidents/{id}/feedback                            all stored outcomes, newest first
POST /v1/incidents/{id}/status     {status, comment?}       manual lifecycle step (decision states are routed through feedback so the outcome is always stored)
POST /v1/incidents/{id}/recommendations/{action}/decision   {decision: accept|reject|further_investigation, comment?}   nothing is executed
GET  /v1/incidents/{id}/report?format=json|markdown|html&download=true     generated on request from stored data; writes nothing
```
**States (PRD section 22):** `DETECTED -> INVESTIGATING -> {CONFIRMED | FALSE_POSITIVE | NEEDS_INVESTIGATION} -> RESPONSE_RECOMMENDED -> ACTION_TAKEN -> RESOLVED`.
| from | allowed next |
|---|---|
| DETECTED | INVESTIGATING, CONFIRMED, FALSE_POSITIVE, NEEDS_INVESTIGATION |
| INVESTIGATING | CONFIRMED, FALSE_POSITIVE, NEEDS_INVESTIGATION |
| NEEDS_INVESTIGATION | INVESTIGATING, CONFIRMED, FALSE_POSITIVE |
| CONFIRMED | RESPONSE_RECOMMENDED, FALSE_POSITIVE, NEEDS_INVESTIGATION |
| FALSE_POSITIVE | RESOLVED, CONFIRMED, NEEDS_INVESTIGATION |
| RESPONSE_RECOMMENDED | ACTION_TAKEN, RESOLVED, NEEDS_INVESTIGATION |
| ACTION_TAKEN | RESOLVED |
| RESOLVED | INVESTIGATING (reopen) |

Any other jump is a controlled `409 invalid_transition` that lists the allowed states and changes nothing. Bad input is `422`; other customers' incidents are `404` (FR-27 / AC-22).

**Human approval (PRD section 21, AC-19):** the platform never executes a response. `ACTION_TAKEN` only records that a human did something *outside* the platform, so it needs
a comment, and - when AI recommendations exist - at least one accepted recommendation first (`409 approval_required` otherwise). Recommendations keep `status: proposed`,
`requires_human_approval: true`, `executed: false`; the analyst's decision is shown next to them as `analyst_decision`.

**Feedback (AC-20):** one `feedback` row per decision (`CONFIRMED | FALSE_POSITIVE | NEEDS_INVESTIGATION`; `true_positive` is an alias of `CONFIRMED`) plus an optional comment (control characters
removed, max 2000 characters, stored as plain text). Decisions can be revised; every one is kept. Feedback is stored for later tuning of rules, prompts and baselines - there is no online learning loop (PRD section 21).
A `CONFIRMED` decision moves the incident on to `RESPONSE_RECOMMENDED` automatically when validated AI recommendations exist (two audited steps: analyst, then system).

**Alerts:** alert status follows the lifecycle - `open` -> `acknowledged` (decision / response stages) -> `closed` (`FALSE_POSITIVE`, `RESOLVED`); reopening a closed incident reopens its alert.

**Audit (PRD sections 33, 35):** every status change, analyst decision and recommendation decision is appended to `details["audit"]` with the `actor` (`analyst:<account id>` or `system`), plus
`details["lifecycle"]["history"]`. Both are lists kept with the incident (last 50 / 100 entries), not tamper-proof storage; the `feedback` table is the permanent record of outcomes.

**Report (PRD section 24):** a deterministic assembly of stored, already-validated data - no LLM, nothing new is claimed. Sections: executive summary (template over the numbers), incident ID, detection time,
affected resources, source information, attack hypothesis (AI inference, labelled, evidence-referenced, or an explicit "not available"), timeline, attack-graph summary, supporting evidence (observed facts / findings /
AI claims kept separate), threat intelligence (the No-Evidence Rule is repeated), MITRE ATT&CK mapping (only technique results actually found; context, not proof), risk and confidence (separate; factors listed),
recommended response with the analyst decision, evidence limitations (deterministic gaps and AI-identified missing evidence kept distinguishable), analyst decision and status history, audit trail, disclaimers.
The Markdown and HTML renderers treat every dynamic value as untrusted text (path/TI/AI/analyst text): entity-escaping, Markdown escaping, no script or remote resources, restrictive `Content-Security-Policy`.

### Verification status of M10 Part 1 (read this)
| Part | Status |
|---|---|
| Whole test suite incl. 64 new tests (`test_lifecycle_states.py`, `test_lifecycle_api.py`, `test_report.py`, `test_evidence_ip_redaction.py`) and the real FastAPI / SQLAlchemy / httpx stack | **Executed in the build sandbox: 454 passed, 0 failed** (this is the first milestone where FastAPI, SQLAlchemy and `httpx` were actually installed: it also executed the M8 API tests and `tests/test_dashboard_api_client.py`, which M8/M9 had marked "written, not executed") |
| 15 deliberate mutations (approval gate, comment rule, illegal transition, feedback not stored, IP redaction, HTML / Markdown escaping, report trusting recommendation flags, DETECTED->INVESTIGATING hook, alert status, auto-advance, control characters, decision routing, decision overlay, CSP header) | each **caught** by at least one test |
| Real server | `uvicorn` was started and the flow register -> website -> demo load -> investigate (no key) -> feedback -> status steps -> JSON / Markdown / HTML report was run over HTTP |
| Live Groq call through CrewAI; real Streamlit rendering | **still NOT executed** (`crewai` and `streamlit` were not installed in the build sandbox; the agent tests use a scripted fake LLM and the UI tests use stubbed `streamlit`/`plotly`) |

### Verification status of M10 Part 2 (read this)
| Part | Status |
|---|---|
| Whole suite on the real stack (Python 3.12, FastAPI 0.142, SQLAlchemy 2.1, httpx 0.28, **Streamlit 1.65**, Plotly 7.1, **crewai 1.15.23** + litellm) | **Executed: 486 passed, 0 failed** (454 from Part 1 + 32 new: `test_dashboard_lifecycle_client.py`, `test_dashboard_viewmodels_m10.py`, `test_embedded_backend.py`, `test_deploy_files.py`, +5 UI smoke tests). One *test* bug was found and fixed (a regex crossing a newline); no product code failed a test |
| **Real Streamlit (`streamlit.testing.AppTest`) against a real backend over HTTP**, using the embedded single-process mode | **Executed**: register -> sign in -> register website (key shown) -> load 144 SYNTHETIC events -> investigation page with all 9 tabs -> save analyst decision (feedback row, status CONFIRMED -> RESPONSE_RECOMMENDED) -> `ACTION_TAKEN` **refused** before any recommendation was accepted -> Accept -> `ACTION_TAKEN` recorded, alert `acknowledged`, every `executed` flag False -> "Run investigation" with no key shows `llm_unavailable` cleanly -> report (Markdown/HTML/JSON) contains the decision and history, HTML has no `<script` |
| Dashboard recommendations/LLM output in that flow | Recommendations were injected from the scripted fake LLM through the real validator (there is no Groq key in the build sandbox) |
| Dockerfile `CMD` and `HEALTHCHECK` command run as plain shell on `$PORT` | **Executed**: `/health` returned 200 |
| `docker build`, `docker compose up`, Streamlit Community Cloud deploy, live Groq call through CrewAI, a real browser (layout / look), real threat-intel providers | **NOT executed** (no Docker, no browser, no Groq key, no network to those services in the sandbox) |

**Bugs found by running it and fixed:** (1) after registering a website the app jumped to the Dashboard and the one-time ingestion key was never shown (M9 behaviour); the app now opens Onboarding after register / rotate. (2) The AI-status warning printed the backend error as a raw dict; it now shows the message. (3) `ApiClient` reduced the backend's structured 409/422 errors to "Request rejected" (fixed earlier, now covered by tests).

Watch when you deploy: `docker build` on `python:3.12-slim` (add `build-essential` to the Dockerfile only if a `crewai` dependency asks for a compiler); the Python version Streamlit Cloud gives you must be one `crewai` supports; Streamlit emits a harmless "missing ScriptRunContext" warning in bare-mode tests only.

## M10 Part 2 assumptions ("PRD does not specify this; using the following implementation assumption...")
- **Analyst actions live in the existing "Analyst actions" tab of the investigation page** (PRD section 23 lists it there); the report gets its own tab. Recommendation decisions are shown read-only in the *Response* tab and edited in *Analyst actions*.
- **The three decision states are set only through the decision form** (so the outcome is always stored as feedback); the lifecycle-step form offers the other next states. The UI mirrors the backend's approval rule for `ACTION_TAKEN` as a hint only; the backend remains the authority and its refusal message is shown as-is.
- **Reports are generated when you press the button** (three backend calls: Markdown, HTML, JSON), cached in the browser session, and discarded after any analyst action so a stale report is never offered.
- **The Markdown preview uses `st.markdown`** on text the backend already escapes; the HTML report is download-only (no embedded iframe).
- **Single-process mode** (above) is my choice to make a Streamlit-Cloud-only deployment possible; it is off unless `WEBINTELX_EMBEDDED_BACKEND` is true. **`docker-compose.yml`** is a convenience; the PRD only lists a `Dockerfile`.
- **Version string** is now `0.10.0` (`GET /health`).
- **Changes to earlier files, all additive or minimal:** `dashboard/api_client.py` (new methods, structured error parsing), `dashboard/viewmodels.py` (functions appended, none changed), `dashboard/streamlit_app.py` (placeholder tab replaced, Response tab caption, bootstrap hook, Onboarding-after-register fix, error-message display), `app/main.py` (version string), `tests/test_dashboard_ui_smoke.py` (fake client extended, one assertion that pinned the M9 placeholder text updated), `.env.example` / `.streamlit/secrets.toml.example` (deploy variables).

### Corrections to M8 (found by actually running its tests)
- **Privacy bug (fixed):** the incident title (a rule template such as "Suspicious activity chain from 203.0.113.77 ...") and threat-intelligence summaries carried the literal source IP into the LLM
  evidence bundle, contradicting M8's "the LLM never sees IPs" guarantee. `safe_text` in `app/agents/evidence.py` now replaces IPv4 / IPv6 literals with `(source ip)`; clock times and version numbers are untouched; `safe_metrics` still drops a string value that carried an IP.
- **Test bugs (fixed):** two M8 API tests read `body["investigation"]`, but the API (and the dashboard) use the flattened shape (`facts` / `inference` at top level). The tests were wrong, the code and dashboard were right.

## M10 Part 1 assumptions ("PRD does not specify this; using the following implementation assumption...")
- **Transition rules** are my choice (table above); the PRD gives only the state diagram. "ANALYST DECISION" is a decision point, represented by its three outcomes. Analysts may decide straight from `DETECTED` and revise decisions.
- **`DETECTED -> INVESTIGATING` is automatic** after an investigation run (system actor), even if the AI step failed, because the deterministic steps ran. It is never applied to an incident that has moved on.
- **Recommendation decisions are keyed by action name** (the validator allows each action once per incident) and survive re-investigation; they do not change the incident status by themselves.
- **No new tables:** feedback uses the PRD `feedback` table; lifecycle history, recommendation decisions and audit live under `incident.details` (like M5-M8). The feedback table has no actor column (PRD section 30), so the actor is recorded in the audit entry that references the `feedback_id`.
- **The report is generated on request** (not stored) by a deterministic builder; the PRD's optional "Reporting / Analyst Assistant" agent is therefore not an LLM role in this build. Reports include source IPs as stored (the user's own data); only the LLM path redacts them.
- **`/status` cannot bypass feedback:** setting `CONFIRMED`, `FALSE_POSITIVE` or `NEEDS_INVESTIGATION` through it creates the feedback row too.

## Detection (M3)
```
POST /v1/ingest -> validate -> normalise -> mask -> FEATURES -> store -> (best-effort) incremental rules
GET  /v1/detection/rules                          rule catalogue + thresholds in force (public, no secrets)
POST /v1/websites/{id}/analyze                    run all rules over the website (idempotent)
GET  /v1/websites/{id}/findings?finding_type=&event_id=&min_confidence=
GET  /v1/websites/{id}/sessions?suspicious_only=true&sort=findings     derived session context
GET  /v1/websites/{id}/sessions/{session_key}                          session + its findings + event ids
python -m app.detection.evaluation               load ALL demo data in a throw-away DB, detect, print precision/recall
```
Rules (`config/detection.yaml`; every threshold and confidence is configurable, a bad file falls back to defaults and is
reported in `/health` -> `detection_config`): **R-AUTH-001** failed-login burst · **R-AUTH-002** many accounts from one source ·
**R-AUTH-003** success after burst · **R-BEH-001** request rate · **R-BEH-002** automation UA / `navigator.webdriver` ·
**R-BEH-003** non-human navigation · **R-BEH-004** recon path probing · **R-ATK-001..004** SQLi / XSS / path traversal / SSRF
indicators · **R-ATK-005** multi-vector probing · **R-WAF-001** WAF alert recorded.

Each finding keeps PRD §19's separation: `observed` (facts) · `derived_metrics` · `interpretation` (rule-authored hedged text,
`basis: "rule_template"`, never an LLM) · `limitations` · `event_ids` (traceable evidence) · `thresholds` used · optional
`mitre_reference` (context only, not proof). `confidence` is a configured rule weight, **not a probability**.

### Measured on the synthetic demo data (9,518 events: 9,063 benign incl. hard negatives, 455 malicious)
| | result |
|---|---|
| False positives on benign events (incl. 8 mistyped-password users + legitimate admin) | **0** |
| Every attack scenario has ≥1 finding | hero credential-abuse ✅ · SQLi/XSS/traversal/SSRF probe ✅ · scraper bot ✅ |
| Hero chain stages detected | abnormal navigation → 126 failures in 18 s → success for targeted account → SQLi request + WAF alert |
| 9,518 events → findings → suspicious events | 23 findings, 455 suspicious events |

**Read these numbers with care (this is deliberate, not modesty):** the rules were tuned while looking at this same synthetic
data, so 100 % precision/recall here only shows the pipeline behaves as designed. The evidence-level 100 % recall also leans on
R-BEH-002 because the synthetic attacker keeps one headless User-Agent for every event. With R-BEH-002 disabled (tested):
hero chain still 139/144 events, injection probe 11/11, scraper falls to 54/300 (peak-rate window only), overall recall ≈ 0.45,
precision unchanged at 1.0. The remaining hero events (post-login context) are joined by the correlation engine (M5, implemented). The PRD's
10,000 → 47 → 8 → 3 → 1 funnel is a demo *target* and is **not** claimed.

## Anomaly detection (M4)
```
POST /v1/websites/{id}/anomalies/analyze    fit baseline on this website's sessions (last window_hours), store findings (idempotent)
GET  /v1/websites/{id}/anomalies?min_confidence=    stored ML findings only (also visible in /findings, agent_name=anomaly_model)
GET  /v1/anomaly/config                     thresholds + feature list in force (public, no secrets); /health -> anomaly_config
python -m app.ml.evaluation                 load ALL demo data in a throw-away DB, run the model, print session-level precision/recall
```
How it works (`config/anomaly.yaml`; a bad file falls back to defaults and is reported in `/health`):
1. Events are sessionised (M3) and each session is summarised into 10 behavioural features (event count, distinct paths, failed
   logins, distinct failed accounts, sensitive accesses, error ratio, peak 10 s request count, request rate, median page gap,
   interaction per page view). Automation user-agent / webdriver are deliberately **not** features (they are rule indicators already).
2. An Isolation Forest (fixed `random_state`) is fitted on **this website's own** sessions. Nothing is pickled or persisted.
3. A session becomes a finding only if **both** hold: `anomaly_score >= 0.65` **and** at least one feature is `>= 8` robust
   deviations (median / max(1.4826·MAD, IQR/1.349, per-feature floor)) on its unusual side. The deviations double as the explanation.
4. Output is a finding in the PRD `findings` table: `observed` · `derived_metrics` (score, deviations, feature values, model info) ·
   `interpretation` (`basis: "model_output_template"`, hedged, never an LLM) · `limitations` · `event_ids` (all session events) ·
   `thresholds`. `confidence` is a configured linear map of the score (0.5-0.9), **not a probability**.
5. Failure handling: the analysis never raises. `status` is one of `ok | disabled | insufficient_baseline | model_unavailable | error`;
   on anything but `ok` nothing is written or deleted and rule detection is unaffected.

### Measured on the synthetic demo data (674 sessions: 670 benign incl. 8 mistyped-password sessions, 4 malicious)
| | result |
|---|---|
| Flagged sessions | `sess-h-pre` (hero chain: 126 failed logins, abnormal navigation) and `sess-bot-1` (scraper) |
| False positives | 0 benign sessions flagged; stable across 10 random seeds and under input re-ordering |
| Missed (by design) | `sess-probe-1` (11-request SQLi probe) and `sess-h-auth` (7-event post-login session): session recall 2/4 = 0.5 |

**Read this with care:** the thresholds were chosen while looking at this same synthetic data, so it shows the model behaves as
designed, not real-world accuracy. Two findings from building it are worth knowing:
- A plain score threshold is not enough. The 8 benign mistyped-password sessions are structurally rare, so their isolation scores
  (0.71-0.74) are as high as the scraper's (0.73). Only the deviation gate (their strongest deviation is 3-4 vs. >=126 / >=200) keeps them out.
- Low-volume attacks are not behaviourally unusual at session level. They are the job of the attack-indicator rules (M3) and the
  correlation engine (M5), not of this model. `tests/test_anomaly_demo.py` asserts this so the claim cannot drift from reality.

## Correlation (M5)
```
POST /v1/websites/{id}/correlate                     findings -> clusters -> incident candidates + correlation records (idempotent)
GET  /v1/incidents/{id}/correlations?relationship_type=   stored links (PRD "Correlations" table shape)
GET  /v1/incidents/{id}/timeline                     chronological entries, each labelled observed | derived_indicator | system
GET  /v1/incidents/{id}/graph                        nodes + edges, each listing the event ids it rests on
GET  /v1/correlation/config                          thresholds in force (public, no secrets); /health -> correlation_config
```
`POST /demo/load` now also runs correlation (response key `correlation`), so the demo path produces incidents.

How it works (`config/correlation.yaml`; a bad file falls back to defaults and is reported in `/health`):
1. **Seeds** = events that carry a finding or are cited as evidence by one (rule engine *and* ML model findings).
2. **Links**: per entity (source IP, session, authenticated user) the time-sorted events are chained when the gap is within a
   configured limit (`same_ip` / `same_session` / `same_user`). Chaining keeps records linear in events (932 records for 455 events
   in the full demo). Inside a cluster, `same_endpoint` and `similar_behavior` are recorded as extra evidence, and `attack_sequence`
   links the recognised stages (abnormal navigation -> failed-login burst -> successful login -> new session -> sensitive access ->
   attack-indicator request) when both ends share an IP or account.
3. **Clusters** = connected components over the *merge* link types that contain a seed. `same_endpoint`/`similar_behavior` are
   never used to merge, so two unrelated actors hitting the same path stay separate (tested).
4. **Incident candidate** when a cluster has a finding with confidence >= 0.6 **or** >= 2 distinct finding categories (configurable).
   Incidents are created `DETECTED` with **no risk, no confidence and no AI text** - those belong to M7/M8. The title is a hedged
   template (`title_basis: "rule_template"`), never an LLM or a verdict.
5. **Strength** = `base[type] * (1 - 0.5 * min(gap / max_gap[type], 1))`: a documented heuristic in [0,1], not a probability.
6. **Timeline / graph** are derived on read (nothing stored). Labels contain recorded facts only (counts, types, paths - never query
   strings or payloads). Evidence types follow PRD section 19; AI inference will get its own type when agents arrive (M8).
7. **Failure handling:** `run_correlation` never raises; `status` is `ok | no_findings | disabled | error`, and an error writes nothing.

### Measured on the synthetic demo data (9,518 events)
| | result |
|---|---|
| Suspicious events (rules + ML) | 455 |
| Clusters / potential incidents | **3 / 3**: hero chain (144 events, all 6 stages), injection probe (11), scraper bot (300) |
| Clusters from the 9,063 benign events (incl. 8 mistyped-password users, legitimate admin) | **0** |
| Hero chain with the automation rule disabled (rules alone flag 139/144) | still **144/144** - post-login events joined by IP/session/account |
| Re-run | idempotent: same incident ids, no duplicate records |

**Read this with care:** the thresholds were chosen while looking at this same synthetic data, and each synthetic actor uses one IP,
which makes clustering easy. This shows the engine behaves as designed, not real-world accuracy. The PRD's 10,000 -> 47 -> 8 -> 3 -> 1
funnel remains a demo *target*: the measured shape here is 9,518 -> 455 suspicious events -> 3 clusters -> 3 potential incidents,
and "1 high-risk investigation" needs risk scoring (M7).

## Risk scoring (M7)
```
POST /v1/incidents/{id}/risk                     score from stored findings + correlation + threat-intel report (idempotent; replaces the previous score)
GET  /v1/incidents/{id}/risk                     stored result + `stale` flag, or {"status": "not_run"}
POST /v1/websites/{id}/risk/score?limit=50       score the website's recent incidents; returns counts by level
GET  /v1/websites/{id}/incidents?risk_level=high&sort=risk     filter / order by stored risk (default listing unchanged)
GET  /v1/risk/config                             weights, thresholds and fingerprint in force (public, no secrets); /health -> risk_config
python -m app.risk.evaluation                    full deterministic pipeline on ALL demo data in a throw-away DB, prints the score table
```
`POST /demo/load` now also scores the incidents it creates (response key `risk`). Scoring never changes the incident `status` (lifecycle is M10).

**Method** (`config/risk.yaml`; a bad file falls back to defaults and is reported in `/health`; PRD section 17):
`score = 100 * SUM(weight_i * value_i) / SUM(weight_i)`, every `value_i` in [0,1] from a documented formula, no LLM anywhere.

| Factor (PRD section 17 item) | Weight | Value comes from |
|---|---|---|
| `behavior` (behavioural signals) | 10 | highest confidence of rule findings of type `behavior_anomaly` |
| `anomaly` (anomaly score) | 10 | Isolation Forest score: `(score - 0.5) / 0.5` |
| `attack_indicators` | 20 | highest `attack_indicator` confidence + 0.1 per additional distinct category |
| `authentication` (auth anomalies) | 20 | strongest configured category value (brute force 0.5, multi-account 0.6, success after burst 1.0) |
| `sensitive_endpoint` | 10 | 0.7 if the incident includes sensitive access, 1.0 if it also includes a successful login stage |
| `correlation` (number + strength) | 15 | 0.4 x stage coverage + 0.3 x log-scaled event count + 0.3 x mean stored link strength |
| `asset_impact` | 10 | highest-impact affected path via longest configured prefix (default 0.2) |
| `threat_intel` | 5 | 0.7 for one real IP/domain/CVE evidence result, +0.15 each additional |

Levels: CRITICAL >= 85, HIGH >= 65, MEDIUM >= 40, else LOW (configurable). Every response carries each factor's `weight`, `value`, `points`, `status`,
`basis` (plain text with the numbers used), the finding ids / stages it rests on, `evidence_gaps`, the supporting findings, and the config `fingerprint`
(a hash of the effective weights, so a score can be tied to the exact configuration).

**Guarantees:** a factor with no evidence adds **0 points and never subtracts** (PRD section 16: absence of threat-intel evidence is neither safety nor
maliciousness; not-run / no-evidence / excluded states are named and listed as gaps). MITRE ATT&CK mappings are context and are not counted. **Synthetic
threat intelligence never raises real severity** (`threat_intel.count_synthetic: false`). **Confidence is separate:** a 0-1 evidence-support index from
signal diversity (auth / behaviour / attack indicator / ML / TI evidence), rule/model confidence and link strength, minus a penalty when evidence was
truncated. A heavy weight on any risk factor changes risk, never confidence (tested). Neither number is a probability.

### Measured on the synthetic demo data (3 incidents, all 9,518 events)
These figures come from `python -m app.risk.evaluation`, which runs rules **and** the ML model before scoring. `POST /demo/load` does not run the ML
model (it is on demand since M4), so there the hero chain is scored without the anomaly factor: **75.3 / confidence 0.79** (still HIGH, with the
`no_ml_anomaly` gap listed). Call `POST /anomalies/analyze` and then re-score to get the full 81.9 / 0.89; the M8 orchestrator will chain these steps.
| incident | level | score | confidence | what drives it |
|---|---|---|---|---|
| hero credential-abuse chain (144 events, 6 stages) | **HIGH** | 81.9 | 0.89 | authentication 20.0 + attack indicator 14.0 + correlation 13.8 + asset 10.0 + sensitive 10.0 + behaviour 7.5 + ML 6.6 |
| multi-vector injection probe (11 events) | LOW | 28.5 | 0.56 | attack indicators 20.0, correlation 6.5, asset 2.0; no auth, sensitive access or ML signal |
| scraper bot (300 events) | LOW | 21.6 | 0.60 | correlation 7.9, behaviour 7.0, ML 4.7, asset 2.0 |
Threat intelligence was not run in these numbers (factor `not_assessed`, 0 points). The measured shape is therefore 9,518 events -> 455 suspicious events
-> 3 clusters -> 3 potential incidents -> **1 high-risk incident**; the PRD's 10,000 -> 47 -> 8 -> 3 -> 1 funnel remains a demo *target*, not a claim.

**Read this with care:** there is no ground-truth severity label, and the weights/thresholds were chosen while looking at these three synthetic incidents,
so this shows the method behaves as designed, not that the severity is right on real traffic. In particular the injection probe scores LOW because, with
only attack-indicator evidence and no authentication, sensitive-access or ML signal, it can reach at most roughly 40 points under these weights. That is a
modelling choice (an unanswered probe is less severe than a confirmed login-then-export chain), not a fact; lower `levels.medium` to 25 in `config/risk.yaml` if
you want it MEDIUM. Mutation checks confirmed the tests fail when synthetic TI is counted as real, MITRE is counted as evidence, the asset prefix rule or the
truncation penalty is changed, or staleness detection is removed.

## M7 assumptions ("PRD does not specify this; using the following implementation assumption...")
- **Levels:** LOW / MEDIUM / HIGH / CRITICAL with configured minimum scores (the PRD only shows "HIGH"). Weights, thresholds and per-factor constants are heuristics.
- **No asset context exists in the PRD data model**, so asset impact is estimated from configured path-prefix rules over the incident's affected resources.
  It overlaps partly with `sensitive_endpoint` (both can fire for an admin path); they answer different questions (involvement vs. value of the target) and are weighted separately.
- **On demand, not per ingest** (like ML, correlation, enrichment); the orchestrator (M8) will call `run_risk`. Re-run it after enrichment or new correlation: a stored score is
  flagged `stale` (with reasons) when the incident's event count or threat-intel report changed afterwards. Correlation re-runs preserve the stored risk (tested).
- **Alerts are not created here.** PRD section 20 incident-level alerts and AC-17 belong to the Response agent (M8); this milestone only provides the risk level they will use.
- **Stored under existing columns + `details["risk"]`**; no schema change. Scoring never touches `status`.
- **Evidence gaps are deterministic** (TI not run / no evidence / no ML finding / no asset context / truncation / synthetic data). AI-identified missing evidence (PRD Agent 4) arrives in M8.

## Dashboard (M9)
```bash
uvicorn app.main:app --reload                        # backend (terminal 1)
streamlit run dashboard/streamlit_app.py             # dashboard (terminal 2); backend URL: WEBINTELX_API_URL env var or .streamlit/secrets.toml (default http://127.0.0.1:8000)
```
Demo path: Create account -> Register website (copy the one-time key / snippet) -> Verify installation -> *Load hero scenario* (SYNTHETIC) -> Dashboard -> **Investigate** -> *Run investigation* (needs `GROQ_API_KEY`; without it the page shows `llm_unavailable` while facts, risk, threat intel and the alert remain).

Layout: `dashboard/viewmodels.py` (pure shaping + escaping, **executed tests**), `dashboard/api_client.py` (httpx wrapper, controlled `ApiError` kinds, never echoes the token), `dashboard/streamlit_app.py` (thin UI). The dashboard talks to the backend over HTTP only; it never opens the database.

How PRD section 19 / 23 show up in the UI:
- **Fact vs inference is visible.** Facts (`Observed fact`, `Derived metric`) and AI output (`AI inference (not proof)`) are separate sections; the timeline and graph label every entry observed / derived indicator / AI inference / platform action; missing evidence is listed with its source (deterministic vs AI agent); recommendations are labelled "needs human approval" and show `executed: False`.
- **Traceability (AC-13).** Every timeline row, graph node and graph edge lists the event ids it rests on (hover text and tables).
- **Untrusted text is displayed as text.** Finding labels, request targets, third-party TI summaries and AI text go through `md_escape` (strips control characters, truncates, escapes Markdown/HTML specials) before `st.markdown`; tables use `st.dataframe`.
- **Measured numbers only.** The reduction funnel shows what is stored (events -> suspicious events -> incidents -> high-risk incidents). The PRD's 10,000 -> 47 -> 8 -> 3 -> 1 demo targets are never displayed. "Suspicious events" reads the first 500 findings and shows a leading "≥" when that page was full.
- **Degraded states** (PRD 33): backend unreachable, expired session, database 503 and LLM unavailable each show a specific banner instead of a stack trace.

### Verification status of M9 (read this)
| Part | Status |
|---|---|
| `dashboard/viewmodels.py` (`tests/test_dashboard_viewmodels.py`, 15 tests on real M8 output shapes) | **Executed**: 15/15 passed; 12 deliberate mutations (no escaping, approval default off, AI missing-evidence dropped, dangling graph edges kept, no-evidence banner removed, closed incidents counted, unscored sorted first, facts mislabelled, funnel showing the 10,000 demo target, input-order graph layout, non-distinct counts) were each caught (one needed a stronger test: a shuffled-input layout check) |
| UI code paths (`tests/test_dashboard_ui_smoke.py`, 6 tests) | **Executed against a STUBBED `streamlit`/`plotly`** and a fake API client with real-shaped data: catches crashes, wrong keys and missing sections (7/7 mutations caught). It does **not** validate that the real Streamlit/Plotly accept the calls |
| `dashboard/api_client.py` (`tests/test_dashboard_api_client.py`) | **Written, NOT executed** (needs `httpx`, unavailable offline in the build sandbox) |
| Real Streamlit rendering, Plotly charts, widget behaviour, layout, the backend round-trip, and M8 API routes | **NOT executed.** Run `python -m pytest -q`, then the demo path above, and report anything that fails |

Things I could not confirm without the real packages (watch for these first): the exact `streamlit`/`plotly` versions that work together (requirements are unpinned lower bounds); I deliberately did not pass `use_container_width` to charts/tables because its deprecation status could not be checked, so charts may render narrower than ideal; `st.container(border=True)` and the `:color[text]` Markdown directive need a reasonably recent Streamlit (>=1.40 assumed).

## M9 assumptions ("PRD does not specify this; using the following implementation assumption...")
- **Streamlit talks to FastAPI over HTTP** (PRD 41 allows deploying them together; the Streamlit Cloud launcher/Dockerfile is M10). No new backend endpoints: KPIs are computed from existing ones.
- **Auth:** the bearer token lives only in `st.session_state` (per browser session, not persisted); expired tokens return the user to the sign-in screen.
- **"Live/near-live event stream"** = the 15 most recent events, refreshed when the page reruns (no websockets or auto-refresh timers).
- **Analyst actions** (accept / reject / further investigate, comments, status) and the **incident report** were a Milestone 10 placeholder in M9; they are real in M10 Part 2 (see *Deploy* and *M10 Part 2 assumptions*). Nothing in the UI executes a response action.
- **Graph layout** is a simple deterministic layered layout (x = backend `layer`), not an interactive graph library: it keeps the view derived from stable structured data (PRD 40 "Visualization instability").
- **pandas is not imported** by the dashboard (lists of dicts go straight to `st.dataframe`); it is installed transitively by Streamlit. The PRD stack table lists pandas for feature engineering, which the backend does without it so far.

## Agents & orchestration (M8)
```
POST /v1/incidents/{id}/investigate     anomaly -> threat intel -> risk -> AI investigation -> AI recommendations -> alert   (never raises; see `status`)
GET  /v1/incidents/{id}/investigation   facts (deterministic) + AI inference (grounded) + validation report + `stale` flag, or {"status": "not_run"}
GET  /v1/incidents/{id}/recommendations proposals only: requires_human_approval=true, executed=false, status="proposed"
GET  /v1/incidents/{id}/alert           incident-level alert (HIGH / CRITICAL by default), or {"status": "no_alert"}
GET  /v1/incidents/{id}/audit           append-only audit trail of AI recommendations / alert changes (analyst decisions arrive in M10)
POST /v1/websites/{id}/investigate?limit=3   highest-risk incidents first (capped by orchestration.max_incidents_per_batch)
GET  /v1/websites/{id}/alerts           prioritised alerts, P1 first
GET  /v1/agents/config                  config + model ids in force (public; booleans only for credentials)
```
Environment: `GROQ_API_KEY`, `LLM_PROVIDER=groq`, `LLM_MODEL` (reasoning), `LLM_FAST_MODEL`, `AGENTS_CONFIG_PATH`. Model **ids are never in YAML** (PRD section 26).

**Which PRD agent is what.** PRD section 13 allows combining roles and the build rules forbid using an LLM for what code does reliably, so only the roles that need reasoning use one:
| PRD agent | Implementation | LLM |
|---|---|---|
| 1 Detection, 2 Anomaly, 3 Attack | `app/agents/deterministic.py` summarises the stored rule / Isolation-Forest findings into each role's PRD output shape | no |
| 4 Investigation | `investigation_agent.py` -> CrewAI agent: hypothesis, supporting evidence, **missing evidence**, alternatives | **yes** (reasoning model) |
| 5 Threat Intelligence | M6 service via `prepare_incident` (providers, No-Evidence Rule) | no |
| 6 Risk Assessment | M7 deterministic scoring ("apply documented scoring logic") | no |
| 7 Response | `response_agent.py` -> CrewAI agent: allow-listed, evidence-cited recommendations | **yes** (reasoning model; per-agent `model_class` is configurable) |
| 8 Reporting (optional) | M10 | - |

**Guarantees (each is unit-tested, and the test was mutation-checked):**
- **Minimised context.** The LLM sees a bounded JSON evidence bundle (`app/agents/evidence.py`): counts, stages, finding summaries, numeric metrics, risk factors, TI statuses. **Never** raw events, payloads/queries, source IPs, user ids, session ids or user agents (entities become counts); remaining strings are control-stripped, character-filtered and truncated, and the data is delimited and declared untrusted (prompt-injection hygiene).
- **Fact vs inference is structural.** `facts` are authored by code; `inference` by the model and labelled `ai_inference`; missing evidence is labelled `missing_evidence`; recommendations `recommendation`. Risk level/score/confidence are never produced or changed by the model.
- **Grounding (PRD section 19).** Every claim and the hypothesis must cite reference labels (`F1`, `S:credential_attack`, `R:authentication`, `TI1`, `T3`, `C:correlation`) that exist in the bundle; labels resolve to concrete event / finding ids. Unsupported claims are **dropped**, nonexistent labels removed and counted (`unsupported_claims_dropped`, `invalid_refs_removed` = the PRD section 39 metrics); a hypothesis with no valid evidence is **rejected**.
- **Confidence.** The model's self-assessed confidence is shown but capped at the deterministic evidence confidence, and labelled "not a probability". Overconfident wording ("definitely", "proves that"...) is flagged, not rewritten.
- **Human approval (AC-19).** Actions must come from an allow-list; `requires_human_approval`, `status` and `executed` are fixed by code (a test shows the model cannot override them). Nothing in this build executes a response action.
- **Alerts (AC-17)** are created by the deterministic risk level, not by the LLM, and are idempotent (same id, `created_at`/`status` kept).
- **Failure handling.** No key / unsupported provider / CrewAI missing -> `llm_unavailable`; rate limit, timeout, auth, provider error -> `llm_error` with a `kind` and a secret-redacted message (not retried); unparseable or ungrounded output -> one more attempt (`llm.max_attempts`), then `invalid_output` / `rejected_ungrounded`. In every case the facts, risk, TI and **alert** remain, the error is shown, and a failed re-run never overwrites a previous successful investigation.
- **Memory (PRD section 29).** Short-term = the in-process evidence bundle for one run; persistent = stored incident data (`details["investigation" | "recommendations" | "alert" | "agent_run" | "audit"]`). The LLM has no memory, history or vector store (`Crew(memory=False)`).

### Verification status of M8 (read this)
| Part | Status |
|---|---|
| Config, evidence bundle, grounding validators, alerting, orchestrator core, persistence merge, staleness (`tests/test_agents_core.py`, 35 tests) | **Executed** in the build sandbox: 35/35 passed; 8 deliberate mutations (leak IPs, let the model set `executed`, keep unsupported claims, alert on every level, overwrite a good result with a failed one, swallow provider errors, stop filtering identifying keys, stop capping confidence) were each caught |
| API routes, DB wrapper (`prepare_incident`, `_timeline`, `run_investigation*`), timeline `ai_inference` entry, `tests/test_investigation_api.py`, edits to M7 tests (version string) | **Written but NOT executed**: the build sandbox had no network, so FastAPI / SQLAlchemy / pytest could not be installed. Run `python -m pytest -q` before relying on them |
| Live Groq call through CrewAI (`app/crew/crew.py`) | **NOT executed.** API usage (`Agent`/`Task`/`Crew`/`Process`, `LLM(model="groq/<id>", api_key=...)`, `CrewOutput.raw`, the `crewai[litellm]` extra) was checked against the CrewAI docs on 2026-10-04 but never run; the exact `LLM(...)` keyword set (`timeout`, `max_tokens`) and CrewAI/FastAPI/pydantic version compatibility are unverified |

Model availability (checked 2026-10-04 against Groq's docs): `llama-3.1-8b-instant` and `llama-3.3-70b-versatile` were deprecated on 2026-08-16 (Groq's replacements: `openai/gpt-oss-20b` / `openai/gpt-oss-120b` or `qwen/qwen3.6-27b`), so the defaults are `openai/gpt-oss-120b` (reasoning) and `openai/gpt-oss-20b` (fast). Free-tier limits quoted by third-party sites (about 30 requests/min and 8K tokens/min on `gpt-oss-120b`) are **not** from Groq's own page; the context budget (`context.max_chars`, 9000) and the reduced Response-Agent context exist because those limits are small. Confirm the numbers in your own console.

## M8 assumptions ("PRD does not specify this; using the following implementation assumption...")
- **Supervisor = our deterministic orchestrator**, running one single-agent CrewAI crew per LLM role and passing only validated structured data between them. CrewAI's hierarchical manager-LLM is not used (extra calls on a small free-tier budget, non-determinism, and unvalidated text would become the system of record, which PRD section 14 forbids).
- **Only two roles use an LLM** (table above). Agents 1-3 are deterministic roles over M3/M4 output; this keeps PRD section 40's "preprocess first, invoke LLM only for high-value steps".
- **JSON + our own validation instead of `output_pydantic`**, because evidence references must be checked and `output_pydantic` has provider-specific rough edges. Prompts contain no `{placeholders}` and `kickoff()` gets no `inputs`, so CrewAI interpolation cannot mangle them (if your CrewAI version still complains about braces, report it).
- **On demand, not per ingest** (like ML / correlation / TI / risk): an LLM call per ingested batch would be slow and costly. `investigate` runs the deterministic prerequisites itself, so one call produces a complete, consistent result.
- **Allow-listed action vocabulary** (10 actions in `config/agents.yaml`) is an implementation choice; the PRD asks only for "defensive recommendations" with human approval.
- **Alert level threshold** = HIGH and CRITICAL (AC-17 says "high-risk"); configurable. The alert is stored in `incident.details["alert"]` (the PRD DB design has no alerts table; no schema change). Alert acknowledgement / status changes arrive with the lifecycle in M10.
- **`incident.status` is not changed** by M8 (DETECTED -> INVESTIGATING etc. is M10).
- **Audit trail** = append-only list in `details["audit"]` (last 50 entries) covering AI recommendations and alert changes (PRD sections 33, 35). It is not tamper-proof storage.
- **A failed run never overwrites a previous successful investigation** (the failure is recorded in `agent_run` and `audit`).
- **Hypothesis confidence** shown = min(model self-assessment, deterministic evidence confidence); the raw model value is kept as `model_confidence`.

## Test the M8 flow (needs the real dependencies; a free Groq key for the live step)
```bash
pip install -r requirements.txt
python -m pytest -q                                   # full suite incl. tests/test_agents_core.py + tests/test_investigation_api.py (fake LLM, no network)
# live demo: put GROQ_API_KEY in .env, then
uvicorn app.main:app --reload                         # register -> create website -> POST /demo/load {"scenario":"hero_credential_abuse"}
# POST /v1/incidents/{id}/investigate   then GET .../investigation, .../recommendations, .../alert, .../timeline
```

## Threat intelligence (M6)
```
GET  /v1/threat-intel/providers                      providers active + config in force (public; booleans only, never a key)
POST /v1/incidents/{id}/threat-intel                 extract indicators -> enrich -> store report (idempotent; replaces the previous one)
GET  /v1/incidents/{id}/threat-intel                 stored report, or {"status": "not_run"}
POST /v1/websites/{id}/threat-intel/enrich?limit=10  enrich the website's most recent incidents (demo / orchestrator convenience)
```
Environment (PRD section 41): `TI_PROVIDER` = `otx` | `synthetic_demo` | empty, `TI_API_KEY` (the OTX key), optional `NVD_API_KEY`.
Knobs live in `config/threat_intel.yaml` (a bad file falls back to defaults and is reported in `/health` -> `threat_intel_config`).

| Provider | Covers | Needs | Status of verification |
|---|---|---|---|
| `otx` (AlienVault OTX) | IPv4/IPv6, domain | free OTX account key in `TI_API_KEY` | endpoint/header verified from public docs on 2026-10-03; **not exercised live from the build sandbox** |
| `nvd_cve` (NVD CVE API 2.0) | valid CVE ids | nothing (public limit 5 req / 30 s); optional `NVD_API_KEY` (50 req / 30 s) | same: documented endpoint, mocked in tests |
| `mitre_attack` (local table) | technique ids from findings | nothing | hand-maintained subset of the 3 techniques the rules use |
| `synthetic_demo` | the 3 demo attacker IPs | `TI_PROVIDER=synthetic_demo` | invented records, flagged `synthetic: true`, summary starts "SYNTHETIC DEMO DATA" |

AbuseIPDB is **not** implemented (project decision); adding it is one new `Provider` subclass.

How it works:
1. **Indicators** come only from what the incident actually contains: its source IPs, valid `CVE-YYYY-NNNN+` ids in request targets,
   technique ids already attached to its findings, and (off by default) SDK referrer hosts. No "technology signal" is extracted because
   the platform collects no technology/version data. Each indicator keeps the event/finding ids it came from.
2. **Privacy gate:** private, loopback, reserved, documentation-range and privacy-masked IPs (`truncate`/`hash` modes) are never sent to an
   external provider (`not_applicable`). Only the indicator value is sent; the API key travels in a header and is never logged or returned.
3. **No-Evidence Rule:** every non-finding result says "No threat-intelligence evidence was found / is available" and that absence is neither
   safe nor malicious. Statuses: `evidence_found | no_evidence | not_configured | not_applicable | rate_limited | timeout | error`.
4. **Reliability:** each lookup is isolated; a failure, timeout or rate limit is shown per indicator, the run is `partial`, and the rest of the
   investigation continues. `run_enrichment` never raises; a total time budget (`deadline_s`) skips remaining network lookups.
5. Third-party text (pulse names, CVE descriptions) is truncated and control-stripped; the dashboard (M9) must still render it as text.

### Measured on the synthetic demo data (3 incidents), M6 tests use mocked HTTP only
| | result |
|---|---|
| `synthetic_demo` | 1 / 2 / 4 indicators per incident (IPs + MITRE techniques), all `ok`, `contains_synthetic: true` |
| Real `httpx` against a host the sandbox blocks (OTX) | every IP reported `error`, run `partial`, MITRE context still returned, incident unaffected |
| Documentation-range IPs with `TI_PROVIDER=otx` | `not_applicable`, **zero** outbound requests (tested) |

**Read this with care:** no real threat-intelligence provider was queried successfully during development. Response parsing is written from
the providers' public documentation and verified only against mocked responses; confirm with your own key before relying on it. The demo's
documentation-range IPs would correctly return no evidence from any real provider, which is why `synthetic_demo` exists (PRD section 40).
Synthetic results are flagged and risk scoring (M7) excludes them from real severity.

## M6 assumptions ("PRD does not specify this; using the following implementation assumption...")
- **Providers chosen:** OTX + NVD + local MITRE (+ synthetic demo). The PRD only asks for providers available within acceptable free/low-cost limits.
- **On demand, not per ingest:** like ML and correlation; the orchestrator (M8) will call `run_enrichment`. One run replaces the previous report.
- **`TI_PROVIDER` means the IP/domain reputation provider.** CVE and MITRE lookups are controlled in the YAML (`nvd.enabled`, `mitre.enabled`).
- **Choosing a provider is consent to share the incident's source IP with that third party**; non-public and masked IPs are never shared.
- **Cache:** in-process TTL (`cache_ttl_s`, default 3600) for real answers only; never failures; lost on restart.
- **Stored under `incident.details["threat_intel"]`:** a key correlation preserves on re-runs (tested). No schema change.
- **MITRE table is a hand-maintained subset** (T1110, T1078, T1190); an id outside it yields an explicit no-mapping result, not a guess.
- **Timeline:** one `system` entry "Threat intelligence enrichment: N indicators checked" (labelled when synthetic data is included).

## M5 assumptions ("PRD does not specify this; using the following implementation assumption...")
- **Failed logins never create `same_user` links.** They carry the *attempted* account, not an authenticated principal; otherwise one
  guessed account would pull that user's genuine sessions into an attack incident (tested, and mutation-checked).
- **Temporal proximity is a gate and a strength factor**, not a separate relationship type.
- **Link direction:** `event_id` = earlier event, `related_event_id` = later event. One record per (pair, relationship type).
- **Incident creation happens here (DETECTED, risk null)** rather than in M10, because the PRD pipeline ends in an "Incident Object" and
  the schema already allows it (`correlations.incident_id` nullable, `incidents.details`). Lifecycle transitions, feedback and
  reports are still M10.
- **Matching incidents across runs** is by event overlap, so an incident keeps its id, status, risk and feedback while its cluster grows;
  correlation overwrites only the `details` keys it owns. An incident whose cluster vanished is deleted only if untouched (`DETECTED`,
  no feedback); otherwise it is kept and flagged `details.stale`.
- **On demand, not per ingest batch** (like the ML model): clusters change as data streams in; the orchestrator (M8) and the demo
  loader call it. Whole-website recompute over `lookback_hours` (72) is fine for SQLite/MVP scale and would need windowing at scale.
- **Shared IPs** (NAT, proxies, `IP_PRIVACY_MODE=truncate`) can group unrelated users; every incident states this in `limitations`.
- **Link cap:** `max_links_per_cluster` (3000) keeps the strongest evidence and always the attack sequence; `links_truncated` says so.

## M4 assumptions ("PRD does not specify this; using the following implementation assumption...")
- **Unit of analysis = session** (derived `SessionContext`, PRD Agent 2 input "session features, request rates, endpoint usage").
- **Trained per website on its own sessions, on demand** - not on every ingest batch (refitting per 20-event batch would make scores
  drift while data streams in) and not from a shipped pre-trained file. The orchestrator (M8) will call it. The baseline is
  *contaminated* by design: it contains whatever sessions exist, including malicious ones (stated in every finding's `limitations`).
- **Minimum baseline** `min_training_sessions: 50`; below it the status is `insufficient_baseline` and no ML findings are produced.
- **Two-signal flag and its constants** (0.65 / 8.0 / per-feature floors) are heuristics tuned on synthetic data and fully configurable.
- **Finding anchor** = the session's first event; every session event is cited in `event_ids`. `finding_type="ml_anomaly"`, `rule_id="M-ANOM-001"`.
- **Re-analysis** deletes/recreates only `anomaly_model` findings for the analysed events; `rule_engine` findings are never touched.
- **Dependencies:** `numpy`, `scikit-learn` added; `pandas` is deferred until something actually needs it.

## Documented assumptions ("PRD does not specify this; using the following implementation assumption...")
- **Auth mechanism:** stdlib scrypt password hashes + opaque bearer tokens (SHA-256 stored). A managed IdP is the production path.
- **Ingestion key:** `wix_pk_…`, header `X-WebIntelX-Key`, only its SHA-256 is stored, shown once. Treated as a limited-scope identifier.
- **Origin check:** enforced only when a browser sends `Origin`; allowed hosts = registered domain. Requests without `Origin` (server-side senders) are allowed; the key is then the only control.
- **Rotation:** immediate cut-off of the previous active key (no grace period). Rate limit is in-process (single-process MVP).
- **IP handling:** `IP_PRIVACY_MODE=none|truncate|hash`, default `none` (demo data is synthetic). `truncate`/`hash` reduce threat-intel usefulness. Email-like user ids are replaced by stable pseudonyms.
- **raw_data:** stored only when a website sets `retain_raw_data`, and even then secret-named keys are redacted. The API never returns `raw_data`.
- **Extra schema fields** (`accounts`, `auth_tokens`, `events.is_synthetic`, `events.received_at`, `incidents.details`, `correlations.website_id`) are listed in `app/database/models.py`. No migrations: SQLite DB is recreated if the schema changes during the hackathon.
- **Project layout:** added `app/pipeline/` (validation/normalisation/masking) which the PRD tree does not list. `.streamlit/secrets.toml` is git-ignored; use `secrets.toml.example`.
- **Dependencies:** `requirements.txt` grows per milestone; CrewAI is added at the agents milestone and its Python/Groq compatibility will be verified then.

## M3 assumptions ("PRD does not specify this; using the following implementation assumption...")
- **No sessions table:** the PRD schema has none, so session context is *derived on demand* from events (single source of truth). Key =
  `session_id`, else `ip:<source_ip>` (marked `inferred`), else `unknown`. Linking a pre-login and post-login session is correlation (M5).
- **Findings by `rule_engine`:** deterministic rules write to `findings` with `agent_name="rule_engine"`; LLM agents (M8) will write under
  their own names. Re-analysis deletes/recreates **only** `rule_engine` findings for the analysed events (idempotent).
- **Incremental detection:** after each ingested batch, rules re-run over *all* events (within `analysis_window_hours`, default 24) of the
  touched sources/sessions, so windowed rules see the full picture. Failure never fails ingestion (`AUTO_DETECT_ON_INGEST=false` disables).
  Verified: batch-by-batch detection ends identical to a full analysis.
- **Suspicious event** = an event that carries a finding **or** is cited as evidence by one (`suspicious_events`); `finding_anchor_events`
  counts only events a finding is attached to.
- **Pattern detection sees only path + query** (no bodies/headers - the platform does not collect them); patterns live in code
  (`app/detection/patterns.py`), thresholds in YAML. MITRE ATT&CK IDs used: T1110, T1078, T1190 (context labels only).
- **IP privacy modes:** with `IP_PRIVACY_MODE=truncate`, unrelated users in one /24 are grouped as one source (can over-merge); `hash` is exact.
- **Stored attack payloads:** finding evidence may contain the (masked) request target, i.e. attacker-controlled text. The dashboard (M9) must render it as text, never HTML.
- **Bug fixed from M2:** `Event.event_id` was only assigned at DB flush, so the demo loader's ground-truth `labels` collapsed to one key.
  IDs are now assigned when the event is built (regression-tested). The M2 test asserting `features is None` was updated (features now exist).

## Demo data (all SYNTHETIC)
`python -m app.demo.generator` regenerates `data/normal_traffic.csv` (9,063 events, incl. 8 benign mistyped-password
users and a legitimate admin), `data/attack_scenarios.csv` (455 events: hero credential-abuse chain 144, injection probe 11,
scraper bot 300) and `data/sample_events.json` (12 events, one per type, POSTable to `/v1/ingest`).
Fixed seed; RFC 5737 documentation IPs only; `scenario`/`label` ground-truth columns are never ingested.
These counts are what the generator produces; the PRD's 10,000 → 47 → 8 → 3 → 1 funnel is a *target* and is not claimed yet.
Load via API scenarios: `all`, `normal`, `bot_scraper`, `injection_probe`, `hero_credential_abuse`.

## SDK assumptions ("PRD does not specify this; using the following implementation assumption...")
- Sent: page views (path only; query string only with `data-include-query="true"`), per-page aggregated interaction *counts*
  (clicks, key events, scrolls, mouse moves, dwell), load time, referrer host, `navigator.webdriver`, language, viewport, UA.
  Never sent: form values, key identities, element text, cookies. `WebIntelX.identify(id)` is opt-in for authorised user ids.
- Transport: `fetch` + `keepalive` (not `sendBeacon`, which cannot carry the key header), batches of 20, flush every 5 s and on page hide,
  bounded queue, circuit breaker (5 failures -> 60 s pause), all errors swallowed. HTTP method/status are not observable from the
  browser SDK, so only server-side sources (auth/api/waf/app) carry status codes.
- Source IP for SDK events is the server-observed client address (set `TRUST_FORWARDED_FOR=true` only behind a trusted proxy).
- Demo IPs are RFC 5737 test ranges, so a real threat-intel provider would correctly have *no evidence* for them; M6 therefore never sends them out and offers the labelled `synthetic_demo` provider for demos.

## Milestone plan
1 Foundation & ingestion ✅ · 2 Demo data + browser SDK ✅ · 3 Features, sessionisation, rule detection ✅ ·
4 ML anomaly (Isolation Forest) ✅ · 5 Correlation engine + attack graph ✅ · 6 Threat-intel adapters ✅ ·
7 Risk scoring (config-driven) ✅ · 8 CrewAI agents + orchestration + alerts + recommendations ✅ (see *Verification status* below) · 9 Streamlit dashboard + investigation page ✅ (written; UI not yet run with real Streamlit - see *Verification status of M9*) ·
10 Incident lifecycle, feedback, report ✅ (Part 1 backend, executed) + dashboard wiring, Dockerfile, deploy notes ✅ (Part 2, tested: 486 passed + real Streamlit/backend flow; Docker build and live Groq not run)
