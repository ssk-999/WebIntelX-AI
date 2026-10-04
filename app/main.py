"""WebIntelX AI backend entry point.   Run:  uvicorn app.main:app --reload"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app.api import anomaly, auth, correlation, demo, detection, incidents, ingestion, investigation, lifecycle, risk, threat_intel, websites
from app.sdk.snippet import SDK_PATH, SDK_URL_PATH
from app.config import get_settings
from app.database import database
from app.agents.config import get_agents_config
from app.correlation.config import get_correlation_config
from app.detection.config import get_detection_config
from app.ml.config import get_anomaly_config
from app.risk.config import get_risk_config
from app.threat_intel.config import get_ti_config
from app.threat_intel.providers import build_providers

APP_VERSION = "0.10.0"
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("webintelx")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    s = get_settings()
    if s.using_dev_salt:
        log.warning("PRIVACY_SALT is not set; using an insecure development salt.")
    database.init_db()
    yield


app = FastAPI(title="WebIntelX AI", version=APP_VERSION, lifespan=lifespan)

# CORS: the browser SDK posts cross-origin. Auth is by header key (no cookies), so a
# wildcard origin is safe here; per-website Origin enforcement happens in /v1/ingest.
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"], allow_headers=["*"],
)


@app.exception_handler(SQLAlchemyError)
async def db_error_handler(_request: Request, exc: SQLAlchemyError):
    log.error("database error: %s", type(exc).__name__)  # never log SQL parameters
    return JSONResponse(status_code=503, content={"detail": "Database unavailable"})


@app.get("/health", tags=["system"])
def health() -> dict:
    s = get_settings()
    try:
        with database.engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        db_ok = True
    except SQLAlchemyError:
        db_ok = False
    # Booleans only; secret values are never exposed.
    return {
        "status": "ok" if db_ok else "degraded",
        "version": APP_VERSION,
        "database": "ok" if db_ok else "unavailable",
        "llm_provider": s.llm_provider,
        "llm_model": s.llm_model,
        "llm_configured": s.llm_configured,
        "threat_intel_configured": build_providers(s, get_ti_config()).reputation is not None,
        "threat_intel_provider": s.ti_provider or None,
        "threat_intel_config": get_ti_config().status,
        "ip_privacy_mode": s.ip_privacy_mode,
        "detection_config": get_detection_config().status,
        "anomaly_config": get_anomaly_config().status,
        "correlation_config": get_correlation_config().status,
        "risk_config": get_risk_config().status,
        "agents_config": get_agents_config().status,
        "llm_fast_model": s.llm_fast_model,
    }


@app.get(SDK_URL_PATH, tags=["sdk"], include_in_schema=False)
def serve_sdk():
    # Served with permissive CORS (middleware) so the integrity-checked <script crossorigin> load works.
    return FileResponse(SDK_PATH, media_type="application/javascript", headers={"Cache-Control": "public, max-age=300"})


app.include_router(auth.router)
app.include_router(websites.router)
app.include_router(ingestion.router)
app.include_router(detection.router)
app.include_router(anomaly.router)
app.include_router(correlation.router)
app.include_router(threat_intel.router)
app.include_router(risk.router)
app.include_router(investigation.router)
app.include_router(lifecycle.router)
app.include_router(incidents.router)
app.include_router(demo.router)
