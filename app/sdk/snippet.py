"""SDK installation snippet (FR-04) with Subresource Integrity for secure delivery (PRD risk table)."""
from __future__ import annotations

import base64
import hashlib
from pathlib import Path

SDK_PATH = Path(__file__).resolve().parents[2] / "sdk" / "web-intelx-ai.js"
SDK_URL_PATH = "/sdk/web-intelx-ai.js"
PLACEHOLDER_KEY = "YOUR_INGESTION_KEY"


def sdk_integrity() -> str:
    digest = hashlib.sha384(SDK_PATH.read_bytes()).digest()
    return "sha384-" + base64.b64encode(digest).decode()


def build_snippet(base_url: str, ingestion_key: str = PLACEHOLDER_KEY) -> str:
    base = base_url.rstrip("/")
    return (
        f'<script src="{base}{SDK_URL_PATH}"\n'
        f'        integrity="{sdk_integrity()}" crossorigin="anonymous" defer\n'
        f'        data-key="{ingestion_key}"\n'
        f'        data-endpoint="{base}/v1/ingest"></script>'
    )
