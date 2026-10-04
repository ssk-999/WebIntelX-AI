"""LLM adapter: CrewAI agents on a Groq-compatible model (PRD sections 13, 26, 27, 40).

Design decisions (PRD does not specify these; using the following implementation assumptions):
  * The *supervisor* is our deterministic orchestrator (`orchestration.py`). It runs one small single-agent, single-task CrewAI crew per LLM
    role and passes only validated, structured data between them. CrewAI's hierarchical manager-LLM is not used: it would add LLM calls
    (free-tier token limits), non-determinism and a path for unvalidated text to become the system of record (PRD section 14).
  * CrewAI is imported lazily, so the rest of the platform, the tests and the deterministic pipeline work without it (PRD section 40 fallback).
  * Structured output is obtained by asking for JSON and validating it ourselves (`validation.py`), not through `output_pydantic`, because we must
    also check evidence references, and `output_pydantic` has known provider-specific rough edges.
  * Crew memory is off: no unrestricted LLM memory (PRD section 29). Delegation is off. Telemetry export is disabled.
Verified against the CrewAI docs (Agent/Task/Crew/Process, `LLM(model="groq/<id>", api_key=...)`, `CrewOutput.raw`) on 2026-10-04; NOT executed
in the build sandbox (no network), so a live Groq call is untested.
"""
from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass
from typing import Any, Protocol

from app.config import Settings, get_settings
from app.agents.config import AgentsConfig, get_agents_config
from app.crew.tasks import TaskSpec

log = logging.getLogger("webintelx.crew")


class LLMUnavailable(Exception):
    """No usable LLM (no key, provider not supported, CrewAI not installed)."""


class LLMCallError(Exception):
    """The model call failed. `kind`: rate_limit | timeout | auth | error. The message never contains secrets."""

    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind, self.message = kind, message


@dataclass(frozen=True)
class LLMResult:
    text: str
    model: str


class LLMRunner(Protocol):
    configured: bool

    def model_for(self, model_class: str) -> str: ...

    def run(self, spec: TaskSpec, *, model_class: str) -> LLMResult: ...


def classify_error(exc: BaseException, secret: str = "") -> LLMCallError:
    msg = f"{type(exc).__name__}: {exc}"
    if secret:
        msg = msg.replace(secret, "[redacted]")
    msg = re.sub(r"gsk_[A-Za-z0-9]+", "[redacted]", msg)[:300]
    low = msg.lower()
    if "rate" in low and "limit" in low or "429" in low or "tokens per minute" in low:
        return LLMCallError("rate_limit", "The LLM provider rate-limited the request (free-tier limits are small). Wait a minute and re-run. " + msg)
    if "timeout" in low or "timed out" in low:
        return LLMCallError("timeout", "The LLM request timed out. " + msg)
    if "401" in low or "invalid api key" in low or "authentication" in low or "unauthorized" in low:
        return LLMCallError("auth", "The LLM provider rejected the credentials; check GROQ_API_KEY. " + msg)
    if "model" in low and ("not found" in low or "decommissioned" in low or "does not exist" in low or "deprecated" in low):
        return LLMCallError("error", "The configured model is not available on the provider; check LLM_MODEL / LLM_FAST_MODEL. " + msg)
    return LLMCallError("error", msg)


class CrewAIRunner:
    """Runs one agent + one task through CrewAI and returns the raw text (validated later by `validation.py`)."""

    def __init__(self, settings: Settings | None = None, cfg: AgentsConfig | None = None):
        self.settings = settings or get_settings()
        self.cfg = cfg or get_agents_config()

    @property
    def configured(self) -> bool:
        return self.settings.llm_provider.lower() == "groq" and bool(self.settings.groq_api_key)

    def model_for(self, model_class: str) -> str:
        return self.settings.llm_fast_model if model_class == "fast" else self.settings.llm_model

    def run(self, spec: TaskSpec, *, model_class: str) -> LLMResult:
        s = self.settings
        if s.llm_provider.lower() != "groq":
            raise LLMUnavailable(f"LLM_PROVIDER '{s.llm_provider}' is not supported in this build; only 'groq' is implemented.")
        if not s.groq_api_key:
            raise LLMUnavailable("GROQ_API_KEY is not set; the AI investigation cannot run.")
        os.environ.setdefault("OTEL_SDK_DISABLED", "true")          # no telemetry export from the framework
        try:
            from crewai import LLM, Agent, Crew, Process, Task      # lazy import
        except ImportError as exc:
            raise LLMUnavailable("CrewAI is not installed (pip install 'crewai[litellm]').") from exc
        model = self.model_for(model_class)
        lc = self.cfg["llm"]
        try:
            llm = LLM(model=f"groq/{model}", api_key=s.groq_api_key, temperature=lc["temperature"],
                      max_tokens=lc["max_output_tokens"], timeout=lc["timeout_s"])
            agent = Agent(role=spec.role, goal=spec.goal, backstory=spec.backstory, llm=llm, allow_delegation=False, verbose=False, max_iter=3)
            task = Task(description=spec.description, expected_output=spec.expected_output, agent=agent)
            crew = Crew(agents=[agent], tasks=[task], process=Process.sequential, memory=False, verbose=False)
            out = crew.kickoff()                                    # no `inputs`: nothing in the prompt is template-interpolated
        except Exception as exc:  # noqa: BLE001 - classify and surface; never leak the key
            raise classify_error(exc, s.groq_api_key) from None
        text = getattr(out, "raw", None) or str(out)
        return LLMResult(text=text, model=model)


def get_runner() -> LLMRunner:
    """Factory used by the API; tests patch it with a fake runner."""
    return CrewAIRunner()
