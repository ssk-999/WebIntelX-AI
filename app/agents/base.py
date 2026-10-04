"""Shared plumbing for the agent roles (PRD section 14): one call -> parse -> ground -> (bounded) retry, with a structured result.

Statuses: ok | llm_unavailable | llm_error | invalid_output | rejected_ungrounded. Nothing here raises: a failed LLM step must
fail safely and expose the error clearly (build prompt: "LLM unavailable -> investigation should fail safely").
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

from app.agents.validation import AgentOutputError, extract_json
from app.crew.crew import LLMCallError, LLMRunner, LLMUnavailable
from app.crew.tasks import TaskSpec


@dataclass
class AgentRunResult:
    agent: str
    status: str
    llm_used: bool = True
    model: str | None = None
    attempts: int = 0
    duration_ms: int = 0
    result: dict[str, Any] | None = None
    error: dict[str, Any] | None = None           # {code, message, kind?}
    validation: dict[str, Any] = field(default_factory=dict)

    def step(self) -> dict[str, Any]:
        """Compact record kept in `details["agent_run"]` (no model output text)."""
        return {"agent": self.agent, "status": self.status, "llm_used": self.llm_used, "model": self.model, "attempts": self.attempts,
                "duration_ms": self.duration_ms, "error": self.error, "validation": self.validation}


def call_agent(agent: str, runner: LLMRunner, spec: TaskSpec, *, model_class: str, max_attempts: int,
               ground: Callable[[Mapping[str, Any]], dict[str, Any]]) -> AgentRunResult:
    t0 = time.monotonic()
    res = AgentRunResult(agent=agent, status="invalid_output", model=None)
    try:
        res.model = runner.model_for(model_class)
    except Exception:  # noqa: BLE001
        res.model = None
    if not getattr(runner, "configured", True):
        res.status, res.error = "llm_unavailable", {"code": "llm_unavailable", "message": "No LLM is configured (check GROQ_API_KEY and LLM_PROVIDER); the AI step was not run."}
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
    last: AgentOutputError | None = None
    for attempt in range(1, max_attempts + 1):
        res.attempts = attempt
        try:
            out = runner.run(spec, model_class=model_class)
            res.model = out.model or res.model
            res.result = ground(extract_json(out.text))
            res.status, res.error, res.validation = "ok", None, dict(res.result.get("validation") or {})
            break
        except LLMUnavailable as exc:
            res.status, res.error = "llm_unavailable", {"code": "llm_unavailable", "message": str(exc)[:300]}
            break
        except LLMCallError as exc:              # auth / rate limit / timeout / provider error: retrying wastes tokens, so stop
            res.status, res.error = "llm_error", {"code": "llm_error", "kind": exc.kind, "message": exc.message}
            break
        except AgentOutputError as exc:          # unparseable or ungrounded output: one more attempt is allowed by config
            last = exc
            res.status, res.error, res.validation = exc.code, {"code": exc.code, "message": exc.message}, dict(exc.report)
        except Exception as exc:  # noqa: BLE001 - defensive: an adapter bug must not crash the investigation
            res.status, res.error = "llm_error", {"code": "llm_error", "kind": "error", "message": f"{type(exc).__name__}: {str(exc)[:200]}"}
            break
    if res.status == "ok":
        res.validation["attempts"] = res.attempts
    elif last is not None and res.status == last.code:
        res.error["message"] = f"{last.message} (after {res.attempts} attempt(s))"
    res.duration_ms = int((time.monotonic() - t0) * 1000)
    return res
