"""Agent 7 - Response Agent (PRD section 14). LLM-backed: translates the validated investigation + risk into defensive recommendations.

Recommendations are proposals only (PRD section 21, AC-19): the validator forces `requires_human_approval=True`, `status="proposed"`,
`executed=False`, and restricts `action` to the configured allow-list. Nothing in this build executes a response action.
"""
from __future__ import annotations

from typing import Any, Mapping

from app.agents.base import AgentRunResult, call_agent
from app.agents.evidence import EvidenceBundle
from app.agents.validation import ground_recommendations
from app.crew.crew import LLMRunner
from app.crew.tasks import response_task

AGENT = "response_agent"


def run_response_agent(runner: LLMRunner, bundle: EvidenceBundle, investigation: Mapping[str, Any], cfg: Mapping[str, Any]) -> AgentRunResult:
    spec = response_task(bundle, investigation, cfg)
    return call_agent(AGENT, runner, spec, model_class=cfg["response"]["model_class"], max_attempts=cfg["llm"]["max_attempts"],
                      ground=lambda obj: ground_recommendations(obj, bundle, cfg))
