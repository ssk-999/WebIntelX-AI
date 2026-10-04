"""Agent 4 - Investigation Agent (PRD section 14). LLM-backed: builds a hypothesis, supporting evidence, missing evidence.

Input: the minimised evidence bundle (seed + correlated events summarised by the deterministic engine).
Output: grounded structured hypothesis; claims without existing evidence refs are dropped (PRD section 19).
"""
from __future__ import annotations

from typing import Any, Mapping

from app.agents.base import AgentRunResult, call_agent
from app.agents.evidence import EvidenceBundle
from app.agents.validation import ground_investigation
from app.crew.crew import LLMRunner
from app.crew.tasks import investigation_task

AGENT = "investigation_agent"


def run_investigation_agent(runner: LLMRunner, bundle: EvidenceBundle, cfg: Mapping[str, Any], risk_confidence: float | None) -> AgentRunResult:
    spec = investigation_task(bundle, cfg)
    return call_agent(AGENT, runner, spec, model_class=cfg["investigation"]["model_class"], max_attempts=cfg["llm"]["max_attempts"],
                      ground=lambda obj: ground_investigation(obj, bundle, cfg, risk_confidence))
