"""
LLM Abstraction Layer (BYOLLM).

⚠️  STUB — بلال يكمل التنفيذ الكامل في Sprint 3.
"""
from schemas.decision_result import SummaryResult


async def summarize(session_data: dict) -> SummaryResult:
    """Summarize a completed Cowrie session using the configured LLM."""
    return SummaryResult(
        text=None,
        provider="stub",
        model="stub",
        status="DISABLED",
    )
