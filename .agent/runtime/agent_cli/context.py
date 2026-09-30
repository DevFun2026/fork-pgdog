"""Offline context planning estimates, never provider billing measurements."""

from dataclasses import dataclass


ESTIMATOR = "utf8-div3-v1"


def estimate_tokens(text: str | bytes) -> int:
    data = text.encode("utf-8") if isinstance(text, str) else text
    return (len(data) + 2) // 3


@dataclass(frozen=True)
class ContextProfile:
    memory_tokens: int
    review_tokens: int
    records: int


PROFILES = {
    "light": ContextProfile(600, 8000, 3),
    "standard": ContextProfile(1200, 32000, 5),
    "deep": ContextProfile(2400, 64000, 10),
}


def report(text: str | bytes, budget: int) -> dict[str, object]:
    data = text.encode("utf-8") if isinstance(text, str) else text
    estimate = estimate_tokens(data)
    return {"bytes": len(data), "estimated_tokens": estimate,
            "estimated_token_budget": budget, "estimator": ESTIMATOR,
            "within_budget": estimate <= budget}
