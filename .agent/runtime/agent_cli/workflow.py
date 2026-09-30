from __future__ import annotations

from enum import Enum


class WorkflowState(str, Enum):
    DISCOVERED = "DISCOVERED"
    DESIGNED = "DESIGNED"
    PLAN_APPROVED = "PLAN_APPROVED"
    IMPLEMENTING = "IMPLEMENTING"
    LOCALLY_VERIFIED = "LOCALLY_VERIFIED"
    CODE_REVIEWED = "CODE_REVIEWED"
    CROSS_REVIEWED = "CROSS_REVIEWED"
    SECURITY_CLEARED = "SECURITY_CLEARED"
    RELEASE_READY = "RELEASE_READY"


ORDERED_STATES = tuple(WorkflowState)


def workflow_guide(task: str) -> dict[str, object]:
    """Planning guidance only: never an alternate merge/release authorization."""
    guides = {
        "content": ("light", "Inline scope and checks; no standalone spec/plan for a small content-only edit.",
                    ["documentation-sync", "verification"]),
        "behavior": ("standard", "Focused plan, regression test, implementation, targeted verification and review. Use a versioned plan for multi-step changes.",
                     ["writing-plan", "test-driven-development", "code-review", "verification"]),
        "interface": ("standard", "Load only the UX/UI skill for the current phase: discovery, design system, implementation or review. Reuse approved artifacts; no mandatory four-step ceremony for a small UI edit. Apply behavior/architecture/security planning for the actual impact.",
                      ["ux-discovery", "ui-design-system", "frontend-design", "ux-ui-review", "verification"]),
        "architecture": ("deep", "Versioned spec/plan and consequential decisions, architecture/security impact, implementation and full review.",
                         ["writing-spec", "writing-plan", "architecture-design", "threat-modeling", "code-review", "verification"]),
        "security": ("deep", "Versioned plan, threat model, security review and required independent clearance.",
                     ["writing-plan", "threat-modeling", "security-review", "code-review", "verification"]),
    }
    if task not in guides:
        raise ValueError("unknown workflow task")
    profile, planning, skills = guides[task]
    return {"task": task, "context_profile": profile, "planning": planning,
            "skills_on_demand": skills, "merge_release_gates_unchanged": True,
            "escalate_when": "Behavior, policy, authorization, dependencies, deployment or trust boundaries change; task labels do not override impact."}


class TransitionError(ValueError):
    """Raised when a workflow attempts to skip a required forward state."""


def transition(current: WorkflowState, target: WorkflowState) -> WorkflowState:
    current_index = ORDERED_STATES.index(current)
    target_index = ORDERED_STATES.index(target)
    if target_index > current_index + 1:
        raise TransitionError(f"cannot skip from {current.value} to {target.value}")
    return target
