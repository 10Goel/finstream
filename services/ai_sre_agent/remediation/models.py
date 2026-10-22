"""Safe remediation domain models for FinStream AI-SRE."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class RemediationActionType(str, Enum):
    """Approved categories of AI-SRE remediation activity."""

    ROLLING_RESTART = "ROLLING_RESTART"
    INVESTIGATE_DEPENDENCIES = "INVESTIGATE_DEPENDENCIES"


class RemediationRiskLevel(str, Enum):
    """Operational risk associated with a remediation candidate."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


@dataclass(frozen=True, slots=True)
class RemediationCandidate:
    """One deterministic remediation action the model may consider."""

    action_id: str
    action_type: RemediationActionType
    affected_service: str
    description: str
    rationale: str
    risk_level: RemediationRiskLevel
    requires_approval: bool
    supporting_evidence: tuple[str, ...]
    verification_steps: tuple[str, ...]
    rollback_guidance: str | None = None

    def __post_init__(self) -> None:
        if not self.action_id.strip():
            raise ValueError(
                "Remediation action ID must not be empty."
            )

        if not self.affected_service.strip():
            raise ValueError(
                "Remediation affected service must not be empty."
            )

        if not self.description.strip():
            raise ValueError(
                "Remediation description must not be empty."
            )

        if not self.rationale.strip():
            raise ValueError(
                "Remediation rationale must not be empty."
            )

        if not self.supporting_evidence:
            raise ValueError(
                "Remediation candidate requires supporting evidence."
            )

        if not self.verification_steps:
            raise ValueError(
                "Remediation candidate requires verification steps."
            )


@dataclass(frozen=True, slots=True)
class RemediationPlanConstraints:
    """Deterministic boundary for remediation planning."""

    incident_id: str
    affected_service: str
    diagnosis_candidate_id: str | None
    candidates: tuple[RemediationCandidate, ...]
    blocked_reason: str | None = None

    def __post_init__(self) -> None:
        if not self.incident_id.strip():
            raise ValueError(
                "Remediation incident ID must not be empty."
            )

        if not self.affected_service.strip():
            raise ValueError(
                "Remediation affected service must not be empty."
            )

        if self.blocked_reason is not None and self.candidates:
            raise ValueError(
                "Blocked remediation plans cannot contain candidates."
            )
