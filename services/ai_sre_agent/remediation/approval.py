"""Approval lifecycle for FinStream AI-SRE remediation proposals."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime
from enum import Enum

from services.ai_sre_agent.models import (
    new_id,
    utc_now,
)
from services.ai_sre_agent.remediation.models import (
    RemediationActionType,
    RemediationRiskLevel,
)
from services.ai_sre_agent.remediation.selector import (
    SelectedRemediation,
)


class RemediationApprovalStatus(str, Enum):
    """Lifecycle states for a remediation proposal."""

    PROPOSED = "PROPOSED"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


class RemediationApprovalError(RuntimeError):
    """Invalid remediation approval lifecycle operation."""


@dataclass(frozen=True, slots=True)
class RemediationProposal:
    """Immutable approval record for one selected remediation."""

    incident_id: str
    action_id: str
    action_type: RemediationActionType
    affected_service: str
    description: str
    rationale: str
    risk_level: RemediationRiskLevel
    requires_approval: bool
    supporting_evidence: tuple[str, ...]
    verification_steps: tuple[str, ...]
    rollback_guidance: str | None
    model_rationale: str

    status: RemediationApprovalStatus = (
        RemediationApprovalStatus.PROPOSED
    )

    created_at: datetime = field(
        default_factory=utc_now
    )

    submitted_at: datetime | None = None
    decided_at: datetime | None = None
    decided_by: str | None = None
    decision_reason: str | None = None

    proposal_id: str = field(
        default_factory=lambda: new_id("rem")
    )

    def __post_init__(self) -> None:
        if not self.incident_id.strip():
            raise ValueError(
                "Remediation proposal incident ID must not be empty."
            )

        if not self.action_id.strip():
            raise ValueError(
                "Remediation proposal action ID must not be empty."
            )

        if not self.affected_service.strip():
            raise ValueError(
                "Remediation proposal service must not be empty."
            )

        if not self.supporting_evidence:
            raise ValueError(
                "Remediation proposal requires supporting evidence."
            )

        if not self.verification_steps:
            raise ValueError(
                "Remediation proposal requires verification steps."
            )

        if (
            self.status
            is RemediationApprovalStatus.AWAITING_APPROVAL
        ):
            if not self.requires_approval:
                raise ValueError(
                    "A non-approval remediation cannot wait for "
                    "human approval."
                )

            if self.submitted_at is None:
                raise ValueError(
                    "Awaiting-approval proposal requires "
                    "submitted_at."
                )

            if (
                self.decided_at is not None
                or self.decided_by is not None
            ):
                raise ValueError(
                    "Awaiting-approval proposal cannot already "
                    "contain a decision."
                )

        if self.status in {
            RemediationApprovalStatus.APPROVED,
            RemediationApprovalStatus.REJECTED,
        }:
            if self.decided_at is None:
                raise ValueError(
                    "Decided remediation proposal requires "
                    "decided_at."
                )

            if (
                self.decided_by is None
                or not self.decided_by.strip()
            ):
                raise ValueError(
                    "Decided remediation proposal requires "
                    "decided_by."
                )


class RemediationApprovalWorkflow:
    """Manage approval without executing remediation."""

    @staticmethod
    def propose(
        *,
        incident_id: str,
        selection: SelectedRemediation,
    ) -> RemediationProposal:
        """Create an immutable remediation proposal."""
        return RemediationProposal(
            incident_id=incident_id,
            action_id=selection.action_id,
            action_type=selection.action_type,
            affected_service=selection.affected_service,
            description=selection.description,
            rationale=selection.rationale,
            risk_level=selection.risk_level,
            requires_approval=selection.requires_approval,
            supporting_evidence=(
                selection.supporting_evidence
            ),
            verification_steps=(
                selection.verification_steps
            ),
            rollback_guidance=(
                selection.rollback_guidance
            ),
            model_rationale=(
                selection.model_rationale
            ),
        )

    @staticmethod
    def submit(
        proposal: RemediationProposal,
    ) -> RemediationProposal:
        """Advance a new proposal according to deterministic policy."""
        if (
            proposal.status
            is not RemediationApprovalStatus.PROPOSED
        ):
            raise RemediationApprovalError(
                "Only a PROPOSED remediation may be submitted."
            )

        now = utc_now()

        if proposal.requires_approval:
            return replace(
                proposal,
                status=(
                    RemediationApprovalStatus.AWAITING_APPROVAL
                ),
                submitted_at=now,
            )

        return replace(
            proposal,
            status=RemediationApprovalStatus.APPROVED,
            decided_at=now,
            decided_by="finstream-policy",
            decision_reason=(
                "Deterministic policy does not require "
                "human approval for this action."
            ),
        )

    @staticmethod
    def approve(
        proposal: RemediationProposal,
        *,
        reviewer: str,
        reason: str | None = None,
    ) -> RemediationProposal:
        """Record human approval without executing the action."""
        if (
            proposal.status
            is not RemediationApprovalStatus.AWAITING_APPROVAL
        ):
            raise RemediationApprovalError(
                "Only an AWAITING_APPROVAL remediation "
                "may be approved."
            )

        reviewer = reviewer.strip()

        if not reviewer:
            raise RemediationApprovalError(
                "Approval requires a reviewer identity."
            )

        normalized_reason = (
            reason.strip()
            if reason is not None and reason.strip()
            else "Approved by human reviewer."
        )

        return replace(
            proposal,
            status=RemediationApprovalStatus.APPROVED,
            decided_at=utc_now(),
            decided_by=reviewer,
            decision_reason=normalized_reason,
        )

    @staticmethod
    def reject(
        proposal: RemediationProposal,
        *,
        reviewer: str,
        reason: str,
    ) -> RemediationProposal:
        """Record human rejection without executing the action."""
        if (
            proposal.status
            is not RemediationApprovalStatus.AWAITING_APPROVAL
        ):
            raise RemediationApprovalError(
                "Only an AWAITING_APPROVAL remediation "
                "may be rejected."
            )

        reviewer = reviewer.strip()
        reason = reason.strip()

        if not reviewer:
            raise RemediationApprovalError(
                "Rejection requires a reviewer identity."
            )

        if not reason:
            raise RemediationApprovalError(
                "Rejection requires a reason."
            )

        return replace(
            proposal,
            status=RemediationApprovalStatus.REJECTED,
            decided_at=utc_now(),
            decided_by=reviewer,
            decision_reason=reason,
        )
