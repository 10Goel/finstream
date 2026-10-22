"""Coordinate remediation approval with the incident lifecycle."""

from __future__ import annotations

from services.ai_sre_agent.models import (
    Incident,
    IncidentStatus,
)
from services.ai_sre_agent.remediation.approval import (
    RemediationApprovalStatus,
    RemediationApprovalWorkflow,
    RemediationProposal,
)
from services.ai_sre_agent.remediation.models import (
    RemediationActionType,
)


class RemediationCoordinationError(RuntimeError):
    """Unsafe or inconsistent remediation lifecycle operation."""


class RemediationIncidentCoordinator:
    """Synchronize proposal approval with incident state.

    This component deliberately contains no remediation execution API.
    """

    @staticmethod
    def _validate_identity(
        *,
        incident: Incident,
        proposal: RemediationProposal,
    ) -> None:
        if proposal.incident_id != incident.incident_id:
            raise RemediationCoordinationError(
                "Remediation proposal belongs to a different "
                "incident."
            )

        if (
            incident.affected_service is not None
            and proposal.affected_service
            != incident.affected_service
        ):
            raise RemediationCoordinationError(
                "Remediation proposal service does not match "
                "the incident."
            )

    @staticmethod
    def _validate_auto_approval(
        proposal: RemediationProposal,
    ) -> None:
        if proposal.requires_approval:
            return

        if (
            proposal.action_type
            is not RemediationActionType.INVESTIGATE_DEPENDENCIES
        ):
            raise RemediationCoordinationError(
                "Only non-mutating dependency investigation may "
                "bypass human approval."
            )

    @classmethod
    def submit(
        cls,
        *,
        incident: Incident,
        proposal: RemediationProposal,
    ) -> RemediationProposal:
        """Submit a proposal without executing remediation."""
        cls._validate_identity(
            incident=incident,
            proposal=proposal,
        )

        if incident.status is not IncidentStatus.DIAGNOSED:
            raise RemediationCoordinationError(
                "Remediation submission requires a DIAGNOSED "
                "incident."
            )

        cls._validate_auto_approval(
            proposal
        )

        submitted = RemediationApprovalWorkflow.submit(
            proposal
        )

        if (
            submitted.status
            is RemediationApprovalStatus.AWAITING_APPROVAL
        ):
            incident.transition_to(
                IncidentStatus.AWAITING_APPROVAL
            )

            return submitted

        if (
            submitted.status
            is RemediationApprovalStatus.APPROVED
        ):
            # Non-mutating investigation is policy-approved.
            # The incident returns to investigation because more
            # diagnostic evidence is still required.
            incident.transition_to(
                IncidentStatus.INVESTIGATING
            )

            return submitted

        raise RemediationCoordinationError(
            "Unexpected remediation submission state."
        )

    @classmethod
    def approve(
        cls,
        *,
        incident: Incident,
        proposal: RemediationProposal,
        reviewer: str,
        reason: str | None = None,
    ) -> RemediationProposal:
        """Record approval without starting execution."""
        cls._validate_identity(
            incident=incident,
            proposal=proposal,
        )

        if (
            incident.status
            is not IncidentStatus.AWAITING_APPROVAL
        ):
            raise RemediationCoordinationError(
                "Incident must be AWAITING_APPROVAL before "
                "remediation approval."
            )

        approved = RemediationApprovalWorkflow.approve(
            proposal,
            reviewer=reviewer,
            reason=reason,
        )

        incident.transition_to(
            IncidentStatus.APPROVED
        )

        return approved

    @classmethod
    def reject(
        cls,
        *,
        incident: Incident,
        proposal: RemediationProposal,
        reviewer: str,
        reason: str,
    ) -> RemediationProposal:
        """Reject remediation and return to investigation."""
        cls._validate_identity(
            incident=incident,
            proposal=proposal,
        )

        if (
            incident.status
            is not IncidentStatus.AWAITING_APPROVAL
        ):
            raise RemediationCoordinationError(
                "Incident must be AWAITING_APPROVAL before "
                "remediation rejection."
            )

        rejected = RemediationApprovalWorkflow.reject(
            proposal,
            reviewer=reviewer,
            reason=reason,
        )

        incident.transition_to(
            IncidentStatus.INVESTIGATING
        )

        return rejected
