"""Execution authorization boundary for FinStream AI-SRE."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, replace
from datetime import datetime
from enum import Enum

from services.ai_sre_agent.models import (
    Incident,
    IncidentStatus,
    new_id,
    utc_now,
)
from services.ai_sre_agent.remediation.approval import (
    RemediationApprovalStatus,
    RemediationProposal,
)
from services.ai_sre_agent.remediation.models import (
    RemediationActionType,
    RemediationRiskLevel,
)


class ExecutionAuthorizationStatus(str, Enum):
    """Lifecycle state of an execution authorization."""

    AUTHORIZED = "AUTHORIZED"
    REVOKED = "REVOKED"


class ExecutionAuthorizationError(RuntimeError):
    """Unsafe or inconsistent execution authorization."""


@dataclass(frozen=True, slots=True)
class ExecutionAuthorization:
    """Immutable authorization for a future remediation executor."""

    incident_id: str
    proposal_id: str
    action_id: str
    action_type: RemediationActionType
    affected_service: str
    risk_level: RemediationRiskLevel
    approved_by: str
    approved_at: datetime
    proposal_digest: str

    status: ExecutionAuthorizationStatus = (
        ExecutionAuthorizationStatus.AUTHORIZED
    )

    created_at: datetime = field(
        default_factory=utc_now
    )

    revoked_at: datetime | None = None
    revoked_by: str | None = None
    revocation_reason: str | None = None

    authorization_id: str = field(
        default_factory=lambda: new_id("auth")
    )

    def __post_init__(self) -> None:
        if not self.incident_id.strip():
            raise ValueError(
                "Authorization incident ID must not be empty."
            )

        if not self.proposal_id.strip():
            raise ValueError(
                "Authorization proposal ID must not be empty."
            )

        if not self.action_id.strip():
            raise ValueError(
                "Authorization action ID must not be empty."
            )

        if not self.approved_by.strip():
            raise ValueError(
                "Authorization requires an approver identity."
            )

        if len(self.proposal_digest) != 64:
            raise ValueError(
                "Authorization proposal digest must be SHA-256."
            )

        if self.status is ExecutionAuthorizationStatus.REVOKED:
            if self.revoked_at is None:
                raise ValueError(
                    "Revoked authorization requires revoked_at."
                )

            if (
                self.revoked_by is None
                or not self.revoked_by.strip()
            ):
                raise ValueError(
                    "Revoked authorization requires revoked_by."
                )

            if (
                self.revocation_reason is None
                or not self.revocation_reason.strip()
            ):
                raise ValueError(
                    "Revoked authorization requires a reason."
                )


class ExecutionAuthorizationManager:
    """Issue and validate authorization without executing actions."""

    @staticmethod
    def _proposal_digest(
        proposal: RemediationProposal,
    ) -> str:
        payload = {
            "proposal_id": proposal.proposal_id,
            "incident_id": proposal.incident_id,
            "action_id": proposal.action_id,
            "action_type": proposal.action_type.value,
            "affected_service": proposal.affected_service,
            "description": proposal.description,
            "rationale": proposal.rationale,
            "risk_level": proposal.risk_level.value,
            "requires_approval": proposal.requires_approval,
            "supporting_evidence": list(
                proposal.supporting_evidence
            ),
            "verification_steps": list(
                proposal.verification_steps
            ),
            "rollback_guidance": (
                proposal.rollback_guidance
            ),
            "model_rationale": proposal.model_rationale,
            "status": proposal.status.value,
            "submitted_at": (
                proposal.submitted_at.isoformat()
                if proposal.submitted_at is not None
                else None
            ),
            "decided_at": (
                proposal.decided_at.isoformat()
                if proposal.decided_at is not None
                else None
            ),
            "decided_by": proposal.decided_by,
            "decision_reason": proposal.decision_reason,
        }

        encoded = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

        return hashlib.sha256(
            encoded
        ).hexdigest()

    @staticmethod
    def _validate_identity(
        *,
        incident: Incident,
        proposal: RemediationProposal,
    ) -> None:
        if incident.incident_id != proposal.incident_id:
            raise ExecutionAuthorizationError(
                "Proposal belongs to a different incident."
            )

        if (
            incident.affected_service is not None
            and incident.affected_service
            != proposal.affected_service
        ):
            raise ExecutionAuthorizationError(
                "Proposal service does not match the incident."
            )

    @classmethod
    def issue(
        cls,
        *,
        incident: Incident,
        proposal: RemediationProposal,
    ) -> ExecutionAuthorization:
        """Issue authorization for a human-approved mutating action."""
        cls._validate_identity(
            incident=incident,
            proposal=proposal,
        )

        if incident.status is not IncidentStatus.APPROVED:
            raise ExecutionAuthorizationError(
                "Incident must be APPROVED before execution "
                "authorization can be issued."
            )

        if (
            proposal.status
            is not RemediationApprovalStatus.APPROVED
        ):
            raise ExecutionAuthorizationError(
                "Remediation proposal must be APPROVED before "
                "execution authorization can be issued."
            )

        if not proposal.requires_approval:
            raise ExecutionAuthorizationError(
                "Execution authorization is reserved for actions "
                "requiring explicit human approval."
            )

        if (
            proposal.action_type
            is not RemediationActionType.ROLLING_RESTART
        ):
            raise ExecutionAuthorizationError(
                "This remediation action type is not currently "
                "authorized for execution."
            )

        if proposal.decided_by == "finstream-policy":
            raise ExecutionAuthorizationError(
                "Policy approval cannot authorize a mutating action."
            )

        if proposal.decided_by is None:
            raise ExecutionAuthorizationError(
                "Human approver identity is missing."
            )

        if proposal.decided_at is None:
            raise ExecutionAuthorizationError(
                "Human approval timestamp is missing."
            )

        return ExecutionAuthorization(
            incident_id=incident.incident_id,
            proposal_id=proposal.proposal_id,
            action_id=proposal.action_id,
            action_type=proposal.action_type,
            affected_service=proposal.affected_service,
            risk_level=proposal.risk_level,
            approved_by=proposal.decided_by,
            approved_at=proposal.decided_at,
            proposal_digest=cls._proposal_digest(
                proposal
            ),
        )

    @classmethod
    def validate(
        cls,
        *,
        incident: Incident,
        proposal: RemediationProposal,
        authorization: ExecutionAuthorization,
    ) -> None:
        """Validate an authorization against current approved state."""
        cls._validate_identity(
            incident=incident,
            proposal=proposal,
        )

        if (
            authorization.status
            is not ExecutionAuthorizationStatus.AUTHORIZED
        ):
            raise ExecutionAuthorizationError(
                "Execution authorization is not active."
            )

        if incident.status is not IncidentStatus.APPROVED:
            raise ExecutionAuthorizationError(
                "Incident is no longer in APPROVED state."
            )

        if (
            proposal.status
            is not RemediationApprovalStatus.APPROVED
        ):
            raise ExecutionAuthorizationError(
                "Remediation proposal is no longer APPROVED."
            )

        if authorization.incident_id != incident.incident_id:
            raise ExecutionAuthorizationError(
                "Authorization incident ID mismatch."
            )

        if authorization.proposal_id != proposal.proposal_id:
            raise ExecutionAuthorizationError(
                "Authorization proposal ID mismatch."
            )

        if authorization.action_id != proposal.action_id:
            raise ExecutionAuthorizationError(
                "Authorization action ID mismatch."
            )

        current_digest = cls._proposal_digest(
            proposal
        )

        if authorization.proposal_digest != current_digest:
            raise ExecutionAuthorizationError(
                "Approved remediation proposal changed after "
                "authorization."
            )

    @staticmethod
    def revoke(
        authorization: ExecutionAuthorization,
        *,
        reviewer: str,
        reason: str,
    ) -> ExecutionAuthorization:
        """Revoke authorization before any future execution."""
        if (
            authorization.status
            is not ExecutionAuthorizationStatus.AUTHORIZED
        ):
            raise ExecutionAuthorizationError(
                "Only an active authorization may be revoked."
            )

        reviewer = reviewer.strip()
        reason = reason.strip()

        if not reviewer:
            raise ExecutionAuthorizationError(
                "Authorization revocation requires a reviewer."
            )

        if not reason:
            raise ExecutionAuthorizationError(
                "Authorization revocation requires a reason."
            )

        return replace(
            authorization,
            status=ExecutionAuthorizationStatus.REVOKED,
            revoked_at=utc_now(),
            revoked_by=reviewer,
            revocation_reason=reason,
        )
