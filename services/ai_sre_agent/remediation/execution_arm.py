"""Explicit human arming boundary for live FinStream remediation."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from enum import Enum

from services.ai_sre_agent.models import (
    Incident,
    new_id,
    utc_now,
)
from services.ai_sre_agent.remediation.approval import (
    RemediationProposal,
)
from services.ai_sre_agent.remediation.authorization import (
    ExecutionAuthorization,
)
from services.ai_sre_agent.remediation.permit import (
    ExecutionPermit,
)
from services.ai_sre_agent.remediation.safety import (
    ExecutionSafetyApproval,
    ExecutionSafetyGate,
    ExecutionSafetySnapshot,
)


class LiveExecutionArmStatus(str, Enum):
    """Lifecycle of an explicit live-execution arm."""

    ACTIVE = "ACTIVE"
    CONSUMED = "CONSUMED"


class LiveExecutionArmError(RuntimeError):
    """Live execution has not been safely armed."""


@dataclass(frozen=True, slots=True)
class LiveExecutionArm:
    """Short-lived human confirmation for a live mutation."""

    incident_id: str
    proposal_id: str
    authorization_id: str
    permit_id: str
    safety_approval_id: str

    namespace: str
    deployment: str
    deployment_generation: int

    reviewer: str
    reason: str

    issued_at: datetime
    expires_at: datetime

    arm_id: str = field(
        default_factory=lambda: new_id("arm")
    )

    status: LiveExecutionArmStatus = (
        LiveExecutionArmStatus.ACTIVE
    )

    consumed_at: datetime | None = None
    consumed_by: str | None = None

    def __post_init__(self) -> None:
        if (
            self.issued_at.tzinfo is None
            or self.issued_at.utcoffset() is None
            or self.expires_at.tzinfo is None
            or self.expires_at.utcoffset() is None
        ):
            raise ValueError(
                "Live execution arm timestamps must be "
                "timezone-aware."
            )

        if self.expires_at <= self.issued_at:
            raise ValueError(
                "Live execution arm must expire after issuance."
            )

        if not self.reviewer.strip():
            raise ValueError(
                "Live execution arm requires a reviewer."
            )

        if not self.reason.strip():
            raise ValueError(
                "Live execution arm requires a reason."
            )


class LiveExecutionArmManager:
    """Issue and validate explicit live-execution confirmation."""

    MAX_TTL_SECONDS = 60

    @classmethod
    def issue(
        cls,
        *,
        incident: Incident,
        proposal: RemediationProposal,
        authorization: ExecutionAuthorization,
        permit: ExecutionPermit,
        snapshot: ExecutionSafetySnapshot,
        safety_approval: ExecutionSafetyApproval,
        reviewer: str,
        reason: str,
        ttl_seconds: int = 30,
    ) -> LiveExecutionArm:
        """Issue a short-lived arm after revalidating safety."""
        reviewer = reviewer.strip()
        reason = reason.strip()

        if not reviewer:
            raise LiveExecutionArmError(
                "Live execution arm requires a reviewer."
            )

        if not reason:
            raise LiveExecutionArmError(
                "Live execution arm requires a reason."
            )

        if not 1 <= ttl_seconds <= cls.MAX_TTL_SECONDS:
            raise LiveExecutionArmError(
                "Live execution arm TTL must be between "
                "1 and 60 seconds."
            )

        ExecutionSafetyGate.validate(
            incident=incident,
            proposal=proposal,
            authorization=authorization,
            permit=permit,
            snapshot=snapshot,
            approval=safety_approval,
        )

        issued_at = utc_now()

        requested_expiry = (
            issued_at
            + timedelta(
                seconds=ttl_seconds
            )
        )

        expires_at = min(
            requested_expiry,
            safety_approval.expires_at,
        )

        if expires_at <= issued_at:
            raise LiveExecutionArmError(
                "Safety approval expires too soon to arm "
                "live execution."
            )

        return LiveExecutionArm(
            incident_id=incident.incident_id,
            proposal_id=proposal.proposal_id,
            authorization_id=authorization.authorization_id,
            permit_id=permit.permit_id,
            safety_approval_id=(
                safety_approval.safety_approval_id
            ),
            namespace=safety_approval.namespace,
            deployment=safety_approval.deployment,
            deployment_generation=(
                safety_approval.deployment_generation
            ),
            reviewer=reviewer,
            reason=reason,
            issued_at=issued_at,
            expires_at=expires_at,
        )

    @staticmethod
    def validate(
        *,
        incident: Incident,
        proposal: RemediationProposal,
        authorization: ExecutionAuthorization,
        permit: ExecutionPermit,
        snapshot: ExecutionSafetySnapshot,
        safety_approval: ExecutionSafetyApproval,
        arm: LiveExecutionArm,
    ) -> None:
        """Fail closed unless every arm binding remains valid."""
        ExecutionSafetyGate.validate(
            incident=incident,
            proposal=proposal,
            authorization=authorization,
            permit=permit,
            snapshot=snapshot,
            approval=safety_approval,
        )

        if arm.status is not LiveExecutionArmStatus.ACTIVE:
            raise LiveExecutionArmError(
                "Live execution arm is not active."
            )

        if arm.incident_id != incident.incident_id:
            raise LiveExecutionArmError(
                "Live execution arm incident mismatch."
            )

        if arm.proposal_id != proposal.proposal_id:
            raise LiveExecutionArmError(
                "Live execution arm proposal mismatch."
            )

        if (
            arm.authorization_id
            != authorization.authorization_id
        ):
            raise LiveExecutionArmError(
                "Live execution arm authorization mismatch."
            )

        if arm.permit_id != permit.permit_id:
            raise LiveExecutionArmError(
                "Live execution arm permit mismatch."
            )

        if (
            arm.safety_approval_id
            != safety_approval.safety_approval_id
        ):
            raise LiveExecutionArmError(
                "Live execution arm safety approval mismatch."
            )

        if arm.namespace != safety_approval.namespace:
            raise LiveExecutionArmError(
                "Live execution arm namespace mismatch."
            )

        if arm.deployment != safety_approval.deployment:
            raise LiveExecutionArmError(
                "Live execution arm deployment mismatch."
            )

        if (
            arm.deployment_generation
            != snapshot.deployment_generation
        ):
            raise LiveExecutionArmError(
                "Deployment generation changed after "
                "live execution was armed."
            )

        if utc_now() >= arm.expires_at:
            raise LiveExecutionArmError(
                "Live execution arm has expired."
            )

    @classmethod
    def consume(
        cls,
        *,
        incident: Incident,
        proposal: RemediationProposal,
        authorization: ExecutionAuthorization,
        permit: ExecutionPermit,
        snapshot: ExecutionSafetySnapshot,
        safety_approval: ExecutionSafetyApproval,
        arm: LiveExecutionArm,
        consumer: str,
    ) -> LiveExecutionArm:
        """Consume a valid arm for one guarded live attempt."""
        consumer = consumer.strip()

        if not consumer:
            raise LiveExecutionArmError(
                "Live execution arm consumer must not be empty."
            )

        cls.validate(
            incident=incident,
            proposal=proposal,
            authorization=authorization,
            permit=permit,
            snapshot=snapshot,
            safety_approval=safety_approval,
            arm=arm,
        )

        return replace(
            arm,
            status=LiveExecutionArmStatus.CONSUMED,
            consumed_at=utc_now(),
            consumed_by=consumer,
        )
