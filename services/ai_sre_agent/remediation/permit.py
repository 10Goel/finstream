"""Short-lived execution permits for FinStream AI-SRE."""

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
    ExecutionAuthorizationManager,
)


class ExecutionPermitStatus(str, Enum):
    """Lifecycle state for a short-lived execution permit."""

    ACTIVE = "ACTIVE"
    CONSUMED = "CONSUMED"


class ExecutionPermitError(RuntimeError):
    """Invalid or unsafe execution-permit operation."""


@dataclass(frozen=True, slots=True)
class ExecutionPermit:
    """Short-lived single-use permit for a future actuator."""

    authorization_id: str
    incident_id: str
    proposal_id: str
    action_id: str
    affected_service: str

    issued_at: datetime
    expires_at: datetime

    status: ExecutionPermitStatus = (
        ExecutionPermitStatus.ACTIVE
    )

    consumed_at: datetime | None = None
    consumed_by: str | None = None

    permit_id: str = field(
        default_factory=lambda: new_id("permit")
    )

    def __post_init__(self) -> None:
        if not self.authorization_id.strip():
            raise ValueError(
                "Execution permit authorization ID must not be empty."
            )

        if not self.incident_id.strip():
            raise ValueError(
                "Execution permit incident ID must not be empty."
            )

        if not self.proposal_id.strip():
            raise ValueError(
                "Execution permit proposal ID must not be empty."
            )

        if not self.action_id.strip():
            raise ValueError(
                "Execution permit action ID must not be empty."
            )

        if not self.affected_service.strip():
            raise ValueError(
                "Execution permit service must not be empty."
            )

        if self.expires_at <= self.issued_at:
            raise ValueError(
                "Execution permit must expire after it is issued."
            )

        if self.status is ExecutionPermitStatus.CONSUMED:
            if self.consumed_at is None:
                raise ValueError(
                    "Consumed execution permit requires consumed_at."
                )

            if (
                self.consumed_by is None
                or not self.consumed_by.strip()
            ):
                raise ValueError(
                    "Consumed execution permit requires consumed_by."
                )


class ExecutionPermitManager:
    """Issue and consume permits without executing remediation."""

    MAX_TTL_SECONDS = 900

    @classmethod
    def issue(
        cls,
        *,
        incident: Incident,
        proposal: RemediationProposal,
        authorization: ExecutionAuthorization,
        ttl_seconds: int = 300,
    ) -> ExecutionPermit:
        """Issue a fresh permit from an active authorization."""
        if not 1 <= ttl_seconds <= cls.MAX_TTL_SECONDS:
            raise ExecutionPermitError(
                "Execution permit TTL must be between 1 and "
                f"{cls.MAX_TTL_SECONDS} seconds."
            )

        ExecutionAuthorizationManager.validate(
            incident=incident,
            proposal=proposal,
            authorization=authorization,
        )

        issued_at = utc_now()

        return ExecutionPermit(
            authorization_id=(
                authorization.authorization_id
            ),
            incident_id=authorization.incident_id,
            proposal_id=authorization.proposal_id,
            action_id=authorization.action_id,
            affected_service=authorization.affected_service,
            issued_at=issued_at,
            expires_at=(
                issued_at
                + timedelta(seconds=ttl_seconds)
            ),
        )

    @staticmethod
    def _validate_identity(
        *,
        permit: ExecutionPermit,
        authorization: ExecutionAuthorization,
    ) -> None:
        if (
            permit.authorization_id
            != authorization.authorization_id
        ):
            raise ExecutionPermitError(
                "Execution permit authorization ID mismatch."
            )

        if permit.incident_id != authorization.incident_id:
            raise ExecutionPermitError(
                "Execution permit incident ID mismatch."
            )

        if permit.proposal_id != authorization.proposal_id:
            raise ExecutionPermitError(
                "Execution permit proposal ID mismatch."
            )

        if permit.action_id != authorization.action_id:
            raise ExecutionPermitError(
                "Execution permit action ID mismatch."
            )

        if (
            permit.affected_service
            != authorization.affected_service
        ):
            raise ExecutionPermitError(
                "Execution permit service mismatch."
            )

    @classmethod
    def validate(
        cls,
        *,
        incident: Incident,
        proposal: RemediationProposal,
        authorization: ExecutionAuthorization,
        permit: ExecutionPermit,
    ) -> None:
        """Validate an active, unexpired execution permit."""
        ExecutionAuthorizationManager.validate(
            incident=incident,
            proposal=proposal,
            authorization=authorization,
        )

        cls._validate_identity(
            permit=permit,
            authorization=authorization,
        )

        if permit.status is not ExecutionPermitStatus.ACTIVE:
            raise ExecutionPermitError(
                "Execution permit is no longer active."
            )

        if utc_now() >= permit.expires_at:
            raise ExecutionPermitError(
                "Execution permit has expired."
            )

    @classmethod
    def consume(
        cls,
        *,
        incident: Incident,
        proposal: RemediationProposal,
        authorization: ExecutionAuthorization,
        permit: ExecutionPermit,
        consumer: str,
    ) -> ExecutionPermit:
        """Consume a permit once without performing execution."""
        cls.validate(
            incident=incident,
            proposal=proposal,
            authorization=authorization,
            permit=permit,
        )

        consumer = consumer.strip()

        if not consumer:
            raise ExecutionPermitError(
                "Execution permit consumption requires an identity."
            )

        return replace(
            permit,
            status=ExecutionPermitStatus.CONSUMED,
            consumed_at=utc_now(),
            consumed_by=consumer,
        )
