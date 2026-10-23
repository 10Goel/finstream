"""Runtime execution safety gate for FinStream AI-SRE."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta

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
    ExecutionPermitManager,
)


class ExecutionSafetyError(RuntimeError):
    """Runtime conditions do not permit remediation execution."""


@dataclass(frozen=True, slots=True)
class ExecutionSafetySnapshot:
    """Fresh operational state used immediately before execution."""

    observed_at: datetime

    namespace: str
    deployment: str
    deployment_generation: int

    desired_replicas: int
    ready_replicas: int
    available_replicas: int

    processor_target_up: bool

    kafka_healthy: bool
    postgres_healthy: bool

    rollout_in_progress: bool
    active_execution_count: int

    def __post_init__(self) -> None:
        if (
            self.observed_at.tzinfo is None
            or self.observed_at.utcoffset() is None
        ):
            raise ValueError(
                "Safety snapshot timestamp must be timezone-aware."
            )

        if not self.namespace.strip():
            raise ValueError(
                "Safety snapshot namespace must not be empty."
            )

        if not self.deployment.strip():
            raise ValueError(
                "Safety snapshot deployment must not be empty."
            )

        if self.deployment_generation < 1:
            raise ValueError(
                "Deployment generation must be positive."
            )

        replica_values = (
            self.desired_replicas,
            self.ready_replicas,
            self.available_replicas,
            self.active_execution_count,
        )

        if any(value < 0 for value in replica_values):
            raise ValueError(
                "Safety snapshot counts must not be negative."
            )


@dataclass(frozen=True, slots=True)
class ExecutionSafetyApproval:
    """Short-lived proof that runtime safety checks passed."""

    incident_id: str
    authorization_id: str
    permit_id: str

    namespace: str
    deployment: str
    deployment_generation: int

    snapshot_digest: str

    evaluated_at: datetime
    expires_at: datetime

    safety_approval_id: str = field(
        default_factory=lambda: new_id("safe")
    )

    def __post_init__(self) -> None:
        if len(self.snapshot_digest) != 64:
            raise ValueError(
                "Safety snapshot digest must be SHA-256."
            )

        if self.expires_at <= self.evaluated_at:
            raise ValueError(
                "Safety approval must expire after evaluation."
            )


class ExecutionSafetyGate:
    """Fail-closed runtime gate before any future actuator."""

    NAMESPACE = "finstream"
    DEPLOYMENT = "processor"

    MAX_EVIDENCE_AGE_SECONDS = 30
    MAX_FUTURE_SKEW_SECONDS = 5
    APPROVAL_TTL_SECONDS = 15

    @staticmethod
    def _snapshot_digest(
        snapshot: ExecutionSafetySnapshot,
    ) -> str:
        payload = {
            "observed_at": snapshot.observed_at.isoformat(),
            "namespace": snapshot.namespace,
            "deployment": snapshot.deployment,
            "deployment_generation": (
                snapshot.deployment_generation
            ),
            "desired_replicas": snapshot.desired_replicas,
            "ready_replicas": snapshot.ready_replicas,
            "available_replicas": (
                snapshot.available_replicas
            ),
            "processor_target_up": (
                snapshot.processor_target_up
            ),
            "kafka_healthy": snapshot.kafka_healthy,
            "postgres_healthy": snapshot.postgres_healthy,
            "rollout_in_progress": (
                snapshot.rollout_in_progress
            ),
            "active_execution_count": (
                snapshot.active_execution_count
            ),
        }

        encoded = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

        return hashlib.sha256(
            encoded
        ).hexdigest()

    @classmethod
    def evaluate(
        cls,
        *,
        incident: Incident,
        proposal: RemediationProposal,
        authorization: ExecutionAuthorization,
        permit: ExecutionPermit,
        snapshot: ExecutionSafetySnapshot,
    ) -> ExecutionSafetyApproval:
        """Evaluate all execution preconditions and fail closed."""
        ExecutionPermitManager.validate(
            incident=incident,
            proposal=proposal,
            authorization=authorization,
            permit=permit,
        )

        if snapshot.namespace != cls.NAMESPACE:
            raise ExecutionSafetyError(
                "Execution namespace is not allowlisted."
            )

        if snapshot.deployment != cls.DEPLOYMENT:
            raise ExecutionSafetyError(
                "Execution deployment is not allowlisted."
            )

        if proposal.affected_service != snapshot.deployment:
            raise ExecutionSafetyError(
                "Safety snapshot deployment does not match "
                "the approved remediation."
            )

        now = utc_now()

        evidence_age = (
            now - snapshot.observed_at
        ).total_seconds()

        if evidence_age > cls.MAX_EVIDENCE_AGE_SECONDS:
            raise ExecutionSafetyError(
                "Execution safety evidence is stale."
            )

        if evidence_age < -cls.MAX_FUTURE_SKEW_SECONDS:
            raise ExecutionSafetyError(
                "Execution safety evidence timestamp is "
                "unexpectedly in the future."
            )

        if snapshot.desired_replicas < 1:
            raise ExecutionSafetyError(
                "Processor has no desired replicas; rolling "
                "restart cannot safely recover this state."
            )

        if snapshot.processor_target_up:
            raise ExecutionSafetyError(
                "Processor Prometheus target has recovered; "
                "restart is no longer justified."
            )

        if (
            snapshot.ready_replicas
            >= snapshot.desired_replicas
            and snapshot.available_replicas
            >= snapshot.desired_replicas
        ):
            raise ExecutionSafetyError(
                "Processor workload has recovered; restart is "
                "no longer justified."
            )

        if not snapshot.kafka_healthy:
            raise ExecutionSafetyError(
                "Kafka dependency is unhealthy."
            )

        if not snapshot.postgres_healthy:
            raise ExecutionSafetyError(
                "PostgreSQL dependency is unhealthy."
            )

        if snapshot.rollout_in_progress:
            raise ExecutionSafetyError(
                "Processor rollout is already in progress."
            )

        if snapshot.active_execution_count != 0:
            raise ExecutionSafetyError(
                "Another remediation execution is already active."
            )

        evaluated_at = utc_now()

        return ExecutionSafetyApproval(
            incident_id=incident.incident_id,
            authorization_id=(
                authorization.authorization_id
            ),
            permit_id=permit.permit_id,
            namespace=snapshot.namespace,
            deployment=snapshot.deployment,
            deployment_generation=(
                snapshot.deployment_generation
            ),
            snapshot_digest=cls._snapshot_digest(
                snapshot
            ),
            evaluated_at=evaluated_at,
            expires_at=(
                evaluated_at
                + timedelta(
                    seconds=cls.APPROVAL_TTL_SECONDS
                )
            ),
        )

    @classmethod
    def validate(
        cls,
        *,
        incident: Incident,
        proposal: RemediationProposal,
        authorization: ExecutionAuthorization,
        permit: ExecutionPermit,
        snapshot: ExecutionSafetySnapshot,
        approval: ExecutionSafetyApproval,
    ) -> None:
        """Revalidate a safety approval before future execution."""
        ExecutionPermitManager.validate(
            incident=incident,
            proposal=proposal,
            authorization=authorization,
            permit=permit,
        )

        if approval.incident_id != incident.incident_id:
            raise ExecutionSafetyError(
                "Safety approval incident mismatch."
            )

        if (
            approval.authorization_id
            != authorization.authorization_id
        ):
            raise ExecutionSafetyError(
                "Safety approval authorization mismatch."
            )

        if approval.permit_id != permit.permit_id:
            raise ExecutionSafetyError(
                "Safety approval permit mismatch."
            )

        if utc_now() >= approval.expires_at:
            raise ExecutionSafetyError(
                "Execution safety approval has expired."
            )

        if (
            approval.deployment_generation
            != snapshot.deployment_generation
        ):
            raise ExecutionSafetyError(
                "Deployment generation changed after safety "
                "evaluation."
            )

        if (
            approval.snapshot_digest
            != cls._snapshot_digest(snapshot)
        ):
            raise ExecutionSafetyError(
                "Runtime safety snapshot changed after "
                "evaluation."
            )
