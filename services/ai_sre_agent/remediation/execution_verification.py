"""Post-execution recovery verification for FinStream AI-SRE."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from services.ai_sre_agent.models import utc_now
from services.ai_sre_agent.remediation.safety import (
    ExecutionSafetyApproval,
)


class LiveExecutionVerificationError(RuntimeError):
    """A live remediation did not satisfy recovery invariants."""


@dataclass(frozen=True, slots=True)
class LiveExecutionVerificationSnapshot:
    """Fresh state observed after a live processor restart."""

    observed_at: datetime

    namespace: str
    deployment: str

    current_generation: int
    observed_generation: int

    previous_pod_uid: str
    current_pod_uid: str

    desired_replicas: int
    updated_replicas: int
    ready_replicas: int
    available_replicas: int

    processor_target_up: bool
    kafka_healthy: bool
    postgres_healthy: bool

    rollout_in_progress: bool

    def __post_init__(self) -> None:
        if (
            self.observed_at.tzinfo is None
            or self.observed_at.utcoffset() is None
        ):
            raise ValueError(
                "Verification timestamp must be timezone-aware."
            )

        if not self.namespace.strip():
            raise ValueError(
                "Verification namespace must not be empty."
            )

        if not self.deployment.strip():
            raise ValueError(
                "Verification deployment must not be empty."
            )

        if (
            self.current_generation < 1
            or self.observed_generation < 1
        ):
            raise ValueError(
                "Verification generations must be positive."
            )

        if not self.previous_pod_uid.strip():
            raise ValueError(
                "Previous processor pod UID must not be empty."
            )

        if not self.current_pod_uid.strip():
            raise ValueError(
                "Current processor pod UID must not be empty."
            )

        counts = (
            self.desired_replicas,
            self.updated_replicas,
            self.ready_replicas,
            self.available_replicas,
        )

        if any(value < 0 for value in counts):
            raise ValueError(
                "Verification replica counts must not be negative."
            )


class LiveExecutionVerifier:
    """Fail closed unless the processor demonstrably recovered."""

    MAX_EVIDENCE_AGE_SECONDS = 30
    MAX_FUTURE_SKEW_SECONDS = 5

    @classmethod
    def verify(
        cls,
        *,
        safety_approval: ExecutionSafetyApproval,
        snapshot: LiveExecutionVerificationSnapshot,
    ) -> None:
        """Verify the exact expected rollout and recovery state."""
        if snapshot.namespace != safety_approval.namespace:
            raise LiveExecutionVerificationError(
                "Verification namespace does not match "
                "the safety approval."
            )

        if snapshot.deployment != safety_approval.deployment:
            raise LiveExecutionVerificationError(
                "Verification deployment does not match "
                "the safety approval."
            )

        age = (
            utc_now() - snapshot.observed_at
        ).total_seconds()

        if age > cls.MAX_EVIDENCE_AGE_SECONDS:
            raise LiveExecutionVerificationError(
                "Post-execution verification evidence is stale."
            )

        if age < -cls.MAX_FUTURE_SKEW_SECONDS:
            raise LiveExecutionVerificationError(
                "Post-execution verification timestamp is "
                "unexpectedly in the future."
            )

        expected_generation = (
            safety_approval.deployment_generation + 1
        )

        if snapshot.current_generation != expected_generation:
            raise LiveExecutionVerificationError(
                "Deployment generation did not advance exactly once."
            )

        if (
            snapshot.observed_generation
            != snapshot.current_generation
        ):
            raise LiveExecutionVerificationError(
                "Deployment controller has not observed "
                "the new generation."
            )

        if (
            snapshot.previous_pod_uid
            == snapshot.current_pod_uid
        ):
            raise LiveExecutionVerificationError(
                "Processor pod identity did not change."
            )

        if snapshot.desired_replicas < 1:
            raise LiveExecutionVerificationError(
                "Processor has no desired replicas after execution."
            )

        if snapshot.rollout_in_progress:
            raise LiveExecutionVerificationError(
                "Processor rollout is still in progress."
            )

        desired = snapshot.desired_replicas

        if (
            snapshot.updated_replicas < desired
            or snapshot.ready_replicas < desired
            or snapshot.available_replicas < desired
        ):
            raise LiveExecutionVerificationError(
                "Processor deployment has not fully recovered."
            )

        if not snapshot.processor_target_up:
            raise LiveExecutionVerificationError(
                "Processor Prometheus target has not recovered."
            )

        if not snapshot.kafka_healthy:
            raise LiveExecutionVerificationError(
                "Kafka is unhealthy after processor remediation."
            )

        if not snapshot.postgres_healthy:
            raise LiveExecutionVerificationError(
                "PostgreSQL is unhealthy after processor remediation."
            )
