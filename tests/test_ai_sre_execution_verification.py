from dataclasses import replace
from datetime import timedelta

import pytest

from services.ai_sre_agent.models import utc_now
from services.ai_sre_agent.remediation import (
    ExecutionSafetyApproval,
    LiveExecutionVerificationError,
    LiveExecutionVerificationSnapshot,
    LiveExecutionVerifier,
)


def make_approval():
    now = utc_now()

    return ExecutionSafetyApproval(
        incident_id="inc-test",
        authorization_id="auth-test",
        permit_id="permit-test",
        namespace="finstream",
        deployment="processor",
        deployment_generation=12,
        snapshot_digest="a" * 64,
        evaluated_at=now,
        expires_at=(
            now + timedelta(seconds=15)
        ),
    )


def make_snapshot():
    return LiveExecutionVerificationSnapshot(
        observed_at=utc_now(),
        namespace="finstream",
        deployment="processor",
        current_generation=13,
        observed_generation=13,
        previous_pod_uid="old-processor-pod",
        current_pod_uid="new-processor-pod",
        desired_replicas=1,
        updated_replicas=1,
        ready_replicas=1,
        available_replicas=1,
        processor_target_up=True,
        kafka_healthy=True,
        postgres_healthy=True,
        rollout_in_progress=False,
    )


def test_recovered_processor_passes_verification():
    LiveExecutionVerifier.verify(
        safety_approval=make_approval(),
        snapshot=make_snapshot(),
    )


def test_stale_verification_is_rejected():
    snapshot = replace(
        make_snapshot(),
        observed_at=(
            utc_now()
            - timedelta(seconds=31)
        ),
    )

    with pytest.raises(
        LiveExecutionVerificationError,
        match="stale",
    ):
        LiveExecutionVerifier.verify(
            safety_approval=make_approval(),
            snapshot=snapshot,
        )


def test_wrong_namespace_is_rejected():
    snapshot = replace(
        make_snapshot(),
        namespace="default",
    )

    with pytest.raises(
        LiveExecutionVerificationError,
        match="namespace",
    ):
        LiveExecutionVerifier.verify(
            safety_approval=make_approval(),
            snapshot=snapshot,
        )


def test_generation_must_advance_exactly_once():
    snapshot = replace(
        make_snapshot(),
        current_generation=14,
        observed_generation=14,
    )

    with pytest.raises(
        LiveExecutionVerificationError,
        match="exactly once",
    ):
        LiveExecutionVerifier.verify(
            safety_approval=make_approval(),
            snapshot=snapshot,
        )


def test_controller_must_observe_generation():
    snapshot = replace(
        make_snapshot(),
        observed_generation=12,
    )

    with pytest.raises(
        LiveExecutionVerificationError,
        match="has not observed",
    ):
        LiveExecutionVerifier.verify(
            safety_approval=make_approval(),
            snapshot=snapshot,
        )


def test_processor_pod_must_change():
    snapshot = replace(
        make_snapshot(),
        current_pod_uid="old-processor-pod",
    )

    with pytest.raises(
        LiveExecutionVerificationError,
        match="identity did not change",
    ):
        LiveExecutionVerifier.verify(
            safety_approval=make_approval(),
            snapshot=snapshot,
        )


def test_processor_must_be_fully_available():
    snapshot = replace(
        make_snapshot(),
        ready_replicas=0,
        available_replicas=0,
    )

    with pytest.raises(
        LiveExecutionVerificationError,
        match="fully recovered",
    ):
        LiveExecutionVerifier.verify(
            safety_approval=make_approval(),
            snapshot=snapshot,
        )


def test_processor_target_must_recover():
    snapshot = replace(
        make_snapshot(),
        processor_target_up=False,
    )

    with pytest.raises(
        LiveExecutionVerificationError,
        match="Prometheus",
    ):
        LiveExecutionVerifier.verify(
            safety_approval=make_approval(),
            snapshot=snapshot,
        )


@pytest.mark.parametrize(
    ("field", "message"),
    (
        ("kafka_healthy", "Kafka"),
        ("postgres_healthy", "PostgreSQL"),
    ),
)
def test_dependencies_must_remain_healthy(
    field,
    message,
):
    snapshot = replace(
        make_snapshot(),
        **{field: False},
    )

    with pytest.raises(
        LiveExecutionVerificationError,
        match=message,
    ):
        LiveExecutionVerifier.verify(
            safety_approval=make_approval(),
            snapshot=snapshot,
        )
