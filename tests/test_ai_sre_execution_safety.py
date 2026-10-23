from dataclasses import replace
from datetime import timedelta

import pytest

from services.ai_sre_agent.models import (
    AlertStatus,
    Incident,
    IncidentStatus,
    utc_now,
)
from services.ai_sre_agent.remediation import (
    ExecutionAuthorizationManager,
    ExecutionPermitManager,
    ExecutionSafetyError,
    ExecutionSafetyGate,
    ExecutionSafetySnapshot,
    RemediationActionType,
    RemediationApprovalWorkflow,
    RemediationIncidentCoordinator,
    RemediationRiskLevel,
    SelectedRemediation,
)


def make_ready():
    incident = Incident(
        fingerprint="execution-safety-test",
        alert_name="FinStreamServiceDown",
        alert_status=AlertStatus.FIRING,
        severity="critical",
        affected_service="processor",
    )

    incident.transition_to(
        IncidentStatus.INVESTIGATING
    )
    incident.transition_to(
        IncidentStatus.DIAGNOSED
    )

    selected = SelectedRemediation(
        action_id="processor-rolling-restart",
        action_type=(
            RemediationActionType.ROLLING_RESTART
        ),
        affected_service="processor",
        description="Approved processor restart.",
        rationale="Processor remains unavailable.",
        risk_level=RemediationRiskLevel.MEDIUM,
        requires_approval=True,
        supporting_evidence=(
            "ev-prometheus",
            "ev-kubernetes",
        ),
        verification_steps=(
            "Confirm processor recovery.",
        ),
        rollback_guidance=(
            "Return incident to investigation."
        ),
        model_rationale="Untrusted commentary.",
    )

    proposal = RemediationApprovalWorkflow.propose(
        incident_id=incident.incident_id,
        selection=selected,
    )

    waiting = RemediationIncidentCoordinator.submit(
        incident=incident,
        proposal=proposal,
    )

    approved = RemediationIncidentCoordinator.approve(
        incident=incident,
        proposal=waiting,
        reviewer="operator@example",
    )

    authorization = ExecutionAuthorizationManager.issue(
        incident=incident,
        proposal=approved,
    )

    permit = ExecutionPermitManager.issue(
        incident=incident,
        proposal=approved,
        authorization=authorization,
    )

    return incident, approved, authorization, permit


def safe_snapshot() -> ExecutionSafetySnapshot:
    return ExecutionSafetySnapshot(
        observed_at=utc_now(),
        namespace="finstream",
        deployment="processor",
        deployment_generation=12,
        desired_replicas=1,
        ready_replicas=0,
        available_replicas=0,
        processor_target_up=False,
        kafka_healthy=True,
        postgres_healthy=True,
        rollout_in_progress=False,
        active_execution_count=0,
    )


def evaluate(snapshot):
    incident, proposal, authorization, permit = make_ready()

    return ExecutionSafetyGate.evaluate(
        incident=incident,
        proposal=proposal,
        authorization=authorization,
        permit=permit,
        snapshot=snapshot,
    )


def test_safe_runtime_state_passes_gate():
    approval = evaluate(
        safe_snapshot()
    )

    assert approval.namespace == "finstream"
    assert approval.deployment == "processor"
    assert approval.deployment_generation == 12
    assert len(approval.snapshot_digest) == 64
    assert approval.expires_at > approval.evaluated_at


def test_safety_approval_revalidates():
    incident, proposal, authorization, permit = make_ready()
    snapshot = safe_snapshot()

    approval = ExecutionSafetyGate.evaluate(
        incident=incident,
        proposal=proposal,
        authorization=authorization,
        permit=permit,
        snapshot=snapshot,
    )

    ExecutionSafetyGate.validate(
        incident=incident,
        proposal=proposal,
        authorization=authorization,
        permit=permit,
        snapshot=snapshot,
        approval=approval,
    )


def test_stale_snapshot_is_rejected():
    snapshot = replace(
        safe_snapshot(),
        observed_at=utc_now() - timedelta(seconds=31),
    )

    with pytest.raises(
        ExecutionSafetyError,
        match="stale",
    ):
        evaluate(snapshot)


def test_future_snapshot_is_rejected():
    snapshot = replace(
        safe_snapshot(),
        observed_at=utc_now() + timedelta(seconds=10),
    )

    with pytest.raises(
        ExecutionSafetyError,
        match="future",
    ):
        evaluate(snapshot)


def test_wrong_namespace_is_rejected():
    snapshot = replace(
        safe_snapshot(),
        namespace="default",
    )

    with pytest.raises(
        ExecutionSafetyError,
        match="namespace",
    ):
        evaluate(snapshot)


def test_wrong_deployment_is_rejected():
    snapshot = replace(
        safe_snapshot(),
        deployment="api",
    )

    with pytest.raises(
        ExecutionSafetyError,
        match="deployment",
    ):
        evaluate(snapshot)


def test_zero_desired_replicas_is_rejected():
    snapshot = replace(
        safe_snapshot(),
        desired_replicas=0,
    )

    with pytest.raises(
        ExecutionSafetyError,
        match="no desired replicas",
    ):
        evaluate(snapshot)


def test_recovered_processor_is_rejected():
    snapshot = replace(
        safe_snapshot(),
        ready_replicas=1,
        available_replicas=1,
        processor_target_up=True,
    )

    with pytest.raises(
        ExecutionSafetyError,
        match="recovered",
    ):
        evaluate(snapshot)


def test_unhealthy_kafka_is_rejected():
    snapshot = replace(
        safe_snapshot(),
        kafka_healthy=False,
    )

    with pytest.raises(
        ExecutionSafetyError,
        match="Kafka",
    ):
        evaluate(snapshot)


def test_unhealthy_postgres_is_rejected():
    snapshot = replace(
        safe_snapshot(),
        postgres_healthy=False,
    )

    with pytest.raises(
        ExecutionSafetyError,
        match="PostgreSQL",
    ):
        evaluate(snapshot)


def test_existing_rollout_is_rejected():
    snapshot = replace(
        safe_snapshot(),
        rollout_in_progress=True,
    )

    with pytest.raises(
        ExecutionSafetyError,
        match="rollout",
    ):
        evaluate(snapshot)


def test_concurrent_execution_is_rejected():
    snapshot = replace(
        safe_snapshot(),
        active_execution_count=1,
    )

    with pytest.raises(
        ExecutionSafetyError,
        match="already active",
    ):
        evaluate(snapshot)
