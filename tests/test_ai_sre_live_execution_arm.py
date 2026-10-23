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
    GuardedKubernetesRestartExecutor,
    KubernetesMutationError,
    KubernetesMutationMode,
    KubernetesMutationResponse,
    LiveExecutionArmError,
    LiveExecutionArmManager,
    LiveExecutionArmStatus,
    RemediationActionType,
    RemediationApprovalWorkflow,
    RemediationIncidentCoordinator,
    RemediationRiskLevel,
    SelectedRemediation,
    SQLiteExecutionRegistry,
)


class FakeLiveTransport:
    mode = KubernetesMutationMode.LIVE

    def __init__(self):
        self.calls = []

    def patch_deployment(self, request):
        self.calls.append(request)

        return KubernetesMutationResponse(
            accepted=True,
            status_code=200,
            resource_version="live-test",
        )


def make_ready():
    incident = Incident(
        fingerprint="live-arm-test",
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
            "Return to investigation."
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

    snapshot = ExecutionSafetySnapshot(
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

    safety = ExecutionSafetyGate.evaluate(
        incident=incident,
        proposal=approved,
        authorization=authorization,
        permit=permit,
        snapshot=snapshot,
    )

    return (
        incident,
        approved,
        authorization,
        permit,
        snapshot,
        safety,
    )


def make_arm(ready):
    return LiveExecutionArmManager.issue(
        incident=ready[0],
        proposal=ready[1],
        authorization=ready[2],
        permit=ready[3],
        snapshot=ready[4],
        safety_approval=ready[5],
        reviewer="human-operator",
        reason="Explicitly approve one controlled live restart.",
    )


def test_valid_live_arm_is_issued():
    ready = make_ready()

    arm = make_arm(ready)

    assert arm.status is LiveExecutionArmStatus.ACTIVE
    assert arm.reviewer == "human-operator"
    assert arm.expires_at <= ready[5].expires_at


def test_blank_reviewer_is_rejected():
    ready = make_ready()

    with pytest.raises(
        LiveExecutionArmError,
        match="reviewer",
    ):
        LiveExecutionArmManager.issue(
            incident=ready[0],
            proposal=ready[1],
            authorization=ready[2],
            permit=ready[3],
            snapshot=ready[4],
            safety_approval=ready[5],
            reviewer=" ",
            reason="Approved.",
        )


def test_blank_reason_is_rejected():
    ready = make_ready()

    with pytest.raises(
        LiveExecutionArmError,
        match="reason",
    ):
        LiveExecutionArmManager.issue(
            incident=ready[0],
            proposal=ready[1],
            authorization=ready[2],
            permit=ready[3],
            snapshot=ready[4],
            safety_approval=ready[5],
            reviewer="operator",
            reason=" ",
        )


def test_expired_arm_is_rejected():
    ready = make_ready()
    arm = make_arm(ready)

    now = utc_now()

    expired = replace(
        arm,
        issued_at=now - timedelta(seconds=2),
        expires_at=now - timedelta(seconds=1),
    )

    with pytest.raises(
        LiveExecutionArmError,
        match="expired",
    ):
        LiveExecutionArmManager.validate(
            incident=ready[0],
            proposal=ready[1],
            authorization=ready[2],
            permit=ready[3],
            snapshot=ready[4],
            safety_approval=ready[5],
            arm=expired,
        )


def test_generation_change_invalidates_arm():
    ready = list(make_ready())
    arm = make_arm(tuple(ready))

    ready[4] = replace(
        ready[4],
        deployment_generation=13,
    )

    with pytest.raises(
        ExecutionSafetyError,
        match="Deployment generation changed",
    ):
        LiveExecutionArmManager.validate(
            incident=ready[0],
            proposal=ready[1],
            authorization=ready[2],
            permit=ready[3],
            snapshot=ready[4],
            safety_approval=ready[5],
            arm=arm,
        )


def test_arm_consumption_is_recorded():
    ready = make_ready()
    arm = make_arm(ready)

    consumed = LiveExecutionArmManager.consume(
        incident=ready[0],
        proposal=ready[1],
        authorization=ready[2],
        permit=ready[3],
        snapshot=ready[4],
        safety_approval=ready[5],
        arm=arm,
        consumer="executor",
    )

    assert consumed.status is LiveExecutionArmStatus.CONSUMED
    assert consumed.consumed_at is not None
    assert consumed.consumed_by == "executor"


def test_consumed_arm_cannot_validate():
    ready = make_ready()

    consumed = LiveExecutionArmManager.consume(
        incident=ready[0],
        proposal=ready[1],
        authorization=ready[2],
        permit=ready[3],
        snapshot=ready[4],
        safety_approval=ready[5],
        arm=make_arm(ready),
        consumer="executor",
    )

    with pytest.raises(
        LiveExecutionArmError,
        match="not active",
    ):
        LiveExecutionArmManager.validate(
            incident=ready[0],
            proposal=ready[1],
            authorization=ready[2],
            permit=ready[3],
            snapshot=ready[4],
            safety_approval=ready[5],
            arm=consumed,
        )


def test_live_transport_without_arm_is_blocked(tmp_path):
    ready = make_ready()
    transport = FakeLiveTransport()

    with pytest.raises(
        KubernetesMutationError,
        match="explicit execution arm",
    ):
        GuardedKubernetesRestartExecutor.execute(
            incident=ready[0],
            proposal=ready[1],
            authorization=ready[2],
            permit=ready[3],
            snapshot=ready[4],
            safety_approval=ready[5],
            registry=SQLiteExecutionRegistry(
                tmp_path / "execution.db"
            ),
            transport=transport,
        )

    assert transport.calls == []


def test_live_transport_with_valid_arm_is_allowed(tmp_path):
    ready = make_ready()
    arm = make_arm(ready)
    transport = FakeLiveTransport()

    result = GuardedKubernetesRestartExecutor.execute(
        incident=ready[0],
        proposal=ready[1],
        authorization=ready[2],
        permit=ready[3],
        snapshot=ready[4],
        safety_approval=ready[5],
        registry=SQLiteExecutionRegistry(
            tmp_path / "execution.db"
        ),
        transport=transport,
        live_arm=arm,
    )

    assert len(transport.calls) == 1
    assert result.consumed_arm is not None
    assert (
        result.consumed_arm.status
        is LiveExecutionArmStatus.CONSUMED
    )


def test_dry_run_rejects_live_arm(tmp_path):
    ready = make_ready()
    arm = make_arm(ready)

    class DryRunTransport:
        mode = KubernetesMutationMode.SERVER_DRY_RUN

        def patch_deployment(self, request):
            raise AssertionError(
                "transport must not be invoked"
            )

    with pytest.raises(
        KubernetesMutationError,
        match="must not be supplied",
    ):
        GuardedKubernetesRestartExecutor.execute(
            incident=ready[0],
            proposal=ready[1],
            authorization=ready[2],
            permit=ready[3],
            snapshot=ready[4],
            safety_approval=ready[5],
            registry=SQLiteExecutionRegistry(
                tmp_path / "execution.db"
            ),
            transport=DryRunTransport(),
            live_arm=arm,
        )
