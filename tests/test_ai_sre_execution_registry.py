import pytest

from services.ai_sre_agent.models import (
    AlertStatus,
    Incident,
    IncidentStatus,
    utc_now,
)
from services.ai_sre_agent.remediation import (
    ExecutionAuthorizationManager,
    ExecutionClaimError,
    ExecutionClaimStatus,
    ExecutionPermitManager,
    ExecutionSafetyGate,
    ExecutionSafetySnapshot,
    RemediationActionType,
    RemediationApprovalWorkflow,
    RemediationIncidentCoordinator,
    RemediationRiskLevel,
    SelectedRemediation,
    SQLiteExecutionRegistry,
)


def make_ready():
    incident = Incident(
        fingerprint="execution-registry-test",
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
        description="Approved restart.",
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


def claim(registry, ready):
    (
        incident,
        proposal,
        authorization,
        permit,
        snapshot,
        safety,
    ) = ready

    return registry.claim(
        incident=incident,
        proposal=proposal,
        authorization=authorization,
        permit=permit,
        snapshot=snapshot,
        safety_approval=safety,
    )


def test_first_execution_claim_is_persisted(tmp_path):
    registry = SQLiteExecutionRegistry(
        tmp_path / "execution.db"
    )

    ready = make_ready()
    execution_claim = claim(
        registry,
        ready,
    )

    assert (
        execution_claim.status
        is ExecutionClaimStatus.CLAIMED
    )

    assert (
        registry.active_claim_count(
            namespace="finstream",
            deployment="processor",
        )
        == 1
    )


def test_same_permit_cannot_be_claimed_twice(tmp_path):
    registry = SQLiteExecutionRegistry(
        tmp_path / "execution.db"
    )

    ready = make_ready()

    claim(registry, ready)

    with pytest.raises(
        ExecutionClaimError,
        match="already been claimed",
    ):
        claim(registry, ready)


def test_second_active_execution_is_blocked(tmp_path):
    registry = SQLiteExecutionRegistry(
        tmp_path / "execution.db"
    )

    first = make_ready()
    claim(registry, first)

    second = make_ready()

    with pytest.raises(
        ExecutionClaimError,
        match="Another execution",
    ):
        claim(registry, second)


def test_release_removes_active_target_claim(tmp_path):
    registry = SQLiteExecutionRegistry(
        tmp_path / "execution.db"
    )

    execution_claim = claim(
        registry,
        make_ready(),
    )

    released = registry.release(
        claim_id=execution_claim.claim_id,
        reason="Execution not started.",
    )

    assert (
        released.status
        is ExecutionClaimStatus.RELEASED
    )

    assert (
        registry.active_claim_count(
            namespace="finstream",
            deployment="processor",
        )
        == 0
    )


def test_released_permit_still_cannot_be_replayed(tmp_path):
    registry = SQLiteExecutionRegistry(
        tmp_path / "execution.db"
    )

    ready = make_ready()

    execution_claim = claim(
        registry,
        ready,
    )

    registry.release(
        claim_id=execution_claim.claim_id,
        reason="Execution cancelled.",
    )

    with pytest.raises(
        ExecutionClaimError,
        match="already been claimed",
    ):
        claim(registry, ready)


def test_fresh_permit_can_claim_after_release(tmp_path):
    registry = SQLiteExecutionRegistry(
        tmp_path / "execution.db"
    )

    first = make_ready()

    first_claim = claim(
        registry,
        first,
    )

    registry.release(
        claim_id=first_claim.claim_id,
        reason="First attempt cancelled.",
    )

    second = make_ready()

    second_claim = claim(
        registry,
        second,
    )

    assert (
        second_claim.status
        is ExecutionClaimStatus.CLAIMED
    )


def test_registry_survives_process_reopen(tmp_path):
    path = tmp_path / "execution.db"

    first_registry = SQLiteExecutionRegistry(
        path
    )

    ready = make_ready()

    execution_claim = claim(
        first_registry,
        ready,
    )

    reopened = SQLiteExecutionRegistry(
        path
    )

    stored = reopened.get_by_permit(
        execution_claim.permit_id
    )

    assert stored is not None
    assert stored.claim_id == execution_claim.claim_id


def test_registry_has_no_execution_api(tmp_path):
    registry = SQLiteExecutionRegistry(
        tmp_path / "execution.db"
    )

    forbidden = (
        "execute",
        "run",
        "apply",
        "restart",
        "remediate",
    )

    for name in forbidden:
        assert not hasattr(
            registry,
            name,
        )
