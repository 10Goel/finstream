import pytest

from services.ai_sre_agent.models import (
    AlertStatus,
    Incident,
    IncidentStatus,
    utc_now,
)
from services.ai_sre_agent.remediation import (
    AuditedRemediationControlPlane,
    AuditEventType,
    ExecutionSafetySnapshot,
    JsonlAuditLog,
    KubernetesMutationError,
    KubernetesMutationMode,
    KubernetesMutationResponse,
    LiveExecutionArmManager,
    LiveExecutionVerificationError,
    LiveExecutionVerificationSnapshot,
    RemediationActionType,
    RemediationRiskLevel,
    SelectedRemediation,
    SQLiteExecutionRegistry,
)


class FakeTransport:
    mode = KubernetesMutationMode.SERVER_DRY_RUN

    def __init__(
        self,
        *,
        accepted: bool = True,
        raises: bool = False,
    ) -> None:
        self.accepted = accepted
        self.raises = raises
        self.calls = []

    def patch_deployment(self, request):
        self.calls.append(request)

        if self.raises:
            raise RuntimeError(
                "simulated transport failure"
            )

        return KubernetesMutationResponse(
            accepted=self.accepted,
            status_code=(
                200
                if self.accepted
                else 409
            ),
            resource_version=(
                "12345"
                if self.accepted
                else None
            ),
        )


def make_ready(tmp_path):
    log = JsonlAuditLog(
        tmp_path / "audit.jsonl"
    )

    control = AuditedRemediationControlPlane(
        audit_log=log
    )

    registry = SQLiteExecutionRegistry(
        tmp_path / "execution.db"
    )

    incident = Incident(
        fingerprint="audited-execution-test",
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

    selection = SelectedRemediation(
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

    proposal = control.propose(
        incident=incident,
        selection=selection,
    )

    waiting = control.submit(
        incident=incident,
        proposal=proposal,
    )

    approved = control.approve(
        incident=incident,
        proposal=waiting,
        reviewer="operator@example",
    )

    authorization = control.issue_authorization(
        incident=incident,
        proposal=approved,
    )

    permit = control.issue_permit(
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

    safety = control.evaluate_execution_safety(
        incident=incident,
        proposal=approved,
        authorization=authorization,
        permit=permit,
        snapshot=snapshot,
    )

    return (
        control,
        log,
        registry,
        incident,
        approved,
        authorization,
        permit,
        snapshot,
        safety,
    )


def test_successful_execution_is_fully_audited(tmp_path):
    ready = make_ready(tmp_path)

    transport = FakeTransport()

    result = ready[0].execute_guarded_restart(
        incident=ready[3],
        proposal=ready[4],
        authorization=ready[5],
        permit=ready[6],
        snapshot=ready[7],
        safety_approval=ready[8],
        registry=ready[2],
        transport=transport,
    )

    assert result.response.accepted is True
    assert len(transport.calls) == 1

    events = [
        record.event_type
        for record in ready[1].read_all()
    ]

    assert events[-2:] == [
        AuditEventType.EXECUTION_REQUESTED,
        AuditEventType.EXECUTION_SUCCEEDED,
    ]


def test_transport_failure_is_audited(tmp_path):
    ready = make_ready(tmp_path)

    transport = FakeTransport(
        raises=True
    )

    with pytest.raises(
        KubernetesMutationError,
        match="transport failed",
    ):
        ready[0].execute_guarded_restart(
            incident=ready[3],
            proposal=ready[4],
            authorization=ready[5],
            permit=ready[6],
            snapshot=ready[7],
            safety_approval=ready[8],
            registry=ready[2],
            transport=transport,
        )

    events = [
        record.event_type
        for record in ready[1].read_all()
    ]

    assert events[-2:] == [
        AuditEventType.EXECUTION_REQUESTED,
        AuditEventType.EXECUTION_FAILED,
    ]


def test_rejected_response_is_audited_as_failure(
    tmp_path,
):
    ready = make_ready(tmp_path)

    transport = FakeTransport(
        accepted=False
    )

    with pytest.raises(
        KubernetesMutationError,
        match="not accepted",
    ):
        ready[0].execute_guarded_restart(
            incident=ready[3],
            proposal=ready[4],
            authorization=ready[5],
            permit=ready[6],
            snapshot=ready[7],
            safety_approval=ready[8],
            registry=ready[2],
            transport=transport,
        )

    assert (
        ready[1].read_all()[-1].event_type
        is AuditEventType.EXECUTION_FAILED
    )


def test_success_audit_contains_request_digest(tmp_path):
    ready = make_ready(tmp_path)

    result = ready[0].execute_guarded_restart(
        incident=ready[3],
        proposal=ready[4],
        authorization=ready[5],
        permit=ready[6],
        snapshot=ready[7],
        safety_approval=ready[8],
        registry=ready[2],
        transport=FakeTransport(),
    )

    record = ready[1].read_all()[-1]

    assert (
        record.event_type
        is AuditEventType.EXECUTION_SUCCEEDED
    )

    assert (
        record.details["request_digest"]
        == result.request.request_digest
    )


def test_audit_does_not_store_mutation_body(tmp_path):
    ready = make_ready(tmp_path)

    ready[0].execute_guarded_restart(
        incident=ready[3],
        proposal=ready[4],
        authorization=ready[5],
        permit=ready[6],
        snapshot=ready[7],
        safety_approval=ready[8],
        registry=ready[2],
        transport=FakeTransport(),
    )

    raw = ready[1].path.read_text()

    assert "restart-requested-at" not in raw
    assert '"spec"' not in raw


class FakeLiveTransport:
    mode = KubernetesMutationMode.LIVE

    def __init__(self) -> None:
        self.calls = []

    def patch_deployment(self, request):
        self.calls.append(request)

        return KubernetesMutationResponse(
            accepted=True,
            status_code=200,
            resource_version="live-audit-test",
        )


def make_live_arm(ready):
    return LiveExecutionArmManager.issue(
        incident=ready[3],
        proposal=ready[4],
        authorization=ready[5],
        permit=ready[6],
        snapshot=ready[7],
        safety_approval=ready[8],
        reviewer="human-operator",
        reason=(
            "Explicitly approve one controlled live "
            "processor restart."
        ),
    )


def test_audited_live_execution_without_arm_fails_closed(
    tmp_path,
):
    ready = make_ready(tmp_path)
    transport = FakeLiveTransport()

    with pytest.raises(
        KubernetesMutationError,
        match="explicit execution arm",
    ):
        ready[0].execute_guarded_restart(
            incident=ready[3],
            proposal=ready[4],
            authorization=ready[5],
            permit=ready[6],
            snapshot=ready[7],
            safety_approval=ready[8],
            registry=ready[2],
            transport=transport,
        )

    assert transport.calls == []

    events = ready[1].read_all()

    assert (
        events[-2].event_type
        is AuditEventType.EXECUTION_REQUESTED
    )

    assert (
        events[-1].event_type
        is AuditEventType.EXECUTION_FAILED
    )


def test_audited_live_execution_consumes_human_arm(
    tmp_path,
):
    ready = make_ready(tmp_path)

    arm = make_live_arm(ready)
    transport = FakeLiveTransport()

    result = ready[0].execute_guarded_restart(
        incident=ready[3],
        proposal=ready[4],
        authorization=ready[5],
        permit=ready[6],
        snapshot=ready[7],
        safety_approval=ready[8],
        registry=ready[2],
        transport=transport,
        live_arm=arm,
    )

    assert len(transport.calls) == 1

    assert result.consumed_arm is not None
    assert (
        result.consumed_arm.arm_id
        == arm.arm_id
    )

    success = ready[1].read_all()[-1]

    assert (
        success.event_type
        is AuditEventType.EXECUTION_SUCCEEDED
    )

    assert (
        success.details["live_arm_id"]
        == arm.arm_id
    )

    assert (
        success.details["live_arm_consumed_by"]
        == "finstream-kubernetes-executor"
    )


def test_execution_request_audits_live_transport_mode(
    tmp_path,
):
    ready = make_ready(tmp_path)

    arm = make_live_arm(ready)

    ready[0].execute_guarded_restart(
        incident=ready[3],
        proposal=ready[4],
        authorization=ready[5],
        permit=ready[6],
        snapshot=ready[7],
        safety_approval=ready[8],
        registry=ready[2],
        transport=FakeLiveTransport(),
        live_arm=arm,
    )

    records = ready[1].read_all()

    request = next(
        record
        for record in reversed(records)
        if (
            record.event_type
            is AuditEventType.EXECUTION_REQUESTED
        )
    )

    assert (
        request.details["transport_mode"]
        == "LIVE"
    )

    assert (
        request.details["live_arm_id"]
        == arm.arm_id
    )

    assert (
        request.details["live_arm_reviewer"]
        == "human-operator"
    )


def make_recovery_snapshot():
    return LiveExecutionVerificationSnapshot(
        observed_at=utc_now(),
        namespace="finstream",
        deployment="processor",
        current_generation=13,
        observed_generation=13,
        previous_pod_uid="processor-old",
        current_pod_uid="processor-new",
        desired_replicas=1,
        updated_replicas=1,
        ready_replicas=1,
        available_replicas=1,
        processor_target_up=True,
        kafka_healthy=True,
        postgres_healthy=True,
        rollout_in_progress=False,
    )


def execute_live_for_verification(ready):
    arm = make_live_arm(ready)

    return ready[0].execute_guarded_restart(
        incident=ready[3],
        proposal=ready[4],
        authorization=ready[5],
        permit=ready[6],
        snapshot=ready[7],
        safety_approval=ready[8],
        registry=ready[2],
        transport=FakeLiveTransport(),
        live_arm=arm,
    )


def test_live_mutation_is_pending_verification(tmp_path):
    ready = make_ready(tmp_path)

    execute_live_for_verification(
        ready
    )

    record = ready[1].read_all()[-1]

    assert (
        record.event_type
        is AuditEventType.EXECUTION_SUCCEEDED
    )

    assert (
        record.details["outcome"]
        == (
            "LIVE_MUTATION_ACCEPTED_"
            "PENDING_VERIFICATION"
        )
    )


def test_verified_live_recovery_is_audited(tmp_path):
    ready = make_ready(tmp_path)

    result = execute_live_for_verification(
        ready
    )

    ready[0].verify_live_execution(
        incident=ready[3],
        proposal=ready[4],
        authorization=ready[5],
        permit=ready[6],
        safety_approval=ready[8],
        result=result,
        snapshot=make_recovery_snapshot(),
    )

    record = ready[1].read_all()[-1]

    assert (
        record.event_type
        is AuditEventType.EXECUTION_VERIFICATION_PASSED
    )

    assert (
        record.details["request_digest"]
        == result.request.request_digest
    )

    assert (
        record.details["previous_pod_uid"]
        == "processor-old"
    )

    assert (
        record.details["current_pod_uid"]
        == "processor-new"
    )


def test_failed_live_recovery_is_audited(tmp_path):
    ready = make_ready(tmp_path)

    result = execute_live_for_verification(
        ready
    )

    bad_snapshot = make_recovery_snapshot()

    bad_snapshot = type(bad_snapshot)(
        observed_at=bad_snapshot.observed_at,
        namespace=bad_snapshot.namespace,
        deployment=bad_snapshot.deployment,
        current_generation=bad_snapshot.current_generation,
        observed_generation=bad_snapshot.observed_generation,
        previous_pod_uid=bad_snapshot.previous_pod_uid,
        current_pod_uid=bad_snapshot.current_pod_uid,
        desired_replicas=bad_snapshot.desired_replicas,
        updated_replicas=bad_snapshot.updated_replicas,
        ready_replicas=bad_snapshot.ready_replicas,
        available_replicas=bad_snapshot.available_replicas,
        processor_target_up=False,
        kafka_healthy=True,
        postgres_healthy=True,
        rollout_in_progress=False,
    )

    with pytest.raises(
        LiveExecutionVerificationError,
        match="Prometheus",
    ):
        ready[0].verify_live_execution(
            incident=ready[3],
            proposal=ready[4],
            authorization=ready[5],
            permit=ready[6],
            safety_approval=ready[8],
            result=result,
            snapshot=bad_snapshot,
        )

    record = ready[1].read_all()[-1]

    assert (
        record.event_type
        is AuditEventType.EXECUTION_VERIFICATION_FAILED
    )

    assert (
        record.details["request_digest"]
        == result.request.request_digest
    )


def test_server_dry_run_cannot_be_verified_as_live(
    tmp_path,
):
    ready = make_ready(tmp_path)

    result = ready[0].execute_guarded_restart(
        incident=ready[3],
        proposal=ready[4],
        authorization=ready[5],
        permit=ready[6],
        snapshot=ready[7],
        safety_approval=ready[8],
        registry=ready[2],
        transport=FakeTransport(),
    )

    with pytest.raises(
        LiveExecutionVerificationError,
        match="consumed live execution arm",
    ):
        ready[0].verify_live_execution(
            incident=ready[3],
            proposal=ready[4],
            authorization=ready[5],
            permit=ready[6],
            safety_approval=ready[8],
            result=result,
            snapshot=make_recovery_snapshot(),
        )

    assert (
        ready[1].read_all()[-1].event_type
        is AuditEventType.EXECUTION_VERIFICATION_FAILED
    )
