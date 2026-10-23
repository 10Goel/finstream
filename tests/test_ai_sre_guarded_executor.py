import json
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
    ExecutionClaimError,
    ExecutionClaimStatus,
    ExecutionPermitManager,
    ExecutionSafetyGate,
    ExecutionSafetySnapshot,
    GuardedKubernetesRestartExecutor,
    KubernetesMutationError,
    KubernetesMutationMode,
    KubernetesMutationResponse,
    RemediationActionType,
    RemediationApprovalWorkflow,
    RemediationIncidentCoordinator,
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
            status_code=200 if self.accepted else 409,
            resource_version=(
                "12345"
                if self.accepted
                else None
            ),
            message=None,
        )


def make_ready():
    incident = Incident(
        fingerprint="guarded-executor-test",
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


def execute(
    *,
    tmp_path,
    ready=None,
    transport=None,
):
    if ready is None:
        ready = make_ready()

    if transport is None:
        transport = FakeTransport()

    registry = SQLiteExecutionRegistry(
        tmp_path / "execution.db"
    )

    (
        incident,
        proposal,
        authorization,
        permit,
        snapshot,
        safety,
    ) = ready

    result = GuardedKubernetesRestartExecutor.execute(
        incident=incident,
        proposal=proposal,
        authorization=authorization,
        permit=permit,
        snapshot=snapshot,
        safety_approval=safety,
        registry=registry,
        transport=transport,
    )

    return result, registry, transport


def test_successful_execution_sends_exactly_one_patch(tmp_path):
    result, registry, transport = execute(
        tmp_path=tmp_path
    )

    assert len(transport.calls) == 1
    assert result.response.accepted is True

    assert (
        registry.active_claim_count(
            namespace="finstream",
            deployment="processor",
        )
        == 0
    )

    assert (
        result.claim.status
        is ExecutionClaimStatus.RELEASED
    )


def test_request_is_fixed_to_finstream_processor(tmp_path):
    result, _, _ = execute(
        tmp_path=tmp_path
    )

    request = result.request

    assert request.namespace == "finstream"
    assert request.deployment == "processor"
    assert request.method == "PATCH"

    assert request.api_path == (
        "/apis/apps/v1/namespaces/"
        "finstream/deployments/processor"
    )


def test_live_request_contains_no_dry_run_parameter(tmp_path):
    result, _, _ = execute(
        tmp_path=tmp_path
    )

    assert "dryRun" not in result.request.api_path
    assert "dryRun" not in result.request.body


def test_request_is_bound_to_authorization_permit_and_claim(
    tmp_path,
):
    result, _, _ = execute(
        tmp_path=tmp_path
    )

    body = json.loads(
        result.request.body
    )

    annotations = (
        body["spec"]["template"]["metadata"]["annotations"]
    )

    assert (
        annotations[
            "finstream.ai-sre/authorization-id"
        ]
        == result.consumed_permit.authorization_id
    )

    assert (
        annotations[
            "finstream.ai-sre/permit-id"
        ]
        == result.consumed_permit.permit_id
    )

    assert (
        annotations[
            "finstream.ai-sre/execution-claim-id"
        ]
        == result.claim.claim_id
    )


def test_success_returns_consumed_permit(tmp_path):
    result, _, _ = execute(
        tmp_path=tmp_path
    )

    assert result.consumed_permit.consumed_at is not None

    assert (
        result.consumed_permit.consumed_by
        == "finstream-kubernetes-executor"
    )


def test_same_original_permit_cannot_execute_twice(tmp_path):
    ready = make_ready()

    registry = SQLiteExecutionRegistry(
        tmp_path / "execution.db"
    )

    transport = FakeTransport()

    args = {
        "incident": ready[0],
        "proposal": ready[1],
        "authorization": ready[2],
        "permit": ready[3],
        "snapshot": ready[4],
        "safety_approval": ready[5],
        "registry": registry,
        "transport": transport,
    }

    GuardedKubernetesRestartExecutor.execute(
        **args
    )

    with pytest.raises(
        ExecutionClaimError,
        match="already been claimed",
    ):
        GuardedKubernetesRestartExecutor.execute(
            **args
        )

    assert len(transport.calls) == 1


def test_transport_failure_releases_claim_and_blocks_replay(
    tmp_path,
):
    ready = make_ready()

    registry = SQLiteExecutionRegistry(
        tmp_path / "execution.db"
    )

    failing = FakeTransport(
        raises=True
    )

    with pytest.raises(
        KubernetesMutationError,
        match="transport failed",
    ):
        GuardedKubernetesRestartExecutor.execute(
            incident=ready[0],
            proposal=ready[1],
            authorization=ready[2],
            permit=ready[3],
            snapshot=ready[4],
            safety_approval=ready[5],
            registry=registry,
            transport=failing,
        )

    assert (
        registry.active_claim_count(
            namespace="finstream",
            deployment="processor",
        )
        == 0
    )

    healthy = FakeTransport()

    with pytest.raises(
        ExecutionClaimError,
        match="already been claimed",
    ):
        GuardedKubernetesRestartExecutor.execute(
            incident=ready[0],
            proposal=ready[1],
            authorization=ready[2],
            permit=ready[3],
            snapshot=ready[4],
            safety_approval=ready[5],
            registry=registry,
            transport=healthy,
        )

    assert healthy.calls == []


def test_rejected_transport_response_fails_closed(tmp_path):
    transport = FakeTransport(
        accepted=False
    )

    with pytest.raises(
        KubernetesMutationError,
        match="not accepted",
    ):
        execute(
            tmp_path=tmp_path,
            transport=transport,
        )

    assert len(transport.calls) == 1


def test_stale_safety_approval_blocks_transport(tmp_path):
    ready = list(
        make_ready()
    )

    ready[5] = replace(
        ready[5],
        evaluated_at=(
            utc_now()
            - timedelta(minutes=1)
        ),
        expires_at=(
            utc_now()
            - timedelta(seconds=1)
        ),
    )

    transport = FakeTransport()

    with pytest.raises(
        Exception,
        match="expired",
    ):
        execute(
            tmp_path=tmp_path,
            ready=tuple(ready),
            transport=transport,
        )

    assert transport.calls == []


def test_changed_runtime_snapshot_blocks_transport(tmp_path):
    ready = list(
        make_ready()
    )

    ready[4] = replace(
        ready[4],
        deployment_generation=13,
    )

    transport = FakeTransport()

    with pytest.raises(
        Exception,
        match="generation changed",
    ):
        execute(
            tmp_path=tmp_path,
            ready=tuple(ready),
            transport=transport,
        )

    assert transport.calls == []
