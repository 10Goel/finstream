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
    ExecutionPermitManager,
    ExecutionPermitStatus,
    KubernetesDryRunActuator,
    KubernetesDryRunError,
    RemediationActionType,
    RemediationApprovalWorkflow,
    RemediationIncidentCoordinator,
    RemediationRiskLevel,
    SelectedRemediation,
)


def make_selected(
    *,
    service: str = "processor",
    action_id: str = "processor-rolling-restart",
) -> SelectedRemediation:
    return SelectedRemediation(
        action_id=action_id,
        action_type=RemediationActionType.ROLLING_RESTART,
        affected_service=service,
        description="Approved rolling restart.",
        rationale="Deterministic FinStream policy rationale.",
        risk_level=RemediationRiskLevel.MEDIUM,
        requires_approval=True,
        supporting_evidence=(
            "ev-prometheus",
            "ev-kubernetes",
        ),
        verification_steps=(
            "Confirm deployment readiness.",
        ),
        rollback_guidance=(
            "Return to investigation if recovery fails."
        ),
        model_rationale=(
            "Untrusted model commentary."
        ),
    )


def make_ready(
    *,
    service: str = "processor",
    action_id: str = "processor-rolling-restart",
):
    incident = Incident(
        fingerprint=f"dry-run-{service}-{action_id}",
        alert_name="FinStreamServiceDown",
        alert_status=AlertStatus.FIRING,
        severity="critical",
        affected_service=service,
    )

    incident.transition_to(
        IncidentStatus.INVESTIGATING
    )
    incident.transition_to(
        IncidentStatus.DIAGNOSED
    )

    proposal = RemediationApprovalWorkflow.propose(
        incident_id=incident.incident_id,
        selection=make_selected(
            service=service,
            action_id=action_id,
        ),
    )

    waiting = RemediationIncidentCoordinator.submit(
        incident=incident,
        proposal=proposal,
    )

    approved = RemediationIncidentCoordinator.approve(
        incident=incident,
        proposal=waiting,
        reviewer="operator@example",
        reason="Approved for validation.",
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

    return (
        incident,
        approved,
        authorization,
        permit,
    )


def test_processor_restart_builds_server_dry_run_request():
    (
        incident,
        proposal,
        authorization,
        permit,
    ) = make_ready()

    request = KubernetesDryRunActuator.prepare(
        incident=incident,
        proposal=proposal,
        authorization=authorization,
        permit=permit,
    )

    assert request.namespace == "finstream"
    assert request.resource == "deployments"
    assert request.name == "processor"
    assert request.method == "PATCH"

    assert (
        request.api_path
        == (
            "/apis/apps/v1/namespaces/"
            "finstream/deployments/processor"
        )
    )

    assert ("dryRun", "All") in request.query
    assert len(request.request_digest) == 64


def test_request_body_is_bound_to_authorization_and_permit():
    (
        incident,
        proposal,
        authorization,
        permit,
    ) = make_ready()

    request = KubernetesDryRunActuator.prepare(
        incident=incident,
        proposal=proposal,
        authorization=authorization,
        permit=permit,
    )

    body = json.loads(
        request.body
    )

    annotations = (
        body["spec"]["template"]["metadata"]["annotations"]
    )

    assert (
        annotations[
            "finstream.ai-sre/authorization-id"
        ]
        == authorization.authorization_id
    )

    assert (
        annotations[
            "finstream.ai-sre/permit-id"
        ]
        == permit.permit_id
    )


def test_preparing_dry_run_does_not_consume_permit():
    (
        incident,
        proposal,
        authorization,
        permit,
    ) = make_ready()

    KubernetesDryRunActuator.prepare(
        incident=incident,
        proposal=proposal,
        authorization=authorization,
        permit=permit,
    )

    assert permit.status is ExecutionPermitStatus.ACTIVE
    assert permit.consumed_at is None
    assert permit.consumed_by is None


def test_non_processor_workload_is_rejected():
    (
        incident,
        proposal,
        authorization,
        permit,
    ) = make_ready(
        service="api",
        action_id="api-rolling-restart",
    )

    with pytest.raises(
        KubernetesDryRunError,
        match="processor deployment",
    ):
        KubernetesDryRunActuator.prepare(
            incident=incident,
            proposal=proposal,
            authorization=authorization,
            permit=permit,
        )


def test_unknown_processor_action_is_rejected():
    (
        incident,
        proposal,
        authorization,
        permit,
    ) = make_ready(
        action_id="processor-other-action",
    )

    with pytest.raises(
        KubernetesDryRunError,
        match="not allowlisted",
    ):
        KubernetesDryRunActuator.prepare(
            incident=incident,
            proposal=proposal,
            authorization=authorization,
            permit=permit,
        )


def test_expired_permit_is_rejected():
    (
        incident,
        proposal,
        authorization,
        permit,
    ) = make_ready()

    expired = replace(
        permit,
        issued_at=utc_now() - timedelta(minutes=10),
        expires_at=utc_now() - timedelta(minutes=5),
    )

    with pytest.raises(
        Exception,
        match="expired",
    ):
        KubernetesDryRunActuator.prepare(
            incident=incident,
            proposal=proposal,
            authorization=authorization,
            permit=expired,
        )


def test_consumed_permit_is_rejected():
    (
        incident,
        proposal,
        authorization,
        permit,
    ) = make_ready()

    consumed = ExecutionPermitManager.consume(
        incident=incident,
        proposal=proposal,
        authorization=authorization,
        permit=permit,
        consumer="test-consumer",
    )

    with pytest.raises(
        Exception,
        match="no longer active",
    ):
        KubernetesDryRunActuator.prepare(
            incident=incident,
            proposal=proposal,
            authorization=authorization,
            permit=consumed,
        )


def test_dry_run_actuator_has_no_execution_api():
    forbidden = (
        "execute",
        "run",
        "apply",
        "restart",
        "send",
    )

    for name in forbidden:
        assert not hasattr(
            KubernetesDryRunActuator,
            name,
        )
