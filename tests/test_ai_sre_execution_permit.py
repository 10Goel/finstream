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
    ExecutionPermitError,
    ExecutionPermitManager,
    ExecutionPermitStatus,
    RemediationActionType,
    RemediationApprovalWorkflow,
    RemediationIncidentCoordinator,
    RemediationRiskLevel,
    SelectedRemediation,
)


def make_selected() -> SelectedRemediation:
    return SelectedRemediation(
        action_id="processor-rolling-restart",
        action_type=(
            RemediationActionType.ROLLING_RESTART
        ),
        affected_service="processor",
        description="Approved remediation.",
        rationale="Deterministic policy rationale.",
        risk_level=RemediationRiskLevel.MEDIUM,
        requires_approval=True,
        supporting_evidence=(
            "ev-prometheus",
            "ev-kubernetes",
        ),
        verification_steps=(
            "Confirm processor readiness.",
            "Confirm Prometheus target health.",
        ),
        rollback_guidance=(
            "Return to investigation if recovery fails."
        ),
        model_rationale=(
            "Model selected the approved action."
        ),
    )


def make_authorized():
    incident = Incident(
        fingerprint="execution-permit-test",
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

    proposal = RemediationApprovalWorkflow.propose(
        incident_id=incident.incident_id,
        selection=make_selected(),
    )

    waiting = RemediationIncidentCoordinator.submit(
        incident=incident,
        proposal=proposal,
    )

    approved = RemediationIncidentCoordinator.approve(
        incident=incident,
        proposal=waiting,
        reviewer="operator@example",
        reason="Operational evidence reviewed.",
    )

    authorization = ExecutionAuthorizationManager.issue(
        incident=incident,
        proposal=approved,
    )

    return incident, approved, authorization


def test_active_authorization_can_issue_short_lived_permit():
    incident, proposal, authorization = make_authorized()

    permit = ExecutionPermitManager.issue(
        incident=incident,
        proposal=proposal,
        authorization=authorization,
        ttl_seconds=300,
    )

    assert permit.status is ExecutionPermitStatus.ACTIVE
    assert (
        permit.authorization_id
        == authorization.authorization_id
    )
    assert permit.action_id == authorization.action_id
    assert permit.expires_at > permit.issued_at


def test_active_permit_validates():
    incident, proposal, authorization = make_authorized()

    permit = ExecutionPermitManager.issue(
        incident=incident,
        proposal=proposal,
        authorization=authorization,
    )

    ExecutionPermitManager.validate(
        incident=incident,
        proposal=proposal,
        authorization=authorization,
        permit=permit,
    )


def test_expired_permit_is_rejected():
    incident, proposal, authorization = make_authorized()

    permit = ExecutionPermitManager.issue(
        incident=incident,
        proposal=proposal,
        authorization=authorization,
    )

    expired = replace(
        permit,
        expires_at=utc_now() - timedelta(seconds=1),
        issued_at=utc_now() - timedelta(seconds=2),
    )

    with pytest.raises(
        ExecutionPermitError,
        match="expired",
    ):
        ExecutionPermitManager.validate(
            incident=incident,
            proposal=proposal,
            authorization=authorization,
            permit=expired,
        )


def test_permit_can_be_consumed_once():
    incident, proposal, authorization = make_authorized()

    permit = ExecutionPermitManager.issue(
        incident=incident,
        proposal=proposal,
        authorization=authorization,
    )

    consumed = ExecutionPermitManager.consume(
        incident=incident,
        proposal=proposal,
        authorization=authorization,
        permit=permit,
        consumer="future-kubernetes-actuator",
    )

    assert (
        consumed.status
        is ExecutionPermitStatus.CONSUMED
    )
    assert consumed.consumed_at is not None
    assert (
        consumed.consumed_by
        == "future-kubernetes-actuator"
    )


def test_consumed_permit_cannot_be_reused():
    incident, proposal, authorization = make_authorized()

    permit = ExecutionPermitManager.issue(
        incident=incident,
        proposal=proposal,
        authorization=authorization,
    )

    consumed = ExecutionPermitManager.consume(
        incident=incident,
        proposal=proposal,
        authorization=authorization,
        permit=permit,
        consumer="future-kubernetes-actuator",
    )

    with pytest.raises(
        ExecutionPermitError,
        match="no longer active",
    ):
        ExecutionPermitManager.consume(
            incident=incident,
            proposal=proposal,
            authorization=authorization,
            permit=consumed,
            consumer="future-kubernetes-actuator",
        )


def test_permit_cannot_be_used_with_other_authorization():
    incident, proposal, authorization = make_authorized()

    permit = ExecutionPermitManager.issue(
        incident=incident,
        proposal=proposal,
        authorization=authorization,
    )

    other = replace(
        authorization,
        authorization_id="auth-other",
    )

    with pytest.raises(
        ExecutionPermitError,
        match="authorization ID mismatch",
    ):
        ExecutionPermitManager.validate(
            incident=incident,
            proposal=proposal,
            authorization=other,
            permit=permit,
        )


def test_invalid_ttl_is_rejected():
    incident, proposal, authorization = make_authorized()

    with pytest.raises(
        ExecutionPermitError,
        match="TTL",
    ):
        ExecutionPermitManager.issue(
            incident=incident,
            proposal=proposal,
            authorization=authorization,
            ttl_seconds=0,
        )

    with pytest.raises(
        ExecutionPermitError,
        match="TTL",
    ):
        ExecutionPermitManager.issue(
            incident=incident,
            proposal=proposal,
            authorization=authorization,
            ttl_seconds=901,
        )


def test_permit_manager_has_no_execution_api():
    forbidden = (
        "execute",
        "run",
        "apply",
        "restart",
        "remediate",
    )

    for name in forbidden:
        assert not hasattr(
            ExecutionPermitManager,
            name,
        )
