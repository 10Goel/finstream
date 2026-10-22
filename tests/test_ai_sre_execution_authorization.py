from dataclasses import replace

import pytest

from services.ai_sre_agent.models import (
    AlertStatus,
    Incident,
    IncidentStatus,
)
from services.ai_sre_agent.remediation import (
    ExecutionAuthorizationError,
    ExecutionAuthorizationManager,
    ExecutionAuthorizationStatus,
    RemediationActionType,
    RemediationApprovalWorkflow,
    RemediationIncidentCoordinator,
    RemediationRiskLevel,
    SelectedRemediation,
)


def make_incident() -> Incident:
    incident = Incident(
        fingerprint="execution-authorization-test",
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

    return incident


def make_selected(
    *,
    requires_approval: bool = True,
    action_type: RemediationActionType = (
        RemediationActionType.ROLLING_RESTART
    ),
) -> SelectedRemediation:
    return SelectedRemediation(
        action_id=(
            "processor-rolling-restart"
            if requires_approval
            else "processor-dependency-investigation"
        ),
        action_type=action_type,
        affected_service="processor",
        description="Approved remediation action.",
        rationale="Deterministic FinStream policy rationale.",
        risk_level=(
            RemediationRiskLevel.MEDIUM
            if requires_approval
            else RemediationRiskLevel.LOW
        ),
        requires_approval=requires_approval,
        supporting_evidence=(
            "ev-prometheus",
            "ev-kubernetes",
        ),
        verification_steps=(
            "Confirm processor readiness.",
            "Confirm Prometheus target health.",
        ),
        rollback_guidance=(
            "Return the incident to investigation if recovery fails."
        ),
        model_rationale=(
            "Model selected the approved action."
        ),
    )


def make_human_approved():
    incident = make_incident()

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
        reason="Evidence reviewed.",
    )

    return incident, approved


def test_human_approved_mutation_can_be_authorized():
    incident, proposal = make_human_approved()

    authorization = ExecutionAuthorizationManager.issue(
        incident=incident,
        proposal=proposal,
    )

    assert (
        authorization.status
        is ExecutionAuthorizationStatus.AUTHORIZED
    )

    assert authorization.incident_id == incident.incident_id
    assert authorization.proposal_id == proposal.proposal_id
    assert authorization.action_id == proposal.action_id
    assert authorization.approved_by == "operator@example"
    assert len(authorization.proposal_digest) == 64


def test_authorization_validates_against_approved_proposal():
    incident, proposal = make_human_approved()

    authorization = ExecutionAuthorizationManager.issue(
        incident=incident,
        proposal=proposal,
    )

    ExecutionAuthorizationManager.validate(
        incident=incident,
        proposal=proposal,
        authorization=authorization,
    )


def test_unapproved_incident_cannot_receive_authorization():
    incident = make_incident()

    proposal = RemediationApprovalWorkflow.propose(
        incident_id=incident.incident_id,
        selection=make_selected(),
    )

    with pytest.raises(
        ExecutionAuthorizationError,
        match="Incident must be APPROVED",
    ):
        ExecutionAuthorizationManager.issue(
            incident=incident,
            proposal=proposal,
        )


def test_policy_approved_action_cannot_receive_execution_authorization():
    incident = make_incident()

    proposal = RemediationApprovalWorkflow.propose(
        incident_id=incident.incident_id,
        selection=make_selected(
            requires_approval=False,
            action_type=(
                RemediationActionType.INVESTIGATE_DEPENDENCIES
            ),
        ),
    )

    approved = RemediationIncidentCoordinator.submit(
        incident=incident,
        proposal=proposal,
    )

    with pytest.raises(
        ExecutionAuthorizationError,
    ):
        ExecutionAuthorizationManager.issue(
            incident=incident,
            proposal=approved,
        )


def test_changed_proposal_fails_digest_validation():
    incident, proposal = make_human_approved()

    authorization = ExecutionAuthorizationManager.issue(
        incident=incident,
        proposal=proposal,
    )

    altered = replace(
        proposal,
        rationale="Altered after approval.",
    )

    with pytest.raises(
        ExecutionAuthorizationError,
        match="changed after authorization",
    ):
        ExecutionAuthorizationManager.validate(
            incident=incident,
            proposal=altered,
            authorization=authorization,
        )


def test_authorization_for_different_incident_is_rejected():
    incident, proposal = make_human_approved()

    authorization = ExecutionAuthorizationManager.issue(
        incident=incident,
        proposal=proposal,
    )

    other = make_incident()

    with pytest.raises(
        ExecutionAuthorizationError,
        match="different incident",
    ):
        ExecutionAuthorizationManager.validate(
            incident=other,
            proposal=proposal,
            authorization=authorization,
        )


def test_authorization_can_be_revoked():
    incident, proposal = make_human_approved()

    authorization = ExecutionAuthorizationManager.issue(
        incident=incident,
        proposal=proposal,
    )

    revoked = ExecutionAuthorizationManager.revoke(
        authorization,
        reviewer="operator@example",
        reason="Change window closed.",
    )

    assert (
        revoked.status
        is ExecutionAuthorizationStatus.REVOKED
    )
    assert revoked.revoked_at is not None
    assert revoked.revoked_by == "operator@example"

    with pytest.raises(
        ExecutionAuthorizationError,
        match="not active",
    ):
        ExecutionAuthorizationManager.validate(
            incident=incident,
            proposal=proposal,
            authorization=revoked,
        )


def test_authorization_manager_has_no_execution_api():
    forbidden = (
        "execute",
        "run",
        "apply",
        "restart",
        "remediate",
    )

    for name in forbidden:
        assert not hasattr(
            ExecutionAuthorizationManager,
            name,
        )
