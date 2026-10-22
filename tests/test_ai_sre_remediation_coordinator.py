import pytest

from services.ai_sre_agent.models import (
    AlertStatus,
    Incident,
    IncidentStatus,
)
from services.ai_sre_agent.remediation import (
    RemediationActionType,
    RemediationApprovalStatus,
    RemediationApprovalWorkflow,
    RemediationCoordinationError,
    RemediationIncidentCoordinator,
    RemediationRiskLevel,
    SelectedRemediation,
)


def make_incident() -> Incident:
    incident = Incident(
        fingerprint="remediation-coordination-test",
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
        description="Approved FinStream remediation.",
        rationale="Deterministic policy rationale.",
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
            "Confirm service health.",
        ),
        rollback_guidance=(
            "Return to investigation if recovery fails."
        ),
        model_rationale=(
            "Model selected an approved candidate."
        ),
    )


def make_proposal(
    incident: Incident,
    *,
    requires_approval: bool = True,
    action_type: RemediationActionType = (
        RemediationActionType.ROLLING_RESTART
    ),
):
    return RemediationApprovalWorkflow.propose(
        incident_id=incident.incident_id,
        selection=make_selected(
            requires_approval=requires_approval,
            action_type=action_type,
        ),
    )


def test_mutating_submission_waits_for_human_approval():
    incident = make_incident()
    proposal = make_proposal(
        incident
    )

    submitted = RemediationIncidentCoordinator.submit(
        incident=incident,
        proposal=proposal,
    )

    assert (
        submitted.status
        is RemediationApprovalStatus.AWAITING_APPROVAL
    )

    assert (
        incident.status
        is IncidentStatus.AWAITING_APPROVAL
    )


def test_human_approval_moves_incident_to_approved_only():
    incident = make_incident()

    proposal = RemediationIncidentCoordinator.submit(
        incident=incident,
        proposal=make_proposal(incident),
    )

    approved = RemediationIncidentCoordinator.approve(
        incident=incident,
        proposal=proposal,
        reviewer="operator@example",
    )

    assert (
        approved.status
        is RemediationApprovalStatus.APPROVED
    )

    assert (
        incident.status
        is IncidentStatus.APPROVED
    )

    assert incident.status is not IncidentStatus.REMEDIATING


def test_rejection_returns_incident_to_investigation():
    incident = make_incident()

    proposal = RemediationIncidentCoordinator.submit(
        incident=incident,
        proposal=make_proposal(incident),
    )

    rejected = RemediationIncidentCoordinator.reject(
        incident=incident,
        proposal=proposal,
        reviewer="operator@example",
        reason="Change window unavailable.",
    )

    assert (
        rejected.status
        is RemediationApprovalStatus.REJECTED
    )

    assert (
        incident.status
        is IncidentStatus.INVESTIGATING
    )


def test_non_mutating_action_returns_to_investigation():
    incident = make_incident()

    proposal = make_proposal(
        incident,
        requires_approval=False,
        action_type=(
            RemediationActionType.INVESTIGATE_DEPENDENCIES
        ),
    )

    approved = RemediationIncidentCoordinator.submit(
        incident=incident,
        proposal=proposal,
    )

    assert (
        approved.status
        is RemediationApprovalStatus.APPROVED
    )

    assert approved.decided_by == "finstream-policy"

    assert (
        incident.status
        is IncidentStatus.INVESTIGATING
    )


def test_proposal_for_different_incident_is_rejected():
    incident = make_incident()

    proposal = RemediationApprovalWorkflow.propose(
        incident_id="inc-something-else",
        selection=make_selected(),
    )

    with pytest.raises(
        RemediationCoordinationError,
        match="different incident",
    ):
        RemediationIncidentCoordinator.submit(
            incident=incident,
            proposal=proposal,
        )


def test_mutating_action_cannot_bypass_human_approval():
    incident = make_incident()

    proposal = make_proposal(
        incident,
        requires_approval=False,
        action_type=(
            RemediationActionType.ROLLING_RESTART
        ),
    )

    with pytest.raises(
        RemediationCoordinationError,
        match="bypass human approval",
    ):
        RemediationIncidentCoordinator.submit(
            incident=incident,
            proposal=proposal,
        )

    assert incident.status is IncidentStatus.DIAGNOSED


def test_coordinator_has_no_execution_api():
    forbidden = (
        "execute",
        "run",
        "apply",
        "restart",
        "remediate",
    )

    for name in forbidden:
        assert not hasattr(
            RemediationIncidentCoordinator,
            name,
        )
