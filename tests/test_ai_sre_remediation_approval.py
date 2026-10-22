import pytest

from services.ai_sre_agent.remediation import (
    RemediationActionType,
    RemediationApprovalError,
    RemediationApprovalStatus,
    RemediationApprovalWorkflow,
    RemediationRiskLevel,
    SelectedRemediation,
)


def make_selected(
    *,
    requires_approval: bool = True,
    action_type: RemediationActionType = (
        RemediationActionType.ROLLING_RESTART
    ),
) -> SelectedRemediation:
    if requires_approval:
        action_id = "processor-rolling-restart"
        risk = RemediationRiskLevel.MEDIUM
    else:
        action_id = "producer-dependency-investigation"
        risk = RemediationRiskLevel.LOW

    return SelectedRemediation(
        action_id=action_id,
        action_type=action_type,
        affected_service="processor",
        description="Approved FinStream remediation.",
        rationale="Deterministic policy rationale.",
        risk_level=risk,
        requires_approval=requires_approval,
        supporting_evidence=(
            "ev-prometheus",
            "ev-kubernetes",
        ),
        verification_steps=(
            "Confirm service health.",
            "Confirm incident symptoms recover.",
        ),
        rollback_guidance=(
            "Return to investigation if recovery fails."
        ),
        model_rationale=(
            "Model selected an approved candidate."
        ),
    )


def test_selected_remediation_becomes_proposed_plan():
    selected = make_selected()

    proposal = RemediationApprovalWorkflow.propose(
        incident_id="inc-test",
        selection=selected,
    )

    assert (
        proposal.status
        is RemediationApprovalStatus.PROPOSED
    )

    assert proposal.action_id == selected.action_id
    assert proposal.risk_level is selected.risk_level
    assert (
        proposal.requires_approval
        is selected.requires_approval
    )
    assert (
        proposal.supporting_evidence
        == selected.supporting_evidence
    )


def test_approval_required_plan_moves_to_waiting():
    proposal = RemediationApprovalWorkflow.propose(
        incident_id="inc-test",
        selection=make_selected(),
    )

    waiting = RemediationApprovalWorkflow.submit(
        proposal
    )

    assert (
        waiting.status
        is RemediationApprovalStatus.AWAITING_APPROVAL
    )
    assert waiting.submitted_at is not None
    assert waiting.decided_at is None
    assert waiting.decided_by is None


def test_human_can_approve_waiting_plan():
    proposal = RemediationApprovalWorkflow.propose(
        incident_id="inc-test",
        selection=make_selected(),
    )

    waiting = RemediationApprovalWorkflow.submit(
        proposal
    )

    approved = RemediationApprovalWorkflow.approve(
        waiting,
        reviewer="operator@example",
        reason="Reviewed operational evidence.",
    )

    assert (
        approved.status
        is RemediationApprovalStatus.APPROVED
    )
    assert approved.decided_at is not None
    assert approved.decided_by == "operator@example"
    assert (
        approved.decision_reason
        == "Reviewed operational evidence."
    )


def test_human_can_reject_waiting_plan():
    proposal = RemediationApprovalWorkflow.propose(
        incident_id="inc-test",
        selection=make_selected(),
    )

    waiting = RemediationApprovalWorkflow.submit(
        proposal
    )

    rejected = RemediationApprovalWorkflow.reject(
        waiting,
        reviewer="operator@example",
        reason="Maintenance window is closed.",
    )

    assert (
        rejected.status
        is RemediationApprovalStatus.REJECTED
    )
    assert rejected.decided_at is not None
    assert rejected.decided_by == "operator@example"


def test_non_mutating_plan_can_be_policy_approved():
    proposal = RemediationApprovalWorkflow.propose(
        incident_id="inc-test",
        selection=make_selected(
            requires_approval=False,
            action_type=(
                RemediationActionType.INVESTIGATE_DEPENDENCIES
            ),
        ),
    )

    approved = RemediationApprovalWorkflow.submit(
        proposal
    )

    assert (
        approved.status
        is RemediationApprovalStatus.APPROVED
    )
    assert approved.decided_by == "finstream-policy"
    assert approved.requires_approval is False


def test_approval_cannot_skip_waiting_state():
    proposal = RemediationApprovalWorkflow.propose(
        incident_id="inc-test",
        selection=make_selected(),
    )

    with pytest.raises(
        RemediationApprovalError,
        match="AWAITING_APPROVAL",
    ):
        RemediationApprovalWorkflow.approve(
            proposal,
            reviewer="operator@example",
        )


def test_rejection_requires_audit_reason():
    proposal = RemediationApprovalWorkflow.propose(
        incident_id="inc-test",
        selection=make_selected(),
    )

    waiting = RemediationApprovalWorkflow.submit(
        proposal
    )

    with pytest.raises(
        RemediationApprovalError,
        match="requires a reason",
    ):
        RemediationApprovalWorkflow.reject(
            waiting,
            reviewer="operator@example",
            reason="   ",
        )


def test_approval_workflow_has_no_execution_api():
    assert not hasattr(
        RemediationApprovalWorkflow,
        "execute",
    )

    assert not hasattr(
        RemediationApprovalWorkflow,
        "run",
    )

    assert not hasattr(
        RemediationApprovalWorkflow,
        "apply",
    )
