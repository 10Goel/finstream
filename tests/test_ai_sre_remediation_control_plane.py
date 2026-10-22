import pytest

from services.ai_sre_agent.models import (
    AlertStatus,
    Incident,
    IncidentStatus,
)
from services.ai_sre_agent.remediation import (
    AuditedRemediationControlPlane,
    AuditEventType,
    ExecutionAuthorizationError,
    ExecutionPermitStatus,
    JsonlAuditLog,
    RemediationActionType,
    RemediationApprovalStatus,
    RemediationRiskLevel,
    SelectedRemediation,
)


def make_incident() -> Incident:
    incident = Incident(
        fingerprint="audited-control-plane-test",
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
        description="FinStream-approved remediation.",
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
            "Confirm processor readiness.",
        ),
        rollback_guidance=(
            "Return to investigation if recovery fails."
        ),
        model_rationale=(
            "Untrusted model commentary."
        ),
    )


def make_control_plane(tmp_path):
    log = JsonlAuditLog(
        tmp_path / "ai-sre-audit.jsonl"
    )

    return (
        AuditedRemediationControlPlane(
            audit_log=log
        ),
        log,
    )


def test_human_approved_path_is_audited_end_to_end(
    tmp_path,
):
    control, log = make_control_plane(
        tmp_path
    )
    incident = make_incident()

    proposal = control.propose(
        incident=incident,
        selection=make_selected(),
    )

    waiting = control.submit(
        incident=incident,
        proposal=proposal,
    )

    approved = control.approve(
        incident=incident,
        proposal=waiting,
        reviewer="operator@example",
        reason="Evidence reviewed.",
    )

    authorization = control.issue_authorization(
        incident=incident,
        proposal=approved,
    )

    permit = control.issue_permit(
        incident=incident,
        proposal=approved,
        authorization=authorization,
        ttl_seconds=300,
    )

    consumed = control.consume_permit(
        incident=incident,
        proposal=approved,
        authorization=authorization,
        permit=permit,
        consumer="future-kubernetes-actuator",
    )

    assert consumed.consumed_by == (
        "future-kubernetes-actuator"
    )

    records = log.read_all()

    assert [
        record.event_type
        for record in records
    ] == [
        AuditEventType.PROPOSAL_CREATED,
        AuditEventType.PROPOSAL_SUBMITTED,
        AuditEventType.PROPOSAL_APPROVED,
        AuditEventType.AUTHORIZATION_ISSUED,
        AuditEventType.PERMIT_ISSUED,
        AuditEventType.PERMIT_CONSUMED,
    ]

    assert log.verify() == 6


def test_human_rejection_is_audited(tmp_path):
    control, log = make_control_plane(
        tmp_path
    )
    incident = make_incident()

    proposal = control.propose(
        incident=incident,
        selection=make_selected(),
    )

    waiting = control.submit(
        incident=incident,
        proposal=proposal,
    )

    rejected = control.reject(
        incident=incident,
        proposal=waiting,
        reviewer="operator@example",
        reason="Change window closed.",
    )

    assert (
        rejected.status
        is RemediationApprovalStatus.REJECTED
    )

    assert incident.status is IncidentStatus.INVESTIGATING

    assert [
        record.event_type
        for record in log.read_all()
    ] == [
        AuditEventType.PROPOSAL_CREATED,
        AuditEventType.PROPOSAL_SUBMITTED,
        AuditEventType.PROPOSAL_REJECTED,
    ]


def test_policy_approval_is_explicitly_audited(tmp_path):
    control, log = make_control_plane(
        tmp_path
    )
    incident = make_incident()

    proposal = control.propose(
        incident=incident,
        selection=make_selected(
            requires_approval=False,
            action_type=(
                RemediationActionType.INVESTIGATE_DEPENDENCIES
            ),
        ),
    )

    approved = control.submit(
        incident=incident,
        proposal=proposal,
    )

    assert (
        approved.status
        is RemediationApprovalStatus.APPROVED
    )

    records = log.read_all()

    assert [
        record.event_type
        for record in records
    ] == [
        AuditEventType.PROPOSAL_CREATED,
        AuditEventType.PROPOSAL_SUBMITTED,
        AuditEventType.PROPOSAL_APPROVED,
    ]

    assert records[-1].actor == "finstream-policy"


def test_failed_authorization_does_not_log_success(
    tmp_path,
):
    control, log = make_control_plane(
        tmp_path
    )
    incident = make_incident()

    proposal = control.propose(
        incident=incident,
        selection=make_selected(),
    )

    with pytest.raises(
        ExecutionAuthorizationError,
    ):
        control.issue_authorization(
            incident=incident,
            proposal=proposal,
        )

    records = log.read_all()

    assert len(records) == 1
    assert (
        records[0].event_type
        is AuditEventType.PROPOSAL_CREATED
    )


def test_authorization_revocation_is_audited(tmp_path):
    control, log = make_control_plane(
        tmp_path
    )
    incident = make_incident()

    proposal = control.propose(
        incident=incident,
        selection=make_selected(),
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

    control.revoke_authorization(
        authorization=authorization,
        reviewer="operator@example",
        reason="Maintenance window closed.",
    )

    assert (
        log.read_all()[-1].event_type
        is AuditEventType.AUTHORIZATION_REVOKED
    )


def test_model_commentary_is_not_written_to_audit(
    tmp_path,
):
    control, log = make_control_plane(
        tmp_path
    )
    incident = make_incident()

    control.propose(
        incident=incident,
        selection=make_selected(),
    )

    raw = log.path.read_text()

    assert "Untrusted model commentary." not in raw


def test_control_plane_has_no_execution_api(tmp_path):
    control, _ = make_control_plane(
        tmp_path
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
            control,
            name,
        )


def test_kubernetes_dry_run_preparation_is_audited(
    tmp_path,
):
    control, log = make_control_plane(
        tmp_path
    )
    incident = make_incident()

    proposal = control.propose(
        incident=incident,
        selection=make_selected(),
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

    request = control.prepare_kubernetes_dry_run(
        incident=incident,
        proposal=approved,
        authorization=authorization,
        permit=permit,
    )

    assert request.name == "processor"

    final_record = log.read_all()[-1]

    assert (
        final_record.event_type
        is AuditEventType.KUBERNETES_DRY_RUN_PREPARED
    )

    assert (
        final_record.details["request_digest"]
        == request.request_digest
    )

    assert final_record.details["dry_run"] is True

    assert permit.status is ExecutionPermitStatus.ACTIVE
