"""Audited remediation control plane for FinStream AI-SRE."""

from __future__ import annotations

from services.ai_sre_agent.models import Incident
from services.ai_sre_agent.remediation.actuator import (
    KubernetesDryRunActuator,
    KubernetesDryRunRequest,
)
from services.ai_sre_agent.remediation.approval import (
    RemediationApprovalStatus,
    RemediationApprovalWorkflow,
    RemediationProposal,
)
from services.ai_sre_agent.remediation.audit import (
    AuditEventType,
    JsonlAuditLog,
)
from services.ai_sre_agent.remediation.authorization import (
    ExecutionAuthorization,
    ExecutionAuthorizationManager,
)
from services.ai_sre_agent.remediation.coordinator import (
    RemediationIncidentCoordinator,
)
from services.ai_sre_agent.remediation.permit import (
    ExecutionPermit,
    ExecutionPermitManager,
)
from services.ai_sre_agent.remediation.safety import (
    ExecutionSafetyApproval,
    ExecutionSafetyError,
    ExecutionSafetyGate,
    ExecutionSafetySnapshot,
)
from services.ai_sre_agent.remediation.selector import (
    SelectedRemediation,
)


class AuditedRemediationControlPlane:
    """Coordinate remediation safety controls with mandatory auditing.

    This class deliberately contains no remediation execution API.
    """

    def __init__(
        self,
        *,
        audit_log: JsonlAuditLog,
    ) -> None:
        self._audit_log = audit_log

    def propose(
        self,
        *,
        incident: Incident,
        selection: SelectedRemediation,
        actor: str = "finstream-ai-sre",
    ) -> RemediationProposal:
        """Create and audit a remediation proposal."""
        if (
            incident.affected_service is not None
            and selection.affected_service
            != incident.affected_service
        ):
            raise ValueError(
                "Selected remediation service does not match "
                "the incident."
            )

        proposal = RemediationApprovalWorkflow.propose(
            incident_id=incident.incident_id,
            selection=selection,
        )

        self._audit_log.append(
            event_type=AuditEventType.PROPOSAL_CREATED,
            actor=actor,
            incident_id=incident.incident_id,
            proposal_id=proposal.proposal_id,
            details={
                "action_id": proposal.action_id,
                "action_type": proposal.action_type,
                "affected_service": (
                    proposal.affected_service
                ),
                "risk_level": proposal.risk_level,
                "requires_approval": (
                    proposal.requires_approval
                ),
                "status": proposal.status,
            },
        )

        return proposal

    def submit(
        self,
        *,
        incident: Incident,
        proposal: RemediationProposal,
        actor: str = "finstream-ai-sre",
    ) -> RemediationProposal:
        """Submit and audit a remediation proposal."""
        submitted = RemediationIncidentCoordinator.submit(
            incident=incident,
            proposal=proposal,
        )

        self._audit_log.append(
            event_type=AuditEventType.PROPOSAL_SUBMITTED,
            actor=actor,
            incident_id=incident.incident_id,
            proposal_id=submitted.proposal_id,
            details={
                "action_id": submitted.action_id,
                "proposal_status": submitted.status,
                "incident_status": incident.status,
            },
        )

        if (
            submitted.status
            is RemediationApprovalStatus.APPROVED
        ):
            self._audit_log.append(
                event_type=(
                    AuditEventType.PROPOSAL_APPROVED
                ),
                actor=(
                    submitted.decided_by
                    or "finstream-policy"
                ),
                incident_id=incident.incident_id,
                proposal_id=submitted.proposal_id,
                details={
                    "action_id": submitted.action_id,
                    "approval_mode": "policy",
                    "incident_status": incident.status,
                },
            )

        return submitted

    def approve(
        self,
        *,
        incident: Incident,
        proposal: RemediationProposal,
        reviewer: str,
        reason: str | None = None,
    ) -> RemediationProposal:
        """Record and audit human approval."""
        approved = RemediationIncidentCoordinator.approve(
            incident=incident,
            proposal=proposal,
            reviewer=reviewer,
            reason=reason,
        )

        self._audit_log.append(
            event_type=AuditEventType.PROPOSAL_APPROVED,
            actor=approved.decided_by or reviewer,
            incident_id=incident.incident_id,
            proposal_id=approved.proposal_id,
            details={
                "action_id": approved.action_id,
                "risk_level": approved.risk_level,
                "requires_approval": (
                    approved.requires_approval
                ),
                "incident_status": incident.status,
            },
        )

        return approved

    def reject(
        self,
        *,
        incident: Incident,
        proposal: RemediationProposal,
        reviewer: str,
        reason: str,
    ) -> RemediationProposal:
        """Record and audit human rejection."""
        rejected = RemediationIncidentCoordinator.reject(
            incident=incident,
            proposal=proposal,
            reviewer=reviewer,
            reason=reason,
        )

        self._audit_log.append(
            event_type=AuditEventType.PROPOSAL_REJECTED,
            actor=rejected.decided_by or reviewer,
            incident_id=incident.incident_id,
            proposal_id=rejected.proposal_id,
            details={
                "action_id": rejected.action_id,
                "incident_status": incident.status,
            },
        )

        return rejected

    def issue_authorization(
        self,
        *,
        incident: Incident,
        proposal: RemediationProposal,
        actor: str = "finstream-ai-sre",
    ) -> ExecutionAuthorization:
        """Issue and audit an execution authorization."""
        authorization = ExecutionAuthorizationManager.issue(
            incident=incident,
            proposal=proposal,
        )

        self._audit_log.append(
            event_type=(
                AuditEventType.AUTHORIZATION_ISSUED
            ),
            actor=actor,
            incident_id=incident.incident_id,
            proposal_id=proposal.proposal_id,
            authorization_id=(
                authorization.authorization_id
            ),
            details={
                "action_id": authorization.action_id,
                "action_type": authorization.action_type,
                "affected_service": (
                    authorization.affected_service
                ),
                "risk_level": authorization.risk_level,
                "approved_by": authorization.approved_by,
                "proposal_digest": (
                    authorization.proposal_digest
                ),
            },
        )

        return authorization

    def revoke_authorization(
        self,
        *,
        authorization: ExecutionAuthorization,
        reviewer: str,
        reason: str,
    ) -> ExecutionAuthorization:
        """Revoke and audit an execution authorization."""
        revoked = ExecutionAuthorizationManager.revoke(
            authorization,
            reviewer=reviewer,
            reason=reason,
        )

        self._audit_log.append(
            event_type=(
                AuditEventType.AUTHORIZATION_REVOKED
            ),
            actor=reviewer,
            incident_id=revoked.incident_id,
            proposal_id=revoked.proposal_id,
            authorization_id=(
                revoked.authorization_id
            ),
            details={
                "action_id": revoked.action_id,
                "status": revoked.status,
            },
        )

        return revoked

    def issue_permit(
        self,
        *,
        incident: Incident,
        proposal: RemediationProposal,
        authorization: ExecutionAuthorization,
        ttl_seconds: int = 300,
        actor: str = "finstream-ai-sre",
    ) -> ExecutionPermit:
        """Issue and audit a short-lived execution permit."""
        permit = ExecutionPermitManager.issue(
            incident=incident,
            proposal=proposal,
            authorization=authorization,
            ttl_seconds=ttl_seconds,
        )

        self._audit_log.append(
            event_type=AuditEventType.PERMIT_ISSUED,
            actor=actor,
            incident_id=permit.incident_id,
            proposal_id=permit.proposal_id,
            authorization_id=permit.authorization_id,
            permit_id=permit.permit_id,
            details={
                "action_id": permit.action_id,
                "affected_service": (
                    permit.affected_service
                ),
                "expires_at": permit.expires_at,
            },
        )

        return permit

    def consume_permit(
        self,
        *,
        incident: Incident,
        proposal: RemediationProposal,
        authorization: ExecutionAuthorization,
        permit: ExecutionPermit,
        consumer: str,
    ) -> ExecutionPermit:
        """Consume and audit a permit without executing remediation."""
        consumed = ExecutionPermitManager.consume(
            incident=incident,
            proposal=proposal,
            authorization=authorization,
            permit=permit,
            consumer=consumer,
        )

        self._audit_log.append(
            event_type=AuditEventType.PERMIT_CONSUMED,
            actor=consumer,
            incident_id=consumed.incident_id,
            proposal_id=consumed.proposal_id,
            authorization_id=(
                consumed.authorization_id
            ),
            permit_id=consumed.permit_id,
            details={
                "action_id": consumed.action_id,
                "status": consumed.status,
            },
        )

        return consumed

    def prepare_kubernetes_dry_run(
        self,
        *,
        incident: Incident,
        proposal: RemediationProposal,
        authorization: ExecutionAuthorization,
        permit: ExecutionPermit,
        actor: str = "finstream-ai-sre",
    ) -> KubernetesDryRunRequest:
        """Prepare and audit a non-mutating Kubernetes dry run."""
        request = KubernetesDryRunActuator.prepare(
            incident=incident,
            proposal=proposal,
            authorization=authorization,
            permit=permit,
        )

        self._audit_log.append(
            event_type=(
                AuditEventType.KUBERNETES_DRY_RUN_PREPARED
            ),
            actor=actor,
            incident_id=incident.incident_id,
            proposal_id=proposal.proposal_id,
            authorization_id=(
                authorization.authorization_id
            ),
            permit_id=permit.permit_id,
            details={
                "namespace": request.namespace,
                "resource": request.resource,
                "name": request.name,
                "method": request.method,
                "dry_run": True,
                "request_digest": (
                    request.request_digest
                ),
            },
        )

        return request

    def evaluate_execution_safety(
        self,
        *,
        incident: Incident,
        proposal: RemediationProposal,
        authorization: ExecutionAuthorization,
        permit: ExecutionPermit,
        snapshot: ExecutionSafetySnapshot,
        actor: str = "finstream-ai-sre",
    ) -> ExecutionSafetyApproval:
        """Evaluate and audit the final runtime safety boundary."""
        try:
            approval = ExecutionSafetyGate.evaluate(
                incident=incident,
                proposal=proposal,
                authorization=authorization,
                permit=permit,
                snapshot=snapshot,
            )
        except ExecutionSafetyError as exc:
            self._audit_log.append(
                event_type=(
                    AuditEventType.EXECUTION_SAFETY_BLOCKED
                ),
                actor=actor,
                incident_id=incident.incident_id,
                proposal_id=proposal.proposal_id,
                authorization_id=(
                    authorization.authorization_id
                ),
                permit_id=permit.permit_id,
                details={
                    "namespace": snapshot.namespace,
                    "deployment": snapshot.deployment,
                    "reason": str(exc),
                },
            )

            raise

        self._audit_log.append(
            event_type=AuditEventType.EXECUTION_SAFETY_PASSED,
            actor=actor,
            incident_id=incident.incident_id,
            proposal_id=proposal.proposal_id,
            authorization_id=(
                authorization.authorization_id
            ),
            permit_id=permit.permit_id,
            details={
                "safety_approval_id": (
                    approval.safety_approval_id
                ),
                "namespace": approval.namespace,
                "deployment": approval.deployment,
                "deployment_generation": (
                    approval.deployment_generation
                ),
                "snapshot_digest": (
                    approval.snapshot_digest
                ),
                "expires_at": approval.expires_at,
            },
        )

        return approval
