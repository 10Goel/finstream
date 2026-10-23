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
from services.ai_sre_agent.remediation.execution_arm import (
    LiveExecutionArm,
)
from services.ai_sre_agent.remediation.execution_registry import (
    SQLiteExecutionRegistry,
)
from services.ai_sre_agent.remediation.execution_verification import (
    LiveExecutionVerificationError,
    LiveExecutionVerificationSnapshot,
    LiveExecutionVerifier,
)
from services.ai_sre_agent.remediation.executor import (
    GuardedExecutionResult,
    GuardedKubernetesRestartExecutor,
    KubernetesMutationTransport,
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
    """Coordinate guarded remediation controls with mandatory auditing."""

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

    def execute_guarded_restart(
        self,
        *,
        incident: Incident,
        proposal: RemediationProposal,
        authorization: ExecutionAuthorization,
        permit: ExecutionPermit,
        snapshot: ExecutionSafetySnapshot,
        safety_approval: ExecutionSafetyApproval,
        registry: SQLiteExecutionRegistry,
        transport: KubernetesMutationTransport,
        live_arm: LiveExecutionArm | None = None,
        actor: str = "finstream-kubernetes-executor",
    ) -> GuardedExecutionResult:
        """Execute and audit one guarded processor restart."""
        self._audit_log.append(
            event_type=AuditEventType.EXECUTION_REQUESTED,
            actor=actor,
            incident_id=incident.incident_id,
            proposal_id=proposal.proposal_id,
            authorization_id=(
                authorization.authorization_id
            ),
            permit_id=permit.permit_id,
            details={
                "action_id": proposal.action_id,
                "namespace": safety_approval.namespace,
                "deployment": safety_approval.deployment,
                "safety_approval_id": (
                    safety_approval.safety_approval_id
                ),
                "transport_mode": (
                    getattr(transport, "mode", None).value
                    if getattr(
                        transport,
                        "mode",
                        None,
                    ) is not None
                    else None
                ),
                "live_arm_id": (
                    live_arm.arm_id
                    if live_arm is not None
                    else None
                ),
                "live_arm_reviewer": (
                    live_arm.reviewer
                    if live_arm is not None
                    else None
                ),
            },
        )

        try:
            result = (
                GuardedKubernetesRestartExecutor.execute(
                    incident=incident,
                    proposal=proposal,
                    authorization=authorization,
                    permit=permit,
                    snapshot=snapshot,
                    safety_approval=safety_approval,
                    registry=registry,
                    transport=transport,
                    live_arm=live_arm,
                    consumer=actor,
                )
            )
        except Exception as exc:
            self._audit_log.append(
                event_type=AuditEventType.EXECUTION_FAILED,
                actor=actor,
                incident_id=incident.incident_id,
                proposal_id=proposal.proposal_id,
                authorization_id=(
                    authorization.authorization_id
                ),
                permit_id=permit.permit_id,
                details={
                    "action_id": proposal.action_id,
                    "error_type": type(exc).__name__,
                    "live_arm_id": (
                        live_arm.arm_id
                        if live_arm is not None
                        else None
                    ),
                },
            )

            raise

        self._audit_log.append(
            event_type=AuditEventType.EXECUTION_SUCCEEDED,
            actor=actor,
            incident_id=incident.incident_id,
            proposal_id=proposal.proposal_id,
            authorization_id=(
                authorization.authorization_id
            ),
            permit_id=result.consumed_permit.permit_id,
            details={
                "action_id": proposal.action_id,
                "claim_id": result.claim.claim_id,
                "request_digest": (
                    result.request.request_digest
                ),
                "status_code": result.response.status_code,
                "resource_version": (
                    result.response.resource_version
                ),
                "live_arm_id": (
                    result.consumed_arm.arm_id
                    if result.consumed_arm is not None
                    else None
                ),
                "live_arm_consumed_by": (
                    result.consumed_arm.consumed_by
                    if result.consumed_arm is not None
                    else None
                ),
                "outcome": (
                    "LIVE_MUTATION_ACCEPTED_"
                    "PENDING_VERIFICATION"
                    if result.consumed_arm is not None
                    else "SERVER_DRY_RUN_ACCEPTED"
                ),
            },
        )

        return result

    def verify_live_execution(
        self,
        *,
        incident: Incident,
        proposal: RemediationProposal,
        authorization: ExecutionAuthorization,
        permit: ExecutionPermit,
        safety_approval: ExecutionSafetyApproval,
        result: GuardedExecutionResult,
        snapshot: LiveExecutionVerificationSnapshot,
        actor: str = "finstream-execution-verifier",
    ) -> None:
        """Verify and audit recovery after one live remediation."""
        try:
            arm = result.consumed_arm

            if arm is None:
                raise LiveExecutionVerificationError(
                    "Live recovery verification requires "
                    "a consumed live execution arm."
                )

            if arm.incident_id != incident.incident_id:
                raise LiveExecutionVerificationError(
                    "Verification incident does not match "
                    "the consumed live arm."
                )

            if arm.proposal_id != proposal.proposal_id:
                raise LiveExecutionVerificationError(
                    "Verification proposal does not match "
                    "the consumed live arm."
                )

            if (
                arm.authorization_id
                != authorization.authorization_id
            ):
                raise LiveExecutionVerificationError(
                    "Verification authorization does not match "
                    "the consumed live arm."
                )

            if arm.permit_id != permit.permit_id:
                raise LiveExecutionVerificationError(
                    "Verification permit does not match "
                    "the consumed live arm."
                )

            if not result.response.accepted:
                raise LiveExecutionVerificationError(
                    "Cannot verify a live mutation that was "
                    "not accepted."
                )

            LiveExecutionVerifier.verify(
                safety_approval=safety_approval,
                snapshot=snapshot,
            )

        except Exception as exc:
            self._audit_log.append(
                event_type=(
                    AuditEventType.EXECUTION_VERIFICATION_FAILED
                ),
                actor=actor,
                incident_id=incident.incident_id,
                proposal_id=proposal.proposal_id,
                authorization_id=(
                    authorization.authorization_id
                ),
                permit_id=permit.permit_id,
                details={
                    "action_id": proposal.action_id,
                    "request_digest": (
                        result.request.request_digest
                    ),
                    "live_arm_id": (
                        result.consumed_arm.arm_id
                        if result.consumed_arm is not None
                        else None
                    ),
                    "error_type": type(exc).__name__,
                    "reason": str(exc),
                },
            )

            raise

        self._audit_log.append(
            event_type=(
                AuditEventType.EXECUTION_VERIFICATION_PASSED
            ),
            actor=actor,
            incident_id=incident.incident_id,
            proposal_id=proposal.proposal_id,
            authorization_id=(
                authorization.authorization_id
            ),
            permit_id=permit.permit_id,
            details={
                "action_id": proposal.action_id,
                "request_digest": result.request.request_digest,
                "resource_version": (
                    result.response.resource_version
                ),
                "live_arm_id": result.consumed_arm.arm_id,
                "previous_pod_uid": snapshot.previous_pod_uid,
                "current_pod_uid": snapshot.current_pod_uid,
                "current_generation": (
                    snapshot.current_generation
                ),
                "observed_generation": (
                    snapshot.observed_generation
                ),
                "desired_replicas": snapshot.desired_replicas,
                "updated_replicas": snapshot.updated_replicas,
                "ready_replicas": snapshot.ready_replicas,
                "available_replicas": (
                    snapshot.available_replicas
                ),
                "processor_target_up": (
                    snapshot.processor_target_up
                ),
                "kafka_healthy": snapshot.kafka_healthy,
                "postgres_healthy": snapshot.postgres_healthy,
            },
        )
