"""Guarded mutation executor for FinStream AI-SRE."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from typing import Protocol

from services.ai_sre_agent.models import (
    Incident,
    utc_now,
)
from services.ai_sre_agent.remediation.approval import (
    RemediationProposal,
)
from services.ai_sre_agent.remediation.authorization import (
    ExecutionAuthorization,
)
from services.ai_sre_agent.remediation.execution_arm import (
    LiveExecutionArm,
    LiveExecutionArmManager,
)
from services.ai_sre_agent.remediation.execution_registry import (
    ExecutionClaim,
    SQLiteExecutionRegistry,
)
from services.ai_sre_agent.remediation.permit import (
    ExecutionPermit,
    ExecutionPermitManager,
)
from services.ai_sre_agent.remediation.safety import (
    ExecutionSafetyApproval,
    ExecutionSafetyGate,
    ExecutionSafetySnapshot,
)


class KubernetesMutationError(RuntimeError):
    """A guarded Kubernetes mutation could not complete safely."""


@dataclass(frozen=True, slots=True)
class KubernetesMutationRequest:
    """Exact allowlisted Kubernetes mutation request."""

    namespace: str
    deployment: str

    method: str
    api_path: str
    content_type: str
    body: str

    request_digest: str

    def __post_init__(self) -> None:
        if self.namespace != "finstream":
            raise ValueError(
                "Mutation request namespace must be finstream."
            )

        if self.deployment != "processor":
            raise ValueError(
                "Mutation request deployment must be processor."
            )

        if self.method != "PATCH":
            raise ValueError(
                "Mutation request must use PATCH."
            )

        if len(self.request_digest) != 64:
            raise ValueError(
                "Mutation request digest must be SHA-256."
            )


@dataclass(frozen=True, slots=True)
class KubernetesMutationResponse:
    """Minimal transport response used by the guarded executor."""

    accepted: bool
    status_code: int
    resource_version: str | None = None
    message: str | None = None


class KubernetesMutationMode(str, Enum):
    """Explicit capability exposed by a Kubernetes transport."""

    SERVER_DRY_RUN = "SERVER_DRY_RUN"
    LIVE = "LIVE"


class KubernetesMutationTransport(Protocol):
    """Transport boundary for an allowlisted Kubernetes mutation."""

    mode: KubernetesMutationMode

    def patch_deployment(
        self,
        request: KubernetesMutationRequest,
    ) -> KubernetesMutationResponse:
        """Submit exactly one Kubernetes deployment patch."""


@dataclass(frozen=True, slots=True)
class GuardedExecutionResult:
    """Outcome of one guarded mutation attempt."""

    claim: ExecutionClaim
    consumed_permit: ExecutionPermit
    request: KubernetesMutationRequest
    response: KubernetesMutationResponse
    consumed_arm: LiveExecutionArm | None = None


class GuardedKubernetesRestartExecutor:
    """Execute one allowlisted processor rolling restart.

    The executor receives a transport dependency. It contains no
    kubectl, subprocess, socket, or HTTP implementation itself.
    """

    NAMESPACE = "finstream"
    DEPLOYMENT = "processor"
    ACTION_ID = "processor-rolling-restart"

    @staticmethod
    def _digest(
        *,
        api_path: str,
        body: str,
    ) -> str:
        payload = {
            "method": "PATCH",
            "api_path": api_path,
            "content_type": (
                "application/merge-patch+json"
            ),
            "body": body,
        }

        encoded = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

        return hashlib.sha256(
            encoded
        ).hexdigest()

    @classmethod
    def _build_request(
        cls,
        *,
        authorization: ExecutionAuthorization,
        permit: ExecutionPermit,
        claim: ExecutionClaim,
    ) -> KubernetesMutationRequest:
        executed_at = utc_now().isoformat()

        body = json.dumps(
            {
                "spec": {
                    "template": {
                        "metadata": {
                            "annotations": {
                                (
                                    "finstream.ai-sre/"
                                    "authorization-id"
                                ): (
                                    authorization.authorization_id
                                ),
                                (
                                    "finstream.ai-sre/"
                                    "permit-id"
                                ): permit.permit_id,
                                (
                                    "finstream.ai-sre/"
                                    "execution-claim-id"
                                ): claim.claim_id,
                                (
                                    "finstream.ai-sre/"
                                    "restart-requested-at"
                                ): executed_at,
                            }
                        }
                    }
                }
            },
            sort_keys=True,
            separators=(",", ":"),
        )

        api_path = (
            "/apis/apps/v1/namespaces/"
            f"{cls.NAMESPACE}/deployments/"
            f"{cls.DEPLOYMENT}"
        )

        return KubernetesMutationRequest(
            namespace=cls.NAMESPACE,
            deployment=cls.DEPLOYMENT,
            method="PATCH",
            api_path=api_path,
            content_type="application/merge-patch+json",
            body=body,
            request_digest=cls._digest(
                api_path=api_path,
                body=body,
            ),
        )

    @classmethod
    def execute(
        cls,
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
        consumer: str = "finstream-kubernetes-executor",
    ) -> GuardedExecutionResult:
        """Execute exactly one guarded processor restart request."""
        if proposal.action_id != cls.ACTION_ID:
            raise KubernetesMutationError(
                "Only the processor rolling restart action "
                "may reach the mutation executor."
            )

        if proposal.affected_service != cls.DEPLOYMENT:
            raise KubernetesMutationError(
                "Only the processor deployment may reach "
                "the mutation executor."
            )

        mode = getattr(
            transport,
            "mode",
            None,
        )

        if not isinstance(
            mode,
            KubernetesMutationMode,
        ):
            raise KubernetesMutationError(
                "Kubernetes transport does not declare "
                "an execution mode."
            )

        if mode is KubernetesMutationMode.LIVE:
            if live_arm is None:
                raise KubernetesMutationError(
                    "Live Kubernetes mutation requires "
                    "an explicit execution arm."
                )

            LiveExecutionArmManager.validate(
                incident=incident,
                proposal=proposal,
                authorization=authorization,
                permit=permit,
                snapshot=snapshot,
                safety_approval=safety_approval,
                arm=live_arm,
            )

        elif live_arm is not None:
            raise KubernetesMutationError(
                "A live execution arm must not be supplied "
                "to a server dry-run transport."
            )

        ExecutionSafetyGate.validate(
            incident=incident,
            proposal=proposal,
            authorization=authorization,
            permit=permit,
            snapshot=snapshot,
            approval=safety_approval,
        )

        consumed_arm: LiveExecutionArm | None = None

        claim = registry.claim(
            incident=incident,
            proposal=proposal,
            authorization=authorization,
            permit=permit,
            snapshot=snapshot,
            safety_approval=safety_approval,
        )

        try:
            consumed_permit = ExecutionPermitManager.consume(
                incident=incident,
                proposal=proposal,
                authorization=authorization,
                permit=permit,
                consumer=consumer,
            )

            if live_arm is not None:
                consumed_arm = LiveExecutionArmManager.consume(
                    incident=incident,
                    proposal=proposal,
                    authorization=authorization,
                    permit=permit,
                    snapshot=snapshot,
                    safety_approval=safety_approval,
                    arm=live_arm,
                    consumer=consumer,
                )

            request = cls._build_request(
                authorization=authorization,
                permit=consumed_permit,
                claim=claim,
            )

            try:
                response = transport.patch_deployment(
                    request
                )
            except Exception as exc:
                raise KubernetesMutationError(
                    "Kubernetes mutation transport failed."
                ) from exc

            if not response.accepted:
                raise KubernetesMutationError(
                    "Kubernetes mutation was not accepted."
                )

        except Exception:
            registry.release(
                claim_id=claim.claim_id,
                reason="Guarded mutation did not succeed.",
            )
            raise

        released_claim = registry.release(
            claim_id=claim.claim_id,
            reason=(
                "Kubernetes rolling restart request accepted."
            ),
        )

        return GuardedExecutionResult(
            claim=released_claim,
            consumed_permit=consumed_permit,
            request=request,
            response=response,
            consumed_arm=consumed_arm,
        )
