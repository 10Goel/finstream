"""Guarded Kubernetes dry-run request builder for FinStream AI-SRE."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from services.ai_sre_agent.models import Incident
from services.ai_sre_agent.remediation.approval import (
    RemediationProposal,
)
from services.ai_sre_agent.remediation.authorization import (
    ExecutionAuthorization,
)
from services.ai_sre_agent.remediation.models import (
    RemediationActionType,
)
from services.ai_sre_agent.remediation.permit import (
    ExecutionPermit,
    ExecutionPermitManager,
)


class KubernetesDryRunError(RuntimeError):
    """Unsafe or unsupported Kubernetes dry-run request."""


@dataclass(frozen=True, slots=True)
class KubernetesDryRunRequest:
    """Immutable server-side dry-run request description."""

    namespace: str
    resource: str
    name: str
    method: str
    api_path: str
    query: tuple[tuple[str, str], ...]
    content_type: str
    body: str
    request_digest: str

    def __post_init__(self) -> None:
        if self.method != "PATCH":
            raise ValueError(
                "Kubernetes dry-run request must use PATCH."
            )

        if (
            ("dryRun", "All")
            not in self.query
        ):
            raise ValueError(
                "Kubernetes dry-run request must include "
                "dryRun=All."
            )

        if len(self.request_digest) != 64:
            raise ValueError(
                "Kubernetes dry-run request digest "
                "must be SHA-256."
            )


class KubernetesDryRunActuator:
    """Prepare one allowlisted Kubernetes server dry-run request.

    This component never sends requests to Kubernetes.
    """

    NAMESPACE = "finstream"
    RESOURCE = "deployments"
    DEPLOYMENT = "processor"
    ACTION_ID = "processor-rolling-restart"

    @staticmethod
    def _digest(
        *,
        method: str,
        api_path: str,
        query: tuple[tuple[str, str], ...],
        content_type: str,
        body: str,
    ) -> str:
        payload = {
            "method": method,
            "api_path": api_path,
            "query": list(query),
            "content_type": content_type,
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
    def prepare(
        cls,
        *,
        incident: Incident,
        proposal: RemediationProposal,
        authorization: ExecutionAuthorization,
        permit: ExecutionPermit,
    ) -> KubernetesDryRunRequest:
        """Validate safety state and build the dry-run request."""
        ExecutionPermitManager.validate(
            incident=incident,
            proposal=proposal,
            authorization=authorization,
            permit=permit,
        )

        if (
            proposal.action_type
            is not RemediationActionType.ROLLING_RESTART
        ):
            raise KubernetesDryRunError(
                "Only rolling restart is supported by the "
                "Kubernetes dry-run actuator."
            )

        if proposal.affected_service != cls.DEPLOYMENT:
            raise KubernetesDryRunError(
                "Only the processor deployment is currently "
                "allowlisted for Kubernetes dry-run."
            )

        if proposal.action_id != cls.ACTION_ID:
            raise KubernetesDryRunError(
                "Remediation action is not allowlisted for "
                "Kubernetes dry-run."
            )

        annotations = {
            "finstream.ai-sre/authorization-id": (
                authorization.authorization_id
            ),
            "finstream.ai-sre/permit-id": (
                permit.permit_id
            ),
            "finstream.ai-sre/restart-requested-at": (
                permit.issued_at.isoformat()
            ),
        }

        body = json.dumps(
            {
                "spec": {
                    "template": {
                        "metadata": {
                            "annotations": annotations,
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

        query = (
            ("dryRun", "All"),
            ("fieldManager", "finstream-ai-sre"),
        )

        content_type = "application/merge-patch+json"

        request_digest = cls._digest(
            method="PATCH",
            api_path=api_path,
            query=query,
            content_type=content_type,
            body=body,
        )

        return KubernetesDryRunRequest(
            namespace=cls.NAMESPACE,
            resource=cls.RESOURCE,
            name=cls.DEPLOYMENT,
            method="PATCH",
            api_path=api_path,
            query=query,
            content_type=content_type,
            body=body,
            request_digest=request_digest,
        )
