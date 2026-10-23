"""Fail-closed Kubernetes server-side dry-run transport."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from typing import Any

from services.ai_sre_agent.remediation.executor import (
    KubernetesMutationRequest,
    KubernetesMutationResponse,
)


class KubernetesTransportError(RuntimeError):
    """Kubernetes transport validation or invocation failed."""


@dataclass(frozen=True, slots=True)
class KubectlServerDryRunTransport:
    """Submit only server-side dry-run processor patches.

    This transport deliberately has no real-mutation mode.
    """

    kubectl_binary: str = "kubectl"
    timeout_seconds: float = 10.0

    NAMESPACE = "finstream"
    DEPLOYMENT = "processor"

    API_PATH = (
        "/apis/apps/v1/namespaces/"
        "finstream/deployments/processor"
    )

    ALLOWED_ANNOTATIONS = frozenset(
        {
            "finstream.ai-sre/authorization-id",
            "finstream.ai-sre/permit-id",
            "finstream.ai-sre/execution-claim-id",
            "finstream.ai-sre/restart-requested-at",
        }
    )

    @classmethod
    def _validate_body(
        cls,
        body: str,
    ) -> None:
        try:
            payload: Any = json.loads(body)
        except json.JSONDecodeError as exc:
            raise KubernetesTransportError(
                "Mutation body is not valid JSON."
            ) from exc

        if not isinstance(payload, dict):
            raise KubernetesTransportError(
                "Mutation body must be a JSON object."
            )

        if set(payload) != {"spec"}:
            raise KubernetesTransportError(
                "Mutation body contains unexpected top-level fields."
            )

        spec = payload.get("spec")

        if not isinstance(spec, dict):
            raise KubernetesTransportError(
                "Mutation spec must be an object."
            )

        if set(spec) != {"template"}:
            raise KubernetesTransportError(
                "Mutation spec contains unexpected fields."
            )

        template = spec.get("template")

        if not isinstance(template, dict):
            raise KubernetesTransportError(
                "Mutation template must be an object."
            )

        if set(template) != {"metadata"}:
            raise KubernetesTransportError(
                "Mutation template contains unexpected fields."
            )

        metadata = template.get("metadata")

        if not isinstance(metadata, dict):
            raise KubernetesTransportError(
                "Mutation template metadata must be an object."
            )

        if set(metadata) != {"annotations"}:
            raise KubernetesTransportError(
                "Mutation metadata contains unexpected fields."
            )

        annotations = metadata.get("annotations")

        if not isinstance(annotations, dict):
            raise KubernetesTransportError(
                "Mutation annotations must be an object."
            )

        if set(annotations) != cls.ALLOWED_ANNOTATIONS:
            raise KubernetesTransportError(
                "Mutation annotations are not exactly allowlisted."
            )

        for key, value in annotations.items():
            if not isinstance(value, str) or not value.strip():
                raise KubernetesTransportError(
                    f"Mutation annotation {key!r} must be "
                    "a non-empty string."
                )

    @classmethod
    def _validate_request(
        cls,
        request: KubernetesMutationRequest,
    ) -> None:
        if request.namespace != cls.NAMESPACE:
            raise KubernetesTransportError(
                "Kubernetes namespace is not allowlisted."
            )

        if request.deployment != cls.DEPLOYMENT:
            raise KubernetesTransportError(
                "Kubernetes deployment is not allowlisted."
            )

        if request.method != "PATCH":
            raise KubernetesTransportError(
                "Kubernetes transport accepts PATCH only."
            )

        if request.api_path != cls.API_PATH:
            raise KubernetesTransportError(
                "Kubernetes API path is not allowlisted."
            )

        if (
            request.content_type
            != "application/merge-patch+json"
        ):
            raise KubernetesTransportError(
                "Kubernetes patch content type is not allowlisted."
            )

        cls._validate_body(
            request.body
        )

    def patch_deployment(
        self,
        request: KubernetesMutationRequest,
    ) -> KubernetesMutationResponse:
        """Validate against the real API without persisting changes."""
        self._validate_request(
            request
        )

        command = [
            self.kubectl_binary,
            "patch",
            "deployment",
            self.DEPLOYMENT,
            "--namespace",
            self.NAMESPACE,
            "--type=merge",
            "--patch",
            request.body,
            "--dry-run=server",
            "--field-manager=finstream-ai-sre",
            "--output=json",
        ]

        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
            )
        except (
            OSError,
            subprocess.SubprocessError,
        ) as exc:
            raise KubernetesTransportError(
                "Failed to invoke kubectl safely."
            ) from exc

        if completed.returncode != 0:
            message = completed.stderr.strip()

            return KubernetesMutationResponse(
                accepted=False,
                status_code=completed.returncode,
                message=(
                    message
                    or "Kubernetes server-side dry run failed."
                ),
            )

        try:
            response = json.loads(
                completed.stdout
            )
        except json.JSONDecodeError as exc:
            raise KubernetesTransportError(
                "kubectl returned malformed JSON."
            ) from exc

        metadata = response.get(
            "metadata",
            {},
        )

        resource_version = metadata.get(
            "resourceVersion"
        )

        return KubernetesMutationResponse(
            accepted=True,
            status_code=200,
            resource_version=resource_version,
            message=(
                "Kubernetes server-side dry run accepted."
            ),
        )
