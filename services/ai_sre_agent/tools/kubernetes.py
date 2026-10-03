"""Read-only Kubernetes diagnostics for FinStream AI-SRE."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from kubernetes.client import ApiException
from kubernetes.config.config_exception import ConfigException

from kubernetes import client, config
from services.ai_sre_agent.models import (
    Evidence,
    EvidenceSource,
    EvidenceTrustLevel,
)


class KubernetesDiagnosticError(RuntimeError):
    """Raised when Kubernetes diagnostics cannot be completed."""


_ALLOWED_SERVICES = {
    "alertmanager",
    "api",
    "grafana",
    "kafka",
    "postgres",
    "processor",
    "producer",
    "prometheus",
}


class KubernetesDiagnosticTool:
    """Bounded read-only Kubernetes diagnostics for FinStream."""

    def __init__(
        self,
        core_api: client.CoreV1Api,
        apps_api: client.AppsV1Api,
        *,
        namespace: str = "finstream",
    ) -> None:
        if not namespace.strip():
            raise ValueError("Kubernetes namespace must not be empty.")

        self._core_api = core_api
        self._apps_api = apps_api
        self._namespace = namespace

    @classmethod
    def from_environment(
        cls,
        *,
        namespace: str = "finstream",
    ) -> KubernetesDiagnosticTool:
        """Create a tool using in-cluster config or local kubeconfig."""
        try:
            config.load_incluster_config()
        except ConfigException:
            config.load_kube_config()

        return cls(
            client.CoreV1Api(),
            client.AppsV1Api(),
            namespace=namespace,
        )

    @staticmethod
    def _normalize_service(service: str) -> str:
        normalized = service.strip().lower()

        if normalized not in _ALLOWED_SERVICES:
            allowed = ", ".join(sorted(_ALLOWED_SERVICES))
            raise ValueError(
                f"Unsupported FinStream service '{service}'. "
                f"Allowed services: {allowed}."
            )

        return normalized

    @staticmethod
    def _pod_is_ready(pod: Any) -> bool:
        conditions = getattr(pod.status, "conditions", None) or []

        return any(
            getattr(condition, "type", None) == "Ready"
            and getattr(condition, "status", None) == "True"
            for condition in conditions
        )

    @staticmethod
    def _pod_restart_count(pod: Any) -> int:
        statuses = getattr(
            pod.status,
            "container_statuses",
            None,
        ) or []

        return sum(
            int(getattr(status, "restart_count", 0) or 0)
            for status in statuses
        )

    @staticmethod
    def _event_timestamp(event: Any) -> datetime | None:
        for attribute in (
            "event_time",
            "last_timestamp",
            "first_timestamp",
        ):
            value = getattr(event, attribute, None)

            if value is not None:
                return value

        metadata = getattr(event, "metadata", None)

        if metadata is not None:
            return getattr(
                metadata,
                "creation_timestamp",
                None,
            )

        return None

    @classmethod
    def _event_sort_key(cls, event: Any) -> float:
        timestamp = cls._event_timestamp(event)

        if timestamp is None:
            return 0.0

        try:
            return timestamp.timestamp()
        except (AttributeError, OSError, ValueError):
            return 0.0

    def get_deployment_status(
        self,
        *,
        incident_id: str,
        service: str,
    ) -> Evidence:
        """Collect deployment availability evidence."""
        normalized_service = self._normalize_service(service)

        try:
            deployment = self._apps_api.read_namespaced_deployment(
                name=normalized_service,
                namespace=self._namespace,
            )
        except ApiException as exc:
            raise KubernetesDiagnosticError(
                f"Unable to read Kubernetes deployment "
                f"'{normalized_service}'."
            ) from exc

        desired = int(deployment.spec.replicas or 0)
        ready = int(deployment.status.ready_replicas or 0)
        available = int(
            deployment.status.available_replicas or 0
        )
        updated = int(
            deployment.status.updated_replicas or 0
        )

        healthy = (
            desired > 0
            and ready >= desired
            and available >= desired
        )

        if healthy:
            summary = (
                f"Kubernetes deployment {normalized_service} "
                f"is healthy with {ready}/{desired} ready replicas."
            )
        else:
            summary = (
                f"Kubernetes deployment {normalized_service} "
                f"is not fully available: desired={desired}, "
                f"ready={ready}, available={available}."
            )

        return Evidence(
            incident_id=incident_id,
            source=EvidenceSource.KUBERNETES,
            tool="get_deployment_status",
            summary=summary,
            trust_level=EvidenceTrustLevel.DIRECT_OBSERVATION,
            service=normalized_service,
            raw_reference=(
                f"deployment/{normalized_service} "
                f"namespace={self._namespace}"
            ),
            metadata={
                "namespace": self._namespace,
                "deployment": normalized_service,
                "desired_replicas": desired,
                "ready_replicas": ready,
                "available_replicas": available,
                "updated_replicas": updated,
                "healthy": healthy,
            },
        )

    def get_pods(
        self,
        *,
        incident_id: str,
        service: str,
    ) -> Evidence:
        """Collect bounded pod-state evidence for a service."""
        normalized_service = self._normalize_service(service)
        selector = f"app={normalized_service}"

        try:
            pod_list = self._core_api.list_namespaced_pod(
                namespace=self._namespace,
                label_selector=selector,
            )
        except ApiException as exc:
            raise KubernetesDiagnosticError(
                f"Unable to list Kubernetes pods for "
                f"'{normalized_service}'."
            ) from exc

        pods = []

        for pod in pod_list.items:
            pods.append(
                {
                    "name": pod.metadata.name,
                    "phase": pod.status.phase,
                    "ready": self._pod_is_ready(pod),
                    "restart_count": self._pod_restart_count(
                        pod
                    ),
                }
            )

        running = sum(
            pod["phase"] == "Running"
            for pod in pods
        )
        ready = sum(
            pod["ready"]
            for pod in pods
        )

        if not pods:
            summary = (
                f"No Kubernetes pods found for "
                f"{normalized_service}."
            )
        else:
            summary = (
                f"Kubernetes reports {len(pods)} pod(s) for "
                f"{normalized_service}: "
                f"{running} Running, {ready} Ready."
            )

        return Evidence(
            incident_id=incident_id,
            source=EvidenceSource.KUBERNETES,
            tool="get_pods",
            summary=summary,
            trust_level=EvidenceTrustLevel.DIRECT_OBSERVATION,
            service=normalized_service,
            raw_reference=(
                f"pods namespace={self._namespace} "
                f"selector={selector}"
            ),
            metadata={
                "namespace": self._namespace,
                "selector": selector,
                "pod_count": len(pods),
                "running_count": running,
                "ready_count": ready,
                "pods": pods,
            },
        )

    def get_restart_count(
        self,
        *,
        incident_id: str,
        service: str,
    ) -> Evidence:
        """Collect container restart-count evidence."""
        normalized_service = self._normalize_service(service)
        selector = f"app={normalized_service}"

        try:
            pod_list = self._core_api.list_namespaced_pod(
                namespace=self._namespace,
                label_selector=selector,
            )
        except ApiException as exc:
            raise KubernetesDiagnosticError(
                f"Unable to inspect restart counts for "
                f"'{normalized_service}'."
            ) from exc

        per_pod = {}
        total_restarts = 0

        for pod in pod_list.items:
            restart_count = self._pod_restart_count(pod)
            per_pod[pod.metadata.name] = restart_count
            total_restarts += restart_count

        summary = (
            f"Kubernetes reports {total_restarts} total "
            f"container restart(s) for {normalized_service}."
        )

        return Evidence(
            incident_id=incident_id,
            source=EvidenceSource.KUBERNETES,
            tool="get_restart_count",
            summary=summary,
            trust_level=EvidenceTrustLevel.DIRECT_OBSERVATION,
            service=normalized_service,
            raw_reference=(
                f"pods namespace={self._namespace} "
                f"selector={selector}"
            ),
            metadata={
                "namespace": self._namespace,
                "selector": selector,
                "total_restarts": total_restarts,
                "per_pod": per_pod,
            },
        )

    def get_recent_events(
        self,
        *,
        incident_id: str,
        service: str,
        max_events: int = 20,
    ) -> Evidence:
        """Collect recent Kubernetes events for a service."""
        normalized_service = self._normalize_service(service)

        if not 1 <= max_events <= 50:
            raise ValueError(
                "max_events must be between 1 and 50."
            )

        try:
            event_list = self._core_api.list_namespaced_event(
                namespace=self._namespace,
            )
        except ApiException as exc:
            raise KubernetesDiagnosticError(
                f"Unable to list Kubernetes events for "
                f"'{normalized_service}'."
            ) from exc

        matching_events = []

        for event in event_list.items:
            involved = getattr(
                event,
                "involved_object",
                None,
            )
            object_name = getattr(
                involved,
                "name",
                "",
            ) or ""

            if (
                object_name != normalized_service
                and not object_name.startswith(
                    f"{normalized_service}-"
                )
            ):
                continue

            matching_events.append(event)

        matching_events.sort(
            key=self._event_sort_key,
            reverse=True,
        )

        bounded_events = matching_events[:max_events]

        events = []

        for event in bounded_events:
            timestamp = self._event_timestamp(event)

            events.append(
                {
                    "type": getattr(event, "type", None),
                    "reason": getattr(event, "reason", None),
                    "message": getattr(event, "message", None),
                    "object": getattr(
                        event.involved_object,
                        "name",
                        None,
                    ),
                    "timestamp": (
                        timestamp.astimezone(
                            timezone.utc
                        ).isoformat()
                        if timestamp is not None
                        else None
                    ),
                }
            )

        summary = (
            f"Kubernetes reports {len(events)} recent "
            f"event(s) for {normalized_service}."
        )

        return Evidence(
            incident_id=incident_id,
            source=EvidenceSource.KUBERNETES,
            tool="get_recent_events",
            summary=summary,
            trust_level=EvidenceTrustLevel.DIRECT_OBSERVATION,
            service=normalized_service,
            raw_reference=(
                f"events namespace={self._namespace} "
                f"service={normalized_service}"
            ),
            metadata={
                "namespace": self._namespace,
                "event_count": len(events),
                "max_events": max_events,
                "events": events,
            },
        )
