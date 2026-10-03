"""Bounded Kubernetes log diagnostics for FinStream AI-SRE."""

from __future__ import annotations

from typing import Any

from kubernetes.client import ApiException

from services.ai_sre_agent.models import (
    Evidence,
    EvidenceSource,
    EvidenceTrustLevel,
)


class LogDiagnosticError(RuntimeError):
    """Raised when FinStream logs cannot be collected safely."""


_ALLOWED_LOG_SERVICES = {
    "api",
    "processor",
    "producer",
}


class LogInvestigationTool:
    """Read-only, bounded log retrieval for FinStream workloads."""

    def __init__(
        self,
        core_api: Any,
        *,
        namespace: str = "finstream",
    ) -> None:
        if not namespace.strip():
            raise ValueError("Kubernetes namespace must not be empty.")

        self._core_api = core_api
        self._namespace = namespace

    @staticmethod
    def _normalize_service(service: str) -> str:
        normalized = service.strip().lower()

        if normalized not in _ALLOWED_LOG_SERVICES:
            allowed = ", ".join(sorted(_ALLOWED_LOG_SERVICES))
            raise ValueError(
                f"Unsupported FinStream log service '{service}'. "
                f"Allowed services: {allowed}."
            )

        return normalized

    @staticmethod
    def _pod_sort_key(pod: Any) -> float:
        metadata = getattr(pod, "metadata", None)

        if metadata is None:
            return 0.0

        timestamp = getattr(
            metadata,
            "creation_timestamp",
            None,
        )

        if timestamp is None:
            return 0.0

        try:
            return timestamp.timestamp()
        except (AttributeError, OSError, ValueError):
            return 0.0

    def _select_pod(
        self,
        service: str,
    ) -> Any | None:
        selector = f"app={service}"

        try:
            pod_list = self._core_api.list_namespaced_pod(
                namespace=self._namespace,
                label_selector=selector,
            )
        except ApiException as exc:
            raise LogDiagnosticError(
                f"Unable to list Kubernetes pods for '{service}'."
            ) from exc

        pods = list(pod_list.items)

        if not pods:
            return None

        pods.sort(
            key=self._pod_sort_key,
            reverse=True,
        )

        return pods[0]

    def get_recent_logs(
        self,
        *,
        incident_id: str,
        service: str,
        since_minutes: int = 10,
        max_lines: int = 200,
        previous: bool = False,
    ) -> Evidence:
        """Collect bounded timestamped logs as untrusted evidence."""
        normalized_service = self._normalize_service(service)

        if not 1 <= since_minutes <= 60:
            raise ValueError(
                "since_minutes must be between 1 and 60."
            )

        if not 1 <= max_lines <= 500:
            raise ValueError(
                "max_lines must be between 1 and 500."
            )

        pod = self._select_pod(normalized_service)

        if pod is None:
            return Evidence(
                incident_id=incident_id,
                source=EvidenceSource.LOGS,
                tool="get_recent_logs",
                summary=(
                    f"No Kubernetes pod found for "
                    f"{normalized_service}; no logs collected."
                ),
                trust_level=EvidenceTrustLevel.DIRECT_OBSERVATION,
                service=normalized_service,
                raw_reference=(
                    f"logs namespace={self._namespace} "
                    f"selector=app={normalized_service}"
                ),
                metadata={
                    "namespace": self._namespace,
                    "pod": None,
                    "container": normalized_service,
                    "since_minutes": since_minutes,
                    "max_lines": max_lines,
                    "previous": previous,
                    "line_count": 0,
                    "log_lines": [],
                    "untrusted_data": True,
                },
            )

        pod_name = pod.metadata.name

        try:
            raw_logs = self._core_api.read_namespaced_pod_log(
                name=pod_name,
                namespace=self._namespace,
                container=normalized_service,
                timestamps=True,
                since_seconds=since_minutes * 60,
                tail_lines=max_lines,
                previous=previous,
            )
        except ApiException as exc:
            raise LogDiagnosticError(
                f"Unable to read Kubernetes logs for "
                f"'{normalized_service}'."
            ) from exc

        if raw_logs is None:
            raw_logs = ""

        if not isinstance(raw_logs, str):
            raw_logs = str(raw_logs)

        lines = raw_logs.splitlines()

        if len(lines) > max_lines:
            lines = lines[-max_lines:]

        summary = (
            f"Collected {len(lines)} timestamped log line(s) "
            f"from {normalized_service} pod {pod_name}."
        )

        if previous:
            summary = (
                f"Collected {len(lines)} timestamped previous-container "
                f"log line(s) from {normalized_service} pod {pod_name}."
            )

        return Evidence(
            incident_id=incident_id,
            source=EvidenceSource.LOGS,
            tool="get_recent_logs",
            summary=summary,
            trust_level=EvidenceTrustLevel.DIRECT_OBSERVATION,
            service=normalized_service,
            raw_reference=(
                f"pod/{pod_name} container={normalized_service} "
                f"namespace={self._namespace}"
            ),
            metadata={
                "namespace": self._namespace,
                "pod": pod_name,
                "container": normalized_service,
                "since_minutes": since_minutes,
                "max_lines": max_lines,
                "previous": previous,
                "line_count": len(lines),
                "log_lines": lines,
                "untrusted_data": True,
            },
        )
