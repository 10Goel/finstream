"""Deterministic evidence collection for FinStream AI-SRE incidents."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from services.ai_sre_agent.models import (
    Evidence,
    Incident,
    ToolCall,
    ToolCallStatus,
    utc_now,
)
from services.ai_sre_agent.tools.kafka import (
    KafkaDiagnosticError,
    KafkaDiagnosticTool,
)
from services.ai_sre_agent.tools.kubernetes import (
    KubernetesDiagnosticError,
    KubernetesDiagnosticTool,
)
from services.ai_sre_agent.tools.logs import (
    LogDiagnosticError,
    LogInvestigationTool,
)
from services.ai_sre_agent.tools.postgres import (
    PostgresDiagnosticError,
    PostgresDiagnosticTool,
)
from services.ai_sre_agent.tools.prometheus import (
    PrometheusDiagnosticTool,
    PrometheusQueryError,
)

_ALLOWED_SERVICES = {
    "api",
    "producer",
    "processor",
}


@dataclass(slots=True)
class EvidenceCollectionResult:
    """Evidence and tool-call history produced for one incident."""

    incident_id: str
    service: str
    evidence: list[Evidence] = field(default_factory=list)
    tool_calls: list[ToolCall] = field(default_factory=list)

    @property
    def successful_tool_calls(self) -> int:
        """Return the number of successful diagnostic calls."""
        return sum(
            call.status is ToolCallStatus.SUCCESS
            for call in self.tool_calls
        )

    @property
    def failed_tool_calls(self) -> int:
        """Return the number of failed diagnostic calls."""
        return sum(
            call.status is ToolCallStatus.FAILED
            for call in self.tool_calls
        )


@dataclass(slots=True)
class _DiagnosticStep:
    """One approved deterministic diagnostic operation."""

    tool: str
    operation: Callable[..., Evidence]
    arguments: dict[str, Any] = field(default_factory=dict)


class EvidenceCollector:
    """Collect service-aware evidence using approved read-only tools."""

    def __init__(
        self,
        *,
        prometheus: PrometheusDiagnosticTool,
        kubernetes: KubernetesDiagnosticTool,
        logs: LogInvestigationTool,
        kafka: KafkaDiagnosticTool,
        postgres: PostgresDiagnosticTool,
    ) -> None:
        self._prometheus = prometheus
        self._kubernetes = kubernetes
        self._logs = logs
        self._kafka = kafka
        self._postgres = postgres

    @staticmethod
    def _normalize_service(
        service: str | None,
    ) -> str:
        if service is None:
            raise ValueError(
                "Incident affected_service must be configured."
            )

        normalized = service.strip().lower()

        if normalized not in _ALLOWED_SERVICES:
            allowed = ", ".join(
                sorted(_ALLOWED_SERVICES)
            )

            raise ValueError(
                f"Unsupported FinStream affected service "
                f"'{service}'. Allowed services: {allowed}."
            )

        return normalized

    def _common_kubernetes_steps(
        self,
        *,
        service: str,
    ) -> list[_DiagnosticStep]:
        return [
            _DiagnosticStep(
                tool="kubernetes.get_deployment_status",
                operation=(
                    self._kubernetes.get_deployment_status
                ),
                arguments={
                    "service": service,
                },
            ),
            _DiagnosticStep(
                tool="kubernetes.get_pods",
                operation=self._kubernetes.get_pods,
                arguments={
                    "service": service,
                },
            ),
            _DiagnosticStep(
                tool="kubernetes.get_restart_count",
                operation=(
                    self._kubernetes.get_restart_count
                ),
                arguments={
                    "service": service,
                },
            ),
            _DiagnosticStep(
                tool="kubernetes.get_recent_events",
                operation=(
                    self._kubernetes.get_recent_events
                ),
                arguments={
                    "service": service,
                    "max_events": 10,
                },
            ),
        ]

    def _common_log_steps(
        self,
        *,
        service: str,
    ) -> list[_DiagnosticStep]:
        return [
            _DiagnosticStep(
                tool="logs.get_recent_logs",
                operation=self._logs.get_recent_logs,
                arguments={
                    "service": service,
                    "since_minutes": 10,
                    "max_lines": 200,
                    "previous": False,
                },
            )
        ]

    def _api_plan(
        self,
    ) -> list[_DiagnosticStep]:
        service = "api"

        return [
            _DiagnosticStep(
                tool="prometheus.get_service_health",
                operation=(
                    self._prometheus.get_service_health
                ),
                arguments={
                    "service": service,
                },
            ),
            _DiagnosticStep(
                tool="prometheus.get_api_p95_latency",
                operation=(
                    self._prometheus.get_api_p95_latency
                ),
            ),
            *self._common_kubernetes_steps(
                service=service,
            ),
            *self._common_log_steps(
                service=service,
            ),
            _DiagnosticStep(
                tool="postgres.check_database_health",
                operation=(
                    self._postgres.check_database_health
                ),
            ),
            _DiagnosticStep(
                tool="postgres.get_connection_statistics",
                operation=(
                    self._postgres.get_connection_statistics
                ),
            ),
        ]

    def _producer_plan(
        self,
    ) -> list[_DiagnosticStep]:
        service = "producer"

        return [
            _DiagnosticStep(
                tool="prometheus.get_service_health",
                operation=(
                    self._prometheus.get_service_health
                ),
                arguments={
                    "service": service,
                },
            ),
            _DiagnosticStep(
                tool="prometheus.get_producer_publish_rate",
                operation=(
                    self._prometheus.get_producer_publish_rate
                ),
            ),
            _DiagnosticStep(
                tool=(
                    "prometheus."
                    "get_producer_delivery_failures"
                ),
                operation=(
                    self._prometheus.
                    get_producer_delivery_failures
                ),
            ),
            *self._common_kubernetes_steps(
                service=service,
            ),
            *self._common_log_steps(
                service=service,
            ),
            _DiagnosticStep(
                tool="kafka.check_broker_health",
                operation=(
                    self._kafka.check_broker_health
                ),
            ),
            _DiagnosticStep(
                tool="kafka.get_topic_metadata",
                operation=(
                    self._kafka.get_topic_metadata
                ),
                arguments={
                    "topic": "transactions",
                },
            ),
        ]

    def _processor_plan(
        self,
    ) -> list[_DiagnosticStep]:
        service = "processor"

        return [
            _DiagnosticStep(
                tool="prometheus.get_service_health",
                operation=(
                    self._prometheus.get_service_health
                ),
                arguments={
                    "service": service,
                },
            ),
            _DiagnosticStep(
                tool="prometheus.get_processor_throughput",
                operation=(
                    self._prometheus.get_processor_throughput
                ),
            ),
            _DiagnosticStep(
                tool="prometheus.get_processor_alert_rate",
                operation=(
                    self._prometheus.get_processor_alert_rate
                ),
            ),
            _DiagnosticStep(
                tool=(
                    "prometheus."
                    "get_invalid_transaction_activity"
                ),
                operation=(
                    self._prometheus.
                    get_invalid_transaction_activity
                ),
            ),
            _DiagnosticStep(
                tool="prometheus.get_dlq_activity",
                operation=(
                    self._prometheus.get_dlq_activity
                ),
            ),
            *self._common_kubernetes_steps(
                service=service,
            ),
            *self._common_log_steps(
                service=service,
            ),
            _DiagnosticStep(
                tool="kafka.check_broker_health",
                operation=(
                    self._kafka.check_broker_health
                ),
            ),
            _DiagnosticStep(
                tool="kafka.get_topic_metadata",
                operation=(
                    self._kafka.get_topic_metadata
                ),
                arguments={
                    "topic": "transactions",
                },
            ),
            _DiagnosticStep(
                tool="kafka.get_consumer_group_state",
                operation=(
                    self._kafka.get_consumer_group_state
                ),
            ),
            _DiagnosticStep(
                tool="kafka.get_consumer_lag",
                operation=(
                    self._kafka.get_consumer_lag
                ),
            ),
            _DiagnosticStep(
                tool="postgres.check_database_health",
                operation=(
                    self._postgres.check_database_health
                ),
            ),
            _DiagnosticStep(
                tool="postgres.get_persistence_freshness",
                operation=(
                    self._postgres.get_persistence_freshness
                ),
                arguments={
                    "window_minutes": 5,
                },
            ),
        ]

    def _build_plan(
        self,
        service: str,
    ) -> list[_DiagnosticStep]:
        if service == "api":
            return self._api_plan()

        if service == "producer":
            return self._producer_plan()

        if service == "processor":
            return self._processor_plan()

        raise ValueError(
            f"No diagnostic plan exists for '{service}'."
        )

    @staticmethod
    def _execute_step(
        *,
        incident_id: str,
        step: _DiagnosticStep,
        result: EvidenceCollectionResult,
    ) -> None:
        call = ToolCall(
            incident_id=incident_id,
            tool=step.tool,
            arguments=dict(step.arguments),
            status=ToolCallStatus.RUNNING,
            started_at=utc_now(),
        )

        try:
            evidence = step.operation(
                incident_id=incident_id,
                **step.arguments,
            )

            if evidence.incident_id != incident_id:
                raise ValueError(
                    "Diagnostic tool returned evidence "
                    "for a different incident."
                )

        except (
            KafkaDiagnosticError,
            KubernetesDiagnosticError,
            LogDiagnosticError,
            PostgresDiagnosticError,
            PrometheusQueryError,
            ValueError,
        ) as exc:
            call.status = ToolCallStatus.FAILED
            call.error = (
                f"{type(exc).__name__}: {exc}"
            )[:500]
            call.completed_at = utc_now()

            result.tool_calls.append(call)
            return

        call.status = ToolCallStatus.SUCCESS
        call.evidence_ids.append(
            evidence.evidence_id
        )
        call.completed_at = utc_now()

        result.evidence.append(evidence)
        result.tool_calls.append(call)

    def collect(
        self,
        *,
        incident: Incident,
    ) -> EvidenceCollectionResult:
        """Collect the deterministic evidence plan for an incident."""
        service = self._normalize_service(
            incident.affected_service
        )

        result = EvidenceCollectionResult(
            incident_id=incident.incident_id,
            service=service,
        )

        for step in self._build_plan(service):
            self._execute_step(
                incident_id=incident.incident_id,
                step=step,
                result=result,
            )

        return result
