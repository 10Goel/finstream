"""Read-only Prometheus diagnostics for FinStream AI-SRE."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode, urlparse
from urllib.request import urlopen

from services.ai_sre_agent.models import (
    Evidence,
    EvidenceSource,
    EvidenceTrustLevel,
)


class PrometheusQueryError(RuntimeError):
    """Raised when Prometheus cannot provide a valid query result."""


@dataclass(frozen=True, slots=True)
class PrometheusSample:
    """A normalized Prometheus instant-vector sample."""

    metric: dict[str, str]
    timestamp: float
    value: float


JsonRequester = Callable[[str], dict[str, Any]]


_SERVICE_JOBS: dict[str, str] = {
    "api": "finstream-api",
    "producer": "finstream-producer",
    "processor": "finstream-processor",
}


class PrometheusDiagnosticTool:
    """Read-only interface to approved FinStream Prometheus diagnostics."""

    def __init__(
        self,
        base_url: str,
        *,
        timeout_seconds: float = 5.0,
        request_json: JsonRequester | None = None,
    ) -> None:
        normalized_url = base_url.rstrip("/")
        parsed = urlparse(normalized_url)

        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError(
                "Prometheus base_url must be a valid HTTP or HTTPS URL."
            )

        if timeout_seconds <= 0:
            raise ValueError("Prometheus timeout_seconds must be positive.")

        self._base_url = normalized_url
        self._timeout_seconds = timeout_seconds
        self._request_json = request_json or self._http_get_json

    def _http_get_json(self, url: str) -> dict[str, Any]:
        """Perform a bounded read-only HTTP request to Prometheus."""
        with urlopen(url, timeout=self._timeout_seconds) as response:
            payload = json.load(response)

        if not isinstance(payload, dict):
            raise PrometheusQueryError(
                "Prometheus returned a non-object JSON response."
            )

        return payload

    def _instant_query(self, query: str) -> list[PrometheusSample]:
        """Execute an internal instant query and normalize vector samples."""
        query_string = urlencode({"query": query})
        url = f"{self._base_url}/api/v1/query?{query_string}"

        try:
            payload = self._request_json(url)
        except PrometheusQueryError:
            raise
        except Exception as exc:
            raise PrometheusQueryError(
                "Prometheus request failed."
            ) from exc

        if payload.get("status") != "success":
            error = payload.get("error", "unknown Prometheus error")
            raise PrometheusQueryError(
                f"Prometheus query failed: {error}"
            )

        data = payload.get("data")

        if not isinstance(data, dict):
            raise PrometheusQueryError(
                "Prometheus response is missing query data."
            )

        if data.get("resultType") != "vector":
            raise PrometheusQueryError(
                "Prometheus instant query did not return a vector."
            )

        result = data.get("result")

        if not isinstance(result, list):
            raise PrometheusQueryError(
                "Prometheus vector result is malformed."
            )

        samples: list[PrometheusSample] = []

        for item in result:
            if not isinstance(item, dict):
                raise PrometheusQueryError(
                    "Prometheus sample is malformed."
                )

            metric = item.get("metric")
            value = item.get("value")

            if not isinstance(metric, dict):
                raise PrometheusQueryError(
                    "Prometheus sample metric labels are malformed."
                )

            if (
                not isinstance(value, list)
                or len(value) != 2
            ):
                raise PrometheusQueryError(
                    "Prometheus sample value is malformed."
                )

            try:
                timestamp = float(value[0])
                numeric_value = float(value[1])
            except (TypeError, ValueError) as exc:
                raise PrometheusQueryError(
                    "Prometheus sample contains a non-numeric value."
                ) from exc

            normalized_labels = {
                str(key): str(label_value)
                for key, label_value in metric.items()
            }

            samples.append(
                PrometheusSample(
                    metric=normalized_labels,
                    timestamp=timestamp,
                    value=numeric_value,
                )
            )

        return samples

    def get_service_health(
        self,
        *,
        incident_id: str,
        service: str,
    ) -> Evidence:
        """Collect Prometheus target-health evidence for a FinStream service."""
        normalized_service = service.strip().lower()

        if normalized_service not in _SERVICE_JOBS:
            allowed = ", ".join(sorted(_SERVICE_JOBS))
            raise ValueError(
                f"Unsupported FinStream service '{service}'. "
                f"Allowed services: {allowed}."
            )

        job = _SERVICE_JOBS[normalized_service]
        query = f'up{{job="{job}"}}'
        samples = self._instant_query(query)

        if not samples:
            return Evidence(
                incident_id=incident_id,
                source=EvidenceSource.PROMETHEUS,
                tool="get_service_health",
                summary=(
                    f"No Prometheus health series found for "
                    f"{normalized_service}."
                ),
                trust_level=EvidenceTrustLevel.DIRECT_OBSERVATION,
                service=normalized_service,
                raw_reference=query,
                metadata={
                    "job": job,
                    "series_count": 0,
                    "up_targets": 0,
                    "down_targets": 0,
                },
            )

        up_targets = sum(sample.value == 1.0 for sample in samples)
        down_targets = len(samples) - up_targets

        if down_targets == 0:
            summary = (
                f"Prometheus reports all {normalized_service} "
                f"targets as up."
            )
        else:
            summary = (
                f"Prometheus reports {down_targets} of "
                f"{len(samples)} {normalized_service} "
                f"target(s) as down."
            )

        return Evidence(
            incident_id=incident_id,
            source=EvidenceSource.PROMETHEUS,
            tool="get_service_health",
            summary=summary,
            trust_level=EvidenceTrustLevel.DIRECT_OBSERVATION,
            service=normalized_service,
            raw_reference=query,
            metadata={
                "job": job,
                "series_count": len(samples),
                "up_targets": up_targets,
                "down_targets": down_targets,
            },
        )

    def _collect_metric_evidence(
        self,
        *,
        incident_id: str,
        service: str,
        tool_name: str,
        query: str,
        metric_name: str,
        unit: str,
        window: str | None = None,
    ) -> Evidence:
        """Collect a predefined FinStream metric as structured evidence."""
        samples = self._instant_query(query)

        metadata: dict[str, Any] = {
            "metric": metric_name,
            "series_count": len(samples),
            "unit": unit,
        }

        if window is not None:
            metadata["window"] = window

        if not samples:
            metadata["value"] = None

            return Evidence(
                incident_id=incident_id,
                source=EvidenceSource.PROMETHEUS,
                tool=tool_name,
                summary=(
                    f"No Prometheus series found for {metric_name}."
                ),
                trust_level=EvidenceTrustLevel.DIRECT_OBSERVATION,
                service=service,
                raw_reference=query,
                metadata=metadata,
            )

        value = sum(sample.value for sample in samples)
        metadata["value"] = value

        if window is None:
            summary = (
                f"Prometheus reports {metric_name} for "
                f"{service} as {value:.6g} {unit}."
            )
        else:
            summary = (
                f"Prometheus reports {metric_name} for "
                f"{service} as {value:.6g} {unit} "
                f"over {window}."
            )

        return Evidence(
            incident_id=incident_id,
            source=EvidenceSource.PROMETHEUS,
            tool=tool_name,
            summary=summary,
            trust_level=EvidenceTrustLevel.DIRECT_OBSERVATION,
            service=service,
            raw_reference=query,
            metadata=metadata,
        )

    def get_api_p95_latency(
        self,
        *,
        incident_id: str,
    ) -> Evidence:
        """Collect FinStream API p95 request latency."""
        query = (
            "histogram_quantile("
            "0.95, "
            "sum by (le) ("
            "rate("
            "finstream_api_http_request_duration_seconds_bucket"
            '{path!="/health"}[5m]'
            ")"
            ")"
            ")"
        )

        return self._collect_metric_evidence(
            incident_id=incident_id,
            service="api",
            tool_name="get_api_p95_latency",
            query=query,
            metric_name="API p95 latency",
            unit="seconds",
            window="5m",
        )

    def get_producer_publish_rate(
        self,
        *,
        incident_id: str,
    ) -> Evidence:
        """Collect transaction producer publishing rate."""
        query = (
            "sum(rate("
            "finstream_producer_transactions_published_total[5m]"
            "))"
        )

        return self._collect_metric_evidence(
            incident_id=incident_id,
            service="producer",
            tool_name="get_producer_publish_rate",
            query=query,
            metric_name="producer publish rate",
            unit="transactions/second",
            window="5m",
        )

    def get_producer_delivery_failures(
        self,
        *,
        incident_id: str,
    ) -> Evidence:
        """Collect producer delivery failures during the recent window."""
        query = (
            "sum(increase("
            "finstream_producer_delivery_failures_total[5m]"
            "))"
        )

        return self._collect_metric_evidence(
            incident_id=incident_id,
            service="producer",
            tool_name="get_producer_delivery_failures",
            query=query,
            metric_name="producer delivery failures",
            unit="failures",
            window="5m",
        )

    def get_processor_throughput(
        self,
        *,
        incident_id: str,
    ) -> Evidence:
        """Collect total stream-processor throughput."""
        query = (
            "sum(rate("
            "finstream_processor_transactions_processed_total[5m]"
            "))"
        )

        return self._collect_metric_evidence(
            incident_id=incident_id,
            service="processor",
            tool_name="get_processor_throughput",
            query=query,
            metric_name="processor throughput",
            unit="transactions/second",
            window="5m",
        )

    def get_processor_alert_rate(
        self,
        *,
        incident_id: str,
    ) -> Evidence:
        """Collect aggregate anomaly-alert generation rate."""
        query = (
            "sum(rate("
            "finstream_processor_alerts_total[5m]"
            "))"
        )

        return self._collect_metric_evidence(
            incident_id=incident_id,
            service="processor",
            tool_name="get_processor_alert_rate",
            query=query,
            metric_name="processor alert rate",
            unit="alerts/second",
            window="5m",
        )

    def get_invalid_transaction_activity(
        self,
        *,
        incident_id: str,
    ) -> Evidence:
        """Collect invalid transaction activity during the recent window."""
        query = (
            "sum(increase("
            "finstream_processor_invalid_transactions_total[5m]"
            "))"
        )

        return self._collect_metric_evidence(
            incident_id=incident_id,
            service="processor",
            tool_name="get_invalid_transaction_activity",
            query=query,
            metric_name="invalid transaction activity",
            unit="transactions",
            window="5m",
        )

    def get_dlq_activity(
        self,
        *,
        incident_id: str,
    ) -> Evidence:
        """Collect DLQ activity during the recent window."""
        query = (
            "sum(increase("
            "finstream_processor_dlq_messages_total[5m]"
            "))"
        )

        return self._collect_metric_evidence(
            incident_id=incident_id,
            service="processor",
            tool_name="get_dlq_activity",
            query=query,
            metric_name="DLQ activity",
            unit="messages",
            window="5m",
        )
