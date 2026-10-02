from urllib.parse import parse_qs, urlparse

import pytest

from services.ai_sre_agent.models import (
    EvidenceSource,
    EvidenceTrustLevel,
)
from services.ai_sre_agent.tools.prometheus import (
    PrometheusDiagnosticTool,
    PrometheusQueryError,
)


def prometheus_vector(values):
    return {
        "status": "success",
        "data": {
            "resultType": "vector",
            "result": [
                {
                    "metric": labels,
                    "value": [timestamp, value],
                }
                for labels, timestamp, value in values
            ],
        },
    }


def test_service_health_returns_up_evidence():
    requested_urls = []

    def request_json(url):
        requested_urls.append(url)
        return prometheus_vector(
            [
                (
                    {
                        "job": "finstream-producer",
                        "instance": "producer-metrics:8001",
                    },
                    1_700_000_000,
                    "1",
                )
            ]
        )

    tool = PrometheusDiagnosticTool(
        "http://prometheus:9090",
        request_json=request_json,
    )

    evidence = tool.get_service_health(
        incident_id="inc-test",
        service="producer",
    )

    assert evidence.source is EvidenceSource.PROMETHEUS
    assert (
        evidence.trust_level
        is EvidenceTrustLevel.DIRECT_OBSERVATION
    )
    assert evidence.service == "producer"
    assert evidence.metadata["up_targets"] == 1
    assert evidence.metadata["down_targets"] == 0
    assert "all producer targets as up" in evidence.summary

    query = parse_qs(
        urlparse(requested_urls[0]).query
    )["query"][0]

    assert query == 'up{job="finstream-producer"}'


def test_service_health_reports_down_target():
    tool = PrometheusDiagnosticTool(
        "http://prometheus:9090",
        request_json=lambda _: prometheus_vector(
            [
                (
                    {
                        "job": "finstream-api",
                        "instance": "api:8000",
                    },
                    1_700_000_000,
                    "0",
                )
            ]
        ),
    )

    evidence = tool.get_service_health(
        incident_id="inc-test",
        service="api",
    )

    assert evidence.metadata["up_targets"] == 0
    assert evidence.metadata["down_targets"] == 1
    assert "1 of 1 api target(s) as down" in evidence.summary


def test_service_health_handles_missing_series():
    tool = PrometheusDiagnosticTool(
        "http://prometheus:9090",
        request_json=lambda _: prometheus_vector([]),
    )

    evidence = tool.get_service_health(
        incident_id="inc-test",
        service="processor",
    )

    assert evidence.metadata["series_count"] == 0
    assert "No Prometheus health series found" in evidence.summary


def test_unknown_service_is_rejected_before_query():
    called = False

    def request_json(_):
        nonlocal called
        called = True
        return prometheus_vector([])

    tool = PrometheusDiagnosticTool(
        "http://prometheus:9090",
        request_json=request_json,
    )

    with pytest.raises(
        ValueError,
        match="Unsupported FinStream service",
    ):
        tool.get_service_health(
            incident_id="inc-test",
            service="kafka",
        )

    assert called is False


def test_prometheus_error_response_is_rejected():
    tool = PrometheusDiagnosticTool(
        "http://prometheus:9090",
        request_json=lambda _: {
            "status": "error",
            "error": "bad query",
        },
    )

    with pytest.raises(
        PrometheusQueryError,
        match="bad query",
    ):
        tool.get_service_health(
            incident_id="inc-test",
            service="producer",
        )


def test_malformed_prometheus_sample_is_rejected():
    tool = PrometheusDiagnosticTool(
        "http://prometheus:9090",
        request_json=lambda _: {
            "status": "success",
            "data": {
                "resultType": "vector",
                "result": [
                    {
                        "metric": {
                            "job": "finstream-producer",
                        },
                        "value": ["not-a-timestamp"],
                    }
                ],
            },
        },
    )

    with pytest.raises(
        PrometheusQueryError,
        match="sample value is malformed",
    ):
        tool.get_service_health(
            incident_id="inc-test",
            service="producer",
        )


def test_invalid_base_url_is_rejected():
    with pytest.raises(
        ValueError,
        match="valid HTTP or HTTPS URL",
    ):
        PrometheusDiagnosticTool("prometheus:9090")


def test_non_positive_timeout_is_rejected():
    with pytest.raises(
        ValueError,
        match="timeout_seconds must be positive",
    ):
        PrometheusDiagnosticTool(
            "http://prometheus:9090",
            timeout_seconds=0,
        )


@pytest.mark.parametrize(
    (
        "method_name",
        "expected_query",
        "expected_service",
        "expected_tool",
        "expected_metric",
    ),
    [
        (
            "get_api_p95_latency",
            (
                "histogram_quantile("
                "0.95, "
                "sum by (le) ("
                "rate("
                "finstream_api_http_request_duration_seconds_bucket"
                '{path!="/health"}[5m]'
                ")"
                ")"
                ")"
            ),
            "api",
            "get_api_p95_latency",
            "API p95 latency",
        ),
        (
            "get_producer_publish_rate",
            (
                "sum(rate("
                "finstream_producer_transactions_published_total[5m]"
                "))"
            ),
            "producer",
            "get_producer_publish_rate",
            "producer publish rate",
        ),
        (
            "get_producer_delivery_failures",
            (
                "sum(increase("
                "finstream_producer_delivery_failures_total[5m]"
                "))"
            ),
            "producer",
            "get_producer_delivery_failures",
            "producer delivery failures",
        ),
        (
            "get_processor_throughput",
            (
                "sum(rate("
                "finstream_processor_transactions_processed_total[5m]"
                "))"
            ),
            "processor",
            "get_processor_throughput",
            "processor throughput",
        ),
        (
            "get_processor_alert_rate",
            (
                "sum(rate("
                "finstream_processor_alerts_total[5m]"
                "))"
            ),
            "processor",
            "get_processor_alert_rate",
            "processor alert rate",
        ),
        (
            "get_invalid_transaction_activity",
            (
                "sum(increase("
                "finstream_processor_invalid_transactions_total[5m]"
                "))"
            ),
            "processor",
            "get_invalid_transaction_activity",
            "invalid transaction activity",
        ),
        (
            "get_dlq_activity",
            (
                "sum(increase("
                "finstream_processor_dlq_messages_total[5m]"
                "))"
            ),
            "processor",
            "get_dlq_activity",
            "DLQ activity",
        ),
    ],
)
def test_predefined_metric_diagnostics(
    method_name,
    expected_query,
    expected_service,
    expected_tool,
    expected_metric,
):
    requested_urls = []

    def request_json(url):
        requested_urls.append(url)
        return prometheus_vector(
            [
                (
                    {
                        "job": f"finstream-{expected_service}",
                    },
                    1_700_000_000,
                    "2.5",
                )
            ]
        )

    tool = PrometheusDiagnosticTool(
        "http://prometheus:9090",
        request_json=request_json,
    )

    method = getattr(tool, method_name)

    evidence = method(
        incident_id="inc-test",
    )

    query = parse_qs(
        urlparse(requested_urls[0]).query
    )["query"][0]

    assert query == expected_query
    assert evidence.service == expected_service
    assert evidence.tool == expected_tool
    assert evidence.metadata["metric"] == expected_metric
    assert evidence.metadata["value"] == 2.5
    assert evidence.metadata["series_count"] == 1
    assert evidence.metadata["window"] == "5m"


def test_metric_diagnostic_sums_multiple_series():
    tool = PrometheusDiagnosticTool(
        "http://prometheus:9090",
        request_json=lambda _: prometheus_vector(
            [
                (
                    {"reason": "new_device"},
                    1_700_000_000,
                    "0.2",
                ),
                (
                    {"reason": "unusual_location"},
                    1_700_000_000,
                    "0.3",
                ),
            ]
        ),
    )

    evidence = tool.get_processor_alert_rate(
        incident_id="inc-test",
    )

    assert evidence.metadata["series_count"] == 2
    assert evidence.metadata["value"] == pytest.approx(0.5)


def test_metric_diagnostic_handles_missing_series():
    tool = PrometheusDiagnosticTool(
        "http://prometheus:9090",
        request_json=lambda _: prometheus_vector([]),
    )

    evidence = tool.get_dlq_activity(
        incident_id="inc-test",
    )

    assert evidence.metadata["series_count"] == 0
    assert evidence.metadata["value"] is None
    assert "No Prometheus series found" in evidence.summary
