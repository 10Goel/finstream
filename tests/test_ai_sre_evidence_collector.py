from unittest.mock import MagicMock

import pytest

from services.ai_sre_agent.investigation import EvidenceCollector
from services.ai_sre_agent.models import (
    AlertStatus,
    Evidence,
    EvidenceSource,
    EvidenceTrustLevel,
    Incident,
    ToolCallStatus,
)
from services.ai_sre_agent.tools.logs import LogDiagnosticError


def make_evidence(
    *,
    incident_id,
    tool,
    service,
    source=EvidenceSource.PROMETHEUS,
):
    return Evidence(
        incident_id=incident_id,
        source=source,
        tool=tool,
        summary=f"Evidence from {tool}.",
        trust_level=EvidenceTrustLevel.DIRECT_OBSERVATION,
        service=service,
    )


def configure_method(
    target,
    method_name,
    *,
    source,
    default_service,
):
    method = getattr(target, method_name)

    def produce(**kwargs):
        return make_evidence(
            incident_id=kwargs["incident_id"],
            tool=method_name,
            service=kwargs.get(
                "service",
                default_service,
            ),
            source=source,
        )

    method.side_effect = produce


def make_collector():
    prometheus = MagicMock()
    kubernetes = MagicMock()
    logs = MagicMock()
    kafka = MagicMock()
    postgres = MagicMock()

    for method_name, service in [
        ("get_service_health", "api"),
        ("get_api_p95_latency", "api"),
        ("get_producer_publish_rate", "producer"),
        (
            "get_producer_delivery_failures",
            "producer",
        ),
        (
            "get_processor_throughput",
            "processor",
        ),
        (
            "get_processor_alert_rate",
            "processor",
        ),
        (
            "get_invalid_transaction_activity",
            "processor",
        ),
        ("get_dlq_activity", "processor"),
    ]:
        configure_method(
            prometheus,
            method_name,
            source=EvidenceSource.PROMETHEUS,
            default_service=service,
        )

    for method_name in [
        "get_deployment_status",
        "get_pods",
        "get_restart_count",
        "get_recent_events",
    ]:
        configure_method(
            kubernetes,
            method_name,
            source=EvidenceSource.KUBERNETES,
            default_service="processor",
        )

    configure_method(
        logs,
        "get_recent_logs",
        source=EvidenceSource.LOGS,
        default_service="processor",
    )

    for method_name, service in [
        ("check_broker_health", "kafka"),
        ("get_topic_metadata", "kafka"),
        (
            "get_consumer_group_state",
            "processor",
        ),
        (
            "get_consumer_lag",
            "processor",
        ),
    ]:
        configure_method(
            kafka,
            method_name,
            source=EvidenceSource.KAFKA,
            default_service=service,
        )

    for method_name in [
        "check_database_health",
        "get_transaction_statistics",
        "get_persistence_freshness",
        "get_connection_statistics",
    ]:
        configure_method(
            postgres,
            method_name,
            source=EvidenceSource.POSTGRESQL,
            default_service="postgres",
        )

    collector = EvidenceCollector(
        prometheus=prometheus,
        kubernetes=kubernetes,
        logs=logs,
        kafka=kafka,
        postgres=postgres,
    )

    return (
        collector,
        {
            "prometheus": prometheus,
            "kubernetes": kubernetes,
            "logs": logs,
            "kafka": kafka,
            "postgres": postgres,
        },
    )


def make_incident(service):
    return Incident(
        fingerprint=f"fingerprint-{service}",
        alert_name="FinStreamServiceDown",
        alert_status=AlertStatus.FIRING,
        severity="critical",
        affected_service=service,
    )


def test_api_plan_collects_expected_evidence():
    collector, tools = make_collector()
    incident = make_incident("api")

    result = collector.collect(
        incident=incident,
    )

    assert result.incident_id == incident.incident_id
    assert result.service == "api"
    assert len(result.tool_calls) == 9
    assert len(result.evidence) == 9
    assert result.successful_tool_calls == 9
    assert result.failed_tool_calls == 0

    tools[
        "postgres"
    ].check_database_health.assert_called_once()

    tools[
        "postgres"
    ].get_connection_statistics.assert_called_once()

    tools[
        "kafka"
    ].check_broker_health.assert_not_called()


def test_producer_plan_collects_expected_evidence():
    collector, tools = make_collector()
    incident = make_incident("producer")

    result = collector.collect(
        incident=incident,
    )

    assert len(result.tool_calls) == 10
    assert len(result.evidence) == 10
    assert result.failed_tool_calls == 0

    tools[
        "prometheus"
    ].get_producer_publish_rate.assert_called_once()

    tools[
        "prometheus"
    ].get_producer_delivery_failures.assert_called_once()

    tools[
        "kafka"
    ].check_broker_health.assert_called_once()

    tools[
        "kafka"
    ].get_topic_metadata.assert_called_once_with(
        incident_id=incident.incident_id,
        topic="transactions",
    )

    tools[
        "postgres"
    ].check_database_health.assert_not_called()


def test_processor_plan_collects_expected_evidence():
    collector, tools = make_collector()
    incident = make_incident("processor")

    result = collector.collect(
        incident=incident,
    )

    assert len(result.tool_calls) == 16
    assert len(result.evidence) == 16
    assert result.successful_tool_calls == 16
    assert result.failed_tool_calls == 0

    tools[
        "kafka"
    ].get_consumer_group_state.assert_called_once()

    tools[
        "kafka"
    ].get_consumer_lag.assert_called_once()

    tools[
        "postgres"
    ].get_persistence_freshness.assert_called_once_with(
        incident_id=incident.incident_id,
        window_minutes=5,
    )


def test_every_evidence_item_keeps_incident_id():
    collector, _ = make_collector()
    incident = make_incident("processor")

    result = collector.collect(
        incident=incident,
    )

    assert all(
        item.incident_id == incident.incident_id
        for item in result.evidence
    )


def test_successful_calls_record_evidence_ids():
    collector, _ = make_collector()
    incident = make_incident("producer")

    result = collector.collect(
        incident=incident,
    )

    evidence_ids = {
        item.evidence_id
        for item in result.evidence
    }

    recorded_ids = {
        evidence_id
        for call in result.tool_calls
        for evidence_id in call.evidence_ids
    }

    assert recorded_ids == evidence_ids

    assert all(
        call.status is ToolCallStatus.SUCCESS
        for call in result.tool_calls
    )

    assert all(
        call.started_at is not None
        and call.completed_at is not None
        for call in result.tool_calls
    )


def test_tool_failure_does_not_abort_investigation():
    collector, tools = make_collector()

    tools[
        "logs"
    ].get_recent_logs.side_effect = LogDiagnosticError(
        "log backend unavailable"
    )

    incident = make_incident("processor")

    result = collector.collect(
        incident=incident,
    )

    assert len(result.tool_calls) == 16
    assert len(result.evidence) == 15

    assert result.successful_tool_calls == 15
    assert result.failed_tool_calls == 1

    failed = [
        call
        for call in result.tool_calls
        if call.status is ToolCallStatus.FAILED
    ]

    assert len(failed) == 1
    assert failed[0].tool == "logs.get_recent_logs"

    assert (
        "LogDiagnosticError"
        in failed[0].error
    )

    assert failed[0].evidence_ids == []


def test_mismatched_incident_evidence_is_rejected():
    collector, tools = make_collector()

    tools[
        "prometheus"
    ].get_service_health.side_effect = (
        lambda **_kwargs: make_evidence(
            incident_id="inc-wrong",
            tool="get_service_health",
            service="producer",
        )
    )

    incident = make_incident("producer")

    result = collector.collect(
        incident=incident,
    )

    assert len(result.tool_calls) == 10
    assert len(result.evidence) == 9
    assert result.failed_tool_calls == 1

    failed = result.tool_calls[0]

    assert failed.status is ToolCallStatus.FAILED

    assert (
        "different incident"
        in failed.error
    )


@pytest.mark.parametrize(
    "service",
    [
        None,
        "",
        "kafka",
        "postgres",
        "unknown-service",
    ],
)
def test_unsupported_affected_service_is_rejected(
    service,
):
    collector, _ = make_collector()
    incident = make_incident(service)

    with pytest.raises(
        ValueError,
        match=(
            "affected_service|"
            "Unsupported FinStream affected service"
        ),
    ):
        collector.collect(
            incident=incident,
        )


def test_processor_plan_is_deterministic():
    collector, _ = make_collector()
    incident = make_incident("processor")

    result = collector.collect(
        incident=incident,
    )

    assert [
        call.tool
        for call in result.tool_calls
    ] == [
        "prometheus.get_service_health",
        "prometheus.get_processor_throughput",
        "prometheus.get_processor_alert_rate",
        (
            "prometheus."
            "get_invalid_transaction_activity"
        ),
        "prometheus.get_dlq_activity",
        "kubernetes.get_deployment_status",
        "kubernetes.get_pods",
        "kubernetes.get_restart_count",
        "kubernetes.get_recent_events",
        "logs.get_recent_logs",
        "kafka.check_broker_health",
        "kafka.get_topic_metadata",
        "kafka.get_consumer_group_state",
        "kafka.get_consumer_lag",
        "postgres.check_database_health",
        "postgres.get_persistence_freshness",
    ]
