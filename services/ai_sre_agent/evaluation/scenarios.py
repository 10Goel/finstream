"""Deterministic evaluation scenarios for FinStream AI-SRE."""

from __future__ import annotations

from dataclasses import dataclass

from services.ai_sre_agent.evaluation.models import (
    EvaluationExpectation,
    EvaluationScenario,
    ExpectedDecision,
)
from services.ai_sre_agent.models import (
    AlertStatus,
    Evidence,
    EvidenceSource,
    EvidenceTrustLevel,
    Incident,
)


@dataclass(frozen=True, slots=True)
class EvaluationFixture:
    """Incident, evidence, and expected behaviour for one scenario."""

    scenario: EvaluationScenario
    incident: Incident
    evidence: tuple[Evidence, ...]


def _incident(
    *,
    scenario_id: str,
    affected_service: str,
    summary: str,
    alert_status: AlertStatus = AlertStatus.FIRING,
) -> Incident:
    return Incident(
        fingerprint=f"evaluation-{scenario_id}",
        alert_name="FinStreamEvaluation",
        alert_status=alert_status,
        severity="critical",
        affected_service=affected_service,
        summary=summary,
    )


def _evidence(
    *,
    incident: Incident,
    evidence_id: str,
    source: EvidenceSource,
    tool: str,
    service: str,
    summary: str,
    metadata: dict,
) -> Evidence:
    return Evidence(
        incident_id=incident.incident_id,
        source=source,
        tool=tool,
        summary=summary,
        trust_level=(
            EvidenceTrustLevel.DIRECT_OBSERVATION
        ),
        service=service,
        metadata=metadata,
        evidence_id=evidence_id,
    )


def processor_outage_fixture() -> EvaluationFixture:
    """Processor unavailable while dependencies remain healthy."""
    incident = _incident(
        scenario_id="processor-outage",
        affected_service="processor",
        summary="Processor workload is unavailable.",
    )

    evidence = (
        _evidence(
            incident=incident,
            evidence_id="ev-processor-prometheus",
            source=EvidenceSource.PROMETHEUS,
            tool="get_service_health",
            service="processor",
            summary="Processor target is down.",
            metadata={
                "series_count": 1,
                "up_targets": 0,
                "down_targets": 1,
            },
        ),
        _evidence(
            incident=incident,
            evidence_id="ev-processor-deployment",
            source=EvidenceSource.KUBERNETES,
            tool="get_deployment_status",
            service="processor",
            summary="Processor has zero ready replicas.",
            metadata={
                "desired_replicas": 0,
                "ready_replicas": 0,
                "available_replicas": 0,
                "healthy": False,
            },
        ),
        _evidence(
            incident=incident,
            evidence_id="ev-kafka-healthy",
            source=EvidenceSource.KAFKA,
            tool="check_broker_health",
            service="kafka",
            summary="Kafka broker is healthy.",
            metadata={
                "broker_count": 1,
                "healthy": True,
            },
        ),
        _evidence(
            incident=incident,
            evidence_id="ev-postgres-healthy",
            source=EvidenceSource.POSTGRESQL,
            tool="check_database_health",
            service="postgres",
            summary="PostgreSQL is healthy.",
            metadata={
                "healthy": True,
            },
        ),
    )

    scenario = EvaluationScenario(
        scenario_id="processor-outage",
        description=(
            "Processor is unavailable while Kafka and "
            "PostgreSQL remain healthy."
        ),
        affected_service="processor",
        expectation=EvaluationExpectation(
            decision=ExpectedDecision.SELECT,
            expected_candidate_ids=(
                "processor-immediate-unavailable",
            ),
            required_ruled_out_subsystems=(
                "kafka",
                "postgres",
            ),
            forbidden_candidate_ids=(
                "kafka-immediate-unavailable",
                "postgres-immediate-unavailable",
            ),
        ),
    )

    return EvaluationFixture(
        scenario=scenario,
        incident=incident,
        evidence=evidence,
    )


def kafka_dependency_impairment_fixture() -> EvaluationFixture:
    """Producer unavailable while Kafka evidence is unhealthy."""
    incident = _incident(
        scenario_id="kafka-dependency-impairment",
        affected_service="producer",
        summary=(
            "Producer is unavailable while Kafka "
            "dependency health is degraded."
        ),
    )

    evidence = (
        _evidence(
            incident=incident,
            evidence_id="ev-producer-prometheus",
            source=EvidenceSource.PROMETHEUS,
            tool="get_service_health",
            service="producer",
            summary="Producer target is down.",
            metadata={
                "series_count": 1,
                "up_targets": 0,
                "down_targets": 1,
            },
        ),
        _evidence(
            incident=incident,
            evidence_id="ev-producer-deployment",
            source=EvidenceSource.KUBERNETES,
            tool="get_deployment_status",
            service="producer",
            summary="Producer has zero ready replicas.",
            metadata={
                "desired_replicas": 1,
                "ready_replicas": 0,
                "available_replicas": 0,
                "healthy": False,
            },
        ),
        _evidence(
            incident=incident,
            evidence_id="ev-kafka-unhealthy",
            source=EvidenceSource.KAFKA,
            tool="check_broker_health",
            service="kafka",
            summary="Kafka reports no reachable brokers.",
            metadata={
                "broker_count": 0,
                "healthy": False,
            },
        ),
    )

    scenario = EvaluationScenario(
        scenario_id="kafka-dependency-impairment",
        description=(
            "Producer outage coincides with unhealthy Kafka "
            "dependency evidence."
        ),
        affected_service="producer",
        expectation=EvaluationExpectation(
            decision=ExpectedDecision.SELECT,
            expected_candidate_ids=(
                "producer-immediate-unavailable",
            ),
            forbidden_candidate_ids=(
                "kafka-immediate-unavailable",
            ),
        ),
    )

    return EvaluationFixture(
        scenario=scenario,
        incident=incident,
        evidence=evidence,
    )


def postgres_dependency_impairment_fixture() -> EvaluationFixture:
    """API unavailable while PostgreSQL evidence is unhealthy."""
    incident = _incident(
        scenario_id="postgres-dependency-impairment",
        affected_service="api",
        summary=(
            "API is unavailable while PostgreSQL "
            "dependency health is degraded."
        ),
    )

    evidence = (
        _evidence(
            incident=incident,
            evidence_id="ev-api-prometheus",
            source=EvidenceSource.PROMETHEUS,
            tool="get_service_health",
            service="api",
            summary="API target is down.",
            metadata={
                "series_count": 1,
                "up_targets": 0,
                "down_targets": 1,
            },
        ),
        _evidence(
            incident=incident,
            evidence_id="ev-api-deployment",
            source=EvidenceSource.KUBERNETES,
            tool="get_deployment_status",
            service="api",
            summary="API has zero ready replicas.",
            metadata={
                "desired_replicas": 1,
                "ready_replicas": 0,
                "available_replicas": 0,
                "healthy": False,
            },
        ),
        _evidence(
            incident=incident,
            evidence_id="ev-postgres-unhealthy",
            source=EvidenceSource.POSTGRESQL,
            tool="check_database_health",
            service="postgres",
            summary=(
                "PostgreSQL diagnostic health is degraded."
            ),
            metadata={
                "healthy": False,
            },
        ),
    )

    scenario = EvaluationScenario(
        scenario_id="postgres-dependency-impairment",
        description=(
            "API outage coincides with unhealthy PostgreSQL "
            "dependency evidence."
        ),
        affected_service="api",
        expectation=EvaluationExpectation(
            decision=ExpectedDecision.SELECT,
            expected_candidate_ids=(
                "api-immediate-unavailable",
            ),
            forbidden_candidate_ids=(
                "postgres-immediate-unavailable",
            ),
        ),
    )

    return EvaluationFixture(
        scenario=scenario,
        incident=incident,
        evidence=evidence,
    )


def healthy_baseline_fixture() -> EvaluationFixture:
    """Healthy processor baseline must not create a diagnosis."""
    incident = _incident(
        scenario_id="healthy-baseline",
        affected_service="processor",
        summary="Processor is operating normally.",
        alert_status=AlertStatus.RESOLVED,
    )

    evidence = (
        _evidence(
            incident=incident,
            evidence_id="ev-healthy-processor",
            source=EvidenceSource.PROMETHEUS,
            tool="get_service_health",
            service="processor",
            summary="Processor target is healthy.",
            metadata={
                "series_count": 1,
                "up_targets": 1,
                "down_targets": 0,
            },
        ),
        _evidence(
            incident=incident,
            evidence_id="ev-healthy-kafka",
            source=EvidenceSource.KAFKA,
            tool="check_broker_health",
            service="kafka",
            summary="Kafka broker is healthy.",
            metadata={
                "broker_count": 1,
                "healthy": True,
            },
        ),
        _evidence(
            incident=incident,
            evidence_id="ev-healthy-postgres",
            source=EvidenceSource.POSTGRESQL,
            tool="check_database_health",
            service="postgres",
            summary="PostgreSQL is healthy.",
            metadata={
                "healthy": True,
            },
        ),
    )

    scenario = EvaluationScenario(
        scenario_id="healthy-baseline",
        description=(
            "All directly observed FinStream components "
            "are healthy."
        ),
        affected_service="processor",
        expectation=EvaluationExpectation(
            decision=ExpectedDecision.ABSTAIN,
        ),
    )

    return EvaluationFixture(
        scenario=scenario,
        incident=incident,
        evidence=evidence,
    )


def ambiguous_processor_fixture() -> EvaluationFixture:
    """Symptoms without direct outage evidence require abstention."""
    incident = _incident(
        scenario_id="ambiguous-processor",
        affected_service="processor",
        summary=(
            "Processor has downstream symptoms but no "
            "direct evidence of unavailability."
        ),
    )

    evidence = (
        _evidence(
            incident=incident,
            evidence_id="ev-group-empty",
            source=EvidenceSource.KAFKA,
            tool="get_consumer_group_state",
            service="processor",
            summary="Consumer group has no active members.",
            metadata={
                "state": "EMPTY",
                "member_count": 0,
            },
        ),
        _evidence(
            incident=incident,
            evidence_id="ev-lag",
            source=EvidenceSource.KAFKA,
            tool="get_consumer_lag",
            service="processor",
            summary="Consumer lag is present.",
            metadata={
                "total_lag": 75,
            },
        ),
        _evidence(
            incident=incident,
            evidence_id="ev-ambiguous-kafka",
            source=EvidenceSource.KAFKA,
            tool="check_broker_health",
            service="kafka",
            summary="Kafka broker is healthy.",
            metadata={
                "broker_count": 1,
                "healthy": True,
            },
        ),
        _evidence(
            incident=incident,
            evidence_id="ev-ambiguous-postgres",
            source=EvidenceSource.POSTGRESQL,
            tool="check_database_health",
            service="postgres",
            summary="PostgreSQL is healthy.",
            metadata={
                "healthy": True,
            },
        ),
    )

    scenario = EvaluationScenario(
        scenario_id="ambiguous-processor",
        description=(
            "Consumer symptoms exist without direct evidence "
            "that the processor workload is unavailable."
        ),
        affected_service="processor",
        expectation=EvaluationExpectation(
            decision=ExpectedDecision.ABSTAIN,
        ),
    )

    return EvaluationFixture(
        scenario=scenario,
        incident=incident,
        evidence=evidence,
    )


def evaluation_scenario_catalog() -> tuple[
    EvaluationFixture,
    ...,
]:
    """Return the deterministic FinStream evaluation corpus."""
    return (
        processor_outage_fixture(),
        kafka_dependency_impairment_fixture(),
        postgres_dependency_impairment_fixture(),
        healthy_baseline_fixture(),
        ambiguous_processor_fixture(),
    )
