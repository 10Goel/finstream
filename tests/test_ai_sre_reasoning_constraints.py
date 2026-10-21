import pytest

from services.ai_sre_agent.models import (
    AlertStatus,
    Evidence,
    EvidenceSource,
    EvidenceTrustLevel,
    Incident,
)
from services.ai_sre_agent.reasoning.constraints import (
    EvidenceConstraintBuilder,
)


def make_incident(
    *,
    fingerprint="constraints-test",
):
    return Incident(
        fingerprint=fingerprint,
        alert_name="FinStreamServiceDown",
        alert_status=AlertStatus.FIRING,
        severity="critical",
        affected_service="processor",
        summary="Processor unavailable.",
    )


def make_evidence(
    incident,
    *,
    evidence_id,
    source,
    tool,
    service,
    metadata,
    summary="Diagnostic observation.",
):
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


def outage_evidence(incident):
    return [
        make_evidence(
            incident,
            evidence_id="ev-prometheus",
            source=EvidenceSource.PROMETHEUS,
            tool="get_service_health",
            service="processor",
            metadata={
                "series_count": 1,
                "up_targets": 0,
                "down_targets": 1,
            },
        ),
        make_evidence(
            incident,
            evidence_id="ev-deployment",
            source=EvidenceSource.KUBERNETES,
            tool="get_deployment_status",
            service="processor",
            metadata={
                "desired_replicas": 0,
                "ready_replicas": 0,
                "available_replicas": 0,
                "healthy": False,
            },
        ),
        make_evidence(
            incident,
            evidence_id="ev-pods",
            source=EvidenceSource.KUBERNETES,
            tool="get_pods",
            service="processor",
            metadata={
                "pod_count": 0,
                "running_count": 0,
                "ready_count": 0,
            },
        ),
        make_evidence(
            incident,
            evidence_id="ev-kafka",
            source=EvidenceSource.KAFKA,
            tool="check_broker_health",
            service="kafka",
            metadata={
                "broker_count": 1,
                "healthy": True,
            },
        ),
        make_evidence(
            incident,
            evidence_id="ev-postgres",
            source=EvidenceSource.POSTGRESQL,
            tool="check_database_health",
            service="postgres",
            metadata={
                "healthy": True,
            },
        ),
        make_evidence(
            incident,
            evidence_id="ev-group",
            source=EvidenceSource.KAFKA,
            tool="get_consumer_group_state",
            service="processor",
            metadata={
                "state": "EMPTY",
                "member_count": 0,
            },
        ),
        make_evidence(
            incident,
            evidence_id="ev-lag",
            source=EvidenceSource.KAFKA,
            tool="get_consumer_lag",
            service="processor",
            metadata={
                "total_lag": 148,
                "partition_count": 3,
            },
        ),
    ]


def test_processor_outage_builds_safe_candidate():
    incident = make_incident()

    constraints = EvidenceConstraintBuilder.build(
        incident=incident,
        evidence=outage_evidence(incident),
    )

    assert len(constraints.candidates) == 1

    candidate = constraints.candidates[0]

    assert (
        candidate.candidate_id
        == "processor-immediate-unavailable"
    )

    assert candidate.supporting_evidence == (
        "ev-prometheus",
        "ev-deployment",
        "ev-pods",
    )

    assert candidate.contradicting_evidence == ()

    assert (
        "deeper reason is not established"
        in candidate.statement
    )


def test_healthy_independent_subsystems_are_ruled_out():
    incident = make_incident()

    constraints = EvidenceConstraintBuilder.build(
        incident=incident,
        evidence=outage_evidence(incident),
    )

    assert constraints.ruled_out_subsystems == (
        "kafka",
        "postgres",
    )

    assert "kafka_healthy" in (
        constraints.observed_conditions
    )

    assert "postgres_healthy" in (
        constraints.observed_conditions
    )


def test_downstream_effects_are_facts_not_causal_support():
    incident = make_incident()

    constraints = EvidenceConstraintBuilder.build(
        incident=incident,
        evidence=outage_evidence(incident),
    )

    assert (
        "processor_consumer_group_empty"
        in constraints.observed_conditions
    )

    assert (
        "processor_consumer_lag_present"
        in constraints.observed_conditions
    )

    candidate = constraints.candidates[0]

    assert "ev-group" not in (
        candidate.supporting_evidence
    )

    assert "ev-lag" not in (
        candidate.supporting_evidence
    )


def test_healthy_processor_does_not_create_outage_candidate():
    incident = make_incident()

    evidence = [
        make_evidence(
            incident,
            evidence_id="ev-health",
            source=EvidenceSource.PROMETHEUS,
            tool="get_service_health",
            service="processor",
            metadata={
                "series_count": 1,
                "up_targets": 1,
                "down_targets": 0,
            },
        ),
        make_evidence(
            incident,
            evidence_id="ev-deployment",
            source=EvidenceSource.KUBERNETES,
            tool="get_deployment_status",
            service="processor",
            metadata={
                "desired_replicas": 1,
                "ready_replicas": 1,
                "available_replicas": 1,
                "healthy": True,
            },
        ),
        make_evidence(
            incident,
            evidence_id="ev-pods",
            source=EvidenceSource.KUBERNETES,
            tool="get_pods",
            service="processor",
            metadata={
                "pod_count": 1,
                "running_count": 1,
                "ready_count": 1,
            },
        ),
    ]

    constraints = EvidenceConstraintBuilder.build(
        incident=incident,
        evidence=evidence,
    )

    assert constraints.candidates == ()


def test_cross_incident_evidence_is_rejected():
    incident = make_incident()

    other_incident = make_incident(
        fingerprint="different-incident"
    )

    evidence = [
        make_evidence(
            other_incident,
            evidence_id="ev-other",
            source=EvidenceSource.KUBERNETES,
            tool="get_deployment_status",
            service="processor",
            metadata={
                "healthy": False,
            },
        )
    ]

    with pytest.raises(
        ValueError,
        match="different incident",
    ):
        EvidenceConstraintBuilder.build(
            incident=incident,
            evidence=evidence,
        )
