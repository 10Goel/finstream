from datetime import timezone

import pytest

from services.ai_sre_agent.models import (
    AlertStatus,
    Evidence,
    EvidenceSource,
    EvidenceTrustLevel,
    Hypothesis,
    Incident,
    IncidentStatus,
    RootCauseAnalysis,
    ToolCall,
    ToolCallStatus,
)


def make_incident() -> Incident:
    return Incident(
        fingerprint="test-fingerprint",
        alert_name="FinStreamServiceDown",
        alert_status=AlertStatus.FIRING,
        severity="critical",
        affected_service="producer",
    )


def test_incident_defaults_to_received():
    incident = make_incident()

    assert incident.incident_id.startswith("inc-")
    assert incident.status is IncidentStatus.RECEIVED
    assert incident.started_at.tzinfo is timezone.utc


def test_valid_incident_transition():
    incident = make_incident()

    incident.transition_to(IncidentStatus.INVESTIGATING)

    assert incident.status is IncidentStatus.INVESTIGATING


def test_invalid_incident_transition_is_rejected():
    incident = make_incident()

    with pytest.raises(
        ValueError,
        match="RECEIVED -> RESOLVED",
    ):
        incident.transition_to(IncidentStatus.RESOLVED)


def test_resolution_records_timestamp():
    incident = make_incident()

    incident.transition_to(IncidentStatus.INVESTIGATING)
    incident.transition_to(IncidentStatus.DIAGNOSED)
    incident.transition_to(IncidentStatus.AWAITING_APPROVAL)
    incident.transition_to(IncidentStatus.REMEDIATING)
    incident.transition_to(IncidentStatus.VERIFYING)
    incident.transition_to(IncidentStatus.RESOLVED)

    assert incident.resolved_at is not None
    assert incident.resolved_at.tzinfo is timezone.utc


def test_evidence_records_provenance():
    incident = make_incident()

    evidence = Evidence(
        incident_id=incident.incident_id,
        source=EvidenceSource.PROMETHEUS,
        tool="get_service_health",
        summary="Producer target is down",
        trust_level=EvidenceTrustLevel.DIRECT_OBSERVATION,
        service="producer",
        raw_reference='up{job="finstream-producer"} = 0',
    )

    assert evidence.evidence_id.startswith("ev-")
    assert evidence.incident_id == incident.incident_id
    assert evidence.source is EvidenceSource.PROMETHEUS
    assert evidence.observed_at.tzinfo is timezone.utc


def test_empty_evidence_summary_is_rejected():
    with pytest.raises(
        ValueError,
        match="Evidence summary must not be empty",
    ):
        Evidence(
            incident_id="inc-test",
            source=EvidenceSource.PROMETHEUS,
            tool="get_service_health",
            summary="   ",
            trust_level=EvidenceTrustLevel.DIRECT_OBSERVATION,
        )


def test_tool_call_starts_pending():
    tool_call = ToolCall(
        incident_id="inc-test",
        tool="get_pod_status",
        arguments={"service": "producer"},
    )

    assert tool_call.tool_call_id.startswith("tool-")
    assert tool_call.status is ToolCallStatus.PENDING
    assert tool_call.evidence_ids == []


def test_hypothesis_confidence_must_be_bounded():
    with pytest.raises(
        ValueError,
        match="confidence must be between 0 and 1",
    ):
        Hypothesis(
            incident_id="inc-test",
            statement="Kafka broker is unavailable",
            confidence=1.5,
        )


def test_rca_requires_supporting_evidence():
    with pytest.raises(
        ValueError,
        match="requires supporting evidence",
    ):
        RootCauseAnalysis(
            incident_id="inc-test",
            affected_service="producer",
            root_cause="Producer workload unavailable",
            impact="Transactions are not being published",
            recommended_action="Inspect producer workload",
            supporting_evidence=[],
        )


def test_valid_rca_is_evidence_grounded():
    rca = RootCauseAnalysis(
        incident_id="inc-test",
        affected_service="producer",
        root_cause="Producer workload unavailable",
        impact="Transactions are not entering Kafka",
        recommended_action="Inspect and restore the producer workload",
        supporting_evidence=["ev-001", "ev-002"],
        confidence=0.9,
        alternatives_considered=["Kafka broker outage"],
    )

    assert rca.rca_id.startswith("rca-")
    assert rca.supporting_evidence == ["ev-001", "ev-002"]
    assert rca.confidence == 0.9
