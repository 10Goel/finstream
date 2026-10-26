from services.ai_sre_agent.investigation.evidence_collector import (
    EvidenceCollectionResult,
)
from services.ai_sre_agent.models import (
    AlertStatus,
    Evidence,
    EvidenceSource,
    EvidenceTrustLevel,
    Incident,
    ToolCall,
    ToolCallStatus,
)
from services.ai_sre_agent.orchestrator import (
    ConstrainedIncidentOrchestrator,
    IncompleteEvidenceError,
)
from services.ai_sre_agent.reasoning.selector import (
    CandidateSelectionOutcome,
)


def make_incident():
    return Incident(
        fingerprint="orchestrator-test",
        alert_name="FinStreamServiceDown",
        alert_status=AlertStatus.FIRING,
        severity="critical",
        affected_service="processor",
        summary="Processor unavailable.",
    )


def make_outage_evidence(incident):
    return [
        Evidence(
            incident_id=incident.incident_id,
            source=EvidenceSource.PROMETHEUS,
            tool="get_service_health",
            summary="Processor target is down.",
            trust_level=(
                EvidenceTrustLevel.DIRECT_OBSERVATION
            ),
            service="processor",
            metadata={
                "series_count": 1,
                "up_targets": 0,
                "down_targets": 1,
            },
            evidence_id="ev-prometheus",
        ),
        Evidence(
            incident_id=incident.incident_id,
            source=EvidenceSource.KUBERNETES,
            tool="get_deployment_status",
            summary="Processor has no ready replicas.",
            trust_level=(
                EvidenceTrustLevel.DIRECT_OBSERVATION
            ),
            service="processor",
            metadata={
                "desired_replicas": 0,
                "ready_replicas": 0,
                "available_replicas": 0,
                "healthy": False,
            },
            evidence_id="ev-deployment",
        ),
    ]


class FakeCollector:
    def __init__(self, result):
        self.result = result
        self.calls = 0

    def collect(self, *, incident):
        self.calls += 1
        return self.result


class FakeReasoner:
    def __init__(self):
        self.calls = 0
        self.last_constraints = None
        self.documentation_context = None
        self.historical_context = None

    def select(
        self,
        *,
        constraints,
        documentation_context=(),
        historical_context=(),
    ):
        self.calls += 1
        self.last_constraints = constraints
        self.documentation_context = (
            documentation_context
        )
        self.historical_context = (
            historical_context
        )

        return CandidateSelectionOutcome(
            selections=(),
            abstained=True,
            abstention_reason="test abstention",
        )


def successful_collection(incident):
    evidence = make_outage_evidence(incident)

    calls = []

    for index, item in enumerate(
        evidence,
        start=1,
    ):
        calls.append(
            ToolCall(
                incident_id=incident.incident_id,
                tool=f"test.tool.{index}",
                status=ToolCallStatus.SUCCESS,
                evidence_ids=[item.evidence_id],
            )
        )

    return EvidenceCollectionResult(
        incident_id=incident.incident_id,
        service="processor",
        evidence=evidence,
        tool_calls=calls,
    )


def test_successful_investigation_reaches_reasoner():
    incident = make_incident()

    collector = FakeCollector(
        successful_collection(incident)
    )
    reasoner = FakeReasoner()

    orchestrator = ConstrainedIncidentOrchestrator(
        collector=collector,
        reasoner=reasoner,
    )

    result = orchestrator.investigate(
        incident=incident
    )

    assert collector.calls == 1
    assert reasoner.calls == 1

    assert result.incident_id == incident.incident_id

    assert (
        result.constraints.affected_service
        == "processor"
    )

    assert len(result.constraints.candidates) == 1

    assert result.selection.abstained is True


def test_failed_diagnostic_blocks_model_reasoning():
    incident = make_incident()

    collection = successful_collection(
        incident
    )

    collection.tool_calls.append(
        ToolCall(
            incident_id=incident.incident_id,
            tool="test.failed",
            status=ToolCallStatus.FAILED,
            error="diagnostic unavailable",
        )
    )

    collector = FakeCollector(collection)
    reasoner = FakeReasoner()

    orchestrator = ConstrainedIncidentOrchestrator(
        collector=collector,
        reasoner=reasoner,
    )

    try:
        orchestrator.investigate(
            incident=incident
        )
    except IncompleteEvidenceError as exc:
        assert "diagnostic" in str(exc)
    else:
        raise AssertionError(
            "Expected IncompleteEvidenceError"
        )

    assert collector.calls == 1
    assert reasoner.calls == 0


def test_constraints_are_built_before_reasoning():
    incident = make_incident()

    collector = FakeCollector(
        successful_collection(incident)
    )
    reasoner = FakeReasoner()

    orchestrator = ConstrainedIncidentOrchestrator(
        collector=collector,
        reasoner=reasoner,
    )

    orchestrator.investigate(
        incident=incident
    )

    assert reasoner.last_constraints is not None

    candidate = (
        reasoner.last_constraints.candidates[0]
    )

    assert (
        candidate.candidate_id
        == "processor-immediate-unavailable"
    )

    assert candidate.supporting_evidence == (
        "ev-prometheus",
        "ev-deployment",
    )


def test_diagnostic_evidence_is_preserved_in_result():
    incident = make_incident()

    collection = successful_collection(
        incident
    )

    orchestrator = ConstrainedIncidentOrchestrator(
        collector=FakeCollector(collection),
        reasoner=FakeReasoner(),
    )

    result = orchestrator.investigate(
        incident=incident
    )

    assert (
        result.evidence_collection.evidence
        == collection.evidence
    )

    assert (
        result.evidence_collection.tool_calls
        == collection.tool_calls
    )
