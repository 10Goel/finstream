from __future__ import annotations

from services.ai_sre_agent.investigation.evidence_collector import (
    EvidenceCollectionResult,
)
from services.ai_sre_agent.memory import (
    DeterministicIncidentMemoryRetriever,
    SQLiteIncidentMemoryStore,
)
from services.ai_sre_agent.models import (
    AlertStatus,
    Evidence,
    EvidenceSource,
    EvidenceTrustLevel,
    Incident,
    IncidentStatus,
    ToolCall,
    ToolCallStatus,
)
from services.ai_sre_agent.orchestrator import (
    ConstrainedIncidentOrchestrator,
    IncompleteEvidenceError,
)
from services.ai_sre_agent.reasoning.selector import (
    CandidateSelectionOutcome,
    SelectedCandidate,
)


def make_incident(
    *,
    fingerprint: str = "current-fingerprint",
) -> Incident:
    return Incident(
        fingerprint=fingerprint,
        alert_name="FinStreamServiceDown",
        alert_status=AlertStatus.FIRING,
        severity="critical",
        affected_service="processor",
        summary="Processor unavailable.",
    )


def make_selection() -> CandidateSelectionOutcome:
    selected = SelectedCandidate(
        candidate_id=(
            "processor-immediate-unavailable"
        ),
        statement=(
            "Processor workload is unavailable."
        ),
        confidence=0.99,
        model_rationale=(
            "Current operational evidence establishes "
            "processor unavailability."
        ),
        supporting_evidence=(
            "ev-prometheus",
            "ev-deployment",
        ),
        contradicting_evidence=(),
        runbook_citations=(),
    )

    return CandidateSelectionOutcome(
        selections=(selected,),
        abstained=False,
        abstention_reason=None,
    )


def make_evidence(
    incident: Incident,
) -> list[Evidence]:
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
            summary=(
                "Processor has no ready replicas."
            ),
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


def successful_collection(
    incident: Incident,
) -> EvidenceCollectionResult:
    evidence = make_evidence(
        incident
    )

    calls = [
        ToolCall(
            incident_id=incident.incident_id,
            tool="test.prometheus",
            status=ToolCallStatus.SUCCESS,
            evidence_ids=[
                "ev-prometheus"
            ],
        ),
        ToolCall(
            incident_id=incident.incident_id,
            tool="test.kubernetes",
            status=ToolCallStatus.SUCCESS,
            evidence_ids=[
                "ev-deployment"
            ],
        ),
    ]

    return EvidenceCollectionResult(
        incident_id=incident.incident_id,
        service="processor",
        evidence=evidence,
        tool_calls=calls,
    )


class FakeCollector:
    def __init__(
        self,
        result: EvidenceCollectionResult,
    ) -> None:
        self.result = result
        self.calls = 0

    def collect(
        self,
        *,
        incident: Incident,
    ) -> EvidenceCollectionResult:
        self.calls += 1
        return self.result


class FakeReasoner:
    def __init__(self) -> None:
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
    ) -> CandidateSelectionOutcome:
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
            abstention_reason=(
                "test abstention"
            ),
        )


class SpyMemoryRetriever:
    def __init__(self) -> None:
        self.calls = 0

    def retrieve(
        self,
        *,
        incident: Incident,
    ):
        self.calls += 1

        raise AssertionError(
            "Historical retrieval must not run after "
            "failed live diagnostics."
        )


def seed_historical_incident(
    *,
    store: SQLiteIncidentMemoryStore,
) -> Incident:
    historical = make_incident(
        fingerprint="historical-fingerprint"
    )

    store.record_investigation(
        incident=historical,
        selection=make_selection(),
    )

    store.finalize(
        incident_id=historical.incident_id,
        final_status=IncidentStatus.RESOLVED,
        resolution_summary=(
            "Processor recovered after an approved "
            "restart and verification."
        ),
    )

    return historical


def test_orchestrator_attaches_historical_context_without_polluting_live_evidence(
    tmp_path,
):
    store = SQLiteIncidentMemoryStore(
        tmp_path / "memory.db"
    )

    historical = seed_historical_incident(
        store=store
    )

    current = make_incident()

    collection = successful_collection(
        current
    )

    reasoner = FakeReasoner()

    orchestrator = (
        ConstrainedIncidentOrchestrator(
            collector=FakeCollector(
                collection
            ),
            reasoner=reasoner,
            incident_memory_retriever=(
                DeterministicIncidentMemoryRetriever(
                    store=store
                )
            ),
        )
    )

    result = orchestrator.investigate(
        incident=current
    )

    assert (
        result.historical_retrieval
        is not None
    )

    assert len(
        result.historical_retrieval.matches
    ) == 1

    assert len(
        result.historical_context
    ) == 1

    historical_context = (
        result.historical_context[0]
    )

    assert (
        reasoner.historical_context
        == result.historical_context
    )

    assert (
        reasoner.documentation_context
        == ()
    )

    assert (
        historical_context.historical_incident_id
        == historical.incident_id
    )

    assert (
        historical_context.current_state_authority
        is False
    )

    assert (
        historical_context.candidate_generation_authority
        is False
    )

    assert (
        historical_context.execution_authority
        is False
    )

    assert (
        historical_context.instruction_authority
        is False
    )

    # Historical context must never enter the collection of current
    # operational evidence.
    evidence_ids = {
        evidence.evidence_id
        for evidence in (
            result.evidence_collection.evidence
        )
    }

    assert evidence_ids == {
        "ev-prometheus",
        "ev-deployment",
    }

    assert (
        historical_context.context_id
        not in evidence_ids
    )

    # Deterministic candidates remain based entirely on current
    # operational evidence.
    assert reasoner.last_constraints is not None

    assert len(
        reasoner.last_constraints.candidates
    ) == 1

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


def test_orchestrator_without_memory_preserves_existing_behavior():
    current = make_incident()

    result = ConstrainedIncidentOrchestrator(
        collector=FakeCollector(
            successful_collection(
                current
            )
        ),
        reasoner=FakeReasoner(),
    ).investigate(
        incident=current
    )

    assert result.historical_retrieval is None
    assert result.historical_context == ()


def test_failed_live_diagnostics_block_historical_retrieval():
    current = make_incident()

    collection = successful_collection(
        current
    )

    collection.tool_calls.append(
        ToolCall(
            incident_id=current.incident_id,
            tool="test.failed",
            status=ToolCallStatus.FAILED,
            error="diagnostic unavailable",
        )
    )

    memory_retriever = (
        SpyMemoryRetriever()
    )

    orchestrator = (
        ConstrainedIncidentOrchestrator(
            collector=FakeCollector(
                collection
            ),
            reasoner=FakeReasoner(),
            incident_memory_retriever=(
                memory_retriever
            ),
        )
    )

    try:
        orchestrator.investigate(
            incident=current
        )
    except IncompleteEvidenceError:
        pass
    else:
        raise AssertionError(
            "Failed live diagnostics did not block "
            "the investigation."
        )

    assert memory_retriever.calls == 0
