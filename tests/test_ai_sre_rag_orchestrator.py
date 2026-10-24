from pathlib import Path

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
)
from services.ai_sre_agent.reasoning.selector import (
    CandidateSelectionOutcome,
)
from services.ai_sre_agent.retrieval import (
    DeterministicRunbookRetriever,
    RunbookCatalog,
)

ROOT = Path(__file__).resolve().parents[1]


class Collector:
    def __init__(self, result):
        self.result = result

    def collect(self, *, incident):
        return self.result


class RagAwareReasoner:
    def __init__(self):
        self.documentation_context = None

    def select(
        self,
        *,
        constraints,
        documentation_context=(),
    ):
        self.documentation_context = (
            documentation_context
        )

        return CandidateSelectionOutcome(
            selections=(),
            abstained=True,
            abstention_reason="test",
        )


def test_orchestrator_retrieves_runbooks_for_reasoning():
    incident = Incident(
        fingerprint="rag-orchestrator",
        alert_name="FinStreamServiceDown",
        alert_status=AlertStatus.FIRING,
        severity="critical",
        affected_service="processor",
        summary="Processor unavailable.",
    )

    evidence = [
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
                "desired_replicas": 1,
                "ready_replicas": 0,
                "available_replicas": 0,
                "healthy": False,
            },
            evidence_id="ev-kubernetes",
        ),
    ]

    collection = EvidenceCollectionResult(
        incident_id=incident.incident_id,
        service="processor",
        evidence=evidence,
        tool_calls=[
            ToolCall(
                incident_id=incident.incident_id,
                tool="prometheus",
                status=ToolCallStatus.SUCCESS,
                evidence_ids=["ev-prometheus"],
            ),
            ToolCall(
                incident_id=incident.incident_id,
                tool="kubernetes",
                status=ToolCallStatus.SUCCESS,
                evidence_ids=["ev-kubernetes"],
            ),
        ],
    )

    catalog = RunbookCatalog.load(
        repository_root=ROOT
    )

    retriever = DeterministicRunbookRetriever(
        catalog=catalog
    )

    reasoner = RagAwareReasoner()

    orchestrator = ConstrainedIncidentOrchestrator(
        collector=Collector(collection),
        reasoner=reasoner,
        runbook_retriever=retriever,
    )

    result = orchestrator.investigate(
        incident=incident
    )

    assert result.runbook_retrieval is not None
    assert result.runbook_retrieval.matches

    assert (
        result.runbook_retrieval
        .matches[0]
        .runbook_id
        == "RB-PROCESSOR-001"
    )

    assert result.documentation_context

    assert (
        result.documentation_context[0].source
        is EvidenceSource.RUNBOOK
    )

    assert (
        reasoner.documentation_context
        == result.documentation_context
    )

    operational_ids = {
        item.evidence_id
        for item in result.evidence_collection.evidence
    }

    documentation_ids = {
        item.evidence_id
        for item in result.documentation_context
    }

    assert operational_ids.isdisjoint(
        documentation_ids
    )
