"""Safe orchestration for FinStream evidence-constrained AI-SRE."""

from __future__ import annotations

from dataclasses import dataclass

from services.ai_sre_agent.investigation.evidence_collector import (
    EvidenceCollectionResult,
    EvidenceCollector,
)
from services.ai_sre_agent.memory import (
    DeterministicIncidentMemoryRetriever,
    HistoricalContextBuilder,
    HistoricalIncidentContext,
    HistoricalIncidentRetrievalResult,
)
from services.ai_sre_agent.models import (
    Evidence,
    Incident,
)
from services.ai_sre_agent.reasoning.constraints import (
    EvidenceConstraintBuilder,
    ReasoningConstraints,
)
from services.ai_sre_agent.reasoning.selector import (
    CandidateSelectionOutcome,
    EvidenceConstrainedReasoner,
)
from services.ai_sre_agent.retrieval import (
    DeterministicRunbookRetriever,
    RunbookContextBuilder,
    RunbookRetrievalResult,
)


class AiSreOrchestrationError(RuntimeError):
    """Base error for constrained AI-SRE orchestration."""


class IncompleteEvidenceError(
    AiSreOrchestrationError
):
    """Required diagnostics did not complete successfully."""


@dataclass(frozen=True, slots=True)
class ConstrainedInvestigationResult:
    """Complete result of one constrained AI-SRE investigation."""

    incident_id: str
    evidence_collection: EvidenceCollectionResult
    constraints: ReasoningConstraints
    selection: CandidateSelectionOutcome

    runbook_retrieval: (
        RunbookRetrievalResult | None
    ) = None

    documentation_context: tuple[
        Evidence,
        ...
    ] = ()

    historical_retrieval: (
        HistoricalIncidentRetrievalResult | None
    ) = None

    historical_context: tuple[
        HistoricalIncidentContext,
        ...
    ] = ()


class ConstrainedIncidentOrchestrator:
    """Run evidence collection and constrained AI reasoning safely."""

    def __init__(
        self,
        *,
        collector: EvidenceCollector,
        reasoner: EvidenceConstrainedReasoner,
        constraint_builder: type[
            EvidenceConstraintBuilder
        ] = EvidenceConstraintBuilder,
        runbook_retriever: (
            DeterministicRunbookRetriever | None
        ) = None,
        incident_memory_retriever: (
            DeterministicIncidentMemoryRetriever | None
        ) = None,
    ) -> None:
        self._collector = collector
        self._reasoner = reasoner
        self._constraint_builder = (
            constraint_builder
        )
        self._runbook_retriever = (
            runbook_retriever
        )
        self._incident_memory_retriever = (
            incident_memory_retriever
        )

    def investigate(
        self,
        *,
        incident: Incident,
    ) -> ConstrainedInvestigationResult:
        """Investigate one incident using guarded AI reasoning."""
        collection = self._collector.collect(
            incident=incident
        )

        if (
            collection.incident_id
            != incident.incident_id
        ):
            raise AiSreOrchestrationError(
                "Evidence collection returned a different "
                "incident ID."
            )

        if collection.failed_tool_calls:
            raise IncompleteEvidenceError(
                "AI reasoning blocked because "
                f"{collection.failed_tool_calls} diagnostic "
                "tool call(s) failed."
            )

        # Live operational evidence is converted into deterministic
        # reasoning constraints BEFORE historical context is retrieved.
        #
        # Historical memory therefore cannot create, remove, or modify
        # the candidate hypotheses produced from current observations.
        constraints = self._constraint_builder.build(
            incident=incident,
            evidence=collection.evidence,
        )

        historical_retrieval = None
        historical_context: tuple[
            HistoricalIncidentContext,
            ...
        ] = ()

        if (
            self._incident_memory_retriever
            is not None
        ):
            historical_retrieval = (
                self._incident_memory_retriever.retrieve(
                    incident=incident
                )
            )

            historical_bundle = (
                HistoricalContextBuilder.build(
                    incident=incident,
                    retrieval=(
                        historical_retrieval
                    ),
                )
            )

            historical_context = (
                historical_bundle.context
            )

        runbook_retrieval = None
        documentation_context: tuple[
            Evidence,
            ...
        ] = ()

        if self._runbook_retriever is not None:
            runbook_retrieval = (
                self._runbook_retriever.retrieve(
                    incident=incident
                )
            )

            context_bundle = (
                RunbookContextBuilder.build(
                    incident=incident,
                    retrieval=runbook_retrieval,
                )
            )

            documentation_context = (
                context_bundle.evidence
            )

        # Candidate generation is already complete before either
        # reference-only context channel reaches the model.
        #
        # documentation_context:
        #   approved procedural/reference information only.
        #
        # historical_context:
        #   finalized precedent only; never current-state evidence
        #   and never execution authority.
        selection = self._reasoner.select(
            constraints=constraints,
            documentation_context=(
                documentation_context
            ),
            historical_context=(
                historical_context
            ),
        )

        return ConstrainedInvestigationResult(
            incident_id=incident.incident_id,
            evidence_collection=collection,
            constraints=constraints,
            selection=selection,
            runbook_retrieval=runbook_retrieval,
            documentation_context=(
                documentation_context
            ),
            historical_retrieval=(
                historical_retrieval
            ),
            historical_context=(
                historical_context
            ),
        )
