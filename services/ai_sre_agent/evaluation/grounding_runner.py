"""Combined RAG + historical-memory evaluation for FinStream AI-SRE."""

from __future__ import annotations

from dataclasses import dataclass

from services.ai_sre_agent.evaluation.evaluator import (
    AiSreEvaluator,
)
from services.ai_sre_agent.evaluation.grounding import (
    GroundingMode,
)
from services.ai_sre_agent.evaluation.grounding_scenarios import (
    GroundingBenchmarkScenario,
)
from services.ai_sre_agent.evaluation.models import (
    EvaluationCaseResult,
    ExpectedDecision,
)
from services.ai_sre_agent.memory import (
    DeterministicIncidentMemoryRetriever,
    HistoricalContextBuilder,
    HistoricalIncidentContext,
)
from services.ai_sre_agent.models import Evidence
from services.ai_sre_agent.reasoning.constraints import (
    EvidenceConstraintBuilder,
)
from services.ai_sre_agent.reasoning.selector import (
    CandidateSelectionError,
    CandidateSelectionOutcome,
    EvidenceConstrainedReasoner,
    HistoricalIncidentCitation,
    RunbookCitation,
)
from services.ai_sre_agent.retrieval import (
    DeterministicRunbookRetriever,
    RunbookContextBuilder,
)


@dataclass(frozen=True, slots=True)
class GroundingEvaluationCase:
    """One combined-grounding benchmark result."""

    scenario_id: str
    mode: GroundingMode

    expected_decision: ExpectedDecision
    actual_decision: ExpectedDecision | None
    selected_candidate_ids: tuple[str, ...]

    retrieved_runbook_ids: tuple[str, ...]
    expected_runbook_top1_id: str | None
    actual_runbook_top1_id: str | None
    runbook_top1_correct: bool | None

    retrieved_historical_incident_ids: tuple[str, ...]
    expected_historical_top1_incident_id: str | None
    actual_historical_top1_incident_id: str | None
    historical_top1_correct: bool | None

    documentation_context_ids: tuple[str, ...]
    historical_context_ids: tuple[str, ...]

    runbook_citation_context_ids: tuple[str, ...]
    historical_citation_context_ids: tuple[str, ...]

    runbook_citation_integrity: bool
    historical_citation_integrity: bool

    documentation_evidence_leak: bool
    historical_evidence_leak: bool
    cross_namespace_citation_violation: bool

    evaluation: EvaluationCaseResult
    reasoner_error: str | None = None


@dataclass(frozen=True, slots=True)
class GroundingEvaluationMetrics:
    """Aggregate quality metrics for combined grounding evaluation."""

    mode: GroundingMode | None

    total_cases: int
    passed_cases: int
    failed_cases: int

    pass_rate: float
    decision_accuracy: float

    selection_accuracy: float | None
    safe_abstention_accuracy: float | None

    runbook_top1_accuracy: float | None
    historical_top1_accuracy: float | None

    runbook_citation_integrity_rate: float | None
    historical_citation_integrity_rate: float | None

    documentation_evidence_leaks: int
    historical_evidence_leaks: int
    cross_namespace_citation_violations: int

    reasoner_errors: int


@dataclass(frozen=True, slots=True)
class GroundingEvaluationReport:
    """Complete comparative multi-source grounding benchmark."""

    cases: tuple[GroundingEvaluationCase, ...]
    overall: GroundingEvaluationMetrics
    mode_metrics: tuple[GroundingEvaluationMetrics, ...]

    def metrics_for(
        self,
        mode: GroundingMode,
    ) -> GroundingEvaluationMetrics:
        """Return metrics for one grounding mode."""
        for metrics in self.mode_metrics:
            if metrics.mode is mode:
                return metrics

        raise KeyError(
            f"No metrics found for grounding mode {mode.value}."
        )


class GroundingEvaluationRunner:
    """Evaluate FinStream across configurable grounding channels."""

    def __init__(
        self,
        *,
        reasoner: EvidenceConstrainedReasoner,
        runbook_retriever: (
            DeterministicRunbookRetriever | None
        ) = None,
        incident_memory_retriever: (
            DeterministicIncidentMemoryRetriever | None
        ) = None,
        top_k: int = 3,
    ) -> None:
        if top_k < 1:
            raise ValueError(
                "Grounding evaluation top_k must be at least 1."
            )

        self._reasoner = reasoner
        self._runbook_retriever = runbook_retriever
        self._incident_memory_retriever = (
            incident_memory_retriever
        )
        self._top_k = top_k

    @staticmethod
    def _runbook_citation_matches(
        *,
        citation: RunbookCitation,
        context: Evidence,
    ) -> bool:
        metadata = context.metadata

        return (
            citation.context_id
            == context.evidence_id
            and citation.runbook_id
            == metadata.get("runbook_id")
            and citation.title
            == metadata.get("title")
            and citation.version
            == metadata.get("version")
            and citation.sha256
            == metadata.get("sha256")
            and citation.path
            == metadata.get("path")
            and citation.raw_reference
            == (context.raw_reference or "")
            and citation.retrieval_score
            == metadata.get("retrieval_score")
        )

    @staticmethod
    def _historical_citation_matches(
        *,
        citation: HistoricalIncidentCitation,
        context: HistoricalIncidentContext,
    ) -> bool:
        return (
            citation.context_id
            == context.context_id
            and citation.memory_id
            == context.memory_id
            and citation.historical_incident_id
            == context.historical_incident_id
            and citation.alert_name
            == context.alert_name
            and citation.affected_service
            == context.affected_service
            and citation.final_status
            == context.final_status.value
            and citation.finalized_at
            == context.finalized_at.isoformat()
            and citation.retrieval_score
            == context.retrieval_score
        )

    @classmethod
    def _citation_state(
        cls,
        *,
        selection: CandidateSelectionOutcome,
        documentation_context: tuple[Evidence, ...],
        historical_context: tuple[
            HistoricalIncidentContext,
            ...,
        ],
    ) -> tuple[
        tuple[str, ...],
        tuple[str, ...],
        bool,
        bool,
        bool,
        bool,
        bool,
    ]:
        documentation_by_id = {
            item.evidence_id: item
            for item in documentation_context
        }

        historical_by_id = {
            item.context_id: item
            for item in historical_context
        }

        documentation_ids = set(
            documentation_by_id
        )

        historical_ids = set(
            historical_by_id
        )

        runbook_citation_ids: list[str] = []
        historical_citation_ids: list[str] = []

        runbook_total = 0
        valid_runbook = 0

        historical_total = 0
        valid_historical = 0

        documentation_evidence_leak = False
        historical_evidence_leak = False
        cross_namespace_violation = False

        for selected in selection.selections:
            runtime_evidence = set(
                selected.supporting_evidence
            ) | set(
                selected.contradicting_evidence
            )

            if runtime_evidence & documentation_ids:
                documentation_evidence_leak = True

            if runtime_evidence & historical_ids:
                historical_evidence_leak = True

            for citation in selected.runbook_citations:
                runbook_total += 1

                runbook_citation_ids.append(
                    citation.context_id
                )

                if citation.context_id in historical_ids:
                    cross_namespace_violation = True

                context = documentation_by_id.get(
                    citation.context_id
                )

                if (
                    context is not None
                    and cls._runbook_citation_matches(
                        citation=citation,
                        context=context,
                    )
                ):
                    valid_runbook += 1

            for citation in (
                selected.historical_incident_citations
            ):
                historical_total += 1

                historical_citation_ids.append(
                    citation.context_id
                )

                if citation.context_id in documentation_ids:
                    cross_namespace_violation = True

                context = historical_by_id.get(
                    citation.context_id
                )

                if (
                    context is not None
                    and cls._historical_citation_matches(
                        citation=citation,
                        context=context,
                    )
                ):
                    valid_historical += 1

        return (
            tuple(runbook_citation_ids),
            tuple(historical_citation_ids),
            runbook_total == valid_runbook,
            historical_total == valid_historical,
            documentation_evidence_leak,
            historical_evidence_leak,
            cross_namespace_violation,
        )

    @staticmethod
    def _accuracy(
        values: list[bool],
    ) -> float | None:
        """Return boolean accuracy or None when unscored."""
        if not values:
            return None

        return (
            sum(1 for value in values if value)
            / len(values)
        )

    @classmethod
    def _build_metrics(
        cls,
        *,
        cases: tuple[GroundingEvaluationCase, ...],
        scenarios: dict[str, GroundingBenchmarkScenario],
        mode: GroundingMode | None,
    ) -> GroundingEvaluationMetrics:
        """Aggregate evaluation cases into benchmark metrics."""
        if not cases:
            raise ValueError(
                "Cannot build grounding metrics from zero cases."
            )

        passed_cases = sum(
            1
            for case in cases
            if case.evaluation.passed
        )

        decision_matches = [
            (
                case.actual_decision
                is case.expected_decision
            )
            for case in cases
        ]

        selection_matches: list[bool] = []
        abstention_matches: list[bool] = []

        for case in cases:
            if case.expected_decision is ExpectedDecision.SELECT:
                scenario = scenarios[
                    case.scenario_id
                ]

                expected_candidate_ids = (
                    scenario
                    .make_fixture()
                    .scenario
                    .expectation
                    .expected_candidate_ids
                )

                selection_matches.append(
                    (
                        case.actual_decision
                        is ExpectedDecision.SELECT
                    )
                    and (
                        case.selected_candidate_ids
                        == expected_candidate_ids
                    )
                )

            else:
                abstention_matches.append(
                    (
                        case.actual_decision
                        is ExpectedDecision.ABSTAIN
                    )
                    and not case.selected_candidate_ids
                )

        runbook_top1 = [
            case.runbook_top1_correct
            for case in cases
            if case.runbook_top1_correct is not None
        ]

        historical_top1 = [
            case.historical_top1_correct
            for case in cases
            if case.historical_top1_correct is not None
        ]

        runbook_integrity = [
            case.runbook_citation_integrity
            for case in cases
            if case.mode.uses_runbooks
        ]

        historical_integrity = [
            case.historical_citation_integrity
            for case in cases
            if case.mode.uses_history
        ]

        return GroundingEvaluationMetrics(
            mode=mode,
            total_cases=len(cases),
            passed_cases=passed_cases,
            failed_cases=(
                len(cases) - passed_cases
            ),
            pass_rate=(
                passed_cases / len(cases)
            ),
            decision_accuracy=(
                sum(
                    1
                    for matched in decision_matches
                    if matched
                )
                / len(decision_matches)
            ),
            selection_accuracy=cls._accuracy(
                selection_matches
            ),
            safe_abstention_accuracy=cls._accuracy(
                abstention_matches
            ),
            runbook_top1_accuracy=cls._accuracy(
                runbook_top1
            ),
            historical_top1_accuracy=cls._accuracy(
                historical_top1
            ),
            runbook_citation_integrity_rate=(
                cls._accuracy(
                    runbook_integrity
                )
            ),
            historical_citation_integrity_rate=(
                cls._accuracy(
                    historical_integrity
                )
            ),
            documentation_evidence_leaks=sum(
                1
                for case in cases
                if case.documentation_evidence_leak
            ),
            historical_evidence_leaks=sum(
                1
                for case in cases
                if case.historical_evidence_leak
            ),
            cross_namespace_citation_violations=sum(
                1
                for case in cases
                if (
                    case
                    .cross_namespace_citation_violation
                )
            ),
            reasoner_errors=sum(
                1
                for case in cases
                if case.reasoner_error is not None
            ),
        )

    def run_suite(
        self,
        *,
        scenarios: tuple[
            GroundingBenchmarkScenario,
            ...,
        ],
        modes: tuple[GroundingMode, ...] = tuple(
            GroundingMode
        ),
    ) -> GroundingEvaluationReport:
        """Run every scenario across requested grounding modes."""
        if not scenarios:
            raise ValueError(
                "Grounding evaluation requires scenarios."
            )

        if not modes:
            raise ValueError(
                "Grounding evaluation requires modes."
            )

        scenario_map = {
            scenario.scenario_id: scenario
            for scenario in scenarios
        }

        if len(scenario_map) != len(scenarios):
            raise ValueError(
                "Grounding scenario IDs must be unique."
            )

        cases = tuple(
            self.run_case(
                scenario=scenario,
                mode=mode,
            )
            for mode in modes
            for scenario in scenarios
        )

        overall = self._build_metrics(
            cases=cases,
            scenarios=scenario_map,
            mode=None,
        )

        mode_metrics = tuple(
            self._build_metrics(
                cases=tuple(
                    case
                    for case in cases
                    if case.mode is mode
                ),
                scenarios=scenario_map,
                mode=mode,
            )
            for mode in modes
        )

        return GroundingEvaluationReport(
            cases=cases,
            overall=overall,
            mode_metrics=mode_metrics,
        )

    def run_case(
        self,
        *,
        scenario: GroundingBenchmarkScenario,
        mode: GroundingMode,
    ) -> GroundingEvaluationCase:
        """Run one scenario through one grounding mode."""
        fixture = scenario.make_fixture()

        expected = fixture.scenario.expectation

        grounding_expectation = (
            scenario.expectation_for(
                mode=mode
            )
        )

        constraints = EvidenceConstraintBuilder.build(
            incident=fixture.incident,
            evidence=list(
                fixture.evidence
            ),
        )

        retrieved_runbook_ids: tuple[str, ...] = ()
        documentation_context: tuple[Evidence, ...] = ()

        actual_runbook_top1: str | None = None
        runbook_top1_correct: bool | None = None

        if mode.uses_runbooks:
            if self._runbook_retriever is None:
                raise ValueError(
                    "Grounding mode requires a "
                    "runbook retriever."
                )

            retrieval = self._runbook_retriever.retrieve(
                incident=fixture.incident,
                top_k=self._top_k,
            )

            retrieved_runbook_ids = tuple(
                match.runbook_id
                for match in retrieval.matches
            )

            actual_runbook_top1 = (
                retrieved_runbook_ids[0]
                if retrieved_runbook_ids
                else None
            )

            if (
                grounding_expectation
                .expected_runbook_top1_id
                is not None
            ):
                runbook_top1_correct = (
                    actual_runbook_top1
                    == grounding_expectation
                    .expected_runbook_top1_id
                )

            documentation_context = (
                RunbookContextBuilder.build(
                    incident=fixture.incident,
                    retrieval=retrieval,
                ).evidence
            )

        retrieved_historical_ids: tuple[
            str,
            ...,
        ] = ()

        historical_context: tuple[
            HistoricalIncidentContext,
            ...,
        ] = ()

        actual_historical_top1: str | None = None
        historical_top1_correct: bool | None = None

        if mode.uses_history:
            if self._incident_memory_retriever is None:
                raise ValueError(
                    "Grounding mode requires an "
                    "incident-memory retriever."
                )

            historical_retrieval = (
                self._incident_memory_retriever.retrieve(
                    incident=fixture.incident,
                    top_k=self._top_k,
                )
            )

            retrieved_historical_ids = tuple(
                match.incident_id
                for match in historical_retrieval.matches
            )

            actual_historical_top1 = (
                retrieved_historical_ids[0]
                if retrieved_historical_ids
                else None
            )

            if (
                grounding_expectation
                .expected_historical_top1_incident_id
                is not None
            ):
                historical_top1_correct = (
                    actual_historical_top1
                    == grounding_expectation
                    .expected_historical_top1_incident_id
                )

            historical_context = (
                HistoricalContextBuilder.build(
                    incident=fixture.incident,
                    retrieval=historical_retrieval,
                ).context
            )

        documentation_context_ids = tuple(
            item.evidence_id
            for item in documentation_context
        )

        historical_context_ids = tuple(
            item.context_id
            for item in historical_context
        )

        try:
            selection = self._reasoner.select(
                constraints=constraints,
                documentation_context=documentation_context,
                historical_context=historical_context,
            )

        except CandidateSelectionError as exc:
            violations = [
                (
                    "Reasoner error: "
                    f"{type(exc).__name__}: {exc}"
                )
            ]

            if runbook_top1_correct is False:
                violations.append(
                    "Runbook top-1 retrieval mismatch."
                )

            if historical_top1_correct is False:
                violations.append(
                    "Historical top-1 retrieval mismatch."
                )

            result = EvaluationCaseResult(
                scenario_id=fixture.scenario.scenario_id,
                passed=False,
                violations=tuple(violations),
            )

            return GroundingEvaluationCase(
                scenario_id=fixture.scenario.scenario_id,
                mode=mode,
                expected_decision=expected.decision,
                actual_decision=None,
                selected_candidate_ids=(),
                retrieved_runbook_ids=(
                    retrieved_runbook_ids
                ),
                expected_runbook_top1_id=(
                    grounding_expectation
                    .expected_runbook_top1_id
                ),
                actual_runbook_top1_id=(
                    actual_runbook_top1
                ),
                runbook_top1_correct=(
                    runbook_top1_correct
                ),
                retrieved_historical_incident_ids=(
                    retrieved_historical_ids
                ),
                expected_historical_top1_incident_id=(
                    grounding_expectation
                    .expected_historical_top1_incident_id
                ),
                actual_historical_top1_incident_id=(
                    actual_historical_top1
                ),
                historical_top1_correct=(
                    historical_top1_correct
                ),
                documentation_context_ids=(
                    documentation_context_ids
                ),
                historical_context_ids=(
                    historical_context_ids
                ),
                runbook_citation_context_ids=(),
                historical_citation_context_ids=(),
                runbook_citation_integrity=True,
                historical_citation_integrity=True,
                documentation_evidence_leak=False,
                historical_evidence_leak=False,
                cross_namespace_citation_violation=False,
                evaluation=result,
                reasoner_error=str(exc),
            )

        actual_decision = (
            ExpectedDecision.ABSTAIN
            if selection.abstained
            else ExpectedDecision.SELECT
        )

        selected_candidate_ids = tuple(
            item.candidate_id
            for item in selection.selections
        )

        base_result = AiSreEvaluator.evaluate(
            scenario=fixture.scenario,
            constraints=constraints,
            selection=selection,
        )

        (
            runbook_citation_context_ids,
            historical_citation_context_ids,
            runbook_citation_integrity,
            historical_citation_integrity,
            documentation_evidence_leak,
            historical_evidence_leak,
            cross_namespace_violation,
        ) = self._citation_state(
            selection=selection,
            documentation_context=documentation_context,
            historical_context=historical_context,
        )

        violations = list(
            base_result.violations
        )

        if runbook_top1_correct is False:
            violations.append(
                "Runbook top-1 retrieval mismatch."
            )

        if historical_top1_correct is False:
            violations.append(
                "Historical top-1 retrieval mismatch."
            )

        if not runbook_citation_integrity:
            violations.append(
                "Runbook citation provenance validation failed."
            )

        if not historical_citation_integrity:
            violations.append(
                "Historical citation provenance validation failed."
            )

        if documentation_evidence_leak:
            violations.append(
                "Documentation context leaked into "
                "runtime evidence."
            )

        if historical_evidence_leak:
            violations.append(
                "Historical context leaked into "
                "runtime evidence."
            )

        if cross_namespace_violation:
            violations.append(
                "Documentation and historical citation "
                "namespaces were crossed."
            )

        passed = (
            base_result.passed
            and runbook_top1_correct is not False
            and historical_top1_correct is not False
            and runbook_citation_integrity
            and historical_citation_integrity
            and not documentation_evidence_leak
            and not historical_evidence_leak
            and not cross_namespace_violation
        )

        result = EvaluationCaseResult(
            scenario_id=fixture.scenario.scenario_id,
            passed=passed,
            violations=tuple(violations),
        )

        return GroundingEvaluationCase(
            scenario_id=fixture.scenario.scenario_id,
            mode=mode,
            expected_decision=expected.decision,
            actual_decision=actual_decision,
            selected_candidate_ids=(
                selected_candidate_ids
            ),
            retrieved_runbook_ids=(
                retrieved_runbook_ids
            ),
            expected_runbook_top1_id=(
                grounding_expectation
                .expected_runbook_top1_id
            ),
            actual_runbook_top1_id=(
                actual_runbook_top1
            ),
            runbook_top1_correct=(
                runbook_top1_correct
            ),
            retrieved_historical_incident_ids=(
                retrieved_historical_ids
            ),
            expected_historical_top1_incident_id=(
                grounding_expectation
                .expected_historical_top1_incident_id
            ),
            actual_historical_top1_incident_id=(
                actual_historical_top1
            ),
            historical_top1_correct=(
                historical_top1_correct
            ),
            documentation_context_ids=(
                documentation_context_ids
            ),
            historical_context_ids=(
                historical_context_ids
            ),
            runbook_citation_context_ids=(
                runbook_citation_context_ids
            ),
            historical_citation_context_ids=(
                historical_citation_context_ids
            ),
            runbook_citation_integrity=(
                runbook_citation_integrity
            ),
            historical_citation_integrity=(
                historical_citation_integrity
            ),
            documentation_evidence_leak=(
                documentation_evidence_leak
            ),
            historical_evidence_leak=(
                historical_evidence_leak
            ),
            cross_namespace_citation_violation=(
                cross_namespace_violation
            ),
            evaluation=result,
        )
