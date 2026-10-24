"""End-to-end trusted-RAG evaluation for FinStream AI-SRE."""

from __future__ import annotations

from dataclasses import dataclass

from services.ai_sre_agent.evaluation.evaluator import (
    AiSreEvaluator,
)
from services.ai_sre_agent.evaluation.models import (
    EvaluationCaseResult,
    ExpectedDecision,
)
from services.ai_sre_agent.evaluation.scenarios import (
    EvaluationFixture,
)
from services.ai_sre_agent.reasoning.constraints import (
    EvidenceConstraintBuilder,
)
from services.ai_sre_agent.reasoning.selector import (
    CandidateSelectionError,
    CandidateSelectionOutcome,
    EvidenceConstrainedReasoner,
    RunbookCitation,
)
from services.ai_sre_agent.retrieval import (
    DeterministicRunbookRetriever,
    RunbookContextBuilder,
)


@dataclass(frozen=True, slots=True)
class RagEvaluationCase:
    """Recorded RAG outcome for one FinStream scenario."""

    scenario_id: str
    expected_decision: ExpectedDecision
    actual_decision: ExpectedDecision | None
    selected_candidate_ids: tuple[str, ...]

    retrieved_runbook_ids: tuple[str, ...]
    expected_top1_runbook_id: str | None
    actual_top1_runbook_id: str | None
    retrieval_top1_correct: bool | None

    documentation_context_ids: tuple[str, ...]
    citation_context_ids: tuple[str, ...]
    citation_runbook_ids: tuple[str, ...]
    citation_integrity: bool
    documentation_evidence_leak: bool

    evaluation: EvaluationCaseResult
    reasoner_error: str | None = None


@dataclass(frozen=True, slots=True)
class RagEvaluationMetrics:
    """Aggregate trusted-RAG benchmark metrics."""

    total: int
    passed: int
    failed: int
    pass_rate: float

    selection_total: int
    correct_selections: int
    selection_accuracy: float

    abstention_total: int
    correct_abstentions: int
    safe_abstention_rate: float

    retrieval_scored_cases: int
    retrieval_top1_correct: int
    retrieval_top1_accuracy: float

    citation_bearing_cases: int
    citation_total: int
    valid_citations: int
    citation_integrity_rate: float

    documentation_evidence_leak_cases: int
    documentation_evidence_leak_rate: float

    reasoner_errors: int
    reasoner_error_rate: float

    constraint_violation_cases: int
    constraint_violation_rate: float


@dataclass(frozen=True, slots=True)
class RagEvaluationReport:
    """Complete trusted-RAG benchmark report."""

    cases: tuple[RagEvaluationCase, ...]
    metrics: RagEvaluationMetrics


_CONSTRAINT_VIOLATION_MARKERS = (
    "Affected service does not match",
    "Required healthy subsystems were not ruled out",
    "Forbidden candidate selected",
    "outside the deterministic candidate set",
    "statement was modified",
    "Supporting evidence was modified",
    "Contradicting evidence was modified",
    "confidence exceeds",
)


class RagEvaluationRunner:
    """Evaluate retrieval, reasoning, citations, and safety."""

    def __init__(
        self,
        *,
        reasoner: EvidenceConstrainedReasoner,
        retriever: DeterministicRunbookRetriever,
        top_k: int = 3,
    ) -> None:
        if top_k < 1:
            raise ValueError(
                "RAG evaluation top_k must be at least 1."
            )

        self._reasoner = reasoner
        self._retriever = retriever
        self._top_k = top_k

    @staticmethod
    def _rate(
        numerator: int,
        denominator: int,
        *,
        zero_value: float = 0.0,
    ) -> float:
        if denominator == 0:
            return zero_value

        return numerator / denominator

    @staticmethod
    def _contains_constraint_violation(
        result: EvaluationCaseResult,
    ) -> bool:
        return any(
            marker in violation
            for violation in result.violations
            for marker in _CONSTRAINT_VIOLATION_MARKERS
        )

    @staticmethod
    def _citation_matches_context(
        *,
        citation: RunbookCitation,
        context_by_id: dict,
    ) -> bool:
        context = context_by_id.get(
            citation.context_id
        )

        if context is None:
            return False

        metadata = context.metadata

        return (
            citation.runbook_id
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
            == int(
                metadata.get(
                    "retrieval_score",
                    -1,
                )
            )
        )

    @classmethod
    def _citation_state(
        cls,
        *,
        selection: CandidateSelectionOutcome,
        documentation_context,
    ) -> tuple[
        tuple[str, ...],
        tuple[str, ...],
        int,
        int,
        bool,
    ]:
        context_by_id = {
            item.evidence_id: item
            for item in documentation_context
        }

        context_ids = set(
            context_by_id
        )

        citation_context_ids: list[str] = []
        citation_runbook_ids: list[str] = []

        citation_total = 0
        valid_citations = 0
        evidence_leak = False

        for selected in selection.selections:
            runtime_evidence = set(
                selected.supporting_evidence
            ) | set(
                selected.contradicting_evidence
            )

            if runtime_evidence & context_ids:
                evidence_leak = True

            for citation in selected.runbook_citations:
                citation_total += 1

                citation_context_ids.append(
                    citation.context_id
                )
                citation_runbook_ids.append(
                    citation.runbook_id
                )

                if cls._citation_matches_context(
                    citation=citation,
                    context_by_id=context_by_id,
                ):
                    valid_citations += 1

        return (
            tuple(citation_context_ids),
            tuple(citation_runbook_ids),
            citation_total,
            valid_citations,
            evidence_leak,
        )

    def run(
        self,
        *,
        fixtures: tuple[EvaluationFixture, ...],
        expected_top1_by_scenario: dict[str, str],
    ) -> RagEvaluationReport:
        """Execute the trusted-RAG benchmark corpus."""
        cases: list[RagEvaluationCase] = []

        selection_total = 0
        correct_selections = 0

        abstention_total = 0
        correct_abstentions = 0

        retrieval_scored_cases = 0
        retrieval_top1_correct = 0

        citation_bearing_cases = 0
        citation_total = 0
        valid_citations = 0

        documentation_evidence_leak_cases = 0

        reasoner_errors = 0
        constraint_violation_cases = 0

        for fixture in fixtures:
            scenario_id = (
                fixture.scenario.scenario_id
            )

            expected = (
                fixture.scenario.expectation
            )

            if expected.decision is ExpectedDecision.SELECT:
                selection_total += 1
            else:
                abstention_total += 1

            retrieval = self._retriever.retrieve(
                incident=fixture.incident,
                top_k=self._top_k,
            )

            retrieved_runbook_ids = tuple(
                match.runbook_id
                for match in retrieval.matches
            )

            actual_top1 = (
                retrieved_runbook_ids[0]
                if retrieved_runbook_ids
                else None
            )

            expected_top1 = (
                expected_top1_by_scenario.get(
                    scenario_id
                )
            )

            retrieval_correct: bool | None = None

            if expected_top1 is not None:
                retrieval_scored_cases += 1

                retrieval_correct = (
                    actual_top1
                    == expected_top1
                )

                if retrieval_correct:
                    retrieval_top1_correct += 1

            context_bundle = (
                RunbookContextBuilder.build(
                    incident=fixture.incident,
                    retrieval=retrieval,
                )
            )

            documentation_context = (
                context_bundle.evidence
            )

            documentation_context_ids = tuple(
                item.evidence_id
                for item in documentation_context
            )

            constraints = (
                EvidenceConstraintBuilder.build(
                    incident=fixture.incident,
                    evidence=list(
                        fixture.evidence
                    ),
                )
            )

            try:
                selection = self._reasoner.select(
                    constraints=constraints,
                    documentation_context=(
                        documentation_context
                    ),
                )
            except CandidateSelectionError as exc:
                reasoner_errors += 1

                violations = [
                    (
                        "Reasoner error: "
                        f"{type(exc).__name__}: {exc}"
                    )
                ]

                if retrieval_correct is False:
                    violations.append(
                        "Top-1 retrieval mismatch: "
                        f"expected {expected_top1}, "
                        f"got {actual_top1}."
                    )

                result = EvaluationCaseResult(
                    scenario_id=scenario_id,
                    passed=False,
                    violations=tuple(violations),
                )

                cases.append(
                    RagEvaluationCase(
                        scenario_id=scenario_id,
                        expected_decision=(
                            expected.decision
                        ),
                        actual_decision=None,
                        selected_candidate_ids=(),
                        retrieved_runbook_ids=(
                            retrieved_runbook_ids
                        ),
                        expected_top1_runbook_id=(
                            expected_top1
                        ),
                        actual_top1_runbook_id=(
                            actual_top1
                        ),
                        retrieval_top1_correct=(
                            retrieval_correct
                        ),
                        documentation_context_ids=(
                            documentation_context_ids
                        ),
                        citation_context_ids=(),
                        citation_runbook_ids=(),
                        citation_integrity=True,
                        documentation_evidence_leak=(
                            False
                        ),
                        evaluation=result,
                        reasoner_error=str(exc),
                    )
                )

                continue

            actual_decision = (
                ExpectedDecision.ABSTAIN
                if selection.abstained
                else ExpectedDecision.SELECT
            )

            selected_candidate_ids = tuple(
                selected.candidate_id
                for selected in selection.selections
            )

            if expected.decision is ExpectedDecision.SELECT:
                if (
                    not selection.abstained
                    and selected_candidate_ids
                    == expected.expected_candidate_ids
                ):
                    correct_selections += 1
            elif (
                selection.abstained
                and not selection.selections
            ):
                correct_abstentions += 1

            base_result = AiSreEvaluator.evaluate(
                scenario=fixture.scenario,
                constraints=constraints,
                selection=selection,
            )

            if self._contains_constraint_violation(
                base_result
            ):
                constraint_violation_cases += 1

            (
                citation_context_ids,
                citation_runbook_ids,
                case_citation_total,
                case_valid_citations,
                documentation_evidence_leak,
            ) = self._citation_state(
                selection=selection,
                documentation_context=(
                    documentation_context
                ),
            )

            citation_total += (
                case_citation_total
            )
            valid_citations += (
                case_valid_citations
            )

            if case_citation_total:
                citation_bearing_cases += 1

            citation_integrity = (
                case_citation_total
                == case_valid_citations
            )

            if documentation_evidence_leak:
                documentation_evidence_leak_cases += 1

            violations = list(
                base_result.violations
            )

            if retrieval_correct is False:
                violations.append(
                    "Top-1 retrieval mismatch: "
                    f"expected {expected_top1}, "
                    f"got {actual_top1}."
                )

            if not citation_integrity:
                violations.append(
                    "One or more runbook citations "
                    "failed trusted provenance binding."
                )

            if documentation_evidence_leak:
                violations.append(
                    "Documentation context leaked into "
                    "runtime evidence."
                )

            passed = (
                base_result.passed
                and retrieval_correct is not False
                and citation_integrity
                and not documentation_evidence_leak
            )

            result = EvaluationCaseResult(
                scenario_id=scenario_id,
                passed=passed,
                violations=tuple(violations),
            )

            cases.append(
                RagEvaluationCase(
                    scenario_id=scenario_id,
                    expected_decision=(
                        expected.decision
                    ),
                    actual_decision=(
                        actual_decision
                    ),
                    selected_candidate_ids=(
                        selected_candidate_ids
                    ),
                    retrieved_runbook_ids=(
                        retrieved_runbook_ids
                    ),
                    expected_top1_runbook_id=(
                        expected_top1
                    ),
                    actual_top1_runbook_id=(
                        actual_top1
                    ),
                    retrieval_top1_correct=(
                        retrieval_correct
                    ),
                    documentation_context_ids=(
                        documentation_context_ids
                    ),
                    citation_context_ids=(
                        citation_context_ids
                    ),
                    citation_runbook_ids=(
                        citation_runbook_ids
                    ),
                    citation_integrity=(
                        citation_integrity
                    ),
                    documentation_evidence_leak=(
                        documentation_evidence_leak
                    ),
                    evaluation=result,
                )
            )

        total = len(cases)

        passed = sum(
            case.evaluation.passed
            for case in cases
        )

        failed = total - passed

        metrics = RagEvaluationMetrics(
            total=total,
            passed=passed,
            failed=failed,
            pass_rate=self._rate(
                passed,
                total,
            ),
            selection_total=selection_total,
            correct_selections=correct_selections,
            selection_accuracy=self._rate(
                correct_selections,
                selection_total,
            ),
            abstention_total=abstention_total,
            correct_abstentions=correct_abstentions,
            safe_abstention_rate=self._rate(
                correct_abstentions,
                abstention_total,
            ),
            retrieval_scored_cases=(
                retrieval_scored_cases
            ),
            retrieval_top1_correct=(
                retrieval_top1_correct
            ),
            retrieval_top1_accuracy=self._rate(
                retrieval_top1_correct,
                retrieval_scored_cases,
            ),
            citation_bearing_cases=(
                citation_bearing_cases
            ),
            citation_total=citation_total,
            valid_citations=valid_citations,
            citation_integrity_rate=self._rate(
                valid_citations,
                citation_total,
                zero_value=1.0,
            ),
            documentation_evidence_leak_cases=(
                documentation_evidence_leak_cases
            ),
            documentation_evidence_leak_rate=(
                self._rate(
                    documentation_evidence_leak_cases,
                    total,
                )
            ),
            reasoner_errors=reasoner_errors,
            reasoner_error_rate=self._rate(
                reasoner_errors,
                total,
            ),
            constraint_violation_cases=(
                constraint_violation_cases
            ),
            constraint_violation_rate=self._rate(
                constraint_violation_cases,
                total,
            ),
        )

        return RagEvaluationReport(
            cases=tuple(cases),
            metrics=metrics,
        )
