"""Repeatable benchmark execution for FinStream AI-SRE."""

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
    EvidenceConstrainedReasoner,
)


@dataclass(frozen=True, slots=True)
class EvaluationRunCase:
    """Recorded outcome for one benchmark scenario."""

    scenario_id: str
    expected_decision: ExpectedDecision
    actual_decision: ExpectedDecision | None
    selected_candidate_ids: tuple[str, ...]
    evaluation: EvaluationCaseResult
    reasoner_error: str | None = None


@dataclass(frozen=True, slots=True)
class EvaluationRunMetrics:
    """Aggregate reliability metrics for one benchmark run."""

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
    reasoner_errors: int
    reasoner_error_rate: float
    constraint_violation_cases: int
    constraint_violation_rate: float


@dataclass(frozen=True, slots=True)
class EvaluationRunReport:
    """Complete benchmark output."""

    cases: tuple[EvaluationRunCase, ...]
    metrics: EvaluationRunMetrics


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


class EvaluationRunner:
    """Run FinStream scenarios through the constrained reasoner."""

    def __init__(
        self,
        *,
        reasoner: EvidenceConstrainedReasoner,
    ) -> None:
        self._reasoner = reasoner

    @staticmethod
    def _rate(
        numerator: int,
        denominator: int,
    ) -> float:
        if denominator == 0:
            return 0.0

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

    def run(
        self,
        *,
        fixtures: tuple[EvaluationFixture, ...],
    ) -> EvaluationRunReport:
        """Execute a complete deterministic evaluation corpus."""
        cases: list[EvaluationRunCase] = []

        selection_total = 0
        correct_selections = 0
        abstention_total = 0
        correct_abstentions = 0
        reasoner_errors = 0
        constraint_violation_cases = 0

        for fixture in fixtures:
            constraints = EvidenceConstraintBuilder.build(
                incident=fixture.incident,
                evidence=list(fixture.evidence),
            )

            expected = fixture.scenario.expectation

            if expected.decision is ExpectedDecision.SELECT:
                selection_total += 1
            else:
                abstention_total += 1

            try:
                selection = self._reasoner.select(
                    constraints=constraints,
                )
            except CandidateSelectionError as exc:
                reasoner_errors += 1

                result = EvaluationCaseResult(
                    scenario_id=fixture.scenario.scenario_id,
                    passed=False,
                    violations=(
                        f"Reasoner error: {type(exc).__name__}: {exc}",
                    ),
                )

                cases.append(
                    EvaluationRunCase(
                        scenario_id=(
                            fixture.scenario.scenario_id
                        ),
                        expected_decision=expected.decision,
                        actual_decision=None,
                        selected_candidate_ids=(),
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

            selected_ids = tuple(
                item.candidate_id
                for item in selection.selections
            )

            if expected.decision is ExpectedDecision.SELECT:
                if (
                    not selection.abstained
                    and selected_ids
                    == expected.expected_candidate_ids
                ):
                    correct_selections += 1

            else:
                if (
                    selection.abstained
                    and not selection.selections
                ):
                    correct_abstentions += 1

            result = AiSreEvaluator.evaluate(
                scenario=fixture.scenario,
                constraints=constraints,
                selection=selection,
            )

            if self._contains_constraint_violation(
                result
            ):
                constraint_violation_cases += 1

            cases.append(
                EvaluationRunCase(
                    scenario_id=(
                        fixture.scenario.scenario_id
                    ),
                    expected_decision=expected.decision,
                    actual_decision=actual_decision,
                    selected_candidate_ids=selected_ids,
                    evaluation=result,
                )
            )

        total = len(cases)

        passed = sum(
            case.evaluation.passed
            for case in cases
        )

        failed = total - passed

        metrics = EvaluationRunMetrics(
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

        return EvaluationRunReport(
            cases=tuple(cases),
            metrics=metrics,
        )
