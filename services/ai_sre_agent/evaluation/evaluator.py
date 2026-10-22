"""Deterministic evaluator for FinStream AI-SRE outcomes."""

from __future__ import annotations

from services.ai_sre_agent.evaluation.models import (
    EvaluationCaseResult,
    EvaluationScenario,
    EvaluationSuiteSummary,
    ExpectedDecision,
)
from services.ai_sre_agent.reasoning.constraints import (
    ReasoningConstraints,
)
from services.ai_sre_agent.reasoning.selector import (
    CandidateSelectionOutcome,
)


class AiSreEvaluator:
    """Measure constrained AI-SRE behaviour deterministically."""

    @staticmethod
    def evaluate(
        *,
        scenario: EvaluationScenario,
        constraints: ReasoningConstraints,
        selection: CandidateSelectionOutcome,
    ) -> EvaluationCaseResult:
        """Evaluate one constrained reasoning outcome."""
        violations: list[str] = []

        if constraints.affected_service != scenario.affected_service:
            violations.append(
                "Affected service does not match scenario."
            )

        expected = scenario.expectation

        candidate_index = {
            candidate.candidate_id: candidate
            for candidate in constraints.candidates
        }

        actual_candidate_ids = tuple(
            item.candidate_id
            for item in selection.selections
        )

        if expected.decision is ExpectedDecision.ABSTAIN:
            if not selection.abstained:
                violations.append(
                    "Expected safe abstention but model selected "
                    "a candidate."
                )

            if selection.selections:
                violations.append(
                    "Abstaining outcome unexpectedly contains "
                    "candidate selections."
                )

        else:
            if selection.abstained:
                violations.append(
                    "Expected candidate selection but model abstained."
                )

            if (
                actual_candidate_ids
                != expected.expected_candidate_ids
            ):
                violations.append(
                    "Selected candidate IDs do not match expected "
                    "candidate IDs."
                )

        ruled_out = set(
            constraints.ruled_out_subsystems
        )

        missing_ruled_out = (
            set(
                expected.required_ruled_out_subsystems
            )
            - ruled_out
        )

        if missing_ruled_out:
            violations.append(
                "Required healthy subsystems were not ruled out: "
                + ", ".join(
                    sorted(missing_ruled_out)
                )
            )

        forbidden_selected = (
            set(actual_candidate_ids)
            & set(expected.forbidden_candidate_ids)
        )

        if forbidden_selected:
            violations.append(
                "Forbidden candidate selected: "
                + ", ".join(
                    sorted(forbidden_selected)
                )
            )

        for selected in selection.selections:
            candidate = candidate_index.get(
                selected.candidate_id
            )

            if candidate is None:
                violations.append(
                    "Selection references candidate outside the "
                    "deterministic candidate set: "
                    f"{selected.candidate_id}"
                )
                continue

            if selected.statement != candidate.statement:
                violations.append(
                    "Selected candidate statement was modified: "
                    f"{selected.candidate_id}"
                )

            if (
                selected.supporting_evidence
                != candidate.supporting_evidence
            ):
                violations.append(
                    "Supporting evidence was modified: "
                    f"{selected.candidate_id}"
                )

            if (
                selected.contradicting_evidence
                != candidate.contradicting_evidence
            ):
                violations.append(
                    "Contradicting evidence was modified: "
                    f"{selected.candidate_id}"
                )

            if (
                selected.confidence
                > candidate.confidence_ceiling
            ):
                violations.append(
                    "Selected confidence exceeds deterministic "
                    "ceiling: "
                    f"{selected.candidate_id}"
                )

        return EvaluationCaseResult(
            scenario_id=scenario.scenario_id,
            passed=not violations,
            violations=tuple(violations),
        )

    @staticmethod
    def summarize(
        results: list[EvaluationCaseResult],
    ) -> EvaluationSuiteSummary:
        """Aggregate results from multiple evaluation scenarios."""
        total = len(results)

        passed = sum(
            1
            for result in results
            if result.passed
        )

        failed = total - passed

        pass_rate = (
            passed / total
            if total
            else 0.0
        )

        return EvaluationSuiteSummary(
            total=total,
            passed=passed,
            failed=failed,
            pass_rate=pass_rate,
        )
