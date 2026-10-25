"""Persistent evidence reporting for FinStream trusted-RAG benchmarks."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

from services.ai_sre_agent.evaluation.rag_runner import (
    RagEvaluationReport,
)


@dataclass(frozen=True, slots=True)
class RepeatedRagBenchmarkReport:
    """Aggregate repeated trusted-RAG benchmark executions."""

    model: str
    reports: tuple[RagEvaluationReport, ...]

    def __post_init__(self) -> None:
        if not self.model.strip():
            raise ValueError(
                "Benchmark model name must not be blank."
            )

        if not self.reports:
            raise ValueError(
                "At least one RAG evaluation report is required."
            )

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

    def aggregate_metrics(
        self,
    ) -> dict[str, int | float]:
        """Calculate aggregate metrics across repeated runs."""
        metrics = [
            report.metrics
            for report in self.reports
        ]

        total = sum(
            item.total
            for item in metrics
        )

        passed = sum(
            item.passed
            for item in metrics
        )

        failed = sum(
            item.failed
            for item in metrics
        )

        selection_total = sum(
            item.selection_total
            for item in metrics
        )

        correct_selections = sum(
            item.correct_selections
            for item in metrics
        )

        abstention_total = sum(
            item.abstention_total
            for item in metrics
        )

        correct_abstentions = sum(
            item.correct_abstentions
            for item in metrics
        )

        retrieval_scored_cases = sum(
            item.retrieval_scored_cases
            for item in metrics
        )

        retrieval_top1_correct = sum(
            item.retrieval_top1_correct
            for item in metrics
        )

        citation_total = sum(
            item.citation_total
            for item in metrics
        )

        valid_citations = sum(
            item.valid_citations
            for item in metrics
        )

        evidence_leaks = sum(
            item.documentation_evidence_leak_cases
            for item in metrics
        )

        constraint_violations = sum(
            item.constraint_violation_cases
            for item in metrics
        )

        reasoner_errors = sum(
            item.reasoner_errors
            for item in metrics
        )

        return {
            "benchmark_runs": len(self.reports),
            "scenario_evaluations": total,
            "passed": passed,
            "failed": failed,
            "overall_pass_rate": self._rate(
                passed,
                total,
            ),
            "selection_total": selection_total,
            "correct_selections": correct_selections,
            "selection_accuracy": self._rate(
                correct_selections,
                selection_total,
            ),
            "abstention_total": abstention_total,
            "correct_abstentions": correct_abstentions,
            "safe_abstention_rate": self._rate(
                correct_abstentions,
                abstention_total,
            ),
            "retrieval_scored_cases": (
                retrieval_scored_cases
            ),
            "retrieval_top1_correct": (
                retrieval_top1_correct
            ),
            "retrieval_top1_accuracy": self._rate(
                retrieval_top1_correct,
                retrieval_scored_cases,
            ),
            "citation_total": citation_total,
            "valid_citations": valid_citations,
            "citation_integrity_rate": self._rate(
                valid_citations,
                citation_total,
                zero_value=1.0,
            ),
            "documentation_evidence_leaks": (
                evidence_leaks
            ),
            "constraint_violation_cases": (
                constraint_violations
            ),
            "reasoner_errors": reasoner_errors,
        }

    def to_dict(self) -> dict:
        """Return the complete benchmark evidence document."""
        runs = []

        for run_number, report in enumerate(
            self.reports,
            start=1,
        ):
            cases = []

            for case in report.cases:
                cases.append(
                    {
                        "scenario_id": case.scenario_id,
                        "expected_decision": (
                            case.expected_decision.value
                        ),
                        "actual_decision": (
                            case.actual_decision.value
                            if case.actual_decision
                            else None
                        ),
                        "selected_candidate_ids": list(
                            case.selected_candidate_ids
                        ),
                        "retrieved_runbook_ids": list(
                            case.retrieved_runbook_ids
                        ),
                        "expected_top1_runbook_id": (
                            case.expected_top1_runbook_id
                        ),
                        "actual_top1_runbook_id": (
                            case.actual_top1_runbook_id
                        ),
                        "retrieval_top1_correct": (
                            case.retrieval_top1_correct
                        ),
                        "citation_runbook_ids": list(
                            case.citation_runbook_ids
                        ),
                        "citation_integrity": (
                            case.citation_integrity
                        ),
                        "documentation_evidence_leak": (
                            case.documentation_evidence_leak
                        ),
                        "passed": (
                            case.evaluation.passed
                        ),
                        "violations": list(
                            case.evaluation.violations
                        ),
                        "reasoner_error": (
                            case.reasoner_error
                        ),
                    }
                )

            runs.append(
                {
                    "run_number": run_number,
                    "metrics": asdict(
                        report.metrics
                    ),
                    "cases": cases,
                }
            )

        return {
            "schema_version": "1.0",
            "benchmark": (
                "FinStream AI-SRE trusted RAG"
            ),
            "model": self.model,
            "aggregate": self.aggregate_metrics(),
            "runs": runs,
        }

    def to_json(self) -> str:
        """Render benchmark evidence as stable JSON."""
        return json.dumps(
            self.to_dict(),
            indent=2,
            sort_keys=True,
        ) + "\n"

    def to_markdown(self) -> str:
        """Render a recruiter-readable benchmark report."""
        aggregate = self.aggregate_metrics()

        lines = [
            "# FinStream AI-SRE Trusted RAG Benchmark",
            "",
            f"**Model:** `{self.model}`",
            "",
            "## Aggregate results",
            "",
            "| Metric | Result |",
            "| --- | ---: |",
            (
                "| Benchmark runs | "
                f"{aggregate['benchmark_runs']} |"
            ),
            (
                "| Scenario evaluations | "
                f"{aggregate['scenario_evaluations']} |"
            ),
            (
                "| Overall pass rate | "
                f"{aggregate['overall_pass_rate']:.1%} |"
            ),
            (
                "| Selection accuracy | "
                f"{aggregate['selection_accuracy']:.1%} |"
            ),
            (
                "| Safe abstention rate | "
                f"{aggregate['safe_abstention_rate']:.1%} |"
            ),
            (
                "| Retrieval top-1 accuracy | "
                f"{aggregate['retrieval_top1_accuracy']:.1%} |"
            ),
            (
                "| Citation integrity | "
                f"{aggregate['citation_integrity_rate']:.1%} |"
            ),
            (
                "| Documentation evidence leaks | "
                f"{aggregate['documentation_evidence_leaks']} |"
            ),
            (
                "| Constraint violations | "
                f"{aggregate['constraint_violation_cases']} |"
            ),
            (
                "| Reasoner errors | "
                f"{aggregate['reasoner_errors']} |"
            ),
            "",
            "## Scenario results",
            "",
            (
                "| Run | Scenario | Expected | Actual | "
                "Passed | Top-1 runbook | Citation integrity |"
            ),
            (
                "| ---: | --- | --- | --- | --- | --- | --- |"
            ),
        ]

        for run_number, report in enumerate(
            self.reports,
            start=1,
        ):
            for case in report.cases:
                actual = (
                    case.actual_decision.value
                    if case.actual_decision
                    else "ERROR"
                )

                lines.append(
                    "| "
                    f"{run_number} | "
                    f"{case.scenario_id} | "
                    f"{case.expected_decision.value} | "
                    f"{actual} | "
                    f"{case.evaluation.passed} | "
                    f"{case.actual_top1_runbook_id or '-'} | "
                    f"{case.citation_integrity} |"
                )

        lines.extend(
            [
                "",
                "## Safety properties",
                "",
                (
                    "- Documentation context remains separate "
                    "from runtime operational evidence."
                ),
                (
                    "- Model selections remain constrained to "
                    "deterministic FinStream candidates."
                ),
                (
                    "- Runbook citations are validated against "
                    "trusted retrieved provenance."
                ),
                (
                    "- Healthy and ambiguous incidents must "
                    "preserve safe abstention."
                ),
                "",
            ]
        )

        return "\n".join(lines)

    def write(
        self,
        *,
        json_path: Path,
        markdown_path: Path,
    ) -> None:
        """Persist JSON and Markdown benchmark evidence."""
        json_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        markdown_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        json_path.write_text(
            self.to_json()
        )

        markdown_path.write_text(
            self.to_markdown()
        )
