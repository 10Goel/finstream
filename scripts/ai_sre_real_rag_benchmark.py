"""Repeated real-Qwen trusted-RAG benchmark for FinStream AI-SRE."""

from __future__ import annotations

from pathlib import Path

from services.ai_sre_agent.evaluation import (
    RagEvaluationRunner,
    evaluation_scenario_catalog,
)
from services.ai_sre_agent.reasoning.ollama import (
    OllamaModelProvider,
)
from services.ai_sre_agent.reasoning.selector import (
    CandidateSelectionResponse,
    EvidenceConstrainedReasoner,
)
from services.ai_sre_agent.retrieval import (
    DeterministicRunbookRetriever,
    RunbookCatalog,
)

RUNS = 3

EXPECTED_TOP1 = {
    "processor-outage": "RB-PROCESSOR-001",
    "kafka-dependency-impairment": "RB-KAFKA-001",
    "postgres-dependency-impairment": (
        "RB-POSTGRES-001"
    ),
}


def make_runner() -> RagEvaluationRunner:
    catalog = RunbookCatalog.load(
        repository_root=Path.cwd()
    )

    retriever = DeterministicRunbookRetriever(
        catalog=catalog
    )

    provider = OllamaModelProvider(
        model="qwen3:1.7b",
        timeout_seconds=180.0,
        context_length=4096,
        response_schema=(
            CandidateSelectionResponse.model_json_schema()
        ),
    )

    return RagEvaluationRunner(
        reasoner=EvidenceConstrainedReasoner(
            provider=provider
        ),
        retriever=retriever,
        top_k=3,
    )


def main() -> None:
    fixtures = evaluation_scenario_catalog()

    total_cases = 0
    total_passed = 0
    total_failed = 0

    total_reasoner_errors = 0
    total_constraint_violations = 0
    total_evidence_leaks = 0

    total_scored_retrieval = 0
    total_correct_retrieval = 0

    total_citations = 0
    total_valid_citations = 0

    total_selection_cases = 0
    total_correct_selections = 0

    total_abstention_cases = 0
    total_correct_abstentions = 0

    print("=" * 78)
    print(
        "FINSTREAM AI-SRE — REPEATED REAL QWEN "
        "TRUSTED-RAG BENCHMARK"
    )
    print("=" * 78)

    for run_number in range(1, RUNS + 1):
        print()
        print("=" * 78)
        print(f"RUN {run_number}/{RUNS}")
        print("=" * 78)

        report = make_runner().run(
            fixtures=fixtures,
            expected_top1_by_scenario=(
                EXPECTED_TOP1
            ),
        )

        m = report.metrics

        for case in report.cases:
            print()
            print(
                f"{case.scenario_id}: "
                f"expected={case.expected_decision.value} "
                f"actual="
                f"{case.actual_decision.value if case.actual_decision else 'ERROR'} "
                f"passed={case.evaluation.passed}"
            )

            print(
                "  selected=",
                case.selected_candidate_ids,
            )

            print(
                "  retrieval=",
                case.actual_top1_runbook_id,
            )

            print(
                "  retrieval_correct=",
                case.retrieval_top1_correct,
            )

            print(
                "  citations=",
                case.citation_runbook_ids,
            )

            print(
                "  citation_integrity=",
                case.citation_integrity,
            )

            print(
                "  evidence_leak=",
                case.documentation_evidence_leak,
            )

            print(
                "  reasoner_error=",
                case.reasoner_error,
            )

            if case.evaluation.violations:
                print(
                    "  violations=",
                    case.evaluation.violations,
                )

        print()
        print("RUN METRICS")
        print("pass_rate:", m.pass_rate)
        print(
            "selection_accuracy:",
            m.selection_accuracy,
        )
        print(
            "safe_abstention_rate:",
            m.safe_abstention_rate,
        )
        print(
            "retrieval_top1_accuracy:",
            m.retrieval_top1_accuracy,
        )
        print(
            "citation_integrity_rate:",
            m.citation_integrity_rate,
        )
        print(
            "documentation_evidence_leak_rate:",
            m.documentation_evidence_leak_rate,
        )
        print(
            "constraint_violation_rate:",
            m.constraint_violation_rate,
        )
        print(
            "reasoner_error_rate:",
            m.reasoner_error_rate,
        )

        total_cases += m.total
        total_passed += m.passed
        total_failed += m.failed

        total_reasoner_errors += m.reasoner_errors
        total_constraint_violations += (
            m.constraint_violation_cases
        )
        total_evidence_leaks += (
            m.documentation_evidence_leak_cases
        )

        total_scored_retrieval += (
            m.retrieval_scored_cases
        )
        total_correct_retrieval += (
            m.retrieval_top1_correct
        )

        total_citations += m.citation_total
        total_valid_citations += (
            m.valid_citations
        )

        total_selection_cases += (
            m.selection_total
        )
        total_correct_selections += (
            m.correct_selections
        )

        total_abstention_cases += (
            m.abstention_total
        )
        total_correct_abstentions += (
            m.correct_abstentions
        )

    print()
    print("=" * 78)
    print("AGGREGATE REAL-QWEN METRICS")
    print("=" * 78)

    print("benchmark_runs:", RUNS)
    print("scenario_evaluations:", total_cases)

    print(
        "overall_pass_rate:",
        total_passed / total_cases,
    )

    print(
        "selection_accuracy:",
        (
            total_correct_selections
            / total_selection_cases
        ),
    )

    print(
        "safe_abstention_rate:",
        (
            total_correct_abstentions
            / total_abstention_cases
        ),
    )

    print(
        "retrieval_top1_accuracy:",
        (
            total_correct_retrieval
            / total_scored_retrieval
        ),
    )

    citation_integrity = (
        total_valid_citations / total_citations
        if total_citations
        else 1.0
    )

    print(
        "citation_integrity_rate:",
        citation_integrity,
    )

    print(
        "documentation_evidence_leaks:",
        total_evidence_leaks,
    )

    print(
        "constraint_violation_cases:",
        total_constraint_violations,
    )

    print(
        "reasoner_errors:",
        total_reasoner_errors,
    )

    print()
    print("=" * 78)
    print("REAL-QWEN BENCHMARK VERDICT")
    print("=" * 78)

    assert total_failed == 0
    assert total_reasoner_errors == 0
    assert total_constraint_violations == 0
    assert total_evidence_leaks == 0

    assert (
        total_correct_retrieval
        == total_scored_retrieval
    )

    assert (
        total_correct_selections
        == total_selection_cases
    )

    assert (
        total_correct_abstentions
        == total_abstention_cases
    )

    assert (
        total_valid_citations
        == total_citations
    )

    print(
        "PASS: every repeated real-Qwen scenario "
        "satisfied its expected decision"
    )

    print(
        "PASS: deterministic retrieval remained "
        "100% correct across repeated runs"
    )

    print(
        "PASS: real-Qwen selection remained "
        "within the deterministic candidate set"
    )

    print(
        "PASS: abstention safety remained stable"
    )

    print(
        "PASS: all returned runbook citations "
        "preserved trusted provenance"
    )

    print(
        "PASS: documentation never became "
        "runtime evidence"
    )

    print(
        "PASS: zero deterministic constraint violations"
    )

    print(
        "PASS: zero reasoner failures"
    )


if __name__ == "__main__":
    main()
