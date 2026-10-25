from pathlib import Path

from services.ai_sre_agent.evaluation import (
    EvaluationCaseResult,
    ExpectedDecision,
    RagEvaluationCase,
    RagEvaluationMetrics,
    RagEvaluationReport,
    RepeatedRagBenchmarkReport,
)


def make_report() -> RagEvaluationReport:
    case = RagEvaluationCase(
        scenario_id="processor-outage",
        expected_decision=ExpectedDecision.SELECT,
        actual_decision=ExpectedDecision.SELECT,
        selected_candidate_ids=(
            "processor-immediate-unavailable",
        ),
        retrieved_runbook_ids=(
            "RB-PROCESSOR-001",
        ),
        expected_top1_runbook_id=(
            "RB-PROCESSOR-001"
        ),
        actual_top1_runbook_id=(
            "RB-PROCESSOR-001"
        ),
        retrieval_top1_correct=True,
        documentation_context_ids=("ev-doc-1",),
        citation_context_ids=("ev-doc-1",),
        citation_runbook_ids=(
            "RB-PROCESSOR-001",
        ),
        citation_integrity=True,
        documentation_evidence_leak=False,
        evaluation=EvaluationCaseResult(
            scenario_id="processor-outage",
            passed=True,
            violations=(),
        ),
    )

    metrics = RagEvaluationMetrics(
        total=1,
        passed=1,
        failed=0,
        pass_rate=1.0,
        selection_total=1,
        correct_selections=1,
        selection_accuracy=1.0,
        abstention_total=0,
        correct_abstentions=0,
        safe_abstention_rate=0.0,
        retrieval_scored_cases=1,
        retrieval_top1_correct=1,
        retrieval_top1_accuracy=1.0,
        citation_bearing_cases=1,
        citation_total=1,
        valid_citations=1,
        citation_integrity_rate=1.0,
        documentation_evidence_leak_cases=0,
        documentation_evidence_leak_rate=0.0,
        reasoner_errors=0,
        reasoner_error_rate=0.0,
        constraint_violation_cases=0,
        constraint_violation_rate=0.0,
    )

    return RagEvaluationReport(
        cases=(case,),
        metrics=metrics,
    )


def test_repeated_report_aggregates_runs():
    report = RepeatedRagBenchmarkReport(
        model="qwen3:1.7b",
        reports=(
            make_report(),
            make_report(),
            make_report(),
        ),
    )

    aggregate = report.aggregate_metrics()

    assert aggregate["benchmark_runs"] == 3
    assert aggregate["scenario_evaluations"] == 3
    assert aggregate["passed"] == 3
    assert aggregate["failed"] == 0
    assert aggregate["overall_pass_rate"] == 1.0
    assert aggregate["selection_accuracy"] == 1.0
    assert aggregate["retrieval_top1_accuracy"] == 1.0
    assert aggregate["citation_integrity_rate"] == 1.0
    assert aggregate["documentation_evidence_leaks"] == 0
    assert aggregate["constraint_violation_cases"] == 0
    assert aggregate["reasoner_errors"] == 0


def test_repeated_report_serializes_case_evidence():
    report = RepeatedRagBenchmarkReport(
        model="qwen3:1.7b",
        reports=(make_report(),),
    )

    payload = report.to_dict()

    assert payload["schema_version"] == "1.0"
    assert payload["model"] == "qwen3:1.7b"

    case = payload["runs"][0]["cases"][0]

    assert case["scenario_id"] == "processor-outage"
    assert case["expected_decision"] == "SELECT"
    assert case["actual_decision"] == "SELECT"
    assert case["retrieval_top1_correct"] is True
    assert case["citation_integrity"] is True
    assert case["documentation_evidence_leak"] is False


def test_repeated_report_markdown_is_recruiter_readable():
    report = RepeatedRagBenchmarkReport(
        model="qwen3:1.7b",
        reports=(make_report(),),
    )

    markdown = report.to_markdown()

    assert "# FinStream AI-SRE Trusted RAG Benchmark" in markdown
    assert "qwen3:1.7b" in markdown
    assert "Selection accuracy" in markdown
    assert "Citation integrity" in markdown
    assert "processor-outage" in markdown
    assert "RB-PROCESSOR-001" in markdown


def test_repeated_report_writes_json_and_markdown(
    tmp_path: Path,
):
    report = RepeatedRagBenchmarkReport(
        model="qwen3:1.7b",
        reports=(make_report(),),
    )

    json_path = tmp_path / "benchmark.json"
    markdown_path = tmp_path / "benchmark.md"

    report.write(
        json_path=json_path,
        markdown_path=markdown_path,
    )

    assert json_path.exists()
    assert markdown_path.exists()

    assert '"schema_version": "1.0"' in (
        json_path.read_text()
    )

    assert (
        "# FinStream AI-SRE Trusted RAG Benchmark"
        in markdown_path.read_text()
    )
