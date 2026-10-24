import json
from pathlib import Path

from services.ai_sre_agent.evaluation import (
    ExpectedDecision,
    RagEvaluationRunner,
    evaluation_scenario_catalog,
)
from services.ai_sre_agent.reasoning.selector import (
    EvidenceConstrainedReasoner,
)
from services.ai_sre_agent.retrieval import (
    DeterministicRunbookRetriever,
    RunbookCatalog,
)

EXPECTED_TOP1 = {
    "processor-outage": "RB-PROCESSOR-001",
    "kafka-dependency-impairment": "RB-KAFKA-001",
    "postgres-dependency-impairment": (
        "RB-POSTGRES-001"
    ),
}


class GroundedFirstCandidateProvider:
    """Select the first deterministic candidate with provenance."""

    def __init__(self):
        self.calls = 0

    def generate(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
    ) -> str:
        del system_prompt

        self.calls += 1

        payload = json.loads(user_prompt)

        candidate = payload["candidates"][0]

        documentation_context = payload.get(
            "documentation_context",
            [],
        )

        context_ids = (
            [
                documentation_context[0][
                    "context_id"
                ]
            ]
            if documentation_context
            else []
        )

        explanation = (
            "Direct runtime evidence supports the "
            "deterministic candidate."
        )

        if context_ids:
            explanation += (
                " Approved runbook documentation "
                "provides supporting operational context."
            )

        return json.dumps(
            {
                "selections": [
                    {
                        "candidate_id": (
                            candidate["candidate_id"]
                        ),
                        "confidence": min(
                            0.90,
                            candidate[
                                "confidence_ceiling"
                            ],
                        ),
                        "explanation": explanation,
                        "documentation_context_ids": (
                            context_ids
                        ),
                    }
                ],
                "abstain": False,
                "abstention_reason": None,
            }
        )


class MalformedProvider:
    """Return invalid output to test failure containment."""

    def generate(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
    ) -> str:
        del system_prompt
        del user_prompt

        return "not-json"


def make_runner(provider):
    catalog = RunbookCatalog.load(
        repository_root=Path.cwd()
    )

    retriever = DeterministicRunbookRetriever(
        catalog=catalog
    )

    return RagEvaluationRunner(
        reasoner=EvidenceConstrainedReasoner(
            provider=provider
        ),
        retriever=retriever,
        top_k=3,
    )


def test_golden_rag_run_passes_all_five_scenarios():
    provider = GroundedFirstCandidateProvider()

    report = make_runner(provider).run(
        fixtures=evaluation_scenario_catalog(),
        expected_top1_by_scenario=EXPECTED_TOP1,
    )

    assert report.metrics.total == 5
    assert report.metrics.passed == 5
    assert report.metrics.failed == 0
    assert report.metrics.pass_rate == 1.0

    assert report.metrics.selection_total == 3
    assert report.metrics.correct_selections == 3
    assert report.metrics.selection_accuracy == 1.0

    assert report.metrics.abstention_total == 2
    assert report.metrics.correct_abstentions == 2
    assert report.metrics.safe_abstention_rate == 1.0

    # Only candidate-bearing scenarios reach the model.
    assert provider.calls == 3


def test_rag_runner_measures_top1_retrieval_accuracy():
    report = make_runner(
        GroundedFirstCandidateProvider()
    ).run(
        fixtures=evaluation_scenario_catalog(),
        expected_top1_by_scenario=EXPECTED_TOP1,
    )

    assert report.metrics.retrieval_scored_cases == 3
    assert report.metrics.retrieval_top1_correct == 3
    assert report.metrics.retrieval_top1_accuracy == 1.0

    cases = {
        case.scenario_id: case
        for case in report.cases
    }

    assert (
        cases[
            "processor-outage"
        ].actual_top1_runbook_id
        == "RB-PROCESSOR-001"
    )

    assert (
        cases[
            "kafka-dependency-impairment"
        ].actual_top1_runbook_id
        == "RB-KAFKA-001"
    )

    assert (
        cases[
            "postgres-dependency-impairment"
        ].actual_top1_runbook_id
        == "RB-POSTGRES-001"
    )


def test_rag_runner_verifies_citation_integrity():
    report = make_runner(
        GroundedFirstCandidateProvider()
    ).run(
        fixtures=evaluation_scenario_catalog(),
        expected_top1_by_scenario=EXPECTED_TOP1,
    )

    assert report.metrics.citation_bearing_cases == 3
    assert report.metrics.citation_total == 3
    assert report.metrics.valid_citations == 3
    assert report.metrics.citation_integrity_rate == 1.0

    assert (
        report.metrics.documentation_evidence_leak_cases
        == 0
    )

    assert (
        report.metrics.documentation_evidence_leak_rate
        == 0.0
    )

    selected_cases = [
        case
        for case in report.cases
        if case.actual_decision
        is ExpectedDecision.SELECT
    ]

    assert len(selected_cases) == 3

    for case in selected_cases:
        assert case.citation_integrity is True
        assert case.documentation_evidence_leak is False
        assert len(case.citation_context_ids) == 1
        assert len(case.citation_runbook_ids) == 1

        assert (
            case.citation_context_ids[0]
            in case.documentation_context_ids
        )


def test_retrieved_context_cannot_force_abstention_case_selection():
    report = make_runner(
        GroundedFirstCandidateProvider()
    ).run(
        fixtures=evaluation_scenario_catalog(),
        expected_top1_by_scenario=EXPECTED_TOP1,
    )

    cases = {
        case.scenario_id: case
        for case in report.cases
    }

    for scenario_id in (
        "healthy-baseline",
        "ambiguous-processor",
    ):
        case = cases[scenario_id]

        # Relevant documentation was available.
        assert case.retrieved_runbook_ids
        assert case.documentation_context_ids

        # But no deterministic candidate existed,
        # therefore the model could not manufacture one.
        assert (
            case.actual_decision
            is ExpectedDecision.ABSTAIN
        )

        assert case.selected_candidate_ids == ()
        assert case.citation_context_ids == ()
        assert case.evaluation.passed is True


def test_top1_retrieval_mismatch_fails_benchmark_case():
    expectations = dict(EXPECTED_TOP1)

    expectations[
        "processor-outage"
    ] = "RB-KAFKA-001"

    report = make_runner(
        GroundedFirstCandidateProvider()
    ).run(
        fixtures=evaluation_scenario_catalog(),
        expected_top1_by_scenario=expectations,
    )

    assert report.metrics.retrieval_scored_cases == 3
    assert report.metrics.retrieval_top1_correct == 2

    assert (
        report.metrics.retrieval_top1_accuracy
        == 2 / 3
    )

    assert report.metrics.passed == 4
    assert report.metrics.failed == 1

    processor = next(
        case
        for case in report.cases
        if case.scenario_id
        == "processor-outage"
    )

    assert (
        processor.retrieval_top1_correct
        is False
    )

    assert processor.evaluation.passed is False

    assert any(
        "Top-1 retrieval mismatch"
        in violation
        for violation
        in processor.evaluation.violations
    )


def test_reasoner_failure_is_contained_without_losing_retrieval_metrics():
    report = make_runner(
        MalformedProvider()
    ).run(
        fixtures=evaluation_scenario_catalog(),
        expected_top1_by_scenario=EXPECTED_TOP1,
    )

    assert report.metrics.total == 5

    # Three candidate-bearing scenarios fail closed.
    assert report.metrics.reasoner_errors == 3
    assert report.metrics.reasoner_error_rate == 0.6

    # Healthy + ambiguous still abstain before model invocation.
    assert report.metrics.passed == 2
    assert report.metrics.failed == 3

    # Retrieval remains independently measurable.
    assert report.metrics.retrieval_top1_correct == 3
    assert report.metrics.retrieval_top1_accuracy == 1.0

    errored = [
        case
        for case in report.cases
        if case.reasoner_error is not None
    ]

    assert len(errored) == 3
