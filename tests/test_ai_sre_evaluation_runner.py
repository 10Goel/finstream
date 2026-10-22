import json

from services.ai_sre_agent.evaluation import (
    EvaluationRunner,
    ExpectedDecision,
    evaluation_scenario_catalog,
)
from services.ai_sre_agent.reasoning.selector import (
    EvidenceConstrainedReasoner,
)


class FirstCandidateProvider:
    """Deterministically select the first permitted candidate."""

    def __init__(self):
        self.calls = 0

    def generate(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
    ) -> str:
        self.calls += 1

        payload = json.loads(user_prompt)
        candidate = payload["candidates"][0]

        return json.dumps(
            {
                "selections": [
                    {
                        "candidate_id": (
                            candidate["candidate_id"]
                        ),
                        "confidence": min(
                            0.9,
                            candidate[
                                "confidence_ceiling"
                            ],
                        ),
                        "explanation": (
                            "Direct evidence supports the "
                            "deterministic candidate."
                        ),
                    }
                ],
                "abstain": False,
                "abstention_reason": None,
            }
        )


class AlwaysAbstainProvider:
    """Abstain even when a deterministic candidate exists."""

    def generate(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
    ) -> str:
        return json.dumps(
            {
                "selections": [],
                "abstain": True,
                "abstention_reason": (
                    "Deterministic test abstention."
                ),
            }
        )


class MalformedProvider:
    """Return invalid model output for error-containment tests."""

    def generate(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
    ) -> str:
        return "not-json"


def make_runner(provider):
    return EvaluationRunner(
        reasoner=EvidenceConstrainedReasoner(
            provider=provider,
        )
    )


def test_catalog_runner_passes_all_five_scenarios():
    provider = FirstCandidateProvider()

    report = make_runner(provider).run(
        fixtures=evaluation_scenario_catalog(),
    )

    assert report.metrics.total == 5
    assert report.metrics.passed == 5
    assert report.metrics.failed == 0
    assert report.metrics.pass_rate == 1.0

    # Only SELECT scenarios require a provider call.
    assert provider.calls == 3


def test_catalog_runner_measures_selection_accuracy():
    report = make_runner(
        FirstCandidateProvider()
    ).run(
        fixtures=evaluation_scenario_catalog(),
    )

    assert report.metrics.selection_total == 3
    assert report.metrics.correct_selections == 3
    assert report.metrics.selection_accuracy == 1.0


def test_catalog_runner_measures_safe_abstention_rate():
    report = make_runner(
        FirstCandidateProvider()
    ).run(
        fixtures=evaluation_scenario_catalog(),
    )

    assert report.metrics.abstention_total == 2
    assert report.metrics.correct_abstentions == 2
    assert report.metrics.safe_abstention_rate == 1.0


def test_golden_run_has_no_constraint_violations():
    report = make_runner(
        FirstCandidateProvider()
    ).run(
        fixtures=evaluation_scenario_catalog(),
    )

    assert report.metrics.constraint_violation_cases == 0
    assert report.metrics.constraint_violation_rate == 0.0
    assert report.metrics.reasoner_errors == 0


def test_unexpected_abstention_is_measured_as_failure():
    report = make_runner(
        AlwaysAbstainProvider()
    ).run(
        fixtures=evaluation_scenario_catalog(),
    )

    assert report.metrics.total == 5

    # Three SELECT scenarios fail.
    assert report.metrics.passed == 2
    assert report.metrics.failed == 3

    assert report.metrics.selection_accuracy == 0.0

    # Healthy + ambiguous scenarios still abstain safely.
    assert report.metrics.safe_abstention_rate == 1.0

    # Wrong decision is not the same as escaping constraints.
    assert report.metrics.constraint_violation_rate == 0.0


def test_reasoner_errors_are_contained_per_scenario():
    report = make_runner(
        MalformedProvider()
    ).run(
        fixtures=evaluation_scenario_catalog(),
    )

    # The three candidate-bearing scenarios reach the provider
    # and fail schema/JSON validation.
    assert report.metrics.reasoner_errors == 3
    assert report.metrics.reasoner_error_rate == 0.6

    # The two no-candidate cases safely abstain before any
    # model call and still pass.
    assert report.metrics.passed == 2
    assert report.metrics.failed == 3

    errored = [
        case
        for case in report.cases
        if case.reasoner_error is not None
    ]

    assert len(errored) == 3


def test_report_preserves_per_scenario_decisions():
    report = make_runner(
        FirstCandidateProvider()
    ).run(
        fixtures=evaluation_scenario_catalog(),
    )

    cases = {
        case.scenario_id: case
        for case in report.cases
    }

    processor = cases["processor-outage"]

    assert (
        processor.expected_decision
        is ExpectedDecision.SELECT
    )
    assert (
        processor.actual_decision
        is ExpectedDecision.SELECT
    )
    assert processor.selected_candidate_ids == (
        "processor-immediate-unavailable",
    )

    healthy = cases["healthy-baseline"]

    assert (
        healthy.expected_decision
        is ExpectedDecision.ABSTAIN
    )
    assert (
        healthy.actual_decision
        is ExpectedDecision.ABSTAIN
    )
    assert healthy.selected_candidate_ids == ()
