import pytest

from services.ai_sre_agent.evaluation import (
    AiSreEvaluator,
    EvaluationExpectation,
    EvaluationScenario,
    ExpectedDecision,
)
from services.ai_sre_agent.reasoning.constraints import (
    CandidateHypothesis,
    ReasoningConstraints,
)
from services.ai_sre_agent.reasoning.selector import (
    CandidateSelectionOutcome,
    SelectedCandidate,
)


def make_constraints():
    return ReasoningConstraints(
        affected_service="processor",
        observed_conditions=(
            "processor_unavailable",
            "kafka_healthy",
            "postgres_healthy",
        ),
        ruled_out_subsystems=(
            "kafka",
            "postgres",
        ),
        candidates=(
            CandidateHypothesis(
                candidate_id=(
                    "processor-immediate-unavailable"
                ),
                statement=(
                    "FinStream processor workload is "
                    "unavailable; the deeper reason is not "
                    "established by the supplied evidence."
                ),
                supporting_evidence=(
                    "ev-prometheus",
                    "ev-kubernetes",
                ),
                confidence_ceiling=0.99,
            ),
        ),
    )


def make_selection(
    *,
    candidate_id=(
        "processor-immediate-unavailable"
    ),
    confidence=0.95,
    statement=None,
    supporting_evidence=None,
):
    candidate = make_constraints().candidates[0]

    return CandidateSelectionOutcome(
        selections=(
            SelectedCandidate(
                candidate_id=candidate_id,
                statement=(
                    candidate.statement
                    if statement is None
                    else statement
                ),
                confidence=confidence,
                model_rationale=(
                    "Direct evidence supports the candidate."
                ),
                supporting_evidence=(
                    candidate.supporting_evidence
                    if supporting_evidence is None
                    else supporting_evidence
                ),
                contradicting_evidence=(
                    candidate.contradicting_evidence
                ),
            ),
        ),
        abstained=False,
    )


def processor_outage_scenario():
    return EvaluationScenario(
        scenario_id="processor-outage",
        description=(
            "Processor is unavailable while Kafka and "
            "PostgreSQL remain healthy."
        ),
        affected_service="processor",
        expectation=EvaluationExpectation(
            decision=ExpectedDecision.SELECT,
            expected_candidate_ids=(
                "processor-immediate-unavailable",
            ),
            required_ruled_out_subsystems=(
                "kafka",
                "postgres",
            ),
            forbidden_candidate_ids=(
                "kafka-immediate-unavailable",
                "postgres-immediate-unavailable",
            ),
        ),
    )


def test_expected_candidate_passes():
    result = AiSreEvaluator.evaluate(
        scenario=processor_outage_scenario(),
        constraints=make_constraints(),
        selection=make_selection(),
    )

    assert result.passed is True
    assert result.violations == ()


def test_wrong_candidate_fails():
    result = AiSreEvaluator.evaluate(
        scenario=processor_outage_scenario(),
        constraints=make_constraints(),
        selection=make_selection(
            candidate_id="invented-candidate"
        ),
    )

    assert result.passed is False

    assert any(
        "candidate IDs" in violation
        for violation in result.violations
    )

    assert any(
        "outside the deterministic candidate set"
        in violation
        for violation in result.violations
    )


def test_safe_abstention_passes():
    scenario = EvaluationScenario(
        scenario_id="ambiguous",
        description="Evidence is insufficient for diagnosis.",
        affected_service="processor",
        expectation=EvaluationExpectation(
            decision=ExpectedDecision.ABSTAIN,
        ),
    )

    result = AiSreEvaluator.evaluate(
        scenario=scenario,
        constraints=ReasoningConstraints(
            affected_service="processor",
            observed_conditions=(),
            ruled_out_subsystems=(),
            candidates=(),
        ),
        selection=CandidateSelectionOutcome(
            selections=(),
            abstained=True,
            abstention_reason=(
                "No deterministic candidates available."
            ),
        ),
    )

    assert result.passed is True


def test_unexpected_abstention_fails():
    result = AiSreEvaluator.evaluate(
        scenario=processor_outage_scenario(),
        constraints=make_constraints(),
        selection=CandidateSelectionOutcome(
            selections=(),
            abstained=True,
            abstention_reason="Model abstained.",
        ),
    )

    assert result.passed is False

    assert any(
        "model abstained" in violation
        for violation in result.violations
    )


def test_modified_evidence_fails():
    result = AiSreEvaluator.evaluate(
        scenario=processor_outage_scenario(),
        constraints=make_constraints(),
        selection=make_selection(
            supporting_evidence=(
                "ev-invented",
            )
        ),
    )

    assert result.passed is False

    assert any(
        "Supporting evidence was modified"
        in violation
        for violation in result.violations
    )


def test_confidence_above_ceiling_fails():
    result = AiSreEvaluator.evaluate(
        scenario=processor_outage_scenario(),
        constraints=make_constraints(),
        selection=make_selection(
            confidence=1.0
        ),
    )

    assert result.passed is False

    assert any(
        "confidence exceeds"
        in violation
        for violation in result.violations
    )


def test_suite_summary_reports_pass_rate():
    passed = AiSreEvaluator.evaluate(
        scenario=processor_outage_scenario(),
        constraints=make_constraints(),
        selection=make_selection(),
    )

    failed = AiSreEvaluator.evaluate(
        scenario=processor_outage_scenario(),
        constraints=make_constraints(),
        selection=CandidateSelectionOutcome(
            selections=(),
            abstained=True,
            abstention_reason="test",
        ),
    )

    summary = AiSreEvaluator.summarize(
        [passed, failed]
    )

    assert summary.total == 2
    assert summary.passed == 1
    assert summary.failed == 1
    assert summary.pass_rate == pytest.approx(0.5)
