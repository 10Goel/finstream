from services.ai_sre_agent.evaluation import (
    AiSreEvaluator,
)
from services.ai_sre_agent.evaluation.scenarios import (
    ambiguous_processor_fixture,
    evaluation_scenario_catalog,
    healthy_baseline_fixture,
    kafka_dependency_impairment_fixture,
    postgres_dependency_impairment_fixture,
    processor_outage_fixture,
)
from services.ai_sre_agent.reasoning.constraints import (
    EvidenceConstraintBuilder,
)
from services.ai_sre_agent.reasoning.selector import (
    CandidateSelectionOutcome,
    SelectedCandidate,
)


def build_constraints(fixture):
    return EvidenceConstraintBuilder.build(
        incident=fixture.incident,
        evidence=list(fixture.evidence),
    )


def selected_outcome(candidate):
    return CandidateSelectionOutcome(
        selections=(
            SelectedCandidate(
                candidate_id=candidate.candidate_id,
                statement=candidate.statement,
                confidence=min(
                    0.95,
                    candidate.confidence_ceiling,
                ),
                model_rationale=(
                    "Evaluation fixture selected the "
                    "deterministic candidate."
                ),
                supporting_evidence=(
                    candidate.supporting_evidence
                ),
                contradicting_evidence=(
                    candidate.contradicting_evidence
                ),
            ),
        ),
        abstained=False,
    )


def abstained_outcome():
    return CandidateSelectionOutcome(
        selections=(),
        abstained=True,
        abstention_reason=(
            "No deterministic diagnosis is permitted."
        ),
    )


def test_processor_outage_builds_safe_candidate():
    fixture = processor_outage_fixture()
    constraints = build_constraints(fixture)

    assert len(constraints.candidates) == 1

    candidate = constraints.candidates[0]

    assert (
        candidate.candidate_id
        == "processor-immediate-unavailable"
    )

    assert set(
        constraints.ruled_out_subsystems
    ) == {
        "kafka",
        "postgres",
    }

    result = AiSreEvaluator.evaluate(
        scenario=fixture.scenario,
        constraints=constraints,
        selection=selected_outcome(candidate),
    )

    assert result.passed is True


def test_kafka_dependency_is_not_falsely_ruled_out():
    fixture = kafka_dependency_impairment_fixture()
    constraints = build_constraints(fixture)

    assert len(constraints.candidates) == 1

    candidate = constraints.candidates[0]

    assert (
        candidate.candidate_id
        == "producer-immediate-unavailable"
    )

    assert "kafka" not in (
        constraints.ruled_out_subsystems
    )

    result = AiSreEvaluator.evaluate(
        scenario=fixture.scenario,
        constraints=constraints,
        selection=selected_outcome(candidate),
    )

    assert result.passed is True


def test_postgres_dependency_is_not_falsely_ruled_out():
    fixture = postgres_dependency_impairment_fixture()
    constraints = build_constraints(fixture)

    assert len(constraints.candidates) == 1

    candidate = constraints.candidates[0]

    assert (
        candidate.candidate_id
        == "api-immediate-unavailable"
    )

    assert "postgres" not in (
        constraints.ruled_out_subsystems
    )

    result = AiSreEvaluator.evaluate(
        scenario=fixture.scenario,
        constraints=constraints,
        selection=selected_outcome(candidate),
    )

    assert result.passed is True


def test_healthy_baseline_requires_abstention():
    fixture = healthy_baseline_fixture()
    constraints = build_constraints(fixture)

    assert constraints.candidates == ()

    result = AiSreEvaluator.evaluate(
        scenario=fixture.scenario,
        constraints=constraints,
        selection=abstained_outcome(),
    )

    assert result.passed is True


def test_ambiguous_symptoms_require_abstention():
    fixture = ambiguous_processor_fixture()
    constraints = build_constraints(fixture)

    assert constraints.candidates == ()

    assert (
        "processor_consumer_group_empty"
        in constraints.observed_conditions
    )

    assert (
        "processor_consumer_lag_present"
        in constraints.observed_conditions
    )

    result = AiSreEvaluator.evaluate(
        scenario=fixture.scenario,
        constraints=constraints,
        selection=abstained_outcome(),
    )

    assert result.passed is True


def test_catalog_contains_five_distinct_scenarios():
    catalog = evaluation_scenario_catalog()

    assert len(catalog) == 5

    scenario_ids = [
        fixture.scenario.scenario_id
        for fixture in catalog
    ]

    assert len(set(scenario_ids)) == 5
