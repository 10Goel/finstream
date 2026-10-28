"""Tests for the combined FinStream grounding benchmark corpus."""

from services.ai_sre_agent.evaluation.grounding import (
    GroundingMode,
)
from services.ai_sre_agent.evaluation.grounding_scenarios import (
    grounding_scenario_catalog,
)
from services.ai_sre_agent.evaluation.models import (
    ExpectedDecision,
)


def catalog_by_id():
    return {
        item.scenario_id: item
        for item in grounding_scenario_catalog()
    }


def test_grounding_catalog_reuses_all_core_scenarios():
    catalog = grounding_scenario_catalog()

    assert tuple(
        item.scenario_id
        for item in catalog
    ) == (
        "processor-outage",
        "kafka-dependency-impairment",
        "postgres-dependency-impairment",
        "healthy-baseline",
        "ambiguous-processor",
    )


def test_every_scenario_has_deterministic_historical_precedent():
    for item in grounding_scenario_catalog():
        fixture = item.make_fixture()
        seed = item.historical_seed

        assert (
            seed.incident_id
            != fixture.incident.incident_id
        )

        # Matching fingerprint intentionally represents recurrence
        # while incident identity remains separate.
        assert (
            seed.fingerprint
            == fixture.incident.fingerprint
        )

        assert (
            seed.alert_name
            == fixture.incident.alert_name
        )

        assert (
            seed.affected_service
            == fixture.incident.affected_service
        )

        expectation = item.expectation_for(
            mode=GroundingMode.CURRENT_PLUS_HISTORY
        )

        assert (
            expectation
            .expected_historical_top1_incident_id
            == seed.incident_id
        )

        assert (
            expectation.expected_runbook_top1_id
            is None
        )


def test_runbook_expectations_match_existing_rag_corpus():
    catalog = catalog_by_id()

    assert (
        catalog["processor-outage"]
        .expected_runbook_top1_id
        == "RB-PROCESSOR-001"
    )

    assert (
        catalog["kafka-dependency-impairment"]
        .expected_runbook_top1_id
        == "RB-KAFKA-001"
    )

    assert (
        catalog["postgres-dependency-impairment"]
        .expected_runbook_top1_id
        == "RB-POSTGRES-001"
    )

    assert (
        catalog["healthy-baseline"]
        .expected_runbook_top1_id
        is None
    )

    assert (
        catalog["ambiguous-processor"]
        .expected_runbook_top1_id
        is None
    )


def test_historical_seed_preserves_select_vs_abstain_contract():
    for item in grounding_scenario_catalog():
        fixture = item.make_fixture()
        expected = fixture.scenario.expectation
        seed = item.historical_seed

        if expected.decision is ExpectedDecision.ABSTAIN:
            assert seed.abstained is True
            assert seed.selected_candidate_ids == ()
            assert seed.abstention_reason
        else:
            assert seed.abstained is False

            assert (
                seed.selected_candidate_ids
                == expected.expected_candidate_ids
            )

            assert seed.abstention_reason is None


def test_expectation_for_mode_exposes_only_enabled_channels():
    item = catalog_by_id()["processor-outage"]

    current_only = item.expectation_for(
        mode=GroundingMode.CURRENT_ONLY
    )

    assert current_only.expected_runbook_top1_id is None

    assert (
        current_only.expected_historical_top1_incident_id
        is None
    )

    runbooks = item.expectation_for(
        mode=GroundingMode.CURRENT_PLUS_RUNBOOKS
    )

    assert (
        runbooks.expected_runbook_top1_id
        == "RB-PROCESSOR-001"
    )

    assert (
        runbooks.expected_historical_top1_incident_id
        is None
    )

    history = item.expectation_for(
        mode=GroundingMode.CURRENT_PLUS_HISTORY
    )

    assert history.expected_runbook_top1_id is None

    assert (
        history.expected_historical_top1_incident_id
        == "inc-historical-processor-outage"
    )

    combined = item.expectation_for(
        mode=(
            GroundingMode
            .CURRENT_PLUS_RUNBOOKS_AND_HISTORY
        )
    )

    assert (
        combined.expected_runbook_top1_id
        == "RB-PROCESSOR-001"
    )

    assert (
        combined.expected_historical_top1_incident_id
        == "inc-historical-processor-outage"
    )
