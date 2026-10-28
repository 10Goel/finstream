"""Tests for combined AI-SRE grounding evaluation contracts."""

import pytest

from services.ai_sre_agent.evaluation.grounding import (
    GroundingExpectation,
    GroundingMode,
    GroundingSecurityExpectation,
)


def test_grounding_modes_expose_expected_channels():
    assert GroundingMode.CURRENT_ONLY.uses_runbooks is False
    assert GroundingMode.CURRENT_ONLY.uses_history is False

    assert (
        GroundingMode.CURRENT_PLUS_RUNBOOKS.uses_runbooks
        is True
    )
    assert (
        GroundingMode.CURRENT_PLUS_RUNBOOKS.uses_history
        is False
    )

    assert (
        GroundingMode.CURRENT_PLUS_HISTORY.uses_runbooks
        is False
    )
    assert (
        GroundingMode.CURRENT_PLUS_HISTORY.uses_history
        is True
    )

    combined = (
        GroundingMode.CURRENT_PLUS_RUNBOOKS_AND_HISTORY
    )

    assert combined.uses_runbooks is True
    assert combined.uses_history is True


def test_combined_mode_accepts_both_retrieval_expectations():
    expectation = GroundingExpectation(
        expected_runbook_top1_id="RB-PROCESSOR-001",
        expected_historical_top1_incident_id=(
            "inc-processor-previous"
        ),
    )

    expectation.validate_mode(
        mode=(
            GroundingMode
            .CURRENT_PLUS_RUNBOOKS_AND_HISTORY
        )
    )


def test_runbook_expectation_requires_runbook_channel():
    expectation = GroundingExpectation(
        expected_runbook_top1_id="RB-PROCESSOR-001",
    )

    with pytest.raises(
        ValueError,
        match="runbook-enabled",
    ):
        expectation.validate_mode(
            mode=GroundingMode.CURRENT_PLUS_HISTORY
        )


def test_history_expectation_requires_history_channel():
    expectation = GroundingExpectation(
        expected_historical_top1_incident_id=(
            "inc-processor-previous"
        ),
    )

    with pytest.raises(
        ValueError,
        match="history-enabled",
    ):
        expectation.validate_mode(
            mode=GroundingMode.CURRENT_PLUS_RUNBOOKS
        )


def test_security_contract_defaults_fail_closed():
    security = GroundingSecurityExpectation()

    assert security.require_candidate_boundary is True

    assert (
        security.require_operational_evidence_boundary
        is True
    )

    assert (
        security.require_documentation_citation_integrity
        is True
    )

    assert (
        security.require_historical_citation_integrity
        is True
    )

    assert security.require_namespace_isolation is True
