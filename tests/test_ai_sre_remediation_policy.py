import pytest

from services.ai_sre_agent.evaluation.scenarios import (
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
from services.ai_sre_agent.remediation import (
    RemediationActionType,
    RemediationCandidate,
    RemediationPolicyError,
    RemediationPolicyPlanner,
    RemediationRiskLevel,
)


def build_constraints(fixture):
    return EvidenceConstraintBuilder.build(
        incident=fixture.incident,
        evidence=list(fixture.evidence),
    )


def select_first(constraints):
    candidate = constraints.candidates[0]

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
                    "Direct evidence supports this diagnosis."
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


def test_processor_outage_allows_approval_gated_restart():
    fixture = processor_outage_fixture()
    constraints = build_constraints(fixture)

    plan = RemediationPolicyPlanner.build(
        incident=fixture.incident,
        constraints=constraints,
        selection=select_first(constraints),
    )

    assert plan.blocked_reason is None
    assert len(plan.candidates) == 1

    action = plan.candidates[0]

    assert (
        action.action_type
        is RemediationActionType.ROLLING_RESTART
    )
    assert action.risk_level is RemediationRiskLevel.MEDIUM
    assert action.requires_approval is True
    assert action.affected_service == "processor"


def test_unhealthy_kafka_blocks_blind_producer_restart():
    fixture = kafka_dependency_impairment_fixture()
    constraints = build_constraints(fixture)

    plan = RemediationPolicyPlanner.build(
        incident=fixture.incident,
        constraints=constraints,
        selection=select_first(constraints),
    )

    assert len(plan.candidates) == 1

    action = plan.candidates[0]

    assert (
        action.action_type
        is RemediationActionType.INVESTIGATE_DEPENDENCIES
    )
    assert action.risk_level is RemediationRiskLevel.LOW
    assert action.requires_approval is False

    assert "kafka" in action.rationale.casefold()


def test_unhealthy_postgres_blocks_blind_api_restart():
    fixture = postgres_dependency_impairment_fixture()
    constraints = build_constraints(fixture)

    plan = RemediationPolicyPlanner.build(
        incident=fixture.incident,
        constraints=constraints,
        selection=select_first(constraints),
    )

    action = plan.candidates[0]

    assert (
        action.action_type
        is RemediationActionType.INVESTIGATE_DEPENDENCIES
    )

    assert "postgres" in action.rationale.casefold()


def test_reasoning_abstention_blocks_remediation():
    fixture = processor_outage_fixture()
    constraints = build_constraints(fixture)

    plan = RemediationPolicyPlanner.build(
        incident=fixture.incident,
        constraints=constraints,
        selection=CandidateSelectionOutcome(
            selections=(),
            abstained=True,
            abstention_reason=(
                "Insufficient evidence."
            ),
        ),
    )

    assert plan.candidates == ()
    assert plan.blocked_reason is not None
    assert plan.diagnosis_candidate_id is None


def test_multiple_diagnoses_block_remediation():
    fixture = processor_outage_fixture()
    constraints = build_constraints(fixture)

    selected = select_first(constraints).selections[0]

    plan = RemediationPolicyPlanner.build(
        incident=fixture.incident,
        constraints=constraints,
        selection=CandidateSelectionOutcome(
            selections=(
                selected,
                selected,
            ),
            abstained=False,
        ),
    )

    assert plan.candidates == ()
    assert plan.blocked_reason is not None


def test_modified_selected_diagnosis_is_rejected():
    fixture = processor_outage_fixture()
    constraints = build_constraints(fixture)

    candidate = constraints.candidates[0]

    selection = CandidateSelectionOutcome(
        selections=(
            SelectedCandidate(
                candidate_id=candidate.candidate_id,
                statement="Invented replacement statement.",
                confidence=0.9,
                model_rationale="test",
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

    with pytest.raises(
        RemediationPolicyError,
        match="statement differs",
    ):
        RemediationPolicyPlanner.build(
            incident=fixture.incident,
            constraints=constraints,
            selection=selection,
        )


def test_remediation_candidate_requires_evidence():
    with pytest.raises(
        ValueError,
        match="requires supporting evidence",
    ):
        RemediationCandidate(
            action_id="test-action",
            action_type=(
                RemediationActionType.ROLLING_RESTART
            ),
            affected_service="processor",
            description="Test action.",
            rationale="Test rationale.",
            risk_level=RemediationRiskLevel.MEDIUM,
            requires_approval=True,
            supporting_evidence=(),
            verification_steps=(
                "Verify recovery.",
            ),
        )
