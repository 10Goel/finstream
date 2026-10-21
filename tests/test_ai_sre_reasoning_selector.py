import json

import pytest

from services.ai_sre_agent.reasoning.constraints import (
    CandidateHypothesis,
    ReasoningConstraints,
)
from services.ai_sre_agent.reasoning.provider import (
    ModelProviderError,
)
from services.ai_sre_agent.reasoning.selector import (
    CandidateSelectionOutputError,
    CandidateSelectionProviderError,
    EvidenceConstrainedReasoner,
)


class FakeProvider:
    def __init__(
        self,
        response,
    ):
        self.response = response
        self.calls = 0
        self.last_system_prompt = None
        self.last_user_prompt = None

    def generate(
        self,
        *,
        system_prompt,
        user_prompt,
    ):
        self.calls += 1
        self.last_system_prompt = system_prompt
        self.last_user_prompt = user_prompt

        if isinstance(
            self.response,
            Exception,
        ):
            raise self.response

        return self.response


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
                    "unavailable; the deeper reason is "
                    "not established by the supplied evidence."
                ),
                supporting_evidence=(
                    "ev-prometheus",
                    "ev-deployment",
                    "ev-pods",
                ),
                confidence_ceiling=0.99,
            ),
        ),
    )


def valid_response():
    return json.dumps(
        {
            "selections": [
                {
                    "candidate_id": (
                        "processor-immediate-unavailable"
                    ),
                    "confidence": 0.94,
                    "explanation": (
                        "Direct processor health and "
                        "Kubernetes observations establish "
                        "the immediate unavailable state."
                    ),
                }
            ],
            "abstain": False,
            "abstention_reason": None,
        }
    )


def test_model_can_select_permitted_candidate():
    provider = FakeProvider(
        valid_response()
    )

    reasoner = EvidenceConstrainedReasoner(
        provider=provider
    )

    result = reasoner.select(
        constraints=make_constraints()
    )

    assert provider.calls == 1
    assert result.abstained is False
    assert len(result.selections) == 1

    selection = result.selections[0]

    assert (
        selection.candidate_id
        == "processor-immediate-unavailable"
    )

    assert selection.confidence == 0.94


def test_model_cannot_rewrite_statement_or_evidence():
    provider = FakeProvider(
        valid_response()
    )

    reasoner = EvidenceConstrainedReasoner(
        provider=provider
    )

    result = reasoner.select(
        constraints=make_constraints()
    )

    selection = result.selections[0]

    candidate = make_constraints().candidates[0]

    assert selection.statement == candidate.statement
    assert (
        selection.supporting_evidence
        == candidate.supporting_evidence
    )

    assert (
        selection.contradicting_evidence
        == candidate.contradicting_evidence
    )


def test_unknown_candidate_is_rejected():
    provider = FakeProvider(
        json.dumps(
            {
                "selections": [
                    {
                        "candidate_id": "invented-root-cause",
                        "confidence": 0.9,
                        "explanation": "Invented candidate.",
                    }
                ],
                "abstain": False,
                "abstention_reason": None,
            }
        )
    )

    reasoner = EvidenceConstrainedReasoner(
        provider=provider
    )

    with pytest.raises(
        CandidateSelectionOutputError,
        match="unknown candidate",
    ):
        reasoner.select(
            constraints=make_constraints()
        )


def test_confidence_ceiling_is_enforced():
    constraints = ReasoningConstraints(
        affected_service="processor",
        observed_conditions=(
            "processor_unavailable",
        ),
        ruled_out_subsystems=(),
        candidates=(
            CandidateHypothesis(
                candidate_id="bounded",
                statement="Processor unavailable.",
                supporting_evidence=("ev-1",),
                confidence_ceiling=0.60,
            ),
        ),
    )

    provider = FakeProvider(
        json.dumps(
            {
                "selections": [
                    {
                        "candidate_id": "bounded",
                        "confidence": 0.95,
                        "explanation": "Too confident.",
                    }
                ],
                "abstain": False,
                "abstention_reason": None,
            }
        )
    )

    reasoner = EvidenceConstrainedReasoner(
        provider=provider
    )

    with pytest.raises(
        CandidateSelectionOutputError,
        match="confidence ceiling",
    ):
        reasoner.select(
            constraints=constraints
        )


def test_explicit_model_abstention_is_supported():
    provider = FakeProvider(
        json.dumps(
            {
                "selections": [],
                "abstain": True,
                "abstention_reason": (
                    "No candidate is sufficiently supported."
                ),
            }
        )
    )

    reasoner = EvidenceConstrainedReasoner(
        provider=provider
    )

    result = reasoner.select(
        constraints=make_constraints()
    )

    assert provider.calls == 1
    assert result.abstained is True
    assert result.selections == ()

    assert (
        result.abstention_reason
        == "No candidate is sufficiently supported."
    )


def test_no_candidates_abstains_without_model_call():
    provider = FakeProvider(
        valid_response()
    )

    constraints = ReasoningConstraints(
        affected_service="processor",
        observed_conditions=(),
        ruled_out_subsystems=(),
        candidates=(),
    )

    reasoner = EvidenceConstrainedReasoner(
        provider=provider
    )

    result = reasoner.select(
        constraints=constraints
    )

    assert provider.calls == 0
    assert result.abstained is True
    assert result.selections == ()


def test_provider_failure_is_wrapped():
    provider = FakeProvider(
        ModelProviderError(
            "provider unavailable"
        )
    )

    reasoner = EvidenceConstrainedReasoner(
        provider=provider
    )

    with pytest.raises(
        CandidateSelectionProviderError,
        match="provider failed",
    ):
        reasoner.select(
            constraints=make_constraints()
        )

    assert provider.calls == 1
