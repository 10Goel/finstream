import json

import pytest

from services.ai_sre_agent.reasoning.constraints import (
    CandidateHypothesis,
    ReasoningConstraints,
)
from services.ai_sre_agent.reasoning.selector import (
    CandidateSelectionOutputError,
    EvidenceConstrainedReasoner,
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
                    "unavailable; deeper cause is not "
                    "established."
                ),
                supporting_evidence=(
                    "ev-prometheus",
                    "ev-kubernetes",
                ),
                contradicting_evidence=(),
                confidence_ceiling=0.99,
            ),
        ),
    )


def invalid_contradictory_response():
    return json.dumps(
        {
            "selections": [
                {
                    "candidate_id": (
                        "processor-immediate-unavailable"
                    ),
                    "confidence": 0.90,
                    "explanation": (
                        "Processor is unavailable."
                    ),
                    "documentation_context_ids": [],
                }
            ],
            "abstain": True,
            "abstention_reason": (
                "Contradictory model output."
            ),
        }
    )


def valid_response():
    return json.dumps(
        {
            "selections": [
                {
                    "candidate_id": (
                        "processor-immediate-unavailable"
                    ),
                    "confidence": 0.90,
                    "explanation": (
                        "The supplied operational evidence "
                        "supports the deterministic candidate."
                    ),
                    "documentation_context_ids": [],
                }
            ],
            "abstain": False,
            "abstention_reason": None,
        }
    )


class RepairingProvider:
    def __init__(self):
        self.calls = 0
        self.system_prompts = []

    def generate(
        self,
        *,
        system_prompt,
        user_prompt,
    ):
        del user_prompt

        self.calls += 1
        self.system_prompts.append(
            system_prompt
        )

        if self.calls == 1:
            return invalid_contradictory_response()

        return valid_response()


class AlwaysInvalidProvider:
    def __init__(self):
        self.calls = 0

    def generate(
        self,
        *,
        system_prompt,
        user_prompt,
    ):
        del system_prompt
        del user_prompt

        self.calls += 1

        return invalid_contradictory_response()


class MalformedThenValidProvider:
    def __init__(self):
        self.calls = 0

    def generate(
        self,
        *,
        system_prompt,
        user_prompt,
    ):
        del system_prompt
        del user_prompt

        self.calls += 1

        if self.calls == 1:
            return "{invalid"

        return valid_response()


def test_invalid_first_response_gets_one_bounded_repair():
    provider = RepairingProvider()

    result = EvidenceConstrainedReasoner(
        provider=provider
    ).select(
        constraints=make_constraints()
    )

    assert provider.calls == 2
    assert result.abstained is False

    assert (
        result.selections[0].candidate_id
        == "processor-immediate-unavailable"
    )

    assert (
        "previous response violated"
        in provider.system_prompts[1].lower()
    )


def test_repeated_invalid_response_fails_closed():
    provider = AlwaysInvalidProvider()

    with pytest.raises(
        CandidateSelectionOutputError,
        match="bounded repair",
    ):
        EvidenceConstrainedReasoner(
            provider=provider
        ).select(
            constraints=make_constraints()
        )

    assert provider.calls == 2


def test_malformed_json_can_be_repaired_once():
    provider = MalformedThenValidProvider()

    result = EvidenceConstrainedReasoner(
        provider=provider
    ).select(
        constraints=make_constraints()
    )

    assert provider.calls == 2
    assert result.abstained is False
