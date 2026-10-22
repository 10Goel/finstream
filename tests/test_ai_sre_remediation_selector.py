import json

import pytest

from services.ai_sre_agent.reasoning.provider import (
    ModelProviderError,
)
from services.ai_sre_agent.remediation import (
    EvidenceConstrainedRemediationSelector,
    RemediationActionType,
    RemediationCandidate,
    RemediationPlanConstraints,
    RemediationRiskLevel,
    RemediationSelectionOutputError,
    RemediationSelectionProviderError,
)


class FakeProvider:
    def __init__(
        self,
        response: str | None = None,
        error: Exception | None = None,
    ):
        self.response = response
        self.error = error
        self.calls = 0
        self.system_prompt = None
        self.user_prompt = None

    def generate(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
    ) -> str:
        self.calls += 1
        self.system_prompt = system_prompt
        self.user_prompt = user_prompt

        if self.error is not None:
            raise self.error

        if self.response is None:
            raise AssertionError(
                "FakeProvider response was not configured."
            )

        return self.response


def make_candidate():
    return RemediationCandidate(
        action_id="processor-rolling-restart",
        action_type=(
            RemediationActionType.ROLLING_RESTART
        ),
        affected_service="processor",
        description=(
            "Perform an approval-gated rolling restart."
        ),
        rationale=(
            "Processor is unavailable while dependencies "
            "have been ruled out."
        ),
        risk_level=RemediationRiskLevel.MEDIUM,
        requires_approval=True,
        supporting_evidence=(
            "ev-prometheus",
            "ev-kubernetes",
        ),
        verification_steps=(
            "Confirm processor becomes ready.",
            "Confirm Prometheus target becomes healthy.",
        ),
        rollback_guidance=(
            "Stop further progression if recovery fails."
        ),
    )


def make_constraints():
    return RemediationPlanConstraints(
        incident_id="inc-test",
        affected_service="processor",
        diagnosis_candidate_id=(
            "processor-immediate-unavailable"
        ),
        candidates=(
            make_candidate(),
        ),
    )


def test_valid_selection_reconstructs_immutable_candidate():
    provider = FakeProvider(
        response=json.dumps(
            {
                "selection": {
                    "action_id": (
                        "processor-rolling-restart"
                    ),
                    "explanation": (
                        "The approved restart is appropriate."
                    ),
                },
                "abstain": False,
                "abstention_reason": None,
            }
        )
    )

    selector = EvidenceConstrainedRemediationSelector(
        provider=provider
    )

    outcome = selector.select(
        constraints=make_constraints()
    )

    assert outcome.abstained is False
    assert outcome.selection is not None

    selected = outcome.selection
    candidate = make_candidate()

    assert selected.action_id == candidate.action_id
    assert selected.action_type is candidate.action_type
    assert selected.affected_service == candidate.affected_service
    assert selected.description == candidate.description
    assert selected.rationale == candidate.rationale
    assert selected.risk_level is candidate.risk_level
    assert (
        selected.requires_approval
        is candidate.requires_approval
    )
    assert (
        selected.supporting_evidence
        == candidate.supporting_evidence
    )
    assert (
        selected.verification_steps
        == candidate.verification_steps
    )
    assert (
        selected.rollback_guidance
        == candidate.rollback_guidance
    )


def test_unknown_action_id_is_rejected():
    provider = FakeProvider(
        response=json.dumps(
            {
                "selection": {
                    "action_id": "invented-action",
                    "explanation": "test",
                },
                "abstain": False,
                "abstention_reason": None,
            }
        )
    )

    selector = EvidenceConstrainedRemediationSelector(
        provider=provider
    )

    with pytest.raises(
        RemediationSelectionOutputError,
        match="unknown remediation action ID",
    ):
        selector.select(
            constraints=make_constraints()
        )


def test_explicit_model_abstention_is_supported():
    provider = FakeProvider(
        response=json.dumps(
            {
                "selection": None,
                "abstain": True,
                "abstention_reason": (
                    "Prefer additional operator review."
                ),
            }
        )
    )

    outcome = EvidenceConstrainedRemediationSelector(
        provider=provider
    ).select(
        constraints=make_constraints()
    )

    assert outcome.abstained is True
    assert outcome.selection is None
    assert outcome.abstention_reason is not None


def test_blocked_policy_never_calls_model():
    provider = FakeProvider(
        response="should-not-be-used"
    )

    constraints = RemediationPlanConstraints(
        incident_id="inc-test",
        affected_service="processor",
        diagnosis_candidate_id=None,
        candidates=(),
        blocked_reason=(
            "Diagnostic reasoner abstained."
        ),
    )

    outcome = EvidenceConstrainedRemediationSelector(
        provider=provider
    ).select(
        constraints=constraints
    )

    assert outcome.abstained is True
    assert outcome.selection is None
    assert provider.calls == 0


def test_empty_candidate_set_never_calls_model():
    provider = FakeProvider(
        response="should-not-be-used"
    )

    constraints = RemediationPlanConstraints(
        incident_id="inc-test",
        affected_service="processor",
        diagnosis_candidate_id=None,
        candidates=(),
    )

    outcome = EvidenceConstrainedRemediationSelector(
        provider=provider
    ).select(
        constraints=constraints
    )

    assert outcome.abstained is True
    assert provider.calls == 0


def test_provider_failure_is_wrapped():
    provider = FakeProvider(
        error=ModelProviderError(
            "model unavailable"
        )
    )

    selector = EvidenceConstrainedRemediationSelector(
        provider=provider
    )

    with pytest.raises(
        RemediationSelectionProviderError,
        match="provider failed",
    ):
        selector.select(
            constraints=make_constraints()
        )


def test_malformed_json_is_rejected():
    provider = FakeProvider(
        response="not-json"
    )

    selector = EvidenceConstrainedRemediationSelector(
        provider=provider
    )

    with pytest.raises(
        RemediationSelectionOutputError,
        match="malformed JSON",
    ):
        selector.select(
            constraints=make_constraints()
        )


def test_extra_model_fields_are_rejected():
    provider = FakeProvider(
        response=json.dumps(
            {
                "selection": {
                    "action_id": (
                        "processor-rolling-restart"
                    ),
                    "explanation": "test",
                    "kubectl_command": (
                        "kubectl rollout restart ..."
                    ),
                },
                "abstain": False,
                "abstention_reason": None,
            }
        )
    )

    selector = EvidenceConstrainedRemediationSelector(
        provider=provider
    )

    with pytest.raises(
        RemediationSelectionOutputError,
        match="schema validation",
    ):
        selector.select(
            constraints=make_constraints()
        )


def test_prompt_contains_no_execution_authority():
    provider = FakeProvider(
        response=json.dumps(
            {
                "selection": {
                    "action_id": (
                        "processor-rolling-restart"
                    ),
                    "explanation": "test",
                },
                "abstain": False,
                "abstention_reason": None,
            }
        )
    )

    selector = EvidenceConstrainedRemediationSelector(
        provider=provider
    )

    selector.select(
        constraints=make_constraints()
    )

    assert provider.system_prompt is not None

    prompt = provider.system_prompt.casefold()

    assert "never generate shell commands" in prompt
    assert "never claim that an action has been executed" in prompt

    payload = json.loads(
        provider.user_prompt
    )

    assert payload["candidates"][0][
        "requires_approval"
    ] is True
