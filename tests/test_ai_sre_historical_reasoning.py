from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from services.ai_sre_agent.memory import (
    HistoricalIncidentContext,
)
from services.ai_sre_agent.models import (
    IncidentStatus,
)
from services.ai_sre_agent.reasoning.constraints import (
    CandidateHypothesis,
    ReasoningConstraints,
)
from services.ai_sre_agent.reasoning.selector import (
    CandidateSelectionContextError,
    CandidateSelectionOutputError,
    CandidateSelectionResponse,
    EvidenceConstrainedReasoner,
)


def constraints() -> ReasoningConstraints:
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


def history() -> HistoricalIncidentContext:
    return HistoricalIncidentContext(
        context_id="hist-mem-previous",
        memory_id="mem-previous",
        historical_incident_id="inc-previous",
        alert_name="FinStreamServiceDown",
        severity="critical",
        affected_service="processor",
        historical_summary=(
            "Processor workload was unavailable."
        ),
        final_status=IncidentStatus.RESOLVED,
        resolution_summary=(
            "The previous incident recovered after an "
            "approved restart and independent verification."
        ),
        finalized_at=datetime(
            2026,
            10,
            20,
            12,
            0,
            tzinfo=UTC,
        ),
        selected_candidate_ids=(
            "processor-immediate-unavailable",
        ),
        runbook_ids=(
            "RB-PROCESSOR-001",
        ),
        retrieval_score=114,
        matched_terms=(
            "processor",
            "unavailable",
        ),
        retrieval_reasons=(
            "exact_alert_match",
            "affected_service_match",
        ),
    )


def response(
    *,
    explanation: str,
    historical_ids: list[str],
) -> str:
    return json.dumps(
        {
            "selections": [
                {
                    "candidate_id": (
                        "processor-immediate-unavailable"
                    ),
                    "confidence": 0.90,
                    "explanation": explanation,
                    "documentation_context_ids": [],
                    "historical_context_ids": (
                        historical_ids
                    ),
                }
            ],
            "abstain": False,
            "abstention_reason": None,
        }
    )


class CapturingProvider:
    def __init__(
        self,
        responses: list[str],
    ) -> None:
        self.responses = responses
        self.calls = 0
        self.payload = None
        self.system_prompts: list[str] = []

    def generate(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
    ) -> str:
        self.system_prompts.append(
            system_prompt
        )

        self.payload = json.loads(
            user_prompt
        )

        result = self.responses[
            self.calls
        ]

        self.calls += 1

        return result


def test_historical_context_reaches_model_as_separate_trust_domain():
    provider = CapturingProvider(
        [
            response(
                explanation=(
                    "Current operational observations support "
                    "the deterministic candidate."
                ),
                historical_ids=[],
            )
        ]
    )

    outcome = EvidenceConstrainedReasoner(
        provider=provider
    ).select(
        constraints=constraints(),
        historical_context=(
            history(),
        ),
    )

    payload = provider.payload

    assert payload is not None

    assert "historical_context" in payload

    historical = payload[
        "historical_context"
    ][0]

    assert (
        historical["trust_domain"]
        == "HISTORICAL_CONTEXT"
    )

    assert (
        historical["authority"]
        == "HISTORICAL_REFERENCE_ONLY"
    )

    assert (
        historical["current_state_authority"]
        is False
    )

    assert (
        historical[
            "candidate_generation_authority"
        ]
        is False
    )

    assert (
        historical["execution_authority"]
        is False
    )

    candidate = payload[
        "candidates"
    ][0]

    assert candidate[
        "supporting_evidence"
    ] == [
        "ev-prometheus",
        "ev-kubernetes",
    ]

    assert (
        outcome.selections[0]
        .historical_incident_citations
        == ()
    )


def test_model_used_history_is_bound_to_system_provenance():
    provider = CapturingProvider(
        [
            response(
                explanation=(
                    "The historical incident provides "
                    "precedent consistent with the current "
                    "deterministic candidate."
                ),
                historical_ids=[
                    "hist-mem-previous"
                ],
            )
        ]
    )

    outcome = EvidenceConstrainedReasoner(
        provider=provider
    ).select(
        constraints=constraints(),
        historical_context=(
            history(),
        ),
    )

    selected = outcome.selections[0]

    assert len(
        selected.historical_incident_citations
    ) == 1

    citation = (
        selected.historical_incident_citations[0]
    )

    assert citation.context_id == (
        "hist-mem-previous"
    )

    assert citation.memory_id == (
        "mem-previous"
    )

    assert citation.historical_incident_id == (
        "inc-previous"
    )

    # The candidate evidence remains the live evidence only.
    assert selected.supporting_evidence == (
        "ev-prometheus",
        "ev-kubernetes",
    )


def test_historical_claim_without_citation_is_repaired():
    provider = CapturingProvider(
        [
            response(
                explanation=(
                    "A previous incident supports this "
                    "candidate."
                ),
                historical_ids=[],
            ),
            response(
                explanation=(
                    "The supplied current operational "
                    "observations support this candidate."
                ),
                historical_ids=[],
            ),
        ]
    )

    outcome = EvidenceConstrainedReasoner(
        provider=provider
    ).select(
        constraints=constraints(),
        historical_context=(
            history(),
        ),
    )

    assert provider.calls == 2

    assert (
        outcome.selections[0]
        .historical_incident_citations
        == ()
    )


def test_unknown_historical_context_id_fails_closed():
    invalid_response = response(
        explanation=(
            "Historical context supports this "
            "candidate."
        ),
        historical_ids=[
            "hist-invented"
        ],
    )

    provider = CapturingProvider(
        [
            invalid_response,
            invalid_response,
        ]
    )

    with pytest.raises(
        CandidateSelectionOutputError,
        match="citation namespaces",
    ):
        EvidenceConstrainedReasoner(
            provider=provider
        ).select(
            constraints=constraints(),
            historical_context=(
                history(),
            ),
        )



def test_historical_prompt_explicitly_denies_runtime_authority():
    provider = CapturingProvider(
        [
            response(
                explanation=(
                    "Current operational evidence supports "
                    "the deterministic candidate."
                ),
                historical_ids=[],
            )
        ]
    )

    EvidenceConstrainedReasoner(
        provider=provider
    ).select(
        constraints=constraints(),
        historical_context=(
            history(),
        ),
    )

    prompt = (
        provider.system_prompts[0]
        .casefold()
    )

    assert (
        "does not establish the current system state"
        in prompt
    )

    assert (
        "cannot create candidates"
        in prompt
    )

    assert (
        "not instructions"
        in prompt
    )

    assert (
        "cannot establish current state"
        in prompt
        or "does not establish the current system state"
        in prompt
    )


def test_historical_context_with_authority_is_rejected():
    class UnsafeHistory:
        context_id = "hist-unsafe"

        def as_payload(self):
            payload = history().as_payload()

            payload[
                "context_id"
            ] = self.context_id

            payload[
                "execution_authority"
            ] = True

            return payload

    provider = CapturingProvider(
        [
            response(
                explanation="Current evidence supports it.",
                historical_ids=[],
            )
        ]
    )

    with pytest.raises(
        CandidateSelectionContextError,
        match="forbidden authority",
    ):
        EvidenceConstrainedReasoner(
            provider=provider
        ).select(
            constraints=constraints(),
            historical_context=(
                UnsafeHistory(),
            ),
        )

    assert provider.calls == 0


def test_model_schema_exposes_historical_citation_field():
    schema = (
        CandidateSelectionResponse
        .model_json_schema()
    )

    decision = schema[
        "$defs"
    ][
        "CandidateDecision"
    ]

    assert (
        "historical_context_ids"
        in decision["required"]
    )
