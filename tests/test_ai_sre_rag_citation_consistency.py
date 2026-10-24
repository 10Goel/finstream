import json

import pytest

from services.ai_sre_agent.models import (
    Evidence,
    EvidenceSource,
    EvidenceTrustLevel,
)
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


def make_context():
    return Evidence(
        incident_id="inc-citation-consistency",
        source=EvidenceSource.RUNBOOK,
        tool="retrieve_approved_runbook",
        summary=(
            "Approved processor runbook. "
            "Documentation context only."
        ),
        trust_level=(
            EvidenceTrustLevel.DOCUMENTATION_CONTEXT
        ),
        raw_reference=(
            "docs/runbooks/processor-unavailable.md"
        ),
        metadata={
            "runbook_id": "RB-PROCESSOR-001",
            "title": "Processor Unavailable",
            "version": "1.0.0",
            "sha256": "a" * 64,
            "path": "processor-unavailable.md",
            "retrieval_score": 135,
            "matched_terms": [
                "processor",
                "unavailable",
            ],
            "retrieval_reasons": [
                "affected_service_match",
                "exact_alert_match",
            ],
            "content": (
                "Investigate processor availability "
                "using live operational evidence."
            ),
        },
        evidence_id="ctx-runbook-processor",
    )


def response(
    *,
    explanation,
    context_ids,
):
    return json.dumps(
        {
            "selections": [
                {
                    "candidate_id": (
                        "processor-immediate-unavailable"
                    ),
                    "confidence": 0.90,
                    "explanation": explanation,
                    "documentation_context_ids": (
                        context_ids
                    ),
                }
            ],
            "abstain": False,
            "abstention_reason": None,
        }
    )


class SequenceProvider:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = 0

    def generate(
        self,
        *,
        system_prompt,
        user_prompt,
    ):
        del system_prompt
        del user_prompt

        result = self.responses[self.calls]
        self.calls += 1

        return result


def test_documentation_claim_without_citation_is_repaired():
    provider = SequenceProvider(
        [
            response(
                explanation=(
                    "The documentation context supports "
                    "the operational interpretation."
                ),
                context_ids=[],
            ),
            response(
                explanation=(
                    "The runbook provides procedural "
                    "context for the observed condition."
                ),
                context_ids=[
                    "ctx-runbook-processor"
                ],
            ),
        ]
    )

    outcome = EvidenceConstrainedReasoner(
        provider=provider
    ).select(
        constraints=make_constraints(),
        documentation_context=(
            make_context(),
        ),
    )

    assert provider.calls == 2

    citation = (
        outcome.selections[0]
        .runbook_citations[0]
    )

    assert (
        citation.runbook_id
        == "RB-PROCESSOR-001"
    )


def test_no_documentation_claim_requires_no_citation():
    provider = SequenceProvider(
        [
            response(
                explanation=(
                    "The direct operational observations "
                    "support the deterministic candidate."
                ),
                context_ids=[],
            )
        ]
    )

    outcome = EvidenceConstrainedReasoner(
        provider=provider
    ).select(
        constraints=make_constraints(),
        documentation_context=(
            make_context(),
        ),
    )

    assert provider.calls == 1

    assert (
        outcome.selections[0]
        .runbook_citations
        == ()
    )


def test_repeated_uncited_documentation_claim_fails_closed():
    invalid = response(
        explanation=(
            "The runbook supports this selection."
        ),
        context_ids=[],
    )

    provider = SequenceProvider(
        [
            invalid,
            invalid,
        ]
    )

    with pytest.raises(
        CandidateSelectionOutputError,
        match="bounded repair",
    ):
        EvidenceConstrainedReasoner(
            provider=provider
        ).select(
            constraints=make_constraints(),
            documentation_context=(
                make_context(),
            ),
        )

    assert provider.calls == 2


def test_documented_synonym_without_citation_is_repaired():
    provider = SequenceProvider(
        [
            response(
                explanation=(
                    "The candidate is supported by the "
                    "documented operational context."
                ),
                context_ids=[],
            ),
            response(
                explanation=(
                    "The supplied operational observations "
                    "support the deterministic candidate."
                ),
                context_ids=[],
            ),
        ]
    )

    outcome = EvidenceConstrainedReasoner(
        provider=provider
    ).select(
        constraints=make_constraints(),
        documentation_context=(
            make_context(),
        ),
    )

    assert provider.calls == 2

    selected = outcome.selections[0]

    assert selected.runbook_citations == ()

    assert (
        "document"
        not in selected.model_rationale.casefold()
    )


def test_citation_repair_receives_exact_allowed_context_id():
    class DiagnosticRepairProvider:
        def __init__(self):
            self.calls = 0
            self.second_system_prompt = None

        def generate(
            self,
            *,
            system_prompt,
            user_prompt,
        ):
            del user_prompt

            self.calls += 1

            if self.calls == 1:
                return response(
                    explanation=(
                        "The documented operational context "
                        "supports this candidate."
                    ),
                    context_ids=[],
                )

            self.second_system_prompt = system_prompt

            assert (
                "ctx-runbook-processor"
                in system_prompt
            )

            assert (
                "documentation_context_ids"
                in system_prompt
            )

            return response(
                explanation=(
                    "The documented operational context "
                    "supports this candidate."
                ),
                context_ids=[
                    "ctx-runbook-processor"
                ],
            )

    provider = DiagnosticRepairProvider()

    outcome = EvidenceConstrainedReasoner(
        provider=provider
    ).select(
        constraints=make_constraints(),
        documentation_context=(
            make_context(),
        ),
    )

    assert provider.calls == 2

    selected = outcome.selections[0]

    assert len(
        selected.runbook_citations
    ) == 1

    assert (
        selected.runbook_citations[0].runbook_id
        == "RB-PROCESSOR-001"
    )
