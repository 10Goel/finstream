import json
from dataclasses import replace

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
    CandidateSelectionContextError,
    EvidenceConstrainedReasoner,
)


class CapturingProvider:
    def __init__(self):
        self.payload = None
        self.system_prompt = None

    def generate(
        self,
        *,
        system_prompt,
        user_prompt,
    ):
        self.system_prompt = system_prompt
        self.payload = json.loads(
            user_prompt
        )

        candidate = self.payload[
            "candidates"
        ][0]

        return json.dumps(
            {
                "selections": [
                    {
                        "candidate_id": (
                            candidate["candidate_id"]
                        ),
                        "confidence": 0.90,
                        "explanation": (
                            "Live evidence supports the "
                            "deterministic candidate; the "
                            "runbook provides operational "
                            "procedure context only."
                        ),
                    }
                ],
                "abstain": False,
                "abstention_reason": None,
            }
        )


def constraints():
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
                    "not established by supplied evidence."
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


def documentation():
    return Evidence(
        incident_id="inc-rag-test",
        source=EvidenceSource.RUNBOOK,
        tool="retrieve_approved_runbook",
        summary=(
            "Approved processor runbook. Documentation "
            "context only."
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
            "retrieval_score": 136,
            "matched_terms": [
                "processor",
                "unavailable",
            ],
            "retrieval_reasons": [
                "affected_service_match",
                "exact_alert_match",
            ],
            "content": (
                "Investigate the processor using live "
                "operational diagnostics. A runbook does "
                "not establish current system state."
            ),
        },
        evidence_id="ctx-runbook-processor",
    )


def test_rag_context_reaches_model_without_changing_candidate_evidence():
    provider = CapturingProvider()

    reasoner = EvidenceConstrainedReasoner(
        provider=provider
    )

    result = reasoner.select(
        constraints=constraints(),
        documentation_context=(
            documentation(),
        ),
    )

    assert provider.payload is not None

    docs = provider.payload[
        "documentation_context"
    ]

    assert len(docs) == 1

    assert (
        docs[0]["runbook_id"]
        == "RB-PROCESSOR-001"
    )

    candidate = provider.payload[
        "candidates"
    ][0]

    assert candidate[
        "supporting_evidence"
    ] == [
        "ev-prometheus",
        "ev-kubernetes",
    ]

    selected = result.selections[0]

    assert selected.supporting_evidence == (
        "ev-prometheus",
        "ev-kubernetes",
    )

    assert (
        "ctx-runbook-processor"
        not in selected.supporting_evidence
    )


def test_runbook_prompt_is_explicitly_non_authoritative():
    provider = CapturingProvider()

    reasoner = EvidenceConstrainedReasoner(
        provider=provider
    )

    reasoner.select(
        constraints=constraints(),
        documentation_context=(
            documentation(),
        ),
    )

    assert provider.system_prompt is not None

    prompt = provider.system_prompt.casefold()

    assert (
        "does not establish current state"
        in prompt
    )

    assert (
        "cannot add candidates"
        in prompt
    )

    assert (
        "not instructions"
        in prompt
    )


def test_direct_observation_cannot_enter_documentation_context():
    bad = replace(
        documentation(),
        trust_level=(
            EvidenceTrustLevel.DIRECT_OBSERVATION
        ),
    )

    with pytest.raises(
        CandidateSelectionContextError,
        match="DOCUMENTATION_CONTEXT",
    ):
        EvidenceConstrainedReasoner(
            provider=CapturingProvider()
        ).select(
            constraints=constraints(),
            documentation_context=(bad,),
        )
