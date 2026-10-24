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


def make_documentation():
    return Evidence(
        incident_id="inc-rag-citation",
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
                "Investigate processor availability "
                "using live evidence."
            ),
        },
        evidence_id="ctx-runbook-processor",
    )


class CitingProvider:
    def generate(
        self,
        *,
        system_prompt,
        user_prompt,
    ):
        payload = json.loads(user_prompt)

        candidate_id = payload[
            "candidates"
        ][0]["candidate_id"]

        context_id = payload[
            "documentation_context"
        ][0]["context_id"]

        return json.dumps(
            {
                "selections": [
                    {
                        "candidate_id": candidate_id,
                        "confidence": 0.91,
                        "explanation": (
                            "Live evidence establishes the "
                            "processor outage; the approved "
                            "runbook provides recovery context."
                        ),
                        "documentation_context_ids": [
                            context_id
                        ],
                    }
                ],
                "abstain": False,
                "abstention_reason": None,
            }
        )


class UnknownCitationProvider:
    def generate(
        self,
        *,
        system_prompt,
        user_prompt,
    ):
        payload = json.loads(user_prompt)

        candidate_id = payload[
            "candidates"
        ][0]["candidate_id"]

        return json.dumps(
            {
                "selections": [
                    {
                        "candidate_id": candidate_id,
                        "confidence": 0.90,
                        "explanation": (
                            "Attempting an invented citation."
                        ),
                        "documentation_context_ids": [
                            "ctx-invented"
                        ],
                    }
                ],
                "abstain": False,
                "abstention_reason": None,
            }
        )


class ForgedProvenanceProvider:
    def generate(
        self,
        *,
        system_prompt,
        user_prompt,
    ):
        payload = json.loads(user_prompt)

        candidate_id = payload[
            "candidates"
        ][0]["candidate_id"]

        return json.dumps(
            {
                "selections": [
                    {
                        "candidate_id": candidate_id,
                        "confidence": 0.90,
                        "explanation": (
                            "Attempting to forge provenance."
                        ),
                        "documentation_context_ids": [
                            "ctx-runbook-processor"
                        ],
                        "runbook_id": "RB-EVIL-999",
                    }
                ],
                "abstain": False,
                "abstention_reason": None,
            }
        )


class NoCitationProvider:
    def generate(
        self,
        *,
        system_prompt,
        user_prompt,
    ):
        payload = json.loads(user_prompt)

        candidate_id = payload[
            "candidates"
        ][0]["candidate_id"]

        return json.dumps(
            {
                "selections": [
                    {
                        "candidate_id": candidate_id,
                        "confidence": 0.88,
                        "explanation": (
                            "Selection is based only on live "
                            "operational evidence."
                        ),
                        "documentation_context_ids": [],
                    }
                ],
                "abstain": False,
                "abstention_reason": None,
            }
        )


def test_model_context_id_binds_to_trusted_provenance():
    outcome = EvidenceConstrainedReasoner(
        provider=CitingProvider()
    ).select(
        constraints=make_constraints(),
        documentation_context=(
            make_documentation(),
        ),
    )

    selected = outcome.selections[0]

    assert len(
        selected.runbook_citations
    ) == 1

    citation = selected.runbook_citations[0]

    assert (
        citation.context_id
        == "ctx-runbook-processor"
    )
    assert (
        citation.runbook_id
        == "RB-PROCESSOR-001"
    )
    assert citation.version == "1.0.0"
    assert citation.sha256 == "a" * 64
    assert (
        citation.path
        == "processor-unavailable.md"
    )
    assert citation.retrieval_score == 136

    assert selected.supporting_evidence == (
        "ev-prometheus",
        "ev-kubernetes",
    )


def test_unknown_context_id_is_rejected():
    with pytest.raises(
        CandidateSelectionOutputError,
        match="unknown documentation context ID",
    ):
        EvidenceConstrainedReasoner(
            provider=UnknownCitationProvider()
        ).select(
            constraints=make_constraints(),
            documentation_context=(
                make_documentation(),
            ),
        )


def test_model_cannot_forge_runbook_provenance():
    with pytest.raises(
        CandidateSelectionOutputError,
        match="schema validation",
    ):
        EvidenceConstrainedReasoner(
            provider=ForgedProvenanceProvider()
        ).select(
            constraints=make_constraints(),
            documentation_context=(
                make_documentation(),
            ),
        )


def test_empty_citations_do_not_change_operational_evidence():
    outcome = EvidenceConstrainedReasoner(
        provider=NoCitationProvider()
    ).select(
        constraints=make_constraints(),
        documentation_context=(
            make_documentation(),
        ),
    )

    selected = outcome.selections[0]

    assert selected.runbook_citations == ()

    assert selected.supporting_evidence == (
        "ev-prometheus",
        "ev-kubernetes",
    )

    assert (
        "ctx-runbook-processor"
        not in selected.supporting_evidence
    )
