from dataclasses import replace
from pathlib import Path

import pytest

from services.ai_sre_agent.models import (
    AlertStatus,
    EvidenceSource,
    EvidenceTrustLevel,
    Incident,
)
from services.ai_sre_agent.retrieval import (
    DeterministicRunbookRetriever,
    RunbookCatalog,
    RunbookContextBuilder,
    RunbookContextError,
)

ROOT = Path(__file__).resolve().parents[1]


def make_incident():
    return Incident(
        fingerprint="rag-context-test",
        alert_name="FinStreamServiceDown",
        alert_status=AlertStatus.FIRING,
        severity="critical",
        affected_service="processor",
        summary=(
            "Processor workload is unavailable while "
            "Kafka and PostgreSQL remain healthy."
        ),
    )


def retrieve(incident):
    catalog = RunbookCatalog.load(
        repository_root=ROOT
    )

    retriever = DeterministicRunbookRetriever(
        catalog=catalog
    )

    return retriever.retrieve(
        incident=incident
    )


def test_context_preserves_runbook_provenance():
    incident = make_incident()

    retrieval = retrieve(incident)

    bundle = RunbookContextBuilder.build(
        incident=incident,
        retrieval=retrieval,
    )

    assert bundle.incident_id == incident.incident_id
    assert bundle.evidence

    first = bundle.evidence[0]

    assert first.source is EvidenceSource.RUNBOOK
    assert (
        first.trust_level
        is EvidenceTrustLevel.DOCUMENTATION_CONTEXT
    )

    assert (
        first.metadata["runbook_id"]
        == "RB-PROCESSOR-001"
    )

    assert len(first.metadata["sha256"]) == 64

    assert first.raw_reference == (
        "docs/runbooks/processor-unavailable.md"
    )


def test_context_removes_generic_terms_from_provenance():
    incident = make_incident()

    bundle = RunbookContextBuilder.build(
        incident=incident,
        retrieval=retrieve(incident),
    )

    terms = set(
        bundle.evidence[0].metadata[
            "matched_terms"
        ]
    )

    assert "processor" in terms
    assert "unavailable" in terms

    assert "and" not in terms
    assert "is" not in terms
    assert "while" not in terms
    assert "fin" not in terms
    assert "stream" not in terms


def test_context_is_explicitly_documentation_only():
    incident = make_incident()

    bundle = RunbookContextBuilder.build(
        incident=incident,
        retrieval=retrieve(incident),
    )

    first = bundle.evidence[0]

    assert first.service is None

    assert (
        "does not establish current runtime state"
        in first.summary
    )

    assert first.metadata["content"]


def test_different_incident_retrieval_is_rejected():
    incident = make_incident()

    retrieval = retrieve(incident)

    mismatched = replace(
        retrieval,
        incident_id="inc-different",
    )

    with pytest.raises(
        RunbookContextError,
        match="different incident",
    ):
        RunbookContextBuilder.build(
            incident=incident,
            retrieval=mismatched,
        )
