from dataclasses import replace
from pathlib import Path

from services.ai_sre_agent.models import (
    AlertStatus,
    Incident,
)
from services.ai_sre_agent.retrieval import (
    DeterministicRunbookRetriever,
    RunbookCatalog,
    RunbookStatus,
)

REPOSITORY_ROOT = (
    Path(__file__).resolve().parents[1]
)


def load_retriever():
    catalog = RunbookCatalog.load(
        repository_root=REPOSITORY_ROOT
    )

    return DeterministicRunbookRetriever(
        catalog=catalog
    )


def make_incident(
    *,
    alert_name,
    service,
    summary,
):
    return Incident(
        fingerprint=(
            f"retrieval-{alert_name}-{service}"
        ),
        alert_name=alert_name,
        alert_status=AlertStatus.FIRING,
        severity="critical",
        affected_service=service,
        summary=summary,
    )


def test_processor_outage_retrieves_processor_runbook_first():
    incident = make_incident(
        alert_name="FinStreamServiceDown",
        service="processor",
        summary=(
            "Processor workload is unavailable."
        ),
    )

    result = load_retriever().retrieve(
        incident=incident
    )

    assert result.matches

    assert (
        result.matches[0].runbook_id
        == "RB-PROCESSOR-001"
    )

    assert (
        "exact_alert_match"
        in result.matches[0].reasons
    )


def test_dlq_alert_retrieves_dlq_runbook_first():
    incident = make_incident(
        alert_name="FinStreamDLQActivity",
        service="processor",
        summary=(
            "Processor dead-letter queue "
            "activity increased."
        ),
    )

    result = load_retriever().retrieve(
        incident=incident
    )

    assert result.matches

    assert (
        result.matches[0].runbook_id
        == "RB-DLQ-001"
    )


def test_api_latency_retrieves_api_runbook_first():
    incident = make_incident(
        alert_name="FinStreamHighAPILatency",
        service="api",
        summary=(
            "API p95 latency is above "
            "the alert threshold."
        ),
    )

    result = load_retriever().retrieve(
        incident=incident
    )

    assert result.matches

    assert (
        result.matches[0].runbook_id
        == "RB-API-001"
    )


def test_generic_processor_outage_still_matches_by_context():
    incident = make_incident(
        alert_name="SyntheticProcessorOutage",
        service="processor",
        summary=(
            "Processor workload unavailable."
        ),
    )

    result = load_retriever().retrieve(
        incident=incident
    )

    assert result.matches

    assert (
        result.matches[0].runbook_id
        == "RB-PROCESSOR-001"
    )


def test_top_k_is_enforced():
    incident = make_incident(
        alert_name="SyntheticDependencyIncident",
        service="processor",
        summary=(
            "Processor Kafka dependency "
            "impairment investigation."
        ),
    )

    result = load_retriever().retrieve(
        incident=incident,
        top_k=1,
    )

    assert len(result.matches) == 1


def test_retired_runbooks_are_not_retrieved():
    catalog = RunbookCatalog.load(
        repository_root=REPOSITORY_ROOT
    )

    retired_documents = tuple(
        replace(
            document,
            status=RunbookStatus.RETIRED,
        )
        for document in catalog.documents
    )

    retired_catalog = RunbookCatalog(
        documents=retired_documents
    )

    retriever = DeterministicRunbookRetriever(
        catalog=retired_catalog
    )

    incident = make_incident(
        alert_name="FinStreamServiceDown",
        service="processor",
        summary=(
            "Processor workload unavailable."
        ),
    )

    result = retriever.retrieve(
        incident=incident
    )

    assert result.matches == ()
