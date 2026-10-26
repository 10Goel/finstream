from __future__ import annotations

from dataclasses import replace

from services.ai_sre_agent.memory import (
    DeterministicIncidentMemoryRetriever,
    SQLiteIncidentMemoryStore,
)
from services.ai_sre_agent.models import (
    AlertStatus,
    Incident,
    IncidentStatus,
)
from services.ai_sre_agent.reasoning.selector import (
    CandidateSelectionOutcome,
    SelectedCandidate,
)


def make_incident(
    *,
    fingerprint: str,
    alert_name: str,
    service: str,
    summary: str,
    severity: str = "critical",
) -> Incident:
    return Incident(
        fingerprint=fingerprint,
        alert_name=alert_name,
        alert_status=AlertStatus.FIRING,
        severity=severity,
        affected_service=service,
        summary=summary,
        status=IncidentStatus.DIAGNOSED,
    )


def make_selection(
    *,
    candidate_id: str,
) -> CandidateSelectionOutcome:
    selected = SelectedCandidate(
        candidate_id=candidate_id,
        statement=(
            "Bounded deterministic historical candidate."
        ),
        confidence=0.95,
        model_rationale=(
            "Selected from current operational evidence."
        ),
        supporting_evidence=(
            "ev-runtime-1",
        ),
        contradicting_evidence=(),
        runbook_citations=(),
    )

    return CandidateSelectionOutcome(
        selections=(selected,),
        abstained=False,
        abstention_reason=None,
    )


def persist_finalized(
    *,
    store: SQLiteIncidentMemoryStore,
    incident: Incident,
    candidate_id: str,
) -> None:
    store.record_investigation(
        incident=incident,
        selection=make_selection(
            candidate_id=candidate_id
        ),
    )

    store.finalize(
        incident_id=incident.incident_id,
        final_status=IncidentStatus.RESOLVED,
        resolution_summary=(
            "Historical incident resolved and "
            "independently verified."
        ),
    )


def test_exact_processor_history_is_ranked_first(
    tmp_path,
):
    store = SQLiteIncidentMemoryStore(
        tmp_path / "memory.db"
    )

    processor = make_incident(
        fingerprint="historical-processor",
        alert_name="FinStreamServiceDown",
        service="processor",
        summary="Processor workload unavailable.",
    )

    kafka = make_incident(
        fingerprint="historical-kafka",
        alert_name="FinStreamServiceDown",
        service="kafka",
        summary="Kafka broker unavailable.",
    )

    persist_finalized(
        store=store,
        incident=processor,
        candidate_id=(
            "processor-immediate-unavailable"
        ),
    )

    persist_finalized(
        store=store,
        incident=kafka,
        candidate_id=(
            "kafka-immediate-unavailable"
        ),
    )

    current = make_incident(
        fingerprint="current-processor",
        alert_name="FinStreamServiceDown",
        service="processor",
        summary=(
            "Processor workload is unavailable."
        ),
    )

    result = (
        DeterministicIncidentMemoryRetriever(
            store=store
        ).retrieve(
            incident=current
        )
    )

    assert result.matches

    assert (
        result.matches[0].incident_id
        == processor.incident_id
    )

    assert (
        "exact_alert_match"
        in result.matches[0].reasons
    )

    assert (
        "affected_service_match"
        in result.matches[0].reasons
    )


def test_exact_fingerprint_has_strongest_weight(
    tmp_path,
):
    store = SQLiteIncidentMemoryStore(
        tmp_path / "memory.db"
    )

    fingerprint_match = make_incident(
        fingerprint="repeat-fingerprint",
        alert_name="HistoricalAlert",
        service="api",
        summary="Historical API condition.",
    )

    service_alert_match = make_incident(
        fingerprint="different-fingerprint",
        alert_name="FinStreamServiceDown",
        service="processor",
        summary="Processor unavailable.",
    )

    persist_finalized(
        store=store,
        incident=fingerprint_match,
        candidate_id="historical-repeat",
    )

    persist_finalized(
        store=store,
        incident=service_alert_match,
        candidate_id=(
            "processor-immediate-unavailable"
        ),
    )

    current = make_incident(
        fingerprint="repeat-fingerprint",
        alert_name="FinStreamServiceDown",
        service="processor",
        summary="Processor unavailable.",
    )

    result = (
        DeterministicIncidentMemoryRetriever(
            store=store
        ).retrieve(
            incident=current
        )
    )

    assert result.matches

    assert (
        result.matches[0].incident_id
        == fingerprint_match.incident_id
    )

    assert (
        "exact_fingerprint_match"
        in result.matches[0].reasons
    )


def test_current_incident_never_retrieves_itself(
    tmp_path,
):
    store = SQLiteIncidentMemoryStore(
        tmp_path / "memory.db"
    )

    current = make_incident(
        fingerprint="self-fingerprint",
        alert_name="FinStreamServiceDown",
        service="processor",
        summary="Processor unavailable.",
    )

    persist_finalized(
        store=store,
        incident=current,
        candidate_id=(
            "processor-immediate-unavailable"
        ),
    )

    result = (
        DeterministicIncidentMemoryRetriever(
            store=store
        ).retrieve(
            incident=current
        )
    )

    assert all(
        match.incident_id
        != current.incident_id
        for match in result.matches
    )


def test_unfinalized_memory_is_not_retrieved(
    tmp_path,
):
    store = SQLiteIncidentMemoryStore(
        tmp_path / "memory.db"
    )

    historical = make_incident(
        fingerprint="unfinished-history",
        alert_name="FinStreamServiceDown",
        service="processor",
        summary="Processor unavailable.",
    )

    store.record_investigation(
        incident=historical,
        selection=make_selection(
            candidate_id=(
                "processor-immediate-unavailable"
            )
        ),
    )

    current = replace(
        historical,
        incident_id="inc-current",
        fingerprint="current-fingerprint",
    )

    result = (
        DeterministicIncidentMemoryRetriever(
            store=store,
            minimum_score=0,
        ).retrieve(
            incident=current
        )
    )

    assert result.matches == ()


def test_irrelevant_history_below_threshold_is_excluded(
    tmp_path,
):
    store = SQLiteIncidentMemoryStore(
        tmp_path / "memory.db"
    )

    historical = make_incident(
        fingerprint="historical-api",
        alert_name="FinStreamHighAPILatency",
        service="api",
        summary="API latency elevated.",
        severity="warning",
    )

    persist_finalized(
        store=store,
        incident=historical,
        candidate_id="api-latency",
    )

    current = make_incident(
        fingerprint="current-kafka",
        alert_name="KafkaReplicationFault",
        service="kafka",
        summary="Broker replication degraded.",
        severity="critical",
    )

    result = (
        DeterministicIncidentMemoryRetriever(
            store=store
        ).retrieve(
            incident=current
        )
    )

    assert result.matches == ()


def test_top_k_is_enforced(
    tmp_path,
):
    store = SQLiteIncidentMemoryStore(
        tmp_path / "memory.db"
    )

    for index in range(4):
        historical = make_incident(
            fingerprint=f"history-{index}",
            alert_name="FinStreamServiceDown",
            service="processor",
            summary=(
                "Processor workload unavailable."
            ),
        )

        persist_finalized(
            store=store,
            incident=historical,
            candidate_id=(
                "processor-immediate-unavailable"
            ),
        )

    current = make_incident(
        fingerprint="current",
        alert_name="FinStreamServiceDown",
        service="processor",
        summary="Processor workload unavailable.",
    )

    result = (
        DeterministicIncidentMemoryRetriever(
            store=store
        ).retrieve(
            incident=current,
            top_k=2,
        )
    )

    assert len(result.matches) == 2


def test_retrieval_exposes_explainable_score_reasons(
    tmp_path,
):
    store = SQLiteIncidentMemoryStore(
        tmp_path / "memory.db"
    )

    historical = make_incident(
        fingerprint="old",
        alert_name="FinStreamServiceDown",
        service="processor",
        summary=(
            "Processor workload unavailable."
        ),
    )

    persist_finalized(
        store=store,
        incident=historical,
        candidate_id=(
            "processor-immediate-unavailable"
        ),
    )

    current = make_incident(
        fingerprint="new",
        alert_name="FinStreamServiceDown",
        service="processor",
        summary=(
            "Processor workload unavailable."
        ),
    )

    match = (
        DeterministicIncidentMemoryRetriever(
            store=store
        ).retrieve(
            incident=current,
            top_k=1,
        ).matches[0]
    )

    assert match.score >= 100

    assert "processor" in (
        match.matched_terms
    )

    assert "exact_alert_match" in (
        match.reasons
    )

    assert "affected_service_match" in (
        match.reasons
    )

    assert "historical_term_match" in (
        match.reasons
    )
