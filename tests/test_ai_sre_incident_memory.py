from __future__ import annotations

from services.ai_sre_agent.memory import (
    IncidentMemoryError,
    SQLiteIncidentMemoryStore,
)
from services.ai_sre_agent.models import (
    AlertStatus,
    Incident,
    IncidentStatus,
)
from services.ai_sre_agent.reasoning.selector import (
    CandidateSelectionOutcome,
    RunbookCitation,
    SelectedCandidate,
)


def make_incident(
    *,
    service: str = "processor",
) -> Incident:
    return Incident(
        fingerprint=f"fingerprint-{service}",
        alert_name="FinStreamServiceDown",
        alert_status=AlertStatus.FIRING,
        severity="critical",
        affected_service=service,
        summary=f"{service} is unavailable",
        status=IncidentStatus.DIAGNOSED,
    )


def make_selection() -> CandidateSelectionOutcome:
    citation = RunbookCitation(
        context_id="ev-runbook-1",
        runbook_id="RB-PROCESSOR-001",
        title="Processor Unavailable",
        version="1.0.0",
        sha256="a" * 64,
        path="processor-unavailable.md",
        raw_reference=(
            "docs/runbooks/"
            "processor-unavailable.md"
        ),
        retrieval_score=135,
    )

    selected = SelectedCandidate(
        candidate_id=(
            "processor-immediate-unavailable"
        ),
        statement=(
            "FinStream processor workload is unavailable."
        ),
        confidence=0.99,
        model_rationale=(
            "Observed processor availability supports "
            "the bounded candidate."
        ),
        supporting_evidence=(
            "ev-prometheus",
            "ev-kubernetes",
        ),
        contradicting_evidence=(),
        runbook_citations=(citation,),
    )

    return CandidateSelectionOutcome(
        selections=(selected,),
        abstained=False,
        abstention_reason=None,
    )


def make_abstention() -> CandidateSelectionOutcome:
    return CandidateSelectionOutcome(
        selections=(),
        abstained=True,
        abstention_reason=(
            "Available evidence does not support "
            "a bounded candidate."
        ),
    )


def test_memory_round_trip_preserves_selection(
    tmp_path,
):
    store = SQLiteIncidentMemoryStore(
        tmp_path / "memory.db"
    )

    incident = make_incident()

    saved = store.record_investigation(
        incident=incident,
        selection=make_selection(),
    )

    loaded = store.get(
        incident.incident_id
    )

    assert loaded == saved

    assert saved.incident_id == (
        incident.incident_id
    )

    assert saved.selected_candidate_ids == (
        "processor-immediate-unavailable",
    )

    assert saved.runbook_ids == (
        "RB-PROCESSOR-001",
    )

    assert saved.abstained is False
    assert saved.abstention_reason is None
    assert saved.final_status is None


def test_memory_round_trip_preserves_abstention(
    tmp_path,
):
    store = SQLiteIncidentMemoryStore(
        tmp_path / "memory.db"
    )

    incident = make_incident(
        service="api"
    )

    saved = store.record_investigation(
        incident=incident,
        selection=make_abstention(),
    )

    assert saved.selected_candidate_ids == ()
    assert saved.runbook_ids == ()
    assert saved.abstained is True

    assert saved.abstention_reason == (
        "Available evidence does not support "
        "a bounded candidate."
    )


def test_same_incident_cannot_be_recorded_twice(
    tmp_path,
):
    store = SQLiteIncidentMemoryStore(
        tmp_path / "memory.db"
    )

    incident = make_incident()

    store.record_investigation(
        incident=incident,
        selection=make_selection(),
    )

    try:
        store.record_investigation(
            incident=incident,
            selection=make_selection(),
        )
    except IncidentMemoryError as exc:
        assert "already" in str(exc)
    else:
        raise AssertionError(
            "Duplicate incident memory was accepted."
        )


def test_memory_can_be_finalized_exactly_once(
    tmp_path,
):
    store = SQLiteIncidentMemoryStore(
        tmp_path / "memory.db"
    )

    incident = make_incident()

    store.record_investigation(
        incident=incident,
        selection=make_selection(),
    )

    finalized = store.finalize(
        incident_id=incident.incident_id,
        final_status=IncidentStatus.RESOLVED,
        resolution_summary=(
            "Processor restarted and post-remediation "
            "health verification passed."
        ),
    )

    assert finalized.final_status is (
        IncidentStatus.RESOLVED
    )

    assert finalized.finalized_at is not None

    assert finalized.resolution_summary == (
        "Processor restarted and post-remediation "
        "health verification passed."
    )

    try:
        store.finalize(
            incident_id=incident.incident_id,
            final_status=IncidentStatus.CLOSED,
            resolution_summary="Second outcome.",
        )
    except IncidentMemoryError as exc:
        assert "already" in str(exc)
    else:
        raise AssertionError(
            "Finalized memory was modified."
        )


def test_unfinalized_memory_is_not_retrievable_as_history(
    tmp_path,
):
    store = SQLiteIncidentMemoryStore(
        tmp_path / "memory.db"
    )

    incident = make_incident()

    store.record_investigation(
        incident=incident,
        selection=make_selection(),
    )

    assert store.recent_finalized() == ()


def test_recent_finalized_can_filter_by_service(
    tmp_path,
):
    store = SQLiteIncidentMemoryStore(
        tmp_path / "memory.db"
    )

    processor = make_incident(
        service="processor"
    )

    api = make_incident(
        service="api"
    )

    store.record_investigation(
        incident=processor,
        selection=make_selection(),
    )

    store.record_investigation(
        incident=api,
        selection=make_abstention(),
    )

    store.finalize(
        incident_id=processor.incident_id,
        final_status=IncidentStatus.RESOLVED,
        resolution_summary=(
            "Processor recovered successfully."
        ),
    )

    store.finalize(
        incident_id=api.incident_id,
        final_status=IncidentStatus.CLOSED,
        resolution_summary=(
            "No remediation was required."
        ),
    )

    processor_history = (
        store.recent_finalized(
            affected_service="processor",
        )
    )

    assert len(processor_history) == 1

    assert (
        processor_history[0].incident_id
        == processor.incident_id
    )

    assert (
        processor_history[0].affected_service
        == "processor"
    )


def test_nonterminal_final_status_is_rejected(
    tmp_path,
):
    store = SQLiteIncidentMemoryStore(
        tmp_path / "memory.db"
    )

    incident = make_incident()

    store.record_investigation(
        incident=incident,
        selection=make_selection(),
    )

    try:
        store.finalize(
            incident_id=incident.incident_id,
            final_status=(
                IncidentStatus.INVESTIGATING
            ),
            resolution_summary="Not actually final.",
        )
    except IncidentMemoryError as exc:
        assert "final status" in str(exc)
    else:
        raise AssertionError(
            "Nonterminal memory finalization was accepted."
        )
