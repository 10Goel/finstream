import json
from datetime import datetime, timezone

import pytest

from services.ai_sre_agent.remediation import (
    AuditEventType,
    AuditIntegrityError,
    JsonlAuditLog,
    RemediationRiskLevel,
)


def test_first_record_uses_genesis_hash(tmp_path):
    log = JsonlAuditLog(
        tmp_path / "audit.jsonl"
    )

    record = log.append(
        event_type=AuditEventType.PROPOSAL_CREATED,
        actor="finstream-ai-sre",
        incident_id="inc-1",
        proposal_id="rem-1",
    )

    assert record.sequence == 1
    assert record.previous_hash == "0" * 64
    assert len(record.record_hash) == 64
    assert log.verify() == 1


def test_records_form_hash_chain(tmp_path):
    log = JsonlAuditLog(
        tmp_path / "audit.jsonl"
    )

    first = log.append(
        event_type=AuditEventType.PROPOSAL_CREATED,
        actor="finstream-ai-sre",
        incident_id="inc-1",
        proposal_id="rem-1",
    )

    second = log.append(
        event_type=AuditEventType.PROPOSAL_APPROVED,
        actor="operator@example",
        incident_id="inc-1",
        proposal_id="rem-1",
    )

    assert second.sequence == 2
    assert second.previous_hash == first.record_hash
    assert log.verify() == 2


def test_journal_survives_reopen_and_continues_chain(tmp_path):
    path = tmp_path / "audit.jsonl"

    first_log = JsonlAuditLog(path)

    first = first_log.append(
        event_type=AuditEventType.AUTHORIZATION_ISSUED,
        actor="finstream-ai-sre",
        incident_id="inc-1",
        authorization_id="auth-1",
    )

    reopened = JsonlAuditLog(path)

    second = reopened.append(
        event_type=AuditEventType.PERMIT_ISSUED,
        actor="finstream-ai-sre",
        incident_id="inc-1",
        authorization_id="auth-1",
        permit_id="permit-1",
    )

    assert second.sequence == 2
    assert second.previous_hash == first.record_hash
    assert reopened.verify() == 2


def test_read_all_requires_valid_chain(tmp_path):
    log = JsonlAuditLog(
        tmp_path / "audit.jsonl"
    )

    log.append(
        event_type=AuditEventType.PERMIT_CONSUMED,
        actor="future-actuator",
        incident_id="inc-1",
        permit_id="permit-1",
    )

    records = log.read_all()

    assert len(records) == 1
    assert (
        records[0].event_type
        is AuditEventType.PERMIT_CONSUMED
    )


def test_modified_record_is_detected(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = JsonlAuditLog(path)

    log.append(
        event_type=AuditEventType.PROPOSAL_APPROVED,
        actor="operator@example",
        incident_id="inc-1",
        proposal_id="rem-1",
        details={
            "risk": "MEDIUM",
        },
    )

    payload = json.loads(
        path.read_text()
    )

    payload["details"]["risk"] = "LOW"

    path.write_text(
        json.dumps(payload) + "\n"
    )

    with pytest.raises(
        AuditIntegrityError,
        match="hash mismatch",
    ):
        log.verify()


def test_broken_previous_hash_is_detected(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = JsonlAuditLog(path)

    log.append(
        event_type=AuditEventType.PROPOSAL_CREATED,
        actor="finstream-ai-sre",
        incident_id="inc-1",
    )

    log.append(
        event_type=AuditEventType.PROPOSAL_APPROVED,
        actor="operator@example",
        incident_id="inc-1",
    )

    lines = path.read_text().splitlines()

    second = json.loads(lines[1])
    second["previous_hash"] = "f" * 64

    lines[1] = json.dumps(second)

    path.write_text(
        "\n".join(lines) + "\n"
    )

    with pytest.raises(
        AuditIntegrityError,
        match="hash chain is broken",
    ):
        log.verify()


def test_malformed_journal_is_rejected(tmp_path):
    path = tmp_path / "audit.jsonl"

    path.write_text(
        '{"broken":\n'
    )

    log = JsonlAuditLog(path)

    with pytest.raises(
        AuditIntegrityError,
        match="malformed JSON",
    ):
        log.verify()


def test_details_are_canonically_serialized(tmp_path):
    log = JsonlAuditLog(
        tmp_path / "audit.jsonl"
    )

    timestamp = datetime(
        2026,
        10,
        22,
        12,
        0,
        tzinfo=timezone.utc,
    )

    record = log.append(
        event_type=AuditEventType.AUTHORIZATION_ISSUED,
        actor="operator@example",
        incident_id="inc-1",
        details={
            "risk": RemediationRiskLevel.MEDIUM,
            "approved_at": timestamp,
            "evidence": (
                "ev-1",
                "ev-2",
            ),
        },
    )

    assert record.details == {
        "risk": "MEDIUM",
        "approved_at": timestamp.isoformat(),
        "evidence": [
            "ev-1",
            "ev-2",
        ],
    }


def test_audit_log_has_no_execution_api():
    forbidden = (
        "execute",
        "run",
        "apply",
        "restart",
        "remediate",
    )

    for name in forbidden:
        assert not hasattr(
            JsonlAuditLog,
            name,
        )
