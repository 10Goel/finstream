from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

from services.ai_sre_agent.models import (
    EvidenceSource,
    EvidenceTrustLevel,
)
from services.ai_sre_agent.tools.postgres import (
    PostgresDiagnosticError,
    PostgresDiagnosticTool,
)


def make_tool(
    *,
    one=None,
    all_rows=None,
    error=None,
):
    cursor = MagicMock()

    if error is not None:
        cursor.execute.side_effect = error

    cursor.fetchone.return_value = one
    cursor.fetchall.return_value = (
        all_rows
        if all_rows is not None
        else []
    )

    cursor_context = MagicMock()
    cursor_context.__enter__.return_value = cursor

    connection = MagicMock()
    connection.cursor.return_value = cursor_context

    connection_context = MagicMock()
    connection_context.__enter__.return_value = (
        connection
    )

    factory = MagicMock(
        return_value=connection_context
    )

    return (
        PostgresDiagnosticTool(factory),
        cursor,
    )


def test_database_health_reports_read_only_identity():
    tool, _ = make_tool(
        one={
            "database_name": "finstream",
            "database_user": "finstream_ai_sre",
            "transaction_read_only": "on",
            "statement_timeout": "5s",
            "lock_timeout": "2s",
            "in_recovery": False,
        }
    )

    evidence = tool.check_database_health(
        incident_id="inc-test",
    )

    assert (
        evidence.source
        is EvidenceSource.POSTGRESQL
    )
    assert (
        evidence.trust_level
        is EvidenceTrustLevel.DIRECT_OBSERVATION
    )
    assert evidence.service == "postgres"
    assert evidence.metadata["healthy"] is True
    assert (
        evidence.metadata[
            "transaction_read_only"
        ]
        is True
    )
    assert (
        evidence.metadata["database_user"]
        == "finstream_ai_sre"
    )


def test_database_health_detects_non_read_only_session():
    tool, _ = make_tool(
        one={
            "database_name": "finstream",
            "database_user": "unsafe-user",
            "transaction_read_only": "off",
            "statement_timeout": "5s",
            "lock_timeout": "2s",
            "in_recovery": False,
        }
    )

    evidence = tool.check_database_health(
        incident_id="inc-test",
    )

    assert evidence.metadata["healthy"] is False
    assert (
        "not read-only"
        in evidence.summary
    )


def test_transaction_statistics_are_normalized():
    tool, _ = make_tool(
        one={
            "total_transactions": 100,
            "normal_transactions": 90,
            "alert_transactions": 10,
            "average_risk_score": 6.58,
            "latest_processed_at": datetime(
                2026,
                10,
                14,
                16,
                0,
                tzinfo=timezone.utc,
            ),
        }
    )

    evidence = tool.get_transaction_statistics(
        incident_id="inc-test",
    )

    assert evidence.metadata[
        "total_transactions"
    ] == 100

    assert evidence.metadata[
        "normal_transactions"
    ] == 90

    assert evidence.metadata[
        "alert_transactions"
    ] == 10

    assert evidence.metadata[
        "average_risk_score"
    ] == 6.58

    assert evidence.metadata[
        "latest_processed_at"
    ].startswith("2026-10-14T16:00:00")


def test_persistence_freshness_reports_recent_activity():
    tool, cursor = make_tool(
        one={
            "recent_transactions": 150,
            "latest_processed_at": datetime(
                2026,
                10,
                14,
                16,
                13,
                tzinfo=timezone.utc,
            ),
            "persistence_age_seconds": 0.58,
        }
    )

    evidence = tool.get_persistence_freshness(
        incident_id="inc-test",
        window_minutes=5,
    )

    assert evidence.metadata["fresh"] is True
    assert (
        evidence.metadata[
            "recent_transactions"
        ]
        == 150
    )
    assert (
        evidence.metadata[
            "persistence_age_seconds"
        ]
        == pytest.approx(0.58)
    )

    assert cursor.execute.call_args.args[1] == (5,)


def test_persistence_freshness_detects_no_activity():
    tool, _ = make_tool(
        one={
            "recent_transactions": 0,
            "latest_processed_at": datetime(
                2026,
                10,
                14,
                15,
                0,
                tzinfo=timezone.utc,
            ),
            "persistence_age_seconds": 3600,
        }
    )

    evidence = tool.get_persistence_freshness(
        incident_id="inc-test",
        window_minutes=5,
    )

    assert evidence.metadata["fresh"] is False
    assert (
        "No FinStream transactions"
        in evidence.summary
    )


@pytest.mark.parametrize(
    "window_minutes",
    [
        0,
        61,
    ],
)
def test_persistence_window_is_bounded(
    window_minutes,
):
    tool, _ = make_tool()

    with pytest.raises(
        ValueError,
        match=(
            "window_minutes must be "
            "between 1 and 60"
        ),
    ):
        tool.get_persistence_freshness(
            incident_id="inc-test",
            window_minutes=window_minutes,
        )


def test_connection_statistics_are_aggregated():
    tool, _ = make_tool(
        all_rows=[
            {
                "state": "active",
                "connection_count": 2,
            },
            {
                "state": "idle",
                "connection_count": 3,
            },
        ]
    )

    evidence = tool.get_connection_statistics(
        incident_id="inc-test",
    )

    assert (
        evidence.metadata[
            "total_connections"
        ]
        == 5
    )

    assert evidence.metadata[
        "connections_by_state"
    ] == {
        "active": 2,
        "idle": 3,
    }


def test_query_failure_is_wrapped():
    tool, _ = make_tool(
        error=RuntimeError(
            "database unavailable"
        )
    )

    with pytest.raises(
        PostgresDiagnosticError,
        match="diagnostic query failed",
    ):
        tool.check_database_health(
            incident_id="inc-test",
        )


def test_missing_query_row_is_rejected():
    tool, _ = make_tool(
        one=None,
    )

    with pytest.raises(
        PostgresDiagnosticError,
        match="returned no row",
    ):
        tool.check_database_health(
            incident_id="inc-test",
        )


def test_datetime_serialization_handles_none():
    tool, _ = make_tool()

    assert (
        tool._serialize_datetime(None)
        is None
    )
