"""Read-only PostgreSQL diagnostics for FinStream AI-SRE."""

from __future__ import annotations

import os
from collections.abc import Callable
from datetime import datetime
from typing import Any

import psycopg
from psycopg.rows import dict_row

from services.ai_sre_agent.models import (
    Evidence,
    EvidenceSource,
    EvidenceTrustLevel,
)


class PostgresDiagnosticError(RuntimeError):
    """Raised when PostgreSQL diagnostics cannot be completed."""


ConnectionFactory = Callable[[], Any]


class PostgresDiagnosticTool:
    """Bounded, predefined PostgreSQL diagnostics for FinStream."""

    def __init__(
        self,
        connection_factory: ConnectionFactory,
    ) -> None:
        self._connection_factory = connection_factory

    @classmethod
    def from_environment(
        cls,
        *,
        connect_timeout_seconds: int = 5,
    ) -> PostgresDiagnosticTool:
        """Create the diagnostic tool from dedicated AI-SRE credentials."""
        if connect_timeout_seconds <= 0:
            raise ValueError(
                "connect_timeout_seconds must be positive."
            )

        host = os.getenv(
            "AI_SRE_POSTGRES_HOST",
            "postgres",
        )
        port_text = os.getenv(
            "AI_SRE_POSTGRES_PORT",
            "5432",
        )
        database = os.getenv(
            "AI_SRE_POSTGRES_DB",
            "finstream",
        )
        user = os.getenv(
            "AI_SRE_POSTGRES_USER",
        )
        password = os.getenv(
            "AI_SRE_POSTGRES_PASSWORD",
        )

        if not user:
            raise ValueError(
                "AI_SRE_POSTGRES_USER must be configured."
            )

        if not password:
            raise ValueError(
                "AI_SRE_POSTGRES_PASSWORD must be configured."
            )

        try:
            port = int(port_text)
        except ValueError as exc:
            raise ValueError(
                "AI_SRE_POSTGRES_PORT must be an integer."
            ) from exc

        if not 1 <= port <= 65535:
            raise ValueError(
                "AI_SRE_POSTGRES_PORT must be between 1 and 65535."
            )

        def connection_factory() -> Any:
            return psycopg.connect(
                host=host,
                port=port,
                dbname=database,
                user=user,
                password=password,
                connect_timeout=connect_timeout_seconds,
                row_factory=dict_row,
                options=(
                    "-c default_transaction_read_only=on "
                    "-c statement_timeout=5000 "
                    "-c lock_timeout=2000 "
                    "-c idle_in_transaction_session_timeout=5000"
                ),
            )

        return cls(connection_factory)

    def _fetch_one(
        self,
        query: str,
        params: tuple[Any, ...] = (),
    ) -> dict[str, Any]:
        try:
            with (
                self._connection_factory() as connection,
                connection.cursor() as cursor,
            ):
                cursor.execute(query, params)
                row = cursor.fetchone()
        except Exception as exc:
            raise PostgresDiagnosticError(
                "PostgreSQL diagnostic query failed."
            ) from exc

        if row is None:
            raise PostgresDiagnosticError(
                "PostgreSQL diagnostic query returned no row."
            )

        return dict(row)

    def _fetch_all(
        self,
        query: str,
        params: tuple[Any, ...] = (),
    ) -> list[dict[str, Any]]:
        try:
            with (
                self._connection_factory() as connection,
                connection.cursor() as cursor,
            ):
                cursor.execute(query, params)
                rows = cursor.fetchall()
        except Exception as exc:
            raise PostgresDiagnosticError(
                "PostgreSQL diagnostic query failed."
            ) from exc

        return [
            dict(row)
            for row in rows
        ]

    @staticmethod
    def _serialize_datetime(
        value: Any,
    ) -> str | None:
        if value is None:
            return None

        if isinstance(value, datetime):
            return value.isoformat()

        return str(value)

    def check_database_health(
        self,
        *,
        incident_id: str,
    ) -> Evidence:
        """Verify PostgreSQL reachability and read-only session state."""
        row = self._fetch_one(
            """
            SELECT
                current_database() AS database_name,
                current_user AS database_user,
                current_setting(
                    'transaction_read_only'
                ) AS transaction_read_only,
                current_setting(
                    'statement_timeout'
                ) AS statement_timeout,
                current_setting(
                    'lock_timeout'
                ) AS lock_timeout,
                pg_is_in_recovery() AS in_recovery;
            """
        )

        transaction_read_only = (
            str(
                row["transaction_read_only"]
            ).lower()
            == "on"
        )

        healthy = transaction_read_only

        if healthy:
            summary = (
                f"PostgreSQL database "
                f"{row['database_name']} is reachable "
                f"using read-only diagnostic identity "
                f"{row['database_user']}."
            )
        else:
            summary = (
                "PostgreSQL is reachable, but the "
                "diagnostic session is not read-only."
            )

        return Evidence(
            incident_id=incident_id,
            source=EvidenceSource.POSTGRESQL,
            tool="check_database_health",
            summary=summary,
            trust_level=(
                EvidenceTrustLevel.DIRECT_OBSERVATION
            ),
            service="postgres",
            raw_reference=(
                "PostgreSQL connection/session settings"
            ),
            metadata={
                "database_name": row[
                    "database_name"
                ],
                "database_user": row[
                    "database_user"
                ],
                "transaction_read_only": (
                    transaction_read_only
                ),
                "statement_timeout": row[
                    "statement_timeout"
                ],
                "lock_timeout": row[
                    "lock_timeout"
                ],
                "in_recovery": bool(
                    row["in_recovery"]
                ),
                "healthy": healthy,
            },
        )

    def get_transaction_statistics(
        self,
        *,
        incident_id: str,
    ) -> Evidence:
        """Collect bounded aggregate transaction statistics."""
        row = self._fetch_one(
            """
            SELECT
                COUNT(*) AS total_transactions,
                COUNT(*) FILTER (
                    WHERE status = 'NORMAL'
                ) AS normal_transactions,
                COUNT(*) FILTER (
                    WHERE status = 'ALERT'
                ) AS alert_transactions,
                COALESCE(
                    AVG(risk_score),
                    0
                ) AS average_risk_score,
                MAX(processed_at) AS latest_processed_at
            FROM public.transactions;
            """
        )

        total = int(
            row["total_transactions"]
        )
        normal = int(
            row["normal_transactions"]
        )
        alerts = int(
            row["alert_transactions"]
        )
        average_risk = float(
            row["average_risk_score"]
        )

        summary = (
            f"PostgreSQL contains {total} FinStream "
            f"transactions: {normal} NORMAL and "
            f"{alerts} ALERT."
        )

        return Evidence(
            incident_id=incident_id,
            source=EvidenceSource.POSTGRESQL,
            tool="get_transaction_statistics",
            summary=summary,
            trust_level=(
                EvidenceTrustLevel.DIRECT_OBSERVATION
            ),
            service="postgres",
            raw_reference=(
                "aggregate statistics from "
                "public.transactions"
            ),
            metadata={
                "total_transactions": total,
                "normal_transactions": normal,
                "alert_transactions": alerts,
                "average_risk_score": round(
                    average_risk,
                    2,
                ),
                "latest_processed_at": (
                    self._serialize_datetime(
                        row["latest_processed_at"]
                    )
                ),
            },
        )

    def get_persistence_freshness(
        self,
        *,
        incident_id: str,
        window_minutes: int = 5,
    ) -> Evidence:
        """Measure whether processed transactions are still arriving."""
        if not 1 <= window_minutes <= 60:
            raise ValueError(
                "window_minutes must be between 1 and 60."
            )

        row = self._fetch_one(
            """
            SELECT
                COUNT(*) FILTER (
                    WHERE processed_at >=
                        NOW()
                        - (%s * INTERVAL '1 minute')
                ) AS recent_transactions,
                MAX(processed_at) AS latest_processed_at,
                EXTRACT(
                    EPOCH FROM (
                        NOW() - MAX(processed_at)
                    )
                ) AS persistence_age_seconds
            FROM public.transactions;
            """,
            (window_minutes,),
        )

        recent_transactions = int(
            row["recent_transactions"]
        )

        age_value = row[
            "persistence_age_seconds"
        ]

        persistence_age_seconds = (
            float(age_value)
            if age_value is not None
            else None
        )

        fresh = recent_transactions > 0

        if fresh:
            summary = (
                f"PostgreSQL received "
                f"{recent_transactions} transaction(s) "
                f"during the last {window_minutes} minute(s)."
            )
        else:
            summary = (
                f"No FinStream transactions were persisted "
                f"during the last {window_minutes} minute(s)."
            )

        return Evidence(
            incident_id=incident_id,
            source=EvidenceSource.POSTGRESQL,
            tool="get_persistence_freshness",
            summary=summary,
            trust_level=(
                EvidenceTrustLevel.DIRECT_OBSERVATION
            ),
            service="postgres",
            raw_reference=(
                "public.transactions.processed_at"
            ),
            metadata={
                "window_minutes": window_minutes,
                "recent_transactions": (
                    recent_transactions
                ),
                "latest_processed_at": (
                    self._serialize_datetime(
                        row["latest_processed_at"]
                    )
                ),
                "persistence_age_seconds": (
                    persistence_age_seconds
                ),
                "fresh": fresh,
            },
        )

    def get_connection_statistics(
        self,
        *,
        incident_id: str,
    ) -> Evidence:
        """Collect safe PostgreSQL connection-state statistics."""
        rows = self._fetch_all(
            """
            SELECT
                COALESCE(
                    state,
                    'unknown'
                ) AS state,
                COUNT(*) AS connection_count
            FROM pg_stat_activity
            WHERE datname = current_database()
            GROUP BY state
            ORDER BY state;
            """
        )

        by_state = {
            str(row["state"]): int(
                row["connection_count"]
            )
            for row in rows
        }

        total_connections = sum(
            by_state.values()
        )

        summary = (
            f"PostgreSQL reports {total_connections} "
            f"connection(s) to the FinStream database."
        )

        return Evidence(
            incident_id=incident_id,
            source=EvidenceSource.POSTGRESQL,
            tool="get_connection_statistics",
            summary=summary,
            trust_level=(
                EvidenceTrustLevel.DIRECT_OBSERVATION
            ),
            service="postgres",
            raw_reference="pg_stat_activity",
            metadata={
                "total_connections": total_connections,
                "connections_by_state": by_state,
            },
        )
