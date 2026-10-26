"""Deterministic retrieval of historical FinStream incidents."""

from __future__ import annotations

import re
from dataclasses import dataclass

from services.ai_sre_agent.memory.store import (
    IncidentMemoryRecord,
    SQLiteIncidentMemoryStore,
)
from services.ai_sre_agent.models import Incident

_TOKEN_PATTERN = re.compile(
    r"[a-z0-9]+"
)

_CAMEL_BOUNDARY = re.compile(
    r"(?<=[a-z0-9])(?=[A-Z])"
)

_SERVICE_ALIASES = {
    "postgresql": "postgres",
    "stream_processor": "processor",
    "stream-processor": "processor",
}


@dataclass(frozen=True, slots=True)
class HistoricalIncidentMatch:
    """One deterministically ranked historical incident."""

    record: IncidentMemoryRecord
    score: int
    matched_terms: tuple[str, ...]
    reasons: tuple[str, ...]

    @property
    def incident_id(self) -> str:
        """Return the historical incident ID."""
        return self.record.incident_id

    @property
    def memory_id(self) -> str:
        """Return the historical memory ID."""
        return self.record.memory_id


@dataclass(frozen=True, slots=True)
class HistoricalIncidentRetrievalResult:
    """Historical incidents relevant to one current incident."""

    incident_id: str
    query_terms: tuple[str, ...]
    matches: tuple[HistoricalIncidentMatch, ...]


class DeterministicIncidentMemoryRetriever:
    """Rank finalized historical incidents without model retrieval."""

    def __init__(
        self,
        *,
        store: SQLiteIncidentMemoryStore,
        minimum_score: int = 60,
        search_limit: int = 100,
    ) -> None:
        if minimum_score < 0:
            raise ValueError(
                "minimum_score must not be negative."
            )

        if search_limit < 1:
            raise ValueError(
                "search_limit must be at least 1."
            )

        self._store = store
        self._minimum_score = minimum_score
        self._search_limit = search_limit

    @staticmethod
    def _normalize_service(
        service: str | None,
    ) -> str | None:
        if service is None:
            return None

        normalized = service.strip().casefold()

        if not normalized:
            return None

        return _SERVICE_ALIASES.get(
            normalized,
            normalized,
        )

    @staticmethod
    def _tokens(
        text: str | None,
    ) -> tuple[str, ...]:
        if not text:
            return ()

        expanded = _CAMEL_BOUNDARY.sub(
            " ",
            text,
        )

        tokens = _TOKEN_PATTERN.findall(
            expanded.casefold()
        )

        normalized = [
            _SERVICE_ALIASES.get(
                token,
                token,
            )
            for token in tokens
        ]

        return tuple(
            dict.fromkeys(normalized)
        )

    @classmethod
    def _query_terms(
        cls,
        *,
        incident: Incident,
    ) -> tuple[str, ...]:
        values = (
            incident.affected_service,
            incident.alert_name,
            incident.summary,
        )

        terms: list[str] = []

        for value in values:
            for token in cls._tokens(value):
                if token not in terms:
                    terms.append(token)

        return tuple(terms)

    @classmethod
    def _historical_terms(
        cls,
        *,
        record: IncidentMemoryRecord,
    ) -> set[str]:
        terms: set[str] = set()

        for value in (
            record.affected_service,
            record.alert_name,
            record.summary,
        ):
            terms.update(
                cls._tokens(value)
            )

        for candidate_id in (
            record.selected_candidate_ids
        ):
            terms.update(
                cls._tokens(candidate_id)
            )

        return terms

    @classmethod
    def _score(
        cls,
        *,
        incident: Incident,
        record: IncidentMemoryRecord,
        query_terms: tuple[str, ...],
    ) -> tuple[
        int,
        tuple[str, ...],
        tuple[str, ...],
    ]:
        score = 0
        reasons: list[str] = []
        matched_terms: set[str] = set()

        current_service = cls._normalize_service(
            incident.affected_service
        )

        historical_service = cls._normalize_service(
            record.affected_service
        )

        if (
            incident.fingerprint
            and incident.fingerprint
            == record.fingerprint
        ):
            # Fingerprint identity is the strongest recurrence
            # signal. Its weight intentionally exceeds the maximum
            # combined score obtainable from weaker similarity
            # signals such as alert, service, severity, and terms.
            score += 200
            reasons.append(
                "exact_fingerprint_match"
            )

        if (
            incident.alert_name
            == record.alert_name
        ):
            score += 60
            reasons.append(
                "exact_alert_match"
            )

        if (
            current_service is not None
            and historical_service
            == current_service
        ):
            score += 40
            reasons.append(
                "affected_service_match"
            )

        if (
            incident.severity.casefold()
            == record.severity.casefold()
        ):
            score += 10
            reasons.append(
                "severity_match"
            )

        query = set(query_terms)

        overlap = (
            query
            & cls._historical_terms(
                record=record
            )
        )

        if overlap:
            bounded_overlap = min(
                len(overlap),
                10,
            )

            score += bounded_overlap * 4

            matched_terms.update(
                overlap
            )

            reasons.append(
                "historical_term_match"
            )

        return (
            score,
            tuple(
                sorted(matched_terms)
            ),
            tuple(reasons),
        )

    @staticmethod
    def _finalized_timestamp(
        match: HistoricalIncidentMatch,
    ) -> float:
        finalized_at = (
            match.record.finalized_at
        )

        if finalized_at is None:
            raise ValueError(
                "Historical retrieval encountered "
                "unfinalized memory."
            )

        return finalized_at.timestamp()

    def retrieve(
        self,
        *,
        incident: Incident,
        top_k: int = 3,
    ) -> HistoricalIncidentRetrievalResult:
        """Retrieve ranked finalized historical incidents."""
        if top_k < 1:
            raise ValueError(
                "top_k must be at least 1."
            )

        query_terms = self._query_terms(
            incident=incident
        )

        matches: list[
            HistoricalIncidentMatch
        ] = []

        records = self._store.recent_finalized(
            limit=self._search_limit
        )

        for record in records:
            # Never allow an incident to retrieve itself as
            # historical precedent.
            if (
                record.incident_id
                == incident.incident_id
            ):
                continue

            (
                score,
                matched_terms,
                reasons,
            ) = self._score(
                incident=incident,
                record=record,
                query_terms=query_terms,
            )

            if score < self._minimum_score:
                continue

            matches.append(
                HistoricalIncidentMatch(
                    record=record,
                    score=score,
                    matched_terms=matched_terms,
                    reasons=reasons,
                )
            )

        matches.sort(
            key=lambda match: (
                -match.score,
                -self._finalized_timestamp(
                    match
                ),
                match.incident_id,
            )
        )

        return HistoricalIncidentRetrievalResult(
            incident_id=incident.incident_id,
            query_terms=query_terms,
            matches=tuple(
                matches[:top_k]
            ),
        )
