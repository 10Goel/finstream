"""Deterministic retrieval of trusted FinStream runbooks."""

from __future__ import annotations

import re
from dataclasses import dataclass

from services.ai_sre_agent.models import Incident
from services.ai_sre_agent.retrieval.runbooks import (
    RunbookCatalog,
    RunbookDocument,
)

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
class RunbookMatch:
    """One deterministic runbook retrieval result."""

    document: RunbookDocument
    score: int
    matched_terms: tuple[str, ...]
    reasons: tuple[str, ...]

    @property
    def runbook_id(self) -> str:
        """Return the stable runbook ID."""
        return self.document.runbook_id


@dataclass(frozen=True, slots=True)
class RunbookRetrievalResult:
    """Ranked runbooks retrieved for one incident."""

    incident_id: str
    query_terms: tuple[str, ...]
    matches: tuple[RunbookMatch, ...]


class DeterministicRunbookRetriever:
    """Rank approved runbooks without model-generated retrieval."""

    def __init__(
        self,
        *,
        catalog: RunbookCatalog,
        minimum_score: int = 35,
    ) -> None:
        if minimum_score < 0:
            raise ValueError(
                "minimum_score must not be negative."
            )

        self._catalog = catalog
        self._minimum_score = minimum_score

    @staticmethod
    def _normalize_service(
        service: str | None,
    ) -> str | None:
        if service is None:
            return None

        normalized = service.strip().casefold()

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
    def _document_tokens(
        cls,
        *,
        document: RunbookDocument,
    ) -> dict[str, set[str]]:
        return {
            "title": set(
                cls._tokens(document.title)
            ),
            "tags": {
                token
                for tag in document.tags
                for token in cls._tokens(tag)
            },
            "summary": set(
                cls._tokens(document.summary)
            ),
            "content": set(
                cls._tokens(document.content)
            ),
        }

    @staticmethod
    def _eligible(
        *,
        document: RunbookDocument,
        service: str | None,
        alert_name: str,
    ) -> bool:
        exact_alert = (
            alert_name in document.alert_names
        )

        if service is None:
            return exact_alert

        return (
            service in document.services
            or exact_alert
        )

    @classmethod
    def _score(
        cls,
        *,
        document: RunbookDocument,
        service: str | None,
        alert_name: str,
        query_terms: tuple[str, ...],
    ) -> tuple[
        int,
        tuple[str, ...],
        tuple[str, ...],
    ]:
        score = 0
        reasons: list[str] = []
        matched_terms: set[str] = set()

        if (
            service is not None
            and service in document.services
        ):
            score += 30
            reasons.append(
                "affected_service_match"
            )

        if alert_name in document.alert_names:
            score += 50
            reasons.append(
                "exact_alert_match"
            )

        query = set(query_terms)

        document_tokens = cls._document_tokens(
            document=document
        )

        weighted_fields = (
            ("tags", 8),
            ("title", 5),
            ("summary", 3),
            ("content", 1),
        )

        for field, weight in weighted_fields:
            overlap = (
                query
                & document_tokens[field]
            )

            if not overlap:
                continue

            score += len(overlap) * weight

            matched_terms.update(
                overlap
            )

            reasons.append(
                f"{field}_term_match"
            )

        return (
            score,
            tuple(
                sorted(matched_terms)
            ),
            tuple(reasons),
        )

    def retrieve(
        self,
        *,
        incident: Incident,
        top_k: int = 3,
    ) -> RunbookRetrievalResult:
        """Retrieve ranked approved runbooks for an incident."""
        if top_k < 1:
            raise ValueError(
                "top_k must be at least 1."
            )

        service = self._normalize_service(
            incident.affected_service
        )

        query_terms = self._query_terms(
            incident=incident
        )

        matches: list[RunbookMatch] = []

        for document in (
            self._catalog.approved_documents
        ):
            if not self._eligible(
                document=document,
                service=service,
                alert_name=incident.alert_name,
            ):
                continue

            (
                score,
                matched_terms,
                reasons,
            ) = self._score(
                document=document,
                service=service,
                alert_name=incident.alert_name,
                query_terms=query_terms,
            )

            if score < self._minimum_score:
                continue

            matches.append(
                RunbookMatch(
                    document=document,
                    score=score,
                    matched_terms=matched_terms,
                    reasons=reasons,
                )
            )

        matches.sort(
            key=lambda match: (
                -match.score,
                match.runbook_id,
            )
        )

        return RunbookRetrievalResult(
            incident_id=incident.incident_id,
            query_terms=query_terms,
            matches=tuple(
                matches[:top_k]
            ),
        )
