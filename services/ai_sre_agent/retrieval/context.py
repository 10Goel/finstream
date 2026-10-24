"""Trusted documentation context for FinStream AI-SRE reasoning."""

from __future__ import annotations

from dataclasses import dataclass

from services.ai_sre_agent.models import (
    Evidence,
    EvidenceSource,
    EvidenceTrustLevel,
    Incident,
)
from services.ai_sre_agent.retrieval.retriever import (
    RunbookMatch,
    RunbookRetrievalResult,
)
from services.ai_sre_agent.retrieval.runbooks import (
    RunbookStatus,
)


class RunbookContextError(RuntimeError):
    """Retrieved runbook context violates the RAG trust contract."""


@dataclass(frozen=True, slots=True)
class RunbookContextBundle:
    """Documentation context assembled for one incident."""

    incident_id: str
    evidence: tuple[Evidence, ...]


class RunbookContextBuilder:
    """Convert trusted retrieval results into documentation context."""

    _MAX_CONTEXT_CHARS = 6000

    _PROVENANCE_STOP_WORDS = frozenset(
        {
            "a",
            "an",
            "and",
            "are",
            "as",
            "at",
            "be",
            "by",
            "fin",
            "for",
            "from",
            "in",
            "is",
            "it",
            "of",
            "on",
            "or",
            "remain",
            "service",
            "stream",
            "that",
            "the",
            "this",
            "to",
            "while",
            "with",
        }
    )

    @classmethod
    def _informative_terms(
        cls,
        match: RunbookMatch,
    ) -> tuple[str, ...]:
        return tuple(
            term
            for term in match.matched_terms
            if term not in cls._PROVENANCE_STOP_WORDS
        )

    @classmethod
    def _bounded_content(
        cls,
        content: str,
    ) -> str:
        normalized = content.strip()

        if len(normalized) <= cls._MAX_CONTEXT_CHARS:
            return normalized

        return (
            normalized[: cls._MAX_CONTEXT_CHARS].rstrip()
            + "\n\n[TRUNCATED BY FINSTREAM]"
        )

    @classmethod
    def build(
        cls,
        *,
        incident: Incident,
        retrieval: RunbookRetrievalResult,
    ) -> RunbookContextBundle:
        """Build documentation-only evidence from retrieved runbooks."""
        if retrieval.incident_id != incident.incident_id:
            raise RunbookContextError(
                "Runbook retrieval belongs to a different incident."
            )

        context: list[Evidence] = []
        seen_runbook_ids: set[str] = set()

        for match in retrieval.matches:
            document = match.document

            if document.status is not RunbookStatus.APPROVED:
                raise RunbookContextError(
                    "Only approved runbooks may enter "
                    "reasoning context."
                )

            if document.runbook_id in seen_runbook_ids:
                raise RunbookContextError(
                    "Duplicate runbook entered reasoning context: "
                    f"{document.runbook_id}"
                )

            seen_runbook_ids.add(
                document.runbook_id
            )

            informative_terms = (
                cls._informative_terms(match)
            )

            context.append(
                Evidence(
                    incident_id=incident.incident_id,
                    source=EvidenceSource.RUNBOOK,
                    tool="retrieve_approved_runbook",
                    summary=(
                        f"Approved runbook {document.runbook_id} "
                        f"v{document.version}: {document.title}. "
                        "Documentation context only; it does not "
                        "establish current runtime state."
                    ),
                    trust_level=(
                        EvidenceTrustLevel.DOCUMENTATION_CONTEXT
                    ),
                    service=None,
                    raw_reference=(
                        f"docs/runbooks/{document.path}"
                    ),
                    metadata={
                        "runbook_id": document.runbook_id,
                        "title": document.title,
                        "version": document.version,
                        "sha256": document.sha256,
                        "path": document.path,
                        "services": list(
                            document.services
                        ),
                        "alert_names": list(
                            document.alert_names
                        ),
                        "retrieval_score": match.score,
                        "matched_terms": list(
                            informative_terms
                        ),
                        "retrieval_reasons": list(
                            match.reasons
                        ),
                        "content": cls._bounded_content(
                            document.content
                        ),
                    },
                )
            )

        return RunbookContextBundle(
            incident_id=incident.incident_id,
            evidence=tuple(context),
        )
