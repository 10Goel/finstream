"""Deterministic evidence constraints for FinStream AI-SRE reasoning."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from services.ai_sre_agent.models import Evidence, Incident


@dataclass(frozen=True, slots=True)
class CandidateHypothesis:
    """A hypothesis the model is permitted to reason about."""

    candidate_id: str
    statement: str
    supporting_evidence: tuple[str, ...]
    contradicting_evidence: tuple[str, ...] = ()
    confidence_ceiling: float = 0.99


@dataclass(frozen=True, slots=True)
class ReasoningConstraints:
    """Deterministic facts and candidate boundaries for one incident."""

    affected_service: str
    observed_conditions: tuple[str, ...]
    ruled_out_subsystems: tuple[str, ...]
    candidates: tuple[CandidateHypothesis, ...]


class EvidenceConstraintBuilder:
    """Translate trusted evidence into deterministic reasoning limits."""

    @staticmethod
    def _normalize_service(
        service: str | None,
    ) -> str | None:
        if service is None:
            return None

        normalized = service.strip().casefold()

        aliases = {
            "postgresql": "postgres",
            "stream_processor": "processor",
            "stream-processor": "processor",
        }

        return aliases.get(
            normalized,
            normalized,
        )

    @staticmethod
    def _integer(
        metadata: dict[str, Any],
        key: str,
    ) -> int | None:
        value = metadata.get(key)

        if isinstance(value, bool):
            return None

        if isinstance(value, int):
            return value

        return None

    @classmethod
    def _reports_unavailable(
        cls,
        evidence: Evidence,
    ) -> bool:
        metadata = evidence.metadata

        if evidence.tool == "get_service_health":
            down_targets = cls._integer(
                metadata,
                "down_targets",
            )
            up_targets = cls._integer(
                metadata,
                "up_targets",
            )
            series_count = cls._integer(
                metadata,
                "series_count",
            )

            if down_targets is not None and down_targets > 0:
                return True

            if (
                up_targets == 0
                and series_count is not None
                and series_count > 0
            ):
                return True

        if evidence.tool == "get_deployment_status":
            if metadata.get("healthy") is False:
                return True

            ready = cls._integer(
                metadata,
                "ready_replicas",
            )
            available = cls._integer(
                metadata,
                "available_replicas",
            )

            if ready == 0 and available == 0:
                return True

        if evidence.tool == "get_pods":
            pod_count = cls._integer(
                metadata,
                "pod_count",
            )
            ready_count = cls._integer(
                metadata,
                "ready_count",
            )

            if pod_count == 0:
                return True

            if (
                pod_count is not None
                and pod_count > 0
                and ready_count == 0
            ):
                return True

        return False

    @classmethod
    def _reports_healthy(
        cls,
        evidence: Evidence,
    ) -> bool:
        metadata = evidence.metadata

        if metadata.get("healthy") is True:
            return True

        if evidence.tool == "get_service_health":
            up_targets = cls._integer(
                metadata,
                "up_targets",
            )
            down_targets = cls._integer(
                metadata,
                "down_targets",
            )

            return (
                up_targets is not None
                and up_targets > 0
                and down_targets == 0
            )

        return False

    @classmethod
    def build(
        cls,
        *,
        incident: Incident,
        evidence: list[Evidence],
    ) -> ReasoningConstraints:
        """Build deterministic reasoning boundaries from evidence."""
        affected_service = cls._normalize_service(
            incident.affected_service
        )

        if affected_service is None:
            raise ValueError(
                "Incident affected_service must not be empty."
            )

        for item in evidence:
            if item.incident_id != incident.incident_id:
                raise ValueError(
                    "Evidence belongs to a different incident."
                )

        supporting_ids: list[str] = []
        conditions: list[str] = []
        ruled_out: list[str] = []

        def add_condition(condition: str) -> None:
            if condition not in conditions:
                conditions.append(condition)

        def add_ruled_out(service: str) -> None:
            if service not in ruled_out:
                ruled_out.append(service)

        for item in evidence:
            service = cls._normalize_service(
                item.service
            )

            if (
                service == affected_service
                and cls._reports_unavailable(item)
            ):
                if item.evidence_id not in supporting_ids:
                    supporting_ids.append(
                        item.evidence_id
                    )

                add_condition(
                    f"{affected_service}_unavailable"
                )

            if (
                service is not None
                and service != affected_service
                and cls._reports_healthy(item)
            ):
                add_condition(
                    f"{service}_healthy"
                )
                add_ruled_out(service)

            if (
                service == affected_service
                and item.tool
                == "get_consumer_group_state"
            ):
                state = item.metadata.get("state")
                member_count = cls._integer(
                    item.metadata,
                    "member_count",
                )

                if (
                    state == "EMPTY"
                    or member_count == 0
                ):
                    add_condition(
                        f"{affected_service}_consumer_group_empty"
                    )

            if (
                service == affected_service
                and item.tool == "get_consumer_lag"
            ):
                total_lag = cls._integer(
                    item.metadata,
                    "total_lag",
                )

                if (
                    total_lag is not None
                    and total_lag > 0
                ):
                    add_condition(
                        f"{affected_service}_consumer_lag_present"
                    )

            if (
                item.tool == "get_persistence_freshness"
                and item.metadata.get("fresh") is True
            ):
                add_condition(
                    "persistence_fresh"
                )

        candidates: list[CandidateHypothesis] = []

        if supporting_ids:
            candidates.append(
                CandidateHypothesis(
                    candidate_id=(
                        f"{affected_service}-"
                        "immediate-unavailable"
                    ),
                    statement=(
                        f"FinStream {affected_service} workload "
                        "is unavailable; the deeper reason is "
                        "not established by the supplied evidence."
                    ),
                    supporting_evidence=tuple(
                        supporting_ids
                    ),
                )
            )

        return ReasoningConstraints(
            affected_service=affected_service,
            observed_conditions=tuple(
                conditions
            ),
            ruled_out_subsystems=tuple(
                ruled_out
            ),
            candidates=tuple(
                candidates
            ),
        )
