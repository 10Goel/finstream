"""Combined grounding benchmark corpus for FinStream AI-SRE."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from services.ai_sre_agent.evaluation.grounding import (
    GroundingExpectation,
    GroundingMode,
    GroundingSecurityExpectation,
)
from services.ai_sre_agent.evaluation.models import (
    ExpectedDecision,
)
from services.ai_sre_agent.evaluation.scenarios import (
    EvaluationFixture,
    ambiguous_processor_fixture,
    healthy_baseline_fixture,
    kafka_dependency_impairment_fixture,
    postgres_dependency_impairment_fixture,
    processor_outage_fixture,
)
from services.ai_sre_agent.models import (
    AlertStatus,
    IncidentStatus,
)

FixtureFactory = Callable[[], EvaluationFixture]


@dataclass(frozen=True, slots=True)
class HistoricalGroundingSeed:
    """Historical incident used as deterministic benchmark precedent."""

    incident_id: str
    fingerprint: str
    alert_name: str
    alert_status: AlertStatus
    severity: str
    affected_service: str | None
    summary: str | None

    selected_candidate_ids: tuple[str, ...]
    abstained: bool
    abstention_reason: str | None

    final_status: IncidentStatus = IncidentStatus.RESOLVED
    resolution_summary: str = (
        "Historical benchmark incident reached a verified "
        "terminal state."
    )

    def __post_init__(self) -> None:
        if not self.incident_id.strip():
            raise ValueError(
                "Historical seed incident ID must not be blank."
            )

        if not self.fingerprint.strip():
            raise ValueError(
                "Historical seed fingerprint must not be blank."
            )

        if self.abstained:
            if self.selected_candidate_ids:
                raise ValueError(
                    "Abstaining historical seed cannot contain "
                    "selected candidate IDs."
                )

            if (
                self.abstention_reason is None
                or not self.abstention_reason.strip()
            ):
                raise ValueError(
                    "Abstaining historical seed requires "
                    "an abstention reason."
                )

        else:
            if not self.selected_candidate_ids:
                raise ValueError(
                    "Selecting historical seed requires at least "
                    "one candidate ID."
                )

            if self.abstention_reason is not None:
                raise ValueError(
                    "Selecting historical seed cannot contain "
                    "an abstention reason."
                )

        if self.final_status not in {
            IncidentStatus.RESOLVED,
            IncidentStatus.FAILED,
            IncidentStatus.CLOSED,
        }:
            raise ValueError(
                "Historical seed must use a terminal status."
            )

        if not self.resolution_summary.strip():
            raise ValueError(
                "Historical seed requires a resolution summary."
            )


@dataclass(frozen=True, slots=True)
class GroundingBenchmarkScenario:
    """One reusable scenario for multi-source grounding evaluation."""

    scenario_id: str
    fixture_factory: FixtureFactory

    expected_runbook_top1_id: str | None

    historical_seed: HistoricalGroundingSeed

    security: GroundingSecurityExpectation = field(
        default_factory=GroundingSecurityExpectation
    )

    def make_fixture(self) -> EvaluationFixture:
        """Return a fresh current-incident evaluation fixture."""
        fixture = self.fixture_factory()

        if (
            fixture.scenario.scenario_id
            != self.scenario_id
        ):
            raise ValueError(
                "Grounding scenario ID does not match "
                "its evaluation fixture."
            )

        return fixture

    def expectation_for(
        self,
        *,
        mode: GroundingMode,
    ) -> GroundingExpectation:
        """Return retrieval expectations for one grounding mode."""
        expectation = GroundingExpectation(
            expected_runbook_top1_id=(
                self.expected_runbook_top1_id
                if mode.uses_runbooks
                else None
            ),
            expected_historical_top1_incident_id=(
                self.historical_seed.incident_id
                if mode.uses_history
                else None
            ),
        )

        expectation.validate_mode(
            mode=mode
        )

        return expectation


def _scenario(
    *,
    fixture_factory: FixtureFactory,
    expected_runbook_top1_id: str | None,
) -> GroundingBenchmarkScenario:
    fixture = fixture_factory()

    scenario = fixture.scenario
    incident = fixture.incident
    expectation = scenario.expectation

    abstained = (
        expectation.decision
        is ExpectedDecision.ABSTAIN
    )

    historical_seed = HistoricalGroundingSeed(
        incident_id=(
            f"inc-historical-{scenario.scenario_id}"
        ),
        # Matching recurrence fingerprint is intentional.
        # The current and historical incident IDs remain different.
        fingerprint=incident.fingerprint,
        alert_name=incident.alert_name,
        alert_status=incident.alert_status,
        severity=incident.severity,
        affected_service=incident.affected_service,
        summary=incident.summary,
        selected_candidate_ids=(
            ()
            if abstained
            else expectation.expected_candidate_ids
        ),
        abstained=abstained,
        abstention_reason=(
            "Historical benchmark incident safely abstained "
            "because current-state evidence was insufficient."
            if abstained
            else None
        ),
        resolution_summary=(
            "Historical benchmark incident was finalized "
            "after bounded investigation and independent "
            "verification."
        ),
    )

    return GroundingBenchmarkScenario(
        scenario_id=scenario.scenario_id,
        fixture_factory=fixture_factory,
        expected_runbook_top1_id=(
            expected_runbook_top1_id
        ),
        historical_seed=historical_seed,
    )


def grounding_scenario_catalog() -> tuple[
    GroundingBenchmarkScenario,
    ...,
]:
    """Return the combined RAG + memory evaluation corpus."""
    return (
        _scenario(
            fixture_factory=processor_outage_fixture,
            expected_runbook_top1_id=(
                "RB-PROCESSOR-001"
            ),
        ),
        _scenario(
            fixture_factory=(
                kafka_dependency_impairment_fixture
            ),
            expected_runbook_top1_id=(
                "RB-KAFKA-001"
            ),
        ),
        _scenario(
            fixture_factory=(
                postgres_dependency_impairment_fixture
            ),
            expected_runbook_top1_id=(
                "RB-POSTGRES-001"
            ),
        ),
        _scenario(
            fixture_factory=healthy_baseline_fixture,
            expected_runbook_top1_id=None,
        ),
        _scenario(
            fixture_factory=ambiguous_processor_fixture,
            expected_runbook_top1_id=None,
        ),
    )
