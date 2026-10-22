"""Evaluation domain models for FinStream AI-SRE."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ExpectedDecision(str, Enum):
    """Expected high-level decision for an evaluation scenario."""

    SELECT = "SELECT"
    ABSTAIN = "ABSTAIN"


@dataclass(frozen=True, slots=True)
class EvaluationExpectation:
    """Expected safe behaviour for one AI-SRE scenario."""

    decision: ExpectedDecision
    expected_candidate_ids: tuple[str, ...] = ()
    required_ruled_out_subsystems: tuple[str, ...] = ()
    forbidden_candidate_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if (
            self.decision is ExpectedDecision.SELECT
            and not self.expected_candidate_ids
        ):
            raise ValueError(
                "SELECT expectations require at least one "
                "expected candidate ID."
            )

        if (
            self.decision is ExpectedDecision.ABSTAIN
            and self.expected_candidate_ids
        ):
            raise ValueError(
                "ABSTAIN expectations cannot define selected "
                "candidate IDs."
            )


@dataclass(frozen=True, slots=True)
class EvaluationScenario:
    """One deterministic AI-SRE evaluation scenario."""

    scenario_id: str
    description: str
    affected_service: str
    expectation: EvaluationExpectation

    def __post_init__(self) -> None:
        if not self.scenario_id.strip():
            raise ValueError(
                "Evaluation scenario ID must not be empty."
            )

        if not self.description.strip():
            raise ValueError(
                "Evaluation scenario description must not be empty."
            )

        if not self.affected_service.strip():
            raise ValueError(
                "Evaluation affected service must not be empty."
            )


@dataclass(frozen=True, slots=True)
class EvaluationCaseResult:
    """Evaluation result for one scenario."""

    scenario_id: str
    passed: bool
    violations: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class EvaluationSuiteSummary:
    """Aggregate deterministic evaluation statistics."""

    total: int
    passed: int
    failed: int
    pass_rate: float
