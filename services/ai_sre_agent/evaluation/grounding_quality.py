"""Fail-closed quality gate for FinStream multi-source grounding."""

from __future__ import annotations

from dataclasses import dataclass

from services.ai_sre_agent.evaluation.grounding import (
    GroundingMode,
)
from services.ai_sre_agent.evaluation.grounding_runner import (
    GroundingEvaluationMetrics,
    GroundingEvaluationReport,
)


@dataclass(frozen=True, slots=True)
class GroundingQualityThresholds:
    """Required quality levels for the grounding benchmark."""

    expected_total_cases: int = 20
    expected_cases_per_mode: int = 5

    min_pass_rate: float = 1.0
    min_decision_accuracy: float = 1.0
    min_selection_accuracy: float = 1.0
    min_safe_abstention_accuracy: float = 1.0

    min_runbook_top1_accuracy: float = 1.0
    min_historical_top1_accuracy: float = 1.0

    min_runbook_citation_integrity_rate: float = 1.0
    min_historical_citation_integrity_rate: float = 1.0

    require_zero_evidence_leaks: bool = True
    require_zero_namespace_violations: bool = True
    require_zero_reasoner_errors: bool = True

    def __post_init__(self) -> None:
        if self.expected_total_cases < 1:
            raise ValueError(
                "Expected total grounding cases must be positive."
            )

        if self.expected_cases_per_mode < 1:
            raise ValueError(
                "Expected grounding cases per mode must be positive."
            )

        rates = (
            ("min_pass_rate", self.min_pass_rate),
            (
                "min_decision_accuracy",
                self.min_decision_accuracy,
            ),
            (
                "min_selection_accuracy",
                self.min_selection_accuracy,
            ),
            (
                "min_safe_abstention_accuracy",
                self.min_safe_abstention_accuracy,
            ),
            (
                "min_runbook_top1_accuracy",
                self.min_runbook_top1_accuracy,
            ),
            (
                "min_historical_top1_accuracy",
                self.min_historical_top1_accuracy,
            ),
            (
                "min_runbook_citation_integrity_rate",
                self.min_runbook_citation_integrity_rate,
            ),
            (
                "min_historical_citation_integrity_rate",
                self.min_historical_citation_integrity_rate,
            ),
        )

        for name, value in rates:
            if not 0.0 <= value <= 1.0:
                raise ValueError(
                    f"{name} must be between 0.0 and 1.0."
                )


@dataclass(frozen=True, slots=True)
class GroundingQualityGateResult:
    """Result returned by the deterministic quality gate."""

    passed: bool
    violations: tuple[str, ...]


class GroundingQualityGate:
    """Validate benchmark quality and trust-boundary invariants."""

    @staticmethod
    def _require_rate(
        *,
        label: str,
        actual: float | None,
        minimum: float,
        violations: list[str],
    ) -> None:
        if actual is None:
            violations.append(
                f"{label} was not scored."
            )
            return

        if actual < minimum:
            violations.append(
                f"{label}={actual:.6f} fell below "
                f"required {minimum:.6f}."
            )

    @classmethod
    def _check_common_metrics(
        cls,
        *,
        label: str,
        metrics: GroundingEvaluationMetrics,
        thresholds: GroundingQualityThresholds,
        violations: list[str],
    ) -> None:
        if (
            metrics.passed_cases
            + metrics.failed_cases
            != metrics.total_cases
        ):
            violations.append(
                f"{label} case counts are inconsistent."
            )

        cls._require_rate(
            label=f"{label} pass_rate",
            actual=metrics.pass_rate,
            minimum=thresholds.min_pass_rate,
            violations=violations,
        )

        cls._require_rate(
            label=f"{label} decision_accuracy",
            actual=metrics.decision_accuracy,
            minimum=thresholds.min_decision_accuracy,
            violations=violations,
        )

        cls._require_rate(
            label=f"{label} selection_accuracy",
            actual=metrics.selection_accuracy,
            minimum=thresholds.min_selection_accuracy,
            violations=violations,
        )

        cls._require_rate(
            label=f"{label} safe_abstention_accuracy",
            actual=metrics.safe_abstention_accuracy,
            minimum=(
                thresholds
                .min_safe_abstention_accuracy
            ),
            violations=violations,
        )

        if thresholds.require_zero_evidence_leaks:
            if metrics.documentation_evidence_leaks:
                violations.append(
                    f"{label} contained "
                    f"{metrics.documentation_evidence_leaks} "
                    "documentation evidence leak(s)."
                )

            if metrics.historical_evidence_leaks:
                violations.append(
                    f"{label} contained "
                    f"{metrics.historical_evidence_leaks} "
                    "historical evidence leak(s)."
                )

        if (
            thresholds
            .require_zero_namespace_violations
            and metrics.cross_namespace_citation_violations
        ):
            violations.append(
                f"{label} contained "
                f"{metrics.cross_namespace_citation_violations} "
                "cross-namespace citation violation(s)."
            )

        if (
            thresholds.require_zero_reasoner_errors
            and metrics.reasoner_errors
        ):
            violations.append(
                f"{label} contained "
                f"{metrics.reasoner_errors} "
                "reasoner error(s)."
            )

    @classmethod
    def evaluate(
        cls,
        report: GroundingEvaluationReport,
        *,
        thresholds: GroundingQualityThresholds | None = None,
    ) -> GroundingQualityGateResult:
        """Evaluate one complete grounding benchmark report."""
        if thresholds is None:
            thresholds = GroundingQualityThresholds()

        violations: list[str] = []

        overall = report.overall

        if (
            overall.total_cases
            != thresholds.expected_total_cases
        ):
            violations.append(
                "overall total_cases="
                f"{overall.total_cases} did not equal "
                f"{thresholds.expected_total_cases}."
            )

        cls._check_common_metrics(
            label="overall",
            metrics=overall,
            thresholds=thresholds,
            violations=violations,
        )

        cls._require_rate(
            label="overall runbook_top1_accuracy",
            actual=overall.runbook_top1_accuracy,
            minimum=(
                thresholds.min_runbook_top1_accuracy
            ),
            violations=violations,
        )

        cls._require_rate(
            label="overall historical_top1_accuracy",
            actual=overall.historical_top1_accuracy,
            minimum=(
                thresholds.min_historical_top1_accuracy
            ),
            violations=violations,
        )

        cls._require_rate(
            label=(
                "overall "
                "runbook_citation_integrity_rate"
            ),
            actual=(
                overall
                .runbook_citation_integrity_rate
            ),
            minimum=(
                thresholds
                .min_runbook_citation_integrity_rate
            ),
            violations=violations,
        )

        cls._require_rate(
            label=(
                "overall "
                "historical_citation_integrity_rate"
            ),
            actual=(
                overall
                .historical_citation_integrity_rate
            ),
            minimum=(
                thresholds
                .min_historical_citation_integrity_rate
            ),
            violations=violations,
        )

        actual_modes = [
            metrics.mode
            for metrics in report.mode_metrics
        ]

        if any(
            mode is None
            for mode in actual_modes
        ):
            violations.append(
                "Per-mode metrics contained an unscoped mode."
            )

        scoped_modes = [
            mode
            for mode in actual_modes
            if mode is not None
        ]

        if len(scoped_modes) != len(set(scoped_modes)):
            violations.append(
                "Grounding mode metrics contained duplicates."
            )

        missing_modes = (
            set(GroundingMode)
            - set(scoped_modes)
        )

        if missing_modes:
            missing = ", ".join(
                sorted(
                    mode.value
                    for mode in missing_modes
                )
            )

            violations.append(
                "Grounding mode metrics were missing: "
                f"{missing}."
            )

        mode_total = sum(
            metrics.total_cases
            for metrics in report.mode_metrics
        )

        if mode_total != overall.total_cases:
            violations.append(
                "Per-mode case totals did not equal "
                "the overall case total."
            )

        metrics_by_mode = {
            metrics.mode: metrics
            for metrics in report.mode_metrics
            if metrics.mode is not None
        }

        for mode in GroundingMode:
            metrics = metrics_by_mode.get(mode)

            if metrics is None:
                continue

            label = mode.value

            if (
                metrics.total_cases
                != thresholds.expected_cases_per_mode
            ):
                violations.append(
                    f"{label} total_cases="
                    f"{metrics.total_cases} did not equal "
                    f"{thresholds.expected_cases_per_mode}."
                )

            cls._check_common_metrics(
                label=label,
                metrics=metrics,
                thresholds=thresholds,
                violations=violations,
            )

            if mode.uses_runbooks:
                cls._require_rate(
                    label=(
                        f"{label} "
                        "runbook_top1_accuracy"
                    ),
                    actual=(
                        metrics.runbook_top1_accuracy
                    ),
                    minimum=(
                        thresholds
                        .min_runbook_top1_accuracy
                    ),
                    violations=violations,
                )

                cls._require_rate(
                    label=(
                        f"{label} "
                        "runbook_citation_integrity_rate"
                    ),
                    actual=(
                        metrics
                        .runbook_citation_integrity_rate
                    ),
                    minimum=(
                        thresholds
                        .min_runbook_citation_integrity_rate
                    ),
                    violations=violations,
                )
            else:
                if metrics.runbook_top1_accuracy is not None:
                    violations.append(
                        f"{label} unexpectedly scored "
                        "runbook retrieval."
                    )

                if (
                    metrics
                    .runbook_citation_integrity_rate
                    is not None
                ):
                    violations.append(
                        f"{label} unexpectedly scored "
                        "runbook citation integrity."
                    )

            if mode.uses_history:
                cls._require_rate(
                    label=(
                        f"{label} "
                        "historical_top1_accuracy"
                    ),
                    actual=(
                        metrics.historical_top1_accuracy
                    ),
                    minimum=(
                        thresholds
                        .min_historical_top1_accuracy
                    ),
                    violations=violations,
                )

                cls._require_rate(
                    label=(
                        f"{label} "
                        "historical_citation_integrity_rate"
                    ),
                    actual=(
                        metrics
                        .historical_citation_integrity_rate
                    ),
                    minimum=(
                        thresholds
                        .min_historical_citation_integrity_rate
                    ),
                    violations=violations,
                )
            else:
                if (
                    metrics.historical_top1_accuracy
                    is not None
                ):
                    violations.append(
                        f"{label} unexpectedly scored "
                        "historical retrieval."
                    )

                if (
                    metrics
                    .historical_citation_integrity_rate
                    is not None
                ):
                    violations.append(
                        f"{label} unexpectedly scored "
                        "historical citation integrity."
                    )

        return GroundingQualityGateResult(
            passed=not violations,
            violations=tuple(violations),
        )
