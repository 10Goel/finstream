"""Tests for the FinStream multi-source grounding quality gate."""

from __future__ import annotations

from dataclasses import replace

import pytest

from services.ai_sre_agent.evaluation.grounding import (
    GroundingMode,
)
from services.ai_sre_agent.evaluation.grounding_quality import (
    GroundingQualityGate,
    GroundingQualityThresholds,
)
from services.ai_sre_agent.evaluation.grounding_runner import (
    GroundingEvaluationMetrics,
    GroundingEvaluationReport,
)


def perfect_metrics(
    *,
    mode: GroundingMode | None,
    total_cases: int,
) -> GroundingEvaluationMetrics:
    runbooks_enabled = (
        mode is None
        or mode.uses_runbooks
    )

    history_enabled = (
        mode is None
        or mode.uses_history
    )

    return GroundingEvaluationMetrics(
        mode=mode,
        total_cases=total_cases,
        passed_cases=total_cases,
        failed_cases=0,
        pass_rate=1.0,
        decision_accuracy=1.0,
        selection_accuracy=1.0,
        safe_abstention_accuracy=1.0,
        runbook_top1_accuracy=(
            1.0
            if runbooks_enabled
            else None
        ),
        historical_top1_accuracy=(
            1.0
            if history_enabled
            else None
        ),
        runbook_citation_integrity_rate=(
            1.0
            if runbooks_enabled
            else None
        ),
        historical_citation_integrity_rate=(
            1.0
            if history_enabled
            else None
        ),
        documentation_evidence_leaks=0,
        historical_evidence_leaks=0,
        cross_namespace_citation_violations=0,
        reasoner_errors=0,
    )


def perfect_report() -> GroundingEvaluationReport:
    return GroundingEvaluationReport(
        cases=(),
        overall=perfect_metrics(
            mode=None,
            total_cases=20,
        ),
        mode_metrics=tuple(
            perfect_metrics(
                mode=mode,
                total_cases=5,
            )
            for mode in GroundingMode
        ),
    )


def test_perfect_grounding_report_passes_quality_gate() -> None:
    result = GroundingQualityGate.evaluate(
        perfect_report()
    )

    assert result.passed is True
    assert result.violations == ()


def test_decision_regression_fails_quality_gate() -> None:
    report = perfect_report()

    degraded = replace(
        report,
        overall=replace(
            report.overall,
            decision_accuracy=0.95,
        ),
    )

    result = GroundingQualityGate.evaluate(
        degraded
    )

    assert result.passed is False

    assert any(
        "overall decision_accuracy"
        in violation
        for violation in result.violations
    )


def test_security_regression_fails_quality_gate() -> None:
    report = perfect_report()

    combined_mode = (
        GroundingMode
        .CURRENT_PLUS_RUNBOOKS_AND_HISTORY
    )

    degraded_modes = tuple(
        replace(
            metrics,
            historical_evidence_leaks=1,
        )
        if metrics.mode is combined_mode
        else metrics
        for metrics in report.mode_metrics
    )

    degraded = replace(
        report,
        overall=replace(
            report.overall,
            historical_evidence_leaks=1,
        ),
        mode_metrics=degraded_modes,
    )

    result = GroundingQualityGate.evaluate(
        degraded
    )

    assert result.passed is False

    assert any(
        "historical evidence leak"
        in violation
        for violation in result.violations
    )


def test_missing_grounding_mode_fails_quality_gate() -> None:
    report = perfect_report()

    degraded = replace(
        report,
        mode_metrics=report.mode_metrics[:-1],
    )

    result = GroundingQualityGate.evaluate(
        degraded
    )

    assert result.passed is False

    assert any(
        "were missing"
        in violation
        for violation in result.violations
    )


def test_invalid_quality_threshold_is_rejected() -> None:
    with pytest.raises(
        ValueError,
        match="min_pass_rate",
    ):
        GroundingQualityThresholds(
            min_pass_rate=1.01
        )
