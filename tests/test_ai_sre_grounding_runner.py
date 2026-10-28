"""Tests for FinStream combined-grounding evaluation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from services.ai_sre_agent.evaluation.grounding import (
    GroundingMode,
)
from services.ai_sre_agent.evaluation.grounding_quality import (
    GroundingQualityGate,
)
from services.ai_sre_agent.evaluation.grounding_runner import (
    GroundingEvaluationRunner,
)
from services.ai_sre_agent.evaluation.grounding_scenarios import (
    GroundingBenchmarkScenario,
    grounding_scenario_catalog,
)
from services.ai_sre_agent.memory import (
    DeterministicIncidentMemoryRetriever,
    SQLiteIncidentMemoryStore,
)
from services.ai_sre_agent.models import (
    Incident,
    IncidentStatus,
)
from services.ai_sre_agent.reasoning.selector import (
    CandidateSelectionOutcome,
    EvidenceConstrainedReasoner,
    SelectedCandidate,
)
from services.ai_sre_agent.retrieval import (
    DeterministicRunbookRetriever,
    RunbookCatalog,
)


class ContextAwareFirstCandidateProvider:
    """Select first deterministic candidate and cite supplied context."""

    def __init__(self) -> None:
        self.calls = 0

    def generate(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
    ) -> str:
        del system_prompt

        self.calls += 1

        payload = json.loads(
            user_prompt
        )

        candidate = payload["candidates"][0]

        documentation = payload.get(
            "documentation_context",
            [],
        )

        history = payload.get(
            "historical_context",
            [],
        )

        documentation_ids = (
            [documentation[0]["context_id"]]
            if documentation
            else []
        )

        historical_ids = (
            [history[0]["context_id"]]
            if history
            else []
        )

        explanation = (
            "Current operational evidence supports "
            "the deterministic candidate."
        )

        if documentation_ids:
            explanation += (
                " Approved runbook documentation "
                "provides reference context."
            )

        if historical_ids:
            explanation += (
                " A historical incident provides "
                "reference precedent."
            )

        return json.dumps(
            {
                "selections": [
                    {
                        "candidate_id": (
                            candidate["candidate_id"]
                        ),
                        "confidence": min(
                            0.90,
                            candidate[
                                "confidence_ceiling"
                            ],
                        ),
                        "explanation": explanation,
                        "documentation_context_ids": (
                            documentation_ids
                        ),
                        "historical_context_ids": (
                            historical_ids
                        ),
                    }
                ],
                "abstain": False,
                "abstention_reason": None,
            }
        )


def processor_scenario() -> GroundingBenchmarkScenario:
    return next(
        item
        for item in grounding_scenario_catalog()
        if item.scenario_id == "processor-outage"
    )


def seed_historical_memory(
    *,
    store: SQLiteIncidentMemoryStore,
    scenario: GroundingBenchmarkScenario,
) -> None:
    seed = scenario.historical_seed

    incident = Incident(
        fingerprint=seed.fingerprint,
        alert_name=seed.alert_name,
        alert_status=seed.alert_status,
        severity=seed.severity,
        affected_service=seed.affected_service,
        summary=seed.summary,
        status=IncidentStatus.INVESTIGATING,
        incident_id=seed.incident_id,
    )

    if seed.abstained:
        selection = CandidateSelectionOutcome(
            selections=(),
            abstained=True,
            abstention_reason=(
                seed.abstention_reason
            ),
        )
    else:
        selection = CandidateSelectionOutcome(
            selections=tuple(
                SelectedCandidate(
                    candidate_id=candidate_id,
                    statement=(
                        "Historical benchmark "
                        "candidate."
                    ),
                    confidence=0.90,
                    model_rationale=(
                        "Historical benchmark "
                        "selection."
                    ),
                    supporting_evidence=(),
                    contradicting_evidence=(),
                )
                for candidate_id
                in seed.selected_candidate_ids
            ),
            abstained=False,
            abstention_reason=None,
        )

    store.record_investigation(
        incident=incident,
        selection=selection,
    )

    store.finalize(
        incident_id=incident.incident_id,
        final_status=seed.final_status,
        resolution_summary=(
            seed.resolution_summary
        ),
    )


def make_runner(
    *,
    tmp_path: Path,
    provider: ContextAwareFirstCandidateProvider,
) -> GroundingEvaluationRunner:
    scenario = processor_scenario()

    store = SQLiteIncidentMemoryStore(
        tmp_path / "memory.db"
    )

    seed_historical_memory(
        store=store,
        scenario=scenario,
    )

    runbook_catalog = RunbookCatalog.load(
        repository_root=Path.cwd()
    )

    return GroundingEvaluationRunner(
        reasoner=EvidenceConstrainedReasoner(
            provider=provider
        ),
        runbook_retriever=(
            DeterministicRunbookRetriever(
                catalog=runbook_catalog
            )
        ),
        incident_memory_retriever=(
            DeterministicIncidentMemoryRetriever(
                store=store
            )
        ),
        top_k=3,
    )


def test_processor_case_passes_all_four_grounding_modes(
    tmp_path: Path,
) -> None:
    provider = ContextAwareFirstCandidateProvider()

    runner = make_runner(
        tmp_path=tmp_path,
        provider=provider,
    )

    scenario = processor_scenario()

    cases = {
        mode: runner.run_case(
            scenario=scenario,
            mode=mode,
        )
        for mode in GroundingMode
    }

    assert len(cases) == 4
    assert provider.calls == 4

    for case in cases.values():
        assert case.evaluation.passed is True

        assert case.actual_decision.value == "SELECT"

        assert case.selected_candidate_ids == (
            "processor-immediate-unavailable",
        )

        assert case.documentation_evidence_leak is False
        assert case.historical_evidence_leak is False

        assert (
            case.cross_namespace_citation_violation
            is False
        )

        assert case.runbook_citation_integrity is True
        assert case.historical_citation_integrity is True

        assert case.reasoner_error is None

    current_only = cases[
        GroundingMode.CURRENT_ONLY
    ]

    assert current_only.retrieved_runbook_ids == ()
    assert (
        current_only.retrieved_historical_incident_ids
        == ()
    )

    assert current_only.documentation_context_ids == ()
    assert current_only.historical_context_ids == ()

    runbooks = cases[
        GroundingMode.CURRENT_PLUS_RUNBOOKS
    ]

    assert runbooks.actual_runbook_top1_id == (
        "RB-PROCESSOR-001"
    )

    assert runbooks.runbook_top1_correct is True

    assert runbooks.documentation_context_ids

    assert runbooks.runbook_citation_context_ids

    assert (
        runbooks.retrieved_historical_incident_ids
        == ()
    )

    history = cases[
        GroundingMode.CURRENT_PLUS_HISTORY
    ]

    assert (
        history.actual_historical_top1_incident_id
        == "inc-historical-processor-outage"
    )

    assert history.historical_top1_correct is True
    assert history.historical_context_ids
    assert history.historical_citation_context_ids

    assert history.retrieved_runbook_ids == ()

    combined = cases[
        GroundingMode
        .CURRENT_PLUS_RUNBOOKS_AND_HISTORY
    ]

    assert combined.actual_runbook_top1_id == (
        "RB-PROCESSOR-001"
    )

    assert combined.runbook_top1_correct is True

    assert (
        combined.actual_historical_top1_incident_id
        == "inc-historical-processor-outage"
    )

    assert combined.historical_top1_correct is True

    assert combined.documentation_context_ids
    assert combined.historical_context_ids

    assert combined.runbook_citation_context_ids
    assert combined.historical_citation_context_ids


def test_required_grounding_channel_cannot_be_missing(
    tmp_path: Path,
) -> None:
    del tmp_path

    runner = GroundingEvaluationRunner(
        reasoner=EvidenceConstrainedReasoner(
            provider=ContextAwareFirstCandidateProvider()
        )
    )

    with pytest.raises(
        ValueError,
        match="runbook retriever",
    ):
        runner.run_case(
            scenario=processor_scenario(),
            mode=GroundingMode.CURRENT_PLUS_RUNBOOKS,
        )

    with pytest.raises(
        ValueError,
        match="incident-memory retriever",
    ):
        runner.run_case(
            scenario=processor_scenario(),
            mode=GroundingMode.CURRENT_PLUS_HISTORY,
        )


def make_suite_runner(
    *,
    tmp_path: Path,
    provider: ContextAwareFirstCandidateProvider,
) -> GroundingEvaluationRunner:
    store = SQLiteIncidentMemoryStore(
        tmp_path / "suite-memory.db"
    )

    for scenario in grounding_scenario_catalog():
        seed_historical_memory(
            store=store,
            scenario=scenario,
        )

    runbook_catalog = RunbookCatalog.load(
        repository_root=Path.cwd()
    )

    return GroundingEvaluationRunner(
        reasoner=EvidenceConstrainedReasoner(
            provider=provider
        ),
        runbook_retriever=(
            DeterministicRunbookRetriever(
                catalog=runbook_catalog
            )
        ),
        incident_memory_retriever=(
            DeterministicIncidentMemoryRetriever(
                store=store
            )
        ),
        top_k=3,
    )


def test_full_grounding_suite_runs_twenty_cases(
    tmp_path: Path,
) -> None:
    provider = ContextAwareFirstCandidateProvider()

    runner = make_suite_runner(
        tmp_path=tmp_path,
        provider=provider,
    )

    report = runner.run_suite(
        scenarios=grounding_scenario_catalog(),
    )

    assert len(report.cases) == 20

    assert report.overall.total_cases == 20
    assert report.overall.passed_cases == 20
    assert report.overall.failed_cases == 0

    assert report.overall.pass_rate == 1.0
    assert report.overall.decision_accuracy == 1.0
    assert report.overall.selection_accuracy == 1.0

    assert (
        report.overall.safe_abstention_accuracy
        == 1.0
    )

    assert (
        report.overall.runbook_top1_accuracy
        == 1.0
    )

    assert (
        report.overall.historical_top1_accuracy
        == 1.0
    )

    assert (
        report.overall
        .runbook_citation_integrity_rate
        == 1.0
    )

    assert (
        report.overall
        .historical_citation_integrity_rate
        == 1.0
    )

    assert (
        report.overall.documentation_evidence_leaks
        == 0
    )

    assert (
        report.overall.historical_evidence_leaks
        == 0
    )

    assert (
        report.overall
        .cross_namespace_citation_violations
        == 0
    )

    assert report.overall.reasoner_errors == 0

    # Three SELECT scenarios invoke the model in each
    # of four grounding modes. The two no-candidate
    # scenarios safely abstain before model invocation.
    assert provider.calls == 12

    quality = GroundingQualityGate.evaluate(
        report
    )

    assert quality.passed is True
    assert quality.violations == ()


def test_grounding_suite_reports_each_mode_separately(
    tmp_path: Path,
) -> None:
    runner = make_suite_runner(
        tmp_path=tmp_path,
        provider=ContextAwareFirstCandidateProvider(),
    )

    report = runner.run_suite(
        scenarios=grounding_scenario_catalog(),
    )

    assert len(report.mode_metrics) == 4

    for mode in GroundingMode:
        metrics = report.metrics_for(mode)

        assert metrics.mode is mode
        assert metrics.total_cases == 5
        assert metrics.passed_cases == 5
        assert metrics.failed_cases == 0

        assert metrics.pass_rate == 1.0
        assert metrics.decision_accuracy == 1.0
        assert metrics.selection_accuracy == 1.0

        assert (
            metrics.safe_abstention_accuracy
            == 1.0
        )

        assert (
            metrics.documentation_evidence_leaks
            == 0
        )

        assert metrics.historical_evidence_leaks == 0

        assert (
            metrics
            .cross_namespace_citation_violations
            == 0
        )

        assert metrics.reasoner_errors == 0

        if mode.uses_runbooks:
            assert metrics.runbook_top1_accuracy == 1.0

            assert (
                metrics
                .runbook_citation_integrity_rate
                == 1.0
            )
        else:
            assert metrics.runbook_top1_accuracy is None

            assert (
                metrics
                .runbook_citation_integrity_rate
                is None
            )

        if mode.uses_history:
            assert (
                metrics.historical_top1_accuracy
                == 1.0
            )

            assert (
                metrics
                .historical_citation_integrity_rate
                == 1.0
            )
        else:
            assert (
                metrics.historical_top1_accuracy
                is None
            )

            assert (
                metrics
                .historical_citation_integrity_rate
                is None
            )


def test_grounding_suite_rejects_empty_inputs(
    tmp_path: Path,
) -> None:
    runner = make_suite_runner(
        tmp_path=tmp_path,
        provider=ContextAwareFirstCandidateProvider(),
    )

    with pytest.raises(
        ValueError,
        match="requires scenarios",
    ):
        runner.run_suite(
            scenarios=(),
        )

    with pytest.raises(
        ValueError,
        match="requires modes",
    ):
        runner.run_suite(
            scenarios=grounding_scenario_catalog(),
            modes=(),
        )
