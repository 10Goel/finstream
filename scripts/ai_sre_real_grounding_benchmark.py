"""Repeated real-Qwen multi-source grounding benchmark for FinStream."""

from __future__ import annotations

import os
import tempfile
import time
from pathlib import Path

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
from services.ai_sre_agent.reasoning.ollama import (
    OllamaModelProvider,
)
from services.ai_sre_agent.reasoning.provider import ModelProviderError
from services.ai_sre_agent.reasoning.selector import (
    CandidateSelectionOutcome,
    CandidateSelectionResponse,
    EvidenceConstrainedReasoner,
    SelectedCandidate,
)
from services.ai_sre_agent.retrieval import (
    DeterministicRunbookRetriever,
    RunbookCatalog,
)

MODEL = "qwen3:1.7b"
SEED = 42
KEEP_ALIVE = "5m"
TIMEOUT_SECONDS = 300.0
CONTEXT_LENGTH = 4096
TOP_K = 3

RUNS = int(
    os.environ.get(
        "FINSTREAM_GROUNDING_RUNS",
        "3",
    )
)

if RUNS < 1:
    raise ValueError(
        "FINSTREAM_GROUNDING_RUNS must be at least 1."
    )


def seed_historical_memory(
    *,
    store: SQLiteIncidentMemoryStore,
    scenarios: tuple[
        GroundingBenchmarkScenario,
        ...,
    ],
) -> None:
    """Seed deterministic finalized historical precedent."""
    for scenario in scenarios:
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
    store: SQLiteIncidentMemoryStore,
) -> GroundingEvaluationRunner:
    """Build one real-Qwen combined-grounding runner."""
    runbook_catalog = RunbookCatalog.load(
        repository_root=Path.cwd()
    )

    runbook_retriever = (
        DeterministicRunbookRetriever(
            catalog=runbook_catalog
        )
    )

    historical_retriever = (
        DeterministicIncidentMemoryRetriever(
            store=store
        )
    )

    provider = OllamaModelProvider(
        model=MODEL,
        timeout_seconds=TIMEOUT_SECONDS,
        context_length=CONTEXT_LENGTH,
        seed=SEED,
        keep_alive=KEEP_ALIVE,
        response_schema=(
            CandidateSelectionResponse
            .model_json_schema()
        ),
    )

    provider = BoundedTransientRetryProvider(
        provider=provider,
        max_attempts=int(
            os.environ.get(
                "FINSTREAM_OLLAMA_MAX_ATTEMPTS",
                "3",
            )
        ),
    )

    return GroundingEvaluationRunner(
        reasoner=EvidenceConstrainedReasoner(
            provider=provider
        ),
        runbook_retriever=runbook_retriever,
        incident_memory_retriever=(
            historical_retriever
        ),
        top_k=TOP_K,
    )


def print_case(
    *,
    case,
) -> None:
    """Print one benchmark case compactly."""
    actual = (
        case.actual_decision.value
        if case.actual_decision is not None
        else "ERROR"
    )

    print()
    print(
        f"{case.mode.value} / "
        f"{case.scenario_id}"
    )

    print(
        "  expected:",
        case.expected_decision.value,
    )

    print(
        "  actual:",
        actual,
    )

    print(
        "  selected:",
        case.selected_candidate_ids,
    )

    print(
        "  runbook_top1:",
        case.actual_runbook_top1_id,
    )

    print(
        "  runbook_correct:",
        case.runbook_top1_correct,
    )

    print(
        "  history_top1:",
        case.actual_historical_top1_incident_id,
    )

    print(
        "  history_correct:",
        case.historical_top1_correct,
    )

    print(
        "  runbook_citations:",
        case.runbook_citation_context_ids,
    )

    print(
        "  historical_citations:",
        case.historical_citation_context_ids,
    )

    print(
        "  runbook_citation_integrity:",
        case.runbook_citation_integrity,
    )

    print(
        "  historical_citation_integrity:",
        case.historical_citation_integrity,
    )

    print(
        "  documentation_evidence_leak:",
        case.documentation_evidence_leak,
    )

    print(
        "  historical_evidence_leak:",
        case.historical_evidence_leak,
    )

    print(
        "  cross_namespace_violation:",
        case.cross_namespace_citation_violation,
    )

    print(
        "  reasoner_error:",
        case.reasoner_error,
    )

    print(
        "  passed:",
        case.evaluation.passed,
    )

    if case.evaluation.violations:
        print(
            "  violations:",
            case.evaluation.violations,
        )


def print_mode_metrics(
    *,
    report,
) -> None:
    """Print metrics for each grounding configuration."""
    print()
    print("=" * 78)
    print("GROUNDING MODE METRICS")
    print("=" * 78)

    for mode in GroundingMode:
        metrics = report.metrics_for(
            mode
        )

        print()
        print(mode.value)

        print(
            "  total_cases:",
            metrics.total_cases,
        )

        print(
            "  pass_rate:",
            metrics.pass_rate,
        )

        print(
            "  decision_accuracy:",
            metrics.decision_accuracy,
        )

        print(
            "  selection_accuracy:",
            metrics.selection_accuracy,
        )

        print(
            "  safe_abstention_accuracy:",
            metrics.safe_abstention_accuracy,
        )

        print(
            "  runbook_top1_accuracy:",
            metrics.runbook_top1_accuracy,
        )

        print(
            "  historical_top1_accuracy:",
            metrics.historical_top1_accuracy,
        )

        print(
            "  runbook_citation_integrity_rate:",
            metrics.runbook_citation_integrity_rate,
        )

        print(
            "  historical_citation_integrity_rate:",
            metrics.historical_citation_integrity_rate,
        )

        print(
            "  documentation_evidence_leaks:",
            metrics.documentation_evidence_leaks,
        )

        print(
            "  historical_evidence_leaks:",
            metrics.historical_evidence_leaks,
        )

        print(
            "  cross_namespace_citation_violations:",
            (
                metrics
                .cross_namespace_citation_violations
            ),
        )

        print(
            "  reasoner_errors:",
            metrics.reasoner_errors,
        )



class BoundedTransientRetryProvider:
    """Retry only transient Ollama transport failures once."""

    def __init__(
        self,
        *,
        provider,
        max_attempts: int = 2,
    ) -> None:
        if max_attempts < 1:
            raise ValueError(
                "max_attempts must be at least 1."
            )

        self._provider = provider
        self._max_attempts = max_attempts
        self.transient_retries = 0
        self.request_count = 0

    def generate(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
    ) -> str:
        for attempt in range(
            1,
            self._max_attempts + 1,
        ):
            self.request_count += 1
            request_id = self.request_count
            started = time.monotonic()

            print(
                f"[GROUNDING] Request {request_id} "
                f"attempt {attempt}/{self._max_attempts} "
                "started",
                flush=True,
            )

            try:
                result = self._provider.generate(
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                )

                elapsed = time.monotonic() - started
                print(
                    f"[GROUNDING] Request {request_id} "
                    f"completed in {elapsed:.2f}s",
                    flush=True,
                )
                return result

            except ModelProviderError as exc:
                elapsed = time.monotonic() - started
                print(
                    f"[GROUNDING] Request {request_id} "
                    f"failed after {elapsed:.2f}s: "
                    f"{type(exc).__name__}",
                    flush=True,
                )
                message = str(exc).lower()

                is_transient = (
                    "timed out" in message
                    or "timeout" in message
                    or "unable to reach ollama" in message
                )

                if (
                    not is_transient
                    or attempt >= self._max_attempts
                ):
                    raise

                self.transient_retries += 1

                print(
                    "\nTRANSIENT OLLAMA FAILURE: "
                    f"{exc}"
                )
                print(
                    "Retrying the same model request "
                    f"({attempt + 1}/"
                    f"{self._max_attempts})..."
                )

        raise AssertionError(
            "Unreachable transport retry state."
        )



def main() -> None:
    scenarios = grounding_scenario_catalog()

    total_cases = 0
    total_passed = 0

    total_reasoner_errors = 0

    total_documentation_leaks = 0
    total_historical_leaks = 0
    total_namespace_violations = 0

    gate_failures = 0

    print("=" * 78)
    print(
        "FINSTREAM AI-SRE — REAL QWEN "
        "MULTI-SOURCE GROUNDING BENCHMARK"
    )
    print("=" * 78)

    print("model:", MODEL)
    print("seed:", SEED)
    print("runs:", RUNS)
    print("scenarios_per_run:", len(scenarios))
    print(
        "grounding_modes:",
        len(tuple(GroundingMode)),
    )

    print(
        "evaluations_per_run:",
        (
            len(scenarios)
            * len(tuple(GroundingMode))
        ),
    )

    with tempfile.TemporaryDirectory(
        prefix="finstream-grounding-"
    ) as temporary_directory:
        store = SQLiteIncidentMemoryStore(
            Path(temporary_directory)
            / "incident-memory.db"
        )

        seed_historical_memory(
            store=store,
            scenarios=scenarios,
        )

        print()
        print(
            "PASS: deterministic historical "
            "benchmark memory seeded"
        )

        for run_number in range(
            1,
            RUNS + 1,
        ):
            print()
            print("=" * 78)
            print(
                f"REAL-QWEN RUN "
                f"{run_number}/{RUNS}"
            )
            print("=" * 78)

            report = make_runner(
                store=store
            ).run_suite(
                scenarios=scenarios
            )

            for case in report.cases:
                print_case(
                    case=case
                )

            print_mode_metrics(
                report=report
            )

            quality = (
                GroundingQualityGate.evaluate(
                    report
                )
            )

            print()
            print("=" * 78)
            print("QUALITY GATE")
            print("=" * 78)

            print(
                "passed:",
                quality.passed,
            )

            print(
                "violations:",
                quality.violations,
            )

            if not quality.passed:
                gate_failures += 1

            metrics = report.overall

            total_cases += (
                metrics.total_cases
            )

            total_passed += (
                metrics.passed_cases
            )

            total_reasoner_errors += (
                metrics.reasoner_errors
            )

            total_documentation_leaks += (
                metrics
                .documentation_evidence_leaks
            )

            total_historical_leaks += (
                metrics
                .historical_evidence_leaks
            )

            total_namespace_violations += (
                metrics
                .cross_namespace_citation_violations
            )

    print()
    print("=" * 78)
    print(
        "AGGREGATE REAL-QWEN "
        "MULTI-SOURCE RESULTS"
    )
    print("=" * 78)

    print("benchmark_runs:", RUNS)
    print("scenario_evaluations:", total_cases)

    print(
        "passed_cases:",
        total_passed,
    )

    print(
        "failed_cases:",
        total_cases - total_passed,
    )

    print(
        "overall_pass_rate:",
        total_passed / total_cases,
    )

    print(
        "reasoner_errors:",
        total_reasoner_errors,
    )

    print(
        "documentation_evidence_leaks:",
        total_documentation_leaks,
    )

    print(
        "historical_evidence_leaks:",
        total_historical_leaks,
    )

    print(
        "cross_namespace_citation_violations:",
        total_namespace_violations,
    )

    print(
        "quality_gate_failures:",
        gate_failures,
    )

    print()
    print("=" * 78)
    print("M10.14F VERDICT")
    print("=" * 78)

    assert total_passed == total_cases
    assert total_reasoner_errors == 0

    assert total_documentation_leaks == 0
    assert total_historical_leaks == 0

    assert total_namespace_violations == 0
    assert gate_failures == 0

    print(
        "PASS: every real-Qwen grounding case "
        "satisfied the deterministic benchmark"
    )

    print(
        "PASS: current operational evidence remained "
        "authoritative in every grounding mode"
    )

    print(
        "PASS: deterministic runbook retrieval "
        "remained correct"
    )

    print(
        "PASS: deterministic historical retrieval "
        "remained correct"
    )

    print(
        "PASS: runbook and historical citations "
        "preserved trusted provenance"
    )

    print(
        "PASS: documentation and historical context "
        "never became runtime evidence"
    )

    print(
        "PASS: citation namespaces remained isolated"
    )

    print(
        "PASS: zero real-Qwen reasoner failures"
    )


if __name__ == "__main__":
    main()
