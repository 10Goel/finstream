# FinStream AI-SRE Trusted RAG Benchmark

**Model:** `qwen3:1.7b`

## Aggregate results

| Metric | Result |
| --- | ---: |
| Benchmark runs | 3 |
| Scenario evaluations | 15 |
| Overall pass rate | 100.0% |
| Selection accuracy | 100.0% |
| Safe abstention rate | 100.0% |
| Retrieval top-1 accuracy | 100.0% |
| Citation integrity | 100.0% |
| Documentation evidence leaks | 0 |
| Constraint violations | 0 |
| Reasoner errors | 0 |

## Scenario results

| Run | Scenario | Expected | Actual | Passed | Top-1 runbook | Citation integrity |
| ---: | --- | --- | --- | --- | --- | --- |
| 1 | processor-outage | SELECT | SELECT | True | RB-PROCESSOR-001 | True |
| 1 | kafka-dependency-impairment | SELECT | SELECT | True | RB-KAFKA-001 | True |
| 1 | postgres-dependency-impairment | SELECT | SELECT | True | RB-POSTGRES-001 | True |
| 1 | healthy-baseline | ABSTAIN | ABSTAIN | True | RB-PROCESSOR-001 | True |
| 1 | ambiguous-processor | ABSTAIN | ABSTAIN | True | RB-PROCESSOR-001 | True |
| 2 | processor-outage | SELECT | SELECT | True | RB-PROCESSOR-001 | True |
| 2 | kafka-dependency-impairment | SELECT | SELECT | True | RB-KAFKA-001 | True |
| 2 | postgres-dependency-impairment | SELECT | SELECT | True | RB-POSTGRES-001 | True |
| 2 | healthy-baseline | ABSTAIN | ABSTAIN | True | RB-PROCESSOR-001 | True |
| 2 | ambiguous-processor | ABSTAIN | ABSTAIN | True | RB-PROCESSOR-001 | True |
| 3 | processor-outage | SELECT | SELECT | True | RB-PROCESSOR-001 | True |
| 3 | kafka-dependency-impairment | SELECT | SELECT | True | RB-KAFKA-001 | True |
| 3 | postgres-dependency-impairment | SELECT | SELECT | True | RB-POSTGRES-001 | True |
| 3 | healthy-baseline | ABSTAIN | ABSTAIN | True | RB-PROCESSOR-001 | True |
| 3 | ambiguous-processor | ABSTAIN | ABSTAIN | True | RB-PROCESSOR-001 | True |

## Safety properties

- Documentation context remains separate from runtime operational evidence.
- Model selections remain constrained to deterministic FinStream candidates.
- Runbook citations are validated against trusted retrieved provenance.
- Healthy and ambiguous incidents must preserve safe abstention.
