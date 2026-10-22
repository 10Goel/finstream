# FinStream AI-SRE Evaluation

## Overview

FinStream includes an evidence-constrained AI-SRE subsystem for
investigating operational incidents.

The architecture deliberately separates deterministic operational
reasoning from language-model judgment.

The model does not receive unrestricted authority to invent a root
cause. Instead, FinStream:

1. collects operational evidence from trusted diagnostic tools;
2. derives deterministic observations and subsystem constraints;
3. constructs only evidence-supported candidate explanations;
4. allows the language model to rank or select only those candidates;
5. validates the model output against the deterministic boundary; and
6. safely abstains when the available evidence does not support a
   diagnosis.

This design treats the language model as a constrained reasoning
component rather than an autonomous source of operational truth.

## Evaluation Corpus

The controlled benchmark currently contains five scenario families.

| Scenario | Expected behavior |
| --- | --- |
| Processor outage | Select `processor-immediate-unavailable` |
| Kafka dependency impairment | Select the immediate producer outage without falsely proving Kafka as the root cause |
| PostgreSQL dependency impairment | Select the immediate API outage without falsely proving PostgreSQL as the root cause |
| Healthy baseline | Safely abstain |
| Ambiguous processor symptoms | Safely abstain |

The healthy and ambiguous scenarios intentionally contain no
deterministically approved diagnosis. FinStream therefore abstains
before invoking the model.

## Deterministic Baseline

Before evaluating a real language model, the same five-scenario corpus
was executed using a deterministic benchmark provider.

Observed result:

- 5/5 scenarios passed
- 100% selection accuracy
- 100% safe-abstention rate
- 0 reasoner errors
- 0 deterministic constraint violations

This verifies the evaluation harness independently of model behavior.

## Real Local Model

The real-model benchmark used:

- Model: `qwen3:1.7b`
- Runtime: Ollama
- Execution: local
- Benchmark runs: 5
- Scenarios per run: 5
- Total scenario evaluations: 25

Three scenario families contained deterministic candidates and reached
the model.

Two scenario families contained no safe deterministic candidate and
were resolved through deterministic abstention without requiring a
model call.

Therefore the repeated benchmark contained:

- 15 model selection opportunities
- 10 deterministic abstention opportunities

## Observed Real-Qwen Results

| Metric | Result |
| --- | ---: |
| Benchmark runs | 5 |
| Perfect runs | 5 |
| Scenario evaluations | 25 |
| Passed | 25 |
| Failed | 0 |
| Selection opportunities | 15 |
| Correct selections | 15 |
| Abstention opportunities | 10 |
| Correct abstentions | 10 |
| Reasoner errors | 0 |
| Constraint-violation cases | 0 |
| Overall pass rate | 100% |
| Selection accuracy | 100% |
| Safe-abstention rate | 100% |
| Reasoner-error rate | 0% |
| Constraint-violation rate | 0% |

Across this controlled evaluation corpus, `qwen3:1.7b` produced the
expected constrained behavior in all 25 scenario evaluations.

Most importantly, no evaluated response escaped FinStream's
deterministic reasoning boundary.

## Safety Properties Demonstrated

The evaluation exercises several important failure modes.

### Evidence grounding

Model-selected candidates must originate from the deterministic
candidate set generated from operational evidence.

### Evidence integrity

The model cannot rewrite candidate statements or replace supporting
and contradicting evidence references.

### Confidence bounds

Model confidence cannot exceed the deterministic confidence ceiling
assigned to the candidate.

### Healthy-subsystem protection

Healthy Kafka or PostgreSQL evidence can rule those subsystems out of
unsupported causal explanations.

### Safe abstention

When direct evidence is insufficient to establish a supported
diagnosis, FinStream produces no candidate and abstains rather than
inventing a root cause.

### Error containment

Malformed or invalid model output is treated as a reasoner failure and
does not become an operational diagnosis.

## Scope and Limitations

These results describe a controlled FinStream benchmark and should not
be interpreted as proof that the model is universally 100% accurate.

The corpus is intentionally small and focused on the current FinStream
architecture.

Further evaluation should expand:

- incident diversity;
- degraded rather than fully unavailable states;
- contradictory evidence combinations;
- stale evidence;
- partial diagnostic-tool failures;
- repeated stochastic model runs;
- larger incident histories; and
- eventual remediation-policy evaluation.

The relevant result is therefore not merely that Qwen achieved 100%
on this benchmark.

The stronger architectural property is that model behavior is bounded
by deterministic operational evidence and can safely fail or abstain
without being allowed to invent an unrestricted diagnosis.
