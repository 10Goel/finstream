# FinStream AI-SRE Live Remediation Benchmark

## Benchmark

**Checkpoint:** M10.11W  
**Date:** 2026-10-23  
**Environment:** local Kubernetes `kind` cluster  
**Target workload:** `finstream/processor`

## Scenario

A controlled processor-only failure was injected by stopping the
processor Python process from the Kubernetes node PID namespace.

The failure was deliberately constructed so that:

- the processor container remained present;
- the processor readiness probe failed;
- Kubernetes reported the processor workload unavailable;
- the processor Prometheus target reported down;
- Kafka remained healthy;
- PostgreSQL remained healthy;
- the processor pod had not restarted before remediation;
- the Deployment generation had not changed before remediation.

This created an evidence-grounded workload outage without inventing
or manually fabricating AI-SRE safety state.

## Guarded execution boundary

The remediation required all of the following:

1. deterministic evidence constraints;
2. deterministic remediation policy;
3. explicit human proposal approval;
4. execution authorization;
5. short-lived execution permit;
6. fresh runtime safety observation;
7. short-lived safety approval;
8. explicit one-attempt human LIVE execution arm;
9. atomic execution claim;
10. permit consumption;
11. arm consumption;
12. Kubernetes server-side dry-run of the exact patch;
13. live Kubernetes mutation;
14. rollout recovery;
15. independent post-execution verification;
16. tamper-evident audit-chain verification.

The model itself did not receive direct Kubernetes mutation authority.

## Result

**Live mutation accepted:** `True`

**Execution outcome:** `LIVE_MUTATION_ACCEPTED_PENDING_VERIFICATION`

**Deployment generation:** `36 -> 37`

**Previous processor pod UID:** `1b4312ff-c9e4-41d0-a433-0c9bda813e7f`

**Recovered processor pod UID:** `cfbe57c0-fe54-4b07-8e55-fca504e348ff`

**Recovered replicas:** `1/1`

**Processor Prometheus target up:** `True`

**Kafka healthy after remediation:** `True`

**PostgreSQL healthy after remediation:** `True`

**Audit records verified:** `9`

## Audit lifecycle

1. `PROPOSAL_CREATED` — `finstream-ai-sre`
2. `PROPOSAL_SUBMITTED` — `finstream-ai-sre`
3. `PROPOSAL_APPROVED` — `human-operator`
4. `AUTHORIZATION_ISSUED` — `finstream-ai-sre`
5. `PERMIT_ISSUED` — `finstream-ai-sre`
6. `EXECUTION_SAFETY_PASSED` — `finstream-ai-sre`
7. `EXECUTION_REQUESTED` — `finstream-kubernetes-executor`
8. `EXECUTION_SUCCEEDED` — `finstream-kubernetes-executor`
9. `EXECUTION_VERIFICATION_PASSED` — `finstream-execution-verifier`

## Outcome

The processor was restored through the bounded remediation path.
The old failed processor pod was replaced, the Deployment completed
its rollout, Prometheus observed the processor target recover, and
the critical dependencies remained healthy.

The final `EXECUTION_VERIFICATION_PASSED` event establishes that a
successful Kubernetes API response alone was not treated as proof of
remediation success. Recovery was evaluated separately after the
mutation.

This benchmark demonstrates a guarded AI-SRE design in which AI
reasoning is separated from deterministic execution authority.
