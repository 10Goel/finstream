# RB-PROCESSOR-001 — Processor Unavailable

## Purpose

Guide investigation of a FinStream stream-processor workload that is
unavailable or has no ready Kubernetes replicas.

This document provides operational context only. It does not establish
the current state or root cause of an incident. Current conclusions must
come from live diagnostic evidence.

## Primary service

`processor`

## Typical signals

- Prometheus reports the processor target unavailable.
- Kubernetes reports zero ready or available processor replicas.
- The processor metrics endpoint cannot be reached.
- Kafka consumer membership may disappear.
- Kafka consumer lag may increase.

Consumer-group and lag changes are downstream observations and must not
automatically be interpreted as the cause of processor unavailability.

## Diagnostic procedure

1. Confirm processor availability through Prometheus.
2. Inspect the processor Kubernetes Deployment.
3. Inspect processor Pods and restart counts.
4. Inspect recent Kubernetes events.
5. Inspect processor logs.
6. Check Kafka broker health.
7. Check transactions topic metadata.
8. Check processor consumer-group state and lag.
9. Check PostgreSQL health.
10. Check recent persistence activity.

## Interpretation

If the processor is unavailable while Kafka and PostgreSQL remain
healthy, the immediate supported conclusion is that the processor
workload is unavailable.

Do not invent a deeper configuration, scheduling, infrastructure,
application, Kafka, or database failure unless live evidence supports
that conclusion.

## Approved remediation context

A processor rolling restart may be considered only when FinStream's
deterministic remediation policy permits it.

A runbook recommendation does not authorize execution.

Any live restart must still pass:

- human approval;
- execution authorization;
- active execution permit;
- fresh runtime safety validation;
- one-shot live execution arm;
- atomic execution claim;
- Kubernetes server-side dry-run.

## Verification

After remediation:

- Deployment rollout must complete;
- desired replicas must be ready and available;
- a replacement processor Pod must be healthy;
- Prometheus must observe the processor target as up;
- Kafka must remain healthy;
- PostgreSQL must remain healthy.

Kubernetes accepting a mutation is not sufficient proof of recovery.

## Escalation

Escalate instead of restarting when:

- Kafka is unhealthy;
- PostgreSQL is unhealthy;
- another rollout is already in progress;
- evidence is ambiguous;
- safety state is stale;
- execution authorization is missing or expired.
