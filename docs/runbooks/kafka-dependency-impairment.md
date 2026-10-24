# RB-KAFKA-001 — Kafka Dependency Impairment

## Purpose

Guide investigation when a FinStream workload appears unhealthy and
Kafka may be contributing to the incident.

This runbook is documentation context, not evidence of Kafka failure.

## Primary services

`kafka`, `producer`, `processor`

## Typical signals

Potential Kafka impairment may include:

- broker health checks failing;
- transactions topic metadata unavailable;
- under-replicated partitions;
- producer delivery failures;
- consumer connectivity failures.

An empty consumer group or increasing consumer lag alone does not prove
Kafka is unhealthy. Those conditions may result from an unavailable
processor.

## Diagnostic procedure

1. Check Kafka broker reachability.
2. Inspect transactions topic metadata.
3. Check partition and replication state.
4. Check producer delivery failures.
5. Check processor consumer-group membership.
6. Check processor consumer lag.
7. Compare these observations with Kubernetes workload state.
8. Check application logs for explicit Kafka errors.

## Interpretation

Kafka should be considered a supported dependency problem only when
direct Kafka diagnostics indicate impairment.

Healthy broker and topic evidence must weaken or reject hypotheses that
blame Kafka.

## Remediation guidance

Do not restart unrelated workloads merely because consumer lag exists.

Kafka remediation is outside the current FinStream autonomous execution
allowlist and should require operator investigation.

## Verification

Confirm:

- broker health is restored;
- transactions topic metadata is healthy;
- producer publishing resumes;
- consumer membership recovers;
- lag trends toward normal levels.

## Escalation

Escalate when the broker remains unreachable, topic metadata is
inconsistent, or storage/replication problems are observed.
