# RB-PRODUCER-001 — Producer Delivery Failure

## Purpose

Guide investigation of FinStream transaction-producer delivery
failures.

This runbook provides procedures and known relationships, not current
incident facts.

## Primary service

`producer`

## Typical signals

- producer delivery-failure counter increases;
- transaction publishing rate falls;
- Kafka connectivity errors appear;
- producer Pod becomes unavailable.

## Diagnostic procedure

1. Check producer Prometheus availability.
2. Check producer publishing rate.
3. Check delivery-failure metrics.
4. Inspect producer Deployment and Pods.
5. Inspect recent Kubernetes events.
6. Inspect producer logs.
7. Check Kafka broker health.
8. Check transactions topic metadata.

## Interpretation

Separate producer workload failure from Kafka dependency failure.

Healthy Kafka diagnostics weaken explanations that blame the Kafka
broker.

A healthy producer workload with explicit delivery errors requires
different investigation from an unavailable producer Pod.

## Remediation guidance

No producer mutation should be derived solely from this document.

Live remediation must be selected by deterministic FinStream policy and
pass the normal authorization and safety controls.

## Verification

Confirm:

- producer is available;
- transaction publishing resumes;
- delivery failures stop increasing;
- Kafka remains healthy.
