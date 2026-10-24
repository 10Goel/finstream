# RB-DLQ-001 — Dead-Letter Queue Activity

## Purpose

Guide investigation when the FinStream processor writes malformed or
invalid transaction records to the Kafka dead-letter queue.

This runbook does not establish that DLQ activity is currently present.

## Primary service

`processor`

## Typical signals

- invalid-transaction counter increases;
- DLQ-message counter increases;
- processor remains otherwise healthy;
- logs indicate validation or decoding failures.

## Diagnostic procedure

1. Check invalid-transaction activity.
2. Check DLQ activity.
3. Confirm processor availability.
4. Inspect processor logs.
5. Inspect representative malformed-message metadata where safe.
6. Confirm Kafka broker and topic health.

## Interpretation

DLQ activity may represent correct defensive behavior rather than a
processor outage.

Do not restart the processor merely because malformed input is being
rejected successfully.

A healthy processor that continues processing valid traffic should not
be diagnosed as unavailable solely because DLQ messages exist.

## Remediation guidance

Prefer identifying and correcting the producer or upstream data-quality
problem.

Do not automatically replay malformed messages.

## Verification

Confirm:

- valid traffic continues processing;
- malformed input is isolated;
- DLQ growth stops after the upstream issue is corrected;
- no valid records are being incorrectly rejected.
