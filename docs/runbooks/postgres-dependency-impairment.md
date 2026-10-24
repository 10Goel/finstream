# RB-POSTGRES-001 — PostgreSQL Dependency Impairment

## Purpose

Guide investigation when PostgreSQL may be contributing to a FinStream
API or processor incident.

This document does not establish current PostgreSQL health.

## Primary services

`postgres`, `api`, `processor`

## Typical signals

Potential PostgreSQL impairment may include:

- database health check failure;
- connection failures;
- transaction persistence failures;
- stale persistence activity;
- explicit database errors in application logs.

## Diagnostic procedure

1. Check PostgreSQL reachability.
2. Check the read-only AI-SRE diagnostic identity.
3. Inspect connection statistics.
4. Check persistence freshness.
5. Inspect API or processor logs for database errors.
6. Compare database observations with Kubernetes workload state.

## Interpretation

A reachable PostgreSQL database directly contradicts a hypothesis that
claims PostgreSQL itself is unavailable.

Persistence becoming stale may be a downstream effect of an unavailable
processor and must not automatically be interpreted as a database
failure.

## Remediation guidance

Database mutation is not part of the FinStream AI-SRE live execution
allowlist.

Do not perform schema changes, failovers, credential changes, or
database restarts from model output.

## Verification

Confirm:

- PostgreSQL accepts connections;
- the diagnostic identity remains read-only;
- persistence resumes where expected;
- dependent workloads recover.

## Escalation

Escalate database incidents requiring mutation, failover, storage
repair, credential changes, or schema modification.
