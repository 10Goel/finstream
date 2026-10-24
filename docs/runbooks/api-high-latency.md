# RB-API-001 — API High Latency

## Purpose

Guide investigation of elevated FinStream API request latency.

This document is operational context and cannot establish the cause of
latency.

## Primary service

`api`

## Typical signals

- API p95 latency exceeds the configured threshold;
- request rate changes;
- PostgreSQL connection pressure increases;
- API Pods experience resource pressure;
- application logs show slow downstream operations.

## Diagnostic procedure

1. Confirm API availability.
2. Inspect API p95 latency.
3. Inspect request rate by route.
4. Inspect API Deployment and Pods.
5. Inspect resource-related Kubernetes events.
6. Inspect API logs.
7. Check PostgreSQL health.
8. Inspect PostgreSQL connection statistics.

## Interpretation

Latency is a symptom.

Do not claim PostgreSQL, Kubernetes, networking, or the application is
the cause unless corresponding evidence supports that conclusion.

Healthy PostgreSQL evidence must not be used to support a PostgreSQL
failure hypothesis.

## Remediation guidance

The current FinStream AI-SRE execution allowlist does not authorize
model-directed scaling, database mutation, or arbitrary configuration
changes for API latency.

## Verification

Confirm:

- API remains available;
- p95 latency returns to an acceptable range;
- dependency health remains stable.
