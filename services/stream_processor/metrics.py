from prometheus_client import Counter

TRANSACTIONS_PROCESSED_TOTAL = Counter(
    "finstream_processor_transactions_processed_total",
    "Total number of valid transactions fully processed by FinStream.",
    ["status"],
)


ALERTS_TOTAL = Counter(
    "finstream_processor_alerts_total",
    "Total number of anomalous transactions detected by FinStream.",
    ["reason"],
)


INVALID_TRANSACTIONS_TOTAL = Counter(
    "finstream_processor_invalid_transactions_total",
    "Total number of invalid transactions rejected by FinStream.",
    ["reason"],
)


DLQ_MESSAGES_TOTAL = Counter(
    "finstream_processor_dlq_messages_total",
    "Total number of messages queued to the FinStream dead-letter queue.",
)


def record_processed_transaction(status, reason):
    TRANSACTIONS_PROCESSED_TOTAL.labels(
        status=status,
    ).inc()

    if status == "ALERT":
        ALERTS_TOTAL.labels(
            reason=reason or "unknown",
        ).inc()


def record_invalid_transaction(reason):
    INVALID_TRANSACTIONS_TOTAL.labels(
        reason=reason or "unknown",
    ).inc()
