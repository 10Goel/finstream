import os

import psycopg


def get_connection():
    """
    Create and return a PostgreSQL database connection.
    """

    return psycopg.connect(
        host=os.getenv("POSTGRES_HOST", "localhost"),
        port=os.getenv("POSTGRES_PORT", "5432"),
        dbname=os.getenv("POSTGRES_DB", "finstream"),
        user=os.getenv("POSTGRES_USER", "finstream"),
        password=os.getenv("POSTGRES_PASSWORD", "finstream_dev"),
    )


def save_transaction(transaction, analysis):
    """
    Persist a processed transaction and its anomaly-analysis result.
    """

    status = "ALERT" if analysis["is_anomalous"] else "NORMAL"

    reason = (
        analysis["reason"]
        if analysis["is_anomalous"]
        else None
    )

    query = """
        INSERT INTO transactions (
            transaction_id,
            customer_id,
            transaction_time,
            amount,
            currency,
            location,
            payment_method,
            device_id,
            status,
            risk_score,
            alert_reason
        )
        VALUES (
            %s, %s, %s, %s, %s,
            %s, %s, %s, %s, %s, %s
        )
        ON CONFLICT (transaction_id) DO NOTHING;
    """

    values = (
        transaction["transaction_id"],
        transaction["customer_id"],
        transaction["timestamp"],
        transaction["amount"],
        transaction["currency"],
        transaction["location"],
        transaction["payment_method"],
        transaction["device_id"],
        status,
        analysis["risk_score"],
        reason,
    )

    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(query, values)
