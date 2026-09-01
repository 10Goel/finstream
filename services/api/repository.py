from psycopg.rows import dict_row

from services.database.postgres import get_connection

def get_transactions(
    limit: int = 50,
    status: str | None = None,
    customer_id: str | None = None,
    min_amount: float | None = None,
):
    query = """
        SELECT
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
            alert_reason,
            processed_at
        FROM transactions
        WHERE 1 = 1
    """

    params = []

    if status is not None:
        query += " AND status = %s"
        params.append(status)

    if customer_id is not None:
        query += " AND customer_id = %s"
        params.append(customer_id)

    if min_amount is not None:
        query += " AND amount >= %s"
        params.append(min_amount)

    query += " ORDER BY processed_at DESC LIMIT %s"
    params.append(limit)

    with get_connection() as connection:
        with connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(query, params)
            return cursor.fetchall()

def get_transaction_by_id(transaction_id):
    query = """
        SELECT
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
            alert_reason,
            processed_at
        FROM transactions
        WHERE transaction_id = %s;
    """

    with get_connection() as connection:
        with connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(query, (transaction_id,))
            return cursor.fetchone()

def get_alerts(limit=50):
    query = """
        SELECT
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
            alert_reason,
            processed_at
        FROM transactions
        WHERE status = 'ALERT'
        ORDER BY processed_at DESC
        LIMIT %s;
    """

    with get_connection() as connection:
        with connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(query, (limit,))
            return cursor.fetchall()

def get_customer_transactions(customer_id: str, limit: int = 50):
    query = """
        SELECT
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
            alert_reason,
            processed_at
        FROM transactions
        WHERE customer_id = %s
        ORDER BY transaction_time DESC
        LIMIT %s;
    """

    with get_connection() as connection:
        with connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(query, (customer_id, limit))
            return cursor.fetchall()

def get_transaction_stats():
    query = """
        SELECT
            COUNT(*) AS total_transactions,
            COUNT(*) FILTER (WHERE status = 'NORMAL') AS normal_transactions,
            COUNT(*) FILTER (WHERE status = 'ALERT') AS alert_transactions,
            COALESCE(SUM(amount), 0) AS total_amount,
            COALESCE(AVG(amount), 0) AS average_amount,
            COALESCE(AVG(risk_score), 0) AS average_risk_score
        FROM transactions;
    """

    with get_connection() as connection:
        with connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(query)
            return cursor.fetchone()
