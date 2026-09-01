from fastapi import FastAPI, HTTPException, Query

from services.api.repository import (
    get_alerts,
    get_customer_transactions,
    get_transaction_by_id,
    get_transaction_stats,
    get_transactions,
)


app = FastAPI(
    title="FinStream API",
    description=(
        "REST API for the FinStream real-time "
        "financial transaction monitoring platform."
    ),
    version="0.1.0",
)


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "finstream-api",
    }

@app.get("/transactions")
def list_transactions(
    limit: int = Query(default=50, ge=1, le=100),
    status: str | None = Query(default=None),
    customer_id: str | None = Query(default=None),
    min_amount: float | None = Query(default=None, ge=0),
):
    if status is not None:
        status = status.upper()

        if status not in {"NORMAL", "ALERT"}:
            raise HTTPException(
                status_code=400,
                detail="status must be NORMAL or ALERT",
            )

    transactions = get_transactions(
        limit=limit,
        status=status,
        customer_id=customer_id,
        min_amount=min_amount,
    )

    return {
        "count": len(transactions),
        "transactions": transactions,
    }

@app.get("/transactions/{transaction_id}")
def transaction_detail(transaction_id: str):
    transaction = get_transaction_by_id(transaction_id)

    if transaction is None:
        raise HTTPException(
            status_code=404,
            detail="Transaction not found",
        )

    return transaction

@app.get("/alerts")
def list_alerts(
    limit: int = Query(
        default=50,
        ge=1,
        le=100,
    )
):
    alerts = get_alerts(limit)

    return {
        "count": len(alerts),
        "alerts": alerts,
    }

@app.get("/customers/{customer_id}/transactions")
def customer_transaction_history(
    customer_id: str,
    limit: int = Query(
        default=50,
        ge=1,
        le=100,
    ),
):
    transactions = get_customer_transactions(
        customer_id=customer_id,
        limit=limit,
    )

    if not transactions:
        raise HTTPException(
            status_code=404,
            detail="Customer not found",
        )

    return {
        "customer_id": customer_id,
        "count": len(transactions),
        "transactions": transactions,
    }

@app.get("/stats")
def transaction_stats():
    stats = get_transaction_stats()

    return {
        "total_transactions": stats["total_transactions"],
        "normal_transactions": stats["normal_transactions"],
        "alert_transactions": stats["alert_transactions"],
        "total_amount": float(stats["total_amount"]),
        "average_amount": round(float(stats["average_amount"]), 2),
        "average_risk_score": round(float(stats["average_risk_score"]), 2),
    }
