import json
import os
import random
import signal
import time

from confluent_kafka import Producer
from prometheus_client import start_http_server

from services.transaction_generator.generator import generate_transaction
from services.transaction_generator.metrics import (
    DELIVERY_FAILURES_TOTAL,
    TRANSACTIONS_PUBLISHED_TOTAL,
    record_generated_transaction,
)

KAFKA_BOOTSTRAP_SERVERS = os.getenv(
    "KAFKA_BOOTSTRAP_SERVERS",
    "localhost:9092",
)

KAFKA_TOPIC = os.getenv(
    "KAFKA_TOPIC",
    "transactions",
)

METRICS_PORT = int(
    os.getenv(
        "METRICS_PORT",
        "8001",
    )
)


def delivery_report(err, msg):
    if err is not None:
        DELIVERY_FAILURES_TOTAL.inc()
        print(f"Message delivery failed: {err}")
        return

    key = msg.key().decode("utf-8") if msg.key() else "None"

    print(
        f"Delivered transaction for customer {key} "
        f"to {msg.topic()} "
        f"[partition {msg.partition()}] "
        f"offset {msg.offset()}"
    )

    TRANSACTIONS_PUBLISHED_TOTAL.inc()


def create_producer():
    config = {
        "bootstrap.servers": KAFKA_BOOTSTRAP_SERVERS,
        "acks": "all",
        "retries": 5,
        "linger.ms": 5,
    }

    return Producer(config)


def publish_transaction(producer, transaction):
    message = json.dumps(transaction).encode("utf-8")

    # Use customer_id as the Kafka message key.
    # Transactions for the same customer will consistently
    # be routed to the same partition.
    key = transaction["customer_id"].encode("utf-8")

    producer.produce(
        topic=KAFKA_TOPIC,
        key=key,
        value=message,
        callback=delivery_report,
    )

    producer.poll(0)


def main():
    start_http_server(METRICS_PORT)
    producer = create_producer()
    shutdown_requested = False

    def handle_shutdown(signum, _frame):
        nonlocal shutdown_requested
        shutdown_requested = True
        signal_name = signal.Signals(signum).name
        print(f"\nReceived {signal_name}. Stopping producer gracefully...")

    signal.signal(signal.SIGTERM, handle_shutdown)

    print("Starting FinStream transaction producer...")
    print(f"Metrics server: :{METRICS_PORT}/metrics")
    print(f"Kafka broker: {KAFKA_BOOTSTRAP_SERVERS}")
    print(f"Kafka topic: {KAFKA_TOPIC}")
    print("Suspicious transaction probability: 10%")
    print("Press Ctrl+C to stop.\n")

    try:
        while not shutdown_requested:

            # Approximately 10% of transactions will be suspicious.
            is_suspicious = random.random() < 0.10

            transaction = generate_transaction(
                suspicious=is_suspicious
            )

            record_generated_transaction(transaction)

            print(
                f"Generated transaction: "
                f"{transaction['transaction_id']} | "
                f"Customer: {transaction['customer_id']} | "
                f"Amount: ₹{transaction['amount']} | "
                f"Suspicious: {transaction['suspicious']}"
            )

            publish_transaction(producer, transaction)

            time.sleep(2)

    except KeyboardInterrupt:
        print("\nStopping transaction producer...")

    finally:
        remaining = producer.flush(10)

        if remaining:
            print(
                f"Warning: {remaining} message(s) "
                f"were not delivered."
            )

        print("Producer stopped.")


if __name__ == "__main__":
    main()
