import json
import os
import signal

from confluent_kafka import Consumer, KafkaError

from services.database.postgres import save_transaction
from services.stream_processor.anomaly_detector import analyze_transaction
from services.stream_processor.dlq import (
    create_dlq_producer,
    send_to_dlq,
)
from services.stream_processor.validator import validate_transaction

KAFKA_BOOTSTRAP_SERVERS = os.getenv(
    "KAFKA_BOOTSTRAP_SERVERS",
    "localhost:9092",
)

KAFKA_TOPIC = os.getenv(
    "KAFKA_TOPIC",
    "transactions",
)

CONSUMER_GROUP = "finstream-anomaly-detector"


def create_consumer():
    return Consumer(
        {
            "bootstrap.servers": KAFKA_BOOTSTRAP_SERVERS,
            "group.id": CONSUMER_GROUP,
            "auto.offset.reset": "latest",
        }
    )


def process_transaction(transaction):
    analysis = analyze_transaction(transaction)

    status = (
        "ALERT"
        if analysis["is_anomalous"]
        else "NORMAL"
    )

    print(
        f"[{status}] "
        f"{transaction['transaction_id']} | "
        f"Customer: {transaction['customer_id']} | "
        f"Amount: ₹{transaction['amount']} | "
        f"Risk: {analysis['risk_score']} | "
        f"Reason: {analysis['reason']}"
    )

    save_transaction(
        transaction=transaction,
        analysis=analysis,
    )


def main():
    consumer = create_consumer()
    dlq_producer = create_dlq_producer()
    shutdown_requested = False

    def handle_shutdown(signum, _frame):
        nonlocal shutdown_requested
        shutdown_requested = True
        signal_name = signal.Signals(signum).name
        print(f"\nReceived {signal_name}. Stopping consumer gracefully...")

    signal.signal(signal.SIGTERM, handle_shutdown)

    consumer.subscribe([KAFKA_TOPIC])

    print("Starting FinStream anomaly detector...")
    print(f"Consumer group: {CONSUMER_GROUP}")
    print(f"Listening to topic: {KAFKA_TOPIC}")
    print("Press Ctrl+C to stop.\n")

    try:
        while not shutdown_requested:
            message = consumer.poll(1.0)

            if message is None:
                continue

            if message.error():
                if (
                    message.error().code()
                    != KafkaError._PARTITION_EOF
                ):
                    print(
                        f"Kafka error: "
                        f"{message.error()}"
                    )

                continue

            try:
                raw_message = message.value().decode(
                    "utf-8"
                )

            except UnicodeDecodeError:
                print(
                    "[INVALID] Message could not "
                    "be decoded as UTF-8"
                )

                send_to_dlq(
                    dlq_producer,
                    str(message.value()),
                    "invalid_utf8",
                )

                continue

            try:
                transaction = json.loads(raw_message)

            except json.JSONDecodeError:
                print(
                    "[INVALID] Reason: malformed_json"
                )

                send_to_dlq(
                    dlq_producer,
                    raw_message,
                    "malformed_json",
                )

                continue

            is_valid, error_reason = (
                validate_transaction(transaction)
            )

            if not is_valid:
                transaction_id = transaction.get(
                    "transaction_id",
                    "unknown",
                )

                print(
                    f"[INVALID] "
                    f"{transaction_id} | "
                    f"Reason: {error_reason}"
                )

                send_to_dlq(
                    dlq_producer,
                    raw_message,
                    error_reason,
                )

                continue

            process_transaction(transaction)

    except KeyboardInterrupt:
        print(
            "\nStopping anomaly detector..."
        )

    finally:
        remaining = dlq_producer.flush(10)

        if remaining:
            print(
                f"Warning: {remaining} DLQ message(s) "
                f"were not delivered."
            )

        consumer.close()

        print("Consumer stopped.")


if __name__ == "__main__":
    main()
