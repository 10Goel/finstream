import json
import os

from confluent_kafka import Producer


DLQ_TOPIC = os.getenv(
    "KAFKA_DLQ_TOPIC",
    "transactions.dlq",
)

KAFKA_BOOTSTRAP_SERVERS = os.getenv(
    "KAFKA_BOOTSTRAP_SERVERS",
    "localhost:9092",
)


def create_dlq_producer():
    return Producer(
        {
            "bootstrap.servers": KAFKA_BOOTSTRAP_SERVERS,
            "acks": "all",
        }
    )


def send_to_dlq(
    producer,
    raw_message,
    error_reason,
):
    payload = {
        "error_reason": error_reason,
        "raw_message": raw_message,
    }

    producer.produce(
        topic=DLQ_TOPIC,
        value=json.dumps(payload).encode("utf-8"),
    )

    producer.poll(0)
