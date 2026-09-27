FROM python:3.12-slim

RUN groupadd --gid 10001 finstream \
    && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin finstream

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=10001:10001 services ./services

USER 10001:10001

CMD ["python", "-m", "services.transaction_generator.kafka_producer"]
