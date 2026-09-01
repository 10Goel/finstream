FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY services ./services

CMD ["python", "-m", "services.transaction_generator.kafka_producer"]
