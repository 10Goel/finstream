from fastapi.testclient import TestClient

from services.api.main import app

client = TestClient(app)


def test_metrics_endpoint_is_available():
    response = client.get("/metrics")

    assert response.status_code == 200
    assert "text/plain" in response.headers["content-type"]


def test_health_request_is_recorded_in_metrics():
    health_response = client.get("/health")

    assert health_response.status_code == 200

    metrics_response = client.get("/metrics")

    assert metrics_response.status_code == 200
    assert "finstream_api_http_requests_total" in metrics_response.text
    assert 'path="/health"' in metrics_response.text


def test_request_duration_metric_is_exposed():
    client.get("/health")

    response = client.get("/metrics")

    assert "finstream_api_http_request_duration_seconds" in response.text


def test_unmatched_route_uses_bounded_metrics_label():
    response = client.get("/definitely-not-a-real-route")

    assert response.status_code == 404

    metrics_response = client.get("/metrics")

    assert 'path="unmatched"' in metrics_response.text
    assert 'path="/definitely-not-a-real-route"' not in metrics_response.text
