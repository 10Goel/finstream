from prometheus_client import Counter, Histogram

HTTP_REQUESTS_TOTAL = Counter(
    "finstream_api_http_requests_total",
    "Total number of HTTP requests handled by the FinStream API.",
    ["method", "path", "status_code"],
)


HTTP_REQUEST_DURATION_SECONDS = Histogram(
    "finstream_api_http_request_duration_seconds",
    "Time spent processing FinStream API HTTP requests.",
    ["method", "path"],
)
