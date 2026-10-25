"""Ollama model provider for FinStream AI-SRE."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from services.ai_sre_agent.reasoning.provider import (
    ModelProviderError,
)


class OllamaModelProvider:
    """Call a local or explicitly configured Ollama chat endpoint."""

    def __init__(
        self,
        *,
        base_url: str = "http://127.0.0.1:11434",
        model: str = "qwen3:1.7b",
        timeout_seconds: float = 180.0,
        max_response_bytes: int = 1_000_000,
        context_length: int = 4096,
        seed: int | None = None,
        keep_alive: str | int = 0,
        response_schema: dict[str, Any] | None = None,
        request_opener: Callable[..., Any] | None = None,
    ) -> None:
        normalized_url = base_url.rstrip("/")
        parsed = urlparse(normalized_url)

        if parsed.scheme not in {"http", "https"}:
            raise ValueError(
                "Ollama base URL must use http or https."
            )

        if not parsed.hostname:
            raise ValueError(
                "Ollama base URL must include a hostname."
            )

        if parsed.username is not None or parsed.password is not None:
            raise ValueError(
                "Ollama base URL must not contain credentials."
            )

        if parsed.path not in {"", "/"}:
            raise ValueError(
                "Ollama base URL must not contain a path."
            )

        if not model.strip():
            raise ValueError(
                "Ollama model name must not be empty."
            )

        if timeout_seconds <= 0:
            raise ValueError(
                "Ollama timeout must be positive."
            )

        if max_response_bytes <= 0:
            raise ValueError(
                "Maximum Ollama response size must be positive."
            )

        if context_length <= 0:
            raise ValueError(
                "Ollama context length must be positive."
            )

        if seed is not None and seed < 0:
            raise ValueError(
                "Ollama seed must not be negative."
            )

        if isinstance(keep_alive, str):
            if not keep_alive.strip():
                raise ValueError(
                    "Ollama keep_alive must not be blank."
                )
        elif isinstance(keep_alive, int):
            if keep_alive < 0:
                raise ValueError(
                    "Ollama keep_alive must not be negative."
                )
        else:
            raise TypeError(
                "Ollama keep_alive must be a string or integer."
            )

        self._base_url = normalized_url
        self._model = model.strip()
        self._timeout_seconds = timeout_seconds
        self._max_response_bytes = max_response_bytes
        self._context_length = context_length
        self._seed = seed
        self._keep_alive = keep_alive
        self._response_schema = response_schema
        self._request_opener = request_opener or urlopen

    def generate(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
    ) -> str:
        """Generate one bounded, non-streaming Ollama response."""
        if not system_prompt.strip():
            raise ModelProviderError(
                "System prompt must not be empty."
            )

        if not user_prompt.strip():
            raise ModelProviderError(
                "User prompt must not be empty."
            )

        options: dict[str, Any] = {
            "temperature": 0,
            "num_ctx": self._context_length,
        }

        if self._seed is not None:
            options["seed"] = self._seed

        request_body: dict[str, Any] = {
            "model": self._model,
            "messages": [
                {
                    "role": "system",
                    "content": system_prompt,
                },
                {
                    "role": "user",
                    "content": user_prompt,
                },
            ],
            "stream": False,
            "think": False,
            "format": (
                self._response_schema
                if self._response_schema is not None
                else "json"
            ),
            "options": options,
            # Important on the user's limited-memory local environment:
            # unload the model after each request.
            "keep_alive": self._keep_alive,
        }

        request = Request(
            f"{self._base_url}/api/chat",
            data=json.dumps(
                request_body,
                separators=(",", ":"),
            ).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )

        try:
            with self._request_opener(
                request,
                timeout=self._timeout_seconds,
            ) as response:
                raw_response = response.read(
                    self._max_response_bytes + 1
                )
        except HTTPError as exc:
            raise ModelProviderError(
                f"Ollama returned HTTP {exc.code}."
            ) from exc
        except (
            URLError,
            TimeoutError,
            OSError,
        ) as exc:
            raise ModelProviderError(
                f"Unable to reach Ollama: {exc}"
            ) from exc

        if len(raw_response) > self._max_response_bytes:
            raise ModelProviderError(
                "Ollama response exceeded the configured "
                "maximum size."
            )

        try:
            decoded_response = raw_response.decode(
                "utf-8",
            )
        except UnicodeDecodeError as exc:
            raise ModelProviderError(
                "Ollama returned invalid UTF-8."
            ) from exc

        try:
            payload = json.loads(
                decoded_response,
            )
        except json.JSONDecodeError as exc:
            raise ModelProviderError(
                "Ollama returned malformed API JSON."
            ) from exc

        if not isinstance(payload, dict):
            raise ModelProviderError(
                "Ollama returned an unexpected API response."
            )

        api_error = payload.get("error")

        if api_error:
            raise ModelProviderError(
                f"Ollama API error: {api_error}"
            )

        if payload.get("done") is not True:
            raise ModelProviderError(
                "Ollama response was not complete."
            )

        message = payload.get("message")

        if not isinstance(message, dict):
            raise ModelProviderError(
                "Ollama response did not contain a message."
            )

        content = message.get("content")

        if not isinstance(content, str) or not content.strip():
            raise ModelProviderError(
                "Ollama returned empty model content."
            )

        return content
