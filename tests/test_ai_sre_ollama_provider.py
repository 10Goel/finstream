import io
import json
from urllib.error import URLError

import pytest

from services.ai_sre_agent.reasoning import (
    ModelProviderError,
    OllamaModelProvider,
)


def ollama_api_response(
    *,
    content: str,
    done: bool = True,
) -> bytes:
    return json.dumps(
        {
            "model": "qwen3:1.7b",
            "message": {
                "role": "assistant",
                "content": content,
            },
            "done": done,
        }
    ).encode("utf-8")


def test_generate_sends_guarded_structured_request():
    captured = {}

    response_schema = {
        "type": "object",
        "properties": {
            "hypotheses": {
                "type": "array",
            }
        },
        "required": [
            "hypotheses",
        ],
    }

    def opener(
        request,
        *,
        timeout,
    ):
        captured["url"] = request.full_url
        captured["timeout"] = timeout
        captured["payload"] = json.loads(
            request.data.decode("utf-8")
        )

        return io.BytesIO(
            ollama_api_response(
                content='{"hypotheses":[]}',
            )
        )

    provider = OllamaModelProvider(
        response_schema=response_schema,
        request_opener=opener,
    )

    result = provider.generate(
        system_prompt="system rules",
        user_prompt="incident evidence",
    )

    assert result == '{"hypotheses":[]}'

    assert (
        captured["url"]
        == "http://127.0.0.1:11434/api/chat"
    )

    assert captured["timeout"] == 180.0

    payload = captured["payload"]

    assert payload["model"] == "qwen3:1.7b"
    assert payload["stream"] is False
    assert payload["think"] is False
    assert payload["keep_alive"] == 0
    assert payload["format"] == response_schema

    assert payload["options"] == {
        "temperature": 0,
        "num_ctx": 4096,
    }

    assert payload["messages"] == [
        {
            "role": "system",
            "content": "system rules",
        },
        {
            "role": "user",
            "content": "incident evidence",
        },
    ]


def test_generate_uses_json_format_without_schema():
    captured = {}

    def opener(
        request,
        *,
        timeout,
    ):
        del timeout

        captured["payload"] = json.loads(
            request.data.decode("utf-8")
        )

        return io.BytesIO(
            ollama_api_response(
                content='{"ok":true}',
            )
        )

    provider = OllamaModelProvider(
        request_opener=opener,
    )

    result = provider.generate(
        system_prompt="system",
        user_prompt="user",
    )

    assert result == '{"ok":true}'
    assert captured["payload"]["format"] == "json"


def test_connection_failure_is_wrapped():
    def opener(
        request,
        *,
        timeout,
    ):
        del request
        del timeout

        raise URLError(
            "connection refused"
        )

    provider = OllamaModelProvider(
        request_opener=opener,
    )

    with pytest.raises(
        ModelProviderError,
        match="Unable to reach Ollama",
    ):
        provider.generate(
            system_prompt="system",
            user_prompt="user",
        )


def test_malformed_outer_api_json_is_rejected():
    def opener(
        request,
        *,
        timeout,
    ):
        del request
        del timeout

        return io.BytesIO(
            b"not-json"
        )

    provider = OllamaModelProvider(
        request_opener=opener,
    )

    with pytest.raises(
        ModelProviderError,
        match="malformed API JSON",
    ):
        provider.generate(
            system_prompt="system",
            user_prompt="user",
        )


def test_incomplete_response_is_rejected():
    def opener(
        request,
        *,
        timeout,
    ):
        del request
        del timeout

        return io.BytesIO(
            ollama_api_response(
                content='{"ok":true}',
                done=False,
            )
        )

    provider = OllamaModelProvider(
        request_opener=opener,
    )

    with pytest.raises(
        ModelProviderError,
        match="not complete",
    ):
        provider.generate(
            system_prompt="system",
            user_prompt="user",
        )


def test_empty_model_content_is_rejected():
    def opener(
        request,
        *,
        timeout,
    ):
        del request
        del timeout

        return io.BytesIO(
            ollama_api_response(
                content="",
            )
        )

    provider = OllamaModelProvider(
        request_opener=opener,
    )

    with pytest.raises(
        ModelProviderError,
        match="empty model content",
    ):
        provider.generate(
            system_prompt="system",
            user_prompt="user",
        )


def test_response_size_is_bounded():
    def opener(
        request,
        *,
        timeout,
    ):
        del request
        del timeout

        return io.BytesIO(
            b"x" * 101
        )

    provider = OllamaModelProvider(
        max_response_bytes=100,
        request_opener=opener,
    )

    with pytest.raises(
        ModelProviderError,
        match="maximum size",
    ):
        provider.generate(
            system_prompt="system",
            user_prompt="user",
        )


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        (
            {
                "base_url": "file:///tmp/ollama",
            },
            "http or https",
        ),
        (
            {
                "model": "   ",
            },
            "model name",
        ),
        (
            {
                "timeout_seconds": 0,
            },
            "timeout",
        ),
        (
            {
                "max_response_bytes": 0,
            },
            "response size",
        ),
        (
            {
                "context_length": 0,
            },
            "context length",
        ),
    ],
)
def test_invalid_configuration_is_rejected(
    kwargs,
    message,
):
    with pytest.raises(
        ValueError,
        match=message,
    ):
        OllamaModelProvider(
            **kwargs,
        )


def test_generate_sends_explicit_seed_when_configured():
    captured = {}

    def opener(
        request,
        *,
        timeout,
    ):
        del timeout

        captured["payload"] = json.loads(
            request.data.decode("utf-8")
        )

        return io.BytesIO(
            ollama_api_response(
                content='{"ok":true}',
            )
        )

    provider = OllamaModelProvider(
        seed=42,
        request_opener=opener,
    )

    provider.generate(
        system_prompt="system",
        user_prompt="user",
    )

    assert captured["payload"]["options"] == {
        "temperature": 0,
        "num_ctx": 4096,
        "seed": 42,
    }


def test_negative_seed_is_rejected():
    with pytest.raises(
        ValueError,
        match="seed",
    ):
        OllamaModelProvider(
            seed=-1,
        )


def test_generate_sends_configured_keep_alive():
    captured = {}

    def opener(
        request,
        *,
        timeout,
    ):
        del timeout

        captured["payload"] = json.loads(
            request.data.decode("utf-8")
        )

        return io.BytesIO(
            ollama_api_response(
                content='{"ok":true}',
            )
        )

    provider = OllamaModelProvider(
        keep_alive="5m",
        request_opener=opener,
    )

    provider.generate(
        system_prompt="system",
        user_prompt="user",
    )

    assert (
        captured["payload"]["keep_alive"]
        == "5m"
    )


@pytest.mark.parametrize(
    "keep_alive",
    [
        "",
        "   ",
        -1,
    ],
)
def test_invalid_keep_alive_value_is_rejected(
    keep_alive,
):
    with pytest.raises(
        ValueError,
        match="keep_alive",
    ):
        OllamaModelProvider(
            keep_alive=keep_alive,
        )


@pytest.mark.parametrize(
    "keep_alive",
    [
        1.5,
        None,
    ],
)
def test_invalid_keep_alive_type_is_rejected(
    keep_alive,
):
    with pytest.raises(
        TypeError,
        match="keep_alive",
    ):
        OllamaModelProvider(
            keep_alive=keep_alive,
        )
