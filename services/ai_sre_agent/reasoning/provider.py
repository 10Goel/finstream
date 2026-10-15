"""Provider-neutral model interface for FinStream AI-SRE reasoning."""

from __future__ import annotations

from typing import Protocol


class ModelProviderError(RuntimeError):
    """Raised when a configured model provider cannot complete a request."""


class ModelProvider(Protocol):
    """Minimal interface implemented by an AI model provider."""

    def generate(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
    ) -> str:
        """Return the model response as text."""
        ...
