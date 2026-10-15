"""Validated model-output schemas for FinStream AI-SRE."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator


class HypothesisProposal(BaseModel):
    """One evidence-grounded hypothesis returned by a model."""

    model_config = ConfigDict(
        extra="forbid",
    )

    statement: str = Field(
        min_length=1,
        max_length=1000,
    )
    confidence: float = Field(
        ge=0.0,
        le=1.0,
    )
    supporting_evidence: list[str] = Field(
        min_length=1,
        max_length=32,
    )
    contradicting_evidence: list[str] = Field(
        default_factory=list,
        max_length=32,
    )

    @field_validator(
        "statement",
    )
    @classmethod
    def statement_must_contain_text(
        cls,
        value: str,
    ) -> str:
        normalized = value.strip()

        if not normalized:
            raise ValueError(
                "Hypothesis statement must not be blank."
            )

        return normalized

    @field_validator(
        "supporting_evidence",
        "contradicting_evidence",
    )
    @classmethod
    def evidence_ids_must_be_unique(
        cls,
        value: list[str],
    ) -> list[str]:
        normalized = [
            evidence_id.strip()
            for evidence_id in value
        ]

        if any(
            not evidence_id
            for evidence_id in normalized
        ):
            raise ValueError(
                "Evidence IDs must not be blank."
            )

        if len(normalized) != len(set(normalized)):
            raise ValueError(
                "Evidence IDs must be unique."
            )

        return normalized


class ReasoningResponse(BaseModel):
    """Complete structured response expected from the model."""

    model_config = ConfigDict(
        extra="forbid",
    )

    hypotheses: list[HypothesisProposal] = Field(
        min_length=1,
        max_length=5,
    )
