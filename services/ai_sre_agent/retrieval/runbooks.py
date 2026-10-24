"""Trusted FinStream operational runbook catalog."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

_ALLOWED_SERVICES = {
    "api",
    "kafka",
    "postgres",
    "processor",
    "producer",
}


class RunbookCatalogError(RuntimeError):
    """Runbook catalog content violates the trust contract."""


class RunbookStatus(str, Enum):
    """Supported runbook lifecycle states."""

    APPROVED = "APPROVED"
    RETIRED = "RETIRED"


@dataclass(frozen=True, slots=True)
class RunbookDocument:
    """One integrity-checked operational runbook."""

    runbook_id: str
    title: str
    version: str
    status: RunbookStatus
    services: tuple[str, ...]
    alert_names: tuple[str, ...]
    tags: tuple[str, ...]
    summary: str
    path: str
    sha256: str
    content: str


@dataclass(frozen=True, slots=True)
class RunbookCatalog:
    """Immutable collection of validated FinStream runbooks."""

    documents: tuple[RunbookDocument, ...]

    @property
    def approved_documents(
        self,
    ) -> tuple[RunbookDocument, ...]:
        """Return only approved documents."""
        return tuple(
            document
            for document in self.documents
            if document.status is RunbookStatus.APPROVED
        )

    def by_id(
        self,
        runbook_id: str,
    ) -> RunbookDocument:
        """Return one runbook by its stable ID."""
        for document in self.documents:
            if document.runbook_id == runbook_id:
                return document

        raise KeyError(
            f"Unknown runbook ID: {runbook_id}"
        )

    @classmethod
    def load(
        cls,
        *,
        repository_root: Path,
        catalog_path: str = "docs/runbooks/catalog.json",
    ) -> RunbookCatalog:
        """Load and integrity-check the committed runbook catalog."""
        root = repository_root.resolve()

        catalog_file = (
            root / catalog_path
        ).resolve()

        try:
            catalog_file.relative_to(root)
        except ValueError as exc:
            raise RunbookCatalogError(
                "Runbook catalog must remain inside "
                "the repository root."
            ) from exc

        try:
            decoded = json.loads(
                catalog_file.read_text(
                    encoding="utf-8"
                )
            )
        except (
            OSError,
            json.JSONDecodeError,
        ) as exc:
            raise RunbookCatalogError(
                "Unable to read runbook catalog."
            ) from exc

        if not isinstance(decoded, dict):
            raise RunbookCatalogError(
                "Runbook catalog root must be an object."
            )

        if decoded.get("schema_version") != 1:
            raise RunbookCatalogError(
                "Unsupported runbook catalog schema version."
            )

        raw_entries = decoded.get("entries")

        if not isinstance(raw_entries, list):
            raise RunbookCatalogError(
                "Runbook catalog entries must be a list."
            )

        documents: list[RunbookDocument] = []
        seen_ids: set[str] = set()

        runbook_root = catalog_file.parent.resolve()

        for raw in raw_entries:
            document = cls._load_entry(
                raw=raw,
                runbook_root=runbook_root,
            )

            if document.runbook_id in seen_ids:
                raise RunbookCatalogError(
                    "Duplicate runbook ID: "
                    f"{document.runbook_id}"
                )

            seen_ids.add(
                document.runbook_id
            )

            documents.append(
                document
            )

        if not documents:
            raise RunbookCatalogError(
                "Runbook catalog must not be empty."
            )

        return cls(
            documents=tuple(documents)
        )

    @classmethod
    def _load_entry(
        cls,
        *,
        raw: Any,
        runbook_root: Path,
    ) -> RunbookDocument:
        if not isinstance(raw, dict):
            raise RunbookCatalogError(
                "Every runbook entry must be an object."
            )

        required = {
            "runbook_id",
            "title",
            "version",
            "status",
            "services",
            "alert_names",
            "tags",
            "summary",
            "path",
            "sha256",
        }

        if set(raw) != required:
            raise RunbookCatalogError(
                "Runbook entry fields do not match "
                "the required schema."
            )

        runbook_id = cls._text(
            raw,
            "runbook_id",
        )

        if not runbook_id.startswith("RB-"):
            raise RunbookCatalogError(
                "Runbook IDs must start with 'RB-'."
            )

        title = cls._text(
            raw,
            "title",
        )

        version = cls._text(
            raw,
            "version",
        )

        summary = cls._text(
            raw,
            "summary",
        )

        relative_path = cls._text(
            raw,
            "path",
        )

        expected_hash = cls._text(
            raw,
            "sha256",
        ).lower()

        if (
            len(expected_hash) != 64
            or any(
                character not in "0123456789abcdef"
                for character in expected_hash
            )
        ):
            raise RunbookCatalogError(
                "Runbook SHA-256 must contain "
                "64 hexadecimal characters."
            )

        try:
            status = RunbookStatus(
                cls._text(
                    raw,
                    "status",
                )
            )
        except ValueError as exc:
            raise RunbookCatalogError(
                "Unsupported runbook status."
            ) from exc

        services = cls._string_tuple(
            raw,
            "services",
        )

        unknown_services = (
            set(services)
            - _ALLOWED_SERVICES
        )

        if unknown_services:
            raise RunbookCatalogError(
                "Unsupported runbook service(s): "
                + ", ".join(
                    sorted(unknown_services)
                )
            )

        alert_names = cls._string_tuple(
            raw,
            "alert_names",
            allow_empty=True,
        )

        tags = cls._string_tuple(
            raw,
            "tags",
        )

        path = (
            runbook_root / relative_path
        ).resolve()

        try:
            path.relative_to(
                runbook_root
            )
        except ValueError as exc:
            raise RunbookCatalogError(
                "Runbook path escapes the trusted "
                "runbook directory."
            ) from exc

        if path.suffix.casefold() != ".md":
            raise RunbookCatalogError(
                "Runbook documents must be Markdown files."
            )

        try:
            content = path.read_text(
                encoding="utf-8"
            )
        except OSError as exc:
            raise RunbookCatalogError(
                f"Unable to read runbook: {relative_path}"
            ) from exc

        if not content.strip():
            raise RunbookCatalogError(
                "Runbook content must not be empty."
            )

        actual_hash = hashlib.sha256(
            content.encode("utf-8")
        ).hexdigest()

        if actual_hash != expected_hash:
            raise RunbookCatalogError(
                "Runbook integrity check failed: "
                f"{runbook_id}"
            )

        return RunbookDocument(
            runbook_id=runbook_id,
            title=title,
            version=version,
            status=status,
            services=services,
            alert_names=alert_names,
            tags=tags,
            summary=summary,
            path=relative_path,
            sha256=expected_hash,
            content=content,
        )

    @staticmethod
    def _text(
        raw: dict[str, Any],
        field: str,
    ) -> str:
        value = raw.get(field)

        if not isinstance(value, str):
            raise RunbookCatalogError(
                f"Runbook field '{field}' must be text."
            )

        normalized = value.strip()

        if not normalized:
            raise RunbookCatalogError(
                f"Runbook field '{field}' must not be blank."
            )

        return normalized

    @staticmethod
    def _string_tuple(
        raw: dict[str, Any],
        field: str,
        *,
        allow_empty: bool = False,
    ) -> tuple[str, ...]:
        value = raw.get(field)

        if not isinstance(value, list):
            raise RunbookCatalogError(
                f"Runbook field '{field}' must be a list."
            )

        normalized: list[str] = []

        for item in value:
            if not isinstance(item, str):
                raise RunbookCatalogError(
                    f"Runbook field '{field}' must "
                    "contain only strings."
                )

            text = item.strip()

            if not text:
                raise RunbookCatalogError(
                    f"Runbook field '{field}' contains "
                    "a blank value."
                )

            normalized.append(text)

        if not normalized and not allow_empty:
            raise RunbookCatalogError(
                f"Runbook field '{field}' must not be empty."
            )

        if len(normalized) != len(set(normalized)):
            raise RunbookCatalogError(
                f"Runbook field '{field}' contains "
                "duplicate values."
            )

        return tuple(normalized)
