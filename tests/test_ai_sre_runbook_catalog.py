import hashlib
import json
from pathlib import Path

import pytest

from services.ai_sre_agent.retrieval import (
    RunbookCatalog,
    RunbookCatalogError,
    RunbookStatus,
)

REPOSITORY_ROOT = (
    Path(__file__).resolve().parents[1]
)


def test_committed_catalog_loads_six_approved_runbooks():
    catalog = RunbookCatalog.load(
        repository_root=REPOSITORY_ROOT
    )

    assert len(catalog.documents) == 6
    assert len(catalog.approved_documents) == 6

    assert all(
        document.status is RunbookStatus.APPROVED
        for document in catalog.documents
    )


def test_committed_runbook_hashes_are_verified():
    catalog = RunbookCatalog.load(
        repository_root=REPOSITORY_ROOT
    )

    for document in catalog.documents:
        actual = hashlib.sha256(
            document.content.encode("utf-8")
        ).hexdigest()

        assert actual == document.sha256


def test_catalog_lookup_uses_stable_runbook_id():
    catalog = RunbookCatalog.load(
        repository_root=REPOSITORY_ROOT
    )

    document = catalog.by_id(
        "RB-PROCESSOR-001"
    )

    assert document.title == "Processor Unavailable"
    assert document.services == ("processor",)


def write_catalog(
    root,
    *,
    relative_path="safe.md",
    expected_hash=None,
    runbook_id="RB-TEST-001",
):
    runbook_dir = root / "docs" / "runbooks"
    runbook_dir.mkdir(
        parents=True
    )

    safe = runbook_dir / "safe.md"

    safe.write_text(
        "# Safe runbook\n",
        encoding="utf-8",
    )

    digest = (
        expected_hash
        if expected_hash is not None
        else hashlib.sha256(
            safe.read_bytes()
        ).hexdigest()
    )

    catalog = {
        "schema_version": 1,
        "entries": [
            {
                "runbook_id": runbook_id,
                "title": "Safe",
                "version": "1.0.0",
                "status": "APPROVED",
                "services": ["processor"],
                "alert_names": [],
                "tags": ["test"],
                "summary": "Test runbook.",
                "path": relative_path,
                "sha256": digest,
            }
        ],
    }

    (
        runbook_dir / "catalog.json"
    ).write_text(
        json.dumps(catalog),
        encoding="utf-8",
    )


def test_tampered_runbook_is_rejected(tmp_path):
    write_catalog(tmp_path)

    path = (
        tmp_path
        / "docs"
        / "runbooks"
        / "safe.md"
    )

    path.write_text(
        "# Modified after approval\n",
        encoding="utf-8",
    )

    with pytest.raises(
        RunbookCatalogError,
        match="integrity check failed",
    ):
        RunbookCatalog.load(
            repository_root=tmp_path
        )


def test_path_traversal_is_rejected(tmp_path):
    outside = tmp_path / "outside.md"

    outside.write_text(
        "# Outside trusted directory\n",
        encoding="utf-8",
    )

    digest = hashlib.sha256(
        outside.read_bytes()
    ).hexdigest()

    write_catalog(
        tmp_path,
        relative_path="../../outside.md",
        expected_hash=digest,
    )

    with pytest.raises(
        RunbookCatalogError,
        match="escapes the trusted",
    ):
        RunbookCatalog.load(
            repository_root=tmp_path
        )


def test_duplicate_runbook_ids_are_rejected(tmp_path):
    write_catalog(tmp_path)

    catalog_path = (
        tmp_path
        / "docs"
        / "runbooks"
        / "catalog.json"
    )

    decoded = json.loads(
        catalog_path.read_text(
            encoding="utf-8"
        )
    )

    duplicate = dict(
        decoded["entries"][0]
    )

    decoded["entries"].append(
        duplicate
    )

    catalog_path.write_text(
        json.dumps(decoded),
        encoding="utf-8",
    )

    with pytest.raises(
        RunbookCatalogError,
        match="Duplicate runbook ID",
    ):
        RunbookCatalog.load(
            repository_root=tmp_path
        )
