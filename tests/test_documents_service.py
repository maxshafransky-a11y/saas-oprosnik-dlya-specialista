from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

sys.path.insert(0, str(Path(__file__).parents[1]))

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL
from sqlalchemy.orm import Session as DbSession
from sqlalchemy.pool import NullPool

from app import documents_scan_service, documents_service
from app.models import Client, ClientStatus, Workspace, WorkspaceStatus

pytest_plugins = ("tests.db_test_support",)


@dataclass
class FakeStorage:
    sizes: dict[str, int] = field(default_factory=dict)
    presigned: list[tuple[str, str, int, int]] = field(default_factory=list)
    downloads: list[tuple[str, int]] = field(default_factory=list)
    head_calls: list[str] = field(default_factory=list)
    deletes: list[str] = field(default_factory=list)

    def presign_put(
        self, object_key: str, content_type: str, content_length: int, expires_seconds: int
    ) -> str:
        self.presigned.append((object_key, content_type, content_length, expires_seconds))
        return f"https://storage.test/{object_key}"

    def head(self, object_key: str) -> documents_service.StorageHead:
        self.head_calls.append(object_key)
        return documents_service.StorageHead(size_bytes=self.sizes[object_key])

    def presign_get(self, object_key: str, expires_seconds: int) -> str:
        self.downloads.append((object_key, expires_seconds))
        return f"https://storage.test/get/{object_key}"

    def delete(self, object_key: str) -> None:
        self.deletes.append(object_key)


def _seed_client(owner_url: URL) -> tuple[UUID, UUID]:
    workspace_id = uuid4()
    client_id = uuid4()
    engine = create_engine(owner_url)
    try:
        with DbSession(engine) as session:
            session.add(
                Workspace(
                    id=workspace_id,
                    name="Test workspace",
                    public_slug=f"test-{workspace_id.hex}",
                    status=WorkspaceStatus.ACTIVE,
                )
            )
            session.flush()
            session.execute(
                text("SELECT set_config('app.workspace_id', :workspace_id, false)"),
                {"workspace_id": str(workspace_id)},
            )
            session.add(
                Client(
                    id=client_id,
                    workspace_id=workspace_id,
                    email_normalized=f"{client_id.hex}@example.test",
                    email_display=f"{client_id.hex}@example.test",
                    status=ClientStatus.ACTIVE,
                )
            )
            session.commit()
    finally:
        engine.dispose()
    return workspace_id, client_id


@pytest.fixture
def document_context(migrated_database):
    owner_url, runtime_url = migrated_database
    workspace_id, client_id = _seed_client(owner_url)
    engine = create_engine(runtime_url, poolclass=NullPool)
    try:
        yield owner_url, engine, workspace_id, client_id
    finally:
        engine.dispose()


def _runtime_session(engine, workspace_id: UUID) -> DbSession:
    session = DbSession(engine)
    session.execute(
        text("SELECT set_config('app.workspace_id', :workspace_id, false)"),
        {"workspace_id": str(workspace_id)},
    )
    return session


def _owner_rows(owner_url: URL, workspace_id: UUID, query: str) -> list[dict]:
    engine = create_engine(owner_url, poolclass=NullPool)
    try:
        with engine.connect() as connection:
            connection.execute(
                text("SELECT set_config('app.workspace_id', :workspace_id, false)"),
                {"workspace_id": str(workspace_id)},
            )
            return [dict(row) for row in connection.execute(text(query)).mappings()]
    finally:
        engine.dispose()


def test_create_upload_intent_validates_and_generates_quarantine_key(document_context) -> None:
    owner_url, engine, workspace_id, client_id = document_context
    storage = FakeStorage()
    request_id = "a" * 32
    try:
        with _runtime_session(engine, workspace_id) as session:
            result = documents_service.create_upload_intent(
                session,
                workspace_id,
                client_id,
                original_name="  анализы.pdf  ",
                declared_mime="application/pdf",
                size_bytes=42,
                storage=storage,
                request_id=request_id,
                now=datetime(2026, 1, 1, tzinfo=UTC),
            )
            session.commit()
    finally:
        engine.dispose()

    assert result.status is documents_service.DocumentStatus.UPLOADING
    assert result.upload_url == f"https://storage.test/{result.object_key}"
    assert re.fullmatch(r"quarantine/[0-9a-f-]{36}", result.object_key)
    assert storage.presigned == [(result.object_key, "application/pdf", 42, 600)]
    rows = _owner_rows(
        owner_url,
        workspace_id,
        "SELECT original_name, object_key, status, size_bytes FROM documents",
    )
    assert rows == [
        {
            "original_name": "анализы.pdf",
            "object_key": result.object_key,
            "status": "uploading",
            "size_bytes": 42,
        }
    ]


@pytest.mark.parametrize(
    ("original_name", "declared_mime", "size_bytes"),
    [
        ("report.exe", "application/octet-stream", 1),
        ("report.pdf", "application/pdf", 0),
        ("report.pdf", "application/pdf", 25 * 1024 * 1024 + 1),
        ("", "application/pdf", 1),
        ("folder/report.pdf", "application/pdf", 1),
        ("report\x00.pdf", "application/pdf", 1),
        ("x" * 256, "application/pdf", 1),
    ],
)
def test_upload_intent_rejects_unsafe_metadata(
    document_context, original_name: str, declared_mime: str, size_bytes: int
) -> None:
    _, engine, workspace_id, client_id = document_context
    try:
        with _runtime_session(engine, workspace_id) as session:
            with pytest.raises(documents_service.InvalidUpload):
                documents_service.create_upload_intent(
                    session,
                    workspace_id,
                    client_id,
                    original_name=original_name,
                    declared_mime=declared_mime,
                    size_bytes=size_bytes,
                    storage=FakeStorage(),
                    request_id="b" * 32,
                )
            session.rollback()
    finally:
        engine.dispose()


def test_complete_checks_exact_size_is_idempotent_and_audits_without_name(document_context) -> None:
    owner_url, engine, workspace_id, client_id = document_context
    storage = FakeStorage()
    try:
        with _runtime_session(engine, workspace_id) as session:
            intent = documents_service.create_upload_intent(
                session,
                workspace_id,
                client_id,
                original_name="very-private-name.pdf",
                declared_mime="application/pdf",
                size_bytes=42,
                storage=storage,
                request_id="c" * 32,
            )
            session.commit()

        storage.sizes[intent.object_key] = 42
        with _runtime_session(engine, workspace_id) as session:
            completed = documents_service.complete_upload(
                session,
                workspace_id,
                client_id,
                intent.document_id,
                storage=storage,
                request_id="d" * 32,
                now=datetime(2026, 1, 2, tzinfo=UTC),
            )
            session.commit()

        assert completed.status is documents_service.DocumentStatus.QUARANTINED
        assert storage.head_calls == [intent.object_key]

        class NoHeadStorage(FakeStorage):
            def head(self, object_key: str) -> documents_service.StorageHead:
                raise AssertionError("idempotent completion must not head the object")

        with _runtime_session(engine, workspace_id) as session:
            repeated = documents_service.complete_upload(
                session,
                workspace_id,
                client_id,
                intent.document_id,
                storage=NoHeadStorage(),
                request_id="e" * 32,
            )
            session.commit()
    finally:
        engine.dispose()

    assert repeated.status is documents_service.DocumentStatus.QUARANTINED
    rows = _owner_rows(
        owner_url,
        workspace_id,
        "SELECT event_type, request_id, metadata_jsonb FROM audit_events",
    )
    assert len(rows) == 1
    assert rows[0]["event_type"] == "document_quarantined"
    assert rows[0]["request_id"] == "d" * 32
    assert rows[0]["metadata_jsonb"] == {"declared_mime": "application/pdf", "size_bytes": 42}
    assert "very-private-name.pdf" not in str(rows[0])


def test_complete_size_mismatch_rolls_back_and_leaves_uploading(document_context) -> None:
    owner_url, engine, workspace_id, client_id = document_context
    storage = FakeStorage()
    try:
        with _runtime_session(engine, workspace_id) as session:
            intent = documents_service.create_upload_intent(
                session,
                workspace_id,
                client_id,
                original_name="report.png",
                declared_mime="image/png",
                size_bytes=42,
                storage=storage,
                request_id="f" * 32,
            )
            session.commit()

        storage.sizes[intent.object_key] = 41
        with _runtime_session(engine, workspace_id) as session:
            with pytest.raises(documents_service.UploadSizeMismatch):
                documents_service.complete_upload(
                    session,
                    workspace_id,
                    client_id,
                    intent.document_id,
                    storage=storage,
                    request_id="1" * 32,
                )
            session.rollback()
    finally:
        engine.dispose()

    rows = _owner_rows(
        owner_url,
        workspace_id,
        "SELECT status, uploaded_at FROM documents",
    )
    assert rows == [{"status": "uploading", "uploaded_at": None}]
    assert _owner_rows(owner_url, workspace_id, "SELECT id FROM audit_events") == []


def test_document_status_is_tenant_scoped(document_context, migrated_database) -> None:
    owner_url, engine, workspace_id, client_id = document_context
    other_owner_url, _ = migrated_database
    other_workspace_id, other_client_id = _seed_client(other_owner_url)
    storage = FakeStorage()
    try:
        with _runtime_session(engine, workspace_id) as session:
            intent = documents_service.create_upload_intent(
                session,
                workspace_id,
                client_id,
                original_name="private.pdf",
                declared_mime="application/pdf",
                size_bytes=1,
                storage=storage,
                request_id="2" * 32,
            )
            session.commit()

        with (
            _runtime_session(engine, other_workspace_id) as session,
            pytest.raises(documents_service.DocumentNotFound),
        ):
            documents_service.get_document_status(
                session,
                other_workspace_id,
                other_client_id,
                intent.document_id,
            )
    finally:
        engine.dispose()


def test_list_documents_is_client_scoped_and_excludes_deleted(document_context) -> None:
    owner_url, engine, workspace_id, client_id = document_context
    storage = FakeStorage()
    try:
        with _runtime_session(engine, workspace_id) as session:
            first = documents_service.create_upload_intent(
                session,
                workspace_id,
                client_id,
                original_name="first.pdf",
                declared_mime="application/pdf",
                size_bytes=1,
                storage=storage,
                request_id="c" * 32,
            )
            second = documents_service.create_upload_intent(
                session,
                workspace_id,
                client_id,
                original_name="second.pdf",
                declared_mime="application/pdf",
                size_bytes=1,
                storage=storage,
                request_id="d" * 32,
            )
            session.commit()
        with _runtime_session(engine, workspace_id) as session:
            documents_service.delete_document(
                session,
                workspace_id,
                client_id,
                first.document_id,
                storage=storage,
                request_id="e" * 32,
            )
            session.commit()
        with _runtime_session(engine, workspace_id) as session:
            result = documents_service.list_documents(session, workspace_id, client_id)
            session.rollback()
    finally:
        engine.dispose()

    assert [item.document_id for item in result] == [second.document_id]
    assert result[0].original_name == "second.pdf"


def test_ready_document_gets_short_download_url_and_audit(document_context) -> None:
    owner_url, engine, workspace_id, client_id = document_context
    storage = FakeStorage()
    try:
        with _runtime_session(engine, workspace_id) as session:
            intent = documents_service.create_upload_intent(
                session,
                workspace_id,
                client_id,
                original_name="analysis.pdf",
                declared_mime="application/pdf",
                size_bytes=42,
                storage=storage,
                request_id="3" * 32,
            )
            session.commit()
        storage.sizes[intent.object_key] = 42
        with _runtime_session(engine, workspace_id) as session:
            documents_service.complete_upload(
                session,
                workspace_id,
                client_id,
                intent.document_id,
                storage=storage,
                request_id="4" * 32,
            )
            session.commit()
        with _runtime_session(engine, workspace_id) as session:
            documents_scan_service.claim_scan_jobs(session, workspace_id)
            session.commit()
        with _runtime_session(engine, workspace_id) as session:
            documents_scan_service.finish_scan(
                session,
                workspace_id,
                client_id,
                intent.document_id,
                attempt=1,
                outcome=documents_scan_service.ScanOutcome(
                    clean=True, detected_mime="application/pdf", sha256="a" * 64
                ),
                request_id="8" * 32,
            )
            session.commit()
        with _runtime_session(engine, workspace_id) as session:
            result = documents_service.get_download_url(
                session,
                workspace_id,
                client_id,
                intent.document_id,
                storage=storage,
                request_id="5" * 32,
            )
            session.commit()
    finally:
        engine.dispose()

    assert result.download_url == f"https://storage.test/get/{intent.object_key}"
    assert storage.downloads == [(intent.object_key, 300)]
    audits = _owner_rows(
        owner_url,
        workspace_id,
        "SELECT event_type, request_id, metadata_jsonb FROM audit_events ORDER BY created_at",
    )
    assert audits[-1] == {
        "event_type": "document_downloaded",
        "request_id": "5" * 32,
        "metadata_jsonb": {},
    }
    assert "analysis.pdf" not in str(audits)


def test_uploading_document_cannot_be_downloaded(document_context) -> None:
    _, engine, workspace_id, client_id = document_context
    try:
        with _runtime_session(engine, workspace_id) as session:
            intent = documents_service.create_upload_intent(
                session,
                workspace_id,
                client_id,
                original_name="analysis.pdf",
                declared_mime="application/pdf",
                size_bytes=1,
                storage=FakeStorage(),
                request_id="6" * 32,
            )
            session.commit()
        with _runtime_session(engine, workspace_id) as session:
            with pytest.raises(documents_service.InvalidDocumentState):
                documents_service.get_download_url(
                    session,
                    workspace_id,
                    client_id,
                    intent.document_id,
                    storage=FakeStorage(),
                    request_id="7" * 32,
                )
            session.rollback()
    finally:
        engine.dispose()


def test_delete_removes_object_marks_document_and_audits(document_context) -> None:
    owner_url, engine, workspace_id, client_id = document_context
    storage = FakeStorage()
    try:
        with _runtime_session(engine, workspace_id) as session:
            intent = documents_service.create_upload_intent(
                session,
                workspace_id,
                client_id,
                original_name="analysis.pdf",
                declared_mime="application/pdf",
                size_bytes=1,
                storage=storage,
                request_id="9" * 32,
            )
            session.commit()
        with _runtime_session(engine, workspace_id) as session:
            result = documents_service.delete_document(
                session,
                workspace_id,
                client_id,
                intent.document_id,
                storage=storage,
                request_id="a" * 32,
                now=datetime(2026, 1, 3, tzinfo=UTC),
            )
            session.commit()
        with _runtime_session(engine, workspace_id) as session:
            repeated = documents_service.delete_document(
                session,
                workspace_id,
                client_id,
                intent.document_id,
                storage=storage,
                request_id="b" * 32,
            )
            session.commit()
    finally:
        engine.dispose()

    assert result.status is documents_service.DocumentStatus.DELETED
    assert repeated.status is documents_service.DocumentStatus.DELETED
    assert storage.deletes == [intent.object_key]
    assert _owner_rows(
        owner_url,
        workspace_id,
        "SELECT status, deleted_at FROM documents",
    ) == [{"status": "deleted", "deleted_at": datetime(2026, 1, 3, tzinfo=UTC)}]
    assert _owner_rows(
        owner_url,
        workspace_id,
        "SELECT event_type, request_id, metadata_jsonb FROM audit_events",
    ) == [{"event_type": "document_deleted", "request_id": "a" * 32, "metadata_jsonb": {}}]
