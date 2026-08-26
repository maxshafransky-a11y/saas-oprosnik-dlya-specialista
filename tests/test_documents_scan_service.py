from __future__ import annotations

import sys
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

sys.path.insert(0, str(Path(__file__).parents[1]))

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL
from sqlalchemy.orm import Session as DbSession
from sqlalchemy.pool import NullPool

from app import documents_scan_service
from app.models import Client, ClientStatus, Document, DocumentStatus, Workspace, WorkspaceStatus

pytest_plugins = ("tests.db_test_support",)


@dataclass(frozen=True)
class ScanSeed:
    document_id: UUID
    workspace_id: UUID
    client_id: UUID
    owner_url: URL


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
def scan_context(migrated_database):
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


def _insert_document(
    session: DbSession,
    workspace_id: UUID,
    client_id: UUID,
    *,
    status: DocumentStatus = DocumentStatus.QUARANTINED,
    next_scan_at: datetime | None = None,
) -> UUID:
    document_id = uuid4()
    session.add(
        Document(
            id=document_id,
            workspace_id=workspace_id,
            client_id=client_id,
            object_key=f"quarantine/{uuid4()}",
            original_name="private.pdf",
            declared_mime="application/pdf",
            size_bytes=42,
            status=status,
            next_scan_at=next_scan_at,
            created_at=datetime(2026, 1, 1, tzinfo=UTC),
        )
    )
    session.flush()
    return document_id


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


def test_claim_sets_lease_and_reclaims_only_after_expiry(scan_context) -> None:
    owner_url, engine, workspace_id, client_id = scan_context
    now = datetime(2026, 1, 2, tzinfo=UTC)
    try:
        with _runtime_session(engine, workspace_id) as session:
            document_id = _insert_document(session, workspace_id, client_id)
            session.commit()

        with _runtime_session(engine, workspace_id) as session:
            jobs = documents_scan_service.claim_scan_jobs(
                session, workspace_id, now=now, lease_seconds=60
            )
            session.commit()

        assert len(jobs) == 1
        assert jobs[0].document_id == document_id
        assert jobs[0].attempt == 1
        assert jobs[0].lease_until == now + timedelta(seconds=60)
        assert not hasattr(jobs[0], "original_name")

        with _runtime_session(engine, workspace_id) as session:
            assert documents_scan_service.claim_scan_jobs(session, workspace_id, now=now) == ()
            session.rollback()

        with _runtime_session(engine, workspace_id) as session:
            reclaimed = documents_scan_service.claim_scan_jobs(
                session, workspace_id, now=now + timedelta(seconds=61), lease_seconds=60
            )
            session.commit()
    finally:
        engine.dispose()

    assert [job.document_id for job in reclaimed] == [document_id]
    assert reclaimed[0].attempt == 2


def test_ready_finalization_is_atomic_and_idempotent(scan_context) -> None:
    owner_url, engine, workspace_id, client_id = scan_context
    now = datetime(2026, 1, 2, tzinfo=UTC)
    digest = "a" * 64
    try:
        with _runtime_session(engine, workspace_id) as session:
            document_id = _insert_document(session, workspace_id, client_id)
            session.commit()
        with _runtime_session(engine, workspace_id) as session:
            documents_scan_service.claim_scan_jobs(session, workspace_id, now=now)
            session.commit()
        with _runtime_session(engine, workspace_id) as session:
            result = documents_scan_service.finish_scan(
                session,
                workspace_id,
                client_id,
                document_id,
                attempt=1,
                outcome=documents_scan_service.ScanOutcome(
                    clean=True, detected_mime="application/pdf", sha256=digest
                ),
                request_id="b" * 32,
                now=now + timedelta(minutes=1),
            )
            session.commit()
        with _runtime_session(engine, workspace_id) as session:
            repeated = documents_scan_service.finish_scan(
                session,
                workspace_id,
                client_id,
                document_id,
                attempt=1,
                outcome=documents_scan_service.ScanOutcome(
                    clean=True, detected_mime="image/png", sha256="c" * 64
                ),
                request_id="c" * 32,
            )
            session.commit()
    finally:
        engine.dispose()

    assert result.status is DocumentStatus.READY
    assert repeated == result
    rows = _owner_rows(
        owner_url,
        workspace_id,
        "SELECT status, detected_mime, sha256, scan_lease_until FROM documents",
    )
    assert rows == [
        {
            "status": "ready",
            "detected_mime": "application/pdf",
            "sha256": digest,
            "scan_lease_until": None,
        }
    ]
    audits = _owner_rows(
        owner_url,
        workspace_id,
        "SELECT event_type, request_id, metadata_jsonb FROM audit_events",
    )
    assert audits == [
        {
            "event_type": "document_ready",
            "request_id": "b" * 32,
            "metadata_jsonb": {"detected_mime": "application/pdf", "sha256": digest},
        }
    ]
    assert "private.pdf" not in str(audits)


def test_rejected_finalization_uses_fixed_reason_and_invalid_output_rolls_back(
    scan_context,
) -> None:
    owner_url, engine, workspace_id, client_id = scan_context
    now = datetime(2026, 1, 2, tzinfo=UTC)
    try:
        with _runtime_session(engine, workspace_id) as session:
            document_id = _insert_document(session, workspace_id, client_id)
            session.commit()
        with _runtime_session(engine, workspace_id) as session:
            documents_scan_service.claim_scan_jobs(session, workspace_id, now=now)
            session.commit()
            session.execute(
                text("SELECT set_config('app.workspace_id', :workspace_id, false)"),
                {"workspace_id": str(workspace_id)},
            )
            with pytest.raises(documents_scan_service.InvalidScanResult):
                documents_scan_service.finish_scan(
                    session,
                    workspace_id,
                    client_id,
                    document_id,
                    attempt=1,
                    outcome=documents_scan_service.ScanOutcome(
                        clean=True, detected_mime="application/zip", sha256="d" * 64
                    ),
                    request_id="e" * 32,
                    now=now,
                )
            session.rollback()
        with _runtime_session(engine, workspace_id) as session:
            rejected = documents_scan_service.finish_scan(
                session,
                workspace_id,
                client_id,
                document_id,
                attempt=1,
                outcome=documents_scan_service.ScanOutcome(
                    clean=False, detected_mime="application/zip", rejection_reason="mime_mismatch"
                ),
                request_id="f" * 32,
                now=now + timedelta(minutes=1),
            )
            session.commit()
    finally:
        engine.dispose()

    assert rejected.status is DocumentStatus.REJECTED
    assert rejected.rejection_reason == "mime_mismatch"
    rows = _owner_rows(
        owner_url,
        workspace_id,
        "SELECT status, rejection_reason, scan_lease_until FROM documents",
    )
    assert rows == [
        {"status": "rejected", "rejection_reason": "mime_mismatch", "scan_lease_until": None}
    ]


def test_stale_attempt_cannot_finalize_after_reclaim(scan_context) -> None:
    owner_url, engine, workspace_id, client_id = scan_context
    now = datetime(2026, 1, 2, tzinfo=UTC)
    try:
        with _runtime_session(engine, workspace_id) as session:
            document_id = _insert_document(session, workspace_id, client_id)
            session.commit()
        with _runtime_session(engine, workspace_id) as session:
            first = documents_scan_service.claim_scan_jobs(
                session, workspace_id, now=now, lease_seconds=1
            )
            session.commit()
        with _runtime_session(engine, workspace_id) as session:
            second = documents_scan_service.claim_scan_jobs(
                session, workspace_id, now=now + timedelta(seconds=2)
            )
            session.commit()
        assert first[0].attempt == 1
        assert second[0].attempt == 2
        with _runtime_session(engine, workspace_id) as session:
            with pytest.raises(documents_scan_service.InvalidScanState):
                documents_scan_service.finish_scan(
                    session,
                    workspace_id,
                    client_id,
                    document_id,
                    attempt=1,
                    outcome=documents_scan_service.ScanOutcome(
                        clean=True, detected_mime="application/pdf", sha256="a" * 64
                    ),
                    request_id="1" * 32,
                    now=now + timedelta(seconds=2),
                )
            session.rollback()
    finally:
        engine.dispose()


def test_claim_is_tenant_scoped(scan_context, migrated_database) -> None:
    _, engine, workspace_id, client_id = scan_context
    other_owner_url, _ = migrated_database
    other_workspace_id, other_client_id = _seed_client(other_owner_url)
    try:
        with _runtime_session(engine, workspace_id) as session:
            _insert_document(session, workspace_id, client_id)
            session.commit()
        with _runtime_session(engine, other_workspace_id) as session:
            jobs = documents_scan_service.claim_scan_jobs(
                session, other_workspace_id, now=datetime.now(UTC)
            )
            session.rollback()
    finally:
        engine.dispose()

    assert jobs == ()
    assert other_client_id != client_id
