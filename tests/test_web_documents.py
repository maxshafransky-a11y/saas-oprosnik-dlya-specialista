from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).parents[1]))

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session as DbSession
from sqlalchemy.pool import NullPool

from app.db import get_engine
from app.documents_service import StorageHead
from app.main import create_app
from app.models import Client, Workspace
from app.models import Session as SessionRecord
from app.security import generate_session_token, hash_session_token
from app.web_auth import SESSION_COOKIE_NAME, build_csrf_token

pytest_plugins = ("tests.db_test_support",)


class FakeStorage:
    def __init__(self) -> None:
        self.last_key: str | None = None
        self.sizes: dict[str, int] = {}
        self.deletes: list[str] = []

    def presign_put(
        self, object_key: str, content_type: str, content_length: int, expires_seconds: int
    ) -> str:
        self.last_key = object_key
        return f"https://storage.test/put/{object_key}"

    def head(self, object_key: str) -> StorageHead:
        return StorageHead(size_bytes=self.sizes[object_key])

    def presign_get(self, object_key: str, expires_seconds: int) -> str:
        return f"https://storage.test/get/{object_key}"

    def delete(self, object_key: str) -> None:
        self.deletes.append(object_key)


@pytest.fixture
def document_client(migrated_database):
    owner_url, _ = migrated_database
    workspace_id = uuid4()
    client_id = uuid4()
    session_id = uuid4()
    now = datetime(2026, 8, 25, 12, 0, tzinfo=UTC)
    token = generate_session_token(workspace_id, session_id)
    storage = FakeStorage()
    engine = create_engine(owner_url, poolclass=NullPool)
    try:
        with DbSession(engine) as session, session.begin():
            session.add(
                Workspace(
                    id=workspace_id,
                    name="Documents test workspace",
                    public_slug=f"documents-{workspace_id.hex}",
                )
            )
            session.flush()
            session.add(
                Client(
                    id=client_id,
                    workspace_id=workspace_id,
                    email_normalized=f"{client_id.hex}@example.com",
                    email_display=f"{client_id.hex}@example.com",
                )
            )
            session.add(
                SessionRecord(
                    id=session_id,
                    workspace_id=workspace_id,
                    client_id=client_id,
                    session_token_hash=hash_session_token(token),
                    idle_expires_at=now + timedelta(days=14),
                    absolute_expires_at=now + timedelta(days=30),
                    last_seen_at=now,
                    created_at=now,
                )
            )
    finally:
        engine.dispose()

    get_engine.cache_clear()
    try:
        yield (
            TestClient(create_app(storage=storage)),
            token,
            storage,
            build_csrf_token(
                session_id,
                "dev-only-app-secret-key-not-for-production-change-me",
            ),
        )
    finally:
        get_engine.cache_clear()


def _headers(csrf: str) -> dict[str, str]:
    return {"origin": "http://testserver", "x-csrf-token": csrf}


def test_document_http_flow_is_tenant_scoped_and_quarantined(document_client) -> None:
    client, token, storage, csrf = document_client
    cookies = {SESSION_COOKIE_NAME: token}

    intent = client.post(
        "/documents/uploads",
        json={
            "original_name": "analysis.pdf",
            "declared_mime": "application/pdf",
            "size_bytes": 42,
        },
        headers=_headers(csrf),
        cookies=cookies,
    )

    assert intent.status_code == 201
    body = intent.json()
    assert body["status"] == "uploading"
    assert body["upload_url"].startswith("https://storage.test/put/")
    assert "object_key" not in body
    document_id = body["document_id"]
    assert storage.last_key is not None
    storage.sizes[storage.last_key] = 42

    completed = client.post(
        f"/documents/{document_id}/complete",
        headers=_headers(csrf),
        cookies=cookies,
    )
    assert completed.status_code == 200
    assert completed.json()["status"] == "quarantined"

    status = client.get(f"/documents/{document_id}/status", cookies=cookies)
    assert status.status_code == 200
    assert status.json()["status"] == "quarantined"

    download = client.post(
        f"/documents/{document_id}/download",
        headers=_headers(csrf),
        cookies=cookies,
    )
    assert download.status_code == 409

    deleted = client.delete(
        f"/documents/{document_id}",
        headers=_headers(csrf),
        cookies=cookies,
    )
    assert deleted.status_code == 200
    assert deleted.json()["status"] == "deleted"
    assert storage.deletes == [storage.last_key]


def test_document_http_rejects_invalid_metadata_and_csrf(document_client) -> None:
    client, token, _, csrf = document_client
    cookies = {SESSION_COOKIE_NAME: token}

    invalid = client.post(
        "/documents/uploads",
        json={
            "original_name": "virus.exe",
            "declared_mime": "application/octet-stream",
            "size_bytes": 4,
        },
        headers=_headers(csrf),
        cookies=cookies,
    )
    assert invalid.status_code == 422

    csrf_rejected = client.post(
        "/documents/uploads",
        json={"original_name": "analysis.pdf", "declared_mime": "application/pdf", "size_bytes": 4},
        headers={"origin": "http://testserver"},
        cookies=cookies,
    )
    assert csrf_rejected.status_code == 403
