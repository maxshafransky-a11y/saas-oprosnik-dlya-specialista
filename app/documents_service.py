"""Tenant-scoped document upload intent and quarantine handoff services."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AuditEvent, Document, DocumentStatus

MAX_DOCUMENT_SIZE = 25 * 1024 * 1024
MIN_DOCUMENT_SIZE = 1
UPLOAD_URL_TTL_SECONDS = 600
DOWNLOAD_URL_TTL_SECONDS = 300
ALLOWED_DECLARED_MIMES = frozenset({"application/pdf", "image/heic", "image/jpeg", "image/png"})
_IDENTIFIER_RE = re.compile(r"[0-9a-f]{32}")


class StoragePort(Protocol):
    def presign_put(
        self, object_key: str, content_type: str, content_length: int, expires_seconds: int
    ) -> str: ...

    def head(self, object_key: str) -> StorageHead: ...

    def presign_get(self, object_key: str, expires_seconds: int) -> str: ...


@dataclass(frozen=True, slots=True)
class StorageHead:
    size_bytes: int


@dataclass(frozen=True, slots=True)
class DocumentResult:
    document_id: UUID
    original_name: str
    declared_mime: str
    size_bytes: int
    status: DocumentStatus
    object_key: str
    upload_url: str | None
    download_url: str | None = None


class InvalidUpload(ValueError):
    """The upload metadata is outside the V1 contract."""


class InvalidRequestId(ValueError):
    """The technical audit request identifier is not canonical."""


class DocumentNotFound(LookupError):
    """The document is not visible in the caller's tenant/client scope."""


class InvalidDocumentState(ValueError):
    """The requested document transition is not allowed."""


class UploadIncomplete(ValueError):
    """The storage object cannot be confirmed as uploaded."""


class UploadSizeMismatch(UploadIncomplete):
    """The object size differs from the declared upload size."""


def _utc(value: datetime | None) -> datetime:
    if value is None:
        return datetime.now(UTC)
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    return value.astimezone(UTC)


def _validate_request_id(request_id: str) -> None:
    if not isinstance(request_id, str) or _IDENTIFIER_RE.fullmatch(request_id) is None:
        raise InvalidRequestId("request id is invalid")


def _validate_upload_metadata(
    original_name: str, declared_mime: str, size_bytes: int
) -> tuple[str, str]:
    if not isinstance(original_name, str):
        raise InvalidUpload("original name is invalid")
    name = original_name.strip()
    if (
        not name
        or name in {".", ".."}
        or len(name) > 255
        or "/" in name
        or "\\" in name
        or any(ord(character) < 32 or ord(character) == 127 for character in name)
    ):
        raise InvalidUpload("original name is invalid")
    if not isinstance(declared_mime, str):
        raise InvalidUpload("declared mime is invalid")
    mime = declared_mime.strip().casefold()
    if mime not in ALLOWED_DECLARED_MIMES:
        raise InvalidUpload("declared mime is invalid")
    if (
        isinstance(size_bytes, bool)
        or not isinstance(size_bytes, int)
        or not MIN_DOCUMENT_SIZE <= size_bytes <= MAX_DOCUMENT_SIZE
    ):
        raise InvalidUpload("size is invalid")
    return name, mime


def _document_view(
    document: Document,
    upload_url: str | None = None,
    download_url: str | None = None,
) -> DocumentResult:
    return DocumentResult(
        document_id=document.id,
        original_name=document.original_name,
        declared_mime=document.declared_mime,
        size_bytes=document.size_bytes,
        status=document.status,
        object_key=document.object_key,
        upload_url=upload_url,
        download_url=download_url,
    )


def _load_document(
    session: Session, workspace_id: UUID, client_id: UUID, document_id: UUID, *, lock: bool
) -> Document:
    statement = select(Document).where(
        Document.id == document_id,
        Document.workspace_id == workspace_id,
        Document.client_id == client_id,
    )
    if lock:
        statement = statement.with_for_update()
    document = session.execute(statement).scalar_one_or_none()
    if document is None:
        raise DocumentNotFound("document not found")
    return document


def create_upload_intent(
    session: Session,
    workspace_id: UUID,
    client_id: UUID,
    *,
    original_name: str,
    declared_mime: str,
    size_bytes: int,
    storage: StoragePort,
    request_id: str,
    response_id: UUID | None = None,
    question_key: str | None = None,
    now: datetime | None = None,
) -> DocumentResult:
    _validate_request_id(request_id)
    name, mime = _validate_upload_metadata(original_name, declared_mime, size_bytes)
    document = Document(
        id=uuid4(),
        workspace_id=workspace_id,
        client_id=client_id,
        response_id=response_id,
        question_key=question_key,
        object_key=f"quarantine/{uuid4()}",
        original_name=name,
        declared_mime=mime,
        size_bytes=size_bytes,
        status=DocumentStatus.UPLOADING,
        created_at=_utc(now),
    )
    session.add(document)
    session.flush()
    upload_url = storage.presign_put(
        document.object_key,
        document.declared_mime,
        document.size_bytes,
        UPLOAD_URL_TTL_SECONDS,
    )
    if not isinstance(upload_url, str) or not upload_url:
        raise UploadIncomplete("storage did not return an upload URL")
    return _document_view(document, upload_url)


def get_document_status(
    session: Session, workspace_id: UUID, client_id: UUID, document_id: UUID
) -> DocumentResult:
    return _document_view(_load_document(session, workspace_id, client_id, document_id, lock=False))


def get_download_url(
    session: Session,
    workspace_id: UUID,
    client_id: UUID,
    document_id: UUID,
    *,
    storage: StoragePort,
    request_id: str,
) -> DocumentResult:
    _validate_request_id(request_id)
    document = _load_document(session, workspace_id, client_id, document_id, lock=False)
    if document.status is not DocumentStatus.READY:
        raise InvalidDocumentState("document is not ready")
    download_url = storage.presign_get(document.object_key, DOWNLOAD_URL_TTL_SECONDS)
    if not isinstance(download_url, str) or not download_url:
        raise UploadIncomplete("storage did not return a download URL")
    session.add(
        AuditEvent(
            id=uuid4(),
            workspace_id=workspace_id,
            client_id=client_id,
            actor_type="client",
            event_type="document_downloaded",
            target_type="document",
            target_id=document.id,
            occurred_at=datetime.now(UTC),
            request_id=request_id,
            metadata_jsonb={},
        )
    )
    session.flush()
    return _document_view(document, download_url=download_url)


def complete_upload(
    session: Session,
    workspace_id: UUID,
    client_id: UUID,
    document_id: UUID,
    *,
    storage: StoragePort,
    request_id: str,
    now: datetime | None = None,
) -> DocumentResult:
    _validate_request_id(request_id)
    document = _load_document(session, workspace_id, client_id, document_id, lock=True)
    if document.status is DocumentStatus.QUARANTINED:
        return _document_view(document)
    if document.status is not DocumentStatus.UPLOADING:
        raise InvalidDocumentState("document cannot be completed")
    try:
        head = storage.head(document.object_key)
    except (KeyError, UploadIncomplete) as error:
        raise UploadIncomplete("storage object is not available") from error
    if (
        not isinstance(head, StorageHead)
        or isinstance(head.size_bytes, bool)
        or not isinstance(head.size_bytes, int)
        or head.size_bytes != document.size_bytes
    ):
        raise UploadSizeMismatch("storage object size does not match declared size")
    occurred_at = _utc(now)
    document.status = DocumentStatus.QUARANTINED
    document.uploaded_at = occurred_at
    session.add(
        AuditEvent(
            id=uuid4(),
            workspace_id=workspace_id,
            client_id=client_id,
            actor_type="client",
            event_type="document_quarantined",
            target_type="document",
            target_id=document.id,
            occurred_at=occurred_at,
            request_id=request_id,
            metadata_jsonb={
                "declared_mime": document.declared_mime,
                "size_bytes": document.size_bytes,
            },
        )
    )
    session.flush()
    return _document_view(document)
