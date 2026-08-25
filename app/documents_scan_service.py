"""Lease-based document scan state transitions."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from app.documents_service import ALLOWED_DECLARED_MIMES
from app.models import AuditEvent, Document, DocumentStatus

MAX_SCAN_BATCH = 100
MIN_LEASE_SECONDS = 1
MAX_LEASE_SECONDS = 3600
_IDENTIFIER_RE = re.compile(r"[0-9a-f]{32}")
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_REJECTION_REASONS = frozenset({"invalid_object", "malware", "mime_mismatch", "scan_error"})


@dataclass(frozen=True, slots=True)
class ScanJob:
    document_id: UUID
    object_key: str
    declared_mime: str
    size_bytes: int
    attempt: int
    lease_until: datetime


@dataclass(frozen=True, slots=True)
class ScanOutcome:
    clean: bool
    detected_mime: str | None = None
    sha256: str | None = None
    rejection_reason: str | None = None


@dataclass(frozen=True, slots=True)
class ScanResult:
    document_id: UUID
    status: DocumentStatus
    detected_mime: str | None
    sha256: str | None
    rejection_reason: str | None


class InvalidScanRequest(ValueError):
    """The scan worker request identifier or lease parameters are invalid."""


class InvalidScanResult(ValueError):
    """The worker returned an unsafe or incomplete scan result."""


class InvalidScanState(ValueError):
    """The document is not currently owned by a scan lease."""


class ScanDocumentNotFound(LookupError):
    """The document is not visible in the worker's tenant scope."""


def _utc(value: datetime | None) -> datetime:
    if value is None:
        return datetime.now(UTC)
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    return value.astimezone(UTC)


def _validate_request_id(request_id: str) -> None:
    if not isinstance(request_id, str) or _IDENTIFIER_RE.fullmatch(request_id) is None:
        raise InvalidScanRequest("request id is invalid")


def _validate_lease(limit: int, lease_seconds: int) -> None:
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_SCAN_BATCH:
        raise InvalidScanRequest("scan batch limit is invalid")
    if (
        isinstance(lease_seconds, bool)
        or not isinstance(lease_seconds, int)
        or not MIN_LEASE_SECONDS <= lease_seconds <= MAX_LEASE_SECONDS
    ):
        raise InvalidScanRequest("scan lease is invalid")


def _validate_text(value: str | None, field: str) -> str | None:
    if value is None:
        return None
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 255
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise InvalidScanResult(f"{field} is invalid")
    return value.casefold()


def _validate_outcome(outcome: ScanOutcome) -> ScanOutcome:
    if not isinstance(outcome, ScanOutcome) or not isinstance(outcome.clean, bool):
        raise InvalidScanResult("scan result is invalid")
    detected_mime = _validate_text(outcome.detected_mime, "detected mime")
    sha256 = outcome.sha256
    if sha256 is not None and _SHA256_RE.fullmatch(sha256) is None:
        raise InvalidScanResult("sha256 is invalid")
    if outcome.clean:
        if detected_mime not in ALLOWED_DECLARED_MIMES or sha256 is None:
            raise InvalidScanResult("clean scan result is incomplete")
        if outcome.rejection_reason is not None:
            raise InvalidScanResult("clean scan result has a rejection reason")
    elif outcome.rejection_reason not in _REJECTION_REASONS:
        raise InvalidScanResult("rejection reason is invalid")
    return ScanOutcome(
        clean=outcome.clean,
        detected_mime=detected_mime,
        sha256=sha256,
        rejection_reason=outcome.rejection_reason,
    )


def _result(document: Document) -> ScanResult:
    return ScanResult(
        document_id=document.id,
        status=document.status,
        detected_mime=document.detected_mime,
        sha256=document.sha256,
        rejection_reason=document.rejection_reason,
    )


def claim_scan_jobs(
    session: Session,
    workspace_id: UUID,
    *,
    limit: int = 10,
    lease_seconds: int = 300,
    now: datetime | None = None,
) -> tuple[ScanJob, ...]:
    _validate_lease(limit, lease_seconds)
    current_time = _utc(now)
    due = or_(
        and_(
            Document.status == DocumentStatus.QUARANTINED,
            or_(Document.next_scan_at.is_(None), Document.next_scan_at <= current_time),
        ),
        and_(
            Document.status == DocumentStatus.SCANNING,
            Document.scan_lease_until <= current_time,
        ),
    )
    statement = (
        select(Document)
        .where(Document.workspace_id == workspace_id, due)
        .order_by(Document.created_at, Document.id)
        .limit(limit)
        .with_for_update(skip_locked=True)
    )
    documents = session.execute(statement).scalars().all()
    lease_until = current_time + timedelta(seconds=lease_seconds)
    jobs: list[ScanJob] = []
    for document in documents:
        document.status = DocumentStatus.SCANNING
        document.scan_attempts += 1
        document.scan_lease_until = lease_until
        jobs.append(
            ScanJob(
                document_id=document.id,
                object_key=document.object_key,
                declared_mime=document.declared_mime,
                size_bytes=document.size_bytes,
                attempt=document.scan_attempts,
                lease_until=lease_until,
            )
        )
    session.flush()
    return tuple(jobs)


def finish_scan(
    session: Session,
    workspace_id: UUID,
    client_id: UUID,
    document_id: UUID,
    *,
    outcome: ScanOutcome,
    request_id: str,
    now: datetime | None = None,
) -> ScanResult:
    _validate_request_id(request_id)
    document = session.execute(
        select(Document)
        .where(
            Document.id == document_id,
            Document.workspace_id == workspace_id,
            Document.client_id == client_id,
        )
        .with_for_update()
    ).scalar_one_or_none()
    if document is None:
        raise ScanDocumentNotFound("document not found")
    if document.status in {DocumentStatus.READY, DocumentStatus.REJECTED}:
        return _result(document)
    if document.status is not DocumentStatus.SCANNING:
        raise InvalidScanState("document is not leased for scanning")
    normalized = _validate_outcome(outcome)
    occurred_at = _utc(now)
    document.detected_mime = normalized.detected_mime
    document.sha256 = normalized.sha256
    document.scan_lease_until = None
    if normalized.clean:
        document.status = DocumentStatus.READY
        document.ready_at = occurred_at
        document.rejection_reason = None
        event_type = "document_ready"
        metadata = {
            "detected_mime": normalized.detected_mime,
            "sha256": normalized.sha256,
        }
    else:
        document.status = DocumentStatus.REJECTED
        document.ready_at = None
        document.rejection_reason = normalized.rejection_reason
        event_type = "document_rejected"
        metadata = {
            "detected_mime": normalized.detected_mime,
            "rejection_reason": normalized.rejection_reason,
        }
    session.add(
        AuditEvent(
            id=uuid4(),
            workspace_id=workspace_id,
            client_id=client_id,
            actor_type="worker",
            event_type=event_type,
            target_type="document",
            target_id=document.id,
            occurred_at=occurred_at,
            request_id=request_id,
            metadata_jsonb=metadata,
        )
    )
    session.flush()
    return _result(document)
