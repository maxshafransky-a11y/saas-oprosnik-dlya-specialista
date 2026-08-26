"""Streaming quarantine scanner and its small ClamAV client."""

from __future__ import annotations

import hashlib
import socket
import struct
import time
from collections.abc import Iterable
from contextlib import closing
from datetime import UTC, datetime
from typing import Any, Protocol
from uuid import UUID, uuid4

from app.config import get_settings
from app.db import session_scope
from app.documents_scan_service import (
    ScanJob,
    ScanOutcome,
    ScanResult,
    claim_scan_jobs,
    finish_scan,
    retry_scan,
)
from app.documents_service import ALLOWED_DECLARED_MIMES, MAX_DOCUMENT_SIZE
from app.storage import S3Storage

READ_CHUNK_SIZE = 64 * 1024
MAGIC_PREFIX_SIZE = 4096
CLAMAV_COMMAND = b"zINSTREAM\0"
CLAMAV_RESPONSE_SIZE = 4096
CLAMAV_MAX_CHUNK_SIZE = (1 << 32) - 1
HEIC_BRANDS = frozenset({"heic", "heix", "hevc", "hevx", "mif1", "msf1"})


class ReadableObject(Protocol):
    def read(self, size: int = -1) -> bytes: ...

    def close(self) -> None: ...


class ScanStorage(Protocol):
    def open_read(self, object_key: str) -> ReadableObject: ...


class Antivirus(Protocol):
    def scan(self, chunks: Iterable[bytes]) -> bool: ...


class InvalidObjectError(ValueError):
    """The quarantined object is truncated, oversized, or has no supported signature."""


class ScannerUnavailable(RuntimeError):
    """A temporary storage or antivirus failure that should be retried."""

    def __init__(self, reason: str = "scanner_unavailable") -> None:
        super().__init__(reason)
        self.reason = reason


def _utc(value: datetime | None) -> datetime:
    if value is None:
        return datetime.now(UTC)
    if value.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    return value.astimezone(UTC)


def detect_mime(prefix: bytes) -> str | None:
    """Detect only the signatures explicitly allowed by the questionnaire contract."""
    if prefix.startswith(b"%PDF-"):
        return "application/pdf"
    if prefix.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if prefix.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if len(prefix) >= 12 and prefix[4:8] == b"ftyp":
        brands = {
            prefix[offset : offset + 4].decode("ascii", "ignore").casefold()
            for offset in range(8, len(prefix) - 3, 4)
        }
        if brands & HEIC_BRANDS:
            return "image/heic"
    return None


def _hashed_chunks(
    body: ReadableObject,
    expected_size: int,
    digest: Any,
    prefix: bytearray,
) -> Iterable[bytes]:
    total = 0
    while total < expected_size:
        try:
            chunk = body.read(min(READ_CHUNK_SIZE, expected_size - total + 1))
        except Exception as error:
            raise ScannerUnavailable("storage_unavailable") from error
        if not isinstance(chunk, bytes):
            raise InvalidObjectError("storage returned a non-bytes chunk")
        if not chunk:
            break
        total += len(chunk)
        if total > expected_size:
            raise InvalidObjectError("object is larger than declared")
        digest.update(chunk)
        if len(prefix) < MAGIC_PREFIX_SIZE:
            prefix.extend(chunk[: MAGIC_PREFIX_SIZE - len(prefix)])
        yield chunk
    if total != expected_size:
        raise InvalidObjectError("object size does not match declared size")
    try:
        trailing = body.read(1)
    except Exception as error:
        raise ScannerUnavailable("storage_unavailable") from error
    if trailing:
        raise InvalidObjectError("object is larger than declared")


def scan_object(job: ScanJob, *, storage: ScanStorage, antivirus: Antivirus) -> ScanOutcome:
    if (
        isinstance(job.size_bytes, bool)
        or not isinstance(job.size_bytes, int)
        or not 1 <= job.size_bytes <= MAX_DOCUMENT_SIZE
        or job.declared_mime not in ALLOWED_DECLARED_MIMES
    ):
        return ScanOutcome(clean=False, rejection_reason="invalid_object")
    try:
        body = storage.open_read(job.object_key)
    except KeyError:
        return ScanOutcome(clean=False, rejection_reason="invalid_object")
    except Exception as error:
        raise ScannerUnavailable("storage_unavailable") from error

    digest = hashlib.sha256()
    prefix = bytearray()
    try:
        with closing(body):
            try:
                clean = antivirus.scan(_hashed_chunks(body, job.size_bytes, digest, prefix))
            except (InvalidObjectError, ScannerUnavailable):
                raise
            except Exception as error:
                raise ScannerUnavailable("scanner_unavailable") from error
    except (InvalidObjectError, ScannerUnavailable):
        raise
    except Exception as error:
        raise ScannerUnavailable("storage_unavailable") from error
    if not isinstance(clean, bool):
        raise ScannerUnavailable("scanner_unavailable")
    detected_mime = detect_mime(bytes(prefix))
    if detected_mime not in ALLOWED_DECLARED_MIMES or detected_mime != job.declared_mime:
        return ScanOutcome(
            clean=False,
            detected_mime=detected_mime,
            rejection_reason="mime_mismatch",
        )
    if not clean:
        return ScanOutcome(
            clean=False,
            detected_mime=detected_mime,
            rejection_reason="malware",
        )
    return ScanOutcome(
        clean=True,
        detected_mime=detected_mime,
        sha256=digest.hexdigest(),
    )


class ClamAVClient:
    def __init__(self, host: str, port: int = 3310, timeout_seconds: float = 60.0) -> None:
        if not isinstance(host, str) or not host.strip():
            raise ValueError("ClamAV host is required")
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError("ClamAV port is invalid")
        if timeout_seconds <= 0:
            raise ValueError("ClamAV timeout is invalid")
        self.host = host.strip()
        self.port = port
        self.timeout_seconds = timeout_seconds

    def scan(self, chunks: Iterable[bytes]) -> bool:
        try:
            with socket.create_connection(
                (self.host, self.port), timeout=self.timeout_seconds
            ) as connection:
                connection.sendall(CLAMAV_COMMAND)
                for chunk in chunks:
                    if (
                        not isinstance(chunk, bytes)
                        or not chunk
                        or len(chunk) > CLAMAV_MAX_CHUNK_SIZE
                    ):
                        raise InvalidObjectError("invalid scanner chunk")
                    connection.sendall(struct.pack(">I", len(chunk)))
                    connection.sendall(chunk)
                connection.sendall(b"\x00\x00\x00\x00")
                response = self._read_response(connection)
        except (InvalidObjectError, ScannerUnavailable):
            raise
        except (OSError, TimeoutError) as error:
            raise ScannerUnavailable("scanner_unavailable") from error
        normalized = response.casefold()
        if normalized.endswith(" ok"):
            return True
        if normalized.endswith(" found"):
            return False
        raise ScannerUnavailable("scanner_unavailable")

    @staticmethod
    def _read_response(connection) -> str:
        response = bytearray()
        while (
            len(response) < CLAMAV_RESPONSE_SIZE
            and b"\n" not in response
            and b"\0" not in response
        ):
            try:
                chunk = connection.recv(CLAMAV_RESPONSE_SIZE - len(response))
            except (OSError, TimeoutError) as error:
                raise ScannerUnavailable("scanner_unavailable") from error
            if not chunk:
                break
            response.extend(chunk)
        terminators = [
            position
            for position in (response.find(b"\n"), response.find(b"\0"))
            if position >= 0
        ]
        if not terminators:
            raise ScannerUnavailable("scanner_unavailable")
        try:
            return bytes(response)[: min(terminators)].decode("ascii").strip()
        except UnicodeDecodeError as error:
            raise ScannerUnavailable("scanner_unavailable") from error


def run_scan_once(
    workspace_id: UUID,
    *,
    storage: ScanStorage,
    antivirus: Antivirus,
    limit: int = 10,
    lease_seconds: int = 300,
    now: datetime | None = None,
) -> tuple[ScanResult, ...]:
    current_time = _utc(now)
    with session_scope(workspace_id) as session:
        jobs = claim_scan_jobs(
            session,
            workspace_id,
            limit=limit,
            lease_seconds=lease_seconds,
            now=current_time,
        )
    results: list[ScanResult] = []
    for job in jobs:
        request_id = uuid4().hex
        try:
            outcome = scan_object(job, storage=storage, antivirus=antivirus)
        except InvalidObjectError:
            outcome = ScanOutcome(clean=False, rejection_reason="invalid_object")
        except ScannerUnavailable as error:
            with session_scope(workspace_id) as session:
                result = retry_scan(
                    session,
                    workspace_id,
                    job.client_id,
                    job.document_id,
                    attempt=job.attempt,
                    reason=error.reason,
                    request_id=request_id,
                    now=current_time,
                )
            results.append(result)
            continue
        with session_scope(workspace_id) as session:
            result = finish_scan(
                session,
                workspace_id,
                job.client_id,
                job.document_id,
                attempt=job.attempt,
                outcome=outcome,
                request_id=request_id,
                now=current_time,
            )
        results.append(result)
    return tuple(results)


def main() -> None:
    settings = get_settings()
    if not settings.scan_workspace_id:
        raise SystemExit("SCAN_WORKSPACE_ID is required for the scan worker")
    try:
        workspace_id = UUID(settings.scan_workspace_id)
    except ValueError as error:
        raise SystemExit("SCAN_WORKSPACE_ID must be a UUID") from error
    storage = S3Storage.from_settings(settings)
    antivirus = ClamAVClient(
        settings.clamav_host,
        settings.clamav_port,
        settings.clamav_timeout_seconds,
    )
    try:
        while True:
            run_scan_once(workspace_id, storage=storage, antivirus=antivirus)
            time.sleep(settings.scan_poll_seconds)
    except KeyboardInterrupt:
        return


if __name__ == "__main__":
    main()
