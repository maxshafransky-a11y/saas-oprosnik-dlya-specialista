from __future__ import annotations

import hashlib
import socket
import sys
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).parents[1]))

from app import scan_worker


def _job(data: bytes, declared_mime: str = "application/pdf") -> SimpleNamespace:
    return SimpleNamespace(
        object_key="quarantine/object",
        declared_mime=declared_mime,
        size_bytes=len(data),
    )


class FakeStorage:
    def __init__(self, data: bytes) -> None:
        self.body = BytesIO(data)

    def open_read(self, object_key: str):
        assert object_key == "quarantine/object"
        return self.body


class RecordingAntivirus:
    def __init__(self, clean: bool = True) -> None:
        self.clean = clean
        self.data = b""

    def scan(self, chunks) -> bool:
        self.data = b"".join(chunks)
        return self.clean


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (b"%PDF-1.7\nbody", "application/pdf"),
        (b"\xff\xd8\xff\xe0body", "image/jpeg"),
        (b"\x89PNG\r\n\x1a\nbody", "image/png"),
        (b"\x00\x00\x00\x18ftypheic\x00\x00", "image/heic"),
        (b"unknown", None),
    ],
)
def test_detect_mime_uses_magic_bytes(data: bytes, expected: str | None) -> None:
    assert scan_worker.detect_mime(data) == expected


def test_scan_object_streams_hash_and_returns_clean_outcome() -> None:
    data = b"%PDF-1.7\n" + b"x" * (scan_worker.READ_CHUNK_SIZE + 11)
    antivirus = RecordingAntivirus()

    outcome = scan_worker.scan_object(
        _job(data), storage=FakeStorage(data), antivirus=antivirus
    )

    assert antivirus.data == data
    assert outcome.clean is True
    assert outcome.detected_mime == "application/pdf"
    assert outcome.sha256 == hashlib.sha256(data).hexdigest()


def test_scan_object_rejects_size_and_magic_mismatch() -> None:
    data = b"not a pdf"
    antivirus = RecordingAntivirus()

    outcome = scan_worker.scan_object(
        _job(data), storage=FakeStorage(data), antivirus=antivirus
    )

    assert outcome.clean is False
    assert outcome.rejection_reason == "mime_mismatch"

    with pytest.raises(scan_worker.InvalidObjectError):
        scan_worker.scan_object(
            _job(data),
            storage=FakeStorage(data + b"extra"),
            antivirus=RecordingAntivirus(),
        )

class FakeSocket:
    def __init__(self, response: bytes) -> None:
        self.response = response
        self.sent: list[bytes] = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def sendall(self, payload: bytes) -> None:
        self.sent.append(payload)

    def recv(self, size: int) -> bytes:
        response, self.response = self.response, b""
        return response


@pytest.mark.parametrize(
    ("response", "clean"),
    [(b"stream: OK\0", True), (b"stream: Eicar FOUND\0", False)],
)
def test_clamav_client_uses_instream_protocol(monkeypatch, response: bytes, clean: bool) -> None:
    connection = FakeSocket(response)
    monkeypatch.setattr(socket, "create_connection", lambda address, timeout: connection)

    result = scan_worker.ClamAVClient("clamav").scan([b"abc", b"def"])

    assert result is clean
    assert connection.sent == [
        b"zINSTREAM\0",
        b"\x00\x00\x00\x03",
        b"abc",
        b"\x00\x00\x00\x03",
        b"def",
        b"\x00\x00\x00\x00",
    ]
