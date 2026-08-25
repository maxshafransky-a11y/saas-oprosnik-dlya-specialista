from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1]))

import pytest
from botocore.exceptions import ClientError

from app import storage
from app.documents_service import StorageHead


class RecordingClient:
    def __init__(self) -> None:
        self.presign_calls: list[tuple[str, dict, int]] = []
        self.head_calls: list[dict] = []
        self.delete_calls: list[dict] = []
        self.object_size = 42

    def generate_presigned_url(self, method: str, *, Params: dict, ExpiresIn: int) -> str:
        self.presign_calls.append((method, Params, ExpiresIn))
        return f"https://storage.test/{method}/{Params['Key']}"

    def head_object(self, **params: str) -> dict[str, int]:
        self.head_calls.append(params)
        return {"ContentLength": self.object_size}

    def delete_object(self, **params: str) -> dict:
        self.delete_calls.append(params)
        return {}


class MissingClient(RecordingClient):
    def head_object(self, **params: str) -> dict[str, int]:
        raise ClientError(
            {"Error": {"Code": "404", "Message": "Not Found"}},
            "HeadObject",
        )


def test_adapter_signs_put_get_heads_and_deletes_without_network() -> None:
    client = RecordingClient()
    adapter = storage.S3Storage("private-health", client=client)

    put_url = adapter.presign_put("quarantine/object", "application/pdf", 42, 600)
    get_url = adapter.presign_get("quarantine/object", 300)
    head = adapter.head("quarantine/object")
    adapter.delete("quarantine/object")

    assert put_url == "https://storage.test/put_object/quarantine/object"
    assert get_url == "https://storage.test/get_object/quarantine/object"
    assert head == StorageHead(size_bytes=42)
    assert client.presign_calls == [
        (
            "put_object",
            {
                "Bucket": "private-health",
                "Key": "quarantine/object",
                "ContentType": "application/pdf",
                "ContentLength": 42,
            },
            600,
        ),
        (
            "get_object",
            {"Bucket": "private-health", "Key": "quarantine/object"},
            300,
        ),
    ]
    assert client.head_calls == [{"Bucket": "private-health", "Key": "quarantine/object"}]
    assert client.delete_calls == [{"Bucket": "private-health", "Key": "quarantine/object"}]


def test_head_maps_provider_not_found_to_safe_missing_signal() -> None:
    adapter = storage.S3Storage("private-health", client=MissingClient())

    with pytest.raises(KeyError):
        adapter.head("quarantine/object")


@pytest.mark.parametrize("bucket", ["", "  "])
def test_bucket_is_required(bucket: str) -> None:
    with pytest.raises(ValueError):
        storage.S3Storage(bucket, client=RecordingClient())
