"""Private S3-compatible object storage adapter."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import boto3
from botocore.exceptions import ClientError

from app.documents_service import StorageHead

if TYPE_CHECKING:
    from app.config import Settings

MAX_PRESIGN_SECONDS = 900


def _validate_key(object_key: str) -> str:
    if (
        not isinstance(object_key, str)
        or not object_key
        or object_key.startswith("/")
        or any(ord(character) < 32 or ord(character) == 127 for character in object_key)
    ):
        raise ValueError("object key is invalid")
    return object_key


def _validate_ttl(expires_seconds: int) -> int:
    if (
        isinstance(expires_seconds, bool)
        or not isinstance(expires_seconds, int)
        or not 1 <= expires_seconds <= MAX_PRESIGN_SECONDS
    ):
        raise ValueError("presign expiry is invalid")
    return expires_seconds


class S3Storage:
    @classmethod
    def from_settings(cls, settings: Settings) -> S3Storage:
        return cls(
            settings.storage_bucket,
            endpoint_url=settings.storage_endpoint_url,
            public_endpoint_url=settings.storage_public_endpoint_url,
            region_name=settings.storage_region,
            access_key_id=(
                settings.storage_access_key_id.get_secret_value()
                if settings.storage_access_key_id is not None
                else None
            ),
            secret_access_key=(
                settings.storage_secret_access_key.get_secret_value()
                if settings.storage_secret_access_key is not None
                else None
            ),
        )

    def __init__(
        self,
        bucket: str,
        *,
        client: Any | None = None,
        presign_client: Any | None = None,
        endpoint_url: str | None = None,
        public_endpoint_url: str | None = None,
        region_name: str | None = None,
        access_key_id: str | None = None,
        secret_access_key: str | None = None,
    ) -> None:
        if not isinstance(bucket, str) or not bucket.strip():
            raise ValueError("storage bucket is required")
        self.bucket = bucket.strip()
        client_kwargs = {
            key: value
            for key, value in {
                "endpoint_url": endpoint_url,
                "region_name": region_name,
                "aws_access_key_id": access_key_id,
                "aws_secret_access_key": secret_access_key,
            }.items()
            if value is not None
        }
        if client is None:
            client = boto3.client("s3", **client_kwargs)
        self._client = client
        if presign_client is not None:
            self._presign_client = presign_client
        elif public_endpoint_url and public_endpoint_url != endpoint_url:
            self._presign_client = boto3.client(
                "s3",
                **{**client_kwargs, "endpoint_url": public_endpoint_url},
            )
        else:
            self._presign_client = client

    def presign_put(
        self, object_key: str, content_type: str, content_length: int, expires_seconds: int
    ) -> str:
        key = _validate_key(object_key)
        if (
            not isinstance(content_type, str)
            or not content_type
            or len(content_type) > 255
            or any(ord(character) < 32 or ord(character) == 127 for character in content_type)
        ):
            raise ValueError("content type is invalid")
        if (
            isinstance(content_length, bool)
            or not isinstance(content_length, int)
            or content_length < 1
        ):
            raise ValueError("content length is invalid")
        expiry = _validate_ttl(expires_seconds)
        return self._presign_client.generate_presigned_url(
            "put_object",
            Params={
                "Bucket": self.bucket,
                "Key": key,
                "ContentType": content_type,
                "ContentLength": content_length,
            },
            ExpiresIn=expiry,
        )

    def presign_get(self, object_key: str, expires_seconds: int) -> str:
        key = _validate_key(object_key)
        expiry = _validate_ttl(expires_seconds)
        return self._presign_client.generate_presigned_url(
            "get_object",
            Params={"Bucket": self.bucket, "Key": key},
            ExpiresIn=expiry,
        )

    def head(self, object_key: str) -> StorageHead:
        key = _validate_key(object_key)
        try:
            response = self._client.head_object(Bucket=self.bucket, Key=key)
        except ClientError as error:
            error_code = str(error.response.get("Error", {}).get("Code", ""))
            if error_code in {"404", "NoSuchKey", "NotFound"}:
                raise KeyError(key) from None
            raise
        size_bytes = response.get("ContentLength")
        if isinstance(size_bytes, bool) or not isinstance(size_bytes, int) or size_bytes < 0:
            raise ValueError("storage returned an invalid object size")
        return StorageHead(size_bytes=size_bytes)

    def open_read(self, object_key: str):
        key = _validate_key(object_key)
        try:
            response = self._client.get_object(Bucket=self.bucket, Key=key)
        except ClientError as error:
            error_code = str(error.response.get("Error", {}).get("Code", ""))
            if error_code in {"404", "NoSuchKey", "NotFound"}:
                raise KeyError(key) from None
            raise
        body = response.get("Body")
        if body is None or not callable(getattr(body, "read", None)):
            raise ValueError("storage returned an invalid object body")
        return body

    def delete(self, object_key: str) -> None:
        self._client.delete_object(Bucket=self.bucket, Key=_validate_key(object_key))
