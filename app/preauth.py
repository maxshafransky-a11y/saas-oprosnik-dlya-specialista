from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

CONSENT_TICKET_VERSION = "v1"
CONSENT_TICKET_DOMAIN = b"health-intake:consent-ticket:v1"
DEFAULT_CONSENT_TTL = timedelta(minutes=30)
MAX_CONSENT_TTL = timedelta(minutes=30)

_PAYLOAD_KEYS = frozenset(
    {"version", "workspace_id", "policy_version", "text_hash", "accepted_at", "expires_at"}
)
_BASE64URL_ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
_HEX_ALPHABET = frozenset("0123456789abcdef")


@dataclass(frozen=True, slots=True)
class ConsentTicket:
    workspace_id: UUID
    policy_version: str
    text_hash: str
    accepted_at: datetime
    expires_at: datetime
    version: str = CONSENT_TICKET_VERSION


def _hmac_key(secret: str | bytes | bytearray | memoryview) -> bytes:
    if isinstance(secret, str):
        secret = secret.encode("utf-8")
    elif isinstance(secret, (bytearray, memoryview)):
        secret = bytes(secret)
    if not isinstance(secret, bytes):
        raise TypeError("secret must be text or bytes")
    if not secret:
        raise ValueError("secret must not be empty")
    return secret


def _utc(value: datetime, field: str) -> datetime:
    if not isinstance(value, datetime):
        raise TypeError(f"{field} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field} must be timezone-aware UTC")
    if value.utcoffset() != timedelta(0):
        raise ValueError(f"{field} must be timezone-aware UTC")
    return value.astimezone(UTC)


def _validate_text_hash(text_hash: object) -> str:
    if not isinstance(text_hash, str):
        raise TypeError("text_hash must be a string")
    if len(text_hash) != 64 or any(character not in _HEX_ALPHABET for character in text_hash):
        raise ValueError("text_hash must be lowercase SHA-256 hex")
    return text_hash


def _validate_ttl(ttl: object) -> timedelta:
    if not isinstance(ttl, timedelta):
        raise TypeError("ttl must be a timedelta")
    if ttl <= timedelta(0):
        raise ValueError("ttl must be positive")
    if ttl > MAX_CONSENT_TTL:
        raise ValueError("ttl exceeds maximum")
    return ttl


def _canonical_json(payload: dict[str, object]) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _encode_base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode_base64url(value: str, field: str) -> bytes:
    if (
        not value
        or "=" in value
        or len(value) % 4 == 1
        or any(character not in _BASE64URL_ALPHABET for character in value)
    ):
        raise ValueError(f"invalid consent ticket {field}")
    try:
        encoded = value.encode("ascii") + b"=" * (-len(value) % 4)
        decoded = base64.b64decode(encoded, altchars=b"-_", validate=True)
    except (binascii.Error, UnicodeEncodeError, ValueError):
        raise ValueError(f"invalid consent ticket {field}") from None
    if _encode_base64url(decoded) != value:
        raise ValueError(f"invalid consent ticket {field}")
    return decoded


def _sign(secret: bytes, payload: bytes) -> bytes:
    return hmac.new(
        secret,
        CONSENT_TICKET_DOMAIN + b"\0" + payload,
        hashlib.sha256,
    ).digest()


def _serialize(payload: dict[str, object], secret: bytes) -> str:
    raw_payload = _canonical_json(payload)
    encoded_payload = _encode_base64url(raw_payload)
    signature = _encode_base64url(_sign(secret, raw_payload))
    return f"{encoded_payload}.{signature}"


def issue_consent_ticket(
    secret: str | bytes | bytearray | memoryview,
    workspace_id: UUID,
    policy_version: str,
    text_hash: str,
    accepted_at: datetime,
    *,
    ttl: timedelta = DEFAULT_CONSENT_TTL,
) -> str:
    key = _hmac_key(secret)
    if not isinstance(workspace_id, UUID):
        raise TypeError("workspace_id must be a UUID")
    if not isinstance(policy_version, str):
        raise TypeError("policy_version must be a string")
    if not policy_version.strip():
        raise ValueError("policy_version must not be empty")
    accepted = _utc(accepted_at, "accepted_at")
    if accepted > datetime.now(UTC):
        raise ValueError("accepted_at cannot be in the future")
    duration = _validate_ttl(ttl)
    expires = accepted + duration
    payload: dict[str, object] = {
        "accepted_at": accepted.isoformat(),
        "expires_at": expires.isoformat(),
        "policy_version": policy_version,
        "text_hash": _validate_text_hash(text_hash),
        "version": CONSENT_TICKET_VERSION,
        "workspace_id": str(workspace_id),
    }
    return _serialize(payload, key)


def _no_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    payload: dict[str, object] = {}
    for key, value in pairs:
        if key in payload:
            raise ValueError("duplicate consent ticket JSON key")
        payload[key] = value
    return payload


def _parse_json(raw_payload: bytes) -> dict[str, object]:
    try:
        payload = json.loads(
            raw_payload.decode("utf-8"),
            object_pairs_hook=_no_duplicate_pairs,
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        raise ValueError("invalid consent ticket JSON") from None
    if not isinstance(payload, dict) or set(payload) != _PAYLOAD_KEYS:
        raise ValueError("invalid consent ticket payload")
    try:
        canonical = _canonical_json(payload)
    except (TypeError, ValueError):
        raise ValueError("invalid consent ticket JSON") from None
    if canonical != raw_payload:
        raise ValueError("consent ticket JSON is not canonical")
    return payload


def _parse_timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"invalid consent ticket {field}")
    try:
        return _utc(datetime.fromisoformat(value), field)
    except (TypeError, ValueError):
        raise ValueError(f"invalid consent ticket {field}") from None


def _parse_payload(payload: dict[str, object]) -> ConsentTicket:
    if payload["version"] != CONSENT_TICKET_VERSION or not isinstance(payload["version"], str):
        raise ValueError("unsupported consent ticket version")
    workspace_value = payload["workspace_id"]
    if not isinstance(workspace_value, str):
        raise ValueError("invalid consent ticket workspace_id")
    try:
        workspace_id = UUID(workspace_value)
    except (AttributeError, TypeError, ValueError):
        raise ValueError("invalid consent ticket workspace_id") from None
    if str(workspace_id) != workspace_value:
        raise ValueError("invalid consent ticket workspace_id")

    policy_version = payload["policy_version"]
    if not isinstance(policy_version, str) or not policy_version.strip():
        raise ValueError("invalid consent ticket policy_version")
    text_hash = _validate_text_hash(payload["text_hash"])
    accepted_at = _parse_timestamp(payload["accepted_at"], "accepted_at")
    expires_at = _parse_timestamp(payload["expires_at"], "expires_at")
    ttl = expires_at - accepted_at
    if ttl <= timedelta(0):
        raise ValueError("consent ticket expiry must follow acceptance")
    if ttl > MAX_CONSENT_TTL:
        raise ValueError("consent ticket TTL exceeds maximum")
    return ConsentTicket(
        workspace_id=workspace_id,
        policy_version=policy_version,
        text_hash=text_hash,
        accepted_at=accepted_at,
        expires_at=expires_at,
    )


def verify_consent_ticket(
    secret: str | bytes | bytearray | memoryview,
    token: str,
    *,
    now: datetime | None = None,
) -> ConsentTicket:
    key = _hmac_key(secret)
    if not isinstance(token, str):
        raise TypeError("token must be a string")
    parts = token.split(".")
    if len(parts) != 2:
        raise ValueError("invalid consent ticket")
    raw_payload = _decode_base64url(parts[0], "payload")
    signature = _decode_base64url(parts[1], "signature")
    if len(signature) != hashlib.sha256().digest_size:
        raise ValueError("invalid consent ticket signature")
    if not hmac.compare_digest(signature, _sign(key, raw_payload)):
        raise ValueError("invalid consent ticket signature")
    ticket = _parse_payload(_parse_json(raw_payload))
    current = _utc(now, "now") if now is not None else datetime.now(UTC)
    if ticket.accepted_at > current:
        raise ValueError("consent ticket accepted_at is in the future")
    if ticket.expires_at <= current:
        raise ValueError("consent ticket expired")
    return ticket
