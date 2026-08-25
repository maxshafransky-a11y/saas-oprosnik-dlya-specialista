from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import secrets
from dataclasses import dataclass
from uuid import UUID

from email_validator import EmailNotValidError, validate_email

OTP_LENGTH = 6
MAGIC_SECRET_BYTES = 32

_OTP_DOMAIN = b"health-intake:otp:v1"
_EMAIL_DOMAIN = b"health-intake:email:v1"
_IP_DOMAIN = b"health-intake:ip:v1"
_MAGIC_SECRET_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)


@dataclass(frozen=True, slots=True)
class MagicToken:
    workspace_id: UUID
    challenge_id: UUID
    secret: str
    secret_bytes: bytes


def normalize_email(email: str) -> str:
    if not isinstance(email, str):
        raise TypeError("email must be a string")

    try:
        normalized = validate_email(email.strip(), check_deliverability=False).normalized
    except EmailNotValidError:
        raise ValueError("invalid email") from None
    return normalized.casefold()


def generate_otp() -> str:
    return f"{secrets.randbelow(10**OTP_LENGTH):0{OTP_LENGTH}d}"


def generate_session_token() -> str:
    return secrets.token_urlsafe(32)


def generate_magic_token(workspace_id: UUID, challenge_id: UUID) -> str:
    if not isinstance(workspace_id, UUID) or not isinstance(challenge_id, UUID):
        raise TypeError("workspace_id and challenge_id must be UUID values")

    secret = secrets.token_urlsafe(MAGIC_SECRET_BYTES)
    return f"{workspace_id}.{challenge_id}.{secret}"


def _parse_uuid(value: str) -> UUID:
    try:
        parsed = UUID(value)
    except (AttributeError, TypeError, ValueError):
        raise ValueError("invalid magic token") from None
    if str(parsed) != value:
        raise ValueError("invalid magic token")
    return parsed


def _decode_magic_secret(value: str) -> bytes:
    if not value or any(character not in _MAGIC_SECRET_ALPHABET for character in value):
        raise ValueError("invalid magic token")
    if len(value) % 4 == 1:
        raise ValueError("invalid magic token")

    try:
        encoded = value.encode("ascii")
        decoded = base64.b64decode(
            encoded + b"=" * (-len(encoded) % 4), altchars=b"-_", validate=True
        )
    except (UnicodeEncodeError, ValueError):
        raise ValueError("invalid magic token") from None

    if len(decoded) < MAGIC_SECRET_BYTES:
        raise ValueError("invalid magic token")
    canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    if canonical != value:
        raise ValueError("invalid magic token")
    return decoded


def parse_magic_token(token: str) -> MagicToken:
    if not isinstance(token, str):
        raise TypeError("token must be a string")

    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("invalid magic token")

    workspace_id = _parse_uuid(parts[0])
    challenge_id = _parse_uuid(parts[1])
    secret_bytes = _decode_magic_secret(parts[2])
    return MagicToken(workspace_id, challenge_id, parts[2], secret_bytes)


def _hash_token(token: str) -> bytes:
    if not isinstance(token, str):
        raise TypeError("token must be a string")
    return hashlib.sha256(token.encode("utf-8")).digest()


def hash_magic_token(token: str) -> bytes:
    return _hash_token(token)


def hash_session_token(token: str) -> bytes:
    return _hash_token(token)


def canonical_ip(address: str) -> str:
    if not isinstance(address, str):
        raise TypeError("ip address must be a string")

    try:
        return ipaddress.ip_address(address.strip()).compressed
    except ValueError:
        raise ValueError("invalid IP address") from None


def _hmac_key(key: str | bytes | bytearray | memoryview) -> bytes:
    if isinstance(key, str):
        key = key.encode("utf-8")
    elif isinstance(key, (bytearray, memoryview)):
        key = bytes(key)
    if not isinstance(key, bytes):
        raise TypeError("HMAC key must be text or bytes")
    if not key:
        raise ValueError("HMAC key must not be empty")
    return key


def _fingerprint(key: str | bytes | bytearray | memoryview, domain: bytes, value: str) -> bytes:
    return hmac.new(_hmac_key(key), domain + b"\0" + value.encode("utf-8"), hashlib.sha256).digest()


def fingerprint_otp(key: str | bytes | bytearray | memoryview, otp: str) -> bytes:
    if (
        not isinstance(otp, str)
        or len(otp) != OTP_LENGTH
        or not all("0" <= character <= "9" for character in otp)
    ):
        raise ValueError("OTP must be six ASCII digits")
    return _fingerprint(key, _OTP_DOMAIN, otp)


def fingerprint_email(key: str | bytes | bytearray | memoryview, email: str) -> bytes:
    return _fingerprint(key, _EMAIL_DOMAIN, normalize_email(email))


def fingerprint_ip(key: str | bytes | bytearray | memoryview, address: str) -> bytes:
    return _fingerprint(key, _IP_DOMAIN, canonical_ip(address))


def verify_digest(
    candidate: bytes | bytearray | memoryview, expected: bytes | bytearray | memoryview
) -> bool:
    if not isinstance(candidate, (bytes, bytearray, memoryview)) or not isinstance(
        expected, (bytes, bytearray, memoryview)
    ):
        raise TypeError("digests must be bytes")
    return hmac.compare_digest(bytes(candidate), bytes(expected))
