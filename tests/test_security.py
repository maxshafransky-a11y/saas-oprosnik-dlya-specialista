import hashlib
import hmac
import importlib
import sys
from base64 import urlsafe_b64decode, urlsafe_b64encode
from pathlib import Path
from uuid import UUID, uuid4

import pytest

ROOT = Path(__file__).parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

security = importlib.import_module("app.security")


APP_KEY = b"app-secret-key-for-security-tests"


def test_normalize_email_is_case_insensitive_and_validated() -> None:
    assert security.normalize_email("  Alice@Example.COM  ") == "alice@example.com"

    with pytest.raises(ValueError):
        security.normalize_email("not-an-email")


def test_generate_otp_keeps_leading_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(security.secrets, "randbelow", lambda upper: 7)

    assert security.generate_otp() == "000007"


def test_magic_token_round_trip_and_strict_parser() -> None:
    workspace_id = uuid4()
    challenge_id = uuid4()

    token = security.generate_magic_token(workspace_id, challenge_id)
    parsed = security.parse_magic_token(token)

    assert parsed.workspace_id == workspace_id
    assert parsed.challenge_id == challenge_id
    assert len(parsed.secret_bytes) >= 32

    secret = urlsafe_b64encode(b"x" * 31).decode().rstrip("=")
    with pytest.raises(ValueError):
        security.parse_magic_token(f"{workspace_id}.{challenge_id}.{secret}")
    with pytest.raises(ValueError):
        security.parse_magic_token(f"{workspace_id}.{challenge_id}.not valid")
    with pytest.raises(ValueError):
        security.parse_magic_token(f"{workspace_id}.{challenge_id}.{parsed.secret}.extra")
    with pytest.raises(ValueError):
        security.parse_magic_token(f"{str(workspace_id).upper()}.{challenge_id}.{parsed.secret}")


def test_token_hashes_are_sha256_digests() -> None:
    token = "opaque-token"
    expected = hashlib.sha256(token.encode()).digest()

    assert security.hash_magic_token(token) == expected
    assert security.hash_session_token(token) == expected
    assert token.encode() not in security.hash_magic_token(token)


def test_session_tokens_are_unique_and_have_256_bits_of_entropy() -> None:
    first = security.generate_session_token()
    second = security.generate_session_token()
    decoded = urlsafe_b64decode(first + "=" * (-len(first) % 4))
    digest = security.hash_session_token(first)

    assert first != second
    assert len(decoded) >= 32
    assert len(digest) == 32
    assert first.encode() not in digest


def test_fingerprints_are_domain_separated_and_canonical() -> None:
    otp = security.fingerprint_otp(APP_KEY, "000007")
    email = security.fingerprint_email(APP_KEY, " Alice@Example.COM ")
    ip = security.fingerprint_ip(APP_KEY, "2001:0db8:0:0:0:0:0:1")

    assert otp == hmac.new(APP_KEY, b"health-intake:otp:v1\0" + b"000007", hashlib.sha256).digest()
    assert otp != email != ip
    assert email == security.fingerprint_email(APP_KEY, "alice@example.com")
    assert ip == security.fingerprint_ip(APP_KEY, "2001:db8::1")
    assert security.verify_digest(otp, security.fingerprint_otp(APP_KEY, "000007"))
    assert not security.verify_digest(otp, security.fingerprint_otp(APP_KEY, "000008"))

    with pytest.raises(ValueError):
        security.fingerprint_otp(APP_KEY, "7")
    with pytest.raises(ValueError):
        security.fingerprint_ip(APP_KEY, "not-an-ip")


def test_magic_token_ids_are_uuid_values() -> None:
    token = security.generate_magic_token(uuid4(), uuid4())
    parsed = security.parse_magic_token(token)

    assert isinstance(parsed.workspace_id, UUID)
    assert isinstance(parsed.challenge_id, UUID)
