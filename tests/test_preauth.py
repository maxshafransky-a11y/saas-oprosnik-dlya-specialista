import base64
import hashlib
import hmac
import importlib
import json
import re
import sys
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest

ROOT = Path(__file__).parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

preauth = importlib.import_module("app.preauth")


APP_KEY = "app-secret-key-for-preauth-tests-" + "x" * 32
DOMAIN = b"health-intake:consent-ticket:v1"
WORKSPACE_ID = UUID("11111111-1111-4111-8111-111111111111")
POLICY_VERSION = "health-profile-v1"
TEXT_HASH = hashlib.sha256(b"approved consent text").hexdigest()


def _issue(*, accepted_at: datetime | None = None, ttl: timedelta | None = None) -> str:
    values: dict[str, object] = {
        "secret": APP_KEY,
        "workspace_id": WORKSPACE_ID,
        "policy_version": POLICY_VERSION,
        "text_hash": TEXT_HASH,
        "accepted_at": accepted_at or datetime.now(UTC) - timedelta(seconds=5),
    }
    if ttl is not None:
        values["ttl"] = ttl
    return preauth.issue_consent_ticket(**values)


def _decode_segment(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def _signed_payload(payload: object, *, raw: bool = False) -> str:
    payload_bytes = (
        payload
        if raw
        else json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode(
            "utf-8"
        )
    )
    encoded_payload = base64.urlsafe_b64encode(payload_bytes).rstrip(b"=")
    signature = hmac.new(APP_KEY.encode(), DOMAIN + b"\0" + payload_bytes, hashlib.sha256).digest()
    encoded_signature = base64.urlsafe_b64encode(signature).rstrip(b"=")
    return f"{encoded_payload.decode()}.{encoded_signature.decode()}"


def _valid_payload(now: datetime) -> dict[str, object]:
    return {
        "version": "v1",
        "workspace_id": str(WORKSPACE_ID),
        "policy_version": POLICY_VERSION,
        "text_hash": TEXT_HASH,
        "accepted_at": (now - timedelta(minutes=1)).isoformat(),
        "expires_at": (now + timedelta(minutes=29)).isoformat(),
    }


def test_round_trip_is_canonical_signed_and_immutable() -> None:
    accepted_at = datetime.now(UTC) - timedelta(seconds=5)
    token = preauth.issue_consent_ticket(
        APP_KEY,
        WORKSPACE_ID,
        POLICY_VERSION,
        TEXT_HASH,
        accepted_at,
    )
    payload_segment, signature_segment = token.split(".")
    raw_payload = _decode_segment(payload_segment)
    payload = json.loads(raw_payload)
    parsed = preauth.verify_consent_ticket(APP_KEY, token, now=accepted_at + timedelta(seconds=1))

    assert payload == {
        "accepted_at": accepted_at.isoformat(),
        "expires_at": (accepted_at + timedelta(minutes=30)).isoformat(),
        "policy_version": POLICY_VERSION,
        "text_hash": TEXT_HASH,
        "version": "v1",
        "workspace_id": str(WORKSPACE_ID),
    }
    assert (
        json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()
        == raw_payload
    )
    assert hmac.compare_digest(
        _decode_segment(signature_segment),
        hmac.new(APP_KEY.encode(), DOMAIN + b"\0" + raw_payload, hashlib.sha256).digest(),
    )
    assert all("=" not in segment for segment in token.split("."))
    assert all(re.fullmatch(r"[A-Za-z0-9_-]+", segment) for segment in token.split("."))
    assert set(payload) == {
        "version",
        "workspace_id",
        "policy_version",
        "text_hash",
        "accepted_at",
        "expires_at",
    }
    assert parsed.workspace_id == WORKSPACE_ID
    assert parsed.policy_version == POLICY_VERSION
    assert parsed.text_hash == TEXT_HASH
    assert parsed.accepted_at == accepted_at
    assert parsed.expires_at == accepted_at + timedelta(minutes=30)
    with pytest.raises(FrozenInstanceError):
        parsed.policy_version = "changed"


@pytest.mark.parametrize(
    ("secret", "workspace_id", "policy_version", "text_hash", "accepted_at", "ttl", "error"),
    [
        ("", WORKSPACE_ID, POLICY_VERSION, TEXT_HASH, None, None, ValueError),
        (APP_KEY, "not-a-uuid", POLICY_VERSION, TEXT_HASH, None, None, TypeError),
        (APP_KEY, WORKSPACE_ID, "", TEXT_HASH, None, None, ValueError),
        (APP_KEY, WORKSPACE_ID, POLICY_VERSION, TEXT_HASH.upper(), None, None, ValueError),
        (APP_KEY, WORKSPACE_ID, POLICY_VERSION, "not-a-hash", None, None, ValueError),
        (
            APP_KEY,
            WORKSPACE_ID,
            POLICY_VERSION,
            TEXT_HASH,
            datetime.now(UTC).replace(tzinfo=None),
            None,
            ValueError,
        ),
        (
            APP_KEY,
            WORKSPACE_ID,
            POLICY_VERSION,
            TEXT_HASH,
            datetime.now(UTC) + timedelta(minutes=1),
            None,
            ValueError,
        ),
        (
            APP_KEY,
            WORKSPACE_ID,
            POLICY_VERSION,
            TEXT_HASH,
            None,
            timedelta(minutes=30, seconds=1),
            ValueError,
        ),
        (APP_KEY, WORKSPACE_ID, POLICY_VERSION, TEXT_HASH, None, timedelta(0), ValueError),
        (APP_KEY, WORKSPACE_ID, POLICY_VERSION, TEXT_HASH, None, 30, TypeError),
    ],
)
def test_issue_rejects_invalid_types_and_time_contract(
    secret: object,
    workspace_id: object,
    policy_version: object,
    text_hash: object,
    accepted_at: object,
    ttl: object,
    error: type[Exception],
) -> None:
    values: dict[str, object] = {
        "secret": secret,
        "workspace_id": workspace_id,
        "policy_version": policy_version,
        "text_hash": text_hash,
        "accepted_at": accepted_at or datetime.now(UTC) - timedelta(seconds=5),
    }
    if ttl is not None:
        values["ttl"] = ttl

    with pytest.raises(error):
        preauth.issue_consent_ticket(**values)


def test_verify_rejects_expired_future_and_excessive_ttl() -> None:
    now = datetime.now(UTC)

    expired = _issue(accepted_at=now - timedelta(minutes=31))
    with pytest.raises(ValueError, match="expired"):
        preauth.verify_consent_ticket(APP_KEY, expired, now=now)

    future = _signed_payload(
        {
            **_valid_payload(now),
            "accepted_at": (now + timedelta(seconds=1)).isoformat(),
            "expires_at": (now + timedelta(minutes=10)).isoformat(),
        }
    )
    with pytest.raises(ValueError, match="future"):
        preauth.verify_consent_ticket(APP_KEY, future, now=now)

    excessive = _signed_payload(
        {
            **_valid_payload(now),
            "accepted_at": (now - timedelta(minutes=1)).isoformat(),
            "expires_at": (now + timedelta(minutes=30, seconds=1)).isoformat(),
        }
    )
    with pytest.raises(ValueError, match="TTL"):
        preauth.verify_consent_ticket(APP_KEY, excessive, now=now)


@pytest.mark.parametrize("token", ["", ".", "not-base64.signature", "a.b.c", "a=.b"])
def test_verify_rejects_malformed_or_invalid_base64(token: str) -> None:
    with pytest.raises((TypeError, ValueError)):
        preauth.verify_consent_ticket(APP_KEY, token)


def test_verify_rejects_malformed_json_type_version_noncanonical_and_pii() -> None:
    now = datetime.now(UTC)
    valid = _valid_payload(now)

    for payload in [
        [valid],
        {**valid, "version": "v2"},
        {**valid, "workspace_id": 7},
        {**valid, "text_hash": TEXT_HASH.upper()},
        {**valid, "email": "alice@example.com"},
    ]:
        with pytest.raises(ValueError):
            preauth.verify_consent_ticket(APP_KEY, _signed_payload(payload), now=now)

    with pytest.raises(ValueError):
        preauth.verify_consent_ticket(APP_KEY, _signed_payload(b"not-json", raw=True), now=now)

    noncanonical = json.dumps(valid, ensure_ascii=False, sort_keys=False).encode()
    with pytest.raises(ValueError):
        preauth.verify_consent_ticket(APP_KEY, _signed_payload(noncanonical, raw=True), now=now)


def test_verify_rejects_tampered_payload_and_signature() -> None:
    token = _issue()
    payload_segment, signature_segment = token.split(".")
    tampered_payload = ("A" if payload_segment[0] != "A" else "B") + payload_segment[1:]
    tampered_signature = ("A" if signature_segment[0] != "A" else "B") + signature_segment[1:]

    with pytest.raises(ValueError, match="signature"):
        preauth.verify_consent_ticket(APP_KEY, f"{tampered_payload}.{signature_segment}")
    with pytest.raises(ValueError, match="signature"):
        preauth.verify_consent_ticket(APP_KEY, f"{payload_segment}.{tampered_signature}")
