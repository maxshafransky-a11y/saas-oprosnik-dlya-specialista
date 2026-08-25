from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.models import (
    AuditEvent,
    Client,
    ClientStatus,
    Consent,
    LoginChallenge,
)
from app.models import Session as SessionRecord
from app.preauth import ConsentTicket
from app.security import (
    fingerprint_ip,
    fingerprint_otp,
    generate_magic_token,
    generate_otp,
    generate_session_token,
    hash_magic_token,
    hash_session_token,
    normalize_email,
    parse_magic_token,
    parse_session_token,
    verify_digest,
)

CHALLENGE_TTL = timedelta(minutes=15)
RESEND_DELAY = timedelta(seconds=60)
RATE_WINDOW = timedelta(minutes=15)
MAX_EMAIL_CHALLENGES = 5
MAX_IP_CHALLENGES = 30
MAX_OTP_ATTEMPTS = 5
SESSION_IDLE_TTL = timedelta(days=14)
SESSION_ABSOLUTE_TTL = timedelta(days=30)
REQUEST_ID_MAX_LENGTH = 128

_OTP_CHALLENGE_DOMAIN = b"health-intake:otp-challenge:v1"


@dataclass(frozen=True, slots=True)
class IssuedChallenge:
    challenge_id: UUID
    magic_token: str
    otp: str
    expires_at: datetime
    resend_after: datetime


@dataclass(frozen=True, slots=True)
class AuthenticatedSession:
    token: str
    workspace_id: UUID
    client_id: UUID
    session_id: UUID
    idle_expires_at: datetime
    absolute_expires_at: datetime


@dataclass(frozen=True, slots=True)
class SessionPrincipal:
    workspace_id: UUID
    client_id: UUID
    session_id: UUID
    idle_expires_at: datetime
    absolute_expires_at: datetime


class ChallengeUnavailable(Exception):
    code = "challenge_unavailable"

    def __init__(self) -> None:
        super().__init__("challenge unavailable")


def _hmac_key(secret: str | bytes | bytearray | memoryview) -> bytes:
    if isinstance(secret, str):
        secret = secret.encode("utf-8")
    elif isinstance(secret, (bytearray, memoryview)):
        secret = bytes(secret)
    if not isinstance(secret, bytes):
        raise TypeError("HMAC key must be text or bytes")
    if not secret:
        raise ValueError("HMAC key must not be empty")
    return secret


def _utc(value: datetime, field: str) -> datetime:
    if not isinstance(value, datetime):
        raise TypeError(f"{field} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field} must be timezone-aware UTC")
    if value.utcoffset() != timedelta(0):
        raise ValueError(f"{field} must be timezone-aware UTC")
    return value.astimezone(UTC)


def _now(value: datetime | None) -> datetime:
    return datetime.now(UTC) if value is None else _utc(value, "now")


def _validate_request_id(request_id: str) -> None:
    if (
        not isinstance(request_id, str)
        or not request_id.strip()
        or len(request_id) > REQUEST_ID_MAX_LENGTH
    ):
        raise ValueError("invalid request_id")


def _challenge_otp_hash(
    secret: str | bytes | bytearray | memoryview, challenge_id: UUID, code: str
) -> bytes:
    key = hmac.new(
        _hmac_key(secret),
        _OTP_CHALLENGE_DOMAIN + b"\0" + challenge_id.bytes,
        hashlib.sha256,
    ).digest()
    return fingerprint_otp(key, code)


def _challenge_is_usable(challenge: LoginChallenge, current: datetime) -> bool:
    return (
        challenge.consumed_at is None
        and challenge.invalidated_at is None
        and challenge.expires_at > current
        and challenge.attempt_count < MAX_OTP_ATTEMPTS
    )


def _load_challenge(
    session: Session, workspace_id: UUID, challenge_id: UUID
) -> LoginChallenge | None:
    return session.scalar(
        select(LoginChallenge)
        .where(
            LoginChallenge.workspace_id == workspace_id,
            LoginChallenge.id == challenge_id,
        )
        .with_for_update()
    )


def _invalidate_sibling_challenges(
    session: Session, challenge: LoginChallenge, current: datetime
) -> None:
    session.execute(
        update(LoginChallenge)
        .where(
            LoginChallenge.workspace_id == challenge.workspace_id,
            LoginChallenge.email_normalized == challenge.email_normalized,
            LoginChallenge.id != challenge.id,
            LoginChallenge.consumed_at.is_(None),
            LoginChallenge.invalidated_at.is_(None),
        )
        .values(invalidated_at=current)
    )


def _complete_challenge(
    session: Session,
    challenge: LoginChallenge,
    request_id: str,
    current: datetime,
) -> AuthenticatedSession | None:
    client = session.scalar(
        select(Client)
        .where(
            Client.workspace_id == challenge.workspace_id,
            Client.email_normalized == challenge.email_normalized,
        )
        .with_for_update()
    )

    challenge.consumed_at = current
    _invalidate_sibling_challenges(session, challenge, current)

    if client is not None and client.status == ClientStatus.DISABLED:
        session.flush()
        return None

    if client is None:
        client = Client(
            id=uuid4(),
            workspace_id=challenge.workspace_id,
            email_normalized=challenge.email_normalized,
            email_display=challenge.email_normalized,
            status=ClientStatus.ACTIVE,
            last_access_at=current,
            created_at=current,
        )
        session.add(client)
        session.flush()
    else:
        client.last_access_at = current

    consent = Consent(
        id=uuid4(),
        workspace_id=challenge.workspace_id,
        client_id=client.id,
        policy_version=challenge.policy_version,
        text_hash=challenge.consent_text_hash,
        accepted_at=challenge.consent_accepted_at,
        created_at=current,
    )
    session.add(consent)

    session_id = uuid4()
    token = generate_session_token(challenge.workspace_id, session_id)
    absolute_expires_at = current + SESSION_ABSOLUTE_TTL
    idle_expires_at = min(current + SESSION_IDLE_TTL, absolute_expires_at)
    auth_session = SessionRecord(
        id=session_id,
        workspace_id=challenge.workspace_id,
        client_id=client.id,
        session_token_hash=hash_session_token(token),
        idle_expires_at=idle_expires_at,
        absolute_expires_at=absolute_expires_at,
        last_seen_at=current,
        created_at=current,
    )
    session.add(auth_session)
    session.add(
        AuditEvent(
            id=uuid4(),
            workspace_id=challenge.workspace_id,
            client_id=client.id,
            actor_type="client",
            event_type="login",
            target_type="session",
            target_id=session_id,
            occurred_at=current,
            request_id=request_id,
            metadata_jsonb={},
            created_at=current,
        )
    )
    session.flush()
    return AuthenticatedSession(
        token=token,
        workspace_id=challenge.workspace_id,
        client_id=client.id,
        session_id=session_id,
        idle_expires_at=idle_expires_at,
        absolute_expires_at=absolute_expires_at,
    )


def issue_login_challenge(
    session: Session,
    *,
    workspace_id: UUID,
    email: str,
    ip_address: str,
    consent: ConsentTicket,
    secret: str | bytes | bytearray | memoryview,
    now: datetime | None = None,
) -> IssuedChallenge:
    current = _now(now)
    if not isinstance(workspace_id, UUID) or not isinstance(consent, ConsentTicket):
        raise ChallengeUnavailable
    try:
        accepted_at = _utc(consent.accepted_at, "consent.accepted_at")
        expires_at = _utc(consent.expires_at, "consent.expires_at")
        valid_consent = (
            consent.version == "v1"
            and consent.workspace_id == workspace_id
            and accepted_at <= current < expires_at
            and isinstance(consent.policy_version, str)
            and bool(consent.policy_version.strip())
            and isinstance(consent.text_hash, str)
            and len(consent.text_hash) == 64
        )
    except (AttributeError, TypeError, ValueError):
        valid_consent = False
    if not valid_consent:
        raise ChallengeUnavailable

    try:
        email_normalized = normalize_email(email)
        ip_fingerprint = fingerprint_ip(secret, ip_address)
    except (TypeError, ValueError):
        raise ChallengeUnavailable from None

    window_start = current - RATE_WINDOW
    email_count = session.scalar(
        select(func.count(LoginChallenge.id)).where(
            LoginChallenge.workspace_id == workspace_id,
            LoginChallenge.email_normalized == email_normalized,
            LoginChallenge.created_at >= window_start,
        )
    )
    ip_count = session.scalar(
        select(func.count(LoginChallenge.id)).where(
            LoginChallenge.workspace_id == workspace_id,
            LoginChallenge.ip_fingerprint == ip_fingerprint,
            LoginChallenge.created_at >= window_start,
        )
    )
    if (email_count or 0) >= MAX_EMAIL_CHALLENGES or (ip_count or 0) >= MAX_IP_CHALLENGES:
        raise ChallengeUnavailable

    cooldown_active = session.scalar(
        select(LoginChallenge.id)
        .where(
            LoginChallenge.workspace_id == workspace_id,
            LoginChallenge.email_normalized == email_normalized,
            LoginChallenge.consumed_at.is_(None),
            LoginChallenge.invalidated_at.is_(None),
            LoginChallenge.resend_after > current,
        )
        .with_for_update()
    )
    if cooldown_active is not None:
        raise ChallengeUnavailable

    session.execute(
        update(LoginChallenge)
        .where(
            LoginChallenge.workspace_id == workspace_id,
            LoginChallenge.email_normalized == email_normalized,
            LoginChallenge.consumed_at.is_(None),
            LoginChallenge.invalidated_at.is_(None),
        )
        .values(invalidated_at=current)
    )

    challenge_id = uuid4()
    magic_token = generate_magic_token(workspace_id, challenge_id)
    otp = generate_otp()
    challenge_expires_at = current + CHALLENGE_TTL
    resend_after = current + RESEND_DELAY
    session.add(
        LoginChallenge(
            id=challenge_id,
            workspace_id=workspace_id,
            email_normalized=email_normalized,
            magic_token_hash=hash_magic_token(magic_token),
            code_hash=_challenge_otp_hash(secret, challenge_id, otp),
            expires_at=challenge_expires_at,
            attempt_count=0,
            resend_after=resend_after,
            ip_fingerprint=ip_fingerprint,
            policy_version=consent.policy_version,
            consent_text_hash=consent.text_hash,
            consent_accepted_at=accepted_at,
            created_at=current,
        )
    )
    session.flush()
    return IssuedChallenge(
        challenge_id=challenge_id,
        magic_token=magic_token,
        otp=otp,
        expires_at=challenge_expires_at,
        resend_after=resend_after,
    )


def authenticate_magic_token(
    session: Session,
    *,
    token: str,
    secret: str | bytes | bytearray | memoryview,
    request_id: str,
    now: datetime | None = None,
) -> AuthenticatedSession | None:
    _validate_request_id(request_id)
    current = _now(now)
    try:
        parsed = parse_magic_token(token)
    except (TypeError, ValueError):
        return None

    challenge = _load_challenge(session, parsed.workspace_id, parsed.challenge_id)
    if challenge is None or not _challenge_is_usable(challenge, current):
        return None
    try:
        candidate_hash = hash_magic_token(token)
    except (TypeError, ValueError):
        return None
    if not verify_digest(candidate_hash, challenge.magic_token_hash):
        return None
    return _complete_challenge(session, challenge, request_id, current)


def authenticate_otp(
    session: Session,
    *,
    workspace_id: UUID,
    challenge_id: UUID,
    code: str,
    secret: str | bytes | bytearray | memoryview,
    request_id: str,
    now: datetime | None = None,
) -> AuthenticatedSession | None:
    _validate_request_id(request_id)
    current = _now(now)
    if (
        not isinstance(workspace_id, UUID)
        or not isinstance(challenge_id, UUID)
        or not isinstance(code, str)
        or len(code) != 6
        or not code.isascii()
        or not code.isdecimal()
    ):
        return None

    challenge = _load_challenge(session, workspace_id, challenge_id)
    if challenge is None or not _challenge_is_usable(challenge, current):
        return None
    try:
        candidate_hash = _challenge_otp_hash(secret, challenge_id, code)
    except (TypeError, ValueError):
        return None
    if not verify_digest(candidate_hash, challenge.code_hash):
        challenge.attempt_count += 1
        if challenge.attempt_count >= MAX_OTP_ATTEMPTS:
            challenge.invalidated_at = current
        session.flush()
        return None
    return _complete_challenge(session, challenge, request_id, current)


def authenticate_session(
    session: Session, *, token: str, now: datetime | None = None
) -> SessionPrincipal | None:
    current = _now(now)
    try:
        parsed = parse_session_token(token)
    except (TypeError, ValueError):
        return None

    record = session.scalar(
        select(SessionRecord)
        .where(
            SessionRecord.workspace_id == parsed.workspace_id,
            SessionRecord.id == parsed.session_id,
        )
        .with_for_update()
    )
    if record is None:
        return None
    try:
        candidate_hash = hash_session_token(token)
    except (TypeError, ValueError):
        return None
    if not verify_digest(candidate_hash, record.session_token_hash):
        return None
    if (
        record.revoked_at is not None
        or record.idle_expires_at <= current
        or record.absolute_expires_at <= current
    ):
        return None

    record.last_seen_at = current
    record.idle_expires_at = min(current + SESSION_IDLE_TTL, record.absolute_expires_at)
    session.flush()
    return SessionPrincipal(
        workspace_id=record.workspace_id,
        client_id=record.client_id,
        session_id=record.id,
        idle_expires_at=record.idle_expires_at,
        absolute_expires_at=record.absolute_expires_at,
    )


def revoke_session(
    session: Session,
    *,
    token: str,
    request_id: str,
    now: datetime | None = None,
) -> bool:
    _validate_request_id(request_id)
    current = _now(now)
    try:
        parsed = parse_session_token(token)
    except (TypeError, ValueError):
        return False

    record = session.scalar(
        select(SessionRecord)
        .where(
            SessionRecord.workspace_id == parsed.workspace_id,
            SessionRecord.id == parsed.session_id,
        )
        .with_for_update()
    )
    if record is None:
        return False
    try:
        candidate_hash = hash_session_token(token)
    except (TypeError, ValueError):
        return False
    if not verify_digest(candidate_hash, record.session_token_hash):
        return False
    if (
        record.revoked_at is not None
        or record.idle_expires_at <= current
        or record.absolute_expires_at <= current
    ):
        return False

    record.revoked_at = current
    session.add(
        AuditEvent(
            id=uuid4(),
            workspace_id=record.workspace_id,
            client_id=record.client_id,
            actor_type="client",
            event_type="logout",
            target_type="session",
            target_id=record.id,
            occurred_at=current,
            request_id=request_id,
            metadata_jsonb={},
            created_at=current,
        )
    )
    session.flush()
    return True
