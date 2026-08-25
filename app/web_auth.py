from __future__ import annotations

import hashlib
import hmac
from collections.abc import Iterator
from dataclasses import dataclass
from uuid import UUID

from fastapi import HTTPException, Request
from sqlalchemy.orm import Session

from app.auth_service import SessionPrincipal, authenticate_session
from app.db import session_scope
from app.security import parse_session_token

SESSION_COOKIE_NAME = "health_intake_session"
_CSRF_DOMAIN = b"health-intake:csrf:v1"


@dataclass(frozen=True, slots=True)
class AuthenticatedRequest:
    session: Session
    principal: SessionPrincipal


def build_csrf_token(
    session_id: UUID,
    secret: str | bytes | bytearray | memoryview,
) -> str:
    if not isinstance(session_id, UUID):
        raise TypeError("session_id must be a UUID")
    if isinstance(secret, str):
        secret = secret.encode("utf-8")
    elif isinstance(secret, (bytearray, memoryview)):
        secret = bytes(secret)
    if not isinstance(secret, bytes) or not secret:
        raise ValueError("CSRF secret must be non-empty bytes")
    return hmac.new(secret, _CSRF_DOMAIN + b"\0" + session_id.bytes, hashlib.sha256).hexdigest()


def valid_csrf_token(
    session_id: UUID,
    candidate: str,
    secret: str | bytes | bytearray | memoryview,
) -> bool:
    if not isinstance(candidate, str):
        return False
    try:
        expected = build_csrf_token(session_id, secret)
    except (TypeError, ValueError):
        return False
    return hmac.compare_digest(candidate, expected)


def _authentication_required() -> HTTPException:
    return HTTPException(status_code=401, detail="authentication required")


def require_authenticated_session(request: Request) -> Iterator[AuthenticatedRequest]:
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        raise _authentication_required()

    try:
        parsed = parse_session_token(token)
    except (TypeError, ValueError):
        raise _authentication_required() from None

    with session_scope(parsed.workspace_id) as session:
        principal = authenticate_session(session, token=token)
        if principal is None:
            raise _authentication_required()
        yield AuthenticatedRequest(session=session, principal=principal)
