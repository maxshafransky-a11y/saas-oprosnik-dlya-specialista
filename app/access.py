from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Workspace, WorkspaceStatus
from app.preauth import ConsentTicket, issue_consent_ticket, verify_consent_ticket

CONSENT_COOKIE_NAME = "health_intake_consent"
CONSENT_POLICY_VERSION = "policy-v1"
CONSENT_TEXT = (
    "Я согласен(на) на обработку предоставленных мной данных о здоровье "
    "для подготовки персональных рекомендаций и консультации."
)
CONSENT_TEXT_HASH = hashlib.sha256(CONSENT_TEXT.encode("utf-8")).hexdigest()
CONSENT_TTL_SECONDS = 30 * 60


def find_active_workspace(session: Session, public_slug: str) -> Workspace | None:
    if (
        not isinstance(public_slug, str)
        or not public_slug
        or len(public_slug) > 128
        or "/" in public_slug
    ):
        return None
    return session.scalar(
        select(Workspace).where(
            Workspace.public_slug == public_slug,
            Workspace.status == WorkspaceStatus.ACTIVE,
        )
    )


def issue_workspace_consent(
    secret: str | bytes | bytearray | memoryview,
    workspace_id: UUID,
    *,
    accepted_at: datetime | None = None,
) -> str:
    timestamp = accepted_at or datetime.now(UTC)
    return issue_consent_ticket(
        secret,
        workspace_id,
        CONSENT_POLICY_VERSION,
        CONSENT_TEXT_HASH,
        timestamp,
    )


def verify_workspace_consent(
    secret: str | bytes | bytearray | memoryview,
    token: str,
    workspace_id: UUID,
    *,
    now: datetime | None = None,
) -> ConsentTicket:
    ticket = verify_consent_ticket(secret, token, now=now)
    if (
        ticket.workspace_id != workspace_id
        or ticket.policy_version != CONSENT_POLICY_VERSION
        or ticket.text_hash != CONSENT_TEXT_HASH
    ):
        raise ValueError("consent ticket is not valid for workspace")
    return ticket
