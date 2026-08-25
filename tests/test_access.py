from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).parents[1]))

import pytest

from app.access import (
    CONSENT_TEXT_HASH,
    issue_workspace_consent,
    verify_workspace_consent,
)

pytest_plugins = ("tests.db_test_support",)


def test_workspace_consent_is_signed_and_workspace_bound() -> None:
    workspace_id = uuid4()
    now = datetime.now(UTC) - timedelta(seconds=1)
    token = issue_workspace_consent("consent-secret", workspace_id, accepted_at=now)

    ticket = verify_workspace_consent(
        "consent-secret", token, workspace_id, now=now + timedelta(seconds=1)
    )

    assert ticket.workspace_id == workspace_id
    assert ticket.text_hash == CONSENT_TEXT_HASH
    with pytest.raises(ValueError, match="workspace"):
        verify_workspace_consent("consent-secret", token, uuid4(), now=now)


def test_workspace_consent_expires() -> None:
    workspace_id = uuid4()
    accepted_at = datetime.now(UTC) - timedelta(minutes=31)
    token = issue_workspace_consent("consent-secret", workspace_id, accepted_at=accepted_at)

    with pytest.raises(ValueError, match="expired"):
        verify_workspace_consent("consent-secret", token, workspace_id)
