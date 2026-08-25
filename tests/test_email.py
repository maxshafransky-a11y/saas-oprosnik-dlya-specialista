from __future__ import annotations

import sys
from pathlib import Path
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).parents[1]))

import pytest
from pydantic import SecretStr

from app.config import Settings
from app.email import build_login_email, build_magic_url
from app.security import generate_magic_token


def _settings(**overrides: object) -> Settings:
    return Settings(
        database_url="postgresql+psycopg://runtime",
        database_owner_url="postgresql+psycopg://owner",
        smtp_from="intake@example.test",
        smtp_password=SecretStr("smtp-secret"),
        **overrides,
    )


def test_magic_url_keeps_token_in_fragment() -> None:
    token = generate_magic_token(uuid4(), uuid4())

    url = build_magic_url("https://intake.example.test", token)

    assert url.startswith("https://intake.example.test/auth/magic#token=")
    assert "?token=" not in url
    assert token not in url.split("#", 1)[0]
    assert token in url.split("#", 1)[1]


def test_login_email_contains_only_access_material() -> None:
    token = generate_magic_token(uuid4(), uuid4())

    message = build_login_email(
        _settings(public_base_url="https://intake.example.test"),
        recipient="Client@example.com",
        magic_token=token,
        otp="123456",
    )

    assert message["To"] == "client@example.com"
    assert "123456" in message.get_body("plain").get_content()
    assert "auth/magic#token=" in message.get_body("plain").get_content()
    assert "ответ" not in message.get_body("plain").get_content().lower()


def test_magic_url_rejects_query_or_invalid_token() -> None:
    with pytest.raises(ValueError):
        build_magic_url("https://intake.example.test?x=1", "invalid")
