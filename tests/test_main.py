from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).parents[1]))

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session as DbSession
from sqlalchemy.pool import NullPool

from app.db import get_engine
from app.main import create_app
from app.models import Client, Workspace
from app.models import Session as SessionRecord
from app.security import generate_session_token, hash_session_token, parse_session_token
from app.web_auth import SESSION_COOKIE_NAME, build_csrf_token, valid_csrf_token

pytest_plugins = ("tests.db_test_support",)


@pytest.fixture
def authenticated_client(migrated_database):
    owner_url, _ = migrated_database
    workspace_id = uuid4()
    client_id = uuid4()
    session_id = uuid4()
    now = datetime(2026, 8, 25, 12, 0, tzinfo=UTC)
    token = generate_session_token(workspace_id, session_id)
    engine = create_engine(owner_url, poolclass=NullPool)
    try:
        with DbSession(engine) as session, session.begin():
            session.add(
                Workspace(
                    id=workspace_id,
                    name="Main test workspace",
                    public_slug=f"main-{workspace_id.hex}",
                )
            )
            session.flush()
            session.add(
                Client(
                    id=client_id,
                    workspace_id=workspace_id,
                    email_normalized=f"{client_id.hex}@example.test",
                    email_display=f"{client_id.hex}@example.test",
                )
            )
            session.add(
                SessionRecord(
                    id=session_id,
                    workspace_id=workspace_id,
                    client_id=client_id,
                    session_token_hash=hash_session_token(token),
                    idle_expires_at=now + timedelta(days=14),
                    absolute_expires_at=now + timedelta(days=30),
                    last_seen_at=now,
                    created_at=now,
                )
            )
    finally:
        engine.dispose()

    get_engine.cache_clear()
    try:
        yield TestClient(create_app()), token
    finally:
        get_engine.cache_clear()


def test_health_is_available_without_openapi_surface() -> None:
    client = TestClient(create_app())

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert client.get("/openapi.json").status_code == 404


def test_csrf_token_is_bound_to_session() -> None:
    session_id = uuid4()
    other_session_id = uuid4()
    token = build_csrf_token(session_id, "test-csrf-secret")

    assert valid_csrf_token(session_id, token, "test-csrf-secret")
    assert not valid_csrf_token(other_session_id, token, "test-csrf-secret")
    assert not valid_csrf_token(session_id, token[:-1], "test-csrf-secret")


def test_security_headers_are_present_on_html_and_json_responses() -> None:
    client = TestClient(create_app())

    response = client.get("/health")

    assert response.headers["content-security-policy"].startswith("default-src 'self'")
    assert response.headers["permissions-policy"] == "camera=(), microphone=(), geolocation=()"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"


def test_questionnaire_route_renders_canonical_section_and_static_css() -> None:
    client = TestClient(create_app())

    response = client.get("/questionnaire?section=nutrition")

    assert response.status_code == 401


def test_authenticated_questionnaire_route_loads_real_state(authenticated_client) -> None:
    client, token = authenticated_client

    response = client.get(
        "/questionnaire?section=nutrition",
        cookies={SESSION_COOKIE_NAME: token},
    )

    assert response.status_code == 200
    assert "Питание" in response.text
    assert 'lang="ru"' in response.text
    assert "/static/app.css" in response.text
    assert client.get("/static/app.css").status_code == 200


def test_authenticated_questionnaire_post_saves_and_redirects(authenticated_client) -> None:
    client, token = authenticated_client
    csrf = build_csrf_token(
        parse_session_token(token).session_id,
        "dev-only-app-secret-key-not-for-production-change-me",
    )

    response = client.post(
        "/q/nutrition",
        data={
            "csrf_token": csrf,
            "revision": "0",
            "section_key": "nutrition",
            "meal_day": "Завтрак в 9:00, обед в 14:00, ужин в 19:00",
            "cravings": "Нет",
            "cravings__comment": "Даже если нет, оставляю пояснение",
            "overeating": "Нет",
            "overeating__comment": "",
            "liked_foods": "Рыба и овощи",
            "avoided_foods": "Не избегаю",
            "diet_history": "Нет",
            "diet_history__comment": "",
        },
        headers={"origin": "http://testserver"},
        cookies={SESSION_COOKIE_NAME: token},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/q/gi_wellbeing"

    resumed = client.get(
        "/q/nutrition",
        cookies={SESSION_COOKIE_NAME: token},
    )
    assert resumed.status_code == 200
    assert "Даже если нет, оставляю пояснение" in resumed.text
    assert 'name="revision" value="1"' in resumed.text


def test_questionnaire_post_rejects_invalid_csrf(authenticated_client) -> None:
    client, token = authenticated_client

    response = client.post(
        "/q/nutrition",
        data={"revision": "0", "section_key": "nutrition"},
        headers={"origin": "http://testserver"},
        cookies={SESSION_COOKIE_NAME: token},
    )

    assert response.status_code == 403


def test_questionnaire_route_rejects_unknown_section(authenticated_client) -> None:
    client, token = authenticated_client

    response = client.get(
        "/q/unknown",
        cookies={SESSION_COOKIE_NAME: token},
    )

    assert response.status_code == 404
