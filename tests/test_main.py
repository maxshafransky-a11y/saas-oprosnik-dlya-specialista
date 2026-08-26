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


@pytest.fixture
def public_workspace(migrated_database):
    owner_url, _ = migrated_database
    workspace_id = uuid4()
    public_slug = f"public-{workspace_id.hex}"
    engine = create_engine(owner_url, poolclass=NullPool)
    try:
        with DbSession(engine) as session, session.begin():
            session.add(
                Workspace(
                    id=workspace_id,
                    name="Public test workspace",
                    public_slug=public_slug,
                )
            )
    finally:
        engine.dispose()

    get_engine.cache_clear()
    try:
        yield public_slug
    finally:
        get_engine.cache_clear()


@pytest.fixture
def public_client(public_workspace):
    yield TestClient(create_app()), public_workspace


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
    assert "connect-src 'self' https:" in response.headers["content-security-policy"]
    assert response.headers["permissions-policy"] == "camera=(), microphone=(), geolocation=()"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"


def test_magic_link_script_consumes_fragment_without_client_storage() -> None:
    script = (Path(__file__).parents[1] / "static" / "auth.js").read_text(encoding="utf-8")

    assert "window.location.hash" in script
    assert "window.history.replaceState" in script
    assert "form.submit()" in script
    assert "localStorage" not in script
    assert "sessionStorage" not in script


def test_questionnaire_script_uses_server_autosave_and_document_endpoints() -> None:
    script = (Path(__file__).parents[1] / "static" / "questionnaire.js").read_text(encoding="utf-8")

    assert 'method: "PUT"' in script
    assert "/answers/" in script
    assert "/documents/uploads" in script
    assert "localStorage" not in script
    assert "sessionStorage" not in script


def test_public_invite_requires_consent_and_opens_email_access(public_client) -> None:
    client, public_slug = public_client

    page = client.get(f"/i/{public_slug}")
    assert page.status_code == 200
    assert "Перед началом" in page.text
    assert 'name="consent"' in page.text

    rejected = client.post(f"/i/{public_slug}/consent", data={})
    assert rejected.status_code == 422
    assert "Поставьте галочку" in rejected.text

    accepted = client.post(
        f"/i/{public_slug}/consent",
        data={"consent": "on"},
        follow_redirects=False,
    )
    assert accepted.status_code == 303
    assert accepted.headers["location"] == f"/i/{public_slug}/access"
    assert "health_intake_consent=" in accepted.headers["set-cookie"]

    access_page = client.get(accepted.headers["location"])
    assert access_page.status_code == 200
    assert 'name="email"' in access_page.text


def test_email_access_requires_consent(public_client) -> None:
    client, public_slug = public_client

    response = client.get(f"/i/{public_slug}/access", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == f"/i/{public_slug}"


def test_email_access_issues_challenge_without_leaking_secrets(public_workspace) -> None:
    sent: list[dict[str, object]] = []

    def sender(settings, **message: object) -> None:
        sent.append(message)

    client = TestClient(create_app(email_sender=sender))
    client.post(f"/i/{public_workspace}/consent", data={"consent": "on"})

    response = client.post(
        f"/i/{public_workspace}/access",
        data={"email": "client@example.com"},
    )

    assert response.status_code == 202
    assert "Письмо отправлено" in response.text
    assert 'name="challenge_id"' in response.text
    assert sent[0]["recipient"] == "client@example.com"
    assert "magic_token" in sent[0]
    assert "otp" in sent[0]
    assert sent[0]["magic_token"] not in response.text
    assert sent[0]["otp"] not in response.text


def test_email_code_creates_session_and_opens_questionnaire(public_workspace) -> None:
    sent: list[dict[str, object]] = []

    def sender(settings, **message: object) -> None:
        sent.append(message)

    client = TestClient(create_app(email_sender=sender))
    client.post(f"/i/{public_workspace}/consent", data={"consent": "on"})
    challenge_page = client.post(
        f"/i/{public_workspace}/access",
        data={"email": "client@example.com"},
    )
    challenge_id = next(
        line.split('value="', 1)[1].split('"', 1)[0]
        for line in challenge_page.text.splitlines()
        if 'name="challenge_id"' in line
    )

    authenticated = client.post(
        "/auth/code",
        data={
            "public_slug": public_workspace,
            "challenge_id": challenge_id,
            "code": sent[0]["otp"],
        },
        headers={"origin": "http://testserver"},
        follow_redirects=False,
    )

    assert authenticated.status_code == 303
    assert authenticated.headers["location"] == "/questionnaire"
    assert "health_intake_session=" in authenticated.headers["set-cookie"]
    questionnaire = client.get(authenticated.headers["location"])
    assert questionnaire.status_code == 200
    assert "Личные данные" in questionnaire.text


def test_invalid_email_code_does_not_create_session(public_workspace) -> None:
    sent: list[dict[str, object]] = []

    def sender(settings, **message: object) -> None:
        sent.append(message)

    client = TestClient(create_app(email_sender=sender))
    client.post(f"/i/{public_workspace}/consent", data={"consent": "on"})
    challenge_page = client.post(
        f"/i/{public_workspace}/access",
        data={"email": "client@example.com"},
    )
    challenge_id = next(
        line.split('value="', 1)[1].split('"', 1)[0]
        for line in challenge_page.text.splitlines()
        if 'name="challenge_id"' in line
    )

    response = client.post(
        "/auth/code",
        data={
            "public_slug": public_workspace,
            "challenge_id": challenge_id,
            "code": "000000" if sent[0]["otp"] != "000000" else "999999",
        },
        headers={"origin": "http://testserver"},
    )

    assert response.status_code == 422
    assert "health_intake_session=" not in response.headers.get("set-cookie", "")


def test_magic_link_exchange_creates_session(public_workspace) -> None:
    sent: list[dict[str, object]] = []

    def sender(settings, **message: object) -> None:
        sent.append(message)

    client = TestClient(create_app(email_sender=sender))
    client.post(f"/i/{public_workspace}/consent", data={"consent": "on"})
    client.post(
        f"/i/{public_workspace}/access",
        data={"email": "client@example.com"},
    )

    landing = client.get("/auth/magic")
    assert landing.status_code == 200
    assert "/static/auth.js" in landing.text

    authenticated = client.post(
        "/auth/magic",
        data={"token": sent[0]["magic_token"]},
        headers={"origin": "http://testserver"},
        follow_redirects=False,
    )

    assert authenticated.status_code == 303
    assert authenticated.headers["location"] == "/questionnaire"
    assert "health_intake_session=" in authenticated.headers["set-cookie"]


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


def test_review_renders_current_answers_and_idempotency_key(authenticated_client) -> None:
    client, token = authenticated_client

    response = client.get("/review", cookies={SESSION_COOKIE_NAME: token})

    assert response.status_code == 200
    assert "Проверьте ответы" in response.text
    assert 'name="idempotency_key"' in response.text
    assert 'name="csrf_token"' in response.text


def test_submit_without_required_answers_returns_review_error(authenticated_client) -> None:
    client, token = authenticated_client
    session_id = parse_session_token(token).session_id
    csrf = build_csrf_token(
        session_id,
        "dev-only-app-secret-key-not-for-production-change-me",
    )

    response = client.post(
        "/submit",
        data={
            "csrf_token": csrf,
            "revision": "0",
            "idempotency_key": "a" * 32,
        },
        headers={"origin": "http://testserver"},
        cookies={SESSION_COOKIE_NAME: token},
    )

    assert response.status_code == 422
    assert "Заполните обязательные поля" in response.text
    assert "Ваше имя, фамилия" in response.text


def test_logout_revokes_session_and_clears_cookie(authenticated_client) -> None:
    client, token = authenticated_client
    session_id = parse_session_token(token).session_id
    csrf = build_csrf_token(
        session_id,
        "dev-only-app-secret-key-not-for-production-change-me",
    )

    response = client.post(
        "/auth/logout",
        data={"csrf_token": csrf},
        headers={"origin": "http://testserver"},
        cookies={SESSION_COOKIE_NAME: token},
    )

    assert response.status_code == 204
    assert SESSION_COOKIE_NAME in response.headers.get("set-cookie", "")
    assert client.get("/questionnaire", cookies={SESSION_COOKIE_NAME: token}).status_code == 401


def test_answer_autosave_returns_next_revision(authenticated_client) -> None:
    client, token = authenticated_client
    session_id = parse_session_token(token).session_id
    csrf = build_csrf_token(
        session_id,
        "dev-only-app-secret-key-not-for-production-change-me",
    )

    response = client.put(
        "/answers/full_name",
        json={"revision": 0, "answer": {"value": "Анна"}},
        headers={"origin": "http://testserver", "x-csrf-token": csrf},
        cookies={SESSION_COOKIE_NAME: token},
    )

    assert response.status_code == 200
    assert response.json() == {
        "question_key": "full_name",
        "revision": 1,
        "section_key": "personal_data",
    }


def test_answer_autosave_exposes_revision_conflict(authenticated_client) -> None:
    client, token = authenticated_client
    session_id = parse_session_token(token).session_id
    csrf = build_csrf_token(
        session_id,
        "dev-only-app-secret-key-not-for-production-change-me",
    )
    headers = {"origin": "http://testserver", "x-csrf-token": csrf}
    cookies = {SESSION_COOKIE_NAME: token}

    first = client.put(
        "/answers/full_name",
        json={"revision": 0, "answer": {"value": "Анна"}},
        headers=headers,
        cookies=cookies,
    )
    second = client.put(
        "/answers/full_name",
        json={"revision": 0, "answer": {"value": "Иван"}},
        headers=headers,
        cookies=cookies,
    )

    assert first.status_code == 200
    assert second.status_code == 409
    assert second.json()["current_revision"] == 1
