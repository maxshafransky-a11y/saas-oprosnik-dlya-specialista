from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1]))

from fastapi.testclient import TestClient

from app.main import create_app


def test_health_is_available_without_openapi_surface() -> None:
    client = TestClient(create_app())

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert client.get("/openapi.json").status_code == 404


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

    assert response.status_code == 200
    assert "Питание" in response.text
    assert 'lang="ru"' in response.text
    assert "/static/app.css" in response.text
    assert client.get("/static/app.css").status_code == 200


def test_questionnaire_route_rejects_unknown_section() -> None:
    response = TestClient(create_app()).get("/questionnaire?section=unknown")

    assert response.status_code == 404
