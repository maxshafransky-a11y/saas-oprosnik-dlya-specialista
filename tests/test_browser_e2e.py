from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.request import urlopen
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).parents[1]))

from playwright.sync_api import expect, sync_playwright
from sqlalchemy import create_engine
from sqlalchemy.orm import Session as DbSession
from sqlalchemy.pool import NullPool

from app.models import Client, Workspace
from app.models import Session as SessionRecord
from app.security import generate_session_token, hash_session_token

pytest_plugins = ("tests.db_test_support",)

ROOT = Path(__file__).parents[1]


def _seed_session(owner_url):
    workspace_id = uuid4()
    client_id = uuid4()
    session_id = uuid4()
    now = datetime.now(UTC)
    token = generate_session_token(workspace_id, session_id)
    engine = create_engine(owner_url, poolclass=NullPool)
    try:
        with DbSession(engine) as session, session.begin():
            session.add(
                Workspace(
                    id=workspace_id,
                    name="Browser test workspace",
                    public_slug=f"browser-{workspace_id.hex}",
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
    return token


def _free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def _wait_for_health(base_url: str, process: subprocess.Popen) -> None:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"uvicorn exited with code {process.returncode}")
        try:
            with urlopen(f"{base_url}/health", timeout=1) as response:
                if response.status == 200:
                    return
        except OSError:
            time.sleep(0.2)
    raise TimeoutError("uvicorn health endpoint did not start")


def test_browser_autosaves_radio_comment_and_survives_reload(migrated_database) -> None:
    owner_url, _ = migrated_database
    token = _seed_session(owner_url)
    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "app.main:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        cwd=ROOT,
        env=os.environ.copy(),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        _wait_for_health(base_url, process)
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            context = browser.new_context(viewport={"width": 390, "height": 844})
            context.add_cookies(
                [{"name": "health_intake_session", "value": token, "url": base_url}]
            )
            page = context.new_page()
            answer_requests = []
            page.on(
                "request",
                lambda request: (
                    answer_requests.append(request.post_data)
                    if "/answers/cravings" in request.url
                    else None
                ),
            )
            page.goto(f"{base_url}/q/nutrition")

            assert page.evaluate(
                "document.documentElement.scrollWidth <= document.documentElement.clientWidth"
            )
            cravings = page.locator('[data-question-key="cravings"]')
            with page.expect_response(
                lambda response: (
                    "/answers/cravings" in response.url
                    and response.request.method == "PUT"
                    and response.status == 200
                )
            ):
                cravings.locator('input[value="Нет"]').check()
            comment = cravings.locator("[data-comment-field]")
            with page.expect_response(
                lambda response: (
                    "/answers/cravings" in response.url
                    and response.request.method == "PUT"
                    and response.status == 200
                )
            ):
                comment.fill("Комментарий сохраняется даже для ответа «Нет»")
                comment.blur()

            expect(comment).to_have_value("Комментарий сохраняется даже для ответа «Нет»")
            expect(page.locator("[data-save-status]")).to_have_text("Сохранено")
            page.reload()
            expect(
                page.locator('[data-question-key="cravings"] input[value="Нет"]')
            ).to_be_checked()
            expect(
                page.locator('[data-question-key="cravings"] [data-comment-field]')
            ).to_have_value("Комментарий сохраняется даже для ответа «Нет»")
            browser.close()
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
