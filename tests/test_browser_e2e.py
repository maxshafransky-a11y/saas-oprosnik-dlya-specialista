from __future__ import annotations

import os
import re
import socket
import socketserver
import subprocess
import sys
import threading
import time
from contextlib import suppress
from email import policy
from email.parser import BytesParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from queue import Empty, Queue
from urllib.parse import unquote, urlsplit
from urllib.request import urlopen
from uuid import UUID, uuid4

sys.path.insert(0, str(Path(__file__).parents[1]))

from playwright.sync_api import expect, sync_playwright
from sqlalchemy import create_engine
from sqlalchemy.orm import Session as DbSession
from sqlalchemy.pool import NullPool

from app.models import Workspace
from app.scan_worker import run_scan_once
from app.storage import S3Storage

pytest_plugins = ("tests.db_test_support",)

ROOT = Path(__file__).parents[1]
VIEWPORT = {"width": 390, "height": 844}
PDF_BYTES = b"%PDF-1.7\nhealth intake browser e2e\n"
SECTION_KEYS = (
    "personal_data",
    "lifestyle",
    "goals_motivation",
    "health_history",
    "nutrition",
    "gi_wellbeing",
    "sleep_stress",
    "gender_health",
    "activity_habits",
    "readiness_final",
)
SECTION_TITLES = (
    "Личные данные",
    "Образ жизни",
    "Цели и мотивация",
    "История здоровья",
    "Питание",
    "ЖКТ и самочувствие",
    "Сон и стресс",
    "Гендерное здоровье",
    "Активность и привычки",
    "Готовность и детали",
)


class _FakeObjectStore:
    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}


class _FakeS3Server(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


class _FakeS3Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _read_body(self) -> bytes:
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            body = bytearray()
            while True:
                size_line = self.rfile.readline()
                if not size_line:
                    raise ValueError("chunked request ended before the size line")
                size = int(size_line.split(b";", 1)[0], 16)
                if size == 0:
                    while self.rfile.readline() not in (b"\r\n", b"\n", b""):
                        pass
                    return bytes(body)
                body.extend(self.rfile.read(size))
                if self.rfile.read(2) != b"\r\n":
                    raise ValueError("invalid chunk terminator")
        content_length = self.headers.get("Content-Length")
        if content_length is None:
            raise ValueError("request has neither chunked encoding nor content length")
        return self.rfile.read(int(content_length))

    def _object_key(self) -> str:
        path = unquote(urlsplit(self.path).path)
        prefix = f"/{self.server.bucket}/"
        if path.startswith(prefix):
            return path[len(prefix) :]
        return path.lstrip("/")

    def _respond(
        self,
        status: int,
        body: bytes = b"",
        content_type: str = "text/plain",
        *,
        write_body: bool = True,
    ) -> None:
        self.send_response(status)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, PUT, HEAD, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.send_header("Access-Control-Max-Age", "600")
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body and write_body:
            self.wfile.write(body)

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._respond(204)

    def do_PUT(self) -> None:  # noqa: N802
        try:
            body = self._read_body()
        except (TypeError, ValueError):
            self._respond(400)
            return
        self.server.store.objects[self._object_key()] = body
        self._respond(200)

    def do_HEAD(self) -> None:  # noqa: N802
        body = self.server.store.objects.get(self._object_key())
        self._respond(200 if body is not None else 404, body or b"", write_body=False)

    def do_GET(self) -> None:  # noqa: N802
        body = self.server.store.objects.get(self._object_key())
        if body is None:
            self._respond(404)
            return
        self._respond(200, body, "application/pdf")

    def do_DELETE(self) -> None:  # noqa: N802
        self.server.store.objects.pop(self._object_key(), None)
        self._respond(204)

    def log_message(self, format: str, *args: object) -> None:
        return


class _SMTPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, server_address, handler_class) -> None:
        super().__init__(server_address, handler_class)
        self.messages: Queue[bytes] = Queue()
        self.commands: Queue[str] = Queue()


class _SMTPHandler(socketserver.StreamRequestHandler):
    def _write(self, response: bytes) -> None:
        self.wfile.write(response)
        self.wfile.flush()

    def handle(self) -> None:
        self._write(b"220 browser-e2e.test\r\n")
        while True:
            line = self.rfile.readline()
            if not line:
                return
            command = line.strip().upper()
            self.server.commands.put(command.decode("ascii", "replace"))
            if command.startswith((b"EHLO", b"HELO")):
                self._write(b"250-browser-e2e.test\r\n250 OK\r\n")
            elif command == b"DATA":
                self._write(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                message = bytearray()
                while True:
                    data_line = self.rfile.readline()
                    if not data_line or data_line == b".\r\n":
                        break
                    if data_line.startswith(b".."):
                        data_line = data_line[1:]
                    message.extend(data_line)
                self.server.messages.put(bytes(message))
                self._write(b"250 2.0.0 queued\r\n")
            elif command.startswith((b"MAIL", b"RCPT", b"RSET", b"NOOP")):
                self._write(b"250 OK\r\n")
            elif command == b"QUIT":
                self._write(b"221 Bye\r\n")
                return
            else:
                self._write(b"502 Command not implemented\r\n")


class _CleanAntivirus:
    def scan(self, chunks) -> bool:
        if sum(len(chunk) for chunk in chunks) == 0:
            raise AssertionError("scanner received an empty object")
        return True


def _seed_workspace(owner_url) -> tuple[str, UUID]:
    workspace_id = uuid4()
    public_slug = f"browser-{workspace_id.hex}"
    engine = create_engine(owner_url, poolclass=NullPool)
    try:
        with DbSession(engine) as session, session.begin():
            session.add(
                Workspace(
                    id=workspace_id,
                    name="Browser test workspace",
                    public_slug=public_slug,
                )
            )
    finally:
        engine.dispose()
    return public_slug, workspace_id


def _free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def _serve(server) -> threading.Thread:
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return thread


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


def _capture_credentials(server: _SMTPServer) -> tuple[str, str]:
    try:
        raw_message = server.messages.get(timeout=10)
    except Empty as error:
        commands = []
        while True:
            try:
                commands.append(server.commands.get_nowait())
            except Empty:
                break
        raise AssertionError(f"login email was not captured; SMTP commands: {commands}") from error
    message = BytesParser(policy=policy.default).parsebytes(raw_message)
    body_part = message.get_body(preferencelist=("plain",))
    if body_part is None:
        raise AssertionError("login email has no plain-text body")
    body = body_part.get_content()
    otp_match = re.search(r"код: (\d{6})", body)
    magic_match = re.search(r"https?://\S+/auth/magic#token=\S+", body)
    if otp_match is None or magic_match is None:
        raise AssertionError("login email does not contain OTP and magic link")
    return otp_match.group(1), magic_match.group(0)


def _assert_mobile(page) -> None:
    assert page.evaluate(
        "document.documentElement.scrollWidth <= document.documentElement.clientWidth"
    )
    expect(page.locator("main")).to_be_visible()


def _answer_section(page, base_url: str, section_key: str, next_section: str | None) -> None:
    page.goto(f"{base_url}/q/{section_key}")
    _assert_mobile(page)
    cards = page.locator("[data-question-key]")
    for index in range(cards.count()):
        card = cards.nth(index)
        key = card.get_attribute("data-question-key")
        question_type = card.get_attribute("data-question-type")
        assert key and question_type
        if question_type == "document_upload":
            continue
        field = card.locator("[data-answer-field]").first
        if question_type in {"text", "date_or_age"}:
            field.fill("38 лет" if question_type == "date_or_age" else f"Ответ {key}")
        elif question_type == "number":
            field.fill("170" if key == "height_cm" else "70" if key == "weight_kg" else "1")
        elif question_type == "textarea":
            field.fill(f"Ответ {key}")
        elif question_type == "single_choice":
            choices = card.locator('input[type="radio"]')
            choice = choices.first
            if key == "cravings":
                with page.expect_response(
                    lambda response: (
                        "/answers/cravings" in response.url
                        and response.request.method == "PUT"
                        and response.status == 200
                    )
                ):
                    choice.check()
            else:
                choice.check()
            assert card.locator('input[type="radio"]:checked').count() == 1
        elif question_type == "multi_choice":
            choices = card.locator('input[type="checkbox"]')
            choices.nth(0).check()
            if choices.count() > 1:
                choices.nth(1).check()
        elif question_type == "scale":
            minimum = int(field.get_attribute("min") or "0")
            maximum = int(field.get_attribute("max") or "0")
            field.evaluate(
                """
                (element, value) => {
                  element.value = value;
                  element.dispatchEvent(new Event('input', {bubbles: true}));
                  element.dispatchEvent(new Event('change', {bubbles: true}));
                }
                """,
                str((minimum + maximum) // 2),
            )
        else:
            raise AssertionError(f"uncovered question type: {question_type}")

        comment = card.locator("[data-comment-field]")
        if comment.count():
            value = "Комментарий для ответа «Нет»" if key == "cravings" else f"Пояснение {key}"
            if key == "cravings":
                with page.expect_response(
                    lambda response: (
                        "/answers/cravings" in response.url
                        and response.request.method == "PUT"
                        and response.status == 200
                    )
                ):
                    comment.fill(value)
                    comment.blur()
            else:
                comment.fill(value)
                comment.blur()

    if section_key == "gender_health":
        expect(page.locator('[data-question-key="female_health"]')).to_be_visible()
        assert page.locator('[data-question-key="male_health"]').count() == 0

    destination = f"{base_url}/review" if next_section is None else f"{base_url}/q/{next_section}"
    with page.expect_navigation():
        page.get_by_role(
            "button", name=re.compile("Сохранить и продолжить|Проверить ответы")
        ).click()
    assert page.url == destination

    if section_key == "nutrition":
        page.goto(f"{base_url}/q/nutrition")
        _assert_mobile(page)
        cravings = page.locator('[data-question-key="cravings"]')
        expect(cravings.locator('input[value="Нет"]')).to_be_checked()
        expect(cravings.locator("[data-comment-field]")).to_have_value(
            "Комментарий для ответа «Нет»"
        )
        with page.expect_navigation():
            page.get_by_role("button", name="Сохранить и продолжить").click()
        assert page.url == destination


def test_browser_covers_full_client_journey_and_mobile_ui(migrated_database) -> None:
    owner_url, runtime_url = migrated_database
    public_slug, workspace_id = _seed_workspace(owner_url)

    object_store = _FakeObjectStore()
    storage_server = _FakeS3Server(("127.0.0.1", 0), _FakeS3Handler)
    storage_server.bucket = "e2e-bucket"
    storage_server.store = object_store
    storage_thread = _serve(storage_server)
    storage_url = f"http://127.0.0.1:{storage_server.server_address[1]}"

    smtp_server = _SMTPServer(("127.0.0.1", 0), _SMTPHandler)
    smtp_thread = _serve(smtp_server)

    app_port = _free_port()
    base_url = f"http://127.0.0.1:{app_port}"
    environment = os.environ.copy()
    environment.update(
        {
            "APP_ENV": "test",
            "APP_SECRET_KEY": "browser-e2e-secret-" + "x" * 48,
            "DATABASE_URL": runtime_url.render_as_string(hide_password=False),
            "DATABASE_OWNER_URL": owner_url.render_as_string(hide_password=False),
            "PUBLIC_BASE_URL": base_url,
            "SMTP_HOST": "127.0.0.1",
            "SMTP_PORT": str(smtp_server.server_address[1]),
            "SMTP_USERNAME": "",
            "SMTP_PASSWORD": "",
            "SMTP_FROM": "intake@example.test",
            "SMTP_STARTTLS": "false",
            "STORAGE_BUCKET": storage_server.bucket,
            "STORAGE_ENDPOINT_URL": storage_url,
            "STORAGE_REGION": "us-east-1",
            "STORAGE_ACCESS_KEY_ID": "e2e-access",
            "STORAGE_SECRET_ACCESS_KEY": "e2e-secret",
        }
    )
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "app.main:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(app_port),
        ],
        cwd=ROOT,
        env=environment,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    browser = None
    try:
        _wait_for_health(base_url, process)
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            context = browser.new_context(
                viewport=VIEWPORT,
                extra_http_headers={"Origin": base_url},
                # The local fake S3 endpoint is HTTP-only; production storage is HTTPS.
                bypass_csp=True,
            )
            page = context.new_page()

            page.goto(f"{base_url}/i/{public_slug}")
            expect(page.get_by_role("heading", name="Перед началом")).to_be_visible()
            _assert_mobile(page)
            page.get_by_role("checkbox", name=re.compile("согласен")).check()
            with (
                page.expect_response(
                    lambda response: (
                        response.url.endswith(f"/i/{public_slug}/consent")
                        and response.request.method == "POST"
                    )
                ) as consent_response,
                page.expect_navigation(),
            ):
                page.get_by_role("button", name=re.compile("^Продолжить")).click()
            assert consent_response.value.status == 303, (
                f"consent response {consent_response.value.status}: "
                f"{consent_response.value.request.all_headers()}"
            )
            page.wait_for_load_state()
            assert page.url == f"{base_url}/i/{public_slug}/access"
            _assert_mobile(page)

            page.get_by_label("Email", exact=True).fill("otp-client@example.com")
            with page.expect_response(
                lambda response: (
                    response.url.endswith(f"/i/{public_slug}/access")
                    and response.request.method == "POST"
                    and response.status == 202
                )
            ):
                page.get_by_role("button", name=re.compile("Получить ссылку")).click()
            otp, _ = _capture_credentials(smtp_server)
            expect(page.get_by_role("heading", name="Проверьте почту")).to_be_visible()
            page.get_by_label("Код из письма", exact=True).fill(otp)
            with page.expect_navigation():
                page.get_by_role("button", name=re.compile("Войти по коду")).click()
            assert page.url == f"{base_url}/questionnaire"
            _assert_mobile(page)

            for section_key, title in zip(SECTION_KEYS, SECTION_TITLES, strict=True):
                link = page.get_by_role("link", name=title, exact=True)
                expect(link).to_have_count(1)
                with page.expect_navigation():
                    link.click()
                assert page.url == f"{base_url}/questionnaire?section={section_key}"
                expect(page.get_by_role("heading", name=title, exact=True)).to_be_visible()
                _assert_mobile(page)

            for index, section_key in enumerate(SECTION_KEYS):
                next_section = SECTION_KEYS[index + 1] if index + 1 < len(SECTION_KEYS) else None
                _answer_section(page, base_url, section_key, next_section)

            page.goto(f"{base_url}/q/readiness_final")
            _assert_mobile(page)
            file_input = page.locator('[data-question-key="documents"] input[type="file"]')
            with page.expect_response(
                lambda response: (
                    response.url.endswith("/documents/uploads")
                    and response.request.method == "POST"
                    and response.status == 201
                )
            ):
                file_input.set_input_files(
                    {
                        "name": "analysis.pdf",
                        "mimeType": "application/pdf",
                        "buffer": PDF_BYTES,
                    }
                )
            expect(
                page.get_by_text("Файл добавлен и отправлен на проверку", exact=True)
            ).to_be_visible(timeout=10000)
            document_line = page.locator('[data-filename="analysis.pdf"]')
            expect(document_line).to_have_attribute("data-document-status", "quarantined")

            scanner_storage = S3Storage(
                storage_server.bucket,
                endpoint_url=storage_url,
                region_name="us-east-1",
                access_key_id="e2e-access",
                secret_access_key="e2e-secret",
            )
            scan_results = run_scan_once(
                workspace_id,
                storage=scanner_storage,
                antivirus=_CleanAntivirus(),
            )
            assert len(scan_results) == 1
            assert PDF_BYTES in object_store.objects.values()
            expect(document_line).to_have_attribute("data-document-status", "ready", timeout=10000)
            download_button = document_line.get_by_role("button", name="Скачать")
            delete_button = document_line.get_by_role("button", name="Удалить")
            expect(download_button).to_be_visible()
            expect(delete_button).to_be_visible()

            with page.expect_response(
                lambda response: (
                    "/documents/" in response.url
                    and response.request.method == "POST"
                    and response.url.endswith("/download")
                    and response.status == 200
                )
            ):
                download_button.click()
            page.goto(f"{base_url}/q/readiness_final")
            document_line = page.locator('[data-filename="analysis.pdf"]')
            delete_button = document_line.get_by_role("button", name="Удалить")
            with page.expect_response(
                lambda response: (
                    "/documents/" in response.url
                    and response.request.method == "DELETE"
                    and response.status == 200
                )
            ):
                delete_button.click()
            expect(document_line).to_have_attribute("data-document-status", "deleted")
            expect(document_line).to_have_text(re.compile("Файл удалён"))

            with page.expect_navigation():
                page.get_by_role("button", name="Проверить ответы").click()
            assert page.url == f"{base_url}/review"
            expect(page.get_by_role("heading", name="Проверьте ответы")).to_be_visible()
            expect(
                page.get_by_text("Пояснение: Комментарий для ответа «Нет»", exact=True)
            ).to_be_visible()
            _assert_mobile(page)

            with page.expect_navigation():
                page.get_by_role("link", name="Вернуться к ответам", exact=True).click()
            assert page.url == f"{base_url}/questionnaire"
            _assert_mobile(page)
            page.goto(f"{base_url}/review")
            with page.expect_navigation():
                page.get_by_role("button", name="Отправить анкету").click()
            assert page.url == f"{base_url}/complete"
            expect(page.get_by_role("heading", name="Анкета отправлена")).to_be_visible()
            _assert_mobile(page)

            with page.expect_navigation():
                page.get_by_role("button", name="Изменить ответы").click()
            assert page.url == f"{base_url}/questionnaire"
            expect(page.get_by_role("heading", name="Готовность и детали")).to_be_visible()
            csrf_token = page.locator('input[name="csrf_token"]').input_value()
            logout = context.request.post(
                f"{base_url}/auth/logout",
                form={"csrf_token": csrf_token},
                headers={"Origin": base_url},
            )
            assert logout.status == 204
            unauthorized = page.goto(f"{base_url}/questionnaire")
            assert unauthorized is not None and unauthorized.status == 401

            magic_context = browser.new_context(
                viewport=VIEWPORT,
                extra_http_headers={"Origin": base_url},
            )
            magic_page = magic_context.new_page()
            magic_page.goto(f"{base_url}/i/{public_slug}")
            magic_page.get_by_role("checkbox", name=re.compile("согласен")).check()
            with magic_page.expect_navigation():
                magic_page.get_by_role("button", name=re.compile("^Продолжить")).click()
                magic_page.get_by_label("Email", exact=True).fill("magic-client@example.com")
            with magic_page.expect_response(
                lambda response: (
                    response.url.endswith(f"/i/{public_slug}/access")
                    and response.request.method == "POST"
                    and response.status == 202
                )
            ):
                magic_page.get_by_role("button", name=re.compile("Получить ссылку")).click()
            _, magic_url = _capture_credentials(smtp_server)
            magic_page.goto(magic_url)
            magic_page.wait_for_url(f"{base_url}/questionnaire")
            _assert_mobile(magic_page)
            magic_context.close()
    finally:
        with suppress(Exception):
            if browser is not None:
                browser.close()
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        smtp_server.shutdown()
        smtp_server.server_close()
        smtp_thread.join(timeout=5)
        storage_server.shutdown()
        storage_server.server_close()
        storage_thread.join(timeout=5)
