from __future__ import annotations

import os
import re
import sys
from pathlib import Path

from playwright.sync_api import APIRequestContext, expect, sync_playwright

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT))

from tests.test_browser_e2e import PDF_BYTES, SECTION_KEYS, _answer_section  # noqa: E402

BASE_URL = os.environ.get("SCREENSHOT_BASE_URL", "http://127.0.0.1:8000")
MAILPIT_URL = os.environ.get("SCREENSHOT_MAILPIT_URL", "http://127.0.0.1:8025")
MINIO_URL = os.environ.get("SCREENSHOT_MINIO_URL", "http://127.0.0.1:9001")
MINIO_BUCKET = os.environ.get("STORAGE_BUCKET", "health-intake-local")
MINIO_USER = os.environ.get("MINIO_ROOT_USER", "health_intake_local")
MINIO_PASSWORD = os.environ.get(
    "MINIO_ROOT_PASSWORD", "health_intake_local_secret_123456789"
)
OUTPUT_DIR = ROOT / "docs" / "screenshots"


def save_screenshot(page, filename: str) -> None:
    path = OUTPUT_DIR / filename
    page.screenshot(path=str(path), full_page=True)
    assert path.is_file() and path.stat().st_size > 0


def latest_mail(api: APIRequestContext, recipient: str) -> dict:
    response = api.get(f"{MAILPIT_URL}/api/v1/messages")
    assert response.ok, response.text()
    messages = response.json().get("messages", [])
    matches = [
        message
        for message in messages
        if any(item.get("Address") == recipient for item in message.get("To", []))
    ]
    return max(matches, key=lambda item: item.get("Created", ""), default={})


def mail_detail(api: APIRequestContext, message_id: str) -> dict:
    response = api.get(f"{MAILPIT_URL}/api/v1/message/{message_id}")
    assert response.ok, response.text()
    return response.json()


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    recipient = f"screenshots-{os.urandom(4).hex()}@example.com"

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        api = playwright.request.new_context()
        desktop = browser.new_context(viewport={"width": 1440, "height": 1000}, locale="ru-RU")
        page = desktop.new_page()

        try:
            page.goto(f"{BASE_URL}/i/local-test", wait_until="networkidle")
            expect(page.get_by_role("heading", name="Перед началом")).to_be_visible()
            save_screenshot(page, "01-consent.png")

            page.get_by_role("checkbox", name=re.compile("согласен")).check()
            with page.expect_navigation():
                page.get_by_role("button", name=re.compile("^Продолжить")).click()
            expect(page.get_by_role("heading", name="Войти в анкету")).to_be_visible()
            save_screenshot(page, "02-email-access.png")

            page.get_by_label("Email", exact=True).fill(recipient)
            with page.expect_response(
                lambda response: (
                    response.url.endswith("/i/local-test/access")
                    and response.request.method == "POST"
                    and response.status == 202
                )
            ):
                page.get_by_role("button", name=re.compile("Получить ссылку")).click()
            expect(page.get_by_role("heading", name="Проверьте почту")).to_be_visible()

            mailpit_page = desktop.new_page()
            mailpit_page.goto(MAILPIT_URL, wait_until="networkidle")
            expect(mailpit_page.locator("body")).to_contain_text(recipient, timeout=15000)
            message = latest_mail(api, recipient)
            assert message, "Mailpit did not return the newly sent message"
            message_id = message["ID"]
            detail = mail_detail(api, message_id)

            mailpit_page.goto(f"{MAILPIT_URL}/view/{message_id}", wait_until="networkidle")
            expect(mailpit_page.locator("body")).to_contain_text(recipient)
            mailpit_page.add_style_tag(
                content=(
                    ".row.flex-fill > .d-none.d-xl-flex { display: none !important; }"
                    ".row.flex-fill > .col-xl-9 { width: 100% !important; }"
                )
            )
            save_screenshot(mailpit_page, "03-mailpit-message.png")

            body = detail.get("Text", "")
            code_match = re.search(r"код: (\d{6})", body)
            magic_match = re.search(r"https?://\S+/auth/magic#token=\S+", body)
            assert code_match and magic_match, "Mailpit message has no OTP or magic link"

            page.goto(magic_match.group(0), wait_until="networkidle")
            page.wait_for_url(re.compile(rf"{re.escape(BASE_URL)}/questionnaire(?:\?.*)?$"))
            expect(page.get_by_role("heading", name="Личные данные", exact=True)).to_be_visible()
            save_screenshot(page, "04-questionnaire-start.png")

            for index, section_key in enumerate(SECTION_KEYS):
                next_section = SECTION_KEYS[index + 1] if index + 1 < len(SECTION_KEYS) else None
                _answer_section(page, BASE_URL, section_key, next_section)

            page.goto(f"{BASE_URL}/q/nutrition", wait_until="networkidle")
            cravings = page.locator('[data-question-key="cravings"]')
            expect(cravings).to_be_visible()
            expect(cravings.locator('input[type="radio"]:checked')).to_have_count(1)
            expect(cravings.locator("[data-comment-field]")).not_to_have_value("")
            save_screenshot(page, "05-choice-comment.png")

            mobile = browser.new_context(
                viewport={"width": 390, "height": 844},
                locale="ru-RU",
                storage_state=desktop.storage_state(),
            )
            mobile_page = mobile.new_page()
            mobile_page.goto(f"{BASE_URL}/q/nutrition", wait_until="networkidle")
            expect(mobile_page.get_by_role("heading", name="Питание", exact=True)).to_be_visible()
            assert mobile_page.evaluate(
                "document.documentElement.scrollWidth <= document.documentElement.clientWidth"
            )
            save_screenshot(mobile_page, "06-mobile-questionnaire.png")
            mobile.close()

            page.goto(f"{BASE_URL}/q/readiness_final", wait_until="networkidle")
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
            expect(document_line).to_have_attribute("data-document-status", "ready", timeout=15000)
            save_screenshot(page, "07-file-upload.png")

            minio_page = desktop.new_page()
            minio_page.goto(f"{MINIO_URL}/login", wait_until="networkidle")
            minio_page.locator("#accessKey").fill(MINIO_USER)
            minio_page.locator("#secretKey").fill(MINIO_PASSWORD)
            with minio_page.expect_response(lambda response: "/api/v1/login" in response.url):
                minio_page.get_by_role("button", name="Login").click()
            minio_page.wait_for_url(re.compile(r"/browser/"))
            minio_page.goto(f"{MINIO_URL}/browser/{MINIO_BUCKET}", wait_until="networkidle")
            expect(minio_page.locator("body")).to_contain_text(MINIO_BUCKET)
            acknowledge = minio_page.get_by_role("button", name="Acknowledge")
            if acknowledge.is_visible():
                acknowledge.click()
            minio_page.reload(wait_until="networkidle")
            expect(minio_page.get_by_text("quarantine", exact=True)).to_be_visible()
            minio_page.get_by_text("quarantine", exact=True).click()
            minio_page.wait_for_load_state("networkidle")
            save_screenshot(minio_page, "08-minio-storage.png")

            with page.expect_navigation():
                page.get_by_role("button", name="Проверить ответы").click()
            expect(page.get_by_role("heading", name="Проверьте ответы")).to_be_visible()
            expect(
                page.get_by_text(
                    "Пояснение: Комментарий для ответа «Нет»", exact=True
                )
            ).to_be_visible()
            save_screenshot(page, "09-review.png")

            with page.expect_navigation():
                page.get_by_role("button", name="Отправить анкету").click()
            expect(page.get_by_role("heading", name="Анкета отправлена")).to_be_visible()
            save_screenshot(page, "10-complete.png")

            with page.expect_navigation():
                page.get_by_role("button", name="Изменить ответы").click()
            expect(page.get_by_role("heading", name="Готовность и детали")).to_be_visible()
            save_screenshot(page, "11-editing.png")
        finally:
            api.dispose()
            desktop.close()
            browser.close()


if __name__ == "__main__":
    main()
