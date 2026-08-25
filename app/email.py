from __future__ import annotations

import smtplib
import ssl
from contextlib import suppress
from email.message import EmailMessage
from html import escape
from urllib.parse import quote, urlsplit

from app.config import Settings
from app.security import normalize_email, parse_magic_token

EMAIL_SUBJECT = "Ваша ссылка для входа в анкету"
MAGIC_LINK_TTL_TEXT = "Ссылка действует 15 минут и используется один раз."


class EmailDeliveryError(Exception):
    pass


def build_magic_url(base_url: str, magic_token: str) -> str:
    if not isinstance(base_url, str):
        raise TypeError("base_url must be a string")
    parsed = urlsplit(base_url.strip())
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("public base URL is invalid")
    parse_magic_token(magic_token)
    return f"{base_url.rstrip('/')}/auth/magic#token={quote(magic_token, safe='')}"


def build_login_email(
    settings: Settings,
    *,
    recipient: str,
    magic_token: str,
    otp: str,
) -> EmailMessage:
    normalized_recipient = normalize_email(recipient)
    if not isinstance(otp, str) or len(otp) != 6 or not otp.isascii() or not otp.isdecimal():
        raise ValueError("OTP must be six ASCII digits")
    magic_url = build_magic_url(settings.public_base_url, magic_token)
    text = (
        "Здравствуйте!\n\n"
        "Откройте ссылку, чтобы войти в анкету:\n"
        f"{magic_url}\n\n"
        f"Если ссылка не сработала, введите код: {otp}\n"
        f"{MAGIC_LINK_TTL_TEXT}\n"
    )
    html = (
        "<p>Здравствуйте!</p>"
        "<p>Откройте ссылку, чтобы войти в анкету:</p>"
        f'<p><a href="{escape(magic_url, quote=True)}">Войти в анкету</a></p>'
        f"<p>Если ссылка не сработала, введите код: <strong>{otp}</strong></p>"
        f"<p>{escape(MAGIC_LINK_TTL_TEXT)}</p>"
    )
    message = EmailMessage()
    message["To"] = normalized_recipient
    message["From"] = settings.smtp_from
    message["Subject"] = EMAIL_SUBJECT
    message.set_content(text)
    message.add_alternative(html, subtype="html")
    return message


def send_login_email(
    settings: Settings,
    *,
    recipient: str,
    magic_token: str,
    otp: str,
) -> None:
    if not settings.smtp_host.strip() or not settings.smtp_from.strip():
        raise EmailDeliveryError("SMTP delivery is not configured")
    message = build_login_email(
        settings,
        recipient=recipient,
        magic_token=magic_token,
        otp=otp,
    )
    smtp: smtplib.SMTP | None = None
    try:
        smtp = smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10)
        if settings.smtp_starttls:
            smtp.starttls(context=ssl.create_default_context())
        if settings.smtp_username:
            password = (
                settings.smtp_password.get_secret_value()
                if settings.smtp_password is not None
                else ""
            )
            smtp.login(settings.smtp_username, password)
        smtp.send_message(message)
    except (OSError, smtplib.SMTPException) as error:
        raise EmailDeliveryError("SMTP delivery failed") from error
    finally:
        if smtp is not None:
            with suppress(OSError, smtplib.SMTPException):
                smtp.quit()
