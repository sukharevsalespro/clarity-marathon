"""Yandex Cloud Function — приём заявок с формы лендинга «Ясность мышления».

Порт lead.php под python312 рантайм serverless-функций Яндекс.Облака.
Точка входа handler(event, context) — формат HTTP-триггера Yandex Cloud Functions.

Отличия от PHP-оригинала:
- leads.csv не пишем (у serverless нет диска) — вместо этого print() JSON-строки,
  это уходит в Yandex Cloud Logging.
- IP лида берём из заголовка X-Forwarded-Api-Gateway / X-Forwarded-For, а не
  $_SERVER['REMOTE_ADDR'] — в событии функции этого поля нет.
- Время в Telegram-карточке считаем явно в зоне Europe/Moscow (zoneinfo),
  а не local date() сервера, как было в PHP.

Секреты — только из переменных окружения: TG_TOKEN, TG_CHAT_ID.
Никаких внешних зависимостей — только стандартная библиотека.
"""

from __future__ import annotations

import html
import json
import logging
import os
import re
from datetime import datetime
from email import message_from_bytes
from typing import Any
from urllib.parse import parse_qsl, urlencode
from urllib.request import Request, urlopen
from zoneinfo import ZoneInfo

logger = logging.getLogger("lead")
logger.setLevel(logging.INFO)

MSK = ZoneInfo("Europe/Moscow")

# Поля лида — порядок и состав как в lead.php
FIELDS = [
    "product", "name", "phone", "email", "tariff_id", "tariff_name",
    "tariff_price", "payment_url", "source_page",
    "utm_source", "utm_campaign", "utm_content",
]

TARIFF_EMOJI = {"solo": "🌱", "guide": "🧭", "vip": "👑"}

USERNAME_RE = re.compile(r"^@([A-Za-z0-9_]{4,})$")
DISPOSITION_NAME_RE = re.compile(r'name="([^"]*)"')


def _get_header(headers: dict[str, str] | None, name: str) -> str:
    """Регистронезависимый поиск заголовка в словаре события Яндекса."""
    if not headers:
        return ""
    name_lower = name.lower()
    for key, value in headers.items():
        if key.lower() == name_lower:
            return value or ""
    return ""


def _decode_body(event: dict[str, Any]) -> bytes:
    body = event.get("body") or ""
    if event.get("isBase64Encoded"):
        import base64

        return base64.b64decode(body)
    return body.encode("utf-8")


def _parse_multipart(body: bytes, content_type: str) -> dict[str, str]:
    """Разбор multipart/form-data стандартной библиотекой (email.parser).

    ponytail: только текстовые поля (name= без filename=) — форма лендинга
    файлов не шлёт, полноценный разбор file-частей не нужен.
    """
    raw = b"Content-Type: " + content_type.encode() + b"\r\nMIME-Version: 1.0\r\n\r\n" + body
    msg = message_from_bytes(raw)
    fields: dict[str, str] = {}
    if not msg.is_multipart():
        return fields
    for part in msg.get_payload():
        disposition = part.get("Content-Disposition", "")
        match = DISPOSITION_NAME_RE.search(disposition)
        if not match:
            continue
        payload = part.get_payload(decode=True) or b""
        charset = part.get_content_charset() or "utf-8"
        fields[match.group(1)] = payload.decode(charset, errors="replace")
    return fields


def _parse_body(event: dict[str, Any]) -> dict[str, str]:
    content_type = _get_header(event.get("headers"), "Content-Type")
    body = _decode_body(event)

    if "multipart/form-data" in content_type:
        return _parse_multipart(body, content_type)

    if "application/json" in content_type:
        try:
            parsed = json.loads(body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {}
        return {k: str(v) for k, v in parsed.items()} if isinstance(parsed, dict) else {}

    # По умолчанию — application/x-www-form-urlencoded (и если Content-Type пуст)
    pairs = parse_qsl(body.decode("utf-8", errors="replace"), keep_blank_values=True)
    return dict(pairs)


def _esc(value: str) -> str:
    return html.escape(value, quote=True)


def _contact_html(phone: str) -> str:
    if phone == "":
        return "—"
    match = USERNAME_RE.match(phone)
    if match:
        return f'<a href="https://t.me/{match.group(1)}">{_esc(phone)}</a>'
    return f"<code>{_esc(phone)}</code>"


def _build_message(data: dict[str, str]) -> str:
    tariff_emoji = TARIFF_EMOJI.get(data["tariff_id"], "💎")
    lines = [
        "🔔 <b>Новая заявка</b> — марафон «Ясность мышления»",
        "",
        f'{tariff_emoji} <b>{_esc(data["tariff_name"] or "Тариф не указан")}</b> · '
        f'<b>{_esc(data["tariff_price"] or "—")}</b>',
        "",
        f'👤 {_esc(data["name"])}',
        f'📱 {_contact_html(data["phone"])}',
        f'📧 {"<code>" + _esc(data["email"]) + "</code>" if data["email"] else "—"}',
    ]

    meta = []
    if data["utm_source"] or data["utm_campaign"]:
        combined = (data["utm_source"] + " / " + data["utm_campaign"]).strip(" /")
        meta.append("UTM: " + _esc(combined))
    meta.append("⏰ " + datetime.now(MSK).strftime("%d.%m.%Y %H:%M") + " MSK")

    lines.append("")
    lines.append("<blockquote>" + "\n".join(meta) + "</blockquote>")
    return "\n".join(lines)


def _send_telegram(text: str) -> None:
    token = os.environ["TG_TOKEN"]
    chat_id = os.environ["TG_CHAT_ID"]
    params = urlencode({
        "chat_id": chat_id,
        "parse_mode": "HTML",
        "text": text,
        "disable_web_page_preview": "true",
    }).encode()
    req = Request(f"https://api.telegram.org/bot{token}/sendMessage", data=params, method="POST")
    try:
        with urlopen(req, timeout=10):
            pass
    except Exception:  # noqa: BLE001 — как в PHP: сбой Telegram не должен ронять ответ лиду
        logger.exception("telegram sendMessage failed")


def _json_response(status_code: int, payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "application/json; charset=utf-8"},
        "body": json.dumps(payload, ensure_ascii=False),
    }


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    if event.get("httpMethod") != "POST":
        return _json_response(405, {"ok": False, "error": "POST only"})

    form = _parse_body(event)
    data = {field: form.get(field, "").strip()[:500] for field in FIELDS}
    data["created_at"] = datetime.now(MSK).isoformat()
    data["ip"] = _get_header(event.get("headers"), "X-Forwarded-For")

    if data["name"] == "" or (data["phone"] == "" and data["email"] == ""):
        return _json_response(422, {"ok": False, "error": "empty lead"})

    logger.info(json.dumps({"event": "lead", **data}, ensure_ascii=False))

    _send_telegram(_build_message(data))

    return _json_response(200, {"ok": True})


def _demo() -> None:
    """Самопроверка порта без сети (Telegram-запрос не выполняется)."""
    event = {
        "httpMethod": "POST",
        "headers": {"Content-Type": "application/x-www-form-urlencoded"},
        "isBase64Encoded": False,
        "body": "name=Иван&phone=%2B79991234567&tariff_id=vip&tariff_name=VIP&tariff_price=49900",
    }
    form = _parse_body(event)
    assert form["name"] == "Иван"
    assert form["phone"] == "+79991234567"

    data = {field: form.get(field, "").strip()[:500] for field in FIELDS}
    assert data["name"] == "Иван"
    msg = _build_message({**data, "utm_source": "", "utm_campaign": ""})
    assert "👑" in msg
    assert "VIP" in msg
    assert "MSK" in msg

    empty_resp = handler({"httpMethod": "GET"}, None)
    assert empty_resp["statusCode"] == 405

    print("lead/index.py self-check: OK")


if __name__ == "__main__":
    _demo()
