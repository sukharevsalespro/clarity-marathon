"""Yandex Cloud Function — вебхук оплат Продамуса (payform.ru).

Порт prodamus-webhook.php под python312 рантайм serverless-функций Яндекс.Облака.
Точка входа handler(event, context) — формат HTTP-триггера Yandex Cloud Functions.

Денежная цепочка: проверка подписи HMAC-SHA256 переписана с максимальной
осторожностью, паритет с PHP-оригиналом проверяется отдельным скриптом
test_signature_parity.py (гоняет оба варианта через один и тот же payload
и сверяет hex-дайджест).

Грабля, задокументированная в задаче: Продамус шлёт products[0][name]=...
в виде x-www-form-urlencoded с bracket-нотацией. PHP разбирает это
в $_POST['products'] как массив с последовательными числовыми ключами
0..n-1, и json_encode() при таких ключах сериализует его как JSON-СПИСОК,
а не объект {"0": ...}. Наша реализация обязана воспроизвести это же
поведение при сборке JSON для подписи — см. _to_jsonable().

Отличия от PHP-оригинала:
- payments.csv не пишем — вместо этого print() JSON-строки в Cloud Logging.
- Секреты только из окружения: TG_TOKEN, TG_CHAT_ID, PRODAMUS_SECRET.
Никаких внешних зависимостей — только стандартная библиотека.
"""

from __future__ import annotations

import hashlib
import hmac
import html
import json
import logging
import os
from datetime import datetime
from email import message_from_bytes
from typing import Any
from urllib.parse import parse_qsl, urlencode
from urllib.request import Request, urlopen
from zoneinfo import ZoneInfo

logger = logging.getLogger("webhook")
logger.setLevel(logging.INFO)

MSK = ZoneInfo("Europe/Moscow")


def _get_header(headers: dict[str, str] | None, name: str) -> str:
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


def _parse_multipart(body: bytes, content_type: str) -> list[tuple[str, str]]:
    """ponytail: только текстовые части, файлов Продамус в вебхуке не шлёт."""
    import re

    raw = b"Content-Type: " + content_type.encode() + b"\r\nMIME-Version: 1.0\r\n\r\n" + body
    msg = message_from_bytes(raw)
    pairs: list[tuple[str, str]] = []
    if not msg.is_multipart():
        return pairs
    name_re = re.compile(r'name="([^"]*)"')
    for part in msg.get_payload():
        match = name_re.search(part.get("Content-Disposition", ""))
        if not match:
            continue
        payload = part.get_payload(decode=True) or b""
        charset = part.get_content_charset() or "utf-8"
        pairs.append((match.group(1), payload.decode(charset, errors="replace")))
    return pairs


def _set_nested(root: dict[str, Any], raw_key: str, value: str) -> None:
    """PHP-стиль разбора bracket-нотации: a[b][c]=v → {'a': {'b': {'c': 'v'}}}.

    ponytail: покрывает вложенность произвольной глубины с именованными и
    числовыми ключами (products[0][name]), не эмулирует полностью parse_str
    (повторные скалярные ключи, a[]=автоинкремент и т.п. — Продамус их не шлёт).
    """
    if "[" not in raw_key:
        root[raw_key] = value
        return
    base, _, rest = raw_key.partition("[")
    parts = [base] + rest.rstrip("]").split("][") if rest else [base]
    node = root
    for part in parts[:-1]:
        node = node.setdefault(part, {})
    node[parts[-1]] = value


def _pairs_to_nested(pairs: list[tuple[str, str]]) -> dict[str, Any]:
    root: dict[str, Any] = {}
    for key, value in pairs:
        _set_nested(root, key, value)
    return root


def _parse_body(event: dict[str, Any]) -> dict[str, Any]:
    content_type = _get_header(event.get("headers"), "Content-Type")
    body = _decode_body(event)

    if "multipart/form-data" in content_type:
        return _pairs_to_nested(_parse_multipart(body, content_type))

    if "application/json" in content_type:
        try:
            parsed = json.loads(body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {}
        return parsed if isinstance(parsed, dict) else {}

    pairs = parse_qsl(body.decode("utf-8", errors="replace"), keep_blank_values=True)
    return _pairs_to_nested(pairs)


def _stringify_leaves(node: Any) -> Any:
    """array_walk_recursive(..., (string) cast) — только листья, не контейнеры."""
    if isinstance(node, dict):
        return {k: _stringify_leaves(v) for k, v in node.items()}
    if isinstance(node, list):
        return [_stringify_leaves(v) for v in node]
    if isinstance(node, bool):
        return "1" if node else ""
    return str(node)


def _php_ksort_key(key: str) -> tuple[int, Any]:
    """ksort(..., SORT_REGULAR): числовые строки сравниваются как числа."""
    try:
        return (0, float(key))
    except (TypeError, ValueError):
        return (1, key)


def _sort_recursive(node: Any) -> Any:
    if isinstance(node, dict):
        sorted_items = sorted(node.items(), key=lambda kv: _php_ksort_key(kv[0]))
        return {k: _sort_recursive(v) for k, v in sorted_items}
    if isinstance(node, list):
        return [_sort_recursive(v) for v in node]
    return node


def _to_jsonable(node: Any) -> Any:
    """Грабля из задачи: dict с ключами '0'..'n-1' по порядку → JSON-список,
    как json_encode() сериализует PHP-массив с последовательными числовыми
    ключами, начинающимися с 0."""
    if isinstance(node, dict):
        keys = list(node.keys())
        is_sequential_list = keys == [str(i) for i in range(len(keys))]
        values = [_to_jsonable(v) for v in node.values()]
        if is_sequential_list and keys:
            return values
        return dict(zip(keys, values))
    if isinstance(node, list):
        return [_to_jsonable(v) for v in node]
    return node


def prodamus_sign(data: dict[str, Any], key: str) -> str:
    canonical = {k: v for k, v in data.items() if k != "sign"}
    canonical = _stringify_leaves(canonical)
    canonical = _sort_recursive(canonical)
    canonical = _to_jsonable(canonical)
    payload = json.dumps(canonical, ensure_ascii=False, separators=(",", ":"))
    return hmac.new(key.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()


def _esc(value: str) -> str:
    return html.escape(value, quote=True)


def _first_product_name(data: dict[str, Any]) -> str:
    products = data.get("products")
    first: Any = None
    if isinstance(products, list) and products:
        first = products[0]
    elif isinstance(products, dict) and products:
        first = next(iter(products.values()))
    if isinstance(first, dict):
        return str(first.get("name", "")).strip()[:300]
    return ""


def _get_field(data: dict[str, Any], key: str) -> str:
    return str(data.get(key, "")).strip()[:300]


def _build_message(status: str, sum_: str, order_num: str, product: str, phone: str, email: str) -> str:
    ok = status == "success"
    header = (
        "💰 <b>Оплата получена</b>" if ok
        else f'⚠️ <b>Платёж: {_esc(status or "статус неизвестен")}</b>'
    ) + " — «Ясность мышления»"

    lines = [
        header,
        "",
        "📦 " + (_esc(product) if product else "—"),
        f"💵 <b>{_esc(sum_)} ₽</b>",
        "📱 " + (f"<code>{_esc(phone)}</code>" if phone else "—"),
        "📧 " + (f"<code>{_esc(email)}</code>" if email else "—"),
        "",
        "<blockquote>Заказ: " + _esc(order_num or "—") + "\n⏰ "
        + datetime.now(MSK).strftime("%d.%m.%Y %H:%M") + " MSK</blockquote>",
    ]
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
    except Exception:  # noqa: BLE001 — сбой Telegram не должен ронять ответ Продамусу
        logger.exception("telegram sendMessage failed")


def _text_response(status_code: int, body: str) -> dict[str, Any]:
    return {"statusCode": status_code, "headers": {"Content-Type": "text/plain; charset=utf-8"}, "body": body}


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    if event.get("httpMethod") != "POST":
        return _text_response(405, "POST only")

    data = _parse_body(event)
    secret = os.environ["PRODAMUS_SECRET"]

    sign = _get_header(event.get("headers"), "Sign") or str(data.get("sign", ""))
    expected = prodamus_sign(data, secret)
    if sign == "" or not hmac.compare_digest(expected, sign):
        return _text_response(403, "bad sign")

    status = _get_field(data, "payment_status")
    sum_ = _get_field(data, "sum")
    order_num = _get_field(data, "order_num") or _get_field(data, "order_id")
    phone = _get_field(data, "customer_phone")
    email = _get_field(data, "customer_email")
    product = _first_product_name(data)

    logger.info(json.dumps({
        "event": "payment", "status": status, "sum": sum_, "order": order_num,
        "product": product, "phone": phone, "email": email,
    }, ensure_ascii=False))

    _send_telegram(_build_message(status, sum_, order_num, product, phone, email))

    return _text_response(200, "success")


def _demo() -> None:
    """Самопроверка без сети: разбор bracket-нотации + собственная подпись
    (сквозная сверка с PHP — в test_signature_parity.py)."""
    body = (
        "payment_status=success&sum=49900.00&order_num=A-1&"
        "customer_phone=%2B79991234567&customer_email=ivan%40example.com&"
        "products[0][name]=%D0%A2%D0%B0%D1%80%D0%B8%D1%84+VIP&"
        "products[0][price]=49900&products[0][quantity]=1"
    )
    event = {
        "httpMethod": "POST",
        "headers": {"content-type": "application/x-www-form-urlencoded"},
        "isBase64Encoded": False,
        "body": body,
    }
    data = _parse_body(event)
    assert isinstance(data["products"], dict)
    assert data["products"]["0"]["name"] == "Тариф VIP"

    canonical = _to_jsonable(_sort_recursive(_stringify_leaves(data)))
    assert isinstance(canonical["products"], list), "products должен стать JSON-списком"

    sig1 = prodamus_sign(data, "secret")
    sig2 = prodamus_sign(dict(data), "secret")
    assert sig1 == sig2

    product = _first_product_name(data)
    assert product == "Тариф VIP"

    os.environ.setdefault("PRODAMUS_SECRET", "secret")
    resp = handler(event, None)  # без Sign-заголовка → 403, сеть не трогаем
    assert resp["statusCode"] == 403

    event_signed = {**event, "headers": {**event["headers"], "Sign": sig1}}
    os.environ.setdefault("TG_TOKEN", "0:x")
    os.environ.setdefault("TG_CHAT_ID", "-1")
    resp_ok = handler(event_signed, None)
    assert resp_ok["statusCode"] == 200, resp_ok

    print("webhook/index.py self-check: OK")


if __name__ == "__main__":
    _demo()
