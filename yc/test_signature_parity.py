"""Сверка подписи Продамуса: питон-порт против живого PHP-кода prodamus-webhook.php.

Денежная цепочка — подпись переписывать вслепую нельзя. Этот скрипт:
1. Собирает синтетический payload оплаты с вложенным products[0][...]
   (та самая задокументированная грабля: PHP сериализует products списком,
   не словарём с ключом '0').
2. Извлекает prodamus_sign() прямо из PHP-файла и считает эталонную подпись
   через `php -r` (не переписывает алгоритм на PHP заново — гоняет тот же код).
3. Считает подпись тем же payload'ом через python-порт (webhook/index.py).
4. Сравнивает hex-дайджесты. Отдельно проверяет, что битая подпись отвергается.

Запуск: python3 test_signature_parity.py
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "webhook"))
import index as webhook  # noqa: E402

REPO_ROOT = Path(__file__).parent.parent
WEBHOOK_PHP = REPO_ROOT / "prodamus-webhook.php"

SECRET = "test-secret-not-real-b3a41db878ae"

# Синтетический payload — как его видит $_POST после разбора Яндексом
# x-www-form-urlencoded тела с bracket-нотацией products[0][...].
PAYLOAD: dict[str, object] = {
    "date": "2026-08-22T12:00:00+03:00",
    "order_id": "1042",
    "order_num": "A-1042",
    "domain": "payform.ru",
    "sum": "49900.00",
    "customer_phone": "+79991234567",
    "customer_email": "ivan@example.com",
    "payment_status": "success",
    "payment_status_description": "Успешная оплата",
    "products": {
        "0": {
            "name": "Тариф VIP — Ясность мышления",
            "price": "49900.00",
            "quantity": "1",
            "sum": "49900.00",
        },
    },
}


def _extract_php_function(source: str, name: str) -> str:
    """Вырезает тело функции `name` из PHP-исходника побайтово (balanced braces),
    не переписывая её — иначе тест проверял бы сам себя."""
    start = source.index(f"function {name}(")
    brace_open = source.index("{", start)
    depth = 0
    for i in range(brace_open, len(source)):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                return source[start:i + 1]
    raise ValueError(f"unbalanced braces while extracting {name}()")


def php_reference_sign(payload: dict[str, object], secret: str) -> str:
    """Считает эталонную подпись, гоняя РОВНО тот же код prodamus_sign(),
    вырезанный из prodamus-webhook.php (файл целиком не include'им — его
    верхнеуровневый роутинг сразу делает exit('POST only'))."""
    source = WEBHOOK_PHP.read_text(encoding="utf-8")
    function_src = _extract_php_function(source, "prodamus_sign")

    php_code = f"""
{function_src}
$data = json_decode(file_get_contents('php://stdin'), true);
echo prodamus_sign($data, {json.dumps(secret)});
"""
    result = subprocess.run(
        ["php", "-r", php_code],
        input=json.dumps(PAYLOAD).encode(),
        capture_output=True,
        check=True,
    )
    return result.stdout.decode().strip()


def python_sign(payload: dict[str, object], secret: str) -> str:
    return webhook.prodamus_sign(payload, secret)


def run() -> None:
    php_sig = php_reference_sign(PAYLOAD, SECRET)
    py_sig = python_sign(PAYLOAD, SECRET)

    print(f"PHP  signature: {php_sig}")
    print(f"Py   signature: {py_sig}")
    match = php_sig == py_sig
    print(f"Match: {match}")
    assert match, "ПОДПИСИ НЕ СОВПАДАЮТ — питон-порт неверен, PHP не трогать"

    # Обратный случай: битая подпись должна отвергаться verify-логикой хендлера.
    event = {
        "httpMethod": "POST",
        "headers": {"content-type": "application/json", "Sign": php_sig[:-1] + ("0" if php_sig[-1] != "0" else "1")},
        "isBase64Encoded": False,
        "body": json.dumps(PAYLOAD),
    }
    import os

    os.environ["PRODAMUS_SECRET"] = SECRET
    resp_bad = webhook.handler(event, None)
    print(f"Bad signature -> statusCode: {resp_bad['statusCode']} body: {resp_bad['body']!r}")
    assert resp_bad["statusCode"] == 403, "битая подпись должна давать 403"

    event_ok = {**event, "headers": {**event["headers"], "Sign": php_sig}}
    os.environ.setdefault("TG_TOKEN", "0:x")
    os.environ.setdefault("TG_CHAT_ID", "-1")
    resp_ok = webhook.handler(event_ok, None)
    print(f"Valid signature -> statusCode: {resp_ok['statusCode']}")
    assert resp_ok["statusCode"] == 200, "валидная подпись должна проходить (200)"

    print("\ntest_signature_parity: ALL OK")


if __name__ == "__main__":
    run()
