"""Деплой двух Yandex Cloud Functions (lead, webhook) в каталог b1gca5upee7s5m8bssk8.

НЕ ЗАПУСКАТЬ автоматически — только по явной команде оператора, после ревью.

Аутентификация — сервисным аккаунтом по ключу /root/.secrets/yc-sa-key.json:
JWT (PS256, aud=IAM tokens endpoint, iss=service_account_id, kid=key id) →
обменивается на IAM-токен. Паттерн скопирован с проверенного
/tmp/.../scratchpad/yc_probe.py (там же уже подтверждено, что ключ рабочий).

Что делает:
1. Получает IAM-токен.
2. Для каждой функции (lead, webhook): создаёт функцию в каталоге, если её
   там ещё нет, заливает новую версию кода (zip каталога), проставляет
   переменные окружения и открывает публичный вызов без авторизации
   (роль serverless.functions.invoker для allUsers).

Зависимости: pyjwt + cryptography (для PS256) — они НЕ едут в сами функции,
это только локальный деплой-скрипт. Сами функции — чистая stdlib.
"""

from __future__ import annotations

import base64
import io
import json
import time
import zipfile
from pathlib import Path
from typing import Any

import jwt as pyjwt
from urllib.request import Request, urlopen
from urllib.error import HTTPError

KEY_PATH = "/root/.secrets/yc-sa-key.json"
FOLDER_ID = "b1gca5upee7s5m8bssk8"
IAM_URL = "https://iam.api.cloud.yandex.net/iam/v1/tokens"
FN_URL = "https://serverless-functions.api.cloud.yandex.net/functions/v1"
OPERATION_URL = "https://operation.api.cloud.yandex.net/operations"

YC_DIR = Path(__file__).parent

FUNCTIONS = [
    {
        "name": "katipa-lead",
        "dir": YC_DIR / "lead",
        "entrypoint": "index.handler",
        "env_keys": ["TG_TOKEN", "TG_CHAT_ID"],
    },
    {
        "name": "katipa-prodamus-webhook",
        "dir": YC_DIR / "webhook",
        "entrypoint": "index.handler",
        "env_keys": ["TG_TOKEN", "TG_CHAT_ID", "PRODAMUS_SECRET"],
    },
]

RUNTIME = "python312"
MEMORY_BYTES = "134217728"  # 128 MB — хватает с большим запасом для этих функций
TIMEOUT_SECONDS = "10"


def iam_token() -> str:
    key = json.load(open(KEY_PATH))
    now = int(time.time())
    assertion = pyjwt.encode(
        {"aud": IAM_URL, "iss": key["service_account_id"], "iat": now, "exp": now + 3600},
        key["private_key"],
        algorithm="PS256",
        headers={"kid": key["id"]},
    )
    req = Request(
        IAM_URL,
        data=json.dumps({"jwt": assertion}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(req, timeout=25) as resp:
        return json.load(resp)["iamToken"]


def _request(method: str, url: str, token: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
    data = json.dumps(body).encode() if body is not None else None
    req = Request(url, data=data, method=method, headers={
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    })
    try:
        with urlopen(req, timeout=60) as resp:
            return json.load(resp)
    except HTTPError as exc:
        raise RuntimeError(f"{method} {url} -> HTTP {exc.code}: {exc.read().decode()[:500]}") from exc


def _wait_operation(operation_id: str, token: str, timeout_s: int = 120) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        op = _request("GET", f"{OPERATION_URL}/{operation_id}", token)
        if op.get("done"):
            if "error" in op:
                raise RuntimeError(f"operation {operation_id} failed: {op['error']}")
            return op.get("response", {})
        time.sleep(2)
    raise TimeoutError(f"operation {operation_id} did not finish in {timeout_s}s")


def find_function_id(name: str, token: str) -> str | None:
    result = _request("GET", f"{FN_URL}/functions?folderId={FOLDER_ID}", token)
    for fn in result.get("functions", []):
        if fn["name"] == name:
            return fn["id"]
    return None


def create_function(name: str, token: str) -> str:
    op = _request("POST", f"{FN_URL}/functions", token, {"folderId": FOLDER_ID, "name": name})
    response = _wait_operation(op["id"], token)
    return response["id"]


def zip_source(directory: Path) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(directory.rglob("*.py")):
            zf.write(path, arcname=path.name)
    return buf.getvalue()


def load_env_values() -> dict[str, str]:
    """Читает секреты для переменных окружения функций.

    Значения НИКОГДА не печатаются — только используются в теле запроса
    к API Яндекса напрямую.
    """
    return {
        "TG_TOKEN": Path("/root/.secrets/prograni_leads_bot.txt").read_text().strip(),
        "TG_CHAT_ID": Path("/root/.secrets/katipa_leads_chat_id.txt").read_text().strip(),
        "PRODAMUS_SECRET": Path("/root/.secrets/prodamus.txt").read_text().strip(),
    }


def make_public(function_id: str, token: str) -> None:
    body = {
        "accessBindings": [
            {"roleId": "serverless.functions.invoker", "subject": {"id": "allUsers", "type": "system"}},
        ],
    }
    op = _request("POST", f"{FN_URL}/functions/{function_id}:setAccessBindings", token, body)
    _wait_operation(op["id"], token)


def deploy_one(spec: dict[str, Any], token: str, env_values: dict[str, str]) -> None:
    function_id = find_function_id(spec["name"], token)
    if function_id is None:
        print(f"создаю функцию {spec['name']}...")
        function_id = create_function(spec["name"], token)
    else:
        print(f"функция {spec['name']} уже есть: {function_id}")

    content_b64 = base64.b64encode(zip_source(spec["dir"])).decode()
    body = {
        "functionId": function_id,
        "runtime": RUNTIME,
        "entrypoint": spec["entrypoint"],
        "resources": {"memory": MEMORY_BYTES},
        "executionTimeout": f"{TIMEOUT_SECONDS}s",
        "environment": {key: env_values[key] for key in spec["env_keys"]},
        "content": content_b64,
    }
    print(f"  заливаю версию кода ({spec['dir'].name})...")
    op = _request("POST", f"{FN_URL}/versions", token, body)
    _wait_operation(op["id"], token)

    print("  открываю публичный вызов...")
    make_public(function_id, token)
    print(f"  готово: {spec['name']} -> {function_id}")


def main() -> None:
    token = iam_token()
    env_values = load_env_values()
    for spec in FUNCTIONS:
        deploy_one(spec, token, env_values)


if __name__ == "__main__":
    main()
