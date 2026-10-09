"""Non-destructive event-day smoke test for the deployed tabletop service."""

from __future__ import annotations

import argparse
import json
import os
from http.cookiejar import CookieJar
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import HTTPCookieProcessor, Request, build_opener, urlopen


def load_env_file(path: Path | None) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path:
        return values
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip("'\"")
    return values


def request_json(opener, url: str):
    open_request = opener.open if hasattr(opener, "open") else opener
    with open_request(Request(url, headers={"Accept": "application/json"}), timeout=10) as response:
        return response.status, json.loads(response.read().decode("utf-8"))


def authenticated_opener(base_url: str, role: str, code: str):
    opener = build_opener(HTTPCookieProcessor(CookieJar()))
    payload = urlencode({"role": role, "code": code}).encode("utf-8")
    with opener.open(Request(f"{base_url}/login", data=payload, method="POST"), timeout=10) as response:
        if response.status != 200:
            raise RuntimeError(f"{role} login returned HTTP {response.status}")
    return opener


def run_smoke_test(base_url: str, codes: dict[str, str]):
    base_url = base_url.rstrip("/")
    _, health = request_json(urlopen, f"{base_url}/api/health")
    if health.get("application") != "ok" or health.get("kusto") != "connected":
        raise RuntimeError(f"Unhealthy service: {health}")

    checks = []
    for role, endpoint in (("alpha", "/api/incidents"), ("bravo", "/api/incidents"), ("facilitator", "/api/facilitator/review")):
        opener = authenticated_opener(base_url, role, codes[role])
        status, payload = request_json(opener, f"{base_url}{endpoint}")
        if status != 200:
            raise RuntimeError(f"{role} workspace returned HTTP {status}")
        checks.append((role, endpoint))
        if role in {"alpha", "bravo"}:
            fs_status, freshservice = request_json(opener, f"{base_url}/api/freshservice/records")
            if fs_status != 200 or len(freshservice.get("records", [])) < 1:
                raise RuntimeError(f"{role} FreshService evidence is unavailable")

    return {"health": health, "checks": checks}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:5000")
    parser.add_argument("--env-file", type=Path)
    args = parser.parse_args()
    file_values = load_env_file(args.env_file)
    codes = {
        "alpha": os.getenv("TABLETOP_ALPHA_CODE") or file_values.get("TABLETOP_ALPHA_CODE") or "alpha-training",
        "bravo": os.getenv("TABLETOP_BRAVO_CODE") or file_values.get("TABLETOP_BRAVO_CODE") or "bravo-training",
        "facilitator": os.getenv("TABLETOP_FACILITATOR_CODE") or file_values.get("TABLETOP_FACILITATOR_CODE") or "facilitator-training",
    }
    result = run_smoke_test(args.base_url, codes)
    print(f"SMOKE TEST PASSED: application={result['health']['application']} kusto={result['health']['kusto']} workspaces=alpha,bravo,facilitator")


if __name__ == "__main__":
    main()
