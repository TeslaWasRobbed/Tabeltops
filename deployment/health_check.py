#!/usr/bin/env python3
"""Exit non-zero unless the application and Kusto emulator are healthy."""

from __future__ import annotations

import argparse
import json
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


DEFAULT_URL = "http://127.0.0.1:5000/api/health"


def check_health(url: str = DEFAULT_URL, timeout: float = 10, opener=urlopen) -> dict:
    request = Request(url, headers={"Accept": "application/json"})
    with opener(request, timeout=timeout) as response:
        payload = json.loads(response.read().decode("utf-8"))
    failures = []
    if payload.get("application") != "ok":
        failures.append("application is not healthy")
    if payload.get("kusto") != "connected":
        failures.append("Kusto is not connected")
    if not payload.get("scenario_available"):
        failures.append("scenario package is unavailable")
    if failures:
        raise RuntimeError("; ".join(failures))
    return payload


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=DEFAULT_URL)
    parser.add_argument("--timeout", type=float, default=10)
    args = parser.parse_args(argv)
    try:
        payload = check_health(args.url, args.timeout)
    except (HTTPError, URLError, TimeoutError, OSError, json.JSONDecodeError, RuntimeError) as exc:
        print(f"UNHEALTHY: {exc}", file=sys.stderr)
        return 1
    print(f"HEALTHY: application=ok kusto=connected database={payload.get('database', 'unknown')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
