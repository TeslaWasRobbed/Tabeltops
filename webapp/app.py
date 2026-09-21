"""Active tabletop application.

This application is deliberately scenario-neutral. Historical exercise apps remain
under ``archive/`` and can be used as references while reusable features are moved
into this application.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from flask import Flask, jsonify, request, send_file


APP_DIR = Path(__file__).resolve().parent
REPO_ROOT = APP_DIR.parent

KUSTO_ENDPOINT = os.getenv("KUSTO_ENDPOINT", "http://127.0.0.1:8080").rstrip("/")
KUSTO_DATABASE = os.getenv("KUSTO_DATABASE", "TabletopSIEM")
DEFAULT_SCENARIO_DIR = REPO_ROOT / "archive" / "2026-08-04_shadow-ai-supply-chain"
SCENARIO_DIR = Path(os.getenv("TABLETOP_SCENARIO_DIR", str(DEFAULT_SCENARIO_DIR))).resolve()

app = Flask(__name__)


def call_kusto(path: str, csl: str, database: str | None = None) -> dict:
    """Send a query or management command to the local Kusto emulator."""
    payload = json.dumps({"db": database or KUSTO_DATABASE, "csl": csl}).encode("utf-8")
    req = Request(
        f"{KUSTO_ENDPOINT}{path}",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(req, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


@app.get("/")
def workspace():
    """Serve the current scenario-neutral analyst workspace."""
    return send_file(REPO_ROOT / "mockup_poc.html")


@app.get("/api/config")
def public_config():
    return jsonify(
        {
            "application": "SOC Training",
            "database": KUSTO_DATABASE,
            "scenario": SCENARIO_DIR.name,
            "scenario_available": SCENARIO_DIR.is_dir(),
        }
    )


@app.get("/api/health")
def health():
    try:
        call_kusto("/v1/rest/mgmt", ".show cluster", database="NetDefaultDB")
        kusto = "connected"
        status = 200
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError, OSError):
        kusto = "unavailable"
        status = 503

    return (
        jsonify(
            {
                "application": "ok",
                "kusto": kusto,
                "database": KUSTO_DATABASE,
                "scenario_available": SCENARIO_DIR.is_dir(),
            }
        ),
        status,
    )


@app.post("/api/kql/query")
def kql_query():
    query = str((request.get_json(silent=True) or {}).get("query", "")).strip()
    if not query:
        return jsonify({"success": False, "error": "Enter a KQL query."}), 400
    if query.startswith("."):
        return jsonify({"success": False, "error": "Management commands are not available in the analyst workspace."}), 400

    try:
        result = call_kusto("/v1/rest/query", query)
        table = (result.get("Tables") or [{}])[0]
        columns = [column.get("ColumnName", "") for column in table.get("Columns", [])]
        rows = [dict(zip(columns, row)) for row in table.get("Rows", [])]
        return jsonify(
            {
                "success": True,
                "columns": columns,
                "rows": rows,
                "row_count": len(rows),
                "database": KUSTO_DATABASE,
            }
        )
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        return jsonify({"success": False, "error": detail or str(exc)}), 400
    except (URLError, TimeoutError, OSError):
        return jsonify({"success": False, "error": "The Kusto emulator is unavailable."}), 503
    except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        return jsonify({"success": False, "error": f"Unexpected Kusto response: {exc}"}), 502


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=False, threaded=True)
