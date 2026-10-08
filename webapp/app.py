"""SOC tabletop application with a server-owned exercise clock and incident workflow."""

from __future__ import annotations

import json
import hmac
import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from flask import Flask, jsonify, redirect, render_template, request, session, url_for

from webapp.ingestion import reset_dataset, sync_due


APP_DIR = Path(__file__).resolve().parent
REPO_ROOT = APP_DIR.parent
KUSTO_ENDPOINT = os.getenv("KUSTO_ENDPOINT", "http://127.0.0.1:8080").rstrip("/")
KUSTO_DATABASE = os.getenv("KUSTO_DATABASE", "TabletopSIEM")
SCENARIO_DIR = Path(os.getenv("TABLETOP_SCENARIO_DIR", str(REPO_ROOT / "scenario"))).resolve()
FRESHSERVICE_PATH = SCENARIO_DIR / "freshservice_records.json"
DEFAULT_STATE_DB = APP_DIR / "data" / "tabletop.db"
EXERCISE_DURATION_SECONDS = 5 * 60 * 60
STATE_LOCK = threading.RLock()
TEAMS = {"alpha": "Team Alpha", "bravo": "Team Bravo"}
ROLES = {*TEAMS, "facilitator"}

CLASSIFICATIONS = [
    "True positive - Suspicious activity",
    "Benign positive - Suspicious but expected",
    "False positive - Incorrect alert logic",
    "False positive - Inaccurate data",
    "Undetermined",
]


def alert(alert_id, minute, title, severity, tactics, description, entities):
    return {"id": alert_id, "release_offset": minute * 60, "title": title, "severity": severity, "tactics": tactics, "description": description, "entities": entities, "historical": False}


DAY_ALERTS = [
    alert("INC-2001", 5, "Admin user deleted an MFA phone from a user's account", "Medium", "Credential Access", "An administrator removed an authentication method from a user account.", [["victoria.nash@creditsafe.com", "Account"], ["Adam Thomas", "Actor"]]),
    alert("INC-2002", 10, "Email messages containing malicious URL deleted after delivery", "Medium", "Initial Access", "Messages containing a malicious URL were removed after delivery.", [["Marketing recipients", "Accounts"], ["Email campaign", "Mail cluster"]]),
    alert("INC-2003", 20, "MFA rejected by user", "Medium", "Credential Access", "A user rejected an authentication request.", [["molly.ups@creditsafe.com", "Account"], ["Managed mobile", "Device"]]),
    alert("INC-2004", 30, "Rare and potentially high-risk Office operations", "High", "Persistence, Collection", "A rare mailbox operation was observed for Louise Lonn.", [["louise.lonn@creditsafe.com", "Account"], ["craiglonn@gmail.com", "Mailbox"]]),
    alert("INC-2005", 40, "Azure VM Run Command executing a unique PowerShell script", "Medium", "Execution", "A unique PowerShell script was executed through Azure VM Run Command.", [["David Woofer", "Account"], ["Azure VM", "Cloud resource"]]),
    alert("INC-2006", 50, "Outbound email exceeds 400", "Medium", "Exfiltration", "An account sent an unusually high number of outbound messages.", [["olivia.mercer@creditsafe.com", "Account"], ["Dynamics connector", "Application"]]),
    alert("INC-2007", 57, "Files copied to USB - blocked by policy", "Low", "Exfiltration", "A removable-media copy was prevented by endpoint policy.", [["aimee.flangan@creditsafe.com", "Account"], ["CS-USB-0042", "USB device"]]),
    alert("INC-2008", 65, "Guest users invited to tenant by new inviters", "Medium", "Persistence", "A user who does not commonly invite guests added an external account.", [["beth.edgar@creditsafe.com", "Account"], ["ayeesha.ahmed@external.example", "Guest"]]),
    alert("INC-2009", 85, "Louise Lonn downloaded 50 files", "High", "Collection", "The bulk-download analytic threshold was reached within one hour.", [["louise.lonn@creditsafe.com", "Account"], ["HR SharePoint", "Cloud resource"]]),
    alert("INC-2010", 100, "Archive created in a suspicious temporary location", "High", "Collection, Exfiltration", "Archive files were created beneath a user's temporary directory.", [["CS-LL-W11-042", "Device"], ["louise.lonn@creditsafe.com", "Account"]]),
    alert("INC-2011", 110, "Account created and deleted in a short timeframe", "Medium", "Persistence", "A cloud account was removed shortly after it was created.", [["Emma Outgram", "Actor"], ["M365 migration test", "Account"]]),
    alert("INC-2012", 120, "Sensitive file upload to external Teams user blocked", "Medium", "Exfiltration", "A DLP policy blocked an upload to an external Teams participant.", [["hannah.rees@creditsafe.com", "Account"], ["Tom Blackburn", "External user"]]),
    alert("INC-2013", 135, "User added to Intune_Local_Admins Entra ID group", "High", "Privilege Escalation", "A user was granted local administrator rights through group membership.", [["bill.cottray@creditsafe.com", "Account"], ["Intune_Local_Admins", "Group"]]),
    alert("INC-2014", 150, "External guest downloaded sensitive archives", "High", "Collection, Exfiltration", "An external guest successfully downloaded archives from an HR SharePoint location.", [["hradvisor@rnicrosoft.com", "Guest"], ["HR SharePoint", "Cloud resource"], ["louise.lonn@creditsafe.com", "Account"]]),
    alert("INC-2015", 170, "Connection to a custom network indicator", "Medium", "Command and Control", "A managed host connected to a destination configured as a custom indicator.", [["NET-ADM-017", "Device"], ["198.51.100.200", "IP address"]]),
    alert("INC-2016", 190, "Registry-based persistence references SparkRAT", "High", "Persistence", "A registry Run key referencing SparkRAT was modified.", [["CS-LL-W11-042", "Device"], ["louise.lonn@creditsafe.com", "Account"]]),
]

HISTORICAL_INCIDENTS = [
    {"id": "INC-1841", "title": "Phishing link reported by Louise Lonn", "severity": "Medium", "tactics": "Initial Access", "description": "A reported phishing message was investigated as an email-only event.", "entities": [["louise.lonn@creditsafe.com", "Account"], ["hr@creditsafe.com", "Mailbox"]], "status": "Closed", "owner": "Anita Job", "classification": "Benign positive - Suspicious but expected", "closure_notes": "Password reset completed. User confirmed the message was reported.", "closed_at": "2026-09-03T09:34:00Z"},
    {"id": "INC-1854", "title": "Impossible travel - Birmingham", "severity": "Medium", "tactics": "Initial Access", "description": "A sign-in from a Birmingham VPN exit node was reviewed.", "entities": [["louise.lonn@creditsafe.com", "Account"], ["192.0.2.85", "IP address"]], "status": "Closed", "owner": "Anita Job", "classification": "Benign positive - Suspicious but expected", "closure_notes": "ExpressVPN activity considered expected.", "closed_at": "2026-09-04T14:46:00Z"},
    {"id": "INC-1868", "title": "Guest account invited to tenant", "severity": "Medium", "tactics": "Persistence", "description": "An external HR adviser account was invited to the tenant.", "entities": [["hradvisor@rnicrosoft.com", "Guest"], ["louise.lonn@creditsafe.com", "Account"]], "status": "Closed", "owner": "Anita Job", "classification": "Benign positive - Suspicious but expected", "closure_notes": "Microsoft adviser account; no further action required.", "closed_at": "2026-09-06T11:31:00Z"},
    {"id": "INC-1889", "title": "Impossible travel - China", "severity": "High", "tactics": "Initial Access", "description": "A sign-in from a China VPN exit node was reviewed.", "entities": [["louise.lonn@creditsafe.com", "Account"], ["203.0.113.44", "IP address"]], "status": "Closed", "owner": "Anita Job", "classification": "Benign positive - Suspicious but expected", "closure_notes": "ExpressVPN use explains location.", "closed_at": "2026-09-11T02:42:00Z"},
    {"id": "INC-1932", "title": "Louise Lonn downloaded 50 personal files", "severity": "High", "tactics": "Collection", "description": "Fifty files were downloaded from SharePoint and OneDrive.", "entities": [["louise.lonn@creditsafe.com", "Account"], ["HR SharePoint", "Cloud resource"]], "status": "Closed", "owner": "Anita Job", "classification": "Benign positive - Suspicious but expected", "closure_notes": "Filenames appear personal. Closed as user activity.", "closed_at": "2026-09-28T11:06:00Z"},
]

# Routine closed incidents provide a believable 90-day queue. They deliberately
# use the same visual treatment as the relevant historical incidents so analysts
# must hunt and correlate instead of being handed the backstory.
HISTORICAL_NOISE = [
    ("INC-1703", "Malware detected and quarantined on one device", "Medium", "Execution", "beth.edgar@creditsafe.com", "Endpoint protection quarantined the file; full scan clean.", "2026-08-16T08:42:00Z"),
    ("INC-1711", "Unfamiliar sign-in properties", "Low", "Initial Access", "james.dryington@creditsafe.com", "Confirmed new corporate mobile and normal UK location.", "2026-08-18T12:16:00Z"),
    ("INC-1720", "Multiple failed sign-ins followed by success", "Medium", "Credential Access", "callum.foster@creditsafe.com", "User confirmed password typo after returning from leave.", "2026-08-21T09:38:00Z"),
    ("INC-1728", "Azure resource deletion activity", "Medium", "Impact", "david.woofer@creditsafe.com", "Approved decommission under platform change record.", "2026-08-24T15:27:00Z"),
    ("INC-1734", "Inbox rule created to move messages", "Low", "Persistence", "ruby.lawson@creditsafe.com", "Rule moves newsletter responses to a campaign folder.", "2026-08-26T10:51:00Z"),
    ("INC-1742", "High-volume SharePoint download", "Medium", "Collection", "alex.williams@creditsafe.com", "Approved evidence export for the quarterly audit.", "2026-08-29T14:05:00Z"),
    ("INC-1751", "Risky sign-in from anonymous IP address", "High", "Initial Access", "imogen.walsh@creditsafe.com", "Corporate travel VPN confirmed by user and manager.", "2026-09-01T17:32:00Z"),
    ("INC-1760", "User reported message as phishing", "Low", "Initial Access", "maya.fielding@creditsafe.com", "Bulk marketing message; sender and links validated.", "2026-09-03T11:19:00Z"),
    ("INC-1769", "PowerShell launched with encoded command", "High", "Execution", "CS-SRE-W11-018", "Signed inventory script deployed by endpoint management.", "2026-09-07T07:58:00Z"),
    ("INC-1777", "Sensitive information sent externally", "Medium", "Exfiltration", "procurement@creditsafe.com", "DLP blocked the message; no information left the tenant.", "2026-09-05T16:44:00Z"),
    ("INC-1785", "Guest user added to a Teams site", "Low", "Persistence", "ayeesha.ahmed@external.example", "Supplier access matched the approved onboarding request.", "2026-09-13T13:20:00Z"),
    ("INC-1794", "MFA rejected by user", "Medium", "Credential Access", "connor.hayes@creditsafe.com", "Stale prompt from the user's managed Outlook client.", "2026-09-16T09:12:00Z"),
    ("INC-1802", "Suspicious archive file created", "Medium", "Collection", "owen.sykes@creditsafe.com", "Campaign artwork package created in the approved project path.", "2026-09-19T12:47:00Z"),
    ("INC-1810", "Connection to newly registered domain", "Medium", "Command and Control", "CS-MKT-W11-033", "Destination belonged to a newly launched approved survey provider.", "2026-09-22T10:36:00Z"),
    ("INC-1818", "Account added to privileged cloud role", "High", "Privilege Escalation", "rhydian.greggs@creditsafe.com", "Time-bound AWS architecture work approved in change record.", "2026-09-25T15:03:00Z"),
    ("INC-1826", "Mass deletion in OneDrive", "Medium", "Impact", "aimee.flangan@creditsafe.com", "User reorganised a project folder; files recoverable in recycle bin.", "2026-09-29T08:29:00Z"),
    ("INC-1835", "Impossible travel - United States", "Medium", "Initial Access", "daniel.price@creditsafe.com", "Concurrent mobile and corporate VPN sessions caused inaccurate location data.", "2026-10-02T18:11:00Z"),
    ("INC-1940", "OAuth application granted mail permissions", "High", "Persistence", "tessa.monroe@creditsafe.com", "Approved marketing automation integration; publisher verified.", "2026-10-05T11:42:00Z"),
    ("INC-1949", "Executable downloaded from cloud storage", "Medium", "Execution", "CS-ENG-W11-071", "Approved developer utility; hash and publisher validated.", "2026-10-09T14:18:00Z"),
    ("INC-1957", "Outbound email volume anomaly", "Medium", "Exfiltration", "naomi.clarke@creditsafe.com", "Expected customer renewal campaign sent through Dynamics.", "2026-10-13T16:07:00Z"),
    ("INC-1965", "Administrative account password reset", "Low", "Credential Access", "adam.thomas@creditsafe.com", "Service Desk reset followed verified identity process.", "2026-10-18T09:54:00Z"),
    ("INC-1973", "Rare process communicating externally", "High", "Command and Control", "NET-ADM-012", "Network diagnostic binary and destination approved for testing.", "2026-10-23T13:31:00Z"),
    ("INC-1981", "Files copied to removable media", "Medium", "Exfiltration", "CS-HR-W11-028", "Copy blocked by device-control policy; no successful transfer.", "2026-10-28T10:22:00Z"),
    ("INC-1989", "New forwarding rule detected", "Medium", "Persistence", "freya.morgan@creditsafe.com", "Temporary cover arrangement approved by Sales management.", "2026-11-02T08:48:00Z"),
    ("INC-1997", "Cloud account created then removed", "Low", "Persistence", "emma.outgram@creditsafe.com", "Short-lived account used for approved migration validation.", "2026-11-08T15:39:00Z"),
]

for index, (incident_id, title, severity, tactics, entity, notes, closed_at) in enumerate(HISTORICAL_NOISE):
    HISTORICAL_INCIDENTS.append({
        "id": incident_id,
        "title": title,
        "severity": severity,
        "tactics": tactics,
        "description": "Historical alert reviewed and closed during routine SOC operations.",
        "entities": [[entity, "Account or device"]],
        "status": "Closed",
        "owner": ("Hannah Rees", "Anita Job", "Marcus Vale", "Priya Shah")[index % 4],
        "classification": "False positive - Inaccurate data" if incident_id in {"INC-1835"} else "Benign positive - Suspicious but expected",
        "closure_notes": notes,
        "closed_at": closed_at,
    })


def utc_now(): return datetime.now(timezone.utc)
def parse_time(value): return datetime.fromisoformat(value.replace("Z", "+00:00")) if value else None
def iso_time(value=None): return (value or utc_now()).isoformat().replace("+00:00", "Z")


def connect_db(app):
    connection = sqlite3.connect(app.config["STATE_DB"], timeout=10)
    connection.row_factory = sqlite3.Row
    return connection


def require_roles(*allowed):
    def decorate(view):
        @wraps(view)
        def protected(*args, **kwargs):
            if session.get("role") not in allowed:
                return jsonify({"error": "Sign in with the appropriate exercise access code."}), 403
            return view(*args, **kwargs)
        return protected
    return decorate


@contextmanager
def database(app):
    connection = connect_db(app)
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def init_db(app):
    path = Path(app.config["STATE_DB"])
    path.parent.mkdir(parents=True, exist_ok=True)
    with database(app) as db:
        db.execute("CREATE TABLE IF NOT EXISTS exercise_state (singleton INTEGER PRIMARY KEY CHECK (singleton = 1), status TEXT NOT NULL, started_at TEXT, updated_at TEXT NOT NULL, accumulated_seconds REAL NOT NULL DEFAULT 0)")
        incident_columns = {row[1] for row in db.execute("PRAGMA table_info(incident_state)")}
        if incident_columns and "team_id" not in incident_columns:
            db.execute("ALTER TABLE incident_state RENAME TO incident_state_single_team")
        db.execute("""CREATE TABLE IF NOT EXISTS incident_state (
            team_id TEXT NOT NULL, incident_id TEXT NOT NULL, status TEXT NOT NULL,
            owner TEXT NOT NULL, classification TEXT, closure_notes TEXT,
            acknowledged_at TEXT, closed_at TEXT, updated_at TEXT NOT NULL,
            PRIMARY KEY(team_id, incident_id))""")
        if incident_columns and "team_id" not in incident_columns:
            db.execute("""INSERT INTO incident_state(team_id,incident_id,status,owner,classification,closure_notes,acknowledged_at,closed_at,updated_at)
                SELECT 'alpha',incident_id,status,owner,classification,closure_notes,acknowledged_at,closed_at,updated_at FROM incident_state_single_team""")
            db.execute("DROP TABLE incident_state_single_team")

        activity_columns = {row[1] for row in db.execute("PRAGMA table_info(activity)")}
        if activity_columns and "team_id" not in activity_columns:
            db.execute("ALTER TABLE activity RENAME TO activity_single_team")
        db.execute("""CREATE TABLE IF NOT EXISTS activity (
            id INTEGER PRIMARY KEY AUTOINCREMENT, team_id TEXT NOT NULL,
            incident_id TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL,
            detail TEXT NOT NULL, created_at TEXT NOT NULL)""")
        if activity_columns and "team_id" not in activity_columns:
            db.execute("""INSERT INTO activity(id,team_id,incident_id,actor,action,detail,created_at)
                SELECT id,'alpha',incident_id,actor,action,detail,created_at FROM activity_single_team""")
            db.execute("DROP TABLE activity_single_team")
        db.execute("INSERT OR IGNORE INTO exercise_state(singleton,status,updated_at,accumulated_seconds) VALUES(1,'not_started',?,0)", (iso_time(),))


def exercise_snapshot(db):
    row = db.execute("SELECT * FROM exercise_state WHERE singleton=1").fetchone()
    elapsed = float(row["accumulated_seconds"])
    if row["status"] == "running" and row["started_at"]:
        elapsed += max(0, (utc_now() - parse_time(row["started_at"])).total_seconds())
    elapsed = min(elapsed, EXERCISE_DURATION_SECONDS)
    status = "completed" if elapsed >= EXERCISE_DURATION_SECONDS else row["status"]
    next_alert = next((a for a in DAY_ALERTS if a["release_offset"] > elapsed), None)
    return {"status": status, "elapsed_seconds": int(elapsed), "duration_seconds": EXERCISE_DURATION_SECONDS, "started_at": row["started_at"], "next_alert_in_seconds": max(0, int(next_alert["release_offset"] - elapsed)) if next_alert and status == "running" else None, "released_alerts": sum(a["release_offset"] <= elapsed for a in DAY_ALERTS), "total_alerts": len(DAY_ALERTS)}


def materialize_incident(definition, state=None):
    item = dict(definition)
    item.update({"status": "New", "owner": "Unassigned", "classification": None, "closure_notes": None, "acknowledged_at": None, "closed_at": None})
    if state:
        item.update({key: state[key] for key in ("status", "owner", "classification", "closure_notes", "acknowledged_at", "closed_at")})
    item["alerts"] = 1
    return item


def get_visible_incidents(db, team_id, include_future=False):
    snapshot = exercise_snapshot(db)
    states = {row["incident_id"]: row for row in db.execute("SELECT * FROM incident_state WHERE team_id=?", (team_id,))}
    current = [materialize_incident(a, states.get(a["id"])) for a in DAY_ALERTS if include_future or a["release_offset"] <= snapshot["elapsed_seconds"]]
    historical = [dict(i, historical=True, release_offset=None, alerts=1, acknowledged_at=None) for i in sorted(HISTORICAL_INCIDENTS, key=lambda item: item["closed_at"], reverse=True)]
    return current + historical


def sync_kusto_if_configured(app, db):
    manifest = app.config.get("INGESTION_MANIFEST")
    container_root = app.config.get("KUSTO_CONTAINER_DATA_ROOT")
    if not manifest or not container_root:
        return 0
    snapshot = exercise_snapshot(db)
    return sync_due(db, snapshot["elapsed_seconds"], manifest, container_root)


def call_kusto(path: str, csl: str, database: str | None = None) -> dict:
    payload = json.dumps({"db": database or KUSTO_DATABASE, "csl": csl}).encode("utf-8")
    req = Request(f"{KUSTO_ENDPOINT}{path}", data=payload, headers={"Content-Type": "application/json"}, method="POST")
    with urlopen(req, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


def load_freshservice_records():
    records = json.loads(FRESHSERVICE_PATH.read_text(encoding="utf-8"))
    if not isinstance(records, list) or any(not isinstance(item, dict) or not item.get("id") for item in records):
        raise ValueError("FreshService records must be a list of objects with IDs.")
    return records


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.getenv("TABLETOP_SECRET_KEY", "development-secret-change-before-exercise"),
        ACCESS_CODES={
            "alpha": os.getenv("TABLETOP_ALPHA_CODE", "alpha-training"),
            "bravo": os.getenv("TABLETOP_BRAVO_CODE", "bravo-training"),
            "facilitator": os.getenv("TABLETOP_FACILITATOR_CODE", "facilitator-training"),
        },
        STATE_DB=os.getenv("TABLETOP_STATE_DB", str(DEFAULT_STATE_DB)),
        INGESTION_MANIFEST=os.getenv("TABLETOP_INGESTION_MANIFEST"),
        KUSTO_CONTAINER_DATA_ROOT=os.getenv("KUSTO_CONTAINER_DATA_ROOT", "/kustodata/tabletop"),
    )
    if test_config: app.config.update(test_config)
    init_db(app)

    @app.get("/")
    def access(): return render_template("access.html", role=None, error=None)

    @app.get("/<role>")
    def workspace(role):
        if role not in ROLES: return jsonify({"error": "Workspace not found."}), 404
        if session.get("role") != role: return render_template("access.html", role=role, error=None)
        return render_template(
            "workspace.html", kusto_database=KUSTO_DATABASE,
            classifications=CLASSIFICATIONS, role=role,
            team_id=role if role in TEAMS else None,
            workspace_label=TEAMS.get(role, "Facilitator"),
            is_facilitator=role == "facilitator",
        )

    @app.post("/login")
    def login():
        role = str(request.form.get("role") or "").lower()
        code = str(request.form.get("code") or "")
        expected = app.config["ACCESS_CODES"].get(role)
        if role not in ROLES or not expected or not hmac.compare_digest(code, expected):
            return render_template("access.html", role=role if role in ROLES else None, error="The access code is incorrect."), 401
        session.clear(); session["role"] = role
        return redirect(url_for("workspace", role=role))

    @app.post("/logout")
    def logout():
        session.clear()
        return redirect(url_for("access"))

    @app.get("/api/config")
    def public_config(): return jsonify({"application": "SOC Training", "database": KUSTO_DATABASE, "scenario": SCENARIO_DIR.name, "scenario_available": SCENARIO_DIR.is_dir()})

    @app.get("/api/health")
    def health():
        try:
            call_kusto("/v1/rest/mgmt", ".show cluster", database="NetDefaultDB"); kusto, status = "connected", 200
        except (HTTPError, URLError, TimeoutError, json.JSONDecodeError, OSError): kusto, status = "unavailable", 503
        return jsonify({"application": "ok", "kusto": kusto, "database": KUSTO_DATABASE, "scenario_available": SCENARIO_DIR.is_dir()}), status

    @app.get("/api/exercise")
    @require_roles("alpha", "bravo", "facilitator")
    def exercise_state():
        with database(app) as db: return jsonify(exercise_snapshot(db))

    @app.post("/api/facilitator/exercise/<action>")
    @require_roles("facilitator")
    def control_exercise(action):
        if action not in {"start", "pause", "resume", "reset"}: return jsonify({"error": "Unknown exercise control."}), 404
        now = utc_now()
        with STATE_LOCK, database(app) as db:
            state = exercise_snapshot(db)
            if action == "start":
                if state["status"] != "not_started": return jsonify({"error": "The exercise has already been started."}), 409
                db.execute("UPDATE exercise_state SET status='running',started_at=?,updated_at=?,accumulated_seconds=0 WHERE singleton=1", (iso_time(now), iso_time(now)))
            elif action == "pause":
                if state["status"] != "running": return jsonify({"error": "Only a running exercise can be paused."}), 409
                db.execute("UPDATE exercise_state SET status='paused',started_at=NULL,updated_at=?,accumulated_seconds=? WHERE singleton=1", (iso_time(now), state["elapsed_seconds"]))
            elif action == "resume":
                if state["status"] != "paused": return jsonify({"error": "Only a paused exercise can be resumed."}), 409
                db.execute("UPDATE exercise_state SET status='running',started_at=?,updated_at=? WHERE singleton=1", (iso_time(now), iso_time(now)))
            else:
                if str((request.get_json(silent=True) or {}).get("confirmation", "")) != "RESET": return jsonify({"error": "Type RESET to confirm."}), 400
                if app.config.get("INGESTION_MANIFEST"):
                    reset_dataset(db, app.config["INGESTION_MANIFEST"], app.config["KUSTO_CONTAINER_DATA_ROOT"])
                db.execute("DELETE FROM activity"); db.execute("DELETE FROM incident_state")
                db.execute("UPDATE exercise_state SET status='not_started',started_at=NULL,updated_at=?,accumulated_seconds=0 WHERE singleton=1", (iso_time(now),))
            return jsonify(exercise_snapshot(db))

    @app.get("/api/incidents")
    @require_roles("alpha", "bravo")
    def incidents():
        team_id = session["role"]
        with STATE_LOCK, database(app) as db:
            sync_kusto_if_configured(app, db)
            return jsonify({"incidents": get_visible_incidents(db, team_id), "exercise": exercise_snapshot(db), "team": TEAMS[team_id]})

    @app.get("/api/incidents/<incident_id>/activity")
    @require_roles("alpha", "bravo")
    def incident_activity(incident_id):
        team_id = session["role"]
        with database(app) as db:
            rows = db.execute("SELECT actor,action,detail,created_at FROM activity WHERE team_id=? AND incident_id=? ORDER BY id DESC", (team_id, incident_id)).fetchall()
            return jsonify({"activity": [dict(row) for row in rows]})

    @app.patch("/api/incidents/<incident_id>")
    @require_roles("alpha", "bravo")
    def update_incident(incident_id):
        team_id = session["role"]; team_name = TEAMS[team_id]
        body = request.get_json(silent=True) or {}; actor = str(body.get("actor") or team_name).strip()[:80]; requested_status = str(body.get("status") or "").strip(); owner = str(body.get("owner") or actor).strip()[:80]; classification = str(body.get("classification") or "").strip() or None; notes = str(body.get("closure_notes") or "").strip() or None
        definition = next((a for a in DAY_ALERTS if a["id"] == incident_id), None)
        if not definition: return jsonify({"error": "Historical incidents are read-only or the incident does not exist."}), 404
        with STATE_LOCK, database(app) as db:
            if incident_id not in {i["id"] for i in get_visible_incidents(db, team_id)}: return jsonify({"error": "This incident has not been released."}), 404
            current = db.execute("SELECT * FROM incident_state WHERE team_id=? AND incident_id=?", (team_id, incident_id)).fetchone(); current_status = current["status"] if current else "New"
            allowed = {"New": {"Active"}, "Active": {"Closed"}, "Closed": set()}
            if requested_status not in allowed[current_status]: return jsonify({"error": f"Invalid transition: {current_status} to {requested_status}."}), 400
            if requested_status == "Closed" and (classification not in CLASSIFICATIONS or not notes): return jsonify({"error": "Choose a valid classification and enter closure notes before closing."}), 400
            now = iso_time(); acknowledged = current["acknowledged_at"] if current else None
            if requested_status == "Active" and not acknowledged: acknowledged = now
            closed_at = now if requested_status == "Closed" else None
            db.execute("""INSERT INTO incident_state(team_id,incident_id,status,owner,classification,closure_notes,acknowledged_at,closed_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(team_id,incident_id) DO UPDATE SET status=excluded.status,owner=excluded.owner,classification=excluded.classification,closure_notes=excluded.closure_notes,acknowledged_at=excluded.acknowledged_at,closed_at=excluded.closed_at,updated_at=excluded.updated_at""", (team_id, incident_id, requested_status, owner, classification, notes, acknowledged, closed_at, now))
            detail = f"Status changed from {current_status} to {requested_status}." + (f" Classification: {classification}. Notes: {notes}" if classification else "")
            db.execute("INSERT INTO activity(team_id,incident_id,actor,action,detail,created_at) VALUES(?,?,?,?,?,?)", (team_id, incident_id, actor, "Status changed", detail, now))
            state = db.execute("SELECT * FROM incident_state WHERE team_id=? AND incident_id=?", (team_id, incident_id)).fetchone()
            return jsonify({"incident": materialize_incident(definition, state)})

    @app.get("/api/facilitator/review")
    @require_roles("facilitator")
    def facilitator_review():
        with database(app) as db:
            teams = {}
            for team_id, team_name in TEAMS.items():
                teams[team_id] = {"name": team_name, "incidents": get_visible_incidents(db, team_id)}
            activity = [dict(row) for row in db.execute("SELECT team_id,incident_id,actor,action,detail,created_at FROM activity ORDER BY id DESC")]
            return jsonify({"exercise": exercise_snapshot(db), "teams": teams, "activity": activity})

    @app.get("/api/freshservice/records")
    @require_roles("alpha", "bravo", "facilitator")
    def freshservice_records():
        fields = ("id", "type", "subject", "requester", "affected_user", "status", "priority", "assigned_to", "group", "created_at", "updated_at", "resolved_at", "assets", "related_records")
        return jsonify({"records": [{key: item.get(key) for key in fields} for item in load_freshservice_records()]})

    @app.get("/api/freshservice/records/<record_id>")
    @require_roles("alpha", "bravo", "facilitator")
    def freshservice_record(record_id):
        record = next((item for item in load_freshservice_records() if item["id"].lower() == record_id.lower()), None)
        if not record: return jsonify({"error": "FreshService record not found."}), 404
        return jsonify({"record": record})

    @app.post("/api/kql/query")
    @require_roles("alpha", "bravo", "facilitator")
    def kql_query():
        query = str((request.get_json(silent=True) or {}).get("query", "")).strip()
        if not query: return jsonify({"success": False, "error": "Enter a KQL query."}), 400
        if query.startswith("."): return jsonify({"success": False, "error": "Management commands are not available in the analyst workspace."}), 400
        try:
            with STATE_LOCK, database(app) as db:
                sync_kusto_if_configured(app, db)
            result = call_kusto("/v1/rest/query", query); table = (result.get("Tables") or [{}])[0]; columns = [column.get("ColumnName", "") for column in table.get("Columns", [])]; rows = [dict(zip(columns, row)) for row in table.get("Rows", [])]
            return jsonify({"success": True, "columns": columns, "rows": rows, "row_count": len(rows), "database": KUSTO_DATABASE})
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace"); return jsonify({"success": False, "error": detail or str(exc)}), 400
        except (URLError, TimeoutError, OSError): return jsonify({"success": False, "error": "The Kusto emulator is unavailable."}), 503
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc: return jsonify({"success": False, "error": f"Unexpected Kusto response: {exc}"}), 502

    return app


app = create_app()

if __name__ == "__main__": app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=False, threaded=True)
