import csv
import json
import os
import re
import time
from datetime import datetime, timezone, timedelta
from flask import Flask, render_template, jsonify, request

app = Flask(__name__)

# --- Configuration & Ground Truth ---

# Which phase each alert belongs to (0 to 5)
# Phase 0: Initial noise
# Phase 1: Postinstall
# Phase 2: Execution
# Phase 3: Network
# Phase 4: Cloud
PHASES = {
    "sa-7f2a-9c1b-4e8d-a6f3-006": 0, # Email AI trial
    "sa-7f2a-9c1b-4e8d-a6f3-008": 0, # Dublin sign-in
    "sa-benign-vscode-009": 0,
    "sa-false-leaver-012": 0,
    "sa-rh-cato-travel": 0,

    "sa-7f2a-9c1b-4e8d-a6f3-005": 1, # Postinstall
    "sa-benign-git-011": 1,

    "sa-7f2a-9c1b-4e8d-a6f3-003": 2, # Child proc
    "sa-7f2a-9c1b-4e8d-a6f3-001": 2, # PowerShell

    "sa-7f2a-9c1b-4e8d-a6f3-002": 3, # Network
    "sa-benign-dotnet-013": 3,

    "sa-7f2a-9c1b-4e8d-a6f3-004": 4, # SharePoint vol
    "sa-7f2a-9c1b-4e8d-a6f3-007": 4, # Customer analytics
    "sa-benign-npm-peer-010": 4,
}

# Ground Truth for automated scoring
# TP = True Positive (Incident/Escalate)
# BP = Benign Positive (Expected/Authorized)
# FP = False Positive / Unrelated
ANSWERS = {
    "sa-7f2a-9c1b-4e8d-a6f3-001": "TP",
    "sa-7f2a-9c1b-4e8d-a6f3-002": "TP",
    "sa-7f2a-9c1b-4e8d-a6f3-003": "TP",
    "sa-7f2a-9c1b-4e8d-a6f3-004": "TP",
    "sa-7f2a-9c1b-4e8d-a6f3-005": "TP",
    "sa-7f2a-9c1b-4e8d-a6f3-006": "FP",
    "sa-7f2a-9c1b-4e8d-a6f3-007": "TP",
    "sa-7f2a-9c1b-4e8d-a6f3-008": "BP",
    "sa-benign-vscode-009": "BP",
    "sa-benign-npm-peer-010": "BP",
    "sa-benign-git-011": "BP",
    "sa-false-leaver-012": "FP",
    "sa-benign-dotnet-013": "BP",
    "sa-rh-cato-travel": "FP",
}

# --- Hints Management ---

HINTS = [
    "Hint 1: Not all alerts are related to the incident. Have you checked if the disabled contractor sign-in is a false lead?",
    "Hint 2: Look closely at the 'postinstall' script. What process did it spawn?",
    "Hint 3: Check DeviceNetworkEvents_CL. Did the outbound connection to the exfil gateway actually succeed?",
    "Hint 4: Correlate the SharePoint downloads with the endpoint timeline. Was the script running when the files were downloaded?",
    "Hint 5: Review the AdditionalFields in the network events. A 'TcpTimeout' means no data was sent."
]

# Incident timestamps span 2026-05-28T06:12 to 2026-05-28T10:04 (~4 hours).
# The simulation clock compresses this into real time via the speed multiplier:
#   speed=6  → ~40 real minutes for full exercise
#   speed=10 → ~24 real minutes (default)
#   speed=20 → ~12 real minutes (fast demo)
SIM_INCIDENT_START = datetime(2026, 5, 28, 6, 0, 0, tzinfo=timezone.utc)

def make_state():
    return {
        "sim": {
            "running": False,
            "speed": 6,            # incident-seconds per real-second (6× ≈ 40 real min for full timeline; suits a 2hr session)
            "start_real": None,    # time.time() when simulation was (last) started
            "offset_secs": 0,      # incident-seconds already elapsed before last start/pause
        },
        "first_solves": {},
        "teams": {
            "team1": {"name": "Alpha Team", "score": 0, "closed": {}, "log": [], "current_hint": -1},
            "team2": {"name": "Bravo Team", "score": 0, "closed": {}, "log": [], "current_hint": -1}
        }
    }

state = make_state()

def get_sim_time():
    """Return the current simulated incident datetime."""
    sim = state["sim"]
    elapsed = sim["offset_secs"]
    if sim["running"] and sim["start_real"] is not None:
        elapsed += (time.time() - sim["start_real"]) * sim["speed"]
    return SIM_INCIDENT_START + timedelta(seconds=elapsed)

def sim_time_str():
    return get_sim_time().strftime("%Y-%m-%dT%H:%M:%SZ")

def load_alerts():
    alerts = []
    csv_path = os.path.join(os.path.dirname(__file__), '..', 'watchlists', 'SecurityAlert_CL.csv')
    if not os.path.exists(csv_path):
        print(f"Warning: Could not find {csv_path}")
        return []
    with open(csv_path, 'r', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Only load alerts that are explicitly in the PHASES dict
            # This keeps the 100 background scan rows in the CSV for Sentinel
            # without flooding the exercise dashboard
            if row.get('SystemAlertId', '') in PHASES:
                alerts.append(row)
    alerts.sort(key=lambda x: x['TimeGenerated'])
    print(f"Loaded {len(alerts)} exercise alerts from {csv_path}")
    return alerts

ALERTS_DB = load_alerts()

# --- Fake KQL Workspace ---

WORKSPACE_TABLES = {}

def parse_dt(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except Exception:
        return None

def load_workspace_tables():
    tables = {}
    watchlist_dir = os.path.join(os.path.dirname(__file__), '..', 'watchlists')
    if not os.path.isdir(watchlist_dir):
        return tables
    for filename in os.listdir(watchlist_dir):
        if not filename.endswith('.csv'):
            continue
        table_name = filename[:-4]
        path = os.path.join(watchlist_dir, filename)
        with open(path, 'r', encoding='utf-8-sig', newline='') as f:
            tables[table_name] = list(csv.DictReader(f))
    print(f"Loaded {len(tables)} fake KQL workspace tables from {watchlist_dir}")
    return tables

WORKSPACE_TABLES = load_workspace_tables()

def row_event_time(row):
    return parse_dt(row.get("TimeGenerated")) or parse_dt(row.get("Timestamp"))

def visible_workspace_rows(table_name):
    rows = WORKSPACE_TABLES.get(table_name, [])
    current_sim = get_sim_time()
    visible = []
    for row in rows:
        event_time = row_event_time(row)
        if event_time is None or event_time <= current_sim:
            visible.append(dict(row))
    return visible

def split_csv_expr(text):
    parts, current, depth, quote = [], [], 0, None
    for ch in text:
        if quote:
            current.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in ('"', "'"):
            quote = ch
        elif ch == '(':
            depth += 1
        elif ch == ')':
            depth = max(0, depth - 1)
        elif ch == ',' and depth == 0:
            parts.append(''.join(current).strip())
            current = []
            continue
        current.append(ch)
    tail = ''.join(current).strip()
    if tail:
        parts.append(tail)
    return parts

def clean_kql(query):
    cleaned = []
    for line in query.replace('\r\n', '\n').split('\n'):
        cleaned.append(line.split('//', 1)[0])
    return '\n'.join(cleaned).strip()

def parse_literal(value, variables):
    value = value.strip()
    if value in variables:
        return variables[value]
    dt_match = re.match(r"datetime\((.*?)\)", value, flags=re.I)
    if dt_match:
        return parse_dt(dt_match.group(1).replace(" ", "T") + ("Z" if "Z" not in dt_match.group(1) else ""))
    if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
        return value[1:-1]
    if value.isdigit():
        return int(value)
    return value

def as_number(value):
    try:
        return float(value)
    except Exception:
        return None

def compare_values(left, op, right):
    left_num = as_number(left)
    right_num = as_number(right)
    if left_num is not None and right_num is not None:
        left_cmp, right_cmp = left_num, right_num
    else:
        left_cmp, right_cmp = str(left), str(right)
    if op == "==":
        return left_cmp == right_cmp
    if op == "!=":
        return left_cmp != right_cmp
    if op == ">=":
        return left_cmp >= right_cmp
    if op == "<=":
        return left_cmp <= right_cmp
    if op == ">":
        return left_cmp > right_cmp
    if op == "<":
        return left_cmp < right_cmp
    return False

def eval_simple_condition(row, condition, variables):
    condition = condition.strip()

    datetime_between = re.match(
        r"(\w+)\s+between\s*\(\s*datetime\((.*?)\)\s*\.\.\s*datetime\((.*?)\)\s*\)",
        condition,
        flags=re.I | re.S,
    )
    if datetime_between:
        field, start_raw, end_raw = datetime_between.groups()
        row_dt = parse_dt(row.get(field))
        start = parse_dt(start_raw.strip().replace(" ", "T") + ("Z" if "Z" not in start_raw else ""))
        end = parse_dt(end_raw.strip().replace(" ", "T") + ("Z" if "Z" not in end_raw else ""))
        return bool(row_dt and start and end and start <= row_dt <= end)

    between = re.match(r"(\w+)\s+between\s*\((.*?)\s*\.\.\s*(.*?)\)", condition, flags=re.I | re.S)
    if between:
        field, start_raw, end_raw = between.groups()
        row_dt = parse_dt(row.get(field))
        start = parse_literal(start_raw, variables)
        end = parse_literal(end_raw, variables)
        return bool(row_dt and start and end and start <= row_dt <= end)

    in_match = re.match(r"(\w+)\s+in\s*\((.*?)\)", condition, flags=re.I | re.S)
    if in_match:
        field, raw_values = in_match.groups()
        raw_values = raw_values.strip()
        if raw_values in variables:
            values = variables[raw_values]
        else:
            values = [parse_literal(v, variables) for v in split_csv_expr(raw_values)]
        return row.get(field, "") in values

    not_empty = re.match(r"isnotempty\((\w+)\)", condition, flags=re.I)
    if not_empty:
        return row.get(not_empty.group(1), "") not in ("", None)

    contains = re.match(r"(\w+)\s+(contains|has)\s+(.+)", condition, flags=re.I)
    if contains:
        field, _, needle = contains.groups()
        return str(parse_literal(needle, variables)).lower() in str(row.get(field, "")).lower()

    comparison = re.match(r"(\w+)\s*(==|!=|>=|<=|>|<)\s*(.+)", condition, flags=re.I)
    if comparison:
        field, op, raw = comparison.groups()
        return compare_values(row.get(field, ""), op, parse_literal(raw, variables))

    return True

def eval_condition(row, condition, variables):
    or_parts = re.split(r"\s+or\s+", condition, flags=re.I)
    if len(or_parts) > 1:
        return any(eval_condition(row, part, variables) for part in or_parts)
    and_parts = re.split(r"\s+and\s+", condition, flags=re.I)
    if len(and_parts) > 1:
        return all(eval_simple_condition(row, part, variables) for part in and_parts)
    return eval_simple_condition(row, condition, variables)

def project_expr(row, expr):
    alias = None
    if '=' in expr and not re.search(r"[!<>]=", expr):
        alias, expr = [part.strip() for part in expr.split('=', 1)]
    name = alias or expr
    tostring = re.match(r"tostring\((\w+)\.(\w+)\)", expr, flags=re.I)
    if tostring:
        obj = row.get(tostring.group(1), {})
        if isinstance(obj, str):
            try:
                obj = json.loads(obj)
            except Exception:
                obj = {}
        return name, obj.get(tostring.group(2), "")
    return name, row.get(expr, "")

def apply_summarize(rows, statement, variables):
    by_fields = []
    if re.search(r"\s+by\s+", statement, flags=re.I):
        agg_part, by_part = re.split(r"\s+by\s+", statement, maxsplit=1, flags=re.I)
        by_fields = [f.strip() for f in split_csv_expr(by_part)]
    else:
        agg_part = statement

    groups = {}
    for row in rows:
        key = tuple(row.get(field, "") for field in by_fields)
        groups.setdefault(key, []).append(row)

    result = []
    aggregations = split_csv_expr(agg_part)
    for key, group_rows in groups.items():
        out = {field: key[index] for index, field in enumerate(by_fields)}
        for agg in aggregations:
            name = "Count"
            expr = agg
            if '=' in agg:
                name, expr = [part.strip() for part in agg.split('=', 1)]
            if re.match(r"count\(\)", expr, flags=re.I):
                out[name] = len(group_rows)
            else:
                countif = re.match(r"countif\((.*)\)", expr, flags=re.I | re.S)
                if countif:
                    out[name] = sum(1 for row in group_rows if eval_condition(row, countif.group(1), variables))
        result.append(out)
    return result

def execute_pipeline(query, variables=None):
    variables = variables or {}
    query = clean_kql(query)
    if not query:
        return [], []

    table_match = re.search(r'_GetWatchlist\(["\']([^"\']+)["\']\)|^\s*([A-Za-z][A-Za-z0-9_]*_CL)', query, flags=re.I)
    if not table_match:
        raise ValueError("Start with a table name, for example SecurityAlert_CL or _GetWatchlist(\"SecurityAlert_CL\").")

    table_name = table_match.group(1) or table_match.group(2)
    if table_name not in WORKSPACE_TABLES:
        raise ValueError(f"Unknown table: {table_name}")

    rows = visible_workspace_rows(table_name)
    pipeline_text = query[table_match.end():].strip()
    if pipeline_text.startswith('|'):
        pipeline_text = pipeline_text[1:]

    for statement in [part.strip() for part in pipeline_text.split('|') if part.strip()]:
        lower = statement.lower()
        if lower.startswith('where '):
            condition = statement[6:].strip()
            rows = [row for row in rows if eval_condition(row, condition, variables)]
        elif lower.startswith('project '):
            exprs = split_csv_expr(statement[8:].replace('\n', ' '))
            rows = [dict(project_expr(row, expr) for expr in exprs) for row in rows]
        elif lower.startswith('extend '):
            for expr in split_csv_expr(statement[7:].replace('\n', ' ')):
                if '=' not in expr:
                    continue
                name, value_expr = [part.strip() for part in expr.split('=', 1)]
                parse_json = re.match(r"parse_json\((\w+)\)", value_expr, flags=re.I)
                for row in rows:
                    if parse_json:
                        try:
                            row[name] = json.loads(row.get(parse_json.group(1), "") or "{}")
                        except Exception:
                            row[name] = {}
                    else:
                        row[name] = parse_literal(value_expr, variables)
        elif lower.startswith('order by '):
            first_sort = split_csv_expr(statement[9:].replace('\n', ' '))[0]
            bits = first_sort.split()
            field = bits[0]
            reverse = len(bits) > 1 and bits[1].lower() == 'desc'
            rows.sort(key=lambda row: parse_dt(row.get(field)) or row.get(field, ""), reverse=reverse)
        elif lower.startswith('take ') or lower.startswith('limit '):
            rows = rows[:int(statement.split()[1])]
        elif lower.startswith('distinct '):
            fields = [f.strip() for f in split_csv_expr(statement[9:])]
            seen, distinct_rows = set(), []
            for row in rows:
                key = tuple(row.get(field, "") for field in fields)
                if key not in seen:
                    seen.add(key)
                    distinct_rows.append({field: row.get(field, "") for field in fields})
            rows = distinct_rows
        elif lower.startswith('summarize '):
            rows = apply_summarize(rows, statement[10:].strip(), variables)
        elif lower.startswith('join ') or lower.startswith('mv-expand ') or lower.startswith('union '):
            raise ValueError(f"'{statement.split()[0]}' is not supported in the fake workspace yet.")

    columns = list(rows[0].keys()) if rows else []
    return rows[:500], columns

def run_fake_kql(query):
    query = clean_kql(query)
    variables = {}

    while query.lower().startswith('let '):
        match = re.match(r"let\s+(\w+)\s*=\s*(.*?);(.*)$", query, flags=re.I | re.S)
        if not match:
            break
        name, expr, remainder = match.groups()
        expr = expr.strip()
        if "_GetWatchlist" in expr or re.match(r"^[A-Za-z][A-Za-z0-9_]*_CL", expr):
            let_rows, let_cols = execute_pipeline(expr, variables)
            if len(let_cols) == 1:
                variables[name] = [row.get(let_cols[0], "") for row in let_rows]
            else:
                variables[name] = let_rows
        else:
            variables[name] = parse_literal(expr, variables)
        query = remainder.strip()

    rows, columns = execute_pipeline(query, variables)
    return {
        "columns": columns,
        "rows": rows,
        "row_count": len(rows),
        "sim_time": sim_time_str(),
        "table_count": len(WORKSPACE_TABLES),
    }

# --- Routes ---

@app.route('/')
def index():
    return render_template('index.html', teams=state["teams"])

@app.route('/dashboard/<team_id>')
def dashboard(team_id):
    if team_id not in state["teams"]:
        return "Team not found", 404
    return render_template('dashboard.html', team_id=team_id, team_name=state["teams"][team_id]["name"])

@app.route('/leaderboard')
def leaderboard():
    return render_template('leaderboard.html')

@app.route('/facilitator')
def facilitator():
    return render_template('facilitator.html')

# --- API Endpoints ---

@app.route('/api/state/<team_id>')
def get_state(team_id):
    if team_id not in state["teams"]:
        return jsonify({"error": "Team not found"}), 404

    team_data = state["teams"][team_id]
    current_sim = get_sim_time()

    # Show alert if its incident timestamp has passed in the simulation
    visible_alerts = []
    for alert in ALERTS_DB:
        aid = alert["SystemAlertId"]
        try:
            alert_time = datetime.fromisoformat(alert["TimeGenerated"].replace("Z", "+00:00"))
        except Exception:
            continue
        if alert_time <= current_sim and aid not in team_data["closed"]:
            visible_alerts.append(alert)

    visible_alerts.sort(key=lambda x: x['TimeGenerated'], reverse=True)

    return jsonify({
        "score": team_data["score"],
        "alerts": visible_alerts,
        "closed_count": len(team_data["closed"]),
        "log": team_data["log"][-5:],
        "hint": HINTS[team_data["current_hint"]] if team_data["current_hint"] >= 0 else None,
        "sim_time": sim_time_str(),
        "sim_running": state["sim"]["running"],
        "sim_speed": state["sim"]["speed"],
    })

@app.route('/api/leaderboard_data')
def get_leaderboard():
    return jsonify({
        "sim_time": sim_time_str(),
        "sim_running": state["sim"]["running"],
        "sim_speed": state["sim"]["speed"],
        "teams": state["teams"],
        "answers": ANSWERS
    })

@app.route('/api/classify', methods=['POST'])
def classify_alert():
    data = request.json
    team_id = data.get("team_id")
    alert_id = data.get("alert_id")
    classification = data.get("classification") # "TP", "BP", "FP"
    
    if team_id not in state["teams"]:
        return jsonify({"error": "Invalid team"}), 400
        
    team = state["teams"][team_id]
    
    if alert_id in team["closed"]:
        return jsonify({"error": "Alert already closed"}), 400
        
    correct_answer = ANSWERS.get(alert_id)
    
    if classification == correct_answer:
        if alert_id in state["first_solves"]:
            points = 0
            msg = f"Correct! (0 pts - Already solved by another team) {alert_id} is {correct_answer}."
        else:
            state["first_solves"][alert_id] = team_id
            points = 10
            msg = f"Correct! (+10 pts - First Solve!) {alert_id} is {correct_answer}."
    else:
        points = -5
        msg = f"Incorrect! (-5 pts) {alert_id} was actually {correct_answer}."
        
    team["score"] += points
    team["closed"][alert_id] = classification
    team["log"].append(msg)
    
    return jsonify({"success": True, "message": msg, "points": points, "new_score": team["score"]})

@app.route('/api/kql/schema')
def kql_schema():
    current_sim = get_sim_time()
    tables = []
    for table_name, rows in sorted(WORKSPACE_TABLES.items()):
        visible = visible_workspace_rows(table_name)
        columns = list(rows[0].keys()) if rows else []
        latest = None
        for row in visible:
            event_time = row_event_time(row)
            if event_time and (latest is None or event_time > latest):
                latest = event_time
        tables.append({
            "name": table_name,
            "columns": columns,
            "total_rows": len(rows),
            "visible_rows": len(visible),
            "latest_visible": latest.strftime("%Y-%m-%dT%H:%M:%SZ") if latest else None,
        })
    return jsonify({
        "sim_time": current_sim.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sim_running": state["sim"]["running"],
        "tables": tables,
    })

@app.route('/api/kql/query', methods=['POST'])
def kql_query():
    data = request.json or {}
    query = data.get("query", "")
    try:
        return jsonify({"success": True, **run_fake_kql(query)})
    except Exception as e:
        return jsonify({"success": False, "error": str(e), "sim_time": sim_time_str()}), 400

@app.route('/api/facilitator/simulation/start', methods=['POST'])
def sim_start():
    sim = state["sim"]
    if not sim["running"]:
        sim["start_real"] = time.time()
        sim["running"] = True
    return jsonify({"success": True, "sim_time": sim_time_str()})

@app.route('/api/facilitator/simulation/pause', methods=['POST'])
def sim_pause():
    sim = state["sim"]
    if sim["running"] and sim["start_real"] is not None:
        sim["offset_secs"] += (time.time() - sim["start_real"]) * sim["speed"]
        sim["start_real"] = None
        sim["running"] = False
    return jsonify({"success": True, "sim_time": sim_time_str()})

@app.route('/api/facilitator/simulation/speed', methods=['POST'])
def sim_speed():
    sim = state["sim"]
    new_speed = request.json.get("speed")
    if new_speed and new_speed in [3, 6, 10, 20]:
        # Capture elapsed before changing speed
        if sim["running"] and sim["start_real"] is not None:
            sim["offset_secs"] += (time.time() - sim["start_real"]) * sim["speed"]
            sim["start_real"] = time.time()
        sim["speed"] = new_speed
        return jsonify({"success": True, "speed": sim["speed"]})
    return jsonify({"error": "Invalid speed. Use 3, 6, 10 or 20"}), 400

@app.route('/api/facilitator/simulation/jump', methods=['POST'])
def sim_jump():
    """Jump simulation to a specific incident time (for manual override)."""
    sim = state["sim"]
    target = request.json.get("incident_time")  # e.g. "2026-05-28T09:10:00Z"
    try:
        t = datetime.fromisoformat(target.replace("Z", "+00:00"))
        sim["offset_secs"] = (t - SIM_INCIDENT_START).total_seconds()
        if sim["running"]:
            sim["start_real"] = time.time()
        return jsonify({"success": True, "sim_time": sim_time_str()})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/api/facilitator/score', methods=['POST'])
def adjust_score():
    data = request.json
    team_id = data.get("team_id")
    points = data.get("points")
    reason = data.get("reason", "Manual adjustment")
    
    if team_id in state["teams"] and isinstance(points, int):
        state["teams"][team_id]["score"] += points
        state["teams"][team_id]["log"].append(f"Facilitator adjustment: {points:+d} pts ({reason})")
        return jsonify({"success": True})
        
    return jsonify({"error": "Invalid request"}), 400

@app.route('/api/facilitator/hint', methods=['POST'])
def send_hint():
    data = request.json
    team_id = data.get("team_id")
    hint_index = data.get("hint_index")
    if team_id in state["teams"] and hint_index is not None and -1 <= hint_index < len(HINTS):
        state["teams"][team_id]["current_hint"] = hint_index
        return jsonify({"success": True})
    return jsonify({"error": "Invalid request"}), 400

@app.route('/api/docs/<doc_name>')
def get_doc(doc_name):
    allowed = {"briefing": "ANALYST_BRIEFING.md", "starter-kql": "STARTER_KQL.md"}
    filename = allowed.get(doc_name)
    if not filename:
        return jsonify({"error": "Not found"}), 404
    doc_path = os.path.join(os.path.dirname(__file__), '..', filename)
    if not os.path.exists(doc_path):
        return jsonify({"error": "File not found"}), 404
    with open(doc_path, encoding='utf-8') as f:
        return jsonify({"content": f.read()})

@app.route('/api/facilitator/reset', methods=['POST'])
def reset_state():
    fresh = make_state()
    state.update(fresh)
    return jsonify({"success": True})

if __name__ == '__main__':
    # threaded=True handles concurrent requests from multiple team browsers
    # debug=False prevents the interactive debugger being exposed on the network
    # use_reloader=False prevents a file save mid-exercise from restarting and wiping state
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True, use_reloader=False)
