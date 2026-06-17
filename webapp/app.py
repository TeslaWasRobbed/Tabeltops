import csv
import json
import os
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
            "speed": 10,           # incident-seconds per real-second
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
