# Active tabletop application

This directory contains the scenario-neutral application currently under development.
Historical exercise implementations remain under `archive/`.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `KUSTO_ENDPOINT` | `http://127.0.0.1:8080` | Local Kusto emulator endpoint |
| `KUSTO_DATABASE` | `TabletopSIEM` | Exercise database |
| `TABLETOP_SCENARIO_DIR` | Archived shadow-AI exercise | Active scenario package |
| `PORT` | `5000` | Flask listening port |
| `TABLETOP_STATE_DB` | `webapp/data/tabletop.db` | Persistent exercise clock, incident workflow, and audit trail |
| `TABLETOP_INGESTION_MANIFEST` | unset | Host path to the generated Kusto batch manifest |
| `KUSTO_CONTAINER_DATA_ROOT` | `/kustodata/tabletop` | Matching data path inside the Kusto container |
| `TABLETOP_BACKUP_DIR` | `/home/ubuntu/tabletop-backups` | Directory inspected by facilitator readiness checks |
| `TABLETOP_SECRET_KEY` | development fallback | Secret used to sign access sessions; set this on the VM |
| `TABLETOP_ALPHA_CODE` | `alpha-training` | Team Alpha access code; override on the VM |
| `TABLETOP_BRAVO_CODE` | `bravo-training` | Team Bravo access code; override on the VM |
| `TABLETOP_FACILITATOR_CODE` | `facilitator-training` | Facilitator access code; override on the VM |

## Run locally

```powershell
python -m flask --app webapp.app run --port 5000
```

Open `http://127.0.0.1:5000/` and sign into the assigned workspace. Direct
workspace paths are `/alpha`, `/bravo`, and `/facilitator`.

The analyst query API is `POST /api/kql/query`. Kusto management commands are
blocked from the analyst workspace.

FreshService records are loaded from `scenario/freshservice_records.json` and
served as read-only application evidence. They are shared by both teams and do
not require a Kusto rebuild when changed.

Successful and failed KQL queries, opened FreshService records, incident status
changes, and evidence bookmarks are recorded per team with exercise-relative
timestamps. The facilitator can download a ZIP grading pack containing a
printable HTML report for each team, a combined incident-decisions CSV, and the
raw exercise audit data as JSON.

After a successful KQL query, analysts can export up to 250 result rows as CSV.
The export carries a visible training-data notice, UTC generation time, database,
query hash, returned/exported counts, and spreadsheet-formula protection. The
export action is retained in the team's facilitator-visible activity trail.

## Exercise controls

Sign into the protected **Facilitator** workspace to start, pause, resume, or
reset the exercise. Team Alpha and Team Bravo share the exercise clock and
Kusto evidence, but their incident status, owners, classifications, closure
notes, and audit trails are stored independently.
Starting establishes `T+00:00`; the first day-of alert is released at `T+00:05`.
Alert state, owners, classifications, closure notes, and the analyst activity trail
are persisted in SQLite, so refreshing the browser does not reset the exercise.

## Build and load exercise data on the VM

The Kusto container maps `/home/ubuntu/kusto-data` on the host to `/kustodata`.
From the project root on the VM:

```bash
sudo mkdir -p /home/ubuntu/kusto-data/tabletop
sudo chown -R ubuntu:ubuntu /home/ubuntu/kusto-data/tabletop
python3 scenario/build_exercise_data.py --output /home/ubuntu/kusto-data/tabletop
python3 -m webapp.ingestion initialize \
  --manifest /home/ubuntu/kusto-data/tabletop/manifest.json \
  --container-root /kustodata/tabletop
```

Then set these variables before starting Flask:

```bash
export TABLETOP_INGESTION_MANIFEST=/home/ubuntu/kusto-data/tabletop/manifest.json
export KUSTO_CONTAINER_DATA_ROOT=/kustodata/tabletop
```

The initializer creates all 22 approved tables and ingests the historical
batches. Once the facilitator starts the exercise, requests from the application
ingest each due day-of batch. The SQLite ingestion ledger makes this idempotent
across page refreshes and application restarts.

When generated scenario telemetry changes, rebuilding the files alone is not
enough. After restarting the application, use the facilitator's typed **RESET**
control once to clear the Kusto tables and reload the revised historical
baseline. Do this only before participants begin and after preserving any state
that must be retained.

## Production service on the VM

Install the locked application dependencies into the virtual environment:

```bash
cd /home/ubuntu/tabletop-siem
.venv/bin/python -m pip install -r requirements.txt
```

The production service uses one Gunicorn worker with eight request threads. The
single worker preserves in-process coordination for timed ingestion, while the
threads allow the facilitator and both teams to use the application concurrently.
Install the provided unit and restart it with:

```bash
sudo cp deployment/tabletop-siem.service /etc/systemd/system/tabletop-siem.service
sudo systemctl daemon-reload
sudo systemctl enable --now tabletop-siem
```

Run the end-to-end health check at any time:

```bash
.venv/bin/python deployment/health_check.py
```

Run the non-destructive authenticated smoke test against all three workspaces:

```bash
sudo .venv/bin/python deployment/smoke_test.py --env-file /etc/tabletop-siem.env
```

It exits non-zero unless Flask, the scenario package, and the Kusto emulator are
all available. Gunicorn access and error output is captured by the systemd
journal and can be viewed with `sudo journalctl -u tabletop-siem`.

## Automatic backups and restore

Install and start the 15-minute backup timer:

```bash
sudo cp deployment/tabletop-siem-backup.service deployment/tabletop-siem-backup.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now tabletop-siem-backup.timer
```

Each run uses SQLite's online backup API, verifies the resulting database, and
stores it in `TABLETOP_BACKUP_DIR`. The newest 96 automatic `tabletop-state-*`
snapshots are retained. Manually named clean-state and pre-restore backups are
never pruned. Trigger and inspect a backup with:

```bash
sudo systemctl start tabletop-siem-backup.service
sudo systemctl status tabletop-siem-backup.service --no-pager -l
```

To restore a selected snapshot, first stop the application. The restore tool
validates the selected snapshot and creates a separate rollback copy of the
current state before replacing it:

```bash
sudo systemctl stop tabletop-siem
.venv/bin/python -m deployment.restore_state /home/ubuntu/tabletop-backups/SELECTED_BACKUP.db
sudo systemctl start tabletop-siem
.venv/bin/python deployment/health_check.py
```
