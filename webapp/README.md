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
