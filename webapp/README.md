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

## Run locally

```powershell
python -m flask --app webapp.app run --port 5000
```

Open `http://127.0.0.1:5000/`.

The analyst query API is `POST /api/kql/query`. Kusto management commands are
blocked from the analyst workspace.
