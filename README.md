# Tabletop SIEM Exercise

This repository contains the active Sentinel-style tabletop application, the Storm-2077 exercise design and the authoritative inputs used to build its simulated telemetry.

## Project layout

| Path | Purpose |
| --- | --- |
| `webapp/` | Active analyst application and Kusto query integration |
| `tests/` | Application tests |
| `scenario/schema/` | Authoritative table schemas, including the approved `CiscoASA_CL` custom schema |
| `scenario/SCENARIO_ROSTER.csv` | Canonical users and simulation profiles |
| `scenario/reference/sentinel-rules/` | Eight exported Sentinel analytics-rule templates |
| `docs/design/` | Canonical narrative, timeline, evidence matrix, red herrings and FreshService design |
| `docs/reference/` | Original reports and source material supplied for the exercise |
| `assets/` | Prototype images and other visual assets |
| `archive/` | Historical exercise implementations; not part of the active application |

## Design entry points

- [Combined exercise timeline](docs/design/EXERCISE_TIMELINE.md)
- [Canonical evidence matrix](docs/design/SCENARIO_EVIDENCE_MATRIX.md)
- [Red-herring plan](docs/design/RED_HERRING_PLAN.md)
- [Authoritative schema contract](docs/design/SCHEMA_CONTRACT.md)
- [FreshService interface design](docs/design/FRESHSERVICE_INTERFACE.md)
- [Early narrative notes](docs/design/plan.txt)

## Active application

Run locally with:

```powershell
python -m flask --app webapp.app run --port 5000
```

The analyst workspace is then available at `http://127.0.0.1:5000/`.

The Kusto emulator defaults to `http://127.0.0.1:8080` using the `TabletopSIEM` database. See [webapp/README.md](webapp/README.md) for configuration.

## Build constraint

A KQL table exists only when its schema is present in `scenario/schema/` or in the retained core schema set under `archive/2026-08-04_fresh-start/`. Exercise application data such as FreshService tickets is kept outside Kusto.
