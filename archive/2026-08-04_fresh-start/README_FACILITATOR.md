# Shadow AI / Developer Supply-Chain Tabletop — Facilitator Guide

## Overview

This exercise simulates a Microsoft Sentinel and Microsoft Defender XDR investigation using **watchlists as fake log tables**. Analysts investigate ambiguous developer-workflow telemetry following alerts for script execution, outbound network activity, and cloud file access.

**Designed duration:** 90–120 minutes (investigation) + 30 minutes (debrief)

**Intended difficulty:** High — requires cross-table correlation, timeline construction, and calibrated conclusions.

## Learning objectives

- Triage and prioritise multiple related alerts without over-relying on a single signal
- Pivot across endpoint, identity, cloud, and email data using KQL-style queries
- Distinguish suspicious activity, confirmed execution, blocked activity, possible exposure, and confirmed exfiltration
- Apply internal policy (approved software, AI tooling, data handling, breach reporting)
- Produce an incident report suitable for SOC management review

## Package contents

| File | Role |
|------|------|
| `SecurityAlert_CL.csv` | Starting point — Defender/Sentinel-style alerts |
| `AlertEvidence_CL.csv` | Alert-to-entity linkage |
| `DeviceInfo_CL.csv` | Endpoint inventory |
| `DeviceProcessEvents_CL.csv` | Process execution trail |
| `DeviceNetworkEvents_CL.csv` | Outbound network activity |
| `DeviceFileEvents_CL.csv` | File create/rename/delete |
| `SigninLogs_CL.csv` | Entra ID sign-in telemetry |
| `CloudAppEvents_CL.csv` | M365 / SharePoint activity |
| `EmailEvents_CL.csv` | Email security events |
| `IdentityInfo_CL.csv` | User enrichment |
| `ANALYST_BRIEFING.md` | Handout for participants (no spoilers) |
| `STARTER_KQL.md` | Seed queries for analysts |
| `FACILITATOR_ANSWER_KEY.md` | Ground truth and facilitation notes |
| `FACILITATOR_VALIDATION_KQL.md` | Queries to validate data / reveal timeline |
| `SCORING_RUBRIC.md` | Team scoring guide |
| `INCIDENT_REPORT_TEMPLATE.md` | Expected deliverable structure |
| `generate_exercise_data.py` | Regenerates CSVs (optional) |

## Sentinel setup (watchlists)

1. In Microsoft Sentinel, create a watchlist for each `*_CL.csv` file located in the `watchlists/` folder.
2. Name watchlists to match table names used in KQL (e.g. `SecurityAlert_CL`).
3. Upload CSV with **first row as header**; map columns to matching names.
4. Ensure datetime columns (`TimeGenerated`, `Timestamp`, etc.) are typed as datetime where supported.
5. For dynamic JSON columns (`ExtendedProperties`, `Entities`, `AdditionalFields`, etc.), store as string if dynamic parsing is unavailable; analysts can use `parse_json()`.

> **Tip:** If your lab cannot ingest dynamic types, string JSON still supports `parse_json()` in Log Analytics queries against watchlists.

## Recommended flow

1. **Brief analysts** using `ANALYST_BRIEFING.md` only.
2. Provide access to the Flask Web App for the interactive exercise.
3. Provide `STARTER_KQL.md` and `INCIDENT_REPORT_TEMPLATE.md`.
4. Allow 90–120 minutes for investigation and report draft.
5. Use `FACILITATOR_VALIDATION_KQL.md` during debrief to walk through ground truth.
6. Score teams using the Web App Leaderboard and `SCORING_RUBRIC.md`.
7. Discuss acceptable outcome range (see answer key — **C** is canonical; **A** is defensible with caveats).

## Web App Setup

1. Ensure Python 3.x is installed.
2. Install dependencies: `pip install flask`
3. Run the application: `python webapp/app.py`
4. Access the dashboard at `http://localhost:5000`
5. Access the facilitator controls at `http://localhost:5000/facilitator`

## Inject timing (optional)

| Time | Inject |
|------|--------|
| T+0 | Briefing and first alert visible |
| T+25 | “User reports slow laptop after npm install” (verbal — no new data) |
| T+45 | “Data Platform owner asks if customer analytics data was taken” (verbal) |
| T+60 | “Helpdesk confirms VPN ticket VPN-48291 for Jordan Velez this morning” (supports sign-in false alarm) |
| T+65 | “Cato Syversen confirms he is traveling to Dublin and using the corporate VPN” (supports Cato travel false alarm) |
| T+75 | “Compliance asks whether breach notification threshold is met” (policy pressure) |

## Ground truth summary (facilitator only)

- **Primary user:** `jordan.velez@creditsafe.com`
- **Primary device:** `CS-DEV-01982`
- **Canonical outcome:** **C** — suspicious activity partially blocked; inconclusive for confirmed breach without further forensics
- **Strong alternate:** **A** — compromised endpoint via malicious package supply chain, if teams weight process/network evidence heavily but acknowledge no confirmed exfiltration

See `FACILITATOR_ANSWER_KEY.md` for full detail.

## Regenerating data

```powershell
python generate_exercise_data.py
```

Re-upload watchlists after regeneration.

## Safety

All data is fictional. No real credentials, customer data, or organisational identifiers are included.
