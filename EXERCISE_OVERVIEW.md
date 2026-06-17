# SOC Tabletop Exercise — Manager Overview

**Exercise name:** Shadow AI / Developer Supply-Chain Incident  
**Format:** Competitive two-team tabletop  
**Intended duration:** 09:00–12:00 (3 hours total — ~2 hours investigation, ~1 hour debrief)  
**Difficulty:** High  

---

## Purpose

This exercise develops and assesses the practical incident response skills of SOC analysts by placing them in a realistic, time-pressured investigation scenario. Teams must identify a realistic threat, correlate evidence across multiple data sources, avoid false leads, and produce a decision-ready recommendation — all under competitive scoring conditions.

The exercise is specifically designed to be **difficult to solve with AI assistance alone**, requiring genuine analytical judgment and cross-table correlation to reach the correct conclusion.

---

## Scenario Summary

A developer workstation at Creditsafe has generated a cluster of security alerts. Analysts are told there has been suspicious activity on an engineering device and that leadership is concerned about possible exposure of customer analytics content in SharePoint.

The underlying incident involves a malicious npm package installed from an unapproved registry. The package's postinstall script spawned an encoded PowerShell chain, staged local project files, and attempted to exfiltrate them — with one destination blocked by Network Protection and a second succeeding with a limited data transfer. The affected developer subsequently accessed Customer Data-labeled SharePoint content via a legitimate, authorised session.

**The correct conclusion is deliberately ambiguous:** the incident is partially blocked with no confirmed exfiltration, requiring analysts to resist the temptation to either under- or over-declare. Teams must distinguish between what is confirmed, what is suspected, and what is inconclusive.

---

## What Skills Are Assessed

| Area | What we are testing |
|------|-------------------|
| Alert triage | Can analysts identify the signal within noise and correctly prioritise? |
| KQL / pivot ability | Can analysts query across 10 log tables and join evidence correctly? |
| Timeline construction | Can analysts place events in the correct order using timestamps? |
| Calibrated judgement | Can analysts avoid over- or under-claiming on exfiltration and breach? |
| Severity and containment | Are containment recommendations scoped and proportionate? |
| Policy awareness | Do analysts reference approved registry, AI tooling, and data handling policy? |
| Communication | Can analysts produce an executive-readable incident report? |
| Lessons learned | Can analysts identify actionable detection gaps? |

---

## Exercise Design

### Data environment
Ten simulated Microsoft Sentinel watchlist tables are uploaded to our Sentinel workspace, each containing 100–180 rows of realistic telemetry across:

- Security alerts and evidence
- Endpoint process, network, and file events
- Entra ID sign-in logs
- Microsoft 365 / SharePoint cloud activity
- Email security events
- Identity enrichment

The data includes **over 1,200 log entries** deliberately seeded with:
- Benign noise (background scans, routine developer activity)
- False leads (spoofed CEO emails, impossible travel that resolves to confirmed VPN use, a disabled contractor spray)
- Ambiguous signals that require multi-table correlation to resolve correctly

### Competitive format
Two teams compete simultaneously. A custom web application hosted on an Azure VM acts as the SIEM interface:

- Alerts stream in automatically on a compressed timeline (real incident time ~4 hours, compressed to ~24 minutes at default speed)
- Each alert received earns points when correctly classified as True Positive, Benign Positive, or False Positive
- **First-solve scoring:** only the first team to correctly classify an alert earns full points — the second team earns nothing, incentivising speed and accuracy
- Incorrect classifications incur a penalty
- A live leaderboard is visible to both teams throughout
- The facilitator can pause the simulation, adjust team scores manually for quality of KQL/report work, and send targeted hints to a struggling team

### Facilitator controls
The exercise is facilitator-run via a separate control panel. The facilitator can:
- Start, pause, and control simulation speed
- Jump to specific incident moments for demos or post-exercise walkthrough
- Send per-team hints without the other team seeing them
- Award or deduct points for qualitative work (good pivots, strong report, overclaiming)
- Reset the exercise for a second run

---

## Scoring Summary

| Category | Points |
|----------|--------|
| Alert triage and prioritisation | 15 |
| Evidence-led investigation | 15 |
| Timeline construction | 15 |
| Avoiding overclaiming | 15 |
| KQL / pivot quality | 10 |
| Correct severity decision | 10 |
| Correct containment decision | 10 |
| Policy / process awareness | 5 |
| Incident report quality | 5 |
| Lessons learned quality | 5 |
| **Total** | **100** |
| Bonus (MITRE mapping, canonical outcome, false lead documentation) | +10 |
| Penalties (overclaiming breach, wrong root cause, disproportionate response) | −5 each |

**Grading bands:**

| Score | Level |
|-------|-------|
| 90–100+ | Outstanding |
| 75–89 | Proficient |
| 60–74 | Developing |
| <60 | Requires follow-up |

---

## Learning Outcomes

Analysts who complete this exercise will have practised:

1. Triaging a realistic multi-alert incident without being handed the answer
2. Writing and executing KQL across joined data sources in Microsoft Sentinel
3. Distinguishing confirmed execution from suspected exfiltration from confirmed breach
4. Applying Creditsafe policy (approved registries, AI tooling, Customer Data handling) to an IR decision
5. Producing a complete, executive-readable incident report under time pressure
6. Identifying detection gaps and recommending actionable improvements

---

## Infrastructure Requirements

| Component | Detail |
|-----------|--------|
| Microsoft Sentinel workspace | 10 watchlists uploaded (CSV files provided) |
| Azure VM (exercise app) | Small VM (B2s), running Python/Flask web app, VNet-accessible |
| Analyst access | Browser access to Sentinel + exercise app URL |
| Facilitator access | Same VM URL, separate `/facilitator` path |

The exercise is entirely self-contained. No production systems, real users, or external services are involved. All data is fictional.

---

## Time Plan

| Clock | Activity |
|-------|----------|
| 08:30 | Facilitator pre-check: confirm Sentinel watchlists uploaded, VM app running, team URLs accessible |
| 09:00 | Welcome and scene-setting — teams receive `ANALYST_BRIEFING.md` and exercise app URL |
| 09:05 | Facilitator starts simulation — alerts begin streaming into the SIEM dashboard |
| 09:05–11:00 | **Active investigation** — teams investigate using Sentinel KQL, classify alerts, build timeline and incident report |
| 11:00 | Facilitator calls time — teams submit completed incident reports |
| 11:00–11:10 | Leaderboard review — final scores, first-solve breakdown |
| 11:10–11:55 | **Debrief** — facilitator walks through ground truth and correct investigation path using validation KQL; teams discuss their conclusions |
| 11:55–12:00 | Lessons learned, wrap-up, any follow-up actions |

---

*Exercise designed and built internally. All scenario data is synthetic and contains no real credentials, customer data, or organisational identifiers.*
