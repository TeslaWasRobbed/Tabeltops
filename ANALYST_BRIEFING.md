# Analyst Briefing — Incident INC-20260528-0042

## Initial notification

You are the assigned SOC analyst for **Incident INC-20260528-0042** (working title: *Developer workstation activity — script and cloud access alerts*).

Microsoft Defender XDR has correlated several alerts on a developer workstation in the Engineering machine group. Triage notes mention recent use of AI-assisted development tooling and a non-standard package registry. Leadership is concerned about **possible exposure of customer analytics content** held in a SharePoint project site.

Your job is to investigate using available telemetry, determine what occurred, assess impact, and recommend appropriate SOC actions.

## Business context

- The organisation is rolling out **approved AI development assistants** under a pilot policy; personal or unapproved SaaS trials are discouraged.
- Developers may use standard package managers, but **only approved registries** are permitted for production-related repositories.
- The **Data Platform** SharePoint site hosts files labeled **Customer Data**; membership is restricted but contributors include selected engineers.
- Least privilege, prompt escalation, and **breach assessment** (including Data Protection consultation) are required when customer-labelled data may have left controlled storage.
- This is a **tabletop exercise** — do not contact real users or external organisations. Role-play escalations to the facilitator.

## Available data (watchlists / tables)

Query these tables in Sentinel (names must match your workspace configuration):


| Table                    | Description                                          |
| ------------------------ | ---------------------------------------------------- |
| `SecurityAlert_CL`       | Security alerts and incident candidates              |
| `AlertEvidence_CL`       | Evidence entities tied to alerts                     |
| `DeviceInfo_CL`          | Managed device inventory                             |
| `DeviceProcessEvents_CL` | Endpoint process events                              |
| `DeviceNetworkEvents_CL` | Endpoint network connections                         |
| `DeviceFileEvents_CL`    | Endpoint file operations                             |
| `SigninLogs_CL`          | Entra ID sign-in logs                                |
| `CloudAppEvents_CL`      | M365 / SaaS activity (Defender for Cloud Apps style) |
| `EmailEvents_CL`         | Email security events                                |
| `IdentityInfo_CL`        | Identity enrichment                                  |


Seed queries are in `STARTER_KQL.md`.

## Expected deliverables

1. **Triage summary** — alert prioritisation with rationale
2. **Investigation timeline** — ordered key events with UTC timestamps
3. **Findings** — what is confirmed vs suspected vs ruled out
4. **Severity recommendation** — with justification (do not overstate)
5. **Containment / eradication / recovery** recommendations — appropriate to evidence
6. **Escalation** — who should be notified (SOC management, Service Desk, Compliance, Data Protection, engineering lead) and why
7. **Completed incident report** using the template found in the team SharePoint
8. **Lessons learned** and **detection gaps** (at least two each)

## Presentation

At **11:15**, each team will have **15 minutes** to present their findings to the room. Structure your presentation around:

- What happened (your investigation narrative)
- What you confirmed, what remains inconclusive, and what you ruled out
- Your severity and classification decision — and why
- Your containment and escalation recommendations

You will then participate in a **joint lessons learned session** at 11:45. Come prepared to discuss what detection gaps you identified and how you would address them.

## Rules of engagement

- Use **only** the provided tables and briefing materials.
- **Do not** assume malware family names from alert titles alone — validate with evidence.
- Distinguish:
  - suspicious vs confirmed malicious execution
  - blocked vs successful network activity
  - possible cloud exposure vs confirmed exfiltration
  - policy violation vs security incident
- If evidence is insufficient, state what is **inconclusive** and what additional data you would request in a real incident.
- Document **hypotheses** and what evidence supports or refutes them.
- Timebox: aim to deliver a decision-ready recommendation within the session; perfection is not required — **calibrated judgment** is.

## Starting point

Begin with `SecurityAlert_CL` around **2026-05-28 07:00–11:00 UTC**, then pivot to affected users, devices, and related evidence.

Good luck.