# Facilitator KQL Walkthrough — INC-20260528-0042

> **Facilitator use only.** This document walks through the complete investigation step-by-step, showing every query, exactly what results to expect, and what decision or pivot each finding should drive. Use it to verify the exercise works end-to-end before running it with analysts, or as a debrief guide.

---

## How to use this document

**Alert interface — the Web App:** Analysts receive and classify alerts through the exercise web app (`http://<vm-ip>:5000`). The web app acts as the SIEM alert queue — alerts appear in phases as the facilitator advances the simulation. Analysts click an alert to see its details, then use the Sentinel KQL queries below to investigate the underlying telemetry in the watchlists.

**Telemetry — Sentinel watchlists:** All the raw log data (process events, network, file events, sign-ins, cloud activity, email) lives in the uploaded watchlists. Every query in this document runs against those watchlists.

Run each query against your Sentinel workspace. Expected results are listed under each query. Column values shown are **exact matches** from the generated data — if you see different values, something is misconfigured.

**Investigation phases:**
1. [Triage — find the signal](#phase-1-triage)
2. [Pivot to device and user](#phase-2-pivot-to-device-and-user)
3. [Process chain — establish execution](#phase-3-process-chain)
4. [Network — C2 and exfil assessment](#phase-4-network-activity)
5. [File events — staging evidence](#phase-5-file-events)
6. [Identity — context and escalation path](#phase-6-identity-enrichment)
7. [Cloud activity — data access assessment](#phase-7-cloud-and-sharepoint)
8. [Email — rule out as root cause](#phase-8-email-investigation)
9. [False leads — dismiss and document](#phase-9-false-leads)
10. [Full timeline union](#phase-10-full-timeline-union)

---

## Phase 1: Triage

### Web App — Alert Phase Reference

The web app surfaces alerts in phases. As facilitator you advance the phase on the Facilitator screen. Here is what analysts see in each phase:

| Web App Phase | Alerts Surfaced | Purpose |
|---------------|----------------|---------|
| Phase 0 | 100 benign background scan alerts + sa-false-leaver-012 | Initial noise — no action needed |
| Phase 1 | sa-7f2a-9c1b-4e8d-a6f3-008 (Dublin sign-in), sa-benign-vscode-009, sa-benign-dotnet-013, sa-benign-git-011, sa-7f2a-9c1b-4e8d-a6f3-006 (email) | Early noise and false leads |
| Phase 2 | sa-7f2a-9c1b-4e8d-a6f3-005 (postinstall), sa-7f2a-9c1b-4e8d-a6f3-003 (child process), sa-7f2a-9c1b-4e8d-a6f3-001 (PowerShell — **incident root**) | Core execution chain |
| Phase 3 | sa-7f2a-9c1b-4e8d-a6f3-002 (network C2), sa-benign-dotnet-013, sa-rh-cato-travel (impossible travel), sa-benign-npm-peer-010 | C2 and false leads |
| Phase 4 | sa-7f2a-9c1b-4e8d-a6f3-004 (SharePoint volume), sa-7f2a-9c1b-4e8d-a6f3-007 (customer analytics) | Impact assessment |

Analysts classify each alert in the web app as **TP / FP / BP** to score points. They use KQL in Sentinel to investigate the underlying data and support their classification.

---

### Step 1.1 — Check active/open alerts in Sentinel

**Purpose:** Validate the alert queue in Sentinel against what the web app is surfacing. The web app shows all alerts; this query filters to only those that are still "live" (New or InProgress) — this is the analyst's priority queue.

> **Note:** The web app surfaces ALL 14 named alerts (across phases). The query below filters to only the 6 that have `Status = New` or `InProgress`. The 8 with `Status = Resolved` are already-actioned or auto-resolved alerts — analysts should still investigate them if they see them in the web app, but they won't appear here.

```kql
_GetWatchlist("SecurityAlert_CL")
| where TimeGenerated between (datetime(2026-05-28 07:00:00) .. datetime(2026-05-28 11:00:00))
| where Status in ("New", "InProgress") or IsIncident == 1
| project TimeGenerated, DisplayName, AlertSeverity, SystemAlertId, Status,
          CompromisedEntity, Tactics, Techniques, ConfidenceScore, ExtendedProperties
| order by TimeGenerated asc
```

**Expected results — exactly 6 rows:**

| Time | DisplayName | Severity | Status | SystemAlertId |
|------|------------|----------|--------|---------------|
| 09:11 | Anomalous postinstall script during package install | **High** | New | sa-7f2a-9c1b-4e8d-a6f3-005 |
| 09:13 | Suspicious child process from script interpreter | Medium | New | sa-7f2a-9c1b-4e8d-a6f3-003 |
| 09:14 | Suspicious PowerShell execution chain | **High** | New | sa-7f2a-9c1b-4e8d-a6f3-001 |
| 09:18 | Outbound connection to low-reputation host | Medium | InProgress | sa-7f2a-9c1b-4e8d-a6f3-002 |
| 10:02 | Unusual volume of SharePoint file downloads | Medium | New | sa-7f2a-9c1b-4e8d-a6f3-004 |
| 10:04 | Multiple downloads of customer analytics content | Medium | InProgress | sa-7f2a-9c1b-4e8d-a6f3-007 |

**To see all 14 named alerts (full picture including auto-resolved):**

```kql
_GetWatchlist("SecurityAlert_CL")
| where TimeGenerated between (datetime(2026-05-28 06:00:00) .. datetime(2026-05-28 11:00:00))
| where SystemAlertId startswith "sa-" and SystemAlertId !startswith "sa-benign-scan"
| project TimeGenerated, DisplayName, AlertSeverity, Status, SystemAlertId, CompromisedEntity
| order by TimeGenerated asc
```

**All 14 named alerts and their statuses:**

| Time | DisplayName | Severity | Status |
|------|------------|----------|--------|
| 06:12 | Failed sign-in for disabled former contractor account | Low | Resolved |
| 07:58 | Sign-in from unfamiliar geographic region | Low | Resolved |
| 08:05 | Software update activity for supported IDE | Informational | Resolved |
| 08:22 | dotnet restore from nuget.org | Informational | Resolved |
| 08:42 | Email reported with embedded link to external SaaS trial | Low | Resolved |
| 08:48 | Git credential manager authentication | Informational | Resolved |
| **09:11** | **Anomalous postinstall script during package install** | **High** | **New** |
| **09:13** | **Suspicious child process from script interpreter** | **Medium** | **New** |
| **09:14** | **Suspicious PowerShell execution chain** | **High** | **New** |
| **09:18** | **Outbound connection to low-reputation host** | **Medium** | **InProgress** |
| 09:25 | npm registry cache refresh on peer developer host | Informational | Resolved |
| 09:30 | Impossible travel activity | Medium | Resolved |
| **10:02** | **Unusual volume of SharePoint file downloads** | **Medium** | **New** |
| **10:04** | **Multiple downloads of customer analytics content** | **Medium** | **InProgress** |

> **Decision:** The 4 Resolved alerts before 09:11 are auto-triaged background noise. The 6 live alerts cluster around two events: the execution chain (09:11–09:18 on CS-DEV-01982) and the SharePoint access (10:02–10:04). Impossible travel (09:30) is Resolved — it was auto-actioned, but analysts should still investigate it when they see it in the web app. Prioritise the 09:11–09:18 cluster first.

---

### Step 1.2 — Check which alert is flagged as the incident root

**Purpose:** Identify the Defender-correlated incident root. Only ONE alert carries `IsIncident=1` — this is the primary pivot point.

```kql
_GetWatchlist("SecurityAlert_CL")
| where IsIncident == 1
| project TimeGenerated, DisplayName, SystemAlertId, CompromisedEntity,
          AlertSeverity, Tactics, Techniques, ExtendedProperties
```

**Expected result — exactly 1 row:**

| Field | Value |
|-------|-------|
| DisplayName | Suspicious PowerShell execution chain |
| SystemAlertId | sa-7f2a-9c1b-4e8d-a6f3-001 |
| AlertSeverity | High |
| CompromisedEntity | **CS-DEV-01982** (the affected device) |
| Tactics | Execution |
| Techniques | T1059 |

> **Decision:** The incident root is on device `CS-DEV-01982`. The affected user is found in the next step via AlertEvidence (the `AccountUpn` field). Pull evidence for this alert now.

---

### Step 1.3 — Get all evidence for the primary alert

**Purpose:** Establish the affected device and initial artefacts.

```kql
_GetWatchlist("AlertEvidence_CL")
| where AlertId == "sa-7f2a-9c1b-4e8d-a6f3-001"
| project TimeGenerated, EntityType, EvidenceRole, FileName, SHA256,
          AccountUpn, DeviceName, RemoteIP, RemoteUrl, ProcessCommandLine, AdditionalFields
| order by TimeGenerated asc
```

**Expected results (3 rows):**

| EntityType | FileName / AccountUpn / DeviceName | Key Field |
|------------|------------------------------------|-----------|
| Process | powershell.exe | ProcessCommandLine contains `-EncodedCommand` |
| Process | cmd.exe | ProcessCommandLine contains `postinstall.js` |
| Account | jordan.velez@creditsafe.com | — |

> **Decision:** Device is `CS-DEV-01982`. User is `jordan.velez@creditsafe.com`. Encoded PowerShell fired from a postinstall script. Pivot to process events on that device.

---

### Step 1.4 — Join all alerts to their evidence (overview)

**Purpose:** Quickly see which alerts have network or process evidence without querying each individually.

```kql
_GetWatchlist("SecurityAlert_CL")
| where TimeGenerated between (datetime(2026-05-28 07:00:00) .. datetime(2026-05-28 11:00:00))
| project AlertTime=TimeGenerated, DisplayName, AlertSeverity, SystemAlertId
| join kind=leftouter (
    _GetWatchlist("AlertEvidence_CL")
    | project AlertId, EntityType, EvidenceRole, DeviceName, AccountUpn, RemoteUrl, ProcessCommandLine
) on $left.SystemAlertId == $right.AlertId
| order by AlertTime asc
```

**What to observe:**
- Alerts `sa-001`, `sa-003`, `sa-005`, `sa-002` all have evidence pointing to `CS-DEV-01982` / `jordan.velez`
- Alert `sa-002` (network) has `RemoteUrl` values including `update-cdn-lab.example` and `pkg-cache-lab.invalid`
- Benign alerts (`sa-benign-*`) have minimal evidence — single host entity only

---

## Phase 2: Pivot to Device and User

### Step 2.1 — Confirm device context

**Purpose:** Understand the machine before diving into telemetry.

```kql
_GetWatchlist("DeviceInfo_CL")
| where DeviceName == "CS-DEV-01982"
| project DeviceName, MachineGroup, OSVersion, ExposureLevel, AssetValue,
          LoggedOnUsers, DeviceManualTags, MitigationStatus, SensorHealthState
```

**Expected result (1 row):**

| Field | Value |
|-------|-------|
| MachineGroup | Engineering-Developers |
| ExposureLevel | Medium |
| AssetValue | Normal |
| LoggedOnUsers | jordan.velez@creditsafe.com |
| SensorHealthState | Active |

> **Decision:** Developer machine, active sensor, medium exposure. Confirms device is under management and telemetry is reliable.

---

### Step 2.2 — Sign-in overview (who stands out tenant-wide)

**Purpose:** Before focussing on Jordan, get a tenant-wide risky sign-in view to catch any other suspicious accounts.

```kql
_GetWatchlist("SigninLogs_CL")
| where TimeGenerated between (datetime(2026-05-27 00:00:00) .. datetime(2026-05-28 12:00:00))
| summarize
    SignInCount=count(),
    Failures=countif(ResultDescription == "Failure"),
    RiskySignIns=countif(IsRisky == 1)
  by UserPrincipalName
| order by RiskySignIns desc, Failures desc, SignInCount desc
```

**What to observe:**
- Several accounts have failures (noise from 100 dummy users)
- `t.oconnor.contractor@creditsafe.com` — high failures, `IsRisky=0` (disabled account spray — false lead)
- `jordan.velez@creditsafe.com` — 1 risky sign-in
- `cato.syversen@creditsafe.com` — 1 risky sign-in (impossible travel false lead)

> **Decision:** Two accounts with risky flags — Jordan and Cato. Investigate both, starting with Jordan as the primary.

---

### Step 2.3 — Risky sign-ins only (narrow view)

**Purpose:** Filter to just the flagged sessions on the incident day.

```kql
_GetWatchlist("SigninLogs_CL")
| where TimeGenerated between (datetime(2026-05-28 06:00:00) .. datetime(2026-05-28 11:00:00))
| where IsRisky == 1 or ResultDescription == "Failure"
| extend Loc = parse_json(LocationDetails)
| project TimeGenerated, UserPrincipalName, ResultDescription, IPAddress,
          City=tostring(Loc.City), Country=tostring(Loc.CountryOrRegion),
          AppDisplayName, RiskLevelDuringSignIn, RiskDetail, SessionId, Status
| order by TimeGenerated asc
```

**Expected results:**

| Time | UserPrincipalName | City | RiskDetail | SessionId |
|------|------------------|------|-----------|-----------|
| 06:11 | t.oconnor.contractor@creditsafe.com | Cardiff | — | — |
| 07:56 | jordan.velez@creditsafe.com | Dublin | unfamiliarLocation | sess-jv-0701-aa11 |
| 09:25 | cato.syversen@creditsafe.com | Dublin | impossibleTravel | sess-cs-0925 |

> **Decision:** Jordan signed in from Dublin (unfamiliar location). Cato signed in from Dublin 85 minutes after a Cardiff sign-in (impossible travel). Both need investigation. Jordan is primary focus.

---

### Step 2.4 — Jordan's full sign-in history

**Purpose:** Establish Jordan's baseline and understand the Dublin session.

```kql
let TargetUser = "jordan.velez@creditsafe.com";
_GetWatchlist("SigninLogs_CL")
| where TimeGenerated between (datetime(2026-05-27 00:00:00) .. datetime(2026-05-28 12:00:00))
| where UserPrincipalName == TargetUser
| extend Loc = parse_json(LocationDetails)
| project TimeGenerated, ResultDescription, IPAddress,
          City=tostring(Loc.City), IsRisky, RiskLevelDuringSignIn,
          SessionId, AppDisplayName, ClientAppUsed, Status, AuthenticationDetails
| order by TimeGenerated asc
```

**Key rows to note:**

| Time | IP | City | IsRisky | SessionId | Status field |
|------|----|------|---------|-----------|--------------|
| 2026-05-27 16:40 | 10.24.18.55 | Cardiff | 0 | sess-jv-2740 | Normal |
| 2026-05-28 07:56 | 198.18.0.44 | Dublin | **1** | sess-jv-0701-aa11 | `{"additionalDetails":{"VpnCorrelation":"User on corporate VPN per helpdesk ticket VPN-48291"}}` |
| 2026-05-28 09:45 | 10.24.18.55 | Cardiff | 0 | **sess-jv-0945-dd44** | Normal |

> **Decision:** The Dublin sign-in (`07:56`) has `VPN-48291` embedded in the `Status.additionalDetails` field — explainable. Cross-reference with facilitator inject at T+60. The Cardiff session `sess-jv-0945-dd44` at 09:45 is the one that later precedes SharePoint activity. Note this session ID for cloud correlation.

---

## Phase 3: Process Chain

### Step 3.1 — All process events on CS-DEV-01982 (investigation window)

**Purpose:** See the full execution timeline on the affected device.

```kql
_GetWatchlist("DeviceProcessEvents_CL")
| where DeviceName == "CS-DEV-01982"
| where TimeGenerated between (datetime(2026-05-28 08:00:00) .. datetime(2026-05-28 10:00:00))
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName,
          InitiatingProcessCommandLine, SHA256, AccountUpn
| order by TimeGenerated asc
```

**Expected key rows (ordered):**

| Time | FileName | ProcessCommandLine (truncated) |
|------|----------|-------------------------------|
| 08:20:05 | dotnet.exe | `"dotnet.exe" restore Platform.Api.sln` |
| 08:55:10 | Code.exe | `"Code.exe" --folder-uri vscode-remote://...` |
| **09:10:28** | **node.exe** | `npm.cmd install @labdev/telemetry-helper@2.1.4 --registry https://pkg-cache-lab.invalid` |
| **09:12:45** | **cmd.exe** | `cmd.exe /d /s /c node .\node_modules\@labdev\telemetry-helper\scripts\postinstall.js` |
| **09:12:52** | **powershell.exe** | `powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand JABzAD0ATgBlAH...` |
| **09:14:10** | **powershell.exe** | `powershell.exe -ExecutionPolicy Bypass -File C:\...\stage\collect.ps1` |
| **09:15:22** | **tar.exe** | `tar.exe -a -c -f C:\...\stage\bundle.zip C:\...\analytics-portal\.env.local` |
| 09:22:00 | npm.exe | `npm cache verify` |

> **Decision:** Clear execution chain — npm install from **unapproved registry** → postinstall → cmd → encoded PowerShell → collect.ps1 → tar staging `.env.local`. This is the incident core.

---

### Step 3.2 — Process tree view (parent-child relationships)

**Purpose:** Visually confirm the spawn chain for the incident report.

```kql
_GetWatchlist("DeviceProcessEvents_CL")
| where DeviceName == "CS-DEV-01982"
| where TimeGenerated between (datetime(2026-05-28 09:00:00) .. datetime(2026-05-28 09:30:00))
| project TimeGenerated,
          Parent=InitiatingProcessFileName,
          Child=FileName,
          ChildCmd=ProcessCommandLine,
          ParentCmd=InitiatingProcessCommandLine
| order by TimeGenerated asc
```

**Expected spawn chain:**

```
node.exe      → cmd.exe        (postinstall.js trigger)
cmd.exe       → powershell.exe (-EncodedCommand)
powershell.exe→ powershell.exe (collect.ps1)
powershell.exe→ tar.exe        (bundle.zip staging)
```

> **Decision:** Confirmed supply-chain execution. The `tar.exe` archiving `.env.local` is the staging artefact. Document SHA256 of `powershell.exe` and `collect.ps1` for containment.

---

### Step 3.3 — Find the package install with registry evidence

**Purpose:** Confirm the unapproved registry was explicitly used in the command line.

```kql
_GetWatchlist("DeviceProcessEvents_CL")
| where ProcessCommandLine has "@labdev/telemetry-helper"
| project TimeGenerated, DeviceName, AccountUpn, ProcessCommandLine,
          InitiatingProcessCommandLine, SHA256
```

**Expected result (1 row):**
- `ProcessCommandLine`: `npm.cmd install @labdev/telemetry-helper@2.1.4 --registry https://pkg-cache-lab.invalid`
- `DeviceName`: CS-DEV-01982
- `AccountUpn`: jordan.velez@creditsafe.com

> **Decision:** Policy violation confirmed — `--registry https://pkg-cache-lab.invalid` explicitly overrides approved feeds. Screenshot this for the incident report.

---

## Phase 4: Network Activity

### Step 4.1 — All outbound connections on CS-DEV-01982 (investigation window)

**Purpose:** See the full network picture and identify which connections are suspicious.

```kql
_GetWatchlist("DeviceNetworkEvents_CL")
| where DeviceName == "CS-DEV-01982"
| where TimeGenerated between (datetime(2026-05-28 08:00:00) .. datetime(2026-05-28 11:00:00))
| project TimeGenerated, ActionType, RemoteIP, RemoteUrl, RemotePort,
          Protocol, InitiatingProcessFileName, InitiatingProcessCommandLine, AdditionalFields
| order by TimeGenerated asc
```

**Key rows to identify:**

| Time | ActionType | RemoteUrl | Process | AdditionalFields |
|------|-----------|-----------|---------|-----------------|
| 08:05:30 | ConnectionSuccess | https://update.code.visualstudio.com | Code.exe | `{"BenignUpdate":true}` |
| **09:10:40** | ConnectionSuccess | https://pkg-cache-lab.invalid/... | node.exe | `{"PackageDownload":true}` |
| **09:16:44** | ConnectionSuccess | https://update-cdn-lab.example/sync/v1/channel | powershell.exe | `{"BytesOut":2048,"ProvesExfiltration":false}` |
| **09:17:02** | **ConnectionFailed** | https://exfil-gateway-lab.invalid/upload | powershell.exe | `{"BlockedBy":"NetworkProtection","Error":"ConnectionBlocked"}` |

> **Decision:** Two suspicious connections by powershell.exe — one **succeeded** (2048 bytes out to CDN-style domain), one was **blocked** by Network Protection. This is NOT confirmed exfiltration — 2048 bytes is limited and the domain name pattern suggests a C2 check-in rather than data transfer. The blocked destination is the intended upload endpoint. Document both for the incident report, classify as "activity partially blocked."

---

### Step 4.2 — Correlate network evidence to alert evidence

**Purpose:** Confirm that the URLs found in network events match what Defender flagged in evidence.

```kql
let SuspiciousUrls = _GetWatchlist("AlertEvidence_CL")
| where isnotempty(RemoteUrl)
| distinct RemoteUrl;
_GetWatchlist("DeviceNetworkEvents_CL")
| where RemoteUrl in (SuspiciousUrls)
| project TimeGenerated, DeviceName, ActionType, RemoteIP, RemoteUrl, InitiatingProcessFileName
| order by TimeGenerated asc
```

**Expected:** 2–3 rows matching the pkg-cache and update-cdn-lab URLs from the process events.

> **Decision:** Cross-source confirmation — network events and alert evidence agree on the same domains. This satisfies the "evidence-led investigation" scoring criterion.

---

### Step 4.3 — Confirm exfil attempt was blocked

**Purpose:** Specifically isolate the blocked connection for the incident report.

```kql
_GetWatchlist("DeviceNetworkEvents_CL")
| where DeviceName == "CS-DEV-01982"
| where TimeGenerated between (datetime(2026-05-28 09:15:00) .. datetime(2026-05-28 09:20:00))
| extend Af = parse_json(AdditionalFields)
| project TimeGenerated, ActionType, RemoteUrl, RemoteIP,
          BlockedBy=tostring(Af.BlockedBy), BytesOut=tostring(Af.BytesOut)
```

**Expected 2 rows:**

| Time | ActionType | RemoteUrl | BlockedBy | BytesOut |
|------|-----------|-----------|-----------|---------|
| 09:16:44 | ConnectionSuccess | https://update-cdn-lab.example/... | (empty) | 2048 |
| 09:17:02 | **ConnectionFailed** | https://exfil-gateway-lab.invalid/upload | **NetworkProtection** | (empty) |

> **Decision:** The intended upload destination was blocked. The successful connection carried only 2048 bytes — likely C2 registration/handshake, not bulk data. **Classification C is correct** — activity partially blocked, exfiltration not confirmed.

---

## Phase 5: File Events

### Step 5.1 — File events on CS-DEV-01982 (investigation window)

**Purpose:** Track what files were created, renamed, or deleted as a result of the execution chain.

```kql
_GetWatchlist("DeviceFileEvents_CL")
| where DeviceName == "CS-DEV-01982"
| where TimeGenerated between (datetime(2026-05-28 09:00:00) .. datetime(2026-05-28 11:00:00))
| project TimeGenerated, ActionType, FileName, FolderPath, SHA256,
          SensitivityLabel, InitiatingProcessFileName, AdditionalFields
| order by TimeGenerated asc
```

**Expected key rows:**

| Time | ActionType | FileName | FolderPath | SensitivityLabel |
|------|-----------|----------|------------|-----------------|
| 09:10:55 | FileCreated | postinstall.js | `...\node_modules\@labdev\...\scripts` | — |
| 09:13:05 | FileCreated | collect.ps1 | `C:\...\AppData\Local\Temp\stage` | — |
| 09:15:25 | FileCreated | bundle.zip | `C:\...\AppData\Local\Temp\stage` | — |
| 09:15:28 | FileRenamed | bundle.zip | `C:\...\AppData\Local\Temp\stage` | — |
| 09:16:00 | FileDeleted | collect.ps1 | `C:\...\AppData\Local\Temp\stage` | — |
| 10:01:00 | FileCreated | CustomerAnalytics_Q2_Draft.xlsx | `C:\...\Downloads` | **Customer Data** |

> **Decision:**
> - `collect.ps1` was **deleted** after execution — anti-forensic behaviour, supports compromise conclusion
> - `bundle.zip` was renamed — obfuscation of staging artefact
> - `CustomerAnalytics_Q2_Draft.xlsx` in `Downloads` with **Customer Data** sensitivity label — this is a local browser download from SharePoint, not an upload to external infrastructure (confirmed by `AdditionalFields`: `{"CloudSyncCopy":true,"NotExfiltration":"Local browser download after SharePoint access"}`)

---

### Step 5.2 — Check AdditionalFields on the xlsx download

**Purpose:** Confirm the xlsx arrival in Downloads is a SharePoint sync/browser download, not a C2 upload.

```kql
_GetWatchlist("DeviceFileEvents_CL")
| where FileName has "CustomerAnalytics"
| extend Af = parse_json(AdditionalFields)
| project TimeGenerated, ActionType, FileName, FolderPath,
          SensitivityLabel, CloudSyncCopy=tostring(Af.CloudSyncCopy),
          NotExfiltration=tostring(Af.NotExfiltration)
```

**Expected result:**
- `CloudSyncCopy`: true
- `NotExfiltration`: "Local browser download after SharePoint access"

> **Decision:** Local browser download only — no matching upload event to external infrastructure. Supports "possible exposure concern" not "confirmed exfiltration."

---

## Phase 6: Identity Enrichment

### Step 6.1 — Jordan's identity and group membership

**Purpose:** Confirm that Jordan is a legitimate member of DataPlatform-Contributors (explaining the SharePoint access) and identify the escalation path.

```kql
_GetWatchlist("IdentityInfo_CL")
| where AccountUPN == "jordan.velez@creditsafe.com"
| project AccountUPN, AccountDisplayName, Department, JobTitle, Manager,
          RiskLevel, RiskState, IsMFARegistered, GroupMembership,
          AssignedRoles, InvestigationPriority
```

**Expected result:**

| Field | Value |
|-------|-------|
| Department | Engineering |
| JobTitle | Software Engineer II |
| Manager | Morgan Kim |
| GroupMembership | `["Engineering","All-Staff","DataPlatform-Contributors"]` |
| RiskLevel | Medium |
| RiskState | AtRisk |
| IsMFARegistered | 1 |
| InvestigationPriority | 65 |

> **Decision:**
> - Jordan IS a `DataPlatform-Contributors` member — SharePoint access is **authorised**. This rules out "insider threat exfiltration" as a clean conclusion.
> - `RiskState: AtRisk` — Defender has flagged this account. Disable active sessions is on the table.
> - Escalation path: **Morgan Kim** (Engineering Manager).

---

### Step 6.2 — Check the disabled contractor account (false lead dismissal)

**Purpose:** Quickly rule out the failed sign-in for the disabled account.

```kql
_GetWatchlist("IdentityInfo_CL")
| where AccountUPN == "t.oconnor.contractor@creditsafe.com"
| project AccountUPN, AccountDisplayName, Department, JobTitle,
          RiskLevel, IsAccountEnabled, UserState
```

**Expected result:**
- `IsAccountEnabled`: 0
- `UserState`: Disabled

> **Decision:** Account is disabled. Failed sign-in at 06:11 is an unrelated credential spray. Dismiss and document as false lead.

---

## Phase 7: Cloud and SharePoint

### Step 7.1 — Jordan's cloud activity in the investigation window

**Purpose:** Understand what Jordan accessed in SharePoint and whether the data access is anomalous.

```kql
_GetWatchlist("CloudAppEvents_CL")
| where Timestamp between (datetime(2026-05-28 09:00:00) .. datetime(2026-05-28 11:00:00))
| where AccountId == "jordan.velez@creditsafe.com"
| extend Raw = parse_json(RawEventData)
| extend Sess = parse_json(SessionData)
| project Timestamp, ActionType, ObjectName, Application,
          SensitivityLabel=tostring(Raw.SensitivityLabel),
          UncommonForUser, SessionId=tostring(Sess.SessionId), IPAddress
| order by Timestamp asc
```

**Expected results (5–6 rows):**

| Time | ActionType | ObjectName | SensitivityLabel | UncommonForUser |
|------|-----------|------------|-----------------|-----------------|
| 09:56 | FilePreviewed | README.md | Internal | `{"Score":10}` |
| 09:58 | **FileDownloaded** | **CustomerAnalytics_Q2_Draft.xlsx** | **Customer Data** | **`{"Score":72,"Reason":"Rare download of labeled file"}`** |
| 09:59 | FileDownloaded | schema-v2.json | Internal | `{"Score":10}` |
| 10:00 | **FileAccessed** | **CustomerAnalytics_Q2_Draft.xlsx** | **Customer Data** | **`{"Score":72,...}`** |
| 10:02 | FileListed | Shared Documents | Internal | `{"Score":10}` |

> **Decision:**
> - `CustomerAnalytics_Q2_Draft.xlsx` was downloaded with `UncommonForUser.Score=72` — flagged as unusual for this user
> - The download occurred ~44 minutes after the malicious script execution on the same device
> - However: `MembershipVerified:true` in `AdditionalFields`, and the IP (`10.24.18.55`) is the corporate Cardiff network — this looks like normal browser activity, not a scripted exfil
> - **Assessment:** Possible data exposure concern; not confirmed exfiltration. Trigger Data Protection consultation, not breach declaration.

---

### Step 7.2 — Correlate SharePoint session back to sign-in log

**Purpose:** Confirm the SharePoint session is the Cardiff corporate session, not the risky Dublin VPN session.

```kql
let TargetSession = "sess-jv-0945-dd44";
_GetWatchlist("SigninLogs_CL")
| where SessionId == TargetSession
| project TimeGenerated, UserPrincipalName, SessionId, CorrelationId,
          IPAddress, AppDisplayName, IsRisky
```

**Expected result:**
- `IPAddress`: 10.24.18.55 (corporate Cardiff)
- `IsRisky`: 0
- `AppDisplayName`: Microsoft Office

> **Decision:** The SharePoint downloads used the **normal Cardiff corporate session**, not the risky Dublin VPN session. This further supports "authorised access path" for the cloud activity.

---

## Phase 8: Email Investigation

### Step 8.1 — Investigate the reported email (false lead)

**Purpose:** Determine whether the AI trial email is the initial access vector.

```kql
_GetWatchlist("EmailEvents_CL")
| where NetworkMessageId == "nm-ext-ai-trial-7c4a9b2e-001"
| extend Auth = parse_json(AuthenticationDetails)
| extend Af = parse_json(AdditionalFields)
| project TimeGenerated, Subject, SenderFromAddress, UrlCount,
          ThreatTypes, ThreatClassification, DeliveryAction,
          SPF=tostring(Auth.SPF), DKIM=tostring(Auth.DKIM), DMARC=tostring(Auth.DMARC),
          UserReportedPhish=tostring(Af.UserReportedPhish),
          RootCause=tostring(Af.RootCause)
```

**Expected result:**
- `Subject`: "Exclusive trial: AI pair-programming for enterprise repos"
- `SPF`: Pass, `DKIM`: Pass, `DMARC`: Pass
- `ThreatTypes`: Phish (low confidence)
- `DeliveryAction`: Delivered
- `UserReportedPhish`: true
- `RootCause`: "Unrelated marketing"
- Arrived at **08:35** — 35 minutes **before** the npm install at 09:10

> **Decision:** Email arrived before the npm install but there is **no process-level linkage** — no browser process spawning node, no click-to-install chain visible in DeviceProcessEvents. Dismiss as coincidental marketing email. **Not the root cause.**

---

### Step 8.2 — Investigate Cato Syversen spoofed emails (false lead)

**Purpose:** Determine whether the emails claiming to be from the CEO are a threat.

```kql
_GetWatchlist("EmailEvents_CL")
| where SenderFromAddress == "cato.syversen@creditsafe.com"
| extend Auth = parse_json(AuthenticationDetails)
| project TimeGenerated, Subject, SenderFromAddress, DeliveryAction, ThreatTypes,
          SPF=tostring(Auth.SPF), DKIM=tostring(Auth.DKIM), DMARC=tostring(Auth.DMARC)
| order by TimeGenerated asc
```

**Expected results (50 rows):**
- All `DeliveryAction`: Junk
- All `SPF`: Fail, `DKIM`: Fail, `DMARC`: Fail
- Timestamps spread 07:00–11:00 on 2026-05-28

> **Decision:** 50 emails claiming to be from the CEO all fail authentication checks and were delivered to Junk. These are spoofed phishing/spam emails, not from Cato Syversen's account. **False lead — dismiss.** No action on the CEO account warranted from this.

---

## Phase 9: False Leads

### Step 9.1 — Cato Syversen impossible travel (false lead)

**Purpose:** Determine whether the CEO's impossible travel alert is a real account compromise.

```kql
_GetWatchlist("SigninLogs_CL")
| where UserPrincipalName == "cato.syversen@creditsafe.com"
| extend Loc = parse_json(LocationDetails)
| project TimeGenerated, IPAddress, City=tostring(Loc.City),
          Country=tostring(Loc.CountryOrRegion), IsRisky, RiskDetail,
          AuthenticationDetails, SessionId, Status
| order by TimeGenerated asc
```

**Expected results (2 rows):**

| Time | IP | City | Country | IsRisky | RiskDetail |
|------|----|------|---------|---------|-----------|
| 08:00 | 10.24.12.99 | Cardiff | GB | 0 | — |
| 09:25 | 198.18.0.45 | Dublin | IE | 1 | **impossibleTravel** |

> **Decision:** Cardiff at 08:00, Dublin at 09:25 — 85 minutes, ~290km. Potentially suspicious. However: facilitator inject at T+65 confirms "Cato is travelling to Dublin and using corporate VPN." The Dublin IP `198.18.0.45` is in the Cisco AnyConnect range (`198.18.x.x`). Check `Status` field for VPN context. **Dismiss as false lead — confirmed VPN use.**

---

### Step 9.2 — Benign alert filter (confirm these are safe)

**Purpose:** Confirm the background scan and maintenance alerts are truly informational.

```kql
_GetWatchlist("SecurityAlert_CL")
| where SystemAlertId startswith "sa-benign"
| project TimeGenerated, DisplayName, AlertSeverity, Status, CompromisedEntity, ExtendedProperties
```

**Expected:** All alerts with `Status: Resolved` and `AlertSeverity: Informational` or `Low`. None on `CS-DEV-01982`.

> **Decision:** All benign alerts are on different hosts or are background scan noise. None link to `jordan.velez` or the incident device. Deprioritise.

---

### Step 9.3 — Disabled contractor spray (false lead)

**Purpose:** Rule out t.oconnor.contractor as a related threat actor.

```kql
_GetWatchlist("SigninLogs_CL")
| where UserPrincipalName == "t.oconnor.contractor@creditsafe.com"
| project TimeGenerated, IPAddress, ResultDescription, IsRisky, RiskDetail, AppDisplayName
| order by TimeGenerated asc
```

**Expected:** Multiple `ResultDescription: Failure` rows across different times. All `IsRisky: 0`.

> **Decision:** Disabled account experiencing external credential spray. Unrelated to this incident. Note as a separate detection gap (no alert fired for spray on disabled account) but do not include in incident scope.

---

## Phase 10: Full Timeline Union

### Step 10.1 — Cross-source timeline (the money query)

**Purpose:** Produce the definitive incident timeline by unioning all relevant sources. This is what gets pasted into the incident report.

```kql
let start = datetime(2026-05-28 08:00:00);
let end   = datetime(2026-05-28 11:00:00);
let device = "CS-DEV-01982";
union isfuzzy=true
    (_GetWatchlist("DeviceProcessEvents_CL")
     | where DeviceName == device and TimeGenerated between (start .. end)
     | extend Source="Process", Detail=strcat(FileName, " | ", ProcessCommandLine)),
    (_GetWatchlist("DeviceNetworkEvents_CL")
     | where DeviceName == device and TimeGenerated between (start .. end)
     | extend Source="Network", Detail=strcat(ActionType, " | ", RemoteUrl)),
    (_GetWatchlist("DeviceFileEvents_CL")
     | where DeviceName == device and TimeGenerated between (start .. end)
     | extend Source="File", Detail=strcat(ActionType, " | ", FileName)),
    (_GetWatchlist("SecurityAlert_CL")
     | where TimeGenerated between (start .. end)
     | where CompromisedEntity has "jordan.velez"
     | extend Source="Alert", Detail=strcat(DisplayName, " [", AlertSeverity, "]")),
    (_GetWatchlist("CloudAppEvents_CL")
     | where AccountId == "jordan.velez@creditsafe.com"
     | where Timestamp between (start .. end)
     | extend Source="Cloud", Detail=strcat(ActionType, " | ", ObjectName))
| project TimeGenerated, Source, Detail
| order by TimeGenerated asc
```

**Expected timeline output (key rows):**

| Time | Source | Detail |
|------|--------|--------|
| 08:20:05 | Process | dotnet.exe \| "dotnet.exe" restore Platform.Api.sln |
| 08:50:00 | Cloud | FilePreviewed \| Sprint-24-Goals.docx |
| 08:55:10 | Process | Code.exe \| "Code.exe" --folder-uri ... |
| 09:10:28 | Process | node.exe \| npm.cmd install @labdev/telemetry-helper@2.1.4 ... pkg-cache-lab.invalid |
| 09:10:40 | Network | ConnectionSuccess \| https://pkg-cache-lab.invalid/... |
| 09:10:55 | File | FileCreated \| postinstall.js |
| 09:11:48 | Alert | Anomalous postinstall script during package install [High] |
| 09:12:45 | Process | cmd.exe \| cmd.exe /d /s /c node .\...\postinstall.js |
| 09:12:52 | Process | powershell.exe \| powershell.exe -NoProfile ... -EncodedCommand ... |
| 09:13:01 | Alert | Suspicious child process from script interpreter [Medium] |
| 09:13:05 | File | FileCreated \| collect.ps1 |
| 09:14:10 | Process | powershell.exe \| ... -File ...\collect.ps1 |
| 09:14:22 | Alert | Suspicious PowerShell execution chain [High] |
| 09:15:22 | Process | tar.exe \| tar.exe -a -c -f ...\bundle.zip ...\.env.local |
| 09:15:25 | File | FileCreated \| bundle.zip |
| 09:15:28 | File | FileRenamed \| bundle.zip |
| 09:16:00 | File | FileDeleted \| collect.ps1 |
| 09:16:44 | Network | ConnectionSuccess \| https://update-cdn-lab.example/... |
| 09:17:02 | Network | ConnectionFailed \| https://exfil-gateway-lab.invalid/upload |
| 09:18:05 | Alert | Outbound connection to low-reputation host [Medium] |
| 09:56:00 | Cloud | FilePreviewed \| README.md |
| 09:58:30 | Cloud | FileDownloaded \| CustomerAnalytics_Q2_Draft.xlsx |
| 10:00:48 | Cloud | FileAccessed \| CustomerAnalytics_Q2_Draft.xlsx |
| 10:02:00 | Cloud | FileListed \| Shared Documents |
| 10:02:33 | Alert | Unusual volume of SharePoint file downloads [Medium] |
| 10:04:18 | Alert | Multiple downloads of customer analytics content [Medium] |

---

## Final Conclusions Checklist

Use this table to verify analysts reached the correct decision on each question:

| Question | Correct Answer | Evidence |
|----------|---------------|---------|
| Primary user | jordan.velez@creditsafe.com | CompromisedEntity on sa-001, DeviceProcessEvents AccountUpn |
| Primary device | CS-DEV-01982 | AlertEvidence DeviceName, DeviceProcessEvents |
| Initial access vector | Malicious npm package `@labdev/telemetry-helper@2.1.4` from `pkg-cache-lab.invalid` | DeviceProcessEvents 09:10 |
| Was exfiltration confirmed? | **No** — primary upload destination blocked | DeviceNetworkEvents 09:17 ConnectionFailed, BlockedBy NetworkProtection |
| Was any data sent externally? | 2048 bytes to update-cdn-lab.example — **not confirmed as data** | DeviceNetworkEvents 09:16, AdditionalFields.ProvesExfiltration=false |
| Was CustomerAnalytics accessed? | Yes — downloaded to local Downloads folder | CloudAppEvents 09:58, DeviceFileEvents 10:01 |
| Was that download an exfil? | **No** — corporate IP, authorised SharePoint member, browser session | CloudAppEvents AdditionalFields.MembershipVerified, DeviceFileEvents AdditionalFields.CloudSyncCopy |
| Is email the root cause? | **No** — arrived 35 min before npm install, no process linkage | EmailEvents 08:35, no chain in DeviceProcessEvents |
| Is Cato's travel suspicious? | **No** — VPN confirmed | SigninLogs Status.VpnCorrelation, facilitator inject T+65 |
| Are spoofed CEO emails a threat? | **No** — Junk delivery, SPF/DKIM/DMARC all fail | EmailEvents AuthenticationDetails |
| Severity | **Medium** (High defensible) | No confirmed exfil; script execution + C2 callback |
| Classification | **C** — partially blocked; inconclusive for breach | Network blocked + no confirmed exfil proof |
| Containment priority | Isolate CS-DEV-01982, block 3 domains, preserve artefacts | Standard IR |
| Escalation | Morgan Kim, Data Platform owner, Compliance/DPO assessment | IdentityInfo Manager field |

---

## MITRE Coverage Verification

| Technique | Evidence Query |
|-----------|---------------|
| T1195.002 Supply Chain | `_GetWatchlist("DeviceProcessEvents_CL") \| where ProcessCommandLine has "pkg-cache-lab.invalid"` |
| T1059.001 PowerShell | `_GetWatchlist("DeviceProcessEvents_CL") \| where FileName == "powershell.exe" and ProcessCommandLine has "EncodedCommand"` |
| T1059.003 Cmd Shell | `_GetWatchlist("DeviceProcessEvents_CL") \| where FileName == "cmd.exe" and ProcessCommandLine has "postinstall"` |
| T1071.001 Web C2 | `_GetWatchlist("DeviceNetworkEvents_CL") \| where RemoteUrl has "update-cdn-lab.example"` |
| T1560.001 Archive | `_GetWatchlist("DeviceProcessEvents_CL") \| where FileName == "tar.exe"` |
| T1048 Exfil (attempt) | `_GetWatchlist("DeviceNetworkEvents_CL") \| where ActionType == "ConnectionFailed" and RemoteUrl has "exfil-gateway"` |
| T1530 Cloud Storage | `_GetWatchlist("CloudAppEvents_CL") \| where ActionType == "FileDownloaded" and AccountId has "jordan.velez"` |
