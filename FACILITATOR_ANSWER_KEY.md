# Facilitator Answer Key — INC-20260528-0042

> **Facilitator only.** Do not distribute to analysts before the debrief.

## Executive summary

Developer **Jordan Velez** (`jordan.velez@creditsafe.com`) on **CS-DEV-01982** installed npm package **`@labdev/telemetry-helper@2.1.4`** from an **unapproved registry** (`pkg-cache-lab.invalid`). The package **postinstall** chain spawned **cmd → PowerShell (encoded) → collect.ps1 → tar** staging local project files including `.env.local`. Outbound HTTPS to **`update-cdn-lab.example` (203.0.113.47)** succeeded with limited bytes; a second destination **`exfil-gateway-lab.invalid`** was **blocked** by network protection. SharePoint downloads of **Customer Data**-labeled content occurred later via normal browser/O365 session — **possible policy and exposure concern**, but **no telemetry proves exfiltration** of those files to external infrastructure.

**Canonical classification: C** — suspicious activity partially blocked; remains inconclusive for confirmed organisational breach without additional forensics (disk image, DLP, proxy full PCAP, package reverse engineering).

**Defensible alternate: A** — endpoint compromise via supply-chain package, if analysts emphasise unauthorized script execution and C2-style domain contact while acknowledging blocked exfil path.

**Incorrect as final answer:**
- **B** — ignores malicious postinstall and successful callback to low-reputation domain
- **D** — overclaims; no confirmed data exfiltration, no persistence, blocked upload destination

**Recommended severity:** **Medium** (raise to **High** if organisational risk tolerance treats any Customer Data label access + script execution as High pending IR validation)

---

## Expected timeline (UTC)

| Time | Source | Event |
|------|--------|-------|
| 06:11 | SigninLogs | Failed sign-in **t.oconnor.contractor@creditsafe.com** (disabled) — **false lead** |
| 07:56 | SigninLogs / Alert | Jordan sign-in from Dublin IP — **explainable VPN** (Status/ExtendedProperties) |
| 08:00 | SigninLogs | Cato Syversen sign-in from Cardiff — **benign** |
| 08:05 | Process/Network/Alert | VS Code update to vendor CDN — **benign** |
| 08:20 | Process/Network/Alert | `dotnet restore` — **benign** |
| 08:35 | Email | External AI trial marketing email — **unrelated root cause** |
| 08:35+ | Email | Spoofed emails claiming to be from Cato Syversen — **false lead (Spam)** |
| 08:48 | Alert | Git credential manager — **benign** |
| 09:10 | Process/Network/File | `npm install @labdev/telemetry-helper` from **pkg-cache-lab.invalid** |
| 09:12 | Process/Alert/Evidence | **postinstall.js** → cmd → **encoded PowerShell** |
| 09:14 | Process | collect.ps1 executed |
| 09:15 | Process/File | **tar** creates `bundle.zip` / rename — staging; **not upload** |
| 09:16 | Network | HTTPS **success** to `update-cdn-lab.example` / 203.0.113.47 |
| 09:17 | Network | Connection **failed/blocked** to `exfil-gateway-lab.invalid` |
| 09:22 | Process/Network | `npm cache verify` — **benign noise** |
| 09:25 | SigninLogs / Alert | Cato Syversen sign-in from Dublin IP — **explainable VPN** (Impossible Travel false lead) |
| 09:56–10:02 | CloudApp / File | SharePoint preview/download/list — includes **CustomerAnalytics_Q2_Draft.xlsx** |
| 10:01 | File | Local copy under Downloads via Chrome — **sync/copy**, not C2 upload |

---

## Alert classification guide

### True positives (incident-related)

| SystemAlertId | DisplayName | Notes |
|---------------|-------------|-------|
| sa-7f2a-9c1b-4e8d-a6f3-001 | Suspicious PowerShell execution chain | Core execution evidence |
| sa-7f2a-9c1b-4e8d-a6f3-003 | Suspicious child process from script interpreter | npm → cmd → ps chain |
| sa-7f2a-9c1b-4e8d-a6f3-005 | Anomalous postinstall script during package install | Supply-chain entry |
| sa-7f2a-9c1b-4e8d-a6f3-002 | Outbound connection to low-reputation host | Success + blocked related |

### Policy / impact alerts (true but different conclusion)

| SystemAlertId | DisplayName | Notes |
|---------------|-------------|-------|
| sa-7f2a-9c1b-4e8d-a6f3-004 | Unusual volume of SharePoint file downloads | Access ≠ exfil |
| sa-7f2a-9c1b-4e8d-a6f3-007 | Multiple downloads of customer analytics content | Triggers breach **assessment**, not proof |

### Benign positives (related appearance, not incident)

| SystemAlertId | DisplayName | Why benign |
|---------------|-------------|------------|
| sa-benign-vscode-009 | Software update activity for supported IDE | Signed vendor update |
| sa-benign-npm-peer-010 | npm registry cache refresh on peer developer host | Different host CS-DEV-01407 |
| sa-benign-git-011 | Git credential manager authentication | Expected DevOps workflow |
| sa-benign-dotnet-013 | dotnet restore from nuget.org | Standard feed |
| sa-rh-cato-travel | Impossible travel activity | Confirmed VPN usage |

### False leads to rule out

| Lead | Ruling |
|------|--------|
| Email sa-7f2a-9c1b-4e8d-a6f3-006 (AI trial) | No temporal/process linkage to npm install; user-reported marketing |
| Sign-in sa-7f2a-9c1b-4e8d-a6f3-008 (Dublin) | VPN ticket VPN-48291 in ExtendedProperties / AuthenticationDetails context |
| sa-false-leaver-012 | Disabled contractor account — unrelated spray |
| tar.zip staging | Suspicious appearance; **AdditionalFields** explain package-local staging; **no** matching upload success |
| sa-rh-cato-travel | VPN context in logs confirms benign travel from Cardiff to Dublin for Cato Syversen |
| Cato Syversen Spoofed Emails | 50 inbound emails claiming to be from Cato fail SPF/DKIM/DMARC and are classified as Spam |

---

## Key evidence by table

### SecurityAlert_CL
- Cluster on CS-DEV-01982 / jordan.velez between 09:10–10:05
- `ExtendedProperties` on package alert documents registry host
- Incident flag on primary PowerShell alert only (`IsIncident=1`)

### AlertEvidence_CL
- Join `AlertId` to `SystemAlertId`
- Process evidence shows parent command lines for npm postinstall
- Network evidence: `ConnectionStatus` Success vs BlockedByFirewall in AdditionalFields

### DeviceProcessEvents_CL
- Full chain: node (npm) → cmd → powershell (encoded) → powershell (collect.ps1) → tar
- **Misleading benign:** tar archiving `.env.local` — investigate but correlate with network (no exfil)

### DeviceNetworkEvents_CL
- **Success:** 203.0.113.47 / update-cdn-lab.example — does not prove data theft
- **Blocked:** exfil-gateway-lab.invalid — partial control effectiveness

### DeviceFileEvents_CL
- postinstall.js, collect.ps1, bundle.zip rename/delete
- Customer analytics xlsx in Downloads with sensitivity label — **possible exposure**, local only

### SigninLogs_CL
- **~180 rows** across 100+ accounts (2026-05-27–28); Jordan has ~15 sign-ins — not obvious from row count alone
- Session `sess-jv-0945-dd44` correlates to cloud activity
- Dublin sign-in: parse `Status` / LocationDetails / facilitator inject VPN-48291
- **False parallels:** Noah Banks (Edinburgh/travel), Priya Nair (Paris workshop IT-44821), multiple contractor failures, Cato Syversen (Dublin VPN)
- Service accounts (`svc-pipeline`, `svc-scanner`) provide non-interactive noise

### CloudAppEvents_CL
- Downloads are authenticated SharePoint actions for site member
- `UncommonForUser` elevated for labeled file — risk signal, not exfil proof
- `RawEventData` / `AdditionalFields`: membership verified

### EmailEvents_CL
- NetworkMessageId `nm-ext-ai-trial-7c4a9b2e-001` — SPF/DKIM pass; low phish confidence
- 50 spoofed emails claiming to be from Cato Syversen — fail SPF/DKIM/DMARC, sent to Junk

### IdentityInfo_CL
- Jordan: Engineering, DataPlatform-Contributors, MFA registered
- Manager: Morgan Kim — escalation path
- svc-pipeline / disabled contractor for context only

---

## What supports compromise vs what does not

| Supports compromise (execution) | Does NOT prove |
|----------------------------------|----------------|
| Unauthorized postinstall shell chain | Customer Data left the tenant |
| Encoded PowerShell | Email was initial access vector |
| Successful call to low-rep domain | Persistence (no services/registry evidence) |
| Staging archive under %TEMP% | Full breach declaration |

---

## Severity recommendation

- **Medium** for SOC handling with IR consultation
- Escalate toward **High** if combining: Customer Data label download + script execution + unapproved registry
- **Not Critical** unless organisational policy mandates Critical for any Customer Data access anomaly

---

## Containment recommendations

1. **Isolate** CS-DEV-01982 from network (allow SOC tooling)
2. **Disable** active sessions for jordan.velez only if parallel sign-in risk confirmed (optional here)
3. **Preserve** EDR quarantine artifacts, `%TEMP%\stage`, npm cache, `node_modules\@labdev\telemetry-helper`
4. **Block** pkg-cache-lab.invalid, update-cdn-lab.example, exfil-gateway-lab.invalid at proxy/firewall
5. **Do not** mass-disable Engineering group

---

## Eradication / recovery

- Reimage or clean rebuild developer workstation
- Rotate secrets in `.env.local` and any API keys in project scope
- Remove malicious package from internal mirrors; scan CI/CD agents
- Validate lockfile and registry configuration (`npm config get registry`)

---

## Escalation recommendations

| Audience | When |
|----------|------|
| SOC management | Immediate — potential supply-chain execution |
| Engineering manager (Morgan Kim) | User context, approved tooling policy |
| Data Platform owner | Customer Data file access |
| Compliance / Data Protection | Possible exposure assessment — **not** confirmed breach notification unless policy threshold met |
| Service Desk | VPN validation already supports sign-in — coordinate user contact via manager |

---

## Evidence capture checklist

- [ ] Export all rows for CS-DEV-01982 and jordan.velez across tables (UTC window)
- [ ] AlertEvidence for SystemAlertIds sa-7f2a-9c1b-4e8d-a6f3-001 through 007
- [ ] Process command lines and SHA256 for postinstall.js, powershell, collect.ps1
- [ ] Network events to 203.0.113.47 and blocked exfil-gateway-lab.invalid
- [ ] CloudAppEvents for CustomerAnalytics_Q2_Draft.xlsx
- [ ] npm install command line and package version metadata
- [ ] IdentityInfo for group membership justification

---

## Policy areas relevant

- Approved package registries and dependency pinning
- AI development tooling pilot policy
- Customer Data labeling and SharePoint access
- Breach notification threshold and DLP alignment
- Least privilege for developer access to analytics sites

---

## Detection gaps

- No alert on unapproved registry until postinstall execution
- Limited script block logging (`ScriptBlockLogging: partial` in ExtendedProperties)
- Cloud download volume alert lacks business justification context
- Peer device npm noise may cause alert fatigue

---

## Lessons learned (facilitator talking points)

- Enforce registry allowlists in CI and on endpoints
- Treat postinstall scripts as high-risk in developer profiles
- Improve correlation between endpoint staging and cloud DLP outcomes
- Runbooks for “labeled data access + endpoint script” combined decision tree

---

## MITRE ATT&CK mapping

| Tactic | Technique | Evidence |
|--------|-----------|----------|
| Initial Access | T1195.002 Supply Chain Compromise | Malicious npm package / postinstall |
| Execution | T1059.001 PowerShell | Encoded command |
| Execution | T1059.003 Windows Command Shell | cmd.exe parent |
| Command and Control | T1071.001 Web Protocols | HTTPS to update-cdn-lab.example |
| Collection | T1560.001 Archive via Utility | tar.zip staging |
| Exfiltration | T1048 (attempt) | **Blocked** exfil-gateway-lab.invalid |
| Collection | T1530 Data from Cloud Storage | SharePoint download (authorized access path) |

---

## Acceptable analyst outcome matrix

| Outcome | Accept if… |
|---------|------------|
| **C** | Partial block cited; breach not declared; further forensics requested |
| **A** | Supply-chain compromise argued; still acknowledges no confirmed exfil |
| **B** | **Reject** — insufficient engagement with postinstall/C2 |
| **D** | **Reject** — overclaim on breach/exfil without evidence |
