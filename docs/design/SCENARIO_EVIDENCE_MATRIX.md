# Storm-2077 / TAG-100 Canonical Evidence Matrix

## Purpose

This document is the build contract for the main incident narrative. Every material conclusion in the facilitator's completed incident report must be supported by evidence that analysts can find in the fake SIEM, the incident queue, or the separate FreshService interface.

The canonical identity population is defined in `../../scenario/SCENARIO_ROSTER.csv`. Red-herring design is defined in `RED_HERRING_PLAN.md`, and the combined elapsed-time schedule is defined in `EXERCISE_TIMELINE.md`; those events must not change or contradict the evidence below.

## Canonical scenario decisions

| Item | Canonical value |
| --- | --- |
| Exercise date | 12 November 2026 |
| Exercise timezone | UTC (the UK is on GMT on this date) |
| Exercise account | `louise.lonn@creditsafe.com` |
| Display name and role | Louise Lonn (LL), HR Analyst |
| HR shared mailbox | `hr@creditsafe.com` |
| Compromised endpoint | `CS-LL-W11-042` |
| Original analyst | Anita Job |
| Fake guest | `hradvisor@rnicrosoft.com` |
| External forwarding target | `craiglonn@gmail.com` |
| Threat actor | TAG-100 is the internal tracking name for activity assessed as Storm-2077 |
| Malware | SparkRAT, installed through a ClickFix PowerShell command |
| C2 domain | `aeifile.offiec.us.kg` |
| C2 exercise IP | `209.141.46.83`, a published TAG-100 C2 indicator used only as static simulated telemetry |
| Historical UK VPN IP | `192.0.2.85`, represented as ExpressVPN in Birmingham |
| Historical China VPN IP | `203.0.113.44`, represented as ExpressVPN in China |
| Download analytic | Alert when one account downloads `>= 50` files in a rolling one-hour window |
| Confirmed exfiltration | Archives shared with and downloaded by the fake guest |
| Blocked exfiltration | Separate attempt to transfer archives to a personal OneDrive account |

All addresses, domains, hashes, IDs and ticket numbers are included only as exercise data. The application must not send messages or make network requests to them.

The C2 IP is taken from Recorded Future's July 2024 TAG-100 IOC appendix, where it is listed as C2 infrastructure last observed on 11 May 2024. Microsoft maps TAG-100 to Storm-2077. Because public IP infrastructure can be reassigned, the value is historical context for static exercise records only and must never be contacted by the application.

## Evidence rules

1. Historical evidence from the previous 90 days is loaded before the exercise begins.
2. Day-of raw events appear before, or at the same time as, their resulting alert. Analysts may therefore discover activity before a detection fires.
3. `Timestamp` represents when the source activity occurred. `TimeGenerated` represents when that record became available to the SIEM. Detection latency must be visible where relevant.
4. Actions recorded under Louise's identity are described as actions performed **using her compromised account**, not actions knowingly performed by Louise.
5. A password reset does not end the compromise. Anita does not revoke sessions, isolate the endpoint, remove SparkRAT, or remove persistence.
6. The two-month persistence is supported by endpoint and C2 evidence. It is not attributed to one session token remaining valid for two months.
7. Session identifiers are reused only where technically appropriate. Cross-service activity is correlated primarily through account, IP, user agent, missing device identity, timing and matching cloud audit data.
8. Only tables with a supplied or explicitly approved exercise schema exist. `CiscoASA_CL` is the sole exercise-created exception.
9. Failed and successful exfiltration are recorded separately.
10. Historical incident records retain Anita's owner, closure time, `Benign Positive` classification and inadequate closure comment.

## Fixed exercise schedule

The facilitator starts the exercise, establishing T+00:00. Historical evidence is available before the start, and day-of events and alerts are released automatically at elapsed-time offsets corresponding to the nominal times below (10:00 = T+00:00). The facilitator may pause and resume the clock for breaks or technical interruptions, but cannot manually release individual stages.

| Time | Content released | Purpose |
| --- | --- | --- |
| 10:00 | Ninety days of normal background, historical attack activity, closed alerts and tickets are available | Exercise begins; retrospective hunting is possible |
| 10:30 | Rare and potentially high-risk Office operations alert | Opening triage |
| 10:35-11:20 | Cloud searches, Purview/eDiscovery activity and threshold-evasion downloads appear | Scope and collection |
| 11:20 | The 50th download completes and crosses the analytic threshold | Collection threshold reached |
| 11:25 | Bulk-download alert appears | Escalation |
| 11:40 | Archive-in-suspicious-location alert appears | Data staging |
| 12:05-12:40 | Guest sharing/download, blocked personal OneDrive transfer and faster C2 appear | Confirm exfiltration and impact |
| 13:10-13:20 | Persistence update and clean-up appear; no C2 or Storm-2077 alert is generated | Establish duration while requiring analysts to perform their own attribution pivot |
| 13:20-14:00 | No new main-story evidence; teams consolidate findings, determine scope and assess attribution | Investigation consolidation |
| 14:00-15:00 | No new alerts or evidence; teams complete and submit their incident reports | Reporting period |
| 15:00 | Exercise ends | Close |

## Historical evidence: initial compromise and missed response

| ID | Timestamp (UTC) | Event and fact it supports | Source and essential fields | Surface behaviour | Expected analyst conclusion |
| --- | --- | --- | --- | --- | --- |
| H01 | 2026-09-03 09:08 | Spear-phishing message sent to Louise and the HR shared mailbox | `EmailEvents`: same `NetworkMessageId`, malicious sender, subject, recipients, URL count and threat classification; recipient-specific delivery and latest-delivery fields show Louise's personal copy removed while the shared-mailbox copy remains delivered | Personal copy is remediated; shared-mailbox copy remains delivered | The campaign targeted HR through individual and shared mailboxes |
| H02 | 2026-09-03 09:10 | Louise opens the shared-mailbox copy and follows its URL | `UrlClickEvents`: account, URL, message ID, IP, workload and click action; `EmailUrlInfo`: message-to-URL enrichment | Original phishing alert creates a FreshService ticket through the application workflow | Louise could still reach the message after her personal copy was removed |
| H03 | 2026-09-03 09:11 | Fake Microsoft page captures credentials and an authenticated session | `SigninLogs`: Louise, unfamiliar IP, unmanaged/empty device detail, unusual user agent, successful Exchange sign-in, elevated risk | Sign-in detection appears after a short delay | Credentials and session material were stolen |
| H04 | 2026-09-03 09:12 | ClickFix instruction launches PowerShell from the browser | `DeviceProcessEvents`: `msedge.exe` -> `powershell.exe`; encoded/download command; Louise and `CS-LL-W11-042` | Raw event; no separate alert during the missed investigation | The event was not merely a credential phish |
| H05 | 2026-09-03 09:13 | PowerShell downloads and starts SparkRAT | `DeviceFileEvents`: SparkRAT creation and origin URL; `DeviceProcessEvents`: `powershell.exe` -> SparkRAT; stable synthetic hashes | Supporting evidence attached to the original alert but overlooked | The corporate endpoint was compromised |
| H06 | From 2026-09-03 09:14 | SparkRAT begins C2 beaconing every ten minutes | `DeviceNetworkEvents`: device, SparkRAT initiating process, C2 domain/IP, HTTPS and successful connections | Historical raw events | SparkRAT provided durable remote access |
| H07 | 2026-09-03 09:18 | Louise reports the email without clearly stating that she ran PowerShell | `EmailEvents`: phish-alert notification delivered to `phishinginvestigations@creditsafe.com`, Louise, original message details and report context; separate FreshService tab: resulting ticket, requester, summary, description and created time | Notification creates/links the FreshService ticket to the original phishing incident | The report gave Anita an incomplete picture but contained enough reason to investigate further |
| H08 | 2026-09-03 09:27 | Anita resets Louise's password only | Separate FreshService tab: action and resolution note; `AuditLogs`: password reset | Ticket resolved | Sessions were not revoked and the device was not contained |
| H09 | 2026-09-03 09:34 | Original phishing incident is closed incorrectly | `SecurityIncident`: owner Anita Job, closed, Benign Positive, minimal classification comment, alert IDs | Visible in historical incidents | The initial investigation treated the event as email-only |
| H10 | 2026-09-04 14:22 | Successful Exchange/Teams access from Birmingham ExpressVPN | `SigninLogs`: Louise, `192.0.2.85`, Birmingham, unmanaged device, successful result, application-specific session values | Impossible-travel/unfamiliar-sign-in alert; Anita closes as VPN use | Post-reset access should have been correlated with the phishing case |
| H11 | 2026-09-06 11:05 | Fake HR adviser is invited as a B2B guest using Louise's identity | `AuditLogs`: `Invite external user`, actor Louise, target guest and invitation properties; `IdentityInfo`: guest object | Guest-user alert; Anita closes because the address was mistaken for Microsoft | Attacker created a cloud persistence/exfiltration path |
| H12 | 2026-09-11 02:17 | China ExpressVPN sign-in | `SigninLogs`: Louise, `203.0.113.44`, China, unmanaged device, successful sign-in and elevated risk | Impossible-travel alert; Anita closes as VPN use | The VPN explanation was accepted without comparison to Louise's baseline |
| H13 | 2026-09-19 13:40 | Louise's compromised identity is added to eDiscovery Manager and Security Reader | `AuditLogs`: both role/group assignments, actor, target and result; `IdentityInfo`: later snapshot includes both assigned roles | Raw audit evidence; optionally linked to a low-severity role-change alert that was overlooked | Explains how the attacker later accesses Purview exports and inspects Sentinel security content |
| H14 | 2026-09-28 10:00-10:42 | Attacker tests collection threshold and downloads exactly 50 personal-looking files | `CloudAppEvents` and `OfficeActivity`: 50 download operations, Louise, SharePoint/OneDrive, filenames and source IP | Bulk-download alert; Anita closes because filenames appear personal | The attacker tested the detection threshold |
| H15 | 2026-09-28 10:50 | Attacker accesses Sentinel content using Louise's Security Reader role | `SigninLogs`: Azure Portal/Log Analytics access; `AzureActivity`: successful read of the relevant Sentinel analytics-rule resource | Raw events | The attacker accessed the rule resource; the exact threshold knowledge is inferred from the subsequent repeated 49-file pattern rather than asserted from unavailable query-audit logs |
| H16 | Selected collection days from 2026-09-29 onward | Repeated groups of 49 downloads inside separate one-hour windows | `CloudAppEvents` and `OfficeActivity`: consistent account, applications and 49-count pattern mixed with normal activity | No bulk-download alert | Repetition immediately below the threshold is deliberate evasion |
| H17 | Throughout Sep-Nov 2026 | SparkRAT launches and continues low-frequency C2 after password reset | `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents` and `DeviceRegistryEvents` | Raw evidence distributed across the 90-day history | The device remained compromised for about two months; persistence did not depend on one old token |
| H18 | 2026-09-01 to 2026-11-12 | Repeated attempts target the external Cisco ASA from `209.141.46.83` | `CiscoASA_CL`: ASA device/version, external source, target service, exploitation-attempt signature, `Action=Blocked`, `Result=Failure` and low transferred bytes; FreshService change record confirms the appliance was patched before the attempts | Raw evidence only; no day-of Cisco alert | The same infrastructure attempted an alternative entry path, but the ASA activity did not produce successful initial access |

## Day-of evidence: 12 November 2026

| ID | Timestamp (UTC) | Event and fact it supports | Source and essential fields | Surface behaviour | Expected analyst conclusion |
| --- | --- | --- | --- | --- | --- |
| D01 | 10:25 | Inbox rule named `Personal` forwards qualifying mail to `craiglonn@gmail.com` | `OfficeActivity`: `New-InboxRule`/`Set-InboxRule`, rule name, conditions, external target, client IP and Louise; `EmailEvents` later records forwarded messages | `Rare and potentially high-risk Office operations` alert appears at 10:30 | An attacker-created external forwarding path exists |
| D02 | 10:35-10:55 | Searches across Exchange, SharePoint and OneDrive for payroll, salary, redundancy, disciplinary, PII and related terms | `OfficeActivity` and `CloudAppEvents`: search/query operation, account, application, object and IP | Raw events | The attacker is locating high-value HR information |
| D03 | 10:45 | Purview/eDiscovery case accessed and searches/exports initiated | `OfficeActivity`: Purview/eDiscovery operations, case identifiers, search terms, export and actor; `AuditLogs` confirms current eDiscovery Manager role | Raw events | The attacker is abusing valid privileges for collection |
| D04 | 10:35-11:19 | Forty-nine files are downloaded inside the active one-hour detection window | `CloudAppEvents` and `OfficeActivity`: 49 completed downloads with deterministic timestamps and the same compromised account | No alert yet | The activity remains immediately below the threshold until the next download |
| D05 | 11:20 | The 50th file download completes and crosses the threshold | `CloudAppEvents` and `OfficeActivity`: exactly 50 completed downloads in the rolling one-hour window | Bulk-download alert appears at 11:25 | The attacker crossed the threshold they had previously learned to evade |
| D06 | 11:30 | eDiscovery exports and downloaded material are written locally | `DeviceFileEvents`: files under Louise's profile/temp paths; sensitivity labels and initiating process where applicable | Raw evidence | Cloud collection reached the endpoint |
| D07 | 11:35 | Archives with generic names are created in `%TEMP%` | `DeviceProcessEvents`: archive command/process; `DeviceFileEvents`: archive creation, size, path and hash | Archive-in-suspicious-location alert appears at 11:40 | Collected data is being staged |
| D08 | 12:05 | Archives are uploaded to the private HR SharePoint location | `CloudAppEvents` and `OfficeActivity`: upload operations, archive object names, Louise and source IP | Raw event | Staged data was returned to a cloud location for sharing |
| D09 | 12:15 | Archive sharing permission is granted to the fake guest | `OfficeActivity` and `CloudAppEvents`: sharing operation, object, guest address and actor | Raw event attached to the collection incident after correlation | The guest account is an exfiltration path |
| D10 | 12:25 | Fake guest successfully downloads the shared archives | `CloudAppEvents` and `OfficeActivity`: external account, archive object, download success, IP and user agent | High-severity exfiltration alert appears at 12:30 | Data exfiltration is confirmed, not merely attempted |
| D11 | 12:35 | Transfer or sync to Craig Lonn's personal OneDrive is blocked | `CloudAppEvents`: destination, blocked action/result and policy details in the event fields | Low/medium blocked-transfer alert or raw event | A second exfiltration route was attempted but failed |
| D12 | From 12:40 | SparkRAT C2 increases from every ten minutes to every ten seconds | `DeviceNetworkEvents`: same device, initiating process, `209.141.46.83` and successful connections; a separately queryable, preloaded `ThreatIntelligenceIndicator` record maps the IP to TAG-100/Storm-2077 | Raw events only; no IOC, C2 or Storm-2077 alert is generated | Analysts must pivot from the network activity to threat intelligence and make the attribution themselves |
| D13 | 13:10 | Existing registry persistence is repaired or modified | `DeviceRegistryEvents`: Run key, value, SparkRAT path, Louise and initiating process | Persistence alert joins the endpoint investigation | Endpoint persistence survived the original response and was actively maintained |
| D14 | 13:20 | Archives are removed after successful transfer | `DeviceFileEvents`: archive deletion, same paths/hashes where supported | Raw event | The attacker attempted local clean-up after exfiltration |

## Alert and incident catalogue

### Historical, closed by Anita Job

| Incident | Source evidence | Closure that analysts must be able to inspect |
| --- | --- | --- |
| LL phishing report | H01-H09 | Closed as Benign Positive after password reset; no endpoint investigation or session revocation recorded |
| Unfamiliar/impossible travel: Birmingham | H10 | Closed as expected VPN activity without validating device or correlating the phish |
| Guest account invited | H11 | Closed after incorrectly treating `rnicrosoft.com` as Microsoft |
| Impossible travel: China | H12 | Closed as expected VPN activity despite geography and unmanaged device |
| Bulk download: 50 files | H14-H15 | Closed because filenames appeared personal; no threshold-evasion or Sentinel-access review |

### Visible on exercise day

| Approximate arrival | Alert | Primary evidence | Initial grouping |
| --- | --- | --- | --- |
| 10:30 | Rare and potentially high-risk Office operations | D01 | Email/cloud incident |
| 11:25 | Louise Lonn downloaded 50 files | D05 | Cloud collection incident |
| 11:40 | Archive created in a suspicious temporary location | D06-D07 | Endpoint incident |
| 12:30 | External guest downloaded sensitive archives | D08-D10 | Added to cloud collection incident |
| 13:10 | Registry-based persistence references SparkRAT | D13 | Endpoint alert correlated into the main incident |

The UI may initially show separate incidents. Correlation should progressively make the relationship apparent rather than presenting one pre-solved incident.

## Report conclusion coverage

| Required report conclusion | Minimum evidence IDs |
| --- | --- |
| HR was targeted by spear phishing | H01-H02 |
| Louise's credentials and session were stolen | H02-H03 |
| A ClickFix command installed SparkRAT | H04-H05 |
| SparkRAT established persistent C2 | H06 and H17 |
| The original response reset only the password | H07-H09 |
| The compromise lasted approximately two months | H05-H17 plus D12-D13 |
| Historical alerts were incorrectly closed in isolation | H09-H14 and historical `SecurityIncident` records |
| The guest was attacker-controlled, not Microsoft | H11, D09-D10 and domain spelling |
| Downloads were deliberately kept below the threshold | H14-H16 and D04-D05 |
| The mailbox-forwarding rule created continuing email exposure | D01 plus subsequent forwarded `EmailEvents` |
| Purview/eDiscovery access was possible and abused | H13 and D02-D07 |
| Sensitive HR information was collected and staged | D02-D07 |
| Guest-based exfiltration succeeded | D08-D10 |
| Personal OneDrive exfiltration failed | D11 |
| Storm-2077/TAG-100 attribution is supported | D12 plus the preloaded threat-intelligence record; analysts must perform the correlation themselves |
| Cisco ASA exploitation was attempted but was not the successful initial-access path | H18 plus the successful phishing/ClickFix chain in H01-H06 |

## Required tables

### Existing archived schemas that can be reused

- `AlertEvidence`
- `CloudAppEvents`
- `DeviceFileEvents`
- `DeviceInfo`
- `DeviceNetworkEvents`
- `DeviceProcessEvents`
- `EmailEvents`
- `IdentityInfo`
- `SecurityAlert`
- `SigninLogs`

### Approved exercise-created schema

- `CiscoASA_CL` — failed exploitation attempts and blocked connection context for the external Cisco ASA

### Additional supplied schemas used by this narrative

| Table | Why it is required |
| --- | --- |
| `SecurityIncident` | Historical ownership, status, classification, closure comments and linked alert IDs |
| `AuditLogs` | Password reset, guest invitation and eDiscovery role assignment |
| `AzureActivity` | Approved Azure VM Run Command red herring and its source/target context |
| `OfficeActivity` | Exchange inbox rules, SharePoint operations and Purview/eDiscovery audit evidence |
| `UrlClickEvents` | Defensible link between the email, Louise and the malicious URL click |
| `EmailUrlInfo` | URL/message enrichment and campaign pivots |
| `EmailAttachmentInfo` | Attachment evidence for forwarded messages where relevant |
| `DeviceRegistryEvents` | Registry persistence and its initiating process |
| `AADRiskyUsers` | Risk state supporting the identity investigation/report |
| `BehaviorAnalytics` | UEBA context required by the enabled `MFA Rejected by User` red-herring rule |
| `ThreatIntelligenceIndicator` | IOC-to-Storm-2077/TAG-100 attribution |

### Application evidence outside KQL

FreshService tickets and change records are displayed in the separate FreshService application tab. They are not represented as a Kusto table and cannot be queried through KQL. Analysts correlate them manually using ticket IDs, users, devices, timestamps and change references.

The supplied and explicitly approved schemas are authoritative. A table without one of those schemas does not exist and must not be referenced by the generator, UI schema browser, analyst queries or facilitator validation.

## Required noise and baselines

The malicious rows cannot be the only records in these tables. The generator must include enough deterministic background data for useful comparisons:

- Normal Louise sign-ins from known managed devices and expected UK locations.
- Legitimate ExpressVPN use by other users and, if appropriate, occasional historical use by Louise.
- Routine HR shared-mailbox traffic and ordinary inbox rules.
- Normal SharePoint/OneDrive searches, opens and small downloads.
- Typical PowerShell activity from IT-managed scripts, distinguishable by signer, command line and parent process.
- Normal archive creation outside suspicious paths.
- Routine DNS/network traffic and software-update connections.
- Legitimate guest invitations from correctly spelled partner domains.
- Normal Sentinel access by authorised SOC personnel.

Noise generation must be seeded and repeatable so facilitator queries and automated tests return stable results.

## Data-quality acceptance checks

Before the scenario is accepted:

1. Every evidence ID must return at least one expected row with its validation query.
2. Every alert must link to one or more `AlertEvidence` rows.
3. Historical incidents must show Anita Job's closure details.
4. Every 50-file window must alert; every 49-file window must not alert.
5. The password reset must occur after the ClickFix execution and before later malicious access.
6. C2 must continue after the password reset.
7. Purview access must occur only after the required eDiscovery role assignment.
8. Guest sharing must precede the guest download.
9. The personal OneDrive attempt must be blocked and must not be described as confirmed exfiltration.
10. The facilitator must be able to prove successful guest-based exfiltration.
11. The historical and day-of IP/location/device patterns must be internally consistent.
12. The 90-day time filter must include all historical attack events and sufficient baseline activity.
13. No report conclusion may depend solely on text displayed in an alert description.
14. The complete facilitator investigation must be reproducible using the analyst-visible interface and KQL.

## Deferred until the main evidence passes validation

- Red-herring data implementation; the approved design candidates are documented in `RED_HERRING_PLAN.md`.
- Scoring and team comparison.
- Authentication and role enforcement around facilitator-only controls.
- Cosmetic polish beyond what is required to investigate the evidence.
- The blank analyst report and corrected completed facilitator report.

## Threat-intelligence references

- [Recorded Future: TAG-100 Uses Open-Source Tools in Suspected Global Espionage Campaign (IOC appendix)](https://go.recordedfuture.com/hubfs/reports/cta-2024-0716.pdf)
- [Microsoft Defender XDR: How Microsoft names threat actors](https://learn.microsoft.com/en-us/defender-xdr/microsoft-threat-actor-naming)

