# Red-Herring Plan

The approved placement of these events in the timed exercise is defined in `EXERCISE_TIMELINE.md`.

## Design rule

A red herring must be suspicious enough to investigate but must contain evidence that allows a careful analyst to resolve or de-scope it. It must not depend on facilitator explanation, and it must not contradict the Louise Lonn attack narrative.

For this three-responder exercise, eleven red herrings create visible alerts. Each must be resolvable in approximately 5-12 minutes once the correct ticket, change record or baseline evidence is found. Additional items remain queryable background events.

## Requested red herrings

| ID | Activity | Principal | Presentation | Evidence that resolves it | Outcome |
| --- | --- | --- | --- | --- | --- |
| RH01 | Teams file upload to an external party | Hannah Rees -> Tom Blackburn | DLP/cloud alert: sensitive file upload to a third party | `CloudAppEvents` shows the upload was blocked; the file is an approved, sanitised security assessment pack; a service/change record identifies Tom as the contracted recipient | Benign business activity blocked by policy; no data transfer occurred |
| RH02 | Connection to a custom network indicator | Damo Tom from a network-management host | Custom-indicator network alert | `DeviceNetworkEvents` and network change record show Damo performed an approved firewall-control validation from the designated test host; process and device differ from Louise/SparkRAT | Authorised security validation; unrelated to the incident |
| RH03 | Malicious URL messages deleted after delivery | Unrelated marketing recipients | Email incident indicating malicious messages were delivered and later remediated | `EmailEvents` shows zero-hour auto purge/deletion; `UrlClickEvents` contains no successful clicks; sender, URL and campaign IDs do not overlap the HR campaign | True malicious campaign, successfully remediated and unrelated |
| RH04 | Outbound email volume exceeds 400 | Olivia Mercer, Sales Team Lead | `[Impact] Outbound email exceeds 400` | `EmailEvents` shows 427 messages through the approved CRM/Dynamics connector, expected customer domains and a sales-campaign reference; no suspicious inbox rule or unusual sign-in | Legitimate sales batch, not exfiltration |

## Additional visible red herrings selected from the Sentinel rule exports

| ID | Exported rule | Severity | Principal | Resolution evidence |
| --- | --- | --- | --- | --- |
| RH06 | `Azure VM Run Command operations executing a unique PowerShell script` | Medium | David Woofer | Approved monitoring-agent deployment, expected Azure VM, known source IP and matching change record; the command is unrelated to Louise's browser-launched ClickFix process |
| RH07 | `Guest Users Invited to Tenant by New Inviters` | Medium | Beth Edgar -> Ayeesha Ahmed | Procurement ticket, established supplier identity, expected invitation issuer and limited SharePoint access |
| RH09 | `Account Created and Deleted in Short Timeframe` | High | Emma Outgram | Temporary M365 migration-validation account, creation and deletion recorded in the same approved change, no sign-ins or assigned privileges |
| RH12 | `[CredentialAccess] Admin User has Deleted an MFA phone from a Users Account` | Medium | Adam Thomas -> Victoria Nash | FreshService request for a lost/replacement phone, identity-verification notes and successful registration of the replacement method |

These rules come from `../../scenario/reference/sentinel-rules/Azure_Sentinel_analytics_rules (10).json`, `(13).json` and `(15).json` and are enabled in the supplied exports.

## Further visible alerts added for queue pressure

| ID | Exported rule | Severity | Principal | Resolution evidence |
| --- | --- | --- | --- | --- |
| RH14 | `MFA Rejected by User` | Medium | Molly Ups | Known managed phone and UK IP, Molly confirms she rejected a stale Outlook authentication prompt after changing her password, and a subsequent normal authentication succeeds |
| RH15 | `[Exfiltration] Files Copied to USB (Blocked by Policy)` | Medium | Aimee Flangan | The attempted copy was blocked, the device is an approved encrypted corporate USB, the files are project documents covered by a matching service request, and no files left the endpoint |
| RH16 | `[PrivilegeEscalation] A user has been added to Intune_Local_Admins Entra ID Group` | Medium | Bill Cottray | Approved time-limited elevation for SRE maintenance, matching change record, expected administrator and scheduled group removal |

These rules come from `../../scenario/reference/sentinel-rules/Azure_Sentinel_analytics_rules (9).json`, `(10).json` and `(12).json` and are enabled in the supplied exports.

## Recommended additional queryable red herrings

These add realism without adding more top-level alerts.

| ID | Activity | Principal | Why it is useful | Resolution evidence |
| --- | --- | --- | --- | --- |
| RH05 | Legitimate Purview/eDiscovery activity | Alex Williams | Gives analysts a clean comparison for Louise's malicious eDiscovery use | Approved audit case, managed device, expected UK IP, documented search scope and no external sharing |
| RH08 | High-volume AWS activity during a deployment | Rhydian Greggs | Creates cloud noise for a privileged technical user using the available `CloudAppEvents` schema | Expected account, Terraform user agent, approved change window and source network |

## Optional alert-bearing decoys

Use at most two of these if testing shows that the four requested alerts are resolved too quickly.

| ID | Activity | Principal | Alert | Resolution evidence |
| --- | --- | --- | --- | --- |
| RH10 | New M365 application registration | Emma Outgram or Barry Thendrews | Unusual cloud application or consent activity | Approved M365 pilot, expected permissions, managed device and change record; no broad `Mail.Read` permission |
| RH11 | Large archive created outside the HR incident | Tessa Monroe | Archive creation on a user device | Marketing campaign assets, expected media filenames, standard project path and no C2 or external guest download |
| RH13 | Shadow-copy deletion and recovery-setting changes | Max Edgar / approved backup service account | Ransomware-like preparation | Backup restore test, signed vendor binary, service account and approved change record |

## Recommended exercise selection

Use RH01-RH04, RH06, RH07, RH09, RH12 and RH14-RH16 as the eleven visible red-herring alerts. Include RH05 and RH08 as background records found through hunting. Do not enable RH10, RH11 or RH13 unless a rehearsal shows the exercise is still too easy.

This gives the exercise:

- Four main-story alerts before the persistence alert.
- Eleven visible but quickly resolvable red-herring alerts.
- Several pieces of realistic queryable noise.
- A protected 14:00-15:00 reporting period with no new evidence.
