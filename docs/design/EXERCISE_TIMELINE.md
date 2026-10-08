# Storm-2077 Tabletop: Combined Timeline

## Operating model

- Exercise date: 12 November 2026.
- Exercise timezone: UTC/GMT.
- Nominal delivery window: 10:00-15:00, but the schedule is anchored to the moment the facilitator presses **Start exercise**.
- Main investigation: T+00:00 to T+03:20.
- Consolidation: T+03:20 to T+04:00.
- Incident-report writing: T+04:00 to T+05:00.
- Historical evidence is queryable before the exercise starts.
- The first day-of alert is released at T+00:05 and later content follows the offsets represented by the times below (10:00 = T+00:00).
- The facilitator may pause and resume the exercise clock for breaks or technical interruptions, but does not manually release individual events.
- No new events or alerts are released after T+03:20.

## Ninety-day historical timeline

| Date/time | Type | Activity | Analyst-visible outcome |
| --- | --- | --- | --- |
| 01 Sep-12 Nov | Related unsuccessful activity | Repeated exploitation attempts from `209.141.46.83` target the external Cisco ASA | `CiscoASA_CL` shows the attempts were blocked against a patched appliance; they are not the successful initial-access path |
| 03 Sep 09:08 | Main story | HR spear-phishing email delivered to Louise Lonn and the HR shared mailbox | Louise's personal copy is removed; the shared-mailbox copy remains |
| 03 Sep 09:10 | Main story | Louise opens the shared-mailbox message and follows the link | URL-click and email evidence |
| 03 Sep 09:11 | Main story | Fake Microsoft page captures credentials and session material | Unmanaged Exchange sign-in evidence |
| 03 Sep 09:12 | Main story | ClickFix instruction causes browser-launched PowerShell | Process evidence |
| 03 Sep 09:13 | Main story | PowerShell downloads and starts SparkRAT | File and process evidence |
| From 03 Sep 09:14 | Main story | SparkRAT beacons to C2 every ten minutes | Historical network evidence |
| 03 Sep 09:18 | Main story | Phish Alert notification is sent to `phishinginvestigations@creditsafe.com`, creating a FreshService investigation | Email notification and ticket |
| 03 Sep 09:27 | Main story | Anita Job resets Louise's password but does not revoke sessions or investigate the endpoint | Audit and ticket evidence |
| 03 Sep 09:34 | Main story | Anita closes the phishing incident as Benign Positive | Historical incident record |
| 04 Sep 14:22 | Main story | Birmingham ExpressVPN access occurs after the reset | Alert closed by Anita as expected VPN use |
| 06 Sep 11:05 | Main story | `hradvisor@rnicrosoft.com` is invited as a guest using Louise's compromised identity | Alert closed after the domain is mistaken for Microsoft |
| 11 Sep 02:17 | Main story | China ExpressVPN access occurs | Impossible-travel alert closed as VPN use |
| 19 Sep 13:40 | Main story | Louise is granted eDiscovery Manager and Security Reader | Queryable role-assignment evidence |
| 28 Sep 10:00-10:42 | Main story | Exactly 50 personal-looking files are downloaded | Bulk-download alert closed by Anita |
| 28 Sep 10:50 | Main story | Louise's compromised account accesses Sentinel/Log Analytics content | Queryable sign-in and query-audit evidence |
| 29 Sep onward | Main story | Downloads repeatedly stop at 49 inside separate one-hour windows | Queryable threshold-evasion pattern; no alerts |
| Sep-Nov | Main story | SparkRAT launches and C2 continues after the password reset | Evidence that the endpoint remained compromised for approximately two months |

## Exercise-day alert stream

These are the only alerts that should appear in the incident queue during the timed investigation.

| Alert time | Class | Alert title | Triggering activity | What resolves or advances it |
| --- | --- | --- | --- | --- |
| 10:05 | Red herring RH12 | [CredentialAccess] Admin User has Deleted an MFA phone from a Users Account | Adam Thomas removes Victoria Nash's old phone method following a lost-phone request | FreshService identity-verification notes and the replacement-method registration establish an authorised Service Desk action |
| 10:10 | Red herring RH03 | Email messages containing malicious URL deleted after delivery | An unrelated campaign reaches Marketing recipients and is removed through zero-hour auto purge | `EmailEvents` shows deletion/remediation and `UrlClickEvents` shows no successful clicks; campaign indicators do not overlap the HR attack |
| 10:20 | Red herring RH14 | MFA Rejected by User | Molly Ups rejects a stale Outlook authentication prompt after a password change | Managed phone, known UK IP, user confirmation and a subsequent successful normal authentication resolve it |
| 10:30 | Main story D01 | Rare and potentially high-risk Office operations | Rule named `Personal` forwards qualifying Louise Lonn email to `craiglonn@gmail.com` | Analysts pivot to Louise, the forwarding target, Office audit activity and historical incidents |
| 10:40 | Red herring RH06 | Azure VM Run Command operations executing a unique PowerShell script | David Woofer deploys the approved monitoring agent to one Azure VM | Azure activity, expected source IP, target VM and approved change distinguish it from Louise's browser-launched ClickFix PowerShell |
| 10:50 | Red herring RH04 | [Impact] Outbound email exceeds 400 | Olivia Mercer sends 427 sales emails using the approved CRM/Dynamics connector | Expected connector, customer recipients, sales-campaign reference and normal sign-in baseline establish legitimate activity |
| 10:57 | Red herring RH15 | [Exfiltration] Files Copied to USB (Blocked by Policy) | Aimee Flangan attempts to copy approved project documents to an encrypted corporate USB, but policy blocks the operation | Blocked result, device serial, service request and expected filenames establish that no files left the endpoint |
| 11:05 | Red herring RH07 | Guest Users Invited to Tenant by New Inviters | Beth Edgar invites supplier representative Ayeesha Ahmed | Procurement ticket, supplier identity and limited site permissions establish legitimate collaboration |
| 11:25 | Main story D05 | Louise Lonn downloaded 50 files | Downloads 1-49 occur between 10:35 and 11:19; the 50th completes at 11:20 | Analysts compare the alert with historical groups of exactly 49 and the old 50-file incident |
| 11:40 | Main story D07 | Archive created in a suspicious temporary location | eDiscovery exports and HR material are archived under Louise's `%TEMP%` directory at 11:35 | Device process/file pivots expose staging and connect the activity to the old ClickFix/SparkRAT chain |
| 11:50 | Red herring RH09 | Account Created and Deleted in Short Timeframe | Emma Outgram deletes a temporary M365 migration-validation account created earlier that morning | Approved change record, no sign-ins, no roles and the account naming convention establish harmless testing |
| 12:00 | Red herring RH01 | Sensitive file upload to external Teams user blocked | Hannah Rees attempts to send `External_PenTest_Findings_Sanitised.pdf` to Tom Blackburn | `CloudAppEvents` proves the transfer was blocked; the file, recipient and approved engagement record establish benign business purpose |
| 12:15 | Red herring RH16 | [PrivilegeEscalation] A user has been added to Intune_Local_Admins Entra ID Group | Bill Cottray receives time-limited local-administrator access for scheduled SRE maintenance | Approved change, expected administrator and scheduled removal establish authorised elevation |
| 12:30 | Main story D10 | External guest downloaded sensitive archives | The attacker uploads archives at 12:05, shares them with the fake guest at 12:15 and the guest downloads them at 12:25 | Cloud audit activity confirms successful exfiltration and links back to the historical fake guest invitation |
| 12:50 | Red herring RH02 | Connection to a custom network indicator | Damo Tom's designated network-management host `NET-ADM-017` contacts test indicator `198.51.100.200` during firewall validation | Device/process identity and an approved network change prove authorised testing; it is unrelated to Louise or `209.141.46.83` |
| 13:10 | Main story D13 | Registry-based persistence references SparkRAT | Existing SparkRAT Run-key persistence is repaired or modified | Registry, process and historical network evidence establish durable endpoint compromise |

## Exercise-day raw events and queryable noise

These records are available through KQL but do not create additional alerts.

| Time | Class | Activity | Purpose and resolution |
| --- | --- | --- | --- |
| 10:00 | Exercise control | Ninety days of background and historical attack evidence become available | Enables retrospective hunting from the beginning |
| 10:01 | Red herring RH12 | Adam Thomas removes Victoria Nash's old MFA phone method | Supporting `AuditLogs` evidence for the 10:05 alert and matching FreshService request |
| 10:02-10:08 | Red herring RH03 | Unrelated malicious email delivery followed by automatic deletion | Supporting evidence for the 10:10 email alert |
| 10:05-10:45 | Red herring RH04 | Olivia Mercer's CRM campaign sends 427 messages | Supporting evidence for the 10:50 volume alert |
| 10:15 | Related unsuccessful activity | The external Cisco ASA blocks another exploitation attempt from `209.141.46.83` | Raw `CiscoASA_CL` evidence only; analysts must determine that it failed and separately pivot the IP to threat intelligence |
| 10:16 | Red herring RH14 | Molly Ups rejects an MFA prompt from her managed phone and known UK IP | Supporting `SigninLogs`, `IdentityInfo` and `BehaviorAnalytics` evidence for the 10:20 alert |
| 10:25 | Main story D01 | The `Personal` inbox rule is created | Raw event precedes the 10:30 alert by five minutes |
| 10:35-10:55 | Main story D02 | Searches across Exchange, SharePoint and OneDrive for payroll, salary, redundancy, disciplinary and PII terms | Establishes discovery and collection intent |
| 10:35-11:19 | Main story D04 | Forty-nine files are downloaded in the active one-hour window | Remains below the detection threshold until 11:20 |
| 10:34 | Red herring RH06 | David Woofer runs an approved unique PowerShell script through Azure VM Run Command | Supporting `AzureActivity` evidence for the 10:40 alert |
| 10:42 | Queryable noise RH05 | Alex Williams conducts approved Purview/eDiscovery activity for a GRC audit | Legitimate case ID, managed device, expected IP and audit scope provide a clean comparator for Louise's activity |
| 10:45 | Main story D03 | Louise's compromised identity accesses Purview/eDiscovery and begins searches/exports | Supported by the historical eDiscovery Manager assignment |
| 10:52 | Red herring RH15 | Aimee Flangan attempts to copy approved project files to encrypted corporate USB `CS-USB-0042`; enforcement blocks the operation | Supporting `CloudAppEvents` evidence for the 10:57 alert and proof that no transfer completed |
| 10:58 | Red herring RH07 | Beth Edgar invites Ayeesha Ahmed to the tenant | Supporting `AuditLogs` evidence for the 11:05 alert |
| 11:20 | Main story D05 | The 50th file is downloaded | Threshold is crossed; alert arrives at 11:25 |
| 11:30 | Main story D06 | eDiscovery exports and downloaded material are written locally | Connects cloud collection to Louise's endpoint |
| 11:35 | Main story D07 | Archives are created in `%TEMP%` | Alert arrives at 11:40 |
| 11:44 | Red herring RH09 | Emma Outgram deletes the temporary M365 migration-validation account created at 09:35 | Supporting `AuditLogs` evidence for the 11:50 alert; the account never signed in or received a role |
| 11:54 | Red herring RH01 | Hannah Rees attempts the external Teams upload; the DLP action is `Blocked` | Supporting evidence for the 12:00 alert |
| 11:55 | Red herring RH07 | Beth Edgar legitimately shares a procurement pack with Ayeesha Ahmed | Follow-on evidence supporting closure of the guest-invitation alert: approved ticket, established supplier identity and non-HR content |
| 12:05 | Main story D08 | HR archives are uploaded to private HR SharePoint | First stage of guest-based exfiltration |
| 12:09 | Red herring RH16 | Bill Cottray is added to `Intune_Local_Admins` for approved SRE maintenance | Supporting `AuditLogs` and change-record evidence for the 12:15 alert |
| 12:10 | Queryable noise RH08 | Rhydian Greggs generates high-volume AWS activity using Terraform | `CloudAppEvents` records the application, action, account, source IP and Terraform user agent; an approved change explains the activity |
| 12:15 | Main story D09 | Archive sharing permission is granted to `hradvisor@rnicrosoft.com` | Links the current activity to the historical guest invitation |
| 12:25 | Main story D10 | The fake guest downloads the archives | Successful exfiltration; alert arrives at 12:30 |
| 12:35 | Main story D11 | Attempt to transfer archives to Craig Lonn's personal OneDrive is blocked | `CloudAppEvents` only; separate failed exfiltration route |
| From 12:40 | Main story D12 | SparkRAT C2 increases from every ten minutes to every ten seconds against `209.141.46.83` | Raw telemetry only; analysts must pivot to the preloaded threat-intelligence record to determine TAG-100/Storm-2077 |
| 12:45 | Red herring RH02 | Damo Tom's validation connection to `198.51.100.200` occurs | Alert arrives at 12:50; distinct user, host, process and indicator from the main incident |
| 13:10 | Main story D13 | SparkRAT registry persistence is modified | Final main-story alert |
| 13:20 | Main story D14 | Local archives are deleted after successful transfer | Final new evidence; no alert is generated |
| 13:20-14:00 | Exercise control | Teams consolidate evidence, determine scope and assess attribution | No new evidence or alerts |
| 14:00-15:00 | Exercise control | Teams complete and submit the incident report | Protected reporting period; no new evidence or alerts |

## Alert-load summary

| Category | Count |
| --- | ---: |
| Main-story alerts | 5 |
| Visible red-herring alerts | 11 |
| Queryable-noise scenarios without alerts | 2 |
| Total day-of alerts | 16 |

The alert stream is intentionally front-loaded enough to require three responders to prioritise and divide work, but stops at 13:10. The final raw clean-up event appears at 13:20, leaving forty minutes for investigation consolidation and one hour for report writing.

## Three-responder pressure model

The exercise does not assign alerts to individuals, but the queue supports three parallel workstreams:

| Workstream | Likely early alerts | Later pivots |
| --- | --- | --- |
| Identity and email | MFA phone removal, deleted malicious email, outbound-email volume | Louise's historical sign-ins, guest invitation and forwarding activity |
| Endpoint and cloud execution | Azure Run Command PowerShell, suspicious archive | SparkRAT process chain, archive staging and registry persistence |
| Cloud sharing and network | New guest inviter, blocked Teams upload | Fake guest exfiltration, personal OneDrive attempt and C2 investigation |

The short-lived-account alert deliberately crosses the identity and cloud workstreams. Teams should have to communicate and reprioritise when the 11:25 bulk-download and 12:30 exfiltration alerts arrive.
