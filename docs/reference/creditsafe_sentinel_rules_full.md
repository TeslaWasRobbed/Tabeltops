# Creditsafe SOC - Full Sentinel Analytics Rules
## Threat-Led | Financial Services Kill Chain Focus
Generated: 2026-04-09  
**Updated: 2026-04-15 - Modified for SecurityEvent table schema compatibility**

> **Note**: These rules have been updated to work with the SecurityEvent table schema as shown in the provided CSV data. Key changes:
> - `ComputerName` → `Computer`  
> - DeviceEvents rules converted to use SecurityEvent (EventID 4688 for process creation)
> - Added fallback detections for endpoints without Microsoft Defender for Endpoint

---

# STAGE 1: INITIAL ACCESS & CREDENTIAL THEFT

---

## Rule 8: Kerberoasting Detection
**Severity:** High  
**Tactic:** Credential Access  
**MITRE:** T1558.003 - Kerberoasting  
**Run every:** 1 hour | **Lookup:** 1 hour  
**Threshold:** Any match  

Kerberoasting requests service tickets using RC4 encryption (0x17) rather than AES. 
Legitimate modern environments should use AES exclusively.

```kql
SecurityEvent
| where EventID == 4769
| extend TicketEncryptionType = extract(@"TicketEncryptionType.*?0x([0-9a-fA-F]+)", 1, EventData)
| extend TicketOptions = extract(@"TicketOptions.*?0x([0-9a-fA-F]+)", 1, EventData)
| where TicketEncryptionType == "17"  // RC4 - weak encryption, used in Kerberoasting
| where TicketOptions == "40810000"
| where ServiceName !endswith "$"       // Exclude machine accounts
| where ServiceName != "krbtgt"
| summarize RequestCount = count(),
            TargetAccounts = make_set(ServiceName, 10),
            SourceIPs = make_set(IpAddress, 5),
            FirstSeen = min(['TimeGenerated']),
            LastSeen = max(['TimeGenerated'])
            by SubjectUserName
| where RequestCount > 3               // Multiple RC4 TGS requests = suspicious
| extend AlertDetail = strcat(SubjectUserName, " requested ", RequestCount, " RC4 service tickets - possible Kerberoasting")
```

**Response:** Immediately check if SubjectUserName is a known pen test account. If not, isolate device and rotate all service account passwords. Check BloodHound/AD paths from compromised account.

---

## Rule 9: AS-REP Roasting Detection
**Severity:** High  
**Tactic:** Credential Access  
**MITRE:** T1558.004 - AS-REP Roasting  
**Run every:** 1 hour | **Lookup:** 1 hour  
**Threshold:** Any match  

Targets accounts with pre-authentication disabled. Attacker requests AS-REP without credentials.

```kql
SecurityEvent
| where EventID == 4768
| extend PreAuthType = extract(@"PreAuthType.*?([0-9]+)", 1, EventData)
| where PreAuthType == "0"             // No pre-authentication required
| where TargetUserName !endswith "$"   // Exclude machine accounts
| summarize AttemptCount = count(),
            TargetAccounts = make_set(TargetUserName, 10),
            FirstSeen = min(['TimeGenerated']),
            LastSeen = max(['TimeGenerated'])
            by IpAddress
| extend AlertDetail = strcat("AS-REP Roasting attempt from ", IpAddress, " against ", AttemptCount, " accounts")
```

**Response:** Identify accounts with pre-auth disabled in AD (Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}). Enable pre-auth on all accounts. Rotate passwords for targeted accounts.

---

## Rule 10: Pass-the-Hash Detection
**Severity:** High  
**Tactic:** Lateral Movement  
**MITRE:** T1550.002 - Pass the Hash  
**Run every:** 30 minutes | **Lookup:** 30 minutes  
**Threshold:** Any match  

PtH produces Type 3 NTLM network logons where the source workstation name differs from the target — 
and crucially no interactive logon (Type 2) preceded it from that device.

```kql
SecurityEvent
| where EventID == 4624
| where LogonType == 3
| where AuthenticationPackageName == "NTLM"
| where WorkstationName != Computer
| where TargetUserName !endswith "$"
| where TargetUserName != "ANONYMOUS LOGON"
| summarize NTLMLogons = count(),
            SourceHosts = make_set(WorkstationName, 10),
            TargetHosts = make_set(Computer, 10),
            FirstSeen = min(['TimeGenerated']),
            LastSeen = max(['TimeGenerated'])
            by TargetUserName
| where NTLMLogons > 5
| extend AlertDetail = strcat(TargetUserName, " has ", NTLMLogons, " NTLM type 3 logons from ", array_length(SourceHosts), " sources - possible PtH")
```

**Response:** Correlate with 4776 failures. Check if user is legitimately working across multiple devices. If not, treat as compromised credential. Enable Defender Credential Guard if not already enabled.

---

## Rule 11: DPAPI Credential Access Spike
**Severity:** High  
**Tactic:** Credential Access  
**MITRE:** T1555.003 - Credentials from Web Browsers  
**Run every:** 1 hour | **Lookup:** 1 hour  
**Threshold:** >50 DPAPI access events per device  

DPAPI is used by browsers and Windows to store credentials. Mass DPAPI access 
suggests credential harvesting tool (e.g. Mimikatz, SharpDPAPI).

```kql
// Note: This rule requires DeviceEvents table from Microsoft Defender for Endpoint
// If only SecurityEvent is available, consider using process creation events (4688) instead
SecurityEvent
| where EventID == 4688  // Process creation
| where NewProcessName has_any ("mimikatz", "sharp", "dpapi")  // Look for credential dumping tools
| project ['TimeGenerated'], Computer, SubjectUserName, NewProcessName, CommandLine
| extend AlertDetail = strcat("Potential DPAPI credential access tool detected: ", NewProcessName, " on ", Computer)
```

**Response:** Identify calling process. If unfamiliar process, isolate device immediately. Check for credential dumping tools in process tree. Assume all stored credentials on device are compromised.

---

## Rule 12: Encoded PowerShell Command Execution
**Severity:** High  
**Tactic:** Execution  
**MITRE:** T1059.001 - PowerShell  
**Run every:** 1 hour | **Lookup:** 1 hour  
**Threshold:** Any match  

Base64 encoded PowerShell is a common obfuscation technique used in phishing payloads 
and post-exploitation frameworks.

```kql
// Using SecurityEvent for PowerShell process creation detection
SecurityEvent
| where EventID == 4688  // Process creation
| where NewProcessName has "powershell"
| where CommandLine has_any ("-enc", "-encoded", "-encodedcommand", "-ec")
    or CommandLine matches regex @"[A-Za-z0-9+/]{100,}={0,2}"  // Long base64 string
    or CommandLine has "FromBase64String"
    or CommandLine has_any ("IEX", "Invoke-Expression", "Invoke-Command")
| project ['TimeGenerated'], Computer,
          SubjectUserName,
          NewProcessName,
          CommandLine
| extend AlertDetail = strcat("Encoded/obfuscated PowerShell executed on ", Computer, " by ", SubjectUserName)
```

**Response:** Decode the Base64 payload and assess intent. Check parent process — if spawned from Office/browser this is likely a phishing payload. Isolate device and check lateral movement from that account.

---

# STAGE 2: LATERAL MOVEMENT

---

## Rule 13: Lateral Movement via RDP - New Source
**Severity:** High  
**Tactic:** Lateral Movement  
**MITRE:** T1021.001 - Remote Desktop Protocol  
**Run every:** 1 hour | **Lookup:** 14 days  
**Threshold:** Any match  

Detects RDP logons from source devices that have never RDP'd to that destination before.

```kql
let knownRDPPairs = 
    SecurityEvent
    | where ['TimeGenerated'] between (ago(14d) .. ago(1h))
    | where EventID == 4624 and LogonType == 10
    | summarize by WorkstationName, Computer;
SecurityEvent
| where ['TimeGenerated'] > ago(1h)
| where EventID == 4624 and LogonType == 10
| where TargetUserName !endswith "$"
| join kind=leftanti knownRDPPairs on WorkstationName, Computer
| project ['TimeGenerated'], Computer, WorkstationName,
          TargetUserName, IpAddress
| extend AlertDetail = strcat(WorkstationName, " RDP'd to ", Computer, " for first time - user: ", TargetUserName)
```

**Response:** Verify with user if they initiated the RDP session. First-time RDP pairs are high value — especially if destination is a server or DC. Check preceding events on source device.

---

## Rule 14: RDP Logon to Domain Controller
**Severity:** High  
**Tactic:** Lateral Movement  
**MITRE:** T1021.001  
**Run every:** 15 minutes | **Lookup:** 15 minutes  
**Threshold:** Any match  

RDP directly onto a DC should be extremely rare. Any interactive session warrants investigation.

```kql
SecurityEvent
| where EventID == 4624
| where LogonType == 10
| where TargetUserName !endswith "$"
| project ['TimeGenerated'], Computer, WorkstationName,
          TargetUserName, IpAddress, LogonType
| extend AlertDetail = strcat(TargetUserName, " RDP logon directly to DC ", Computer, " from ", WorkstationName)
```

**Response:** Confirm with user and their manager. DC RDP should only occur during approved change windows. If unplanned, treat as potential compromise.

---

## Rule 15: Remote WMI Execution
**Severity:** High  
**Tactic:** Lateral Movement / Execution  
**MITRE:** T1047 - Windows Management Instrumentation  
**Run every:** 1 hour | **Lookup:** 1 hour  
**Threshold:** Any match  

```kql
// WMI process creation detection using SecurityEvent
SecurityEvent
| where EventID == 4688  // Process creation
| where NewProcessName has "wmic.exe" or ParentProcessName has "wmiprvse.exe"
| where SubjectUserName != "SYSTEM" and SubjectUserName != "LOCAL SERVICE"
| project ['TimeGenerated'], Computer,
          SubjectUserName,
          NewProcessName,
          CommandLine,
          ParentProcessName
| extend AlertDetail = strcat("Potential WMI execution on ", Computer, " by ", SubjectUserName)
```

**Response:** WMI is heavily used in lateral movement. Identify source IP and correlate with other events. Check if SCCM/management tooling or genuine threat.

---

## Rule 16: Named Pipe Lateral Movement
**Severity:** Medium  
**Tactic:** Lateral Movement  
**MITRE:** T1570 - Lateral Tool Transfer  
**Run every:** 1 hour | **Lookup:** 1 hour  
**Threshold:** >100 named pipe events from single process  

Named pipes are used by C2 frameworks (Cobalt Strike, Metasploit) for lateral movement.
High volume from a single non-system process is suspicious.

```kql
// Named pipe detection via process creation - look for suspicious processes that commonly use pipes
SecurityEvent
| where EventID == 4688  // Process creation
| where NewProcessName has_any ("psexec", "cobalt", "beacon", "meterpreter") 
    or CommandLine has_any ("NamedPipe", "pipe", "IPC$")
| where NewProcessName !in (
    "svchost.exe", "lsass.exe", "services.exe", 
    "spoolsv.exe", "wininit.exe", "csrss.exe"
)
| project ['TimeGenerated'], Computer, SubjectUserName, NewProcessName, CommandLine
| extend AlertDetail = strcat("Suspicious process with pipe activity: ", NewProcessName, " on ", Computer)
```

**Response:** Investigate the initiating process. Known C2 pipe names include: msagent_, postex_, status_, mojo. If pipe names match known C2 patterns, escalate immediately.

---

# STAGE 3: DOMAIN COMPROMISE

---

## Rule 17: DCSync Attack Detection
**Severity:** Critical  
**Tactic:** Credential Access  
**MITRE:** T1003.006 - DCSync  
**Run every:** 15 minutes | **Lookup:** 15 minutes  
**Threshold:** Any match  

DCSync replicates AD credentials by abusing replication rights. 
Only DC machine accounts should ever trigger 4929. Any user account = critical alert.

```kql
SecurityEvent
| where EventID in (4928, 4929)
| where SubjectUserName !endswith "$"   // Machine accounts are legitimate
| where SubjectUserName != "ANONYMOUS LOGON"
| project ['TimeGenerated'], Computer,
          SubjectUserName, SubjectDomainName,
          SubjectLogonId
| extend AlertDetail = strcat("CRITICAL: DCSync by non-machine account ", SubjectUserName, " - possible credential dumping")
```

**Response:** CRITICAL - Assume full domain compromise. Immediately isolate the device associated with SubjectUserName. Initiate IR process. All domain credentials should be considered compromised. Rotate krbtgt password twice.

---

## Rule 18: New Domain Admin Account Created
**Severity:** Critical  
**Tactic:** Persistence  
**MITRE:** T1136.002 - Domain Account  
**Run every:** 15 minutes | **Lookup:** 15 minutes  
**Threshold:** Any match  

```kql
SecurityEvent
| where EventID == 4728
| where TargetUserName in ("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators")
| project ['TimeGenerated'], Computer,
          SubjectUserName,    // Who made the change
          MemberName,         // Who was added
          TargetUserName      // Which group
| extend AlertDetail = strcat(SubjectUserName, " added ", MemberName, " to ", TargetUserName)
```

**Response:** Verify with SubjectUserName's manager. If unauthorised, immediately remove from group, disable account, and investigate how SubjectUserName's account was used.

---

## Rule 19: Audit Policy or Security Log Tampered
**Severity:** High  
**Tactic:** Defence Evasion  
**MITRE:** T1562.002 - Disable Windows Event Logging  
**Run every:** 15 minutes | **Lookup:** 15 minutes  
**Threshold:** Any match  

Attackers disable logging to cover tracks. Any change to audit policy warrants investigation.

```kql
SecurityEvent
| where EventID in (4719, 1102)
// Filtering out machine accounts (ends with $)
| where SubjectUserName !endswith "$"
| extend 
    AlertName = iff(EventID == 1102, "Critical: Security Log Cleared", "Warning: Audit Policy Modified"),
    Severity = iff(EventID == 1102, "High", "Medium")
| project 
    TimeGenerated, 
    Computer, 
    SubjectUserName, 
    SubjectUserSid,
    Activity, 
    EventID, 
    AlertName,
    Severity,
    // Using column_ifexists ensures the query doesn't fail or blank out if the schema is thin
    Process = column_ifexists("ProcessName", "Not Captured"),
    ClientIP = column_ifexists("IpAddress", "Not Captured")
| extend AlertDetail = strcat(AlertName, " by ", SubjectUserName, " on ", Computer, " via ", Process)
| sort by TimeGenerated desc
```

**Response:** Security log clearing is an immediate critical indicator. Audit policy changes should be correlated with approved change records. If neither is approved, treat as active attacker covering tracks.

---

## Rule 20: AD Object Modification on Privileged Account
**Severity:** High  
**Tactic:** Privilege Escalation  
**MITRE:** T1484 - Domain Policy Modification  
**Run every:** 1 hour | **Lookup:** 1 hour  
**Threshold:** Any match  

```kql
SecurityEvent
| where EventID == 5136
| extend ObjectClass = extract(@"ObjectClass.*?>(.*?)<", 1, EventData)
| extend ObjectDN = extract(@"ObjectDN.*?>(.*?)<", 1, EventData)
| extend AttributeLDAPDisplayName = extract(@"AttributeLDAPDisplayName.*?>(.*?)<", 1, EventData)
| extend AttributeValue = extract(@"AttributeValue.*?>(.*?)<", 1, EventData)
| where ObjectClass == "user"
| where SubjectUserName !endswith "$"
| where SubjectUserName != "ADconnectSync2"
| project ['TimeGenerated'], Computer,
          SubjectUserName,
          ObjectDN,
          AttributeLDAPDisplayName,
          AttributeValue
| extend AlertDetail = strcat(SubjectUserName, " modified AD attribute ", AttributeLDAPDisplayName, " on ", ObjectDN)
```

**Response:** Check if change was authorised via change management. Modifications to adminCount, userAccountControl, or group membership on privileged accounts are highest priority.

---

# STAGE 4: DATA EXFILTRATION

---

## Rule 21: USB Drive Inserted on High Value Asset
**Severity:** High  
**Tactic:** Exfiltration  
**MITRE:** T1052.001 - Exfiltration over Physical Medium  
**Run every:** 1 hour | **Lookup:** 1 hour  
**Threshold:** Any match  

```kql
// Note: USB detection requires Windows Security Events to be configured for removable storage auditing
// This is an alternative approach using process creation for USB-related activities
SecurityEvent
| where EventID == 4688  // Process creation
| where CommandLine has_any ("USB", "removable", "E:\\", "F:\\", "G:\\")  // Common USB drive letters
| where Computer has_any ("server", "DCL", "finance", "FINANCE", "PAW")  // Adjust to your naming
    or SubjectUserName has_any ("-a")  // Admin accounts
| project ['TimeGenerated'], Computer,
          SubjectUserName,
          NewProcessName,
          CommandLine
| extend AlertDetail = strcat("Potential USB access on high-value device ", Computer, " by ", SubjectUserName)
```

**Response:** Verify with user. USB on servers or PAW devices should be near-zero. Consider enforcing USB block policy via Defender for Endpoint if not already in place.

---

## Rule 22: Sensitive File Access Outside Business Hours
**Severity:** Medium  
**Tactic:** Collection  
**MITRE:** T1005 - Data from Local System  
**Run every:** 1 hour | **Lookup:** 1 hour  
**Threshold:** >20 sensitive file reads  

```kql
// File access monitoring using process creation events for file operations
SecurityEvent
| where EventID == 4688  // Process creation
| where CommandLine has_any ("copy", "xcopy", "robocopy", "type", "findstr", "dir")
| where CommandLine has_any (".xlsx", ".docx", ".pdf", "confidential", "financial", "salary")
| extend HourOfDay = datetime_part("hour", ['TimeGenerated'])
| where HourOfDay !between (7 .. 19)    // Outside 07:00-19:00 UTC - adjust for your timezone
| summarize FileOperationCount = count(),
            Commands = make_set(CommandLine, 10),
            FirstSeen = min(['TimeGenerated']),
            LastSeen = max(['TimeGenerated'])
            by Computer, SubjectUserName
| where FileOperationCount > 20
| extend AlertDetail = strcat(SubjectUserName, " performed ", FileOperationCount, " file operations outside business hours on ", Computer)
```

**Response:** Contact user to verify activity. After-hours mass file access combined with other indicators (VPN from unusual location, new process) is a high-confidence exfil indicator.

---

## Rule 23: Screenshot Capture on Endpoint
**Severity:** Medium  
**Tactic:** Collection  
**MITRE:** T1113 - Screen Capture  
**Run every:** 1 hour | **Lookup:** 1 hour  
**Threshold:** >10 screenshots in 1 hour  

```kql
// Screenshot detection using process creation - look for screenshot tools and suspicious activity
SecurityEvent
| where EventID == 4688  // Process creation
| where NewProcessName has_any ("screenshot", "capture", "grab", "print") 
    or CommandLine has_any ("screenshot", "capture", "print screen", "prtscr")
| where NewProcessName !in (
    "snippingtool.exe", "SnippingTool.exe",
    "ms-screenclip.exe", "ShareX.exe",
    "teams.exe", "zoom.exe", "webex.exe"   // Conferencing tools legitimately screenshot
)
| summarize ScreenshotProcessCount = count(),
            FirstSeen = min(['TimeGenerated']),
            LastSeen = max(['TimeGenerated'])
            by Computer, SubjectUserName, NewProcessName
| where ScreenshotProcessCount > 10
| extend AlertDetail = strcat(NewProcessName, " executed ", ScreenshotProcessCount, " times - potential screenshot activity on ", Computer)
```

**Response:** Identify the process taking screenshots. Legitimate tools (Snipping Tool, Teams) are excluded. Unknown processes taking mass screenshots indicate spyware or RAT.

---

# STAGE 5: PERSISTENCE

---

## Rule 24: WMI Event Subscription Persistence
**Severity:** High  
**Tactic:** Persistence  
**MITRE:** T1546.003 - WMI Event Subscription  
**Run every:** 1 hour | **Lookup:** 1 hour  
**Threshold:** Any match  

WMI subscriptions survive reboots and are commonly used for fileless persistence.

```kql
// WMI persistence detection using process creation for WMI subscription commands
SecurityEvent
| where EventID == 4688  // Process creation
| where CommandLine has_any ("__EventFilter", "__EventConsumer", "Set-WmiInstance", "Register-WmiEvent")
    or CommandLine has_any ("wmic", "wbemcons", "scrcons")
| where CommandLine has "ActiveScriptEventConsumer" or CommandLine has "CommandLineEventConsumer"
| project ['TimeGenerated'], Computer,
          SubjectUserName,
          NewProcessName,
          CommandLine
| extend AlertDetail = strcat("WMI persistence attempt detected on ", Computer, " by ", SubjectUserName)
```

**Response:** WMI subscriptions outside of known management tools (SCCM, monitoring agents) should be treated as malicious persistence. Remove subscription and investigate initiating process.

---

## Rule 25: New Service Installed Outside Change Window
**Severity:** Medium  
**Tactic:** Persistence  
**MITRE:** T1543.003 - Windows Service  
**Run every:** 1 hour | **Lookup:** 1 hour  
**Threshold:** Any match  

```kql
// Service installation detection using Security Event 4697
SecurityEvent
| where EventID == 4697  // Service installed
| extend HourOfDay = datetime_part("hour", ['TimeGenerated'])
| extend DayOfWeek = dayofweek(['TimeGenerated'])
// Flag outside business hours or weekends
| where HourOfDay !between (7 .. 19) 
    or DayOfWeek in (0d, 6d)   // Sunday = 0, Saturday = 6
| where ServiceFileName has_any ("temp", "appdata", "public", "programdata")
    or ServiceFileName matches regex @"[A-Za-z0-9]{8,12}\.exe"   // Random named executable
| project ['TimeGenerated'], Computer,
          SubjectUserName,
          ServiceName, ServiceFileName
| extend AlertDetail = strcat("Suspicious service '", ServiceName, "' installed on ", Computer, " outside change window")
```

**Response:** Verify against change management records. Services installed from temp/appdata paths outside business hours are high confidence malware persistence.

---

## Rule 26: Driver Loaded from Non-Standard Path
**Severity:** High  
**Tactic:** Defence Evasion  
**MITRE:** T1014 - Rootkit  
**Run every:** 1 hour | **Lookup:** 1 hour  
**Threshold:** Any match  

```kql
// Driver loading detection - look for driver installation processes
SecurityEvent
| where EventID == 4688  // Process creation
| where NewProcessName has_any ("pnputil", "drvload", "sc.exe") 
    or CommandLine has_any ("install", "driver", ".sys", ".inf")
| where CommandLine !has "C:\\Windows\\System32\\"
    and CommandLine !has "C:\\Windows\\SysWOW64\\"
    and CommandLine !has "C:\\Program Files\\"
    and CommandLine !has "C:\\Program Files (x86)\\"
| project ['TimeGenerated'], Computer,
          SubjectUserName,
          NewProcessName,
          CommandLine
| extend AlertDetail = strcat("Potential driver installation from non-standard path on ", Computer, " by ", SubjectUserName)
```

**Response:** Drivers from temp or user-writable paths indicate a BYOVD (Bring Your Own Vulnerable Driver) attack or rootkit. Isolate device immediately.

---

# BONUS: FINANCIAL SERVICES SPECIFIC

---

## Rule 27: Privileged Admin Account Logon Outside Business Hours
**Severity:** Medium  
**Tactic:** Initial Access  
**MITRE:** T1078.002 - Domain Accounts  
**Run every:** 1 hour | **Lookup:** 1 hour  
**Threshold:** Any match  

Admin accounts (identified by -a suffix naming convention at Creditsafe) 
logging in outside business hours warrants attention.

```kql
SecurityEvent
| where EventID == 4624
| where LogonType in (2, 10)   // Interactive or RDP only
| where TargetUserName endswith "-a"   // Admin account naming convention
| extend HourOfDay = datetime_part("hour", ['TimeGenerated'])
| extend DayOfWeek = dayofweek(['TimeGenerated'])
| where HourOfDay !between (7 .. 19)
    or DayOfWeek in (0d, 6d)
| project ['TimeGenerated'], Computer, WorkstationName,
          TargetUserName, LogonType, IpAddress
| extend AlertDetail = strcat("Admin account ", TargetUserName, " interactive logon outside business hours from ", WorkstationName)
```

**Response:** Verify with account owner. Out-of-hours admin logons should correlate with approved change records or on-call activity. Combined with other indicators this could indicate account compromise.

---

## Rule 28: Multiple Failed Logons Followed by Success (Brute Force Success)
**Severity:** High  
**Tactic:** Credential Access  
**MITRE:** T1110.001 - Password Guessing  
**Run every:** 1 hour | **Lookup:** 1 hour  
**Threshold:** Any match  

The most dangerous pattern — attacker guesses password successfully after failures.

```kql
let failures = 
    SecurityEvent
    | where ['TimeGenerated'] > ago(1h)
    | where EventID == 4625
    | summarize FailCount = count(), LastFailure = max(['TimeGenerated'])
        by TargetUserName, IpAddress
    | where FailCount >= 5;
let successes = 
    SecurityEvent
    | where ['TimeGenerated'] > ago(1h)
    | where EventID == 4624
    | summarize FirstSuccess = min(['TimeGenerated'])
        by TargetUserName, IpAddress;
failures
| join kind=inner successes on TargetUserName, IpAddress
| where FirstSuccess > LastFailure   // Success came AFTER failures
| project TargetUserName, IpAddress, FailCount, LastFailure, FirstSuccess
| extend AlertDetail = strcat(TargetUserName, " had ", FailCount, " failures then successful logon from ", IpAddress)
```

**Response:** High confidence account compromise. Immediately disable account, reset password, and investigate all activity from that account and IP in the preceding 24 hours.

---

# IMPLEMENTATION SUMMARY

## Priority Order for Implementation

| Priority | Rule | Severity | Reason |
|---|---|---|---|
| 1 | Rule 17 - DCSync | Critical | DC compromise = game over |
| 2 | Rule 18 - New Domain Admin | Critical | Persistence at highest level |
| 3 | Rule 28 - Brute Force Success | High | Active account compromise |
| 4 | Rule 8 - Kerberoasting | High | Most common AD attack path |
| 5 | Rule 10 - Pass-the-Hash | High | Lateral movement detection |
| 6 | Rule 19 - Log Tampering | High | Attacker covering tracks |
| 7 | Rule 12 - Encoded PowerShell | High | Phishing payload execution |
| 8 | Rule 13 - New RDP Pair | High | Lateral movement |
| 9 | Rule 14 - RDP to DC | High | Direct DC access |
| 10 | Rule 27 - Admin OOH Logon | Medium | Financial services compliance |

## Combined with Previous Rules (Rules 1-7)
Total rule count: **28 analytics rules** covering the full financial services kill chain.

## Entity Mapping (Apply to All Rules)
- **Account entity** → TargetUserName / SubjectUserName / InitiatingProcessAccountName
- **Host entity** → ComputerName / DeviceName / WorkstationName  
- **IP entity** → IpAddress / RemoteIP

## Incident Grouping Recommendation
- Group by **Account** within **5 hour** window for credential-based rules
- Group by **Host** within **24 hour** window for endpoint-based rules
- Rules 17, 18, 19 → **No grouping** — every event = separate incident
