# Facilitator Validation KQL

> Reveals ground truth. Use in debrief only.

## Full incident timeline (all key sources)

```kql
let start = datetime(2026-05-28 06:00:00);
let end   = datetime(2026-05-28 11:00:00);
let user = "jordan.velez@creditsafe.com";
let device = "CS-DEV-01982";
union isfuzzy=true
    (_GetWatchlist("SecurityAlert_CL") | where TimeGenerated between (start .. end)
     | extend Source="Alert", Detail=DisplayName, Severity=AlertSeverity),
    (_GetWatchlist("DeviceProcessEvents_CL") | where DeviceName == device and TimeGenerated between (start .. end)
     | extend Source="Process", Detail=ProcessCommandLine, Severity=ActionType),
    (_GetWatchlist("DeviceNetworkEvents_CL") | where DeviceName == device and TimeGenerated between (start .. end)
     | extend Source="Network", Detail=strcat(RemoteUrl, " [", ActionType, "]"), Severity=ActionType),
    (_GetWatchlist("DeviceFileEvents_CL") | where DeviceName == device and TimeGenerated between (start .. end)
     | extend Source="File", Detail=strcat(ActionType, ": ", FileName), Severity=SensitivityLabel),
    (_GetWatchlist("SigninLogs_CL") | where UserPrincipalName == user and TimeGenerated between (start .. end)
     | extend Source="SignIn", Detail=strcat(IPAddress, " ", tostring(parse_json(Status))), Severity=RiskLevelDuringSignIn),
    (_GetWatchlist("CloudAppEvents_CL") | where AccountObjectId == "8f3a2b1c-4d5e-6a7b-8c9d-0e1f2a3b4c5d" and Timestamp between (start .. end)
     | extend Source="Cloud", Detail=strcat(ActionType, ": ", ObjectName), Severity=Application)
| project TimeGenerated, Source, Detail, Severity
| order by TimeGenerated asc
```

## All events for affected user

```kql
let user = "jordan.velez@creditsafe.com";
let oid = "8f3a2b1c-4d5e-6a7b-8c9d-0e1f2a3b4c5d";
union isfuzzy=true
    (_GetWatchlist("SigninLogs_CL") | where UserPrincipalName == user),
    (_GetWatchlist("DeviceProcessEvents_CL") | where AccountUpn == user),
    (_GetWatchlist("CloudAppEvents_CL") | where AccountObjectId == oid),
    (_GetWatchlist("AlertEvidence_CL") | where AccountUpn == user)
| project TimeGenerated, Type, Details=coalesce(ProcessCommandLine, tostring(ActivityType), Title)
| order by TimeGenerated asc
```

## All events for affected device

```kql
let device = "CS-DEV-01982";
union isfuzzy=true
    (_GetWatchlist("DeviceProcessEvents_CL") | where DeviceName == device),
    (_GetWatchlist("DeviceNetworkEvents_CL") | where DeviceName == device),
    (_GetWatchlist("DeviceFileEvents_CL") | where DeviceName == device),
    (_GetWatchlist("AlertEvidence_CL") | where DeviceName == device)
| project TimeGenerated, Type, FileName, ProcessCommandLine, RemoteUrl, ActionType
| order by TimeGenerated asc
```

## All alert evidence (incident alerts)

```kql
let IncidentAlerts = _GetWatchlist("SecurityAlert_CL")
| where SystemAlertId startswith "sa-7f2a" or SystemAlertId startswith "sa-benign" or SystemAlertId startswith "sa-false"
| project SystemAlertId, DisplayName;
_GetWatchlist("AlertEvidence_CL")
| join kind=inner IncidentAlerts on $left.AlertId == $right.SystemAlertId
| project TimeGenerated, DisplayName, EntityType, EvidenceRole, FileName, SHA256,
          RemoteIP, RemoteUrl, ProcessCommandLine, CloudResource, AdditionalFields
| order by AlertId, TimeGenerated asc
```

## Suspicious process tree (ground truth chain)

```kql
_GetWatchlist("DeviceProcessEvents_CL")
| where DeviceName == "CS-DEV-01982"
| where TimeGenerated between (datetime(2026-05-28 09:10:00) .. datetime(2026-05-28 09:20:00))
| project TimeGenerated,
          Parent=InitiatingProcessFileName,
          Child=FileName,
          ChildCmd=ProcessCommandLine,
          ParentCmd=InitiatingProcessCommandLine,
          SHA256
| order by TimeGenerated asc
```

## Suspicious network destinations

```kql
_GetWatchlist("DeviceNetworkEvents_CL")
| where DeviceName == "CS-DEV-01982"
| where RemoteUrl has_any ("pkg-cache-lab.invalid", "update-cdn-lab.example", "exfil-gateway-lab.invalid")
    or RemoteIP in ("203.0.113.47", "198.51.100.22", "203.0.113.99")
| extend Af = parse_json(AdditionalFields)
| project TimeGenerated, ActionType, RemoteIP, RemoteUrl, InitiatingProcessFileName,
          Blocked=Af.BlockedBy, BytesOut=Af.BytesOut
| order by TimeGenerated asc
```

## Cloud activity by affected user

```kql
_GetWatchlist("CloudAppEvents_CL")
| where AccountObjectId == "8f3a2b1c-4d5e-6a7b-8c9d-0e1f2a3b4c5d"
| extend Raw = parse_json(RawEventData)
| project Timestamp, ActionType, ObjectName, UncommonForUser, Raw.SensitivityLabel, AdditionalFields
| order by Timestamp asc
```

## Email events by NetworkMessageId

```kql
_GetWatchlist("EmailEvents_CL")
| where NetworkMessageId in (
    "nm-ext-ai-trial-7c4a9b2e-001",
    "nm-newsletter-npm-8d1f3a4c-002",
    "nm-internal-sharepoint-9e2b5c6d-003"
)
| project TimeGenerated, NetworkMessageId, Subject, SenderFromAddress, ThreatTypes,
          DeliveryAction, UrlCount, AdditionalFields
| order by TimeGenerated asc
```

## Identity enrichment for affected user

```kql
_GetWatchlist("IdentityInfo_CL")
| where AccountUPN == "jordan.velez@creditsafe.com"
| extend Groups = parse_json(GroupMembership)
| project AccountUPN, Department, JobTitle, Manager, RiskLevel, IsMFARegistered,
          Groups, InvestigationPriority, BlastRadius
```

## Validation: blocked vs successful exfil paths

```kql
_GetWatchlist("DeviceNetworkEvents_CL")
| where DeviceName == "CS-DEV-01982"
| where TimeGenerated between (datetime(2026-05-28 09:15:00) .. datetime(2026-05-28 09:20:00))
| extend Af = parse_json(AdditionalFields)
| project TimeGenerated, ActionType, RemoteUrl, Af
```

## Validation: package install command line

```kql
_GetWatchlist("DeviceProcessEvents_CL")
| where ProcessCommandLine has "@labdev/telemetry-helper"
| project TimeGenerated, DeviceName, AccountUpn, ProcessCommandLine, InitiatingProcessCommandLine, SHA256
```

## Validation: benign alert filter check

```kql
_GetWatchlist("SecurityAlert_CL")
| where SystemAlertId startswith "sa-benign"
| project TimeGenerated, DisplayName, Status, CompromisedEntity, ExtendedProperties
```

## Validation: false lead — disabled contractor

```kql
union _GetWatchlist("SigninLogs_CL"), _GetWatchlist("SecurityAlert_CL")
| where UserPrincipalName == "t.oconnor.contractor@creditsafe.com"
    or CompromisedEntity == "t.oconnor.contractor@creditsafe.com"
| project TimeGenerated, Type, Details=coalesce(DisplayName, ResultType)
```

## Validation: false lead — Cato Syversen (Spoofing & Travel)

```kql
union
    (_GetWatchlist("SigninLogs_CL") | where UserPrincipalName == "cato.syversen@creditsafe.com" | project TimeGenerated, Type="SignIn", Details=strcat(IPAddress, " ", tostring(parse_json(Status)))),
    (_GetWatchlist("EmailEvents_CL") | where SenderFromAddress == "cato.syversen@creditsafe.com" | project TimeGenerated, Type="Email", Details=strcat(Subject, " (", DeliveryAction, ")"))
| order by TimeGenerated asc
```
