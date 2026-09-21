# Starter KQL — Analyst Queries

Use watchlist/table names as configured in your Sentinel workspace. Adjust the time range if needed.

## 1. Open incidents and new alerts (starting point)

```kql
_GetWatchlist("SecurityAlert_CL")
| where TimeGenerated between (datetime(2026-05-28 07:00:00) .. datetime(2026-05-28 11:00:00))
| where Status in ("New", "InProgress") or IsIncident == 1
| project TimeGenerated, DisplayName, AlertSeverity, SystemAlertId, Status, CompromisedEntity,
          Tactics, Techniques, ConfidenceScore, ExtendedProperties
| order by TimeGenerated asc
```

## 2. All alerts by severity

```kql
_GetWatchlist("SecurityAlert_CL")
| where TimeGenerated between (datetime(2026-05-28 06:00:00) .. datetime(2026-05-28 11:00:00))
| summarize Count=count() by AlertSeverity, Status
| order by Count desc
```

## 3. Evidence for a specific alert

```kql
let TargetAlertId = "sa-7f2a-9c1b-4e8d-a6f3-001";  // replace with alert under investigation
_GetWatchlist("AlertEvidence_CL")
| where AlertId == TargetAlertId
| project TimeGenerated, EntityType, EvidenceRole, FileName, SHA256, AccountUpn, DeviceName,
          RemoteIP, RemoteUrl, ProcessCommandLine, NetworkMessageId, CloudResource, AdditionalFields
| order by TimeGenerated asc
```

## 4. Map alerts to evidence (join)

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

## 5. Identify top affected devices from alerts

```kql
_GetWatchlist("SecurityAlert_CL")
| where TimeGenerated between (datetime(2026-05-28 07:00:00) .. datetime(2026-05-28 11:00:00))
| extend EntitiesJson = parse_json(Entities)
| mv-expand EntitiesJson
| extend DeviceName = tostring(EntitiesJson.Name)
| where EntitiesJson.Type == "host"
| summarize Alerts=dcount(SystemAlertId) by DeviceName
| order by Alerts desc
```

## 6. Process events for a device (pivot)

```kql
let TargetDevice = "CS-DEV-01982";  // set after triage
_GetWatchlist("DeviceProcessEvents_CL")
| where TimeGenerated between (datetime(2026-05-28 08:00:00) .. datetime(2026-05-28 11:00:00))
| where DeviceName == TargetDevice
| project TimeGenerated, ActionType, FileName, ProcessCommandLine, InitiatingProcessFileName,
          InitiatingProcessCommandLine, SHA256, AccountUpn
| order by TimeGenerated asc
```

## 7. Process tree style view

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

## 8. Network connections for device

```kql
_GetWatchlist("DeviceNetworkEvents_CL")
| where DeviceName == "CS-DEV-01982"
| where TimeGenerated between (datetime(2026-05-28 08:00:00) .. datetime(2026-05-28 11:00:00))
| project TimeGenerated, ActionType, RemoteIP, RemoteUrl, RemotePort, Protocol,
          InitiatingProcessFileName, InitiatingProcessCommandLine, AdditionalFields
| order by TimeGenerated asc
```

## 9. Correlate network to alert evidence

```kql
let SuspiciousUrls = _GetWatchlist("AlertEvidence_CL")
| where isnotempty(RemoteUrl)
| distinct RemoteUrl;
_GetWatchlist("DeviceNetworkEvents_CL")
| where RemoteUrl in (SuspiciousUrls)
| project TimeGenerated, DeviceName, ActionType, RemoteIP, RemoteUrl, InitiatingProcessFileName
| order by TimeGenerated asc
```

## 10. File events on endpoint

```kql
_GetWatchlist("DeviceFileEvents_CL")
| where DeviceName == "CS-DEV-01982"
| where TimeGenerated between (datetime(2026-05-28 09:00:00) .. datetime(2026-05-28 11:00:00))
| project TimeGenerated, ActionType, FileName, FolderPath, SHA256, SensitivityLabel,
          InitiatingProcessFileName, AdditionalFields
| order by TimeGenerated asc
```

## 11. Sign-in volume overview (find who stands out)

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

## 11b. Risky sign-ins across the tenant (narrow the field)

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

## 11c. Sign-ins for a specific user (after pivot)

```kql
let TargetUser = "jordan.velez@creditsafe.com";  // replace once identified
_GetWatchlist("SigninLogs_CL")
| where TimeGenerated between (datetime(2026-05-27 00:00:00) .. datetime(2026-05-28 12:00:00))
| where UserPrincipalName == TargetUser
| extend Loc = parse_json(LocationDetails)
| project TimeGenerated, ResultDescription, IPAddress, City=tostring(Loc.City),
          IsRisky, RiskLevelDuringSignIn, SessionId, CorrelationId, AppDisplayName,
          ClientAppUsed, Status, AuthenticationDetails
| order by TimeGenerated asc
```

## 11d. Correlate sign-in session to cloud activity

```kql
let TargetSession = "sess-jv-0945-dd44";  // example — discover via user timeline
_GetWatchlist("SigninLogs_CL")
| where SessionId == TargetSession
| project TimeGenerated, UserPrincipalName, SessionId, CorrelationId, IPAddress, AppDisplayName
| join kind=inner (
    _GetWatchlist("CloudAppEvents_CL")
    | extend Sess = parse_json(SessionData)
    | where tostring(Sess.SessionId) == TargetSession
) on $left.CorrelationId == $right.Sess.CorrelationId
```

## 12. Cloud application activity

```kql
let TargetUser = "jordan.velez@creditsafe.com";
_GetWatchlist("CloudAppEvents_CL")
| where Timestamp between (datetime(2026-05-28 09:00:00) .. datetime(2026-05-28 11:00:00))
| where AccountObjectId in (
    _GetWatchlist("IdentityInfo_CL")
    | where AccountUPN == TargetUser
    | project AccountObjectId
)
| project Timestamp, ActionType, ObjectName, Application, IPAddress, IsAdminOperation,
          UncommonForUser, RawEventData, ActivityObjects, SessionData
| order by Timestamp asc
```

## 13. Email pivot by NetworkMessageId

```kql
let MsgId = "nm-ext-ai-trial-7c4a9b2e-001";  // from alert evidence
_GetWatchlist("EmailEvents_CL")
| where NetworkMessageId == MsgId
| project TimeGenerated, Subject, SenderFromAddress, UrlCount, ThreatTypes, ThreatClassification,
          DeliveryAction, AuthenticationDetails, AdditionalFields
```

## 14. Identity enrichment

```kql
_GetWatchlist("IdentityInfo_CL")
| where AccountUPN == "jordan.velez@creditsafe.com"
| project AccountUPN, AccountDisplayName, Department, JobTitle, Manager, RiskLevel, RiskState,
          IsMFARegistered, GroupMembership, AssignedRoles, InvestigationPriority
```

## 15. Union timeline (multi-source)

```kql
let start = datetime(2026-05-28 08:00:00);
let end   = datetime(2026-05-28 11:00:00);
let device = "CS-DEV-01982";
union isfuzzy=true
    (_GetWatchlist("DeviceProcessEvents_CL") | where DeviceName == device and TimeGenerated between (start .. end)
     | extend Source="Process", Detail=strcat(FileName, " | ", ProcessCommandLine)),
    (_GetWatchlist("DeviceNetworkEvents_CL") | where DeviceName == device and TimeGenerated between (start .. end)
     | extend Source="Network", Detail=strcat(RemoteUrl, " | ", ActionType)),
    (_GetWatchlist("DeviceFileEvents_CL") | where DeviceName == device and TimeGenerated between (start .. end)
     | extend Source="File", Detail=strcat(ActionType, " | ", FileName)),
    (_GetWatchlist("CloudAppEvents_CL") | where TimeGenerated between (start .. end)
     | extend Source="Cloud", Detail=strcat(ActionType, " | ", ObjectName))
| project TimeGenerated, Source, Detail
| order by TimeGenerated asc
```

## 16. Device inventory context

```kql
_GetWatchlist("DeviceInfo_CL")
| where DeviceName == "CS-DEV-01982"
| project DeviceName, MachineGroup, OSVersion, ExposureLevel, AssetValue, LoggedOnUsers,
          DeviceManualTags, MitigationStatus, SensorHealthState
```

## 17. Investigate Spoofed Emails

```kql
_GetWatchlist("EmailEvents_CL")
| where TimeGenerated between (datetime(2026-05-28 06:00:00) .. datetime(2026-05-28 12:00:00))
| where SenderFromAddress == "cato.syversen@creditsafe.com"
| extend AuthDetails = parse_json(AuthenticationDetails)
| project TimeGenerated, Subject, SenderFromAddress, DeliveryAction, ThreatTypes, 
          SPF=AuthDetails.SPF, DKIM=AuthDetails.DKIM, DMARC=AuthDetails.DMARC
| order by TimeGenerated asc
```
