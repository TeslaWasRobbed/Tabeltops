# Authoritative SIEM Schema Contract

## Rule

A KQL table exists only when a schema CSV has been supplied for it. The scenario generator, table browser, alerts and facilitator queries must use the exact table and column names from these files.

No additional `_CL` tables or convenience tables may be invented unless the exercise owner explicitly approves and supplies or authorises creation of its schema. `CiscoASA_CL` is the sole approved exercise-owned exception.

## Available tables

The following 22 tables are authoritative:

1. `AADRiskyUsers`
2. `AlertEvidence`
3. `AuditLogs`
4. `AzureActivity`
5. `BehaviorAnalytics`
6. `CloudAppEvents`
7. `DeviceFileEvents`
8. `DeviceInfo`
9. `DeviceNetworkEvents`
10. `DeviceProcessEvents`
11. `DeviceRegistryEvents`
12. `EmailAttachmentInfo`
13. `EmailEvents`
14. `EmailUrlInfo`
15. `IdentityInfo`
16. `OfficeActivity`
17. `SecurityAlert`
18. `SecurityIncident`
19. `SigninLogs`
20. `ThreatIntelligenceIndicator`
21. `UrlClickEvents`
22. `CiscoASA_CL`

The first ten core Defender/Sentinel schemas are stored in `archive/2026-08-04_fresh-start`. The eleven supplied additional schemas and the explicitly approved `CiscoASA_CL` exercise schema are stored in `scenario/schema`.

## Evidence moved to existing tables

| Requirement | Authoritative representation |
| --- | --- |
| Personal phishing copy removed but shared-mailbox copy delivered | Recipient-specific rows and delivery fields in `EmailEvents` |
| Link contained in the phishing message | `EmailUrlInfo` |
| Louise clicked the link | `UrlClickEvents` |
| SparkRAT C2 and beacon frequency | `DeviceNetworkEvents` |
| Access to a Sentinel analytics-rule resource | `AzureActivity` plus the Azure/Log Analytics access in `SigninLogs` |
| Blocked personal OneDrive and USB transfers | `CloudAppEvents` action/result details |
| Storm-2077/TAG-100 IOC mapping | `ThreatIntelligenceIndicator` |
| Failed Cisco ASA exploitation attempts and blocked connection context | `CiscoASA_CL` |

## Evidence outside the SIEM

FreshService is a separate interface view backed by scenario application data. It is not a KQL table.

The following previously proposed tables do not exist and must not be referenced:

- `FreshServiceTickets_CL`
- `AbnormalEmailLogs_CL`
- `LAQueryLogs_CL`
- `DnsEvents_CL`
- `FirewallLogs_CL`
- `DlpEvents_CL`
- `ThreatIntelIndicators`

The broader `FirewallLogs_CL` and DNS storylines remain unavailable. Cisco ASA evidence is permitted only through the authoritative `CiscoASA_CL` schema.
