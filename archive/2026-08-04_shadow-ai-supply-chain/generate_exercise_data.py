#!/usr/bin/env python3
"""Generate SOC tabletop exercise CSV watchlists and documentation."""
import csv
import json
import os
from pathlib import Path

BASE = Path(__file__).parent
TENANT = "tenant-lab-001-a000-0000-0000-000000000001"

# Core entities
USER_UPN = "jordan.velez@creditsafe.com"
USER_OID = "8f3a2b1c-4d5e-6a7b-8c9d-0e1f2a3b4c5d"
USER_DISPLAY = "Jordan Velez"
USER_SID = "S-1-5-21-1000000000-2000000000-3000000000-104421"
DEVICE_ID = "dev-01982-a1b2-c3d4-e5f6-7890abcd0198"
DEVICE_NAME = "CS-DEV-01982"
AAD_DEVICE = "aad-dev-01982-1111-2222-3333-444455556666"
REPORT_BASE = 8829100000000

# Package / tooling
PKG_NAME = "@labdev/telemetry-helper"
PKG_VERSION = "2.1.4"
PKG_SHA256 = "a7f3c91e2b8d4f6a0c1e5d9b3a7f2c8e1d4b6a9f0c3e7d2b5a8f1c4e9d6b3a7f2"
PKG_SHA1 = "7a3f9c2e1b8d4f6a0c5e9d3b7a2f1c8e4d6b9a0"
PS1_SHA256 = "c4e9d6b3a7f2c8e1d5b9a0f3c7e2d8b5a1f6c4e9d3b7a2f8c1e5d9b6a3f7c2e8"
PS1_SHA1 = "4e9d6b3a7f2c8e1d5b9a0f3c7e2d8b5a1f6c4e9"
STAGE_ZIP_SHA256 = "f1c4e9d6b3a7f2c8e5d9b0a3f7c2e8d1b5a9f0c3e7d2b6a8f1c4e9d5b3a7f2c8"
REMOTE_IP_C2 = "203.0.113.47"
REMOTE_IP_UPDATE = "198.51.100.22"
REMOTE_URL_PKG = "https://pkg-cache-lab.invalid/v2/registry/@labdev/telemetry-helper/-/telemetry-helper-2.1.4.tgz"
REMOTE_URL_C2 = "https://update-cdn-lab.example/sync/v1/channel"
NETWORK_MSG_EXTERNAL = "nm-ext-ai-trial-7c4a9b2e-001"
NETWORK_MSG_NEWSLETTER = "nm-newsletter-npm-8d1f3a4c-002"
NETWORK_MSG_INTERNAL = "nm-internal-sharepoint-9e2b5c6d-003"

# Alert IDs
ALERTS = {
    "primary_ps": "sa-7f2a-9c1b-4e8d-a6f3-001",
    "network_out": "sa-7f2a-9c1b-4e8d-a6f3-002",
    "child_proc": "sa-7f2a-9c1b-4e8d-a6f3-003",
    "cloud_access": "sa-7f2a-9c1b-4e8d-a6f3-004",
    "package_anomaly": "sa-7f2a-9c1b-4e8d-a6f3-005",
    "email_url": "sa-7f2a-9c1b-4e8d-a6f3-006",
    "sensitive_dl": "sa-7f2a-9c1b-4e8d-a6f3-007",
    "signin_risk": "sa-7f2a-9c1b-4e8d-a6f3-008",
    "benign_vscode": "sa-benign-vscode-009",
    "benign_npm_peer": "sa-benign-npm-peer-010",
    "benign_git": "sa-benign-git-011",
    "false_leaver": "sa-false-leaver-012",
    "benign_dotnet": "sa-benign-dotnet-013",
}

VENDOR_IDS = {k: f"defender-{v}" for k, v in zip(ALERTS, range(88001, 88014))}


def j(obj):
    return json.dumps(obj, separators=(",", ":"))


def esc(s):
    if s is None:
        return ""
    s = str(s)
    if "," in s or '"' in s or "\n" in s:
        return '"' + s.replace('"', '""') + '"'
    return s


def row_csv(values):
    return ",".join(esc(v) for v in values)


def write_csv(name, headers, rows):
    out_dir = BASE / "watchlists"
    out_dir.mkdir(exist_ok=True)
    
    if len(headers) > 50:
        important = {
            # Common
            "TimeGenerated", "Timestamp", "Type", "TenantId", "ReportId", "AdditionalFields",
            # SecurityAlert
            "DisplayName", "AlertSeverity", "SystemAlertId", "Status", "CompromisedEntity", "ExtendedProperties", "IsIncident",
            # AlertEvidence
            "AlertId", "EntityType", "EvidenceRole", "FileName", "SHA256", "AccountUpn", "DeviceName", "RemoteUrl", "ProcessCommandLine",
            # DeviceInfo
            "MachineGroup", "OSVersion", "ExposureLevel", "AssetValue", "LoggedOnUsers",
            # DeviceProcessEvents / Network / File
            "ActionType", "InitiatingProcessFileName", "InitiatingProcessCommandLine", "RemoteIP", "RemotePort", "Protocol", "FolderPath", "SensitivityLabel",
            # SigninLogs
            "UserPrincipalName", "ResultDescription", "IPAddress", "LocationDetails", "AppDisplayName", "IsRisky", "ResultType", "CorrelationId", "SessionId",
            # CloudAppEvents
            "ObjectName", "Application", "IsAdminOperation", "UncommonForUser", "AccountObjectId", "RawEventData",
            # EmailEvents
            "NetworkMessageId", "Subject", "SenderFromAddress", "UrlCount", "ThreatTypes", "ThreatClassification",
            # IdentityInfo
            "AccountUPN", "AccountDisplayName", "Department", "JobTitle", "Manager", "RiskLevel", "RiskState", "IsMFARegistered"
        }
        
        keep_indices = []
        for i, h in enumerate(headers):
            if h in important:
                keep_indices.append(i)
                
        for i, h in enumerate(headers):
            if len(keep_indices) >= 50:
                break
            if i not in keep_indices:
                keep_indices.append(i)
                
        keep_indices.sort()
        headers = [headers[i] for i in keep_indices]
        rows = [[r[i] if i < len(r) else "" for i in keep_indices] for r in rows]

    path = out_dir / name
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
        w.writerow(headers)
        for r in rows:
            w.writerow(r)
    print(f"Wrote {path} ({len(rows)} rows, {len(headers)} columns)")


def dt(s):
    return s


# --- SecurityAlert_CL ---
def gen_security_alerts():
    h = [
        "TenantId", "TimeGenerated", "DisplayName", "AlertName", "AlertSeverity", "Description",
        "ProviderName", "VendorName", "VendorOriginalId", "SystemAlertId", "ResourceId",
        "SourceComputerId", "AlertType", "ConfidenceLevel", "ConfidenceScore", "IsIncident",
        "StartTime", "EndTime", "ProcessingEndTime", "RemediationSteps", "ExtendedProperties",
        "Entities", "SourceSystem", "WorkspaceSubscriptionId", "WorkspaceResourceGroup",
        "ExtendedLinks", "ProductName", "ProductComponentName", "AlertLink", "Status",
        "CompromisedEntity", "Tactics", "Techniques", "SubTechniques", "Type",
    ]
    rows = []

    def alert(tg, disp, name, sev, desc, sid, vid, atype, conf, score, incident, start, end,
              rem, ext, ent, status, comp, tactics, tech, subtech):
        rows.append([
            TENANT, tg, disp, name, sev, desc, "MDATP", "Microsoft", vid, sid, "", DEVICE_ID,
            atype, conf, score, 1 if incident else 0, start, end, end,
            rem, ext, ent, "Detection", "", "", "", "Microsoft Defender XDR", "Endpoint",
            f"https://security.microsoft.com/alerts/{sid}", status, comp, tactics, tech, subtech,
            "SecurityAlert",
        ])

    alert(
        "2026-05-28T09:14:22Z", "Suspicious PowerShell execution chain",
        "Suspicious PowerShell execution chain", "High",
        "Encoded PowerShell spawned from a Node package manager child process on a developer workstation.",
        ALERTS["primary_ps"], VENDOR_IDS["primary_ps"], "WindowsDefenderAv", "High", 82, 1,
        "2026-05-28T09:12:08Z", "2026-05-28T09:15:40Z",
        "Isolate device; collect process and script artifacts; review recent package installs.",
        j({"IncidentId": "inc-20260528-0042", "DetectionId": "T1059.001", "ScriptBlockLogging": "partial"}),
        j([{"Type": "account", "Name": USER_UPN}, {"Type": "host", "Name": DEVICE_NAME}]),
        "New", DEVICE_NAME, "Execution", "T1059.001", "T1059.001.001",
    )
    alert(
        "2026-05-28T09:18:05Z", "Outbound connection to low-reputation host",
        "Outbound connection to low-reputation host", "Medium",
        "Process initiated HTTPS connection to a recently registered domain used by third-party package mirrors.",
        ALERTS["network_out"], VENDOR_IDS["network_out"], "WindowsDefenderAv", "Medium", 68, 0,
        "2026-05-28T09:16:44Z", "2026-05-28T09:19:12Z",
        "Validate package source; block domain if unapproved; inspect staging directory.",
        j({"RemoteUrl": REMOTE_URL_C2, "RemoteIP": REMOTE_IP_C2, "ConnectionResult": "Success"}),
        j([{"Type": "host", "Name": DEVICE_NAME}, {"Type": "ip", "Address": REMOTE_IP_C2}]),
        "InProgress", DEVICE_NAME, "Command and Control", "T1071.001", "",
    )
    alert(
        "2026-05-28T09:13:01Z", "Suspicious child process from script interpreter",
        "Suspicious child process from script interpreter", "Medium",
        "cmd.exe launched powershell.exe with execution policy bypass following npm lifecycle script.",
        ALERTS["child_proc"], VENDOR_IDS["child_proc"], "WindowsDefenderAv", "Medium", 74, 0,
        "2026-05-28T09:12:45Z", "2026-05-28T09:14:00Z",
        "Review npm package integrity; compare package hash to known-good registry.",
        j({"ParentProcess": "node.exe", "ChildProcess": "powershell.exe"}),
        j([{"Type": "file", "Name": "postinstall.js"}, {"Type": "account", "Name": USER_UPN}]),
        "New", DEVICE_NAME, "Execution", "T1059.003", "T1059.001",
    )
    alert(
        "2026-05-28T10:02:33Z", "Unusual volume of SharePoint file downloads",
        "Unusual volume of SharePoint file downloads", "Medium",
        "User downloaded multiple files from a project site within a short interval including labeled content.",
        ALERTS["cloud_access"], VENDOR_IDS["cloud_access"], "MCAS", "Medium", 55, 0,
        "2026-05-28T09:55:00Z", "2026-05-28T10:05:00Z",
        "Verify business justification; confirm sensitivity label handling; assess DLP outcomes.",
        j({"SiteUrl": "https://corpexample.sharepoint.com/sites/DataPlatform", "DownloadCount": 4}),
        j([{"Type": "account", "Name": USER_UPN}]),
        "New", USER_UPN, "Collection", "T1530", "",
    )
    alert(
        "2026-05-28T09:11:48Z", "Anomalous postinstall script during package install",
        "Anomalous postinstall script during package install", "High",
        "Package manager executed lifecycle script invoking shell interpreter not typical for this project profile.",
        ALERTS["package_anomaly"], VENDOR_IDS["package_anomaly"], "WindowsDefenderAv", "High", 79, 0,
        "2026-05-28T09:10:30Z", "2026-05-28T09:12:30Z",
        "Quarantine package cache; rebuild node_modules from lockfile; scan staging folder.",
        j({"PackageName": PKG_NAME, "PackageVersion": PKG_VERSION, "Registry": "pkg-cache-lab.invalid"}),
        j([{"Type": "file", "Sha256": PKG_SHA256}]),
        "New", DEVICE_NAME, "Initial Access", "T1195.002", "",
    )
    alert(
        "2026-05-28T08:42:10Z", "Email reported with embedded link to external SaaS trial",
        "Email reported with embedded link to external SaaS trial", "Low",
        "User reported message promoting third-party AI development assistant trial with external registration URL.",
        ALERTS["email_url"], VENDOR_IDS["email_url"], "OfficeATP", "Low", 42, 0,
        "2026-05-28T08:35:00Z", "2026-05-28T08:45:00Z",
        "Review message headers and URL reputation; user awareness if benign marketing.",
        j({"NetworkMessageId": NETWORK_MSG_EXTERNAL, "UrlCount": 3}),
        j([{"Type": "mailbox", "Name": USER_UPN}, {"Type": "mailMessage", "NetworkMessageId": NETWORK_MSG_EXTERNAL}]),
        "Resolved", USER_UPN, "Initial Access", "T1566", "T1566.002",
    )
    alert(
        "2026-05-28T10:04:18Z", "Multiple downloads of customer analytics content",
        "Multiple downloads of customer analytics content", "Medium",
        "Several files with Customer Data sensitivity label accessed from developer endpoint session.",
        ALERTS["sensitive_dl"], VENDOR_IDS["sensitive_dl"], "MCAS", "Medium", 61, 0,
        "2026-05-28T09:58:00Z", "2026-05-28T10:08:00Z",
        "Coordinate with data owner; evaluate breach reporting threshold per data handling policy.",
        j({"Labels": ["Customer Data", "Internal"], "PolicyNote": "Approved project membership not verified in alert"}),
        j([{"Type": "account", "Name": USER_UPN}]),
        "InProgress", USER_UPN, "Exfiltration", "T1048", "",
    )
    alert(
        "2026-05-28T07:58:44Z", "Sign-in from unfamiliar geographic region",
        "Sign-in from unfamiliar geographic region", "Low",
        "Interactive sign-in observed from IP geolocated outside user's typical pattern.",
        ALERTS["signin_risk"], VENDOR_IDS["signin_risk"], "AADIdentityProtection", "Low", 48, 0,
        "2026-05-28T07:55:00Z", "2026-05-28T08:00:00Z",
        "Validate sign-in with user; review MFA and CA outcomes.",
        j({"SessionId": "sess-jv-0701-aa11", "Explainable": "Corporate VPN egress documented in Status field"}),
        j([{"Type": "account", "Name": USER_UPN}]),
        "Resolved", USER_UPN, "Initial Access", "T1078", "T1078.004",
    )
    # Benign
    alert(
        "2026-05-28T09:30:00Z", "Impossible travel activity",
        "Impossible travel activity", "Medium",
        "Sign-in from geographically distant locations within a short time.",
        "sa-rh-cato-travel", "defender-rh-002", "AADIdentityProtection", "Medium", 60, 0,
        "2026-05-28T09:25:00Z", "2026-05-28T09:25:00Z", "Confirm user location.",
        j({"PreviousLocation": "Cardiff, GB", "CurrentLocation": "Dublin, IE"}),
        j([{"Type": "account", "Name": "cato.syversen@creditsafe.com"}]),
        "Resolved", "cato.syversen@creditsafe.com", "Initial Access", "T1078", "",
    )
    alert(
        "2026-05-28T08:05:12Z", "Software update activity for supported IDE",
        "Software update activity for supported IDE", "Informational",
        "Signed update binary contacted vendor CDN for version manifest.",
        ALERTS["benign_vscode"], VENDOR_IDS["benign_vscode"], "WindowsDefenderAv", "Informational", 12, 0,
        "2026-05-28T08:03:00Z", "2026-05-28T08:06:00Z", "No action required.",
        j({"Product": "Code", "Channel": "stable"}),
        j([{"Type": "host", "Name": DEVICE_NAME}]),
        "Resolved", DEVICE_NAME, "", "", "",
    )
    alert(
        "2026-05-28T09:25:00Z", "npm registry cache refresh on peer developer host",
        "npm registry cache refresh on peer developer host", "Informational",
        "Routine package metadata fetch on separate device in Engineering machine group.",
        ALERTS["benign_npm_peer"], VENDOR_IDS["benign_npm_peer"], "WindowsDefenderAv", "Informational", 15, 0,
        "2026-05-28T09:22:00Z", "2026-05-28T09:26:00Z", "No action required.",
        j({"DeviceName": "CS-DEV-01407"}),
        j([{"Type": "host", "Name": "CS-DEV-01407"}]),
        "Resolved", "CS-DEV-01407", "", "", "",
    )
    alert(
        "2026-05-28T08:48:30Z", "Git credential manager authentication",
        "Git credential manager authentication", "Informational",
        "Expected developer workflow invoking git-credential-manager-core for Azure DevOps.",
        ALERTS["benign_git"], VENDOR_IDS["benign_git"], "WindowsDefenderAv", "Informational", 18, 0,
        "2026-05-28T08:47:00Z", "2026-05-28T08:49:00Z", "No action required.",
        j({"Remote": "dev.azure.com/corp-example"}),
        j([{"Type": "account", "Name": USER_UPN}]),
        "Resolved", USER_UPN, "", "", "",
    )
    alert(
        "2026-05-28T06:12:00Z", "Failed sign-in for disabled former contractor account",
        "Failed sign-in for disabled former contractor account", "Low",
        "Sign-in failure for account marked disabled in Entra ID.",
        ALERTS["false_leaver"], VENDOR_IDS["false_leaver"], "AADIdentityProtection", "Low", 35, 0,
        "2026-05-28T06:10:00Z", "2026-05-28T06:15:00Z", "Monitor for password spray; no linkage to active incident.",
        j({"UserPrincipalName": "t.oconnor.contractor@creditsafe.com"}),
        j([{"Type": "account", "Name": "t.oconnor.contractor@creditsafe.com"}]),
        "Resolved", "t.oconnor.contractor@creditsafe.com", "Credential Access", "T1110", "",
    )
    alert(
        "2026-05-28T08:22:00Z", "dotnet restore from nuget.org",
        "dotnet restore from nuget.org", "Informational",
        "Package restore for internal API solution using standard NuGet feed.",
        ALERTS["benign_dotnet"], VENDOR_IDS["benign_dotnet"], "WindowsDefenderAv", "Informational", 10, 0,
        "2026-05-28T08:20:00Z", "2026-05-28T08:24:00Z", "No action required.",
        j({"Solution": "Platform.Api.sln"}),
        j([{"Type": "host", "Name": DEVICE_NAME}]),
        "Resolved", DEVICE_NAME, "", "", "",
    )
    for i in range(100):
        alert(
            f"2026-05-28T11:{i%60:02d}:{i%60:02d}Z", f"Routine background scan {i}",
            f"Routine background scan {i}", "Informational",
            "Scheduled Windows Defender background scan completed.",
            f"sa-benign-scan-{i}", f"defender-890{i:03d}", "WindowsDefenderAv", "Informational", 5, 0,
            f"2026-05-28T11:{i%60:02d}:00Z", f"2026-05-28T11:{i%60:02d}:00Z", "No action required.",
            j({"ScanType": "Quick"}),
            j([{"Type": "host", "Name": DEVICE_NAME}]),
            "Resolved", DEVICE_NAME, "", "", "",
        )
    write_csv("SecurityAlert_CL.csv", h, rows)


def gen_alert_evidence():
    h = [
        "TenantId", "TimeGenerated", "Timestamp", "AlertId", "Title", "Categories",
        "AttackTechniques", "ServiceSource", "DetectionSource", "EntityType", "EvidenceRole",
        "EvidenceDirection", "FileName", "FolderPath", "SHA1", "SHA256", "FileSize",
        "ThreatFamily", "RemoteIP", "RemoteUrl", "AccountName", "AccountDomain", "AccountSid",
        "AccountObjectId", "AccountUpn", "DeviceId", "DeviceName", "LocalIP", "NetworkMessageId",
        "EmailSubject", "ApplicationId", "Application", "OAuthApplicationId", "ProcessCommandLine",
        "AdditionalFields", "RegistryKey", "RegistryValueName", "RegistryValueData",
        "CloudPlatform", "CloudResource", "Severity", "SourceSystem", "Type",
    ]
    rows = []

    def ev(aid, tg, ts, title, etype, role, **kw):
        rows.append([
            TENANT, tg, ts, aid, title, kw.get("cat", "SuspiciousActivity"),
            kw.get("tech", "T1059"), "Microsoft Defender for Endpoint",
            "AutomatedInvestigation", etype, role, kw.get("dir", "Related"),
            kw.get("fn", ""), kw.get("fp", ""), kw.get("s1", ""), kw.get("s256", ""),
            kw.get("fsize", ""), kw.get("tf", ""), kw.get("rip", ""), kw.get("rurl", ""),
            kw.get("an", "jordan.velez"), kw.get("ad", "creditsafe.com"), kw.get("asid", USER_SID),
            kw.get("aoid", USER_OID), kw.get("aupn", USER_UPN), kw.get("did", DEVICE_ID),
            kw.get("dname", DEVICE_NAME), kw.get("lip", "10.24.18.55"), kw.get("nmid", ""),
            kw.get("esub", ""), kw.get("appid", ""), kw.get("app", ""), kw.get("oauth", ""),
            kw.get("cmd", ""), kw.get("af", ""), "", "", "",
            kw.get("cloud", ""), kw.get("cres", ""), kw.get("sev", "Medium"),
            "Detection", "AlertEvidence",
        ])

    aid = ALERTS["primary_ps"]
    ev(aid, "2026-05-28T09:14:22Z", "2026-05-28T09:12:52Z", "Suspicious PowerShell execution chain",
       "Process", "Primary", cmd='powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand JABzAD0A...',
       s1=PS1_SHA1, s256=PS1_SHA256, fn="powershell.exe", fp="C:\\Windows\\System32\\WindowsPowerShell\\v1.0",
       af=j({"EncodedLength": 1842, "ParentFile": "cmd.exe"}))
    ev(aid, "2026-05-28T09:14:22Z", "2026-05-28T09:12:48Z", "Suspicious PowerShell execution chain",
       "Process", "Parent", cmd="cmd.exe /d /s /c node .\\node_modules\\@labdev\\telemetry-helper\\scripts\\postinstall.js",
       fn="cmd.exe", fp="C:\\Windows\\System32")
    ev(aid, "2026-05-28T09:14:22Z", "2026-05-28T09:12:45Z", "Suspicious PowerShell execution chain",
       "Process", "Parent", cmd='node.exe "C:\\Program Files\\nodejs\\node.exe" install', fn="node.exe",
       fp="C:\\Program Files\\nodejs")

    aid = ALERTS["network_out"]
    ev(aid, "2026-05-28T09:18:05Z", "2026-05-28T09:16:44Z", "Outbound connection to low-reputation host",
       "Ip", "Primary", rip=REMOTE_IP_C2, rurl=REMOTE_URL_C2, fn="powershell.exe",
       af=j({"ConnectionStatus": "Success", "BytesSent": 2048}))
    ev(aid, "2026-05-28T09:18:05Z", "2026-05-28T09:17:02Z", "Outbound connection to low-reputation host",
       "Url", "Related", rurl=REMOTE_URL_PKG, rip="198.51.100.22", af=j({"ConnectionStatus": "BlockedByFirewall"}))

    aid = ALERTS["package_anomaly"]
    ev(aid, "2026-05-28T09:11:48Z", "2026-05-28T09:10:55Z", "Anomalous postinstall script during package install",
       "File", "Primary", fn="postinstall.js",
       fp=f"C:\\Users\\jordan.velez\\Projects\\analytics-portal\\node_modules\\@labdev\\telemetry-helper\\scripts",
       s1="9b0f2a7c3e1d8f5a4c6e9d2b7a1f0c8e5d4b6a9", s256=PKG_SHA256, fsize=4288,
       af=j({"Package": PKG_NAME, "Version": PKG_VERSION}))
    ev(aid, "2026-05-28T09:11:48Z", "2026-05-28T09:10:30Z", "Anomalous postinstall script during package install",
       "File", "Related", fn="telemetry-helper-2.1.4.tgz", rip="198.51.100.22", rurl=REMOTE_URL_PKG)

    aid = ALERTS["email_url"]
    ev(aid, "2026-05-28T08:42:10Z", "2026-05-28T08:35:12Z", "Email reported with embedded link to external SaaS trial",
       "MailMessage", "Primary", nmid=NETWORK_MSG_EXTERNAL, esub="Exclusive trial: AI pair-programming for enterprise repos",
       aupn=USER_UPN, af=j({"PhishConfidence": "Low", "UserReported": True}))

    aid = ALERTS["cloud_access"]
    ev(aid, "2026-05-28T10:02:33Z", "2026-05-28T10:01:05Z", "Unusual volume of SharePoint file downloads",
       "CloudResource", "Primary", cloud="Azure", cres="/sites/DataPlatform/Shared Documents/CustomerAnalytics_Q2_Draft.xlsx",
       aupn=USER_UPN, af=j({"Action": "FileDownloaded", "SensitivityLabel": "Customer Data"}))
    ev(aid, "2026-05-28T10:02:33Z", "2026-05-28T09:59:22Z", "Unusual volume of SharePoint file downloads",
       "CloudResource", "Related", cloud="Azure", cres="/sites/DataPlatform/Shared Documents/README.md",
       aupn=USER_UPN, af=j({"Action": "FilePreviewed"}))

    aid = ALERTS["sensitive_dl"]
    ev(aid, "2026-05-28T10:04:18Z", "2026-05-28T10:00:48Z", "Multiple downloads of customer analytics content",
       "CloudResource", "Primary", cloud="Azure",
       cres="https://corpexample.sharepoint.com/sites/DataPlatform/Shared Documents/CustomerAnalytics_Q2_Draft.xlsx",
       sev="Medium", af=j({"Label": "Customer Data", "ExfiltrationProof": False}))

    aid = ALERTS["child_proc"]
    ev(aid, "2026-05-28T09:13:01Z", "2026-05-28T09:12:50Z", "Suspicious child process from script interpreter",
       "Process", "Primary", fn="powershell.exe", cmd="-ExecutionPolicy Bypass -File C:\\Users\\jordan.velez\\AppData\\Local\\Temp\\stage\\collect.ps1")

    aid = ALERTS["signin_risk"]
    ev(aid, "2026-05-28T07:58:44Z", "2026-05-28T07:56:10Z", "Sign-in from unfamiliar geographic region",
       "Account", "Primary", rip="198.18.0.44", aupn=USER_UPN,
       af=j({"City": "Dublin", "Country": "IE", "VpnEgress": True}))

    aid = ALERTS["child_proc"]
    ev(aid, "2026-05-28T09:13:01Z", "2026-05-28T09:12:48Z", "Suspicious child process from script interpreter",
       "File", "Related", fn="postinstall.js",
       fp="C:\\Users\\jordan.velez\\Projects\\analytics-portal\\node_modules\\@labdev\\telemetry-helper\\scripts",
       s256=PKG_SHA256)

    aid = ALERTS["network_out"]
    ev(aid, "2026-05-28T09:18:05Z", "2026-05-28T09:15:25Z", "Outbound connection to low-reputation host",
       "File", "Related", fn="bundle.zip",
       fp="C:\\Users\\jordan.velez\\AppData\\Local\\Temp\\stage", s256=STAGE_ZIP_SHA256,
       af=j({"StagingOnly": True}))

    aid = ALERTS["cloud_access"]
    ev(aid, "2026-05-28T10:02:33Z", "2026-05-28T10:00:48Z", "Unusual volume of SharePoint file downloads",
       "CloudResource", "Related", cloud="Azure", cres="/sites/DataPlatform/Shared Documents/schema-v2.json",
       aupn=USER_UPN)

    aid = ALERTS["primary_ps"]
    ev(aid, "2026-05-28T09:14:22Z", "2026-05-28T09:13:05Z", "Suspicious PowerShell execution chain",
       "File", "Related", fn="collect.ps1",
       fp="C:\\Users\\jordan.velez\\AppData\\Local\\Temp\\stage", s1=PS1_SHA1, s256=PS1_SHA256)

    aid = ALERTS["package_anomaly"]
    ev(aid, "2026-05-28T09:11:48Z", "2026-05-28T09:10:28Z", "Anomalous postinstall script during package install",
       "Process", "Related", cmd='npm.cmd install @labdev/telemetry-helper@2.1.4 --registry https://pkg-cache-lab.invalid',
       fn="node.exe")

    for i in range(100):
        ev(f"sa-benign-scan-{i}", f"2026-05-28T11:{i%60:02d}:{i%60:02d}Z", f"2026-05-28T11:{i%60:02d}:00Z", f"Routine background scan {i}",
           "Process", "Primary", fn="MsMpEng.exe", cmd="MsMpEng.exe -Scan -ScanType 1")

    write_csv("AlertEvidence_CL.csv", h, rows)


def gen_device_info():
    h = [
        "TenantId", "AdditionalFields", "ClientVersion", "DeviceId", "DeviceName", "DeviceObjectId",
        "IsAzureADJoined", "LoggedOnUsers", "MachineGroup", "OSArchitecture", "OSBuild", "OSPlatform",
        "OSVersion", "PublicIP", "RegistryDeviceTag", "ReportId", "TimeGenerated", "Timestamp",
        "AadDeviceId", "DeviceCategory", "DeviceSubtype", "DeviceType", "JoinType", "MergedDeviceIds",
        "MergedToDeviceId", "Model", "OnboardingStatus", "OSDistribution", "OSVersionInfo", "Vendor",
        "SensorHealthState", "IsExcluded", "ExclusionReason", "AssetValue", "ExposureLevel",
        "IsInternetFacing", "DeviceManualTags", "DeviceDynamicTags", "AzureResourceId",
        "AwsResourceName", "GcpFullResourceName", "AzureVmId", "AzureVmSubscriptionId",
        "CloudPlatforms", "HardwareUuid", "HostDeviceId", "IsTransient", "MitigationStatus",
        "OsBuildRevision", "RestrictedDeviceSecurityOperations", "SourceSystem", "Type",
    ]
    devices = [
        (DEVICE_ID, DEVICE_NAME, AAD_DEVICE, USER_UPN, "Engineering-Developers", "High", "Medium"),
        ("dev-01407-b2c3-d4e5-f6a7-8901abcd1407", "CS-DEV-01407", "aad-dev-01407-aaaa-bbbb-cccc-dddddddd1407",
         "morgan.kim@creditsafe.com", "Engineering-Developers", "Normal", "Low"),
        ("dev-04421-c3d4-e5f6-a7b8-9012cdef4421", "CS-LT-04421", "aad-lt-04421-eeee-ffff-0000-111122223333",
         "alex.park@creditsafe.com", "Corporate-Standard", "Normal", "Low"),
    ]
    for i in range(100):
        devices.append((f"dev-noise-{i:04d}", f"CS-LT-{i:04d}", f"aad-noise-{i:04d}", f"user{i}@creditsafe.com", "Corporate-Standard", "Normal", "Low"))
    rows = []
    for i, (did, dname, aad, user, mg, av, exp) in enumerate(devices):
        rid = REPORT_BASE + i
        rows.append([
            TENANT, j({"LastFullScan": "2026-05-27T22:00:00Z"}), "10.8240.28500.1000", did, dname, f"obj-{did}",
            1, j([{"UserName": user.split("@")[0], "DomainName": "creditsafe.com"}]), mg, "64-bit", 22631,
            "Windows11", "23H2", "198.18.0.10" if i == 0 else "198.18.0.20", "tag-dev-primary", rid,
            "2026-05-28T06:00:00Z", "2026-05-28T06:00:00Z", aad, "Endpoint", "Workstation", "Workstation",
            "AAD", "", "", "Latitude 7440", "Onboarded", "Windows", "10.0.22631", "Dell",
            "Active", 0, "", av, exp, 0 if i else 0,
            "DevMachine;AI-Tooling-ApprovedWithReview", "MachineGroup:Engineering", "", "", "", "", "",
            "", f"hw-{did}", "", 0,
            j({"AntivirusMode": "Active", "EDR": "Enabled", "NetworkProtection": "BlockMode"}),
            "22631.3527", "", "Detection", "DeviceInfo",
        ])
    write_csv("DeviceInfo_CL.csv", h, rows)


def empty_proc_row():
    return [""] * 73


def gen_device_process():
    h = [
        "TenantId", "AccountDomain", "AccountName", "AccountObjectId", "AccountSid", "AccountUpn",
        "ActionType", "AdditionalFields", "AppGuardContainerId", "DeviceId", "DeviceName", "FileName",
        "FolderPath", "FileSize", "InitiatingProcessAccountDomain", "InitiatingProcessAccountName",
        "InitiatingProcessAccountObjectId", "InitiatingProcessAccountSid", "InitiatingProcessAccountUpn",
        "InitiatingProcessCommandLine", "InitiatingProcessFileName", "InitiatingProcessFolderPath",
        "InitiatingProcessId", "InitiatingProcessIntegrityLevel", "InitiatingProcessLogonId",
        "InitiatingProcessMD5", "InitiatingProcessParentFileName", "InitiatingProcessParentId",
        "InitiatingProcessSHA1", "InitiatingProcessSHA256", "InitiatingProcessTokenElevation",
        "InitiatingProcessFileSize", "InitiatingProcessVersionInfoCompanyName",
        "InitiatingProcessVersionInfoProductName", "InitiatingProcessVersionInfoProductVersion",
        "InitiatingProcessVersionInfoInternalFileName", "InitiatingProcessVersionInfoOriginalFileName",
        "InitiatingProcessVersionInfoFileDescription", "LogonId", "MD5", "MachineGroup",
        "ProcessCommandLine", "ProcessCreationTime", "ProcessId", "ProcessIntegrityLevel",
        "ProcessTokenElevation", "ProcessVersionInfoCompanyName", "ProcessVersionInfoProductName",
        "ProcessVersionInfoProductVersion", "ProcessVersionInfoInternalFileName",
        "ProcessVersionInfoOriginalFileName", "ProcessVersionInfoFileDescription",
        "InitiatingProcessSignerType", "InitiatingProcessSignatureStatus", "ReportId", "SHA1", "SHA256",
        "TimeGenerated", "Timestamp", "InitiatingProcessParentCreationTime", "InitiatingProcessCreationTime",
        "CreatedProcessSessionId", "IsProcessRemoteSession", "ProcessRemoteSessionDeviceName",
        "ProcessRemoteSessionIP", "InitiatingProcessSessionId", "IsInitiatingProcessRemoteSession",
        "InitiatingProcessRemoteSessionDeviceName", "InitiatingProcessRemoteSessionIP",
        "InitiatingProcessUniqueId", "ProcessUniqueId", "SourceSystem", "Type",
    ]

    def pe(tg, ts, action, fn, fp, cmd, ipid, pid, ipfn, ipcmd, ipfp, ips1, ips256, s1, s256,
           iuniq, puniq, af="", signer="Trusted", sig="Valid", elev="None"):
        return [
            TENANT, "creditsafe.com", "jordan.velez", USER_OID, USER_SID, USER_UPN, action, af, "",
            DEVICE_ID, DEVICE_NAME, fn, fp, 0, "creditsafe.com", "jordan.velez", USER_OID, USER_SID, USER_UPN,
            ipcmd, ipfn, ipfp, ipid, "High", 1248821, "", ipfn if ipfn != "explorer.exe" else "unknown",
            ipid - 100, ips1, ips256, elev, 0, "Microsoft Corporation", ipfn, "10.0", ipfn, ipfn, ipfn,
            1248821, "", "Engineering-Developers", cmd, ts, pid, "High", elev,
            "Microsoft Corporation", fn, "10.0", fn, fn, fn, signer, sig, REPORT_BASE + pid,
            s1, s256, tg, ts, ts, ts, 1, 0, "", "", 1, 0, "", "", iuniq, puniq, "Detection",
            "DeviceProcessEvents",
        ]

    rows = []
    events = [
        ("2026-05-28T08:20:05Z", "ProcessCreated", "dotnet.exe",
         "C:\\Program Files\\dotnet", '"dotnet.exe" restore Platform.Api.sln',
         4100, 4101, "powershell.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         "C:\\Windows\\System32\\WindowsPowerShell\\v1.0",
         "a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b", "b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2",
         "c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7a8b", "d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3",
         "ip-dotnet-001", "p-dotnet-001", j({"Note": "Benign restore activity"})),
        ("2026-05-28T08:55:10Z", "ProcessCreated", "Code.exe",
         "C:\\Users\\jordan.velez\\AppData\\Local\\Programs\\Microsoft VS Code",
         '"Code.exe" --folder-uri vscode-remote://wsl+ubuntu/home/jordan/analytics-portal',
         4200, 4201, "explorer.exe", "C:\\Windows\\explorer.exe", "C:\\Windows",
         "e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0", "f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4",
         "a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4", "b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5",
         "ip-code-001", "p-code-001", j({"AIExtension": "GitHub Copilot enabled"})),
        ("2026-05-28T09:10:28Z", "ProcessCreated", "node.exe", "C:\\Program Files\\nodejs",
         'npm.cmd install @labdev/telemetry-helper@2.1.4 --registry https://pkg-cache-lab.invalid',
         4300, 4301, "cmd.exe", "C:\\Windows\\System32\\cmd.exe", "C:\\Windows\\System32",
         "c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4", "d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6",
         PKG_SHA1, PKG_SHA256, "ip-npm-001", "p-npm-001"),
        ("2026-05-28T09:12:45Z", "ProcessCreated", "cmd.exe", "C:\\Windows\\System32",
         "cmd.exe /d /s /c node .\\node_modules\\@labdev\\telemetry-helper\\scripts\\postinstall.js",
         4301, 4302, "node.exe", 'node.exe "C:\\Program Files\\nodejs\\node.exe"',
         "C:\\Program Files\\nodejs", PKG_SHA1, PKG_SHA256, "9b0f2a7c3e1d8f5a4c6e9d2b7a1f0c8e5d4b6a9",
         "0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1", "ip-cmd-001", "p-cmd-001",
         j({"Lifecycle": "postinstall"})),
        ("2026-05-28T09:12:52Z", "ProcessCreated", "powershell.exe",
         "C:\\Windows\\System32\\WindowsPowerShell\\v1.0",
         "powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand JABzAD0ATgBlAHcALQBPAGoA...",
         4302, 4303, "cmd.exe", "cmd.exe /d /s /c node .\\node_modules\\@labdev\\telemetry-helper\\scripts\\postinstall.js",
         "C:\\Windows\\System32", "4e9d6b3a7f2c8e1d5b9a0f3c7e2d8b5a1f6c4e9",
         PS1_SHA256, PS1_SHA1, PS1_SHA256, "ip-ps-001", "p-ps-001",
         j({"IncidentCore": True, "BlockedSecondStage": False})),
        ("2026-05-28T09:14:10Z", "ProcessCreated", "powershell.exe",
         "C:\\Windows\\System32\\WindowsPowerShell\\v1.0",
         "powershell.exe -ExecutionPolicy Bypass -File C:\\Users\\jordan.velez\\AppData\\Local\\Temp\\stage\\collect.ps1",
         4303, 4304, "powershell.exe",
         "powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand JABzAD0A...",
         "C:\\Windows\\System32\\WindowsPowerShell\\v1.0", PS1_SHA1, PS1_SHA256,
         "1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1", "2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4",
         "ip-ps-002", "p-ps-002"),
        ("2026-05-28T09:15:22Z", "ProcessCreated", "tar.exe", "C:\\Windows\\System32",
         'tar.exe -a -c -f C:\\Users\\jordan.velez\\AppData\\Local\\Temp\\stage\\bundle.zip C:\\Users\\jordan.velez\\Projects\\analytics-portal\\.env.local',
         4304, 4305, "powershell.exe",
         "powershell.exe -ExecutionPolicy Bypass -File C:\\Users\\jordan.velez\\AppData\\Local\\Temp\\stage\\collect.ps1",
         "C:\\Windows\\System32\\WindowsPowerShell\\v1.0", PS1_SHA1, PS1_SHA256,
         "3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3", STAGE_ZIP_SHA256,
         "ip-tar-001", "p-tar-001", j({"LooksSuspicious": True, "Explanation": "Local env backup script in package; no upload observed"})),
        ("2026-05-28T09:22:00Z", "ProcessCreated", "npm.exe", "C:\\Program Files\\nodejs",
         "npm cache verify", 4400, 4401, "cmd.exe", "cmd.exe /c npm cache verify", "C:\\Windows\\System32",
         "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4", "e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6",
         "f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6", "a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7",
         "ip-npm-verify", "p-npm-verify", j({"BenignMaintenance": True})),
    ]
    for i in range(100):
        events.append((f"2026-05-28T12:{i%60:02d}:{i%60:02d}Z", "ProcessCreated", "svchost.exe",
         "C:\\Windows\\System32", "svchost.exe -k LocalService",
         5000+i, 5001+i, "services.exe", "C:\\Windows\\System32\\services.exe",
         "C:\\Windows\\System32",
         "a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b", "b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2",
         "c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7a8b", "d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3",
         f"ip-svc-{i}", f"p-svc-{i}", j({"Note": "Benign background service"})))
    for e in events:
        rows.append(pe(e[0], e[0], *e[1:]))
    write_csv("DeviceProcessEvents_CL.csv", h, rows)


def gen_device_network():
    h = [
        "TenantId", "ActionType", "AdditionalFields", "AppGuardContainerId", "DeviceId", "DeviceName",
        "InitiatingProcessAccountDomain", "InitiatingProcessAccountName", "InitiatingProcessAccountObjectId",
        "InitiatingProcessAccountSid", "InitiatingProcessAccountUpn", "InitiatingProcessCommandLine",
        "InitiatingProcessFileName", "InitiatingProcessFolderPath", "InitiatingProcessId",
        "InitiatingProcessIntegrityLevel", "InitiatingProcessMD5", "InitiatingProcessParentFileName",
        "InitiatingProcessParentId", "InitiatingProcessSHA1", "InitiatingProcessSHA256",
        "InitiatingProcessTokenElevation", "InitiatingProcessFileSize",
        "InitiatingProcessVersionInfoCompanyName", "InitiatingProcessVersionInfoProductName",
        "InitiatingProcessVersionInfoProductVersion", "InitiatingProcessVersionInfoInternalFileName",
        "InitiatingProcessVersionInfoOriginalFileName", "InitiatingProcessVersionInfoFileDescription",
        "LocalIP", "LocalIPType", "LocalPort", "MachineGroup", "Protocol", "RemoteIP", "RemoteIPType",
        "RemotePort", "RemoteUrl", "ReportId", "TimeGenerated", "Timestamp",
        "InitiatingProcessParentCreationTime", "InitiatingProcessCreationTime", "InitiatingProcessSessionId",
        "IsInitiatingProcessRemoteSession", "InitiatingProcessRemoteSessionDeviceName",
        "InitiatingProcessRemoteSessionIP", "InitiatingProcessUniqueId", "SourceSystem", "Type",
    ]
    rows = []
    nets = [
        ("ConnectionSuccess", "2026-05-28T08:05:30Z", "Code.exe", "update.code.visualstudio.com", "198.51.100.10", 443, "https://update.code.visualstudio.com", "ip-code-net", j({"BenignUpdate": True})),
        ("ConnectionSuccess", "2026-05-28T09:10:40Z", "node.exe", REMOTE_URL_PKG, REMOTE_IP_UPDATE, 443, REMOTE_URL_PKG, "ip-npm-pkg", j({"PackageDownload": True})),
        ("ConnectionSuccess", "2026-05-28T09:16:44Z", "powershell.exe", REMOTE_URL_C2, REMOTE_IP_C2, 443, REMOTE_URL_C2, "ip-ps-c2", j({"BytesOut": 2048, "ProvesExfiltration": False})),
        ("ConnectionFailed", "2026-05-28T09:17:02Z", "powershell.exe", "exfil-gateway-lab.invalid", "203.0.113.99", 443, "https://exfil-gateway-lab.invalid/upload", "ip-ps-blocked", j({"BlockedBy": "NetworkProtection", "Error": "ConnectionBlocked"})),
        ("ConnectionSuccess", "2026-05-28T08:21:00Z", "dotnet.exe", "api.nuget.org", "151.101.1.41", 443, "https://api.nuget.org/v3/index.json", "ip-nuget", j({"Benign": True})),
        ("ConnectionSuccess", "2026-05-28T09:23:00Z", "npm.exe", "registry.npmjs.org", "104.16.0.1", 443, "https://registry.npmjs.org/-/ping", "ip-npm-ping", j({"BenignCacheVerify": True})),
    ]
    for i in range(100):
        nets.append(("ConnectionSuccess", f"2026-05-28T13:{i%60:02d}:{i%60:02d}Z", "chrome.exe", f"example{i}.com", f"198.51.100.{i%255}", 443, f"https://example{i}.com", f"ip-chrome-{i}", j({"BenignBrowsing": True})))
    for i, (act, ts, proc, _, rip, port, url, iuniq, af) in enumerate(nets):
        rows.append([
            TENANT, act, af, "", DEVICE_ID, DEVICE_NAME, "creditsafe.com", "jordan.velez", USER_OID, USER_SID, USER_UPN,
            f"{proc} network activity", proc, "C:\\Windows\\System32" if proc == "cmd.exe" else f"C:\\Program Files",
            4300 + i, "High", "", "explorer.exe", 4200, PS1_SHA1 if "powershell" in proc else PKG_SHA1,
            PS1_SHA256 if "powershell" in proc else PKG_SHA256, "None", 0, "Microsoft Corporation", proc, "10.0",
            proc, proc, proc, "10.24.18.55", "Private", 52000 + i, "Engineering-Developers", "Tcp", rip, "Public",
            port, url, REPORT_BASE + 500 + i, ts, ts, ts, ts, 1, 0, "", "", iuniq, "Detection", "DeviceNetworkEvents",
        ])
    write_csv("DeviceNetworkEvents_CL.csv", h, rows)


def gen_device_file():
    h = [
        "TenantId", "ActionType", "AdditionalFields", "AppGuardContainerId", "DeviceId", "DeviceName",
        "FileName", "FileOriginIP", "FileOriginReferrerUrl", "FileOriginUrl", "FileSize", "FolderPath",
        "InitiatingProcessAccountDomain", "InitiatingProcessAccountName", "InitiatingProcessAccountObjectId",
        "InitiatingProcessAccountSid", "InitiatingProcessAccountUpn", "InitiatingProcessCommandLine",
        "InitiatingProcessFileName", "InitiatingProcessFolderPath", "InitiatingProcessId",
        "InitiatingProcessIntegrityLevel", "InitiatingProcessMD5", "InitiatingProcessParentFileName",
        "InitiatingProcessParentId", "InitiatingProcessSHA1", "InitiatingProcessSHA256",
        "InitiatingProcessTokenElevation", "IsAzureInfoProtectionApplied", "MD5", "MachineGroup",
        "PreviousFileName", "PreviousFolderPath", "ReportId", "RequestAccountDomain", "RequestAccountName",
        "RequestAccountSid", "RequestProtocol", "RequestSourceIP", "RequestSourcePort", "SHA1", "SHA256",
        "SensitivityLabel", "SensitivitySubLabel", "ShareName", "Timestamp", "TimeGenerated",
        "InitiatingProcessParentCreationTime", "InitiatingProcessCreationTime", "InitiatingProcessFileSize",
        "InitiatingProcessVersionInfoCompanyName", "InitiatingProcessVersionInfoFileDescription",
        "InitiatingProcessVersionInfoInternalFileName", "InitiatingProcessVersionInfoOriginalFileName",
        "InitiatingProcessVersionInfoProductName", "InitiatingProcessVersionInfoProductVersion",
        "InitiatingProcessSessionId", "IsInitiatingProcessRemoteSession",
        "InitiatingProcessRemoteSessionDeviceName", "InitiatingProcessRemoteSessionIP",
        "InitiatingProcessUniqueId", "SourceSystem", "Type",
    ]
    files = [
        ("FileCreated", "2026-05-28T09:10:55Z", "postinstall.js", 4288,
         "C:\\Users\\jordan.velez\\Projects\\analytics-portal\\node_modules\\@labdev\\telemetry-helper\\scripts",
         "node.exe", PKG_SHA1, PKG_SHA256, "", "", "ip-npm-001", REMOTE_URL_PKG, REMOTE_IP_UPDATE),
        ("FileCreated", "2026-05-28T09:13:05Z", "collect.ps1", 1520,
         "C:\\Users\\jordan.velez\\AppData\\Local\\Temp\\stage", "powershell.exe", PS1_SHA1, PS1_SHA256, "", "", "ip-ps-001", "", ""),
        ("FileCreated", "2026-05-28T09:15:25Z", "bundle.zip", 18432,
         "C:\\Users\\jordan.velez\\AppData\\Local\\Temp\\stage", "tar.exe", "4f2a8c1e9d0b7a3c5e6f1d8b2a9c0e7f4d6b8a", STAGE_ZIP_SHA256,
         "", "", "ip-tar-001", "", ""),
        ("FileRenamed", "2026-05-28T09:15:28Z", "bundle.zip", 18432,
         "C:\\Users\\jordan.velez\\AppData\\Local\\Temp\\stage", "tar.exe", "4f2a8c1e9d0b7a3c5e6f1d8b2a9c0e7f4d6b8a", STAGE_ZIP_SHA256,
         "workspace-export.tmp", "C:\\Users\\jordan.velez\\AppData\\Local\\Temp\\stage", "ip-tar-002", "", ""),
        ("FileDeleted", "2026-05-28T09:16:00Z", "collect.ps1", 1520,
         "C:\\Users\\jordan.velez\\AppData\\Local\\Temp\\stage", "powershell.exe", PS1_SHA1, PS1_SHA256, "", "", "ip-ps-del", "", ""),
        ("FileCreated", "2026-05-28T10:01:00Z", "CustomerAnalytics_Q2_Draft.xlsx", 245760,
         "C:\\Users\\jordan.velez\\Downloads", "chrome.exe",
         "8e1d4b6a9f0c3e7d2b5a8f1c4e9d6b3a7f2c8e1", "9f0c3e7d2b5a8f1c4e9d6b3a7f2c8e1d5b9a0f3c7e2d8b5a1f6c4e9d6b3a7f2",
         "", "", "ip-chrome-dl", "", "",
         j({"CloudSyncCopy": True, "NotExfiltration": "Local browser download after SharePoint access"})),
    ]
    for i in range(100):
        files.append(("FileCreated", f"2026-05-28T14:{i%60:02d}:{i%60:02d}Z", f"temp{i}.tmp", 1024,
         "C:\\Windows\\Temp", "svchost.exe", "8e1d4b6a9f0c3e7d2b5a8f1c4e9d6b3a7f2c8e1", "9f0c3e7d2b5a8f1c4e9d6b3a7f2c8e1d5b9a0f3c7e2d8b5a1f6c4e9d6b3a7f2",
         "", "", f"ip-svc-{i}", "", ""))
    rows = []
    for i, f in enumerate(files):
        act, ts, fn, fsize, folder, iproc, s1, s256, prev_fn, prev_fp, iuniq, fou, foip = f[:13]
        # f[13] is already a j()-produced string; do NOT call j() again (double-encoding)
        af = f[13] if len(f) > 13 else (j({"FileOriginUrl": fou}) if fou.startswith("http") else "")
        rows.append([
            TENANT, act, af, "", DEVICE_ID, DEVICE_NAME,
            fn, foip, "", fou if fou.startswith("http") else "", fsize, folder,
            "creditsafe.com", "jordan.velez", USER_OID, USER_SID, USER_UPN, f"{iproc} file operation", iproc,
            "C:\\Windows\\System32", 4300 + i, "High", "", "explorer.exe", 4200, s1, s256, "None",
            1 if fn.endswith(".xlsx") else 0, "", "Engineering-Developers", prev_fn, prev_fp,
            # Cols 33-41: ReportId, RequestAccountDomain/Name/Sid/Protocol/SourceIP/SourcePort, SHA1, SHA256
            # 6 empty strings cover RequestAccount* (34-38) + RequestSourcePort (39) so SHA1/SHA256 align correctly
            REPORT_BASE + 600 + i, "", "", "", "", "", "", s1, s256,
            "Customer Data" if "CustomerAnalytics" in fn else "", "Customer" if "CustomerAnalytics" in fn else "",
            "", ts, ts, ts, ts, 0, "Microsoft Corporation", iproc, iproc, iproc, iproc, "10.0", 1, 0, "", "",
            iuniq, "Detection", "DeviceFileEvents",
        ])
    write_csv("DeviceFileEvents_CL.csv", h, rows)


def gen_signin_logs():
    h = [
        "TenantId", "SourceSystem", "TimeGenerated", "ResourceId", "OperationName", "OperationVersion",
        "Category", "ResultType", "ResultSignature", "ResultDescription", "DurationMs", "CorrelationId",
        "Resource", "ResourceGroup", "ResourceProvider", "Identity", "Level", "Location",
        "AlternateSignInName", "AppDisplayName", "AppId", "AuthenticationContextClassReferences",
        "AuthenticationDetails", "AppliedEventListeners", "AuthenticationMethodsUsed",
        "AuthenticationProcessingDetails", "AuthenticationRequirement", "AuthenticationRequirementPolicies",
        "ClientAppUsed", "ConditionalAccessPolicies", "ConditionalAccessStatus", "CreatedDateTime",
        "DeviceDetail", "IsInteractive", "Id", "IPAddress", "IsRisky", "LocationDetails", "MfaDetail",
        "NetworkLocationDetails", "OriginalRequestId", "ProcessingTimeInMilliseconds", "RiskDetail",
        "RiskEventTypes", "RiskEventTypes_V2", "RiskLevelAggregated", "RiskLevelDuringSignIn",
        "RiskState", "ResourceDisplayName", "ResourceIdentity", "ResourceServicePrincipalId",
        "ServicePrincipalId", "ServicePrincipalName", "Status", "TokenIssuerName", "TokenIssuerType",
        "UserAgent", "UserDisplayName", "UserId", "UserPrincipalName", "AADTenantId", "UserType",
        "FlaggedForReview", "IPAddressFromResourceProvider", "SignInIdentifier", "SignInIdentifierType",
        "ResourceTenantId", "HomeTenantId", "UniqueTokenIdentifier", "SessionId", "SessionLifetimePolicies",
        "AutonomousSystemNumber", "AuthenticationProtocol", "CrossTenantAccessType",
        "AuthenticationAppDeviceDetails", "AuthenticationAppPolicyEvaluationDetails", "ClientCredentialType",
        "FederatedCredentialId", "GlobalSecureAccessIpAddress", "HomeTenantName", "IncomingTokenType",
        "IsTenantRestricted", "IsThroughGlobalSecureAccess", "OriginalTransferMethod",
        "TokenProtectionStatusDetails", "AppOwnerTenantId", "ResourceOwnerTenantId", "Agent",
        "SourceAppClientId", "ConditionalAccessAudiences", "AuthenticatorAppLocation",
        "AppliedConditionalAccessPolicies", "RiskLevel", "Type",
    ]

    USERS = {
        USER_UPN: (USER_OID, USER_DISPLAY, "Member"),
        "morgan.kim@creditsafe.com": ("oid-morgan-kim-2222", "Morgan Kim", "Member"),
        "alex.park@creditsafe.com": ("oid-alex-park-3333", "Alex Park", "Member"),
        "priya.nair@creditsafe.com": ("oid-priya-nair-4444", "Priya Nair", "Member"),
        "liam.chen@creditsafe.com": ("oid-liam-chen-5555", "Liam Chen", "Member"),
        "samira.holt@creditsafe.com": ("oid-samira-holt-6666", "Samira Holt", "Member"),
        "noah.banks@creditsafe.com": ("oid-noah-banks-7777", "Noah Banks", "Member"),
        "svc-pipeline@creditsafe.com": ("oid-svc-pipeline-3333", "Pipeline Service", "Member"),
        "svc-scanner@creditsafe.com": ("oid-svc-scanner-8888", "Vulnerability Scanner", "Member"),
        "t.oconnor.contractor@creditsafe.com": ("oid-contractor-disabled", "Taylor O'Connor", "Member"),
        "guest.vendor@partner-lab.example": ("oid-guest-vendor-9999", "Vendor Guest", "Guest"),
        "cato.syversen@creditsafe.com": ("oid-cato-syversen", "Cato Syversen", "Member"),
    }

    APPS = {
        "Microsoft 365": ("00000003-0000-0ff1-ce00-000000000000", "Office 365 Exchange Online"),
        "Azure Portal": ("00000003-0000-0000-c000-000000000000", "Windows Azure Service Management API"),
        "Azure DevOps": ("499b84ac-1321-427f-aa17-267ca0a5a001", "Azure DevOps"),
        "Microsoft Teams": ("48ad82fe-8d80-4c8c-8c3c-3c3c3c3c3c3c", "Microsoft Teams Web Client"),
        "Microsoft Office": ("d3590ed6-52b3-4102-aeff-aad2292ab01c", "Microsoft Office"),
        "Microsoft Graph": ("00000003-0000-0000-c000-000000000000", "Microsoft Graph"),
        "Windows Sign In": ("00000002-0000-0ff1-ce00-000000000000", "Windows Azure Active Directory"),
    }

    # ts, upn, app_key, ip, city, country, result, interactive, risky, risk_agg, risk_ev, sess, corr,
    # device_name, client, status_extra, mfa_methods, result_type
    events = [
        # --- Prior day baseline noise ---
        ("2026-05-27T07:12:00Z", "alex.park@creditsafe.com", "Microsoft 365", "10.24.12.88", "Cardiff", "GB", "Success", 1, 0, "None", "", "sess-ap-2707", "corr-ap-2707", "CS-LT-04421", "Browser", "", "Password, PhoneAppNotification", "0"),
        ("2026-05-27T07:45:00Z", "priya.nair@creditsafe.com", "Microsoft Teams", "10.24.14.22", "London", "GB", "Success", 1, 0, "None", "", "sess-pn-2745", "corr-pn-2745", "CS-LT-05219", "Browser", "", "Password, PhoneAppNotification", "0"),
        ("2026-05-27T08:00:00Z", "svc-pipeline@creditsafe.com", "Azure DevOps", "10.0.4.50", "Cardiff", "GB", "Success", 0, 0, "None", "", "", "corr-svc-2800", "", "Mobile Apps and Desktop clients", j({"ServicePrincipal": True}), "None", "0"),
        ("2026-05-27T08:30:00Z", "morgan.kim@creditsafe.com", "Microsoft 365", "10.24.16.10", "Cardiff", "GB", "Success", 1, 0, "None", "", "sess-mk-2830", "corr-mk-2830", "CS-LT-03811", "Browser", "", "Password, PhoneAppNotification", "0"),
        ("2026-05-27T09:15:00Z", "liam.chen@creditsafe.com", "Azure Portal", "10.24.19.44", "Bristol", "GB", "Success", 1, 0, "None", "", "sess-lc-2915", "corr-lc-2915", "CS-DEV-01407", "Browser", "", "Password, PhoneAppNotification", "0"),
        ("2026-05-27T11:00:00Z", "noah.banks@creditsafe.com", "Microsoft Office", "198.18.0.60", "Edinburgh", "GB", "Success", 1, 1, "Low", "unfamiliarLocation", "sess-nb-1100", "corr-nb-1100", "CS-LT-06102", "Mobile Apps and Desktop clients", j({"TravelStatus": "Pre-approved conference"}), "Password, PhoneAppNotification", "0"),
        ("2026-05-27T14:22:00Z", "samira.holt@creditsafe.com", "Microsoft 365", "10.24.21.77", "Cardiff", "GB", "Success", 1, 0, "None", "", "sess-sh-1422", "corr-sh-1422", "CS-LT-04773", "Browser", "", "Password, PhoneAppNotification", "0"),
        ("2026-05-27T16:40:00Z", USER_UPN, "Azure DevOps", "10.24.18.55", "Cardiff", "GB", "Success", 1, 0, "None", "", "sess-jv-2740", "corr-jv-2740", DEVICE_NAME, "Browser", "", "Password, PhoneAppNotification", "0"),
        ("2026-05-27T17:05:00Z", USER_UPN, "Microsoft Teams", "10.24.18.55", "Cardiff", "GB", "Success", 1, 0, "None", "", "sess-jv-2705", "corr-jv-2705", DEVICE_NAME, "Browser", "", "Password, PhoneAppNotification", "0"),
        ("2026-05-27T18:30:00Z", "guest.vendor@partner-lab.example", "Microsoft Teams", "198.18.0.90", "London", "GB", "Success", 1, 0, "None", "", "sess-gv-1830", "corr-gv-1830", "Unknown", "Browser", j({"B2BGuest": True}), "OneTimePasscode", "0"),
        ("2026-05-27T22:10:00Z", "svc-scanner@creditsafe.com", "Microsoft Graph", "10.0.8.12", "Cardiff", "GB", "Success", 0, 0, "None", "", "", "corr-scan-2210", "", "Mobile Apps and Desktop clients", j({"NonInteractive": True}), "None", "0"),
        # --- Incident day early morning ---
        ("2026-05-28T05:02:00Z", "svc-pipeline@creditsafe.com", "Azure DevOps", "10.0.4.50", "Cardiff", "GB", "Success", 0, 0, "None", "", "", "corr-svc-0502", "", "Mobile Apps and Desktop clients", "", "None", "0"),
        ("2026-05-28T05:45:00Z", "svc-scanner@creditsafe.com", "Microsoft Graph", "10.0.8.12", "Cardiff", "GB", "Success", 0, 0, "None", "", "", "corr-scan-0545", "", "Mobile Apps and Desktop clients", "", "None", "0"),
        ("2026-05-28T06:02:00Z", "t.oconnor.contractor@creditsafe.com", "Microsoft 365", "203.0.113.8", "Unknown", "US", "Failure", 1, 1, "High", "disabledAccount", "", "corr-false-leaver-01", "Unknown", "Browser", j({"errorCode": 50126, "reason": "Account disabled"}), "Password", "50126"),
        ("2026-05-28T06:08:00Z", "t.oconnor.contractor@creditsafe.com", "Windows Sign In", "198.51.100.15", "Amsterdam", "NL", "Failure", 1, 1, "High", "invalidCredentials", "", "corr-false-leaver-02", "Unknown", "Browser", j({"errorCode": 50126}), "Password", "50126"),
        ("2026-05-28T06:11:30Z", "t.oconnor.contractor@creditsafe.com", "Microsoft 365", "203.0.113.5", "Unknown", "US", "Failure", 1, 1, "High", "disabledAccount", "", "corr-false-leaver", "Unknown", "Browser", j({"errorCode": 50126}), "Password", "50126"),
        ("2026-05-28T06:25:00Z", "alex.park@creditsafe.com", "Microsoft 365", "10.24.12.88", "Cardiff", "GB", "Success", 1, 0, "None", "", "sess-ap-0625", "corr-ap-0625", "CS-LT-04421", "Browser", "", "Password, PhoneAppNotification", "0"),
        ("2026-05-28T06:40:00Z", "priya.nair@creditsafe.com", "Azure Portal", "10.24.14.22", "London", "GB", "Success", 1, 0, "None", "", "sess-pn-0640", "corr-pn-0640", "CS-LT-05219", "Browser", "", "Password, PhoneAppNotification", "0"),
        ("2026-05-28T07:00:00Z", "liam.chen@creditsafe.com", "Microsoft 365", "10.24.19.44", "Bristol", "GB", "Success", 1, 0, "None", "", "sess-lc-0700", "corr-lc-0700", "CS-DEV-01407", "Browser", "", "Password, PhoneAppNotification", "0"),
        ("2026-05-28T07:15:00Z", "noah.banks@creditsafe.com", "Microsoft 365", "198.18.0.60", "Edinburgh", "GB", "Success", 1, 1, "Low", "unfamiliarLocation", "sess-nb-0715", "corr-nb-0715", "CS-LT-06102", "Browser", j({"TravelStatus": "Conference day 2"}), "Password, PhoneAppNotification", "0"),
        ("2026-05-28T07:22:00Z", "samira.holt@creditsafe.com", "Microsoft Teams", "10.24.21.77", "Cardiff", "GB", "Success", 1, 0, "None", "", "sess-sh-0722", "corr-sh-0722", "CS-LT-04773", "Browser", "", "Password, PhoneAppNotification", "0"),
        ("2026-05-28T07:30:00Z", "morgan.kim@creditsafe.com", "Microsoft 365", "10.24.16.10", "Cardiff", "GB", "Success", 1, 0, "None", "", "sess-mk-0730", "corr-mk-0730", "CS-LT-03811", "Browser", "", "Password, PhoneAppNotification", "0"),
        # Jordan VPN sign-in (investigation-relevant, buried in noise)
        ("2026-05-28T07:56:10Z", USER_UPN, "Microsoft 365", "198.18.0.44", "Dublin", "IE", "Success", 1, 1, "Low", "unfamiliarLocation",
         "sess-jv-0701-aa11", "corr-jv-0701", DEVICE_NAME, "Browser",
         j({"VpnCorrelation": "User on corporate VPN per helpdesk ticket VPN-48291"}), "Password, PhoneAppNotification", "0"),
        ("2026-05-28T08:00:00Z", "liam.chen@creditsafe.com", "Azure DevOps", "10.24.19.44", "Bristol", "GB", "Success", 1, 0, "None", "", "sess-lc-0800", "corr-lc-0800", "CS-DEV-01407", "Browser", "", "Password, PhoneAppNotification", "0"),
        ("2026-05-28T08:05:00Z", "priya.nair@creditsafe.com", "Microsoft Office", "10.24.14.22", "London", "GB", "Success", 1, 0, "None", "", "sess-pn-0805", "corr-pn-0805", "CS-LT-05219", "Mobile Apps and Desktop clients", "", "Password, PhoneAppNotification", "0"),
        ("2026-05-28T08:12:00Z", "alex.park@creditsafe.com", "Microsoft Teams", "10.24.12.88", "Cardiff", "GB", "Success", 1, 0, "None", "", "sess-ap-0812", "corr-ap-0812", "CS-LT-04421", "Browser", "", "Password, PhoneAppNotification", "0"),
        ("2026-05-28T08:18:00Z", "noah.banks@creditsafe.com", "Azure DevOps", "198.18.0.60", "Edinburgh", "GB", "Success", 1, 0, "None", "", "sess-nb-0818", "corr-nb-0818", "CS-LT-06102", "Browser", "", "Password, PhoneAppNotification", "0"),
        ("2026-05-28T08:22:00Z", USER_UPN, "Azure DevOps", "10.24.18.55", "Cardiff", "GB", "Success", 1, 0, "None", "", "sess-jv-0822", "corr-jv-0822", DEVICE_NAME, "Browser", "", "Password, PhoneAppNotification", "0"),
        ("2026-05-28T08:25:00Z", "samira.holt@creditsafe.com", "Microsoft 365", "10.24.21.77", "Cardiff", "GB", "Failure", 1, 0, "None", "", "", "corr-sh-0825-fail", "CS-LT-04773", "Browser", j({"errorCode": 50074, "reason": "MFA interrupted"}), "Password", "50074"),
        ("2026-05-28T08:26:00Z", "samira.holt@creditsafe.com", "Microsoft 365", "10.24.21.77", "Cardiff", "GB", "Success", 1, 0, "None", "", "sess-sh-0826", "corr-sh-0826", "CS-LT-04773", "Browser", "", "Password, PhoneAppNotification", "0"),
        ("2026-05-28T08:30:00Z", USER_UPN, "Microsoft 365", "10.24.18.55", "Cardiff", "GB", "Success", 1, 0, "None", "", "sess-jv-0830-bb22", "corr-jv-0830", DEVICE_NAME, "Browser", "", "Password, PhoneAppNotification", "0"),
        ("2026-05-28T08:35:00Z", "guest.vendor@partner-lab.example", "Microsoft Teams", "198.18.0.90", "London", "GB", "Success", 1, 0, "None", "", "sess-gv-0835", "corr-gv-0835", "Unknown", "Browser", "", "OneTimePasscode", "0"),
        ("2026-05-28T08:40:00Z", "morgan.kim@creditsafe.com", "Microsoft Teams", "10.24.16.10", "Cardiff", "GB", "Success", 1, 0, "None", "", "sess-mk-0840", "corr-mk-0840", "CS-LT-03811", "Browser", "", "Password, PhoneAppNotification", "0"),
        ("2026-05-28T08:45:00Z", "priya.nair@creditsafe.com", "Microsoft 365", "10.24.14.22", "London", "GB", "Success", 1, 0, "None", "", "sess-pn-0845", "corr-pn-0845", "CS-LT-05219", "Browser", "", "Password, PhoneAppNotification", "0"),
        ("2026-05-28T08:50:00Z", "liam.chen@creditsafe.com", "Microsoft 365", "10.24.19.44", "Bristol", "GB", "Success", 1, 0, "None", "", "sess-lc-0850", "corr-lc-0850", "CS-DEV-01407", "Browser", "", "Password, PhoneAppNotification", "0"),
        ("2026-05-28T08:55:00Z", "alex.park@creditsafe.com", "Azure Portal", "10.24.12.88", "Cardiff", "GB", "Success", 1, 0, "None", "", "sess-ap-0855", "corr-ap-0855", "CS-LT-04421", "Browser", "", "Password, PhoneAppNotification", "0"),
        ("2026-05-28T09:00:00Z", "noah.banks@creditsafe.com", "Microsoft Teams", "198.18.0.60", "Edinburgh", "GB", "Success", 1, 0, "None", "", "sess-nb-0900", "corr-nb-0900", "CS-LT-06102", "Browser", "", "Password, PhoneAppNotification", "0"),
        ("2026-05-28T09:02:00Z", "svc-pipeline@creditsafe.com", "Azure DevOps", "10.0.4.50", "Cardiff", "GB", "Success", 0, 0, "None", "", "", "corr-svc-0902", "", "Mobile Apps and Desktop clients", "", "None", "0"),
        ("2026-05-28T09:05:00Z", USER_UPN, "Microsoft 365", "10.24.18.55", "Cardiff", "GB", "Success", 1, 0, "None", "", "sess-jv-0905-cc33", "corr-jv-0905", DEVICE_NAME, "Browser", "", "Password, PhoneAppNotification", "0"),
        ("2026-05-28T09:08:00Z", "samira.holt@creditsafe.com", "Azure DevOps", "10.24.21.77", "Cardiff", "GB", "Success", 1, 0, "None", "", "sess-sh-0908", "corr-sh-0908", "CS-LT-04773", "Browser", "", "Password, PhoneAppNotification", "0"),
        ("2026-05-28T09:10:00Z", "morgan.kim@creditsafe.com", "Microsoft Office", "10.24.16.10", "Cardiff", "GB", "Success", 1, 0, "None", "", "sess-mk-0910", "corr-mk-0910", "CS-LT-03811", "Mobile Apps and Desktop clients", "", "Password, PhoneAppNotification", "0"),
        ("2026-05-28T09:12:00Z", "priya.nair@creditsafe.com", "Microsoft Teams", "10.24.14.22", "London", "GB", "Success", 1, 0, "None", "", "sess-pn-0912", "corr-pn-0912", "CS-LT-05219", "Browser", "", "Password, PhoneAppNotification", "0"),
        ("2026-05-28T09:15:00Z", "liam.chen@creditsafe.com", "Microsoft Teams", "10.24.19.44", "Bristol", "GB", "Success", 1, 0, "None", "", "sess-lc-0915", "corr-lc-0915", "CS-DEV-01407", "Browser", "", "Password, PhoneAppNotification", "0"),
        ("2026-05-28T09:18:00Z", "alex.park@creditsafe.com", "Microsoft 365", "10.24.12.88", "Cardiff", "GB", "Success", 1, 0, "None", "", "sess-ap-0918", "corr-ap-0918", "CS-LT-04421", "Browser", "", "Password, PhoneAppNotification", "0"),
        ("2026-05-28T09:20:00Z", "noah.banks@creditsafe.com", "Microsoft 365", "198.18.0.60", "Edinburgh", "GB", "Success", 1, 0, "None", "", "sess-nb-0920", "corr-nb-0920", "CS-LT-06102", "Browser", "", "Password, PhoneAppNotification", "0"),
        ("2026-05-28T09:25:00Z", USER_UPN, "Azure DevOps", "10.24.18.55", "Cardiff", "GB", "Success", 1, 0, "None", "", "sess-jv-0925", "corr-jv-0925", DEVICE_NAME, "Browser", "", "Password, PhoneAppNotification", "0"),
        ("2026-05-28T09:28:00Z", "t.oconnor.contractor@creditsafe.com", "Microsoft 365", "203.0.113.12", "Chicago", "US", "Failure", 1, 1, "High", "disabledAccount", "", "corr-false-leaver-03", "Unknown", "Browser", j({"errorCode": 50126}), "Password", "50126"),
        ("2026-05-28T09:30:00Z", "samira.holt@creditsafe.com", "Microsoft 365", "10.24.21.77", "Cardiff", "GB", "Success", 1, 0, "None", "", "sess-sh-0930", "corr-sh-0930", "CS-LT-04773", "Browser", "", "Password, PhoneAppNotification", "0"),
        ("2026-05-28T09:32:00Z", "priya.nair@creditsafe.com", "Azure DevOps", "10.24.14.22", "London", "GB", "Success", 1, 0, "None", "", "sess-pn-0932", "corr-pn-0932", "CS-LT-05219", "Browser", "", "Password, PhoneAppNotification", "0"),
        ("2026-05-28T09:35:00Z", "morgan.kim@creditsafe.com", "Microsoft 365", "10.24.16.10", "Cardiff", "GB", "Success", 1, 0, "None", "", "sess-mk-0935", "corr-mk-0935", "CS-LT-03811", "Browser", "", "Password, PhoneAppNotification", "0"),
        ("2026-05-28T09:38:00Z", "liam.chen@creditsafe.com", "Azure DevOps", "10.24.19.44", "Bristol", "GB", "Success", 1, 0, "None", "", "sess-lc-0938", "corr-lc-0938", "CS-DEV-01407", "Browser", "", "Password, PhoneAppNotification", "0"),
        ("2026-05-28T09:40:00Z", "alex.park@creditsafe.com", "Microsoft Office", "10.24.12.88", "Cardiff", "GB", "Success", 1, 0, "None", "", "sess-ap-0940", "corr-ap-0940", "CS-LT-04421", "Mobile Apps and Desktop clients", "", "Password, PhoneAppNotification", "0"),
        ("2026-05-28T09:42:00Z", USER_UPN, "Microsoft Teams", "10.24.18.55", "Cardiff", "GB", "Success", 1, 0, "None", "", "sess-jv-0942", "corr-jv-0942", DEVICE_NAME, "Browser", "", "Password, PhoneAppNotification", "0"),
        ("2026-05-28T09:45:00Z", USER_UPN, "Microsoft Office", "10.24.18.55", "Cardiff", "GB", "Success", 1, 0, "None", "",
         "sess-jv-0945-dd44", "corr-jv-0945", DEVICE_NAME, "Mobile Apps and Desktop clients",
         j({"OAuthApp": "Microsoft Office"}), "Password, PhoneAppNotification", "0"),
        ("2026-05-28T09:48:00Z", "noah.banks@creditsafe.com", "Microsoft Office", "198.18.0.60", "Edinburgh", "GB", "Success", 1, 0, "None", "", "sess-nb-0948", "corr-nb-0948", "CS-LT-06102", "Mobile Apps and Desktop clients", "", "Password, PhoneAppNotification", "0"),
        ("2026-05-28T09:50:00Z", "svc-scanner@creditsafe.com", "Microsoft Graph", "10.0.8.12", "Cardiff", "GB", "Success", 0, 0, "None", "", "", "corr-scan-0950", "", "Mobile Apps and Desktop clients", "", "None", "0"),
        ("2026-05-28T09:52:00Z", "priya.nair@creditsafe.com", "Microsoft 365", "10.24.14.22", "London", "GB", "Success", 1, 0, "None", "", "sess-pn-0952", "corr-pn-0952", "CS-LT-05219", "Browser", "", "Password, PhoneAppNotification", "0"),
        ("2026-05-28T09:55:00Z", "samira.holt@creditsafe.com", "Microsoft 365", "10.24.21.77", "Cardiff", "GB", "Success", 1, 0, "None", "", "sess-sh-0955", "corr-sh-0955", "CS-LT-04773", "Browser", "", "Password, PhoneAppNotification", "0"),
        ("2026-05-28T09:58:00Z", "morgan.kim@creditsafe.com", "Azure Portal", "10.24.16.10", "Cardiff", "GB", "Success", 1, 0, "None", "", "sess-mk-0958", "corr-mk-0958", "CS-LT-03811", "Browser", "", "Password, PhoneAppNotification", "0"),
        ("2026-05-28T10:00:00Z", "liam.chen@creditsafe.com", "Microsoft 365", "10.24.19.44", "Bristol", "GB", "Success", 1, 0, "None", "", "sess-lc-1000", "corr-lc-1000", "CS-DEV-01407", "Browser", "", "Password, PhoneAppNotification", "0"),
        ("2026-05-28T10:02:00Z", USER_UPN, "Microsoft Office", "10.24.18.55", "Cardiff", "GB", "Success", 1, 0, "None", "", "sess-jv-1002", "corr-jv-1002", DEVICE_NAME, "Mobile Apps and Desktop clients", "", "Password, PhoneAppNotification", "0"),
        ("2026-05-28T10:05:00Z", "alex.park@creditsafe.com", "Microsoft 365", "10.24.12.88", "Cardiff", "GB", "Success", 1, 0, "None", "", "sess-ap-1005", "corr-ap-1005", "CS-LT-04421", "Browser", "", "Password, PhoneAppNotification", "0"),
        ("2026-05-28T10:08:00Z", "noah.banks@creditsafe.com", "Azure Portal", "198.18.0.60", "Edinburgh", "GB", "Success", 1, 0, "None", "", "sess-nb-1008", "corr-nb-1008", "CS-LT-06102", "Browser", "", "Password, PhoneAppNotification", "0"),
        ("2026-05-28T10:10:00Z", "priya.nair@creditsafe.com", "Microsoft Teams", "10.24.14.22", "London", "GB", "Success", 1, 0, "None", "", "sess-pn-1010", "corr-pn-1010", "CS-LT-05219", "Browser", "", "Password, PhoneAppNotification", "0"),
        ("2026-05-28T10:12:00Z", "samira.holt@creditsafe.com", "Microsoft Office", "10.24.21.77", "Cardiff", "GB", "Success", 1, 0, "None", "", "sess-sh-1012", "corr-sh-1012", "CS-LT-04773", "Mobile Apps and Desktop clients", "", "Password, PhoneAppNotification", "0"),
        ("2026-05-28T10:15:00Z", "morgan.kim@creditsafe.com", "Microsoft 365", "10.24.16.10", "Cardiff", "GB", "Success", 1, 0, "None", "", "sess-mk-1015", "corr-mk-1015", "CS-LT-03811", "Browser", "", "Password, PhoneAppNotification", "0"),
        ("2026-05-28T10:18:00Z", USER_UPN, "Microsoft 365", "10.24.18.55", "Cardiff", "GB", "Success", 1, 0, "None", "", "sess-jv-1018", "corr-jv-1018", DEVICE_NAME, "Browser", "", "Password, PhoneAppNotification", "0"),
        ("2026-05-28T10:20:00Z", "liam.chen@creditsafe.com", "Azure DevOps", "10.24.19.44", "Bristol", "GB", "Success", 1, 0, "None", "", "sess-lc-1020", "corr-lc-1020", "CS-DEV-01407", "Browser", "", "Password, PhoneAppNotification", "0"),
        ("2026-05-28T10:25:00Z", "guest.vendor@partner-lab.example", "Microsoft 365", "198.18.0.90", "London", "GB", "Success", 1, 0, "None", "", "sess-gv-1025", "corr-gv-1025", "Unknown", "Browser", "", "OneTimePasscode", "0"),
        ("2026-05-28T10:30:00Z", "svc-pipeline@creditsafe.com", "Azure DevOps", "10.0.4.50", "Cardiff", "GB", "Success", 0, 0, "None", "", "", "corr-svc-1030", "", "Mobile Apps and Desktop clients", "", "None", "0"),
        ("2026-05-28T10:35:00Z", "alex.park@creditsafe.com", "Microsoft Teams", "10.24.12.88", "Cardiff", "GB", "Success", 1, 0, "None", "", "sess-ap-1035", "corr-ap-1035", "CS-LT-04421", "Browser", "", "Password, PhoneAppNotification", "0"),
        ("2026-05-28T10:40:00Z", "priya.nair@creditsafe.com", "Microsoft 365", "198.18.0.72", "Manchester", "GB", "Success", 1, 1, "Low", "unfamiliarLocation", "sess-pn-1040", "corr-pn-1040", "CS-LT-05219", "Browser", j({"WorkFromHome": "Approved hot-desk office"}), "Password, PhoneAppNotification", "0"),
        ("2026-05-28T10:45:00Z", "noah.banks@creditsafe.com", "Microsoft 365", "198.18.0.60", "Edinburgh", "GB", "Success", 1, 0, "None", "", "sess-nb-1045", "corr-nb-1045", "CS-LT-06102", "Browser", "", "Password, PhoneAppNotification", "0"),
        ("2026-05-28T10:50:00Z", "samira.holt@creditsafe.com", "Microsoft 365", "10.24.21.77", "Cardiff", "GB", "Success", 1, 0, "None", "", "sess-sh-1050", "corr-sh-1050", "CS-LT-04773", "Browser", "", "Password, PhoneAppNotification", "0"),
        ("2026-05-28T11:00:00Z", USER_UPN, "Microsoft Teams", "10.24.18.55", "Cardiff", "GB", "Success", 1, 0, "None", "", "sess-jv-1100", "corr-jv-1100", DEVICE_NAME, "Browser", "", "Password, PhoneAppNotification", "0"),
        ("2026-05-28T11:05:00Z", "morgan.kim@creditsafe.com", "Microsoft Teams", "10.24.16.10", "Cardiff", "GB", "Success", 1, 0, "None", "", "sess-mk-1105", "corr-mk-1105", "CS-LT-03811", "Browser", "", "Password, PhoneAppNotification", "0"),
        ("2026-05-28T11:10:00Z", "liam.chen@creditsafe.com", "Microsoft 365", "10.24.19.44", "Bristol", "GB", "Success", 1, 0, "None", "", "sess-lc-1110", "corr-lc-1110", "CS-DEV-01407", "Browser", "", "Password, PhoneAppNotification", "0"),
        # Misleading: another user risky sign-in same morning (false parallel)
        ("2026-05-28T08:02:00Z", "priya.nair@creditsafe.com", "Microsoft 365", "198.18.0.55", "Paris", "FR", "Success", 1, 1, "Medium", "unfamiliarLocation", "sess-pn-0802", "corr-pn-0802", "CS-LT-05219", "Browser", j({"Reason": "Client workshop - calendar invite IT-44821"}), "Password, PhoneAppNotification", "0"),
        # Legacy auth failure noise
        ("2026-05-28T07:48:00Z", "alex.park@creditsafe.com", "Microsoft 365", "10.24.12.88", "Cardiff", "GB", "Failure", 1, 0, "None", "", "", "corr-ap-0748-fail", "CS-LT-04421", "Browser", j({"errorCode": 53003, "reason": "Conditional Access blocked legacy auth"}), "Password", "53003"),
        ("2026-05-28T07:49:00Z", "alex.park@creditsafe.com", "Microsoft 365", "10.24.12.88", "Cardiff", "GB", "Success", 1, 0, "None", "", "sess-ap-0749", "corr-ap-0749", "CS-LT-04421", "Browser", "", "Password, PhoneAppNotification", "0"),
        
        # Red Herrings: Cato Syversen impossible travel (VPN)
        ("2026-05-28T08:00:00Z", "cato.syversen@creditsafe.com", "Microsoft 365", "10.24.12.99", "Cardiff", "GB", "Success", 1, 0, "None", "", "sess-cs-0800", "corr-cs-0800", "CS-EXEC-001", "Browser", "", "Password, PhoneAppNotification", "0"),
        ("2026-05-28T09:25:00Z", "cato.syversen@creditsafe.com", "Microsoft 365", "198.18.0.45", "Dublin", "IE", "Success", 1, 1, "Medium", "impossibleTravel", "sess-cs-0925", "corr-cs-0925", "CS-EXEC-001", "Browser", j({"TravelStatus": "Cisco AnyConnect VPN"}), "Password, PhoneAppNotification", "0"),
    ]

    for i in range(100):
        events.append((f"2026-05-28T15:{i%60:02d}:{i%60:02d}Z", f"user{i}@creditsafe.com", "Microsoft 365", f"10.24.12.{i%255}", "Cardiff", "GB", "Success", 1, 0, "None", "", f"sess-u{i}", f"corr-u{i}", f"CS-LT-{i:04d}", "Browser", "", "Password", "0"))
        USERS[f"user{i}@creditsafe.com"] = (f"oid-user{i}", f"User {i}", "Member")

    rows = []
    for i, ev in enumerate(events):
        (ts, upn, app_key, ip, city, country, res, interactive, risky, risk_agg, risk_ev,
         sess, corr, device_name, client, status_extra, mfa_methods, result_type) = ev
        uid, disp, utype = USERS[upn]
        app_id, resource_name = APPS[app_key]
        loc = j({"City": city, "CountryOrRegion": country, "State": ""})
        success = res == "Success"
        status_obj = status_extra if isinstance(status_extra, dict) else (
            j({"additionalDetails": status_extra}) if status_extra else j({"additionalDetails": ""})
        )
        if not success and isinstance(status_extra, dict):
            status_obj = j(status_extra)
        mfa_list = [] if mfa_methods == "None" else [m.strip() for m in mfa_methods.split(",")]

        rows.append([
            TENANT, "Azure AD", ts, "", "Sign-in activity", "1.0", "SignInLogs", result_type,
            "SUCCESS" if success else "FAILURE", res, 80 + (i % 90), corr, "", "", "", upn,
            "Informational", "UK South", upn, app_key, app_id,
            j([{"Id": "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"}]),
            j({"MfaRequired": bool(mfa_list), "Methods": mfa_list}),
            "", mfa_methods, "", "multiFactorAuthentication" if mfa_list else "singleFactorAuthentication",
            "", client, j([]), "success" if success else "failure", ts,
            j({"displayName": device_name, "operatingSystem": "Windows 11" if device_name != "Unknown" else "Unknown"}),
            interactive, f"sig-{i:04d}", ip, risky, loc,
            j({"authMethod": mfa_list[-1] if mfa_list else "none", "result": "success" if success else "failure"}),
            "", f"req-{i:04d}", str(120 + (i % 80)), risk_ev, risk_ev if risky else "", risk_ev if risky else "",
            risk_agg, risk_agg, "none" if success else "atRisk", resource_name, "", "", "", "",
            status_obj, "Azure AD", "AzureAD",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            disp, uid, upn, TENANT, utype, 1 if risky and upn == USER_UPN else 0, "", upn, "userPrincipalName",
            TENANT, TENANT, f"uti-{i:04d}", sess, "", "AS64496", "none", "none", "", "", "none", "",
            "Corp Example Lab", "none", 0, 0, "none", j({"status": "Bound" if success else "Unbound"}),
            TENANT, TENANT, "", "", "", "", risk_agg, "SigninLogs",
        ])
    write_csv("SigninLogs_CL.csv", h, rows)


def gen_cloud_app():
    h = [
        "TenantId", "AccountId", "AccountType", "AdditionalFields", "RawEventData", "ReportId", "ObjectId",
        "ObjectType", "ObjectName", "ActivityObjects", "ActivityType", "UserAgent", "ISP", "City",
        "CountryCode", "IsAnonymousProxy", "IsExternalUser", "IsImpersonated", "IPAddress", "IPCategory",
        "IPTags", "OSPlatform", "DeviceType", "IsAdminOperation", "AccountDisplayName", "AccountObjectId",
        "AppInstanceId", "ApplicationId", "Application", "ActionType", "UserAgentTags", "TimeGenerated",
        "Timestamp", "AuditSource", "LastSeenForUser", "OAuthAppId", "SessionData", "UncommonForUser",
        "SourceSystem", "Type",
    ]
    events = [
        ("2026-05-28T09:56:00Z", "FilePreviewed", "README.md", "/sites/DataPlatform/Shared Documents/README.md", False),
        ("2026-05-28T09:58:30Z", "FileDownloaded", "CustomerAnalytics_Q2_Draft.xlsx",
         "/sites/DataPlatform/Shared Documents/CustomerAnalytics_Q2_Draft.xlsx", True),
        ("2026-05-28T09:59:45Z", "FileDownloaded", "schema-v2.json", "/sites/DataPlatform/Shared Documents/schema-v2.json", False),
        ("2026-05-28T10:00:48Z", "FileAccessed", "CustomerAnalytics_Q2_Draft.xlsx",
         "/sites/DataPlatform/Shared Documents/CustomerAnalytics_Q2_Draft.xlsx", True),
        ("2026-05-28T10:02:00Z", "FileListed", "Shared Documents", "/sites/DataPlatform/Shared Documents", False),
        ("2026-05-28T08:50:00Z", "FilePreviewed", "Sprint-24-Goals.docx", "/sites/Engineering/Shared Documents/Sprint-24-Goals.docx", False),
    ]
    # Benign noise: spread across other employees on different sites/times to avoid polluting Jordan's activity
    NOISE_USERS = [
        ("morgan.kim@creditsafe.com", "oid-morgan-kim-2222", "Morgan Kim", "10.24.11.33"),
        ("alex.park@creditsafe.com", "oid-alex-park-3333", "Alex Park", "10.24.12.88"),
        ("priya.nair@creditsafe.com", "oid-priya-nair-4444", "Priya Nair", "10.24.14.22"),
        ("liam.chen@creditsafe.com", "oid-liam-chen-5555", "Liam Chen", "10.24.15.44"),
        ("samira.holt@creditsafe.com", "oid-samira-holt-6666", "Samira Holt", "10.24.16.55"),
    ]
    NOISE_SITES = ["Engineering", "HR", "Finance", "Marketing", "IT"]
    noise_events = []
    for i in range(100):
        u_upn, u_oid, u_disp, u_ip = NOISE_USERS[i % len(NOISE_USERS)]
        hour = 8 + (i % 10)
        minute = (i * 7) % 60
        site = NOISE_SITES[i % len(NOISE_SITES)]
        noise_events.append((f"2026-05-28T{hour:02d}:{minute:02d}:00Z", "FilePreviewed",
            f"Document{i}.docx", f"/sites/{site}/Shared Documents/Document{i}.docx",
            False, u_upn, u_oid, u_disp, u_ip, f"sess-noise-{i}", f"corr-noise-{i}"))

    rows = []
    for i, (ts, act, oname, path, uncommon) in enumerate(events):
        rows.append([
            TENANT, USER_UPN, "Regular", j({"Site": "DataPlatform", "MembershipVerified": True}),
            j({"Workload": "SharePoint", "ListId": "list-dataplatform-001", "SensitivityLabel": "Customer Data" if "CustomerAnalytics" in oname else "Internal"}),
            f"rpt-cloud-{i}", f"obj-sp-{i}", "File", path,
            j([{"Name": oname, "Type": "File", "Id": f"file-id-{i}"}]),
            act, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0", "Corp ISP Lab", "Cardiff", "GB",
            0, 0, 0, "10.24.18.55", "Corporate", j(["CorpNetwork"]), "Windows", "Desktop", 0, USER_DISPLAY, USER_OID,
            0, 20893, "Microsoft SharePoint Online", act, j([]), ts, ts, "Defender for Cloud Apps",
            j({"LastFileDownload": "2026-05-20"}), "00000003-0000-0ff1-ce00-000000000000",
            j({"SessionId": "sess-jv-0945-dd44", "CorrelationId": "corr-jv-0945"}),
            j({"Score": 72, "Reason": "Rare download of labeled file"}) if uncommon else j({"Score": 10}),
            "Detection", "CloudAppEvents",
        ])
    for ni, (ts, act, oname, path, uncommon, u_upn, u_oid, u_disp, u_ip, sess, corr) in enumerate(noise_events):
        rows.append([
            TENANT, u_upn, "Regular", j({"Site": "TeamSite", "MembershipVerified": True}),
            j({"Workload": "SharePoint", "ListId": f"list-site-{ni}", "SensitivityLabel": "Internal"}),
            f"rpt-cloud-n{ni}", f"obj-sp-n{ni}", "File", path,
            j([{"Name": oname, "Type": "File", "Id": f"file-id-n{ni}"}]),
            act, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0", "Corp ISP Lab", "Cardiff", "GB",
            0, 0, 0, u_ip, "Corporate", j(["CorpNetwork"]), "Windows", "Desktop", 0, u_disp, u_oid,
            0, 20893, "Microsoft SharePoint Online", act, j([]), ts, ts, "Defender for Cloud Apps",
            j({"LastFileDownload": "2026-05-15"}), "00000003-0000-0ff1-ce00-000000000000",
            j({"SessionId": sess, "CorrelationId": corr}),
            j({"Score": 5}),
            "Detection", "CloudAppEvents",
        ])
    write_csv("CloudAppEvents_CL.csv", h, rows)


def gen_email():
    h = [
        "TenantId", "AttachmentCount", "AuthenticationDetails", "AdditionalFields", "ConfidenceLevel",
        "Connectors", "DetectionMethods", "DeliveryAction", "DeliveryLocation", "EmailClusterId",
        "EmailDirection", "EmailLanguage", "EmailAction", "EmailActionPolicy", "EmailActionPolicyGuid",
        "OrgLevelAction", "OrgLevelPolicy", "InternetMessageId", "NetworkMessageId", "RecipientEmailAddress",
        "RecipientObjectId", "ReportId", "SenderDisplayName", "SenderFromAddress", "SenderFromDomain",
        "SenderObjectId", "SenderIPv4", "SenderIPv6", "SenderMailFromAddress", "SenderMailFromDomain",
        "Subject", "ThreatTypes", "ThreatNames", "TimeGenerated", "LastEventExecutionTime", "Timestamp",
        "UrlCount", "UserLevelAction", "UserLevelPolicy", "BulkComplaintLevel", "LatestDeliveryLocation",
        "LatestDeliveryAction", "ExchangeTransportRule", "DistributionList", "ForwardingInformation",
        "Context", "To", "Cc", "ThreatClassification", "RecipientDomain", "EmailSize", "IsFirstContact",
        "SourceSystem", "Type",
    ]
    # Tuples: (nmid, subj, direction, sender, domain, urls, delivery, loc, first, threat, conf, ts)
    emails = [
        (NETWORK_MSG_EXTERNAL, "Exclusive trial: AI pair-programming for enterprise repos", "Inbound",
         "promo@devassist-trials.example", "devassist-trials.example", 3, "Delivered", "Inbox", 1, "Phish", "Low",
         "2026-05-28T08:35:00Z"),
        (NETWORK_MSG_NEWSLETTER, "npm weekly: security advisories roundup", "Inbound",
         "newsletter@notify.npmjs.org", "notify.npmjs.org", 5, "Delivered", "Inbox", 0, "", "None",
         "2026-05-28T07:12:00Z"),
        (NETWORK_MSG_INTERNAL, "FYI: updated Data Platform site permissions", "Inbound",
         "data-platform-team@creditsafe.com", "creditsafe.com", 1, "Delivered", "Inbox", 0, "", "None",
         "2026-05-27T16:30:00Z"),
    ]
    # Benign newsletter noise spread across prior day and incident day
    for i in range(100):
        hour = 6 + (i % 12)
        minute = (i * 7) % 60
        day = "2026-05-27" if i < 50 else "2026-05-28"
        ts_noise = f"{day}T{hour:02d}:{minute:02d}:00Z"
        emails.append((f"nm-noise-{i}", f"Newsletter {i}", "Inbound",
         f"news@newsletter{i}.example", f"newsletter{i}.example", 1, "Delivered", "Inbox", 0, "", "None",
         ts_noise))

    # Red Herrings: Spoofed emails appearing to be from Cato Syversen (but safe/benign content)
    # Spread across the incident morning to maximise investigative distraction
    for i in range(50):
        hour = 7 + (i // 10)
        minute = (i * 6) % 60
        ts_spoof = f"2026-05-28T{hour:02d}:{minute:02d}:00Z"
        emails.append((f"nm-spoof-cato-{i}", f"Urgent: Q3 Planning {i}", "Inbound",
         "cato.syversen@creditsafe.com", "creditsafe.com", 0, "Junk", "Junk", 0, "Spam", "Low",
         ts_spoof))

    rows = []
    for nmid, subj, direction, sender, domain, urls, delivery, loc, first, threat, conf, ts in emails:
        auth = j({"SPF": "Fail", "DKIM": "Fail", "DMARC": "Fail"}) if "spoof" in nmid else j({"SPF": "Pass", "DKIM": "Pass", "DMARC": "Pass"})
        ts_exec = ts.replace("Z", "").replace("T", "T") + "Z"
        ts_late = ts.replace(":00Z", ":12Z")
        rows.append([
            TENANT, 0 if "internal" in sender else 1, auth,
            j({"UserReportedPhish": nmid == NETWORK_MSG_EXTERNAL, "RootCause": "Unrelated marketing"}),
            conf, "", "AnalystReport" if nmid == NETWORK_MSG_EXTERNAL else "AllowList",
            delivery, loc, 10001, direction, "en", "Delivered", "", "", "Allow", "Default",
            f"<{nmid}@mail.example>", nmid, USER_UPN, USER_OID, f"rpt-email-{nmid[-3:]}",
            "DevAssist Promotions" if "devassist" in domain else ("npm Inc" if "npmjs" in domain else "Data Platform Team"),
            sender, domain, "", "198.51.100.88" if "devassist" in domain else "10.0.0.1",
            "", sender, domain, subj, threat, "", ts_exec, ts_exec, ts_late,
            urls, "", "", 1, loc, delivery, "", "", "", "Email", j([USER_UPN]), j([]),
            "Spam" if threat == "Phish" else "None", "creditsafe.com", 24000, first, "Detection", "EmailEvents",
        ])
    write_csv("EmailEvents_CL.csv", h, rows)


def gen_identity():
    h = [
        "TenantId", "TimeGenerated", "AccountName", "AccountDomain", "AccountUPN", "AccountSID",
        "AccountObjectId", "AccountTenantId", "AccountDisplayName", "GivenName", "Surname",
        "OnPremisesAccountObjectId", "OnPremisesExtensionAttributes", "OnPremisesDistinguishedName", "Tags",
        "AccountCreationTime", "InvestigationPriority", "InvestigationPriorityPercentile", "RiskLevel",
        "RiskLevelDetails", "RiskState", "BlastRadius", "GroupMembership", "AssignedRoles", "Department",
        "EmployeeId", "JobTitle", "RelatedAccounts", "MailAddress", "AdditionalMailAddresses", "Manager",
        "StreetAddress", "City", "CompanyName", "Country", "State", "Phone", "IsAccountEnabled",
        "IsServiceAccount", "DeletedDateTime", "LastSeenDate", "UACFlags", "UserState", "UserStateChangedOn",
        "UserType", "ExtensionProperty", "AccountCloudSID", "IsMFARegistered", "Applications", "ServicePrincipals",
        "SourceSystem", "UserAccountControl", "ChangeSource", "EntityRiskScore", "SAMAccountName", "Type",
    ]
    users = [
        (USER_UPN, USER_OID, "Jordan", "Velez", "Jordan Velez", "jordan.velez", USER_SID, "Software Engineer II",
         "Engineering", "EMP-104421", "Morgan Kim", "Medium", 65, 1, 0, "Active"),
        ("morgan.kim@creditsafe.com", "oid-morgan-kim-2222", "Morgan", "Kim", "Morgan Kim", "morgan.kim",
         "S-1-5-21-1000000000-2000000000-3000000000-104407", "Engineering Manager", "Engineering", "EMP-104407",
         "Alex Park", "Low", 25, 1, 0, "Active"),
        ("svc-pipeline@creditsafe.com", "oid-svc-pipeline-3333", "Pipeline", "Service", "Pipeline Service",
         "svc-pipeline", "S-1-5-21-1000000000-2000000000-3000000000-50012", "CI/CD Service Account",
         "Platform Engineering", "EMP-SVC-012", "", "Low", 10, 1, 1, "Active"),
        ("t.oconnor.contractor@creditsafe.com", "oid-contractor-disabled", "Taylor", "O'Connor", "Taylor O'Connor",
         "t.oconnor.contractor", "S-1-5-21-1000000000-2000000000-3000000000-99001", "Former Contractor",
         "Data Platform", "EMP-C-99001", "Morgan Kim", "High", 90, 0, 0, "Disabled"),
    ]
    for i in range(100):
        users.append((f"user{i}@creditsafe.com", f"oid-user{i}", "User", f"{i}", f"User {i}", f"user{i}",
         f"S-1-5-21-000-{i}", "Employee", "Sales", f"EMP-{i}", "Alex Park", "Low", 5, 1, 0, "Active"))
    rows = []
    for upn, oid, gn, sn, disp, sam, sid, title, dept, emp, mgr, risk, pct, enabled, svc, state in users:
        rows.append([
            TENANT, "2026-05-28T06:00:00Z", sam.split(".")[0] if "@" not in sam else sam.split("@")[0].split(".")[0],
            "creditsafe.com", upn, sid, oid, TENANT, disp, gn, sn, "", "", "", "Developer;GitHubCopilot",
            "2024-01-15T00:00:00Z", pct, pct, risk,
            j({"Factors": ["Recent script execution alerts"] if upn == USER_UPN else []}),
            "AtRisk" if upn == USER_UPN else "None", "Medium" if upn == USER_UPN else "Low",
            j(["Engineering", "All-Staff", "DataPlatform-Contributors"] if upn == USER_UPN else ["Engineering", "Managers"]),
            j(["User"] if not svc else ["ServiceAccount"]),
            dept, emp, title, j([]), upn, j([]), mgr, "", "Cardiff", "Corp Example Lab", "GB", "", "",
            enabled, svc, "" if enabled else "2026-04-01T00:00:00Z", "2026-05-28T08:00:00Z", "", state,
            "2026-04-01T00:00:00Z" if not enabled else "", "Member" if not svc else "Service",
            j({"ApprovedAITools": "Copilot;InternalAssistant"}), "", 1 if enabled else 0,
            "Azure DevOps;SharePoint" if upn == USER_UPN else "", j([]), "IdentityInfo", j({}), "Graph",
            j({"Score": pct}), sam, "IdentityInfo",
        ])
    write_csv("IdentityInfo_CL.csv", h, rows)


def main():
    gen_security_alerts()
    gen_alert_evidence()
    gen_device_info()
    gen_device_process()
    gen_device_network()
    gen_device_file()
    gen_signin_logs()
    gen_cloud_app()
    gen_email()
    gen_identity()
    print("All CSV files generated.")


if __name__ == "__main__":
    main()
