# FreshService Training Interface

## Purpose

FreshService appears as a separate top-level tab beside Incidents, Logs and Bookmarks. It provides the service-management context needed to investigate historical decisions and quickly resolve selected red herrings.

FreshService data is application data, not SIEM telemetry. It is not visible in the KQL schema browser and cannot be queried with KQL.

## Views

### Ticket list

The list supports search and filtering by:

- Ticket or change ID.
- Requester and affected user.
- Assigned agent or group.
- Status and priority.
- Created and resolved date.
- Incident, service request or change type.

Each row shows ID, subject, requester, status, priority, assigned agent and last update.

### Ticket detail

The detail view shows:

- Ticket metadata and description.
- Conversation and private-note timeline.
- Agent actions and resolution notes.
- Linked user, device and asset identifiers.
- Attachments represented by safe metadata only.
- Related incident, service request or change references.

### Change records

Change records provide the approval evidence required to resolve benign alerts. They show requester, approver, implementation window, affected service or asset, implementation plan and status.

## Required scenario records

| Record | Purpose |
| --- | --- |
| Historical Louise phishing investigation | Shows Louise's incomplete disclosure and Anita Job's password-reset-only response |
| Louise password-reset action | Confirms the reset but absence of session revocation and endpoint isolation |
| Victoria Nash lost-phone request | Resolves the admin MFA-phone-removal alert |
| David Woofer monitoring-agent change | Resolves the Azure VM Run Command alert |
| Beth Edgar supplier onboarding request | Resolves the genuine Ayeesha Ahmed guest invitation |
| Emma Outgram M365 migration change | Resolves the short-lived test-account alert |
| Hannah Rees external engagement record | Resolves the blocked Teams upload to Tom Blackburn |
| Aimee Flangan encrypted-USB request | Resolves the blocked USB-copy alert |
| Bill Cottray SRE maintenance change | Resolves the Intune local-admin elevation |
| Damo Tom firewall-validation change | Resolves the custom network-indicator connection |
| Cisco ASA patch/maintenance record | Confirms the external appliance was patched before the failed exploitation attempts |
| Olivia Mercer sales campaign record | Resolves the outbound-email-volume alert |
| Rhydian Greggs deployment change | Explains the Terraform/AWS cloud activity |
| Alex Williams audit authorisation | Explains legitimate Purview/eDiscovery activity |

## Exercise behaviour

- All historical tickets and approved changes needed for investigation are visible before the facilitator starts the exercise.
- Analysts must search for them; alerts do not contain direct links to the answer.
- Historical records are read-only so teams cannot alter ground-truth evidence.
- Search state and opened records may be retained per team.
- No new FreshService evidence appears after 13:20.
- Team investigation notes remain in the SIEM/bookmark workflow rather than modifying source tickets.
