# Tenant Review reference

Technical detail for administrators and engineers: what each review covers, the permissions it uses, the files it writes, every setting and the full troubleshooting list. For a step-by-step walkthrough, see the [how-to guide](how-to.md).

## Contents

- [Coverage at a glance](#coverage-at-a-glance)
- [Microsoft 365](#microsoft-365)
- [CIS and CISA SCuBA benchmarks](#cis-and-cisa-scuba-benchmarks)
- [Service settings](#service-settings)
- [Licensed but not used](#licensed-but-not-used)
- [Action plan](#action-plan)
- [Azure](#azure)
- [Servers](#servers)
- [Google Workspace](#google-workspace)
- [Permissions](#permissions)
- [Manual app registration](#manual-app-registration)
- [Outputs](#outputs)
- [Settings (config.json)](#settings-configjson)
- [Troubleshooting](#troubleshooting)
- [Running without the window](#running-without-the-window)
- [Changing or adding checks](#changing-or-adding-checks)
- [How it connects](#how-it-connects)
- [Folder layout](#folder-layout)

## Coverage at a glance

| | Microsoft 365 | Google Workspace |
| --- | --- | --- |
| Sign-in | Admin account in the client tenant, or a partner account through GDAP | A super admin of the client's Google Workspace |
| Checks | 133, plus 29 for Azure | 72 |
| Servers (optional) | 31 checks | The same 31 checks |
| Benchmarks | CIS Microsoft 365 v7.0.0 (160 controls), CISA SCuBA (109) | CIS Google Workspace v1.4.0 (86 controls), CISA SCuBA ScubaGoggles 1.0 (138) |
| Licensed but not used | 32 features | 13 features |
| First time per client | Grant consent | Trust the app |
| Tidy up afterwards | Remove the review app from the tenant | Revoke the review app's access |

Each check returns Pass, Fail, Warning, Info, Manual or Not assessed. Not assessed always comes with the reason, for example a missing role or a licence the tenant does not have.

## Microsoft 365

| Area | Examples |
| --- | --- |
| Identity and access | Security defaults, Conditional Access (MFA, legacy authentication, admins, risk, device), MFA registration, authentication methods, user consent, guest settings, inactive accounts, directory sync health, LAPS |
| Privileged access | Global Administrator count, guests with roles, synced or licensed admins, PIM, apps with directory roles |
| Applications | High-risk application permissions, tenant-wide and user consents, expiring secrets and certificates |
| Licensing | Spare licences, licences on disabled accounts and shared mailboxes, subscription state |
| Exchange Online | Audit, modern authentication, SMTP AUTH, external forwarding, mailbox forwards, mail flow rules, anti-spam allow lists, anti-phishing, Safe Links, Safe Attachments, external tagging, calendar sharing, shared mailbox sign-in, POP and IMAP, quotas |
| Email DNS | SPF, DKIM, DMARC, non-mail domain lockdown, MX routing, MTA-STS |
| SharePoint, OneDrive and Teams | Sharing level, resharing, legacy authentication, idle sign-out, sync restrictions, inactive sites, group creation, ownerless and public groups, guests in Teams |
| Intune and devices | Compliance coverage by platform, encryption, Windows versions, endpoint security policies, enrolment restrictions, app protection, update rings (RMM aware) |
| Intune set-up | Apple push certificate, Apple Business Manager enrolment and VPP tokens, Android Enterprise binding, policies assigned to nobody, policy errors and conflicts, Windows LAPS, BitLocker with key escrow, firewall profiles, attack surface reduction rules, Defender Antivirus, Windows Hello for Business, security baselines, Autopilot, Enrolment Status Page, failed required apps, device clean-up rule, compliance essentials |
| Microsoft Defender XDR | Device onboarding coverage against Intune, discovered devices not onboarded, sensor health, exposure level, vulnerable software and CVEs with public exploits, high-impact recommendations, open incidents, attack simulation training |
| Microsoft Purview | DLP policies and mode, retention coverage of Exchange, SharePoint, OneDrive and Teams, sensitivity labels and label policies, default alert policies, retention labels, eDiscovery cases |
| Secure Score | Overall score and every improvement action with its gap |
| Permissions | Mailbox Full Access, Send As and Send on Behalf; group and Team owners and members; optional sharing link activity from the audit log |
| Service settings | Teams meeting, messaging, app and external access policies; SharePoint and OneDrive tenant sharing; Power BI (Fabric) tenant settings; Power Platform environments, DLP policies and tenant isolation |

Backup is listed as a manual check because it cannot be read through the APIs.

## CIS and CISA SCuBA benchmarks

When the benchmark area is ticked, the Benchmarks tab assesses every control in both frameworks from the same data as the findings. No extra sign-in is needed.

| Status | Meaning |
| --- | --- |
| Met | The setting meets the control |
| Not met | The setting does not meet the control; the evidence says what was found |
| Check manually | The setting has no API, or the control needs a judgement call, for example confirming which accounts are the emergency access accounts |
| Not assessed | The data the control needs could not be read; the reason is shown |
| Not applicable | The control needs a licence the client does not have, for example Entra ID P2 for PIM, or applies only to US federal agencies |

The score for each framework is the controls met divided by the controls met plus not met. A second figure shows the core score: Level 1 controls for CIS and SHALL controls for SCuBA.

Controls that cover the same setting are mapped to each other, so a CIS control shows its SCuBA equivalent and the other way round. Each finding lists the benchmark controls it relates to. `Benchmarks.csv` holds one row per control and `BenchmarkDetails.csv` lists the affected items.

Licensing of the benchmark content:

- The CIS Benchmark text is licensed by CIS under CC BY-NC-SA 4.0. The tool uses its own short control titles and guidance and only references CIS control numbers, so the report can go to clients. For the full wording, rationale and audit steps, use the PDF from CIS WorkBench.
- The CISA SCuBA baselines (ScubaGear and ScubaGoggles) are public domain (CC0).

## Service settings

Some benchmark controls need settings that Microsoft Graph does not expose: Teams policies, SharePoint tenant settings, Power BI tenant settings and Power Platform settings. When **Teams, SharePoint, Power BI and Power Platform settings** is ticked, the review asks for read access to those services once at the start of the run.

- If the account has already approved them for this client, nothing is shown.
- Otherwise the browser opens once, with the account filled in. Approve it and the review carries on. If you close the page or decline, the review continues without them and the related controls show Not assessed.
- A service that is not set up in the client tenant, for example a tenant that has never used Power BI, is skipped.

These permissions are requested during the review, so they are not part of the app registration. They are removed with the app if you use **Remove the review app from this tenant**.

The SharePoint admin address is worked out from the tenant's onmicrosoft.com domain. If the tenant was renamed and that address is wrong, set `SharePointAdminUrl`.

## Licensed but not used

The Opportunities tab compares the service plans in each user's licences, ignoring plans switched off on the licence, with what is configured or used.

| Status | Meaning |
| --- | --- |
| Not used | Licensed, but no matching configuration or activity |
| Partly used | Licensed and started, but incomplete, for example DLP only in simulation or 40% of users active in OneDrive |
| In use | Licensed and configured or used |
| Check in portal | Licensed, but usage cannot be read through the APIs |
| Not assessed | The evidence could not be read; the reason is shown |
| Not applicable, Not licensed | Hidden by default; Not licensed can be shown with the filter as upsell context |

Microsoft 365 covers 32 features, including Conditional Access, SSPR, dynamic groups, Identity Protection, PIM, access reviews, Intune, Autopilot, app protection, Defender for Endpoint or Business, Defender for Identity, Defender for Cloud Apps, Defender for Office 365, attack simulation, sensitivity labels, auto-labelling, DLP, endpoint DLP, retention, online archiving, eDiscovery (Premium), insider risk, Audit (Premium), Customer Lockbox, Microsoft 365 desktop apps, OneDrive, SharePoint, Teams, Teams Phone and Microsoft 365 Copilot.

Google Workspace covers 13 features: data loss prevention, Vault, advanced endpoint management, Windows device management, context-aware access, the security centre, the Gmail security sandbox, data regions, Gemini, Meet, Drive, AppSheet, and passkeys and security keys.

Each feature says what you would set up, the benefit to the client and an effort estimate in days. The full list is written to `Opportunities.csv`.

## Action plan

| Group | What goes in it | Suggested timescale |
| --- | --- | --- |
| Must do | High-severity failures (P1) | Start within 2 weeks |
| Should do | Medium-severity failures and high-severity warnings (P2) | Within 3 months |
| Could do | Other warnings and low-severity items (P3) | Within 6 months |
| Use what you already pay for | Licensed features not used or only partly used | After the fixes above |
| Things to confirm | Manual checks to go through with the client | At the review meeting |

Within each group, items are gathered into themes by area. Each theme says why it matters in plain English, what staff will notice, what you need from the client and the engineer time. Each item shows what good looks like, what was found and its effort.

The indicative timeline assumes `PlanDaysPerWeek` engineer days a week. Set `DayRate` to add an indicative cost per group; costs are hidden while it is 0. `ActionPlan.csv` has one row per item. The theme wording is in `Module\Private\ActionPlan.ps1`.

## Azure

Tick **Azure subscriptions and resources** (Microsoft 365 only). At the start of the review the browser asks once to approve read access to Azure Resource Manager. The tool then reads every subscription the account can see through Azure Resource Manager, Azure Resource Graph, Defender for Cloud and Azure Advisor.

| Area | Examples |
| --- | --- |
| Subscriptions and security | Offers, Defender for Cloud plans, secure score and the Microsoft cloud security benchmark, security alert contacts |
| Network | Management ports and public IPs open to the internet, subnets without NSGs, retired Basic SKUs, Network Watcher |
| Virtual machines | Backup and vault hardening, operating system support (including Arc servers), Defender for Endpoint and Azure Monitor agents, Trusted Launch, patching, Arc connection health |
| Data and apps | Storage, Key Vault, SQL and App Service settings |
| Governance and cost | Owners and guests with Azure roles, resource locks, activity log export, unattached disks and IPs, Advisor cost and high-impact recommendations, budgets |

Azure roles are separate from Entra roles and from GDAP:

- The account needs an Azure role on each subscription, or on a management group above them. **Reader** covers most checks and **Security Reader** adds the Defender for Cloud detail. Global Administrator alone does not give access to subscriptions.
- For CSP subscriptions, your admin agents usually already hold a role through the partner relationship. Subscriptions billed elsewhere need a role in the client tenant or through Azure Lighthouse.
- Where a subscription is visible but a setting is not readable, the finding says so instead of reporting it as off.

Azure has its own tab and score, separate from the Microsoft 365 score. Its findings appear in the action plan with everything else.

## Servers

The collectors in the `Collectors` folder are read-only. They write one `.server-review.json` file per server, which holds configuration only (no passwords or file contents).

| Collector | Where it runs | Main parameters |
| --- | --- | --- |
| `Get-ServerReviewData.ps1` | Each Windows server (Windows Server 2012 R2 or later, PowerShell 5.1), as an administrator or SYSTEM | `-OutputPath` (default `C:\ProgramData\TenantReview\ServerData`), `-SkipUpdateSearch`, `-UpdateSearchTimeoutSeconds` (default 240), `-MaxAdObjects` (default 50000) |
| `Invoke-ServerReviewCollection.ps1` | An admin workstation or management server | `-ComputerName`, `-FromActiveDirectory`, `-Credential`, `-UseSSL`, `-SkipUpdateSearch`, `-ThrottleLimit` (default 8 servers at a time), `-OutputPath` (default `Documents\Server Review Data`) |
| `server-review-collect.sh` | Each Linux server, with sudo | First argument: output folder (default `/var/tmp/server-review`), or `-` to print to the console |
| `Get-VMwareReviewData.ps1` | Any Windows machine with VMware PowerCLI | `-Server` (vCenter or ESXi), `-Credential`, `-OutputPath` (default `Documents\Server Review Data`) |

| Area | Checks |
| --- | --- |
| Windows servers | Supported version, missing security updates and pending restarts, EDR and Defender health, remote access (RDP Network Level Authentication, WinRM, firewall rules open to any address), SMBv1 and signing, a 33-setting hardening baseline drawn from CIS Windows Server Level 1 and the Microsoft security baseline, local administrators and LAPS, audit policy and the Security log, disk space, backup agents, risky services, out-of-support software, time sync, expiring certificates, unexpected shutdowns and disk errors, BitLocker on physical servers |
| Active Directory | Replication and SYSVOL, privileged groups and Protected Users, Kerberoastable and AS-REP roastable accounts, delegation and weak password flags, password and lockout policy, Recycle Bin, krbtgt age, machine account quota, functional level, stale and out-of-support accounts, domain controller hardening, LAPS coverage |
| Hyper-V | Old checkpoints, replication health, cluster nodes and CSV space, stop action, integration services, Secure Boot and Generation 1 VMs, hosts running other roles |
| Linux | Supported release, pending security updates and restarts, SSH and sudo settings, extra root accounts, EDR, host firewall, SELinux or AppArmor, auditd, time sync, disk space, legacy services, kernel hardening |
| VMware | ESXi and vCenter support, lockdown mode, SSH and ESXi Shell, NTP, remote syslog, snapshots, VMware Tools, ISO images, datastore space, vSphere HA |

If a server appears more than once, the newest file is used. The **Server data coverage** finding lists every file found, which were used, and any sections that could not be read.

## Google Workspace

| Area | Examples |
| --- | --- |
| Users, sign-in and administrators | 2-Step Verification enrolment and enforcement (including organisational unit and group overrides), allowed 2SV methods, password policy, session length, inactive accounts, app passwords, less secure apps, recovery emails outside the organisation, unmanaged conflicting accounts |
| Privileged access | Super admin count, super admins without a security key or passkey, super admins used for day-to-day email, super admin self-recovery, roles held by suspended accounts |
| Third-party apps and API access | Access for unconfigured apps, high-impact OAuth grants, Marketplace install policy, internal app trust, Google service API restrictions |
| Licensing | Suspended users still licensed, active users with no edition, assignments by edition |
| Gmail | Spoofing and authentication, attachment and link protection, pre-delivery scanning, automatic forwarding, POP and IMAP, outbound gateways, spam bypass and IP allow lists, comprehensive mail storage, external recipient warnings, mail delegation |
| Email DNS | MX, SPF, DKIM with a 2048-bit key, DMARC enforcement and reporting, unverified domains, MTA-STS |
| Drive and Docs | External sharing, publishing to the web, default link access, shared drive settings, Drive for desktop on unmanaged devices, optional sharing activity from the Drive audit log |
| Calendar, Chat, Meet, Groups and Sites | External calendar sharing, external chat, chat history, Meet host management, group creation and external members, groups open to the internet, ownerless groups, Sites, Takeout |
| Endpoint management | Compromised and unencrypted devices, devices out of support, stale devices, Android patch age, ChromeOS auto-update expiry |
| Alert Center and rules | The CIS system alert rules, open high-severity alerts, suspicious sign-ins and leaked passwords, admin role changes, DLP rules where licensed |

Settings are read through the Policy API for the whole organisation and for every organisational unit or group that overrides it. A few settings the Policy API does not expose are read from the admin audit log for the last 180 days. If nothing was changed in that time, the Google default is assumed and the evidence says so.

Not covered: Gmail filters, delegates and forwarding set by individual users, sharing of individual files beyond the Drive audit log, Vault retention rules and holds, domain-wide delegation clients, context-aware access levels and backup. The report lists these under Method and limitations.

Benchmark points specific to Google:

- Where CIS and SCuBA disagree, both are reported and the guidance says so. Examples are user self-recovery, trusting internal apps, adding non-members to shared drive files and password expiry.
- SCuBA policies that only apply to US federal agencies show Not applicable.
- Controls that need Enterprise, Frontline or Education features show Not applicable when the client does not have them.

The scopes are read-only apart from `apps.licensing`, `apps.groups.settings`, `apps.alerts` and `admin.directory.user.security`, which Google only offers as read and write. The tool only reads with them. No Gmail or Drive content scopes are used.

## Permissions

The app registration created by `New-TenantReviewApp.ps1` is a public client with delegated permissions only. It has no secret or certificate, so it only works with a signed-in user and can never do more than that user's roles allow.

| Platform | Account | Roles |
| --- | --- | --- |
| Microsoft 365 | Admin account in the client tenant | Global Administrator covers everything |
| Microsoft 365 | Partner account through GDAP | Global Reader, plus Security Reader, Reports Reader, Compliance Administrator and the service admin roles for full coverage. Cloud Application Administrator lets engineers grant consent |
| Azure | Either of the above | Reader and Security Reader on each subscription or a management group |
| Google Workspace | Client super admin | Super admin; delegated roles leave many checks Not assessed |
| Servers | Local administrator, SYSTEM, sudo or a read-only vCenter account | Only on the servers being collected |

Notes:

- DLP policies need a Purview role such as Compliance Administrator, or membership of the Organization Management role group. Global Reader alone can return access denied for DLP.
- Teams phone numbers need Teams Communications Administrator. Without it only the Teams Phone opportunity shows Not assessed.
- Entra ID P2 tenants have PIM settings read with `RoleManagementPolicy.Read.Directory`. Without P2 the PIM controls show Not applicable.
- Removing the app at the end of a review asks once for `Application.ReadWrite.All`, for that action only.

## Manual app registration

To create the app in the Entra admin centre instead of running `New-TenantReviewApp.ps1`:

- **Supported account types**: Accounts in any organizational directory.
- **Authentication**: add the platform **Mobile and desktop applications** with the redirect URIs `http://localhost` and `https://login.microsoftonline.com/common/oauth2/nativeclient`. Set **Allow public client flows** to **Yes**.
- **API permissions (delegated)**, Microsoft Graph: `User.Read`, `Directory.Read.All`, `Policy.Read.All`, `AuditLog.Read.All`, `Reports.Read.All`, `ReportSettings.Read.All`, `RoleManagement.Read.Directory`, `Application.Read.All`, `SecurityEvents.Read.All`, `IdentityRiskyUser.Read.All`, `UserAuthenticationMethod.Read.All`, `Domain.Read.All`, `Organization.Read.All`, `Group.Read.All`, `GroupMember.Read.All`, `DeviceManagementConfiguration.Read.All`, `DeviceManagementManagedDevices.Read.All`, `DeviceManagementApps.Read.All`, `DeviceManagementServiceConfig.Read.All`, `SharePointTenantSettings.Read.All`, `OnPremDirectorySynchronization.Read.All`, `AuditLogsQuery-SharePoint.Read.All`, `AuditLogsQuery-OneDrive.Read.All`, `ThreatHunting.Read.All`, `SecurityIncident.Read.All`, `AttackSimulation.Read.All`, `RecordsManagement.Read.All`, `eDiscovery.Read.All`, `offline_access`, `openid`, `profile`.
- Optional Microsoft Graph permissions: `AccessReview.Read.All`, `Printer.Read.All`, `TeamsTelephoneNumber.Read.All`, `SecurityIdentitiesSensors.Read.All`, `Policy.Read.DeviceConfiguration`, `OrgSettings-AppsAndServices.Read.All`, `OrgSettings-Forms.Read.All`, `RoleManagementPolicy.Read.Directory`.
- Office 365 Exchange Online: `Exchange.Manage` (and `Exchange.ManageV2` if listed). The tool only runs Get cmdlets.
- Microsoft Exchange Online Protection (Security & Compliance): `Exchange.Manage` if it is offered as a delegated permission.

Put the Application (client) ID into `config.json` as `ClientId`.

## Outputs

Each run creates `<Reports folder>\<Client>\<yyyy-MM-dd_HHmm>\` containing:

| File | Contents |
| --- | --- |
| `<Client>-M365-Review-<date>.html` | The interactive report. Tabs for the executive summary, action plan, findings, recommendations, opportunities, benchmarks, Azure and Servers (when included), inventories and method and limitations |
| `<Client>-M365-Review-<date>.pdf` | The report as an A4 PDF, created with Microsoft Edge or Chrome in the background. Inventories are left out; they are in the HTML and CSV files |
| `<Client>-M365-Review-<date>-Summary-and-Action-Plan.pdf` | Only the executive summary and the action plan, written for the client |
| `CSV\` | Findings, affected items, recommendations, the action plan, opportunities, benchmarks and benchmark affected items, and one CSV per inventory |
| `RawData.json` | Everything collected. Used by **Rebuild from saved data** |
| `Review.log` | The run log |

Google Workspace files are named `<Client>-Google-Workspace-Review-<date>`. These files contain client data. Store them with the client's documentation.

## Settings (config.json)

| Setting | Default | Purpose |
| --- | --- | --- |
| `ClientId` | Set by setup | App (client) ID of the review app in Entra ID |
| `GoogleClientId`, `GoogleClientSecret` | Empty | OAuth client ID and secret of the Desktop app client in your Google Cloud project |
| `CompanyName`, `CompanyShortName` | Your Company | Branding in the app and on the report |
| `HoursPerDay` | 7.5 | Converts effort hours to days |
| `PlanDaysPerWeek` | 2 | Engineer days a week assumed for the action plan timeline |
| `DayRate` | 0 | Day rate for the indicative cost in the action plan. 0 hides costs |
| `CurrencySymbol` | Pound sign | Currency symbol for costs. In `config.json` the pound sign is written as `\u00a3` |
| `PatchingViaRmm` | true | Treats Windows patching as RMM-managed and flags Intune update rings that overlap |
| `MinimumWindows11Build` | 26100 | Windows 11 builds below this are flagged |
| `InactiveDays`, `StaleDeviceDays`, `InactiveSiteDays` | 90, 180, 180 | Thresholds for inactivity checks |
| `MaxMailboxes` | 3000 | Cap on mailboxes read for Full Access. For Google, the cap on users whose app grants and app passwords are read |
| `MaxGroups` | 1000 | Google Workspace: cap on groups whose settings and members are read |
| `OutputRoot` | `Documents\Tenant Reviews` | Default reports folder |
| `DnsMode` | Auto | Auto uses Windows DNS, falling back to DNS over HTTPS. Set `DoH` if the local resolver gives split-horizon answers |
| `LogoPath` | `Assets\logo.svg` | Logo in the app and on the report. SVG, PNG or JPG; relative paths are from the tool folder |
| `CreatePdf` | true | Creates the PDF copy of the report after each review or rebuild |
| `CreateSummaryPdf` | true | Also creates the summary and action plan PDF |
| `PdfBrowserPath` | Automatic | Path to `msedge.exe` or `chrome.exe` if the PDF step cannot find a browser |
| `SharePointAdminUrl` | Automatic | SharePoint admin address, for example `https://contoso-admin.sharepoint.com`. Only needed after a tenant rename |

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| "has not been consented in this tenant" | Run **Grant consent** for that client. Consent is per client and only needed once, or again after the app's permissions change. |
| "has no access to the tenant" | The GDAP relationship has expired or your security group is not assigned to it. |
| "Blocked by a Conditional Access policy" | The client's Conditional Access blocks the sign-in. Check the client's sign-in log. |
| Exchange checks show Not assessed | Exchange did not accept the token. Check Collection diagnostics for the exact error, confirm Global Reader is in the GDAP relationship and that an Exchange permission is consented. |
| Intune checks show Not assessed | The tenant is not licensed for Intune or the account lacks Intune read access. |
| Defender checks show Not assessed | Advanced hunting needs Defender for Endpoint or Defender for Business, the `ThreatHunting.Read.All` consent, and Security Reader or Global Reader. The DefenderDevices row in Collection diagnostics has the exact error. |
| Purview checks say "Secure Score reports" | The Security & Compliance API could not be reached, so the check fell back to Secure Score evidence. See SccDlpPolicies in Collection diagnostics. Run `New-TenantReviewApp.ps1 -UpdateExisting` and **Grant consent** if the error mentions the permission. |
| "this account is not allowed to read DLP policies" | Add Compliance Administrator, or add the account to the Purview Organization Management role group. |
| "Defender for Endpoint has not been set up in this tenant" | No devices have been onboarded. Not a fault in the tool; the Defender device checks show Not assessed. |
| An opportunity shows Not assessed | The usage data could not be read, or its review area was not selected. The reason is in the card. |
| Usage reports show random names | The tenant conceals names in reports. Turn it off in the Microsoft 365 admin centre under **Org settings**, **Reports**, if the client agrees. |
| Teams, SharePoint, Power BI or Power Platform controls show Not assessed | The service access was not approved, the account lacks the admin role, or the service is not set up. The log line for each service at the start of the run says which. |
| SharePoint settings show Not assessed with a 404 | The admin address worked out from the onmicrosoft.com domain is wrong, usually after a rename. Set `SharePointAdminUrl`. |
| No PDF was created | Edge is not in the standard location. Set `PdfBrowserPath`, or open the HTML report and select **Save as PDF**. |
| A single check shows Not assessed | The data it needs could not be read. The reason is in the finding and in Collection diagnostics. |
| Google: "blocks this app" (`admin_policy_enforced`) | The client has not trusted the review app. Use **Trust the app**, then wait a few minutes. |
| Google: "did not recognise the OAuth client" | `GoogleClientId` or `GoogleClientSecret` does not match the Desktop app client, or the client was deleted. |
| Google: "Access blocked: this app's request is invalid" or `redirect_uri_mismatch` | The OAuth client is not of type Desktop app. |
| Google: "this account cannot read the Google Workspace directory" | The account is not an admin of that Google Workspace. Sign in as a super admin. |
| Google: HTTP 403 "API has not been used in project" | One of the five APIs is not enabled in your Google Cloud project. Enable it and wait a few minutes. |
| Google: HTTP 403 "insufficient authentication scopes" | A permission was not ticked on the consent screen. Sign in again and tick every permission. |
| Google: usage figures look a few days old | Google publishes usage reports two to four days in arrears. The tool uses the latest day available and says which. |
| Azure tab shows no subscriptions | The account has no Azure role on any subscription. Assign Reader and Security Reader, then run the review again. Rebuilding does not re-read Azure. |
| Azure findings say a setting "could not be read" | The account can see the subscription but lacks a role for that setting, usually Security Reader. |
| Azure was skipped | Azure read access was not approved when the browser asked. Run the review again and approve it. |
| Server data: 0 systems | The folder holds no `.server-review.json` files from the collectors. Check the Server data files inventory. |
| A server finding says sections could not be read | The collector did not run as an administrator or SYSTEM. Run it again elevated. |
| Missing update search shows TimedOut or Failed | The server could not reach Windows Update or WSUS in time. Use `-UpdateSearchTimeoutSeconds 600`, or rely on your RMM patch report and `-SkipUpdateSearch`. |
| `Invoke-ServerReviewCollection.ps1` fails for a server | WinRM is not enabled or is blocked. Run `Enable-PSRemoting` on the server, use the FQDN so Kerberos works, or run the collector locally through your RMM. |
| Removing the review app reports an error | The account could not approve `Application.ReadWrite.All`. Sign in as a Global Administrator or Cloud Application Administrator, or delete the **Tenant Review** enterprise application in the Entra admin centre. |

## Running without the window

Microsoft 365:

```powershell
Import-Module .\Module\TenantReview.psm1
Import-TRSettings -Path .\config.json | Out-Null
Connect-TRTenant -Tenant 'fabrikam.onmicrosoft.com' -ClientId '<client id>'
Invoke-TenantReview -ClientName 'Fabrikam Lettings Ltd' -OutputRoot 'C:\Reviews' -ServerDataPath 'C:\Reviews\Fabrikam Lettings Ltd\Server data'
Invoke-TenantAnalysis -RawPath 'C:\Reviews\Fabrikam Lettings Ltd\2026-10-17_1400\RawData.json'
```

`-ServerDataPath` is optional on both commands. On `Invoke-TenantAnalysis` it adds or refreshes the server data in a saved review.

Google Workspace:

```powershell
Import-Module .\Module\TenantReview.psm1
$s = Import-TRSettings -Path .\config.json
Connect-TRGoogle -Domain 'northwinddental.example' -ClientId $s.GoogleClientId -ClientSecret $s.GoogleClientSecret
Invoke-TenantReview -ClientName 'Northwind Dental Ltd' -OutputRoot 'C:\Reviews'
Remove-TRGoogleAccess
```

## Changing or adding checks

| What | Where | Registered with |
| --- | --- | --- |
| Microsoft 365 checks | `Module\Private\Checks.ps1`, `IntuneChecks.ps1` | `Register-TRCheck` |
| Azure and server checks | `AzureChecks.ps1`, `ServerChecks.ps1` | `Register-TRCheck -Platform Any` |
| Google Workspace checks | `GoogleChecks.ps1` | `Register-TRCheck -Platform Google` |
| Benchmark controls | `BaselinesCis.ps1`, `BaselinesScuba.ps1`, `GoogleBaselinesCis.ps1`, `GoogleBaselinesScuba.ps1` | `Register-TRControl` |
| Licence opportunities | `Opportunities.ps1`, `GoogleOpportunities.ps1` | `Register-TROpportunity` |
| Action plan themes | `ActionPlan.ps1` | |
| Data collection | `Collect.ps1`, `AzureCollect.ps1`, `GoogleCollect.ps1` | |

Each check has an ID, area, severity, effort, the data it needs, the recommendation, a reference link and a test that returns Pass, Fail, Warning, Info, Manual or NotAssessed. After a change, rebuild a saved review to test it without touching a tenant.

## How it connects

Microsoft 365:

- Sign-in uses the OAuth 2.0 authorisation code flow with PKCE and a loopback redirect in the system browser, so MFA, passkeys and Conditional Access work normally.
- Microsoft Graph is used for identity, apps, licensing, SharePoint settings, usage reports, Intune and Secure Score.
- Exchange Online is read through the REST endpoint the Exchange Online PowerShell module uses, with Get cmdlets only.
- Purview policies are read the same way from the Security & Compliance endpoint. If it cannot be reached, Purview checks fall back to Secure Score evidence.
- Defender data comes from Microsoft Graph advanced hunting, covering the last 30 days.
- Teams, SharePoint, Power BI and Power Platform settings come from their admin APIs. The tool only reads from them.

Google Workspace:

- Sign-in uses the OAuth 2.0 authorisation code flow with PKCE and a loopback redirect in the system browser, so 2SV, passkeys and security keys work normally.
- The Admin SDK Directory API is used for users, domains, organisational units, admin roles, groups, app grants and ChromeOS devices; the Reports API for usage and audit logs; the Cloud Identity API for Admin console settings and endpoint devices; the Enterprise License Manager API for licences; the Groups Settings API for group access; and the Alert Center API for alerts.

Both:

- DNS records are read from Windows DNS or DNS over HTTPS.
- Tokens are held in memory only and are discarded when the window closes. Nothing is written to the client tenant or Workspace, apart from removing the review app when you ask the tool to.

## Folder layout

```
tenant-review/
  Start-TenantReview.cmd
  Start-TenantReview.ps1
  New-TenantReviewApp.ps1
  config.json
  Assets/
  Collectors/
    Get-ServerReviewData.ps1
    Invoke-ServerReviewCollection.ps1
    Get-VMwareReviewData.ps1
    server-review-collect.sh
  Module/
    TenantReview.psm1
    Private/
  docs/
    how-to.md
    reference.md
    images/
```
