<p align="center">
  <img src="docs/images/hero.png" alt="Tenant Review: read-only security reviews with a plan your clients will understand" width="100%">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Windows-10%20%7C%2011-0F4761?style=flat-square" alt="Windows 10 or 11">
  <img src="https://img.shields.io/badge/PowerShell-5.1%20%7C%207-1F8FB8?style=flat-square" alt="PowerShell 5.1 or 7">
  <img src="https://img.shields.io/badge/Microsoft%20365-supported-0F4761?style=flat-square" alt="Microsoft 365">
  <img src="https://img.shields.io/badge/Google%20Workspace-supported-0F4761?style=flat-square" alt="Google Workspace">
  <img src="https://img.shields.io/badge/access-read--only-2E7D32?style=flat-square" alt="Read-only">
  <img src="https://img.shields.io/badge/version-1.5.0-5F6B76?style=flat-square" alt="Version 1.5.0">
</p>

# Tenant Review

Tenant Review is a Windows desktop tool for IT consultants and managed service providers. It reviews a client's **Microsoft 365** tenant or **Google Workspace**, and optionally their **Azure** subscriptions and **servers**. The engineer signs in, the tool reads the configuration (read-only), runs its checks, scores the client against the **CIS** and **CISA SCuBA** benchmarks and produces a report the client can act on.

Every report opens with a plain-English **action plan**: what must be done, what is advised, what could wait, how long each part takes and what the client needs to provide.

It needs no PowerShell modules, so there are no Graph SDK, Exchange or Google module version conflicts.

**[Read the how-to guide](docs/how-to.md)** | **[Technical reference](docs/reference.md)** | **[Sample reports](samples/)**

## Contents

- [What you get](#what-you-get)
- [How it works](#how-it-works)
- [Quick start](#quick-start)
- [Screenshots](#screenshots)
- [Security and privacy](#security-and-privacy)
- [Requirements](#requirements)
- [Benchmark content](#benchmark-content)

## What you get

| | Microsoft 365 | Google Workspace |
| --- | --- | --- |
| Checks | 133, plus 29 for Azure | 72 |
| Servers (optional) | 31 checks across Windows, Active Directory, Hyper-V, Linux and VMware | The same 31 checks |
| Benchmarks | CIS Microsoft 365 v7.0.0 (160 controls), CISA SCuBA (109) | CIS Google Workspace v1.4.0 (86 controls), CISA SCuBA ScubaGoggles 1.0 (138) |
| Licensed but not used | 32 features | 13 features |
| Typical run time | 2 to 5 minutes for a small business | 1 to 3 minutes for a small business |

Each review produces:

- an interactive **HTML report** with an executive summary, action plan, findings, prioritised recommendations, licence opportunities, benchmarks, Azure, servers, inventories and method;
- a short **Summary and action plan PDF** written for the client and their board;
- a **full report PDF** ready to attach;
- **CSV exports** of findings, the action plan, benchmarks and every inventory, ready for a proposal or your PSA;
- **RawData.json**, so the report can be rebuilt later without signing in again.

Before you share it, select **Edit effort** in the report to adjust any estimate. Every total, the timeline and the costs recalculate as you type, and the changes can be saved for the tool's PDFs and CSV files too. If the review account could not read something, the end of the log and the report's Method and limitations section say why and what to do, so you can fix the permission and run again.

<p align="center">
  <img src="docs/images/report-action-plan.png" alt="The action plan tab" width="100%">
</p>

<p align="center"><em>The action plan groups the work into Must do, Should do, Could do and Use what you already pay for, with effort and an indicative timeline.</em></p>

## How it works

<p align="center">
  <img src="docs/images/how-it-works.png" alt="How Tenant Review works" width="100%">
</p>

1. **Sign in** through the browser with the client admin account. MFA, passkeys and Conditional Access work as normal.
2. **Collect** the configuration through the official APIs. Nothing is changed.
3. **Check, benchmark and plan** on the engineer's PC.
4. **Share** the summary PDF with the client, and keep the full outputs with their documentation.

## Quick start

1. Download the repository and extract the `tenant-review` folder.
2. Run `New-TenantReviewApp.ps1` once in your own tenant. It creates a read-only, multi-tenant app registration and saves its client ID in `config.json`.
3. Set `CompanyName` (and optionally `LogoPath` and `DayRate`) in `config.json`.
4. Double-click `Start-TenantReview.cmd`.
5. Enter the client name and tenant, select **Grant consent** (first time only), then **Sign in** and **Run review**.

For Google Workspace, Azure, servers and everything else, follow the **[how-to guide](docs/how-to.md)**.

<p align="center">
  <img src="docs/images/review-flow.png" alt="A review from start to finish" width="100%">
</p>

## Screenshots

All screenshots use fictional organisations and `.example` domains.

<table>
  <tr>
    <td width="50%"><img src="docs/images/app-window.png" alt="The app after a Microsoft 365 review"><br><sub><b>The app</b>: sign in, choose the areas, run</sub></td>
    <td width="50%"><img src="docs/images/report-summary.png" alt="Executive summary"><br><sub><b>Executive summary</b>: score, RAG status and key figures</sub></td>
  </tr>
  <tr>
    <td><img src="docs/images/report-findings.png" alt="Findings"><br><sub><b>Findings</b>: evidence, affected items and how to fix</sub></td>
    <td><img src="docs/images/report-benchmarks.png" alt="Benchmarks"><br><sub><b>Benchmarks</b>: CIS and CISA SCuBA, mapped to each other</sub></td>
  </tr>
  <tr>
    <td><img src="docs/images/report-opportunities.png" alt="Opportunities"><br><sub><b>Opportunities</b>: licensed features not in use</sub></td>
    <td><img src="docs/images/report-recommendations.png" alt="Recommendations"><br><sub><b>Recommendations</b>: prioritised, with effort</sub></td>
  </tr>
  <tr>
    <td><img src="docs/images/report-azure.png" alt="Azure"><br><sub><b>Azure</b>: subscriptions, exposure, backup and cost</sub></td>
    <td><img src="docs/images/report-servers.png" alt="Servers"><br><sub><b>Servers</b>: Windows, Active Directory, Hyper-V, Linux and VMware</sub></td>
  </tr>
  <tr>
    <td><img src="docs/images/google-summary.png" alt="Google Workspace summary"><br><sub><b>Google Workspace</b>: the same report for Google clients</sub></td>
    <td><img src="docs/images/pdf-pages.png" alt="Summary and action plan PDF"><br><sub><b>Summary PDF</b>: the pack you send to the client</sub></td>
  </tr>
  <tr>
    <td><img src="docs/images/report-edit-effort.png" alt="Editing effort in the report"><br><sub><b>Edit effort</b>: change any estimate and everything recalculates</sub></td>
    <td><img src="docs/images/report-what-to-fix.png" alt="What could not be read, and how to fix it"><br><sub><b>What to fix</b>: permission and licence gaps, with the fix</sub></td>
  </tr>
</table>

## Security and privacy

- **Read-only.** The tool only reads configuration. The one exception is removing its own app from the client tenant at the end of a review, and only when you ask it to.
- **Delegated sign-in.** The app registration has no secret or certificate. It only works with a signed-in user and can never do more than that user's roles allow.
- **Nothing is sent anywhere else.** Data goes from the client's APIs to the engineer's PC and stays there. There is no telemetry. The only other lookups are public DNS records for the client's domains, through Windows DNS or, as a fallback, Google's public DNS over HTTPS (`DnsMode` in `config.json`).
- **Tokens in memory only.** They are discarded when the window closes.
- **Easy to tidy up.** One option removes the app and its consents from a Microsoft 365 tenant, or revokes the Google tokens, when the review finishes.

Review outputs describe the client's environment in detail. Store them with the client's documentation and never commit them to a public repository.

## Requirements

- Windows 10 or 11 with Windows PowerShell 5.1 (built in) or PowerShell 7.
- Microsoft Edge or Google Chrome for sign-in and the PDFs.
- **Microsoft 365**: an admin account in the client tenant with Global Administrator, or a partner account with a GDAP relationship that includes Global Reader. See [Permissions](docs/reference.md#permissions) for the extra roles that give full coverage.
- **Google Workspace**: a super admin of the client's Google Workspace, and a Google Cloud project with a Desktop app OAuth client (one-off).
- **Azure** (optional): Reader and Security Reader on the client's subscriptions.
- **Servers** (optional): local administrator, SYSTEM through your RMM, sudo on Linux, or a read-only vCenter account.

## Benchmark content

- The CIS Benchmark text is licensed by CIS under CC BY-NC-SA 4.0. Tenant Review uses its own short control titles and guidance and only references CIS control numbers. For the full wording, use the benchmark PDFs from CIS WorkBench.
- The CISA SCuBA baselines (ScubaGear and ScubaGoggles) are public domain (CC0).

Microsoft 365, Azure, Entra and Intune are trademarks of Microsoft. Google Workspace is a trademark of Google. CIS Benchmarks is a trademark of the Center for Internet Security. Tenant Review is not affiliated with or endorsed by any of them.
