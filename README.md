# ServerCloak

A lightweight intrusion detection and defense system for Windows Server. ServerCloak watches event logs, IIS logs
and network traffic for failed logins (IPv4 and IPv6). When an address reaches the limit, it is blocked inbound in
Windows Defender Firewall, for longer each time it comes back.

[![License: Dual](https://img.shields.io/badge/license-MIT%20%2B%20Commercial-blue.svg)](LICENSE)

## What it protects

| Cloak | Source |
|---|---|
| Windows logon (RDP with NLA, SMB, WinRM, Hyper-V remote management, IIS Windows auth) | Security event 4625 |
| Remote Desktop | RdpCoreTS/Operational event 140 |
| RD Gateway | TerminalServices-Gateway/Operational events 201, 301 |
| Active Directory (NTLM) | Security event 4776, workstation resolved by DNS |
| Kerberos | Security event 4771 |
| SQL Server | Application event 18456 |
| OpenSSH Server | OpenSSH/Operational (in-box from Server 2019) |
| Routing and Remote Access / VPN | System event 20271 |
| FileMaker | Application event 661 |
| IIS web | W3C log, 401.1 |
| Exchange / OWA | W3C log, 401.1 on OWA, ECP, EWS, ActiveSync, MAPI, RPC, Autodiscover, OAB (off by default) |
| RD Web Access | W3C log, failed sign-in posts to `/RDWeb/.../login.aspx` |
| IIS FTP | FTP W3C log, PASS with 530 (works with FTPS) |
| IIS SMTP | SMTP W3C log, 535 |
| SMTP, FTP, RDP sniffers | Raw socket on plain-text traffic, IPv4 and IPv6 (FTP and RDP sniffers are off by default) |
| Custom rules | Any event log + event IDs (optional regex), or any text log + regex with `(?<ip>…)` and optional `(?<user>…)` |
| Windows Firewall | Turned back on within 30 seconds if switched off |

## Features

- **Repeat offender escalation:** 1 hour the first time, then 1 day, then permanent (steps are editable).
- **User names tried:** recorded per attempt. Windows, Kerberos, SQL Server and OpenSSH status codes tell whether the
  account really exists, and an alert is sent when a real account is targeted.
- **Country blocking:** block chosen countries, or allow only chosen countries.
- **Shared block lists:** Spamhaus DROP (IPv4/IPv6), FireHOL level 1, the AbuseIPDB blacklist (API key) and any list
  URL. Blocked attackers can be reported to AbuseIPDB.
- **Never blocked:** the whitelist, this server's addresses, private and reserved networks, and the client addresses
  of signed-in Remote Desktop sessions (self-lockout guard).
- **Alerts:** email (SMTP) and a Slack, Teams workflow or Discord webhook, for blocks, attack spikes, the service
  stopping, real accounts targeted, failed health checks and a daily summary.
- **Health check:** an event log warning and alert when no failed logins are seen for a set number of hours.
- **Test mode:** records attacks and shows what would be blocked without touching the firewall.
- **Tray icon:** minimise to the tray, pop-ups for blocks and alerts, optional start at sign-in.
- **Reports:** attacks-over-time chart (24 h, 7 days, 30 days), CSV export of attempts and addresses, PDF report.
- **IP list:** search, paging, and a right-click menu to whitelist, unblock, block, copy or look up an address.
- **Settings backup:** export and import cloaks, custom rules, whitelist, countries, block lists, alerts and options
  as JSON (passwords and keys are never exported).
- **Updates:** checks GitHub releases daily and installs a newer installer; signed builds only accept updates signed
  by the same publisher.

Country lookup uses the free DB-IP Lite database (IPv4 and IPv6), downloaded by the service and refreshed monthly.
IP geolocation by [DB-IP](https://db-ip.com), CC BY 4.0.

### Per Windows version

| Feature | 2016 | 2019 | 2022 / 2025 |
|---|---|---|---|
| All event log and IIS cloaks | Yes | Yes | Yes |
| OpenSSH cloak | If OpenSSH is installed | Yes | Yes |
| Firewall dynamic keywords (one keyword holds the block list) | No, rules used | No, rules used | Yes, with fallback to rules |

Without dynamic keywords the block list is kept in rules named `ServerCloak Block 001`, `002`, … (1000 addresses
each). Country and block list ranges are kept in `ServerCloak Range 001`, `002`, …

## Solution layout

| Project | Purpose |
|---|---|
| `src/ServerCloak.Core` | SQLite databases (EF Core), firewall (NetFwTypeLib COM), country lookup, block lists, alerts, service control, OS detection. |
| `src/ServerCloak.Service` | Windows service (`ServerCloakService.exe`) hosting the cloaks. `ServerCloakService.exe install` / `uninstall` is used by the installer. |
| `src/ServerCloak.App` | WPF desktop app (`ServerCloak.exe`), bento glass design with light and dark themes, tray icon. |
| `tests/ServerCloak.Tests` | xUnit tests for IP and CIDR matching, range sets, log parsers, IIS detectors and the packet parser. |
| `installer/ServerCloak.iss` | Inno Setup 6 installer script. |
| `tools/IconGen` | Renders `assets/ServerCloak.ico`. |

## Requirements

- Windows Server 2016 or later, or Windows 10/11 (64-bit)
- Windows Defender Firewall
- Visual Studio 2026 (or 2022) with the .NET desktop workload to build. The firewall code uses a COM reference,
  so build with Visual Studio's MSBuild, not `dotnet build`.
- Optional: [Inno Setup 6](https://jrsoftware.org/isinfo.php) for the installer, and the Windows SDK (`signtool`) with
  a code signing certificate to sign.

The published build is self-contained: .NET does not need to be installed on the server.

## Build and publish

```powershell
git clone https://github.com/vikasrulez/ServerCloak.git
cd ServerCloak
```

Open `ServerCloak.slnx` in Visual Studio, or publish from PowerShell:

```powershell
.\publish.ps1                                 # tests, self-contained build in .\publish, installer if Inno Setup is installed
.\publish.ps1 -CertThumbprint <thumbprint>    # also signs the exes, dlls and installer
```

The installer is written to `.\publish-installer\ServerCloak-Setup-<version>.exe`. For auto-update, attach it to a
GitHub release tagged `v<version>` in the repository set on the App card (default `vikasrulez/ServerCloak`).
The version number is set in `Directory.Build.props`.

To run only the tests, build `tests/ServerCloak.Tests` and run
`tests/ServerCloak.Tests/bin/Debug/net10.0-windows/win-x64/ServerCloak.Tests.exe`.

## Setup

With the installer: run `ServerCloak-Setup-<version>.exe`. It installs to Program Files and installs and starts the
service.

Without it:

1. Copy the `publish` folder to the server, for example `C:\Program Files\ServerCloak`.
2. Run `ServerCloak.exe` (it asks for administrator rights) and click **Install service**.

Then add trusted addresses to the whitelist, and adjust cloaks, limits and block times.

## Data

| File | Contents |
|---|---|
| `C:\ProgramData\ServerCloak\servercloak.db` | Settings, cloaks, blocks, whitelist, countries, block lists, country ranges |
| `C:\ProgramData\ServerCloak\servercloak-logs.db` | Attack history (kept 180 days by default) and notifications |
| `C:\ProgramData\ServerCloak\ErrorLog.txt` | Errors |

Service messages go to the Application event log under the source `ServerCloak`. New tables and columns are added
automatically when a newer version starts.

## How it works

1. Each cloak watches its event log, log files or port.
2. Every failed attempt is stored with the address, cloak and user name.
3. When an address reaches the cloak's limit, it is added to the firewall block list for the escalation step (or the
   cloak's block time when escalation is off).
4. Expired blocks are removed every minute; permanent blocks stay until unblocked in the app.

## License

Dual-licensed, see [LICENSE](LICENSE).

- **MIT License:** free for personal, educational, and non-commercial use.
- **Commercial License:** required for business or commercial use. Contact
  [vikasrulez@gmail.com](mailto:vikasrulez@gmail.com).
