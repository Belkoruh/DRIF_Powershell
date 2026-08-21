# PowerShell Incident Response & Digital Forensics (DFIR)

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%20%7C%207%2B-5391FE?logo=powershell&logoColor=white)](https://microsoft.com/PowerShell)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%20%7C%2011%20%7C%20Server-0078D6?logo=windows&logoColor=white)](https://microsoft.com/windows)
[![MDE Live Response](https://img.shields.io/badge/Defender%20Live%20Response-Supported-00A4EF?logo=microsoft)](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/live-response)
[![License: BSD-3-Clause](https://img.shields.io/badge/License-BSD_3--Clause-blue.svg)](./LICENSE)

A comprehensive suite of PowerShell scripts for **Digital Forensics & Incident Response (DFIR)**, **threat hunting**, **evidence acquisition**, **containment**, and **interactive HTML reporting** on Windows endpoints, Active Directory Domain Controllers, and Microsoft Cloud environments (Microsoft Defender for Endpoint / Entra ID).

---

## ⚡ Quick Start

### 1. Automated Host Triage (`DFIR-Script.ps1`)

```powershell
# Automated Full Triage (Default: last 2 days of security events)
.\DFIR-Script.ps1

# Automated Triage with custom search window (e.g., last 10 days)
.\DFIR-Script.ps1 -sw 10

# Bypass execution policy if required
PowerShell.exe -ExecutionPolicy Bypass -File .\DFIR-Script.ps1 -sw 7
```

> 📁 Triage evidence is saved in `DFIR-<Hostname>-<Date>/` and automatically compressed into a `.zip` archive.

### 2. Generate Interactive HTML Forensic Report (`Generate-DFIRHtmlReport.ps1`)

```powershell
# Automatically detect the latest DFIR-* output folder and open the HTML dashboard
.\Analysis\Generate-DFIRHtmlReport.ps1 -OpenReport

# Generate report from a specific evidence folder or ZIP archive
.\Analysis\Generate-DFIRHtmlReport.ps1 -EvidencePath ".\DFIR-HOST-2026-08-21" -OpenReport
.\Analysis\Generate-DFIRHtmlReport.ps1 -EvidencePath ".\DFIR-HOST-2026-08-21.zip" -OutputFile "Report.html" -OpenReport
```

---

## 📁 Repository Structure

```text
DFIR_Powershell/
├── DFIR-Script.ps1              # Core automated triage engine (25+ indicators -> CSV & ZIP)
├── Acquisition/                 # Targeted evidence collection (26 scripts)
├── Analysis/                    # Threat hunting, persistence, auditing & HTML reporting (15 scripts)
├── Containment/                 # Host & cloud remediation scripts (6 scripts)
├── LICENSE                      # BSD 3-Clause License
└── README.md                    # Documentation & script catalog
```

---

## 🛠️ Main Engine: `DFIR-Script.ps1`

The all-in-one triage engine collects forensic indicators across multiple dimensions, generates **SIEM-ready CSV files** in `CSV Results (SIEM Import Data)\`, and archives the entire output folder.

### Collected Artifacts

| Category | Standard User | Administrator (Elevated) |
|:---|:---|:---|
| **Identity & Users** | Active Users, Local Users | Full Registry Hives (`SAM`, `SYSTEM`, `SECURITY`, `SOFTWARE`, `NTUSER.DAT`) |
| **Execution & History** | PSReadLine History (Current User), Run Keys, Startup Folder | PSReadLine History (All Users), Prefetch (`.pf`) |
| **Network & Comms** | Open TCP/UDP Connections, DNS Cache, Active SMB Shares, Office URLs | Remotely Opened Files (SMB sessions) |
| **System & Persistence** | Running Services, Scheduled Tasks, Installed Drivers, Software List | Volume Shadow Copies (`VSS`) |
| **Security & Logs** | Active USB / PnP Devices, RDP Sessions | Windows Security Events (Logons, Process Cre.), MPLogs, Defender Exclusions |
| **Browsers** | Chrome, Edge, Brave, Opera, Firefox History & Profiles | - |

---

## 📦 Script Catalog

### 1. Acquisition (`Acquisition/`)

| Script | Purpose | Key Parameters | Privilege |
|:---|:---|:---|:---|
| [`CollectAIArtifacts.ps1`](./Acquisition/CollectAIArtifacts.ps1) | Extracts AI/LLM desktop chat history, configs, API keys (Claude, ChatGPT, Cursor, Windsurf, Copilot, Ollama, Jan, LM Studio, etc.) | `-AllUsers`, `-OutputDir`, `-ExcludeModels` | User / Admin |
| [`CollectActiveDirectoryArtifacts.ps1`](./Acquisition/CollectActiveDirectoryArtifacts.ps1) | DC Forensics: detects DC role, dumps NTDS.dit / BootKey, SYSVOL/GPOs, ADSI Kerberos surface (Kerberoasting, AS-REP, Delegation) | `-OutputDir`, `-DumpNTDS`, `-IncludeSYSVOL` | **Domain Admin** |
| [`CollectVPNAndSockets.ps1`](./Acquisition/CollectVPNAndSockets.ps1) | Live TCP/UDP sockets mapped to process commands + VPN configs (Cisco, GlobalProtect, OpenVPN, FortiClient, WireGuard, Tailscale) | `-AllUsers`, `-IncludeLogs`, `-OutputDir` | User / Admin |
| [`CollectSSHArtifacts.ps1`](./Acquisition/CollectSSHArtifacts.ps1) | Reconstructs lateral movement: OpenSSH configs, `known_hosts`, `authorized_keys`, PuTTY, WinSCP, MobaXterm sessions & keys | `-AllUsers`, `-CollectPrivateKeys`, `-OutputDir` | User / Admin |
| [`CollectExecutionArtifacts.ps1`](./Acquisition/CollectExecutionArtifacts.ps1) | Gathers binary execution proof: Prefetch (`.pf`), SRUM (`SRUDB.dat`), BAM/DAM, and Amcache (`Amcache.hve`) | `-OutputDir`, `-PrefetchOnly` | **Admin** |
| [`CollectTargetedEvtxLogs.ps1`](./Acquisition/CollectTargetedEvtxLogs.ps1) | Copies critical EVTX logs (Sysmon, PowerShell 4104/4103, TaskScheduler, RDP, Defender, Security, System) | `-OutputDir`, `-IncludeAllChannels` | **Admin** |
| [`CollectWindowsEvents.ps1`](./Acquisition/CollectWindowsEvents.ps1) | Dumps Windows Event Log entries within a configured time window to CSV | `-Days`, `-OutputDir` | Admin |
| [`CollectWindowsSecurityEvents.ps1`](./Acquisition/CollectWindowsSecurityEvents.ps1) | Extracts Security event logs (Logons 4624/4625, Process Creation 4688, User Mgmt) | `-Days`, `-OutputDir` | Admin |
| [`DumpRegistryHives.ps1`](./Acquisition/DumpRegistryHives.ps1) | Dumps raw Windows Registry Hives (SAM, SYSTEM, SECURITY, SOFTWARE, DEFAULT, NTUSER.DAT, UsrClass.dat) | `-OutputDir`, `-SystemOnly`, `-UserOnly` | **Admin** |
| [`CollectUserActivity.ps1`](./Acquisition/CollectUserActivity.ps1) | Collects LNK shortcuts, Jump Lists (`AutomaticDestinations`), and Recent file access across profiles | `-AllUsers`, `-OutputDir` | User / Admin |
| [`CollectNetworkTriage.ps1`](./Acquisition/CollectNetworkTriage.ps1) | Captures volatile network state: DNS Client cache, ARP/Neighbor tables, IP routes, SMB sessions | `-OutputDir` | User / Admin |
| [`CollectPSReadLineHistory.ps1`](./Acquisition/CollectPSReadLineHistory.ps1) | Collects `ConsoleHost_history.txt` across all user profiles | `-AllUsers`, `-OutputDir` | User / Admin |
| [`CollectRDPArtifacts.ps1`](./Acquisition/CollectRDPArtifacts.ps1) | Collects RDP client credentials hints, Bitmap caches (`bcache*.bmc`), and Terminal Services logs | `-OutputDir` | User / Admin |
| [`CollectBrowserArtifacts.ps1`](./Acquisition/CollectBrowserArtifacts.ps1) | Unified browser artifact collector (Edge, Chrome, Brave, Firefox, Opera) | `-AllUsers`, `-OutputDir` | User / Admin |
| [`CollectLocalDefenderAlerts.ps1`](./Acquisition/CollectLocalDefenderAlerts.ps1) | Queries local Defender detection history via `Get-MpThreatDetection` | Console | User / Admin |
| [`GenerateEvidenceManifest.ps1`](./Acquisition/GenerateEvidenceManifest.ps1) | Computes SHA-256 hashes for all evidence files and generates `manifest.json` for Chain of Custody | `-TargetDir`, `-OutputFile` | User / Admin |
| [`FolderToStorageBlob.ps1`](./Acquisition/FolderToStorageBlob.ps1) | Direct HTTPS upload of evidence directory to Azure Storage Blob via SAS token | SAS Token / Storage Account | Contributor |
| [`ExecuteKQLAdvancedHunting.ps1`](./Acquisition/ExecuteKQLAdvancedHunting.ps1) | Runs KQL queries against Microsoft Defender for Endpoint API via Graph (Interactive) | Inline `$KQL` | Graph API |
| [`ExecuteKQLAdvancedHuntingServicePrincipal.ps1`](./Acquisition/ExecuteKQLAdvancedHuntingServicePrincipal.ps1) | Runs KQL queries against Defender API using App Registration / Service Principal | `-TenantId`, `-ClientId`, `-ClientSecret` | Graph API |
| [`GetSecurityIncidents.ps1`](./Acquisition/GetSecurityIncidents.ps1) | Fetches active Microsoft Defender / Sentinel incidents via API | Graph API | Analyst |
| [`ZipFolder.ps1`](./Acquisition/ZipFolder.ps1) | Utility script to compress folders into ZIP archives | `-SourcePath`, `-DestinationZip` | User |
| *Browser Extractors* | Dedicated collectors for [Edge](./Acquisition/EdgeArtifacts.ps1), [Chrome/Chromium](./Acquisition/ChromiumArtifacts.ps1), [Brave](./Acquisition/BraveArtifacts.ps1), [Firefox](./Acquisition/FirefoxArtifacts.ps1), [Opera](./Acquisition/OperaArtifacts.ps1) | `-AllUsers`, `-OutputDir` | User / Admin |

---

### 2. Analysis & Threat Hunting (`Analysis/`)

| Script / Guide | Purpose | Output / Mode |
|:---|:---|:---|
| [`Generate-DFIRHtmlReport.ps1`](./Analysis/Generate-DFIRHtmlReport.ps1) | Generates an interactive standalone HTML Forensic Dashboard from collected CSVs/ZIP with KPI cards, search, sorting, and alerts | HTML Report (`-OpenReport`) |
| [`Get-NamedPipes.ps1`](./Analysis/Get-NamedPipes.ps1) | Enumerates Named Pipes & flags C2 patterns (*Cobalt Strike*, *Sliver*, *Meterpreter*, *PsExec*, *PAExec*) | Console / CSV (`-ExportCsv`) |
| [`Get-WMIPersistence.ps1`](./Analysis/Get-WMIPersistence.ps1) | Audits WMI subscriptions (`__EventFilter`, `CommandLineEventConsumer`, bindings) for fileless persistence | Console / CSV (`-ExportCsv`) |
| [`ListRootCertificates.ps1`](./Analysis/ListRootCertificates.ps1) | Audits LocalMachine and CurrentUser Root CA stores to detect rogue CA certificates or MitM inspection proxies | Console / CSV (`-ExportCsv`) |
| [`ListInstalledSecurityProducts.ps1`](./Analysis/ListInstalledSecurityProducts.ps1) | Discovers Antivirus, AntiSpyware, and Firewall products & their real-time state via `SecurityCenter2` | Console |
| [`ListDefenderExclusions.ps1`](./Analysis/ListDefenderExclusions.ps1) | Lists all configured Microsoft Defender path, extension, and process exclusions | Console |
| [`ListVSCodeExtensions.ps1`](./Analysis/ListVSCodeExtensions.ps1) | Audits installed VS Code & Cursor extensions across user profiles (`-AllUsers`) | Console |
| [`CollectPnPDevices.ps1`](./Analysis/CollectPnPDevices.ps1) | Lists connected and historical PnP/USB devices and hardware IDs | Console |
| [`DumpLocalAdmins.ps1`](./Analysis/DumpLocalAdmins.ps1) | Discovers all members of the local `Administrators` group | Console |
| [`LastLogons.ps1`](./Analysis/LastLogons.ps1) | Audits last user logon timestamps and interactive sessions | Console / CSV (`-ExportCsv`) |
| [`PrefetchFiles.ps1`](./Analysis/PrefetchFiles.ps1) | Lists prefetch files (`.pf`), execution timestamps, and run counts | Console / CSV (`-ExportCsv`) |
| [`RunMRUEntries.ps1`](./Analysis/RunMRUEntries.ps1) | Extracts Most Recently Used (`RunMRU`) registry entries | Console |
| [`ExportBrowserExtensions.ps1`](./Analysis/ExportBrowserExtensions.ps1) | Packages installed browser extensions from Chrome, Edge, Brave, and Opera into a ZIP file for analysis | ZIP File in `$env:TEMP` |
| [`DFIR-Commands.md`](./Analysis/DFIR-Commands.md) | Cheatsheet of standalone PowerShell commands and one-liners for live triage | Reference Guide |

---

### 3. Containment & Remediation (`Containment/`)

> ⚠️ Cloud containment scripts require the `Microsoft.Graph` module:  
> `Install-Module Microsoft.Graph -Scope CurrentUser -Repository PSGallery -Force`

| Script | Target | Action | Required Permissions |
|:---|:---|:---|:---|
| [`Invoke-FullIdentityContainment.ps1`](./Containment/Invoke-FullIdentityContainment.ps1) | **Entra ID / M365** | **Cloud Playbook**: Disable account, revoke sessions, reset password, purge rogue MFA (FIDO2, Authenticator, Phone, TAP), revoke OAuth grants | Graph: `User.ReadWrite.All`, `UserAuthenticationMethod.ReadWrite.All`, `DelegatedPermissionGrant.ReadWrite.All` |
| [`Isolate-Host.ps1`](./Containment/Isolate-Host.ps1) | **Host / Endpoint** | **Host Isolation**: Emergency firewall isolation (inbound/outbound with SOC whitelist), kill user processes, force session logoff, purge Kerberos tickets & credentials | **Local Administrator** |
| [`Revoke-ADUserHybrid.ps1`](./Containment/Revoke-ADUserHybrid.ps1) | **Active Directory** | **AD / Hybrid Playbook**: Disable AD account (RSAT / ADSI fallback), reset password, strip admin groups, move to Quarantine OU | **Domain Admin** |
| [`LocalUserResponse.ps1`](./Containment/LocalUserResponse.ps1) | Local Accounts | List accounts (`-List`), rotate password to random 20-char (`-Rotate <SID>`), kill user processes (`-Kill <SID>`), delete account (`-Delete <SID>`) | Local Administrator |
| [`RevokeSessions.ps1`](./Containment/RevokeSessions.ps1) | Entra ID / M365 | Instantly invalidates all active OAuth tokens and sign-in sessions for target users | Graph: `User.RevokeSessions.All` |
| [`ForcePasswordChangeNextSignIn.ps1`](./Containment/ForcePasswordChangeNextSignIn.ps1) | Entra ID / M365 | Generates temporary password & enforces reset on next sign-in | Graph: `UserAuthenticationMethod.ReadWrite.All` |

---

## 🛡️ Microsoft Defender for Endpoint (MDE) Live Response

All scripts are lightweight, dependency-free, and ready to run inside an **MDE Live Response** console.

### Prerequisites
1. Open **[security.microsoft.com](https://security.microsoft.com)** $\rightarrow$ **Settings** $\rightarrow$ **Endpoints** $\rightarrow$ **Advanced Features**.
2. Turn ON **Live Response** and **Live Response unsigned script execution**.

### Execution Steps
```text
1. Connect to device via Live Response.
2. Upload script:         putfile DFIR-Script.ps1
3. Execute triage:        run DFIR-Script.ps1 -parameters "-sw 10"
4. Download evidence:     getfile DFIR-<Hostname>-<Date>.zip
```

---

## 📊 SIEM Integration (CSV Schema)

The automated triage exports standard CSV files directly ingestible by **Microsoft Sentinel**, **Splunk**, **Elastic**, or **ADX**:

```text
CSV Results (SIEM Import Data)/
├── ActiveUsers.csv            ├── IPConfiguration.csv        ├── RunningServices.csv
├── AutoRun.csv                ├── LocalUsers.csv             ├── ScheduledTasks.csv
├── ConnectedDevices.csv       ├── NetworkShares.csv          ├── ScheduledTasksRunInfo.csv
├── DefenderExclusions.csv     ├── OfficeConnections.csv      ├── SecurityEvents.csv
├── DNSCache.csv               ├── OpenTCPConnections.csv     ├── ShadowCopy.csv
├── Drivers.csv                ├── PowerShellHistory.csv      └── SMBShares.csv
├── InstalledSoftware.csv      ├── Processes.csv
└── RDPSessions.csv            └── RemotelyOpenedFiles.csv
```

---

## 🔗 Related Resources

- [Incident Response Part 3: Leveraging Live Response](https://kqlquery.com/posts/leveraging-live-response/)
- [Incident Response PowerShell V2](https://kqlquery.com/posts/incident-response-powershell-v2/)
- [Microsoft Defender for Endpoint Live Response Docs](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/live-response)

---

## 📄 License

This project is licensed under the **[BSD 3-Clause License](./LICENSE)**.  
Copyright (c) 2026, Bert-Jan.
