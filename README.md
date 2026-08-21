# ⚡ DFIR PowerShell - Windows Incident Response & Digital Forensics

```text
  _____  ______ _____ _____    _____                         _____ _          _ _ 
 |  __ \|  ____|_   _|  __ \  |  __ \                       / ____| |        | | |
 | |  | | |__    | | | |__) | | |__) |____      _____ _ __ | (___ | |__   ___| | |
 | |  | |  __|   | | |  _  /  |  ___/ _ \ \ /\ / / _ \ '__| \___ \| '_ \ / _ \ | |
 | |__| | |     _| |_| | \ \  | |  | (_) \ V  V /  __/ |    ____) | | | |  __/ | |
 |_____/|_|    |_____|_|  \_\ |_|   \___/ \_/\_/ \___|_|   |_____/|_| |_|\___|_|_|
```

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%20%7C%207%2B-5391FE?logo=powershell&logoColor=white)](https://microsoft.com/PowerShell)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%20%7C%2011%20%7C%20Server-0078D6?logo=windows&logoColor=white)](https://microsoft.com/windows)
[![MDE Live Response](https://img.shields.io/badge/Defender%20Live%20Response-Supported-00A4EF?logo=microsoft)](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/live-response)
[![Forensics](https://img.shields.io/badge/Forensics-RFC%203227%20%7C%20Read--Only-blue)](https://www.ietf.org/rfc/rfc3227.txt)
[![Threat Intel](https://img.shields.io/badge/Threat%20Intel-STIX%202.1%20%7C%20MISP-orange)](https://oasis-open.github.io/cti-documentation/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Windows%20Matrix-red)](https://attack.mitre.org/matrices/enterprise/windows/)
[![License: BSD-3-Clause](https://img.shields.io/badge/License-BSD_3--Clause-blue.svg)](./LICENSE)

A comprehensive, modular suite of PowerShell scripts for **Digital Forensics & Incident Response (DFIR)**, **threat hunting**, **evidence acquisition**, **Active Directory & Cloud containment**, and **interactive HTML reporting** across Windows endpoints, Domain Controllers, and Microsoft 365 / Entra ID environments.

---

## 📋 Table of Contents

- [Overview & Philosophy](#-overview--philosophy)
- [Key Forensic Principles](#-key-forensic-principles)
- [Project Architecture](#-project-architecture)
- [Quick Start Guide](#-quick-start-guide)
- [Command Line Options](#-command-line-options)
- [Main Engine (`DFIR-Script.ps1`)](#-main-engine-dfir-scriptps1)
- [Script Catalog](#-script-catalog)
  - [1. Acquisition Modules (`Acquisition/`)](#1-acquisition-modules-acquisition)
  - [2. Analysis & Threat Hunting Modules (`Analysis/`)](#2-analysis--threat-hunting-modules-analysis)
  - [3. Containment & Remediation (`Containment/`)](#3-containment--remediation-containment)
- [Interactive Standalone HTML Forensic Dashboard](#-interactive-standalone-html-forensic-dashboard)
- [Microsoft Defender for Endpoint (MDE) Live Response](#-microsoft-defender-for-endpoint-mde-live-response)
- [SIEM Integration (CSV Schemas)](#-siem-integration-csv-schemas)
- [MITRE ATT&CK® Matrix for Windows & Cloud](#-mitre-attck-matrix-for-windows--cloud)
- [Chain of Custody & Forensic Best Practices](#-chain-of-custody--forensic-best-practices)
- [License & Attribution](#-license--attribution)

---

## 🔍 Overview & Philosophy

**DFIR PowerShell** is designed to provide incident responders, CERTs, and SOC analysts with a unified, lightweight, and dependency-free toolkit for Windows systems. 

It captures volatile in-memory evidence, extracts raw registry hives, dumps execution artifacts (Prefetch, SRUM, Amcache), audits Active Directory Domain Controllers, automates threat hunting, and generates standalone dark-mode HTML reports—all while strictly adhering to **RFC 3227 Order of Volatility** and **100% Read-Only** collection standards.

---

## 🛡️ Key Forensic Principles

1. **Order of Volatility (RFC 3227)**:
   - Prioritizes volatile system state: Network sockets & ARP/DNS cache $\rightarrow$ Process memory & execution proofs $\rightarrow$ Active user sessions $\rightarrow$ Event logs (EVTX) $\rightarrow$ Registry hives & Volume Shadow Copies (VSS).
2. **Forensic Soundness & Zero Footprint**:
   - Acquisition scripts execute in **Strict Read-Only Mode** without altering target configurations, services, or registry values.
   - Preserves filesystem MACB (Modified, Accessed, Created, Born) timestamps.
3. **Chain of Custody & Cryptographic Verification**:
   - Calculates **SHA-256 hashes** for every collected artifact, generating a machine-readable `manifest.json`.
   - Packages evidence into a secured `.zip` archive with metadata integrity verification.
4. **Hermetic Separation with Containment**:
   - Active containment playbooks (host network isolation, AD account quarantine, Entra ID session revocation, MFA purging) are strictly separated into `Containment/` and must be explicitly invoked by an authorized analyst.

---

## 🏛 Project Architecture

```text
DFIR_Powershell/
├── DFIR-Script.ps1              # Core automated triage engine (25+ indicators -> CSV & ZIP)
├── LICENSE                      # BSD 3-Clause License
├── README.md                    # Master documentation & MITRE ATT&CK mapping
│
├── Acquisition/                 # 26 Targeted Evidence Collectors (100% Read-Only)
│   ├── CollectAIArtifacts.ps1                  # AI & LLM desktop chats, configs, API keys (Claude, Cursor, Ollama)
│   ├── CollectActiveDirectoryArtifacts.ps1     # DC Forensics: NTDS.dit / BootKey, SYSVOL/GPOs, Kerberos attack surface
│   ├── CollectVPNAndSockets.ps1               # Live TCP/UDP sockets mapped to process commands + VPN configs
│   ├── CollectSSHArtifacts.ps1                 # Lateral movement: OpenSSH, PuTTY, WinSCP, MobaXterm sessions & keys
│   ├── CollectExecutionArtifacts.ps1          # Execution proof: Prefetch (.pf), SRUM (SRUDB.dat), BAM/DAM, Amcache
│   ├── CollectTargetedEvtxLogs.ps1            # Critical EVTX logs (Sysmon, PowerShell 4104, TaskScheduler, RDP)
│   ├── CollectWindowsEvents.ps1                # Dumps Windows Event Log entries within a configured time window
│   ├── CollectWindowsSecurityEvents.ps1        # Security logs (Logons 4624/4625, Process Creation 4688, User Mgmt)
│   ├── DumpRegistryHives.ps1                  # Raw Registry Hives (SAM, SYSTEM, SECURITY, SOFTWARE, NTUSER.DAT)
│   ├── CollectUserActivity.ps1                 # LNK shortcuts, Jump Lists (AutomaticDestinations), Recent files
│   ├── CollectNetworkTriage.ps1                # Volatile network state: DNS cache, ARP tables, IP routes, SMB sessions
│   ├── CollectPSReadLineHistory.ps1            # ConsoleHost_history.txt across all user profiles
│   ├── CollectRDPArtifacts.ps1                 # RDP client credential hints, Bitmap caches (bcache*.bmc), TS logs
│   ├── CollectBrowserArtifacts.ps1             # Unified browser collector (Edge, Chrome, Brave, Firefox, Opera)
│   ├── CollectLocalDefenderAlerts.ps1          # Queries local Defender detection history (Get-MpThreatDetection)
│   ├── GenerateEvidenceManifest.ps1            # Computes SHA-256 hashes and generates manifest.json for Chain of Custody
│   ├── FolderToStorageBlob.ps1                 # Direct HTTPS upload of evidence directory to Azure Storage via SAS
│   ├── ExecuteKQLAdvancedHunting.ps1           # Runs KQL queries against Defender for Endpoint API (Interactive)
│   ├── ExecuteKQLAdvancedHuntingServicePrincipal.ps1 # Runs KQL queries using Service Principal / App Registration
│   ├── GetSecurityIncidents.ps1                # Fetches active Microsoft Defender / Sentinel incidents via API
│   ├── ZipFolder.ps1                           # Compresses evidence folder into ZIP archive
│   └── Browser Extractors                      # EdgeArtifacts, ChromiumArtifacts, BraveArtifacts, FirefoxArtifacts, OperaArtifacts
│
├── Analysis/                    # 15 Threat Hunting, Persistence & Reporting Scripts
│   ├── Generate-DFIRHtmlReport.ps1             # Standalone dark-mode HTML Forensic Dashboard with KPI cards & alerts
│   ├── Get-NamedPipes.ps1                      # Enumerates Named Pipes & flags C2 patterns (Cobalt Strike, Sliver, Meterpreter)
│   ├── Get-WMIPersistence.ps1                  # Audits WMI subscriptions (__EventFilter, CommandLineEventConsumer)
│   ├── ListRootCertificates.ps1                # Audits Root CA stores to detect rogue CA certificates / MitM proxies
│   ├── ListInstalledSecurityProducts.ps1       # Discovers AV, AntiSpyware, Firewall products & state via SecurityCenter2
│   ├── ListDefenderExclusions.ps1              # Lists configured Defender path, extension, and process exclusions
│   ├── ListVSCodeExtensions.ps1                # Audits installed VS Code & Cursor extensions across user profiles
│   ├── CollectPnPDevices.ps1                   # Connected & historical PnP/USB devices and hardware IDs
│   ├── DumpLocalAdmins.ps1                     # Discovers all members of the local Administrators group
│   ├── LastLogons.ps1                          # Audits last user logon timestamps and interactive sessions
│   ├── PrefetchFiles.ps1                       # Lists prefetch files (.pf), execution timestamps, and run counts
│   ├── RunMRUEntries.ps1                       # Extracts Most Recently Used (RunMRU) registry entries
│   ├── ExportBrowserExtensions.ps1             # Packages installed browser extensions into a ZIP for analysis
│   └── DFIR-Commands.md                        # Cheatsheet of standalone PowerShell one-liners for live triage
│
└── Containment/                 # 6 Host, Active Directory & Cloud Remediation Scripts
    ├── Invoke-FullIdentityContainment.ps1      # Cloud Playbook: Disable account, revoke sessions, reset PW, purge rogue MFA, OAuth
    ├── Isolate-Host.ps1                        # Host Isolation: Firewall isolation (in/out + SOC whitelist), kill user procs, logoff
    ├── Revoke-ADUserHybrid.ps1                 # AD / Hybrid Playbook: Disable AD account, reset PW, strip admin groups, Quarantine OU
    ├── LocalUserResponse.ps1                   # Local accounts: Rotate password (-Rotate), kill procs (-Kill), delete (-Delete)
    ├── RevokeSessions.ps1                      # Instantly invalidates all active OAuth tokens & sign-in sessions in Entra ID
    └── ForcePasswordChangeNextSignIn.ps1       # Generates temporary password & enforces reset on next sign-in
```

---

## ⚡ Quick Start Guide

### 1. Automated Full Triage (`DFIR-Script.ps1`)

```powershell
# Automated Full Triage (Default: last 2 days of security events)
.\DFIR-Script.ps1

# Automated Triage with custom event search window (e.g., last 10 days)
.\DFIR-Script.ps1 -sw 10

# Bypass execution policy if running in restricted environments
PowerShell.exe -ExecutionPolicy Bypass -File .\DFIR-Script.ps1 -sw 7
```

> 📁 Triage evidence is saved in `DFIR-<Hostname>-<Date>/` and automatically archived into a sealed `.zip`.

### 2. Generate Interactive HTML Forensic Report (`Generate-DFIRHtmlReport.ps1`)

```powershell
# Automatically detects the latest DFIR-* output folder and opens the HTML dashboard
.\Analysis\Generate-DFIRHtmlReport.ps1 -OpenReport

# Generate report from a specific evidence folder or ZIP archive
.\Analysis\Generate-DFIRHtmlReport.ps1 -EvidencePath ".\DFIR-HOST-2026-08-21" -OpenReport
.\Analysis\Generate-DFIRHtmlReport.ps1 -EvidencePath ".\DFIR-HOST-2026-08-21.zip" -OutputFile "Report.html" -OpenReport
```

---

## ⚙️ Command Line Options

| Parameter | Type | Description | Default |
|---|---|---|---|
| `-sw <days>` | Integer | Security event log search window in days | `2` |
| `-AllUsers` | Switch | Iterates across all user profiles on disk | `$false` |
| `-OutputDir <path>` | String | Custom output directory for collected artifacts | `./DFIR-<Host>-<Date>` |
| `-OpenReport` | Switch | Automatically opens generated HTML report in default browser | `$false` |
| `-ExportCsv` | Switch | Exports analysis findings to normalized CSV | `$false` |

---

## 🛠️ Main Engine (`DFIR-Script.ps1`)

The all-in-one triage engine collects forensic indicators across multiple dimensions, generates **SIEM-ready CSV files** in `CSV Results (SIEM Import Data)\`, and archives the entire output folder.

### Collected Artifacts

| Category | Standard User | Administrator (Elevated) |
|:---|:---|:---|
| **Identity & Users** | Active Users, Local Users | Full Registry Hives (`SAM`, `SYSTEM`, `SECURITY`, `SOFTWARE`, `NTUSER.DAT`) |
| **Execution & History** | PSReadLine History (Current User), Run Keys, Startup Folder | PSReadLine History (All Users), Prefetch (`.pf`), Amcache, SRUM |
| **Network & Comms** | Open TCP/UDP Connections, DNS Cache, Active SMB Shares, Office URLs | Remotely Opened Files (SMB sessions), Promiscuous interfaces |
| **System & Persistence** | Running Services, Scheduled Tasks, Installed Drivers, Software List | Volume Shadow Copies (`VSS`), WMI Event Subscriptions |
| **Security & Logs** | Active USB / PnP Devices, RDP Sessions | Windows Security Events (Logons 4624/4625, Process Creation 4688, MPLogs) |
| **Browsers & AI** | Chrome, Edge, Brave, Firefox History, Claude / Cursor / Ollama configs | System-wide browser profiles, Token presence in environment |

---

## 📦 Script Catalog

### 1. Acquisition Modules (`Acquisition/`)

| Script | Purpose | Key Parameters | Privilege |
|:---|:---|:---|:---|
| [`CollectAIArtifacts.ps1`](./Acquisition/CollectAIArtifacts.ps1) | Extracts AI/LLM desktop chat history, configs, API keys (Claude, ChatGPT, Cursor, Windsurf, Copilot, Ollama, Jan, LM Studio) | `-AllUsers`, `-OutputDir`, `-ExcludeModels` | User / Admin |
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
| *Browser Extractors* | Dedicated collectors for [Edge](./Acquisition/EdgeArtifacts.ps1), [Chromium](./Acquisition/ChromiumArtifacts.ps1), [Brave](./Acquisition/BraveArtifacts.ps1), [Firefox](./Acquisition/FirefoxArtifacts.ps1), [Opera](./Acquisition/OperaArtifacts.ps1) | `-AllUsers`, `-OutputDir` | User / Admin |

---

### 2. Analysis & Threat Hunting Modules (`Analysis/`)

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

> ⚠️ Cloud containment scripts require the `Microsoft.Graph` PowerShell module:  
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

All scripts are lightweight, dependency-free, and ready to execute inside an **MDE Live Response** console.

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

## 📊 SIEM Integration (CSV Schemas)

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

## 🛡 MITRE ATT&CK® Matrix for Windows & Cloud

| MITRE ATT&CK Tactic | Covered Techniques | Associated Modules |
|---|---|---|
| **Initial Access (TA0001)** | T1078 (Valid Accounts), T1133 (External Remote Services), T1190 (Exploit Public-Facing App), T1566 (Phishing) | `CollectSSHArtifacts.ps1`, `CollectUserActivity.ps1`, `CollectVPNAndSockets.ps1` |
| **Execution (TA0002)** | T1059.001 (PowerShell), T1047 (WMI), T1053.005 (Scheduled Task), T1569.002 (Service Execution) | `CollectExecutionArtifacts.ps1`, `CollectPSReadLineHistory.ps1`, `Get-WMIPersistence.ps1` |
| **Persistence (TA0003)** | T1547.001 (Registry Run Keys), T1543.003 (Windows Service), T1546.003 (WMI Subscriptions), T1053.005 (Scheduled Task) | `Get-WMIPersistence.ps1`, `CollectExecutionArtifacts.ps1`, `DFIR-Script.ps1` |
| **Privilege Escalation (TA0004)** | T1078.002 (Domain Accounts), T1548 (Abuse Elevation), T1068 (Priv Esc Exploitation) | `CollectActiveDirectoryArtifacts.ps1`, `DumpLocalAdmins.ps1` |
| **Defense Evasion (TA0005)** | T1562.001 (Disable Defender / Exclusions), T1070 (Indicator Removal), T1553.004 (Install Root CA) | `ListDefenderExclusions.ps1`, `ListRootCertificates.ps1`, `CollectTargetedEvtxLogs.ps1` |
| **Credential Access (TA0006)** | T1003.002 (SAM Dump), T1003.003 (NTDS.dit), T1558 (Kerberoasting / AS-REP), T1555 (Credentials in Files) | `DumpRegistryHives.ps1`, `CollectActiveDirectoryArtifacts.ps1`, `CollectAIArtifacts.ps1` |
| **Discovery (TA0007)** | T1082 (System Info), T1049 (Network Connections), T1057 (Process Discovery), T1018 (Remote System Discovery) | `CollectNetworkTriage.ps1`, `Get-NamedPipes.ps1`, `CollectPnPDevices.ps1` |
| **Lateral Movement (TA0008)** | T1021.001 (RDP), T1021.002 (SMB/Windows Admin Shares), T1021.004 (SSH) | `CollectRDPArtifacts.ps1`, `CollectSSHArtifacts.ps1`, `CollectVPNAndSockets.ps1` |
| **Command and Control (TA0011)** | T1071 (Application Layer Protocol), T1571 (Non-Standard Port), T1090 (Proxy), T1572 (Protocol Tunneling) | `Get-NamedPipes.ps1`, `CollectVPNAndSockets.ps1` |

---

## 🔒 Chain of Custody & Forensic Best Practices

1. **Execute from External Storage**: Run scripts and write evidence to an external drive (`-OutputDir E:\Evidence`) to prevent overwriting unallocated disk clusters.
2. **Preserve Volatile Memory First**: Capture memory, network sockets, and process state before acquiring persistent event logs.
3. **Validate Cryptographic Seals**: Maintain the generated `manifest.json` and `.zip` SHA-256 hashes to establish proof of evidence integrity for judicial admissibility.
4. **Use Containment with Discretion**: Active remediation (`Invoke-FullIdentityContainment.ps1`, `Isolate-Host.ps1`) should only be executed once initial volatile evidence has been acquired.

---

## 📄 License & Attribution

This project is licensed under the **[BSD 3-Clause License](./LICENSE)**.  
Copyright (c) 2026, **Bellk0ruh** & contributors. All rights reserved.
