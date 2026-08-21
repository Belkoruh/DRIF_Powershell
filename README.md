# DFIR Bash - Linux Incident Response & Digital Forensics

[![Bash](https://img.shields.io/badge/Bash-4.0%2B-4EAA25?logo=gnu-bash&logoColor=white)](https://www.gnu.org/software/bash/)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Servers%20%7C%20Workstations-FCC624?logo=linux&logoColor=black)](https://kernel.org)
[![Forensics](https://img.shields.io/badge/Forensics-RFC%203227%20%7C%20Read--Only-blue)](https://www.ietf.org/rfc/rfc3227.txt)
[![Threat Intel](https://img.shields.io/badge/Threat%20Intel-STIX%202.1%20%7C%20MISP-orange)](https://oasis-open.github.io/cti-documentation/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Linux%20Matrix-red)](https://attack.mitre.org/matrices/enterprise/linux/)
[![License: BSD-3-Clause](https://img.shields.io/badge/License-BSD_3--Clause-blue.svg)](./LICENSE)

A comprehensive, modular suite of Bash scripts for **Digital Forensics & Incident Response (DFIR)**, **threat hunting**, **evidence acquisition**, **live auditing**, **emergency containment**, and **interactive HTML reporting** on Linux endpoints, Cloud instances (AWS, Azure, GCP), and enterprise servers.

---

## ⚡ Quick Start

### 1. Automated Host Triage (`DFIR-Script.sh`)

```bash
# Automated Full Triage (Default: last 2 days of security events & system logs)
sudo ./DFIR-Script.sh

# Automated Triage with custom search window (e.g., last 7 days) and auto-compression
sudo ./DFIR-Script.sh -w 7 -c

# Zero-Footprint best practice: Save evidence directly to an external USB or mount
sudo ./DFIR-Script.sh -o /mnt/evidence_usb/case_001 -c

# Targeted triage (e.g., Cloud, eBPF, Network, and Process artifacts only)
sudo ./DFIR-Script.sh -m cloud,ebpf,network,process,security
```

> 📁 Evidence is saved into `DFIR-<Hostname>-<YYYY-MM-DD_HHMMSS>/` with normalized CSVs, raw artifacts, SHA-256 manifest, and sealed `.tar.gz` archive.

### 2. Generate Interactive HTML Forensic Report (`Generate-DFIRHtmlReport.sh`)

```bash
# Automatically detects the latest DFIR evidence folder and compiles the standalone HTML dashboard
./Analysis/Generate-DFIRHtmlReport.sh

# Generate report from a specific evidence folder
./Analysis/Generate-DFIRHtmlReport.sh "./DFIR-srv-prod-2026-08-22_010000" "Report.html"
```

### 3. Generate STIX 2.1 Threat Intel Bundle (`Generate-STIXReport.sh`)

```bash
# Extracts IOCs (hashes, C2 IPs, malicious commands) into STIX 2.1 JSON and MISP/OpenCTI CSV
./Analysis/Generate-STIXReport.sh "./DFIR-srv-prod-2026-08-22_010000"
```

---

## 📁 Repository Structure

```text
DFIR_bash/
├── DFIR-Script.sh              # Core automated triage engine (RFC 3227 order of volatility)
├── Acquisition/                 # Targeted forensic collectors (18 scripts - 100% Read-Only)
├── Analysis/                    # Threat hunting, MACB timeline, STIX 2.1 & HTML dashboard (11 scripts)
├── Containment/                 # Emergency network isolation & live response playbooks (6 scripts)
├── LICENSE                      # BSD 3-Clause License
└── README.md                    # Documentation & complete script catalog
```

---

## 🛠️ Main Engine: `DFIR-Script.sh`

The all-in-one triage engine collects forensic indicators across multiple dimensions, generates **SIEM-ready CSV files** in `CSV_Results/`, computes a cryptographic **SHA-256 manifest**, and compiles an interactive HTML dashboard.

### Collected Artifacts

| Category | Standard User | Elevated Privileges (Root / Sudo) |
|:---|:---|:---|
| **Identity & Users** | Current user environment, Shell histories (`.bash_history`, `.zsh_history`), Active sessions (`utmp`) | Full `/etc/shadow` hash audit, Sudoers NOPASSWD rules, Login history (`wtmp`, `btmp`) |
| **Execution & Memory** | Userland process tree (`ps`), current user `/proc/[pid]/environ` | Complete `/proc` maps, `memfd_create` detection, **deleted running ELF binary quarantine** |
| **Network & Comms** | Active sockets, TCP/UDP endpoints (`ss`/`netstat`), DNS resolvers | Promiscuous interfaces, Raw sockets, ARP tables, Firewall rules (`iptables`/`nftables`) |
| **Kernel & Stealth** | `/proc/sys/kernel/tainted` read | Loaded LKMs (`lsmod`), eBPF filters (`bpftool`), `/proc` vs `ps` hidden process audit |
| **Security Subsystems** | AppArmor / SELinux user status | AppArmor profile denials (`apparmor="DENIED"`), SELinux AVCs (`type=AVC`), Kernel mitigations |
| **Cloud & Tunnels** | Tailscale/WireGuard user configs | AWS IMDSv2, Azure & GCP metadata, Cloud-Init logs, Chisel/Ngrok/Ligolo-ng reverse proxies |
| **Dev Ecosystem & AI** | User NPM/PyPI tokens, AI chat histories (Claude, Cursor, Ollama) | Global Git hooks (`core.hooksPath`), Python `.pth` injection files, System mail queues |

---

## 📦 Script Catalog

### 1. Acquisition (`Acquisition/`)

| Script | Purpose | Key Parameters | Privilege |
|:---|:---|:---|:---|
| [`CollectNetworkTriage.sh`](./Acquisition/CollectNetworkTriage.sh) | Sockets (`ss`, `lsof`), active connections, routing tables, ARP cache, DNS resolvers, firewall rules, and eBPF filters | `$1` (TargetDir) | User / Root |
| [`CollectExecutionArtifacts.sh`](./Acquisition/CollectExecutionArtifacts.sh) | Process trees, `/proc/[pid]/*`, cmdline, environ, memory maps, `memfd_create`, and **quarantine of deleted running binaries** | `$1` (TargetDir) | **Root** |
| [`CollectPersistence.sh`](./Acquisition/CollectPersistence.sh) | Systemd services & timers, Crontabs, At jobs, `/etc/ld.so.preload` hijacking, shell hooks (`.bashrc`, `profile.d`), PAM, Udev | `$1` (TargetDir) | User / Root |
| [`CollectUserActivity.sh`](./Acquisition/CollectUserActivity.sh) | Account audit, `/etc/shadow` hashes, sudoers rules, active sessions (`utmp`), `wtmp`/`btmp`, and shell command histories | `$1` (TargetDir) | **Root** |
| [`CollectSSHArtifacts.sh`](./Acquisition/CollectSSHArtifacts.sh) | `authorized_keys`, `known_hosts`, OpenSSH server/client configs, private/public key inventory, and active SSH sessions | `$1` (TargetDir) | User / Root |
| [`CollectBrowserArtifacts.sh`](./Acquisition/CollectBrowserArtifacts.sh) | Unified browser collector: SQLite histories, downloads, extensions for Chrome, Chromium, Firefox, Brave, Edge, Opera, Tor | `$1` (TargetDir) | User / Root |
| [`CollectAIArtifacts.sh`](./Acquisition/CollectAIArtifacts.sh) | AI & LLM forensics: Ollama models, Claude Desktop/Code, Cursor, Windsurf, Copilot, LM Studio, Aider, API tokens | `$1` (TargetDir) | User / Root |
| [`CollectSystemLogs.sh`](./Acquisition/CollectSystemLogs.sh) | Systemd journal (`journalctl`) with time-window filtering, `auth.log`, `audit.log`, `dmesg`, syslog, and web server logs | `$1` (TargetDir), `$2` (Days) | **Root** |
| [`CollectSecuritySubsystems.sh`](./Acquisition/CollectSecuritySubsystems.sh) | AppArmor status & denials, SELinux status, AVC denials (`type=AVC`), booleans, and kernel mitigations (ASLR, Yama, Seccomp) | `$1` (TargetDir) | **Root** |
| [`CollectHardwareAndContainers.sh`](./Acquisition/CollectHardwareAndContainers.sh) | Connected USB devices (`lsusb`), PCI (`lspci`), mount points (`fstab`), Docker, Podman, Kubernetes pods, and coredumps | `$1` (TargetDir) | User / Root |
| [`CollectVPNAndTunnelingArtifacts.sh`](./Acquisition/CollectVPNAndTunnelingArtifacts.sh) | WireGuard, OpenVPN, Tailscale, ZeroTier, Cloudflare Tunnel, Ngrok, Chisel, FRP, Ligolo-ng, and IPsec policies | `$1` (TargetDir) | User / Root |
| [`CollectCloudMetadata.sh`](./Acquisition/CollectCloudMetadata.sh) | Cloud instance identity & IAM credentials: AWS EC2 (IMDSv2), Azure VM IMDS, GCP metadata, Cloud-Init logs | `$1` (TargetDir) | User / Root |
| [`CollectWebserverAndDatabaseArtifacts.sh`](./Acquisition/CollectWebserverAndDatabaseArtifacts.sh) | Configurations, SSL certs, `.htaccess`, Nginx, Apache, **Redis unauthenticated public binding check**, MySQL, PostgreSQL | `$1` (TargetDir) | **Root** |
| [`CollectEBPFArtifacts.sh`](./Acquisition/CollectEBPFArtifacts.sh) | Loaded eBPF programs, maps, attached links, XDP, kprobes, tracepoints, `/sys/fs/bpf` objects (Symbiote, BPFDoor detection) | `$1` (TargetDir) | **Root** |
| [`CollectDeveloperEcosystem.sh`](./Acquisition/CollectDeveloperEcosystem.sh) | Supply chain secrets: NPM (`.npmrc`), Python (`.pypirc`, `.pth` hooks), Cargo credentials, Git global hooks, tokens | `$1` (TargetDir) | User / Root |
| [`CollectMailArtifacts.sh`](./Acquisition/CollectMailArtifacts.sh) | Mail transport agents (Postfix, Exim, Sendmail), active queues (`mailq`), spools, and `/etc/aliases` pipe injection audits | `$1` (TargetDir) | User / Root |
| [`CollectDesktopArtifacts.sh`](./Acquisition/CollectDesktopArtifacts.sh) | Workstation forensics: `recently-used.xbel`, Linux Trash can files/metadata (`~/.local/share/Trash`), thumbnails, keyloggers | `$1` (TargetDir) | User / Root |
| [`DumpProcessMemory.sh`](./Acquisition/DumpProcessMemory.sh) | Surgical memory dumper for suspect PIDs via `/proc/[pid]/mem` and `/proc/[pid]/maps` or `gcore` | `$1` (PID), `$2` (TargetDir) | **Root** |
| [`CollectFileSystemArtifacts.sh`](./Acquisition/CollectFileSystemArtifacts.sh) | SUID/SGID binaries (GTFOBins audit), POSIX capabilities (`getcap`), `/tmp` staging files, hidden files, immutable flags (`+i`) | `$1` (TargetDir), `$2` (Days) | **Root** |
| [`CollectRootkitIndicators.sh`](./Acquisition/CollectRootkitIndicators.sh) | LKM audit (out-of-tree `O`/unsigned `E`), kernel taint decode, hidden process detection (`/proc` vs `ps`), rootkit signatures | `$1` (TargetDir) | **Root** |
| [`GenerateEvidenceManifest.sh`](./Acquisition/GenerateEvidenceManifest.sh) | Calculates SHA-256 hashes for all evidence files, generating `manifest.json` and `checksums.sha256` for Chain of Custody | `$1` (TargetDir) | User / Root |
| [`ArchiveFolder.sh`](./Acquisition/ArchiveFolder.sh) | Forensic `.tar.gz` compression with strict timestamp preservation (`--atime-preserve`) and detached `.sha256` seal | `$1` (TargetDir), `$2` (Archive) | User / Root |

---

### 2. Analysis & Threat Hunting (`Analysis/`)

| Script / Guide | Purpose | Output / Mode |
|:---|:---|:---|
| [`Generate-DFIRHtmlReport.sh`](./Analysis/Generate-DFIRHtmlReport.sh) | Generates an interactive standalone HTML Forensic Dashboard from collected CSVs with metric cards, search, and alerts | HTML Report (`Report.html`) |
| [`Generate-MACTimeline.sh`](./Analysis/Generate-MACTimeline.sh) | Generates a SleuthKit Bodyfile and supertimeline capturing Modified, Accessed, Changed, and Birth (MACB) timestamps | Bodyfile & CSV Timeline |
| [`Generate-STIXReport.sh`](./Analysis/Generate-STIXReport.sh) | Converts collected indicators (hashes, C2 IPs, suspicious commands) into a **STIX 2.1 JSON Bundle** and MISP/OpenCTI CSV | JSON Bundle & CSV Feed |
| [`DetectCryptominers.sh`](./Analysis/DetectCryptominers.sh) | Hunts for illicit miners: Stratum protocol connections (3333, 4444, etc.), fake `[kworker]` CPU hogs, and mining configs | Console / CSV (`-ExportCsv`) |
| [`DetectLogTampering.sh`](./Analysis/DetectLogTampering.sh) | Anti-forensics detector: unlinked deleted logs held open in RAM (`/proc/*/fd`), truncated `wtmp`/`btmp`, `HISTFILE=/dev/null` | Console / CSV (`-ExportCsv`) |
| [`DumpPrivilegedUsers.sh`](./Analysis/DumpPrivilegedUsers.sh) | Audits UID 0 accounts, administrative group members (sudo, wheel), `NOPASSWD` rules, and passwordless shadow accounts | Console / CSV (`-ExportCsv`) |
| [`ListCronAndTimers.sh`](./Analysis/ListCronAndTimers.sh) | Consolidated tabular overview of all scheduled tasks (Systemd timers, crontabs, user cron, at jobs) | Console / CSV (`-ExportCsv`) |
| [`ListNetworkListeners.sh`](./Analysis/ListNetworkListeners.sh) | Triage of listening ports with process names, PIDs, executable paths, and public exposure highlights | Console / CSV (`-ExportCsv`) |
| [`ListPackageIntegrity.sh`](./Analysis/ListPackageIntegrity.sh) | Verifies cryptographic package checksums of key system binaries (`dpkg -V` / `rpm -Va` / `pacman -Qk`) | Console / CSV (`-ExportCsv`) |
| [`ListKernelModules.sh`](./Analysis/ListKernelModules.sh) | Audits loaded kernel modules from `/proc/modules` and flags out-of-tree (`O`) or unsigned (`E`) LKMs | Console / CSV (`-ExportCsv`) |
| [`ScanSuspiciousStaging.sh`](./Analysis/ScanSuspiciousStaging.sh) | Rapid scanner for world-writable staging directories (`/tmp`, `/dev/shm`) to detect ELF binaries, webshells, reverse shells | Console / CSV (`-ExportCsv`) |

---

### 3. Containment & Remediation (`Containment/`)

| Script | Target | Action | Required Permissions |
|:---|:---|:---|:---|
| [`Isolate-Host.sh`](./Containment/Isolate-Host.sh) | **Host / Network** | **Host Isolation**: Emergency firewall isolation (`DROP all`) with SOC whitelist (`--allowed-ips`) and clean release (`--release`) | **Root** |
| [`Kill-C2Threat.sh`](./Containment/Kill-C2Threat.sh) | **Processes & C2** | **Surgical Neutralization**: Terminates specific PIDs, blocks remote C2 IP in iptables, and quarantines malware binary | **Root** |
| [`QuarantineArtifact.sh`](./Containment/QuarantineArtifact.sh) | **Malware / Files** | **Zero-Permission Isolation**: Moves file to `/var/dfir_quarantine`, strips perms (`chmod 000`), sets `chattr +i`, computes SHA-256 seal | **Root** |
| [`EnableForensicAuditing.sh`](./Containment/EnableForensicAuditing.sh) | **Kernel Auditing** | **Live Audit Rule Injection**: Deploys high-resolution Auditd rules in RAM (execve, /etc, kmods, ptrace) without reboot | **Root** |
| [`LocalUserResponse.sh`](./Containment/LocalUserResponse.sh) | **Compromised User** | **User Containment**: Locks password, expires account, disables shell to `/sbin/nologin`, quarantines SSH keys, kills processes | **Root** |
| [`RevokeSessions.sh`](./Containment/RevokeSessions.sh) | **Active Sessions** | **Session Teardown**: Forcefully closes all remote interactive sessions (`pts/*`) and purges Kerberos ticket caches | **Root** |

---

## 🛡️ Remote Live Response Execution

All scripts are dependency-free, POSIX-compliant, and ready to execute across SSH, Ansible, Salt, or cloud bastions.

### Execution Steps
```text
1. Connect to remote host:     ssh root@target-host
2. Transfer DFIR suite:        scp -r DFIR_bash/ root@target-host:/tmp/
3. Execute automated triage:   sudo /tmp/DFIR_bash/DFIR-Script.sh -w 7 -c
4. Download sealed evidence:   scp root@target-host:/tmp/DFIR-*.tar.gz ./
```

---

## 📊 SIEM Integration (CSV Schema)

The automated triage exports standard CSV files directly ingestible by **Splunk**, **Microsoft Sentinel**, **Elasticsearch**, or **Wazuh**:

```text
CSV_Results (SIEM Import Data)/
├── ActiveSessions.csv             ├── FileCapabilities.csv          ├── RouteTable.csv
├── AITokenPresence.csv            ├── HiddenProcessAudit.csv        ├── ScheduledTasks.csv
├── AIToolsDetected.csv            ├── KernelModulesAudit.csv        ├── SecurityEvents.csv
├── AppArmorDenials.csv            ├── LocalUsers.csv                ├── SELinuxDenials.csv
├── ARPTable.csv                   ├── LoginHistory.csv              ├── ShellHooks.csv
├── BrowserDownloads.csv           ├── MACSubsystems.csv             ├── SSHAuthorizedKeys.csv
├── BrowserExtensions.csv          ├── MailArtifacts.csv             ├── SSHKnownHosts.csv
├── BrowserHistory.csv             ├── MemfdExecutions.csv           ├── StagingFiles.csv
├── CommandHistory.csv             ├── MountPoints.csv               ├── SUIDBinaries.csv
├── ConnectedDevices.csv           ├── NetworkInterfaces.csv         ├── SystemCoredumps.csv
├── Containers.csv                 ├── OpenSockets.csv               ├── TrashArtifacts.csv
├── DeletedRunningBinaries.csv     ├── PersistenceSummary.csv        └── TunnelingArtifacts.csv
├── DeveloperEcosystem.csv         ├── Processes.csv                 └── WebAndDatabaseServers.csv
└── EBPFPrograms.csv               └── RecentFiles.csv               └── RootkitIndicators.csv
```

---

## 🛡 MITRE ATT&CK® Matrix for Linux

| MITRE ATT&CK Tactic | Covered Techniques | Associated Modules |
|---|---|---|
| **Initial Access (TA0001)** | T1078 (Valid Accounts), T1133 (External Remote Services), T1190 (Exploit Public App), T1195 (Supply Chain) | `CollectSSHArtifacts.sh`, `CollectUserActivity.sh`, `CollectWebserverAndDatabaseArtifacts.sh`, `CollectDeveloperEcosystem.sh` |
| **Execution (TA0002)** | T1059 (Command & Scripting Interpreter), T1053 (Scheduled Task/Job), T1610 (Deploy Container) | `CollectExecutionArtifacts.sh`, `CollectPersistence.sh`, `CollectHardwareAndContainers.sh` |
| **Persistence (TA0003)** | T1543.002 (Systemd Service), T1053.003 (Cron), T1546.004 (.bashrc), T1574.006 (LD_PRELOAD), T1546.014 (eBPF) | `CollectPersistence.sh`, `CollectRootkitIndicators.sh`, `CollectEBPFArtifacts.sh` |
| **Privilege Escalation (TA0004)** | T1548.001 (Setuid/Setgid), T1548.003 (Sudoers), T1068 (Priv Esc Exploitation), T1611 (Escape to Host) | `CollectFileSystemArtifacts.sh`, `DumpPrivilegedUsers.sh`, `CollectHardwareAndContainers.sh` |
| **Defense Evasion (TA0005)** | T1070 (Indicator Removal), T1014 (Rootkit), T1620 (memfd_create), T1562.001 (Disable Tools), T1574.007 (eBPF rootkit) | `CollectRootkitIndicators.sh`, `CollectExecutionArtifacts.sh`, `CollectSecuritySubsystems.sh`, `DetectLogTampering.sh`, `CollectEBPFArtifacts.sh` |
| **Credential Access (TA0006)** | T1003.008 (/etc/passwd and /etc/shadow), T1552.004 (Private Keys), T1552.005 (Cloud IMDS), T1555 (Credentials in Files) | `CollectUserActivity.sh`, `CollectSSHArtifacts.sh`, `CollectCloudMetadata.sh`, `CollectDeveloperEcosystem.sh`, `CollectAIArtifacts.sh` |
| **Discovery (TA0007)** | T1082 (System Info), T1049 (Network Connections), T1057 (Process Discovery), T1613 (Container Discovery) | `CollectNetworkTriage.sh`, `CollectExecutionArtifacts.sh`, `CollectHardwareAndContainers.sh` |
| **Command and Control (TA0011)** | T1071 (Application Layer Protocol), T1571 (Non-Standard Port), T1572 (Protocol Tunneling), T1090 (Proxy) | `CollectNetworkTriage.sh`, `CollectVPNAndTunnelingArtifacts.sh`, `ListNetworkListeners.sh` |
| **Impact (TA0040)** | T1496 (Resource Hijacking / Cryptomining) | `DetectCryptominers.sh` |

---

## 🔒 Chain of Custody & Best Practices

1. **Execute from External Storage**: Point output to an external mount (`-o /mnt/external_drive`) to prevent altering unallocated space on the target host.
2. **Never Reboot**: Do not restart the compromised system before capturing volatile memory artifacts (`/proc`, open sockets, eBPF maps, memory dumps).
3. **Preserve Checksums & Digital Seals**: Retain the `checksums.sha256` and `.tar.gz.sha256` files for legal admissibility.
4. **Use Strict Containment with Caution**: Emergency containment scripts (`Isolate-Host.sh`, `Kill-C2Threat.sh`, `LocalUserResponse.sh`) alter system state; ensure initial volatile memory collection is completed prior to triggering active containment.

---

## 📄 License

This project is licensed under the **[BSD 3-Clause License](./LICENSE)**.  
Copyright (c) 2026, [Bellk0ruh](https://github.com/Bellk0ruh). All rights reserved.
