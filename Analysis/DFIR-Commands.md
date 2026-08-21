# PowerShell Incident Response Commands

# Connections

### All Open Connections
```PowerShell
Get-NetTCPConnection -State Established
```

### Connections Made By Office Applications
```PowerShell
Get-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Internet\Server Cache*
```
If this command returns an error check if your version is correct. If that is the case then no connection was made from office.

### Network Shares
```PowerShell
Get-ChildItem -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\
```

### SMB Shares
```PowerShell
Get-SmbShare
```

### RDP Sessions
```PowerShell
qwinsta /server:localhost
```

# Persistence

### Collect All Startup Files
```PowerShell
Get-CimInstance -ClassName Win32_StartupCommand |
  Select-Object -Property Command, Description, User, Location |
  Out-GridView
```

# Windows Security Events

### Collect The Last 10 Windows Security Event Logs Filter on EventID
```PowerShell
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4688} -MaxEvents 10 | Format-List *
```

### Count By Event Last 2 Days
```PowerShell
$SecurityEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=(Get-Date).AddDays(-2)}
$SecurityEvents | Group-Object -Property Id -NoElement | Sort-Object -Property Count -Descending
```

### Collect Detailed Information All Windows Security Events Last 2 Days
```PowerShell
$SecurityEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=(Get-Date).AddDays(-2)}
$SecurityEvents | Format-List TimeCreated, Id, LevelDisplayName, Message, ProviderName, MachineName, UserId
```

# User & Group Information

### Active Users / Kerberos Sessions
```PowerShell
query user /server:$server
```

### Members of Local Administrator Group
```PowerShell
net localgroup administrators
```
### Local Users
```PowerShell
Get-LocalUser | Format-Table 
```

# Processes

### Detailed Proces Information by Procesname
```PowerShell
Get-Process explorer | Format-List *
```

### Processcommandline
```PowerShell
Get-WmiObject Win32_Process | Select-Object Name,  ProcessId, CommandLine, Path | Format-List
```

### Powershell History
```PowerShell
history
```

### Stop Specific Process by Name
```PowerShell
Stop-Process -Name "Teams"
```

### Stop Specific Process by ID
```PowerShell
Stop-Process -ID 666
```

### Scheduled Task List
```PowerShell
Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | Format-List
```

### Scheduled Task List Run Status
```PowerShell
Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | Get-ScheduledTaskInfo
```


# Applications

### Installed Software (RegistryKey Based)
```PowerShell
$InstalledSoftware = Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
foreach($obj in $InstalledSoftware){write-host $obj.GetValue('DisplayName') -NoNewline; write-host " - " -NoNewline; write-host $obj.GetValue('DisplayVersion')}
```
### Recently Installed Software (Windows Event Logs)
```PowerShell
Get-WinEvent -ProviderName msiinstaller | where id -eq 1033 | select timecreated,message | FL *
```

### Running Services
```PowerShell
Get-Service | Where-Object {$_.Status -eq "Running"} | format-list
```

# File Analysis

### Collect File Stream Information
```PowerShell
Get-Item .\DFIR-Script.ps1 -Stream *
```
### Collect File Content
```PowerShell
Get-Content .\DFIR-Script.ps1
```

### Collect Raw File Content
```PowerShell
Get-Content .\DFIR-Script.ps1 -Encoding Byte | Format-hex
```

### Recent Open Docs
```PowerShell
Get-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\
# based on the list select an ID to further investigate
(Get-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\).71 | Format-Hex
```

### Decode Base64
```PowerShell
$encodedstring = "aHR0cHM6Ly90aGlzaXNhbWFsaWNpb3VzZG9tYWluLmNvbS9kb3dubG9hZC9tYWx3YXJlLmV4ZQ=="
[System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($encodedstring))
```

# Hash Incicators of Compromise

### SHA1 Hash
```PowerShell
Get-FileHash -Algorithm SHA1 -Path C:\Users\User\AppData\Roaming\Microsoft\MaliciousFile.exe
```
### MD5 Hash
```PowerShell
Get-FileHash -Algorithm MD5 -Path C:\Users\User\AppData\Roaming\Microsoft\MaliciousFile.exe
```
### SHA1 Hash
```PowerShell
Get-FileHash -Algorithm SHA256 -Path C:\Users\User\AppData\Roaming\Microsoft\MaliciousFile.exe
```

# Connected Devices

## List Plug and Play devices
```PowerShell
Get-PnpDevice
```

# Retrieve Logs
For the best results run the retrieval of the logs as local admin. Otherwise not all logs can be collected.

## Windows Logs
```PowerShell
$eventLogs = 'Application', 'System', 'Security'
$logEntries = foreach ($logName in $eventLogs) {
    Get-WinEvent -FilterHashtable @{LogName=$logName; StartTime=(Get-Date).AddDays(-2)} -MaxEvents 1000 -ErrorAction SilentlyContinue
}
$logEntries | Format-Table LogName, TimeCreated, Id, LevelDisplayName, Message -AutoSize
```

## Windows Security Events
```PowerShell
Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=(Get-Date).AddDays(-2)} -MaxEvents 500
```
### Windows Security Events to CSV
```PowerShell
$ExecutionDate = (Get-Date -Format "yyyy-MM-dd")
$OutputName = "SecurityEvents-$ExecutionDate.csv"
Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=(Get-Date).AddDays(-2)} |
    Select-Object TimeCreated, Id, LevelDisplayName, Message, ProviderName, MachineName, UserId |
    Export-Csv -Path $OutputName -NoTypeInformation -Encoding UTF8
```


# Defender Exclusions
List the defender exclusions that are defined for your (local) machine.

## IP
```PowerShell
Get-MpPreference | Select-Object -ExpandProperty ExclusionIpAddress
```
## FolderPath
```PowerShell
Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
```
## Process
```PowerShell
Get-MpPreference | Select-Object -ExpandProperty ExclusionProcess
```
## Extension
```PowerShell
Get-MpPreference | Select-Object -ExpandProperty ExclusionExtension
```

# Browser Forensics & Acquisition

### Collect Artifacts from All Browsers (Chrome, Edge, Brave, Opera, Firefox)
```PowerShell
.\Acquisition\CollectBrowserArtifacts.ps1 -AllUsers
```

### Collect Specific Browser Artifacts
```PowerShell
# Firefox (places.sqlite, cookies, sessions, logins, extensions)
.\Acquisition\FirefoxArtifacts.ps1 -Username "Belk0ruh"

# Microsoft Edge (History, Cookies, Login Data, Sessions, Web Data)
.\Acquisition\EdgeArtifacts.ps1 -Username "Belk0ruh"

# Brave Browser (History, Cookies, Login Data, Sessions)
.\Acquisition\BraveArtifacts.ps1 -Username "Belk0ruh"

# Opera & Opera GX (History, Cookies, Login Data, Sessions)
.\Acquisition\OperaArtifacts.ps1 -Username "Belk0ruh"

# Chromium / Google Chrome
.\Acquisition\ChromiumArtifacts.ps1 -Username "Belk0ruh"
```

### Collect All Artifacts Recursively
```PowerShell
.\Acquisition\FirefoxArtifacts.ps1 -AllUsers -CollectAllArtifacts
.\Acquisition\EdgeArtifacts.ps1 -AllUsers -CollectAllArtifacts
.\Acquisition\BraveArtifacts.ps1 -AllUsers -CollectAllArtifacts
.\Acquisition\OperaArtifacts.ps1 -AllUsers -CollectAllArtifacts
```

### List Installed Browser Extensions
```PowerShell
.\Analysis\ListBrowserExtensions.ps1
```

### Export Browser Extensions to Zip
```PowerShell
.\Analysis\ExportBrowserExtensions.ps1
```

# Windows Registry Hives Acquisition

### Dump All Registry Hives (System + All Users)
```PowerShell
.\Acquisition\DumpRegistryHives.ps1
```

### Dump Registry Hives to Custom Output Directory
```PowerShell
.\Acquisition\DumpRegistryHives.ps1 -OutputDir "C:\IR\RegistryDump"
```

### Dump Only System Hives (SAM, SYSTEM, SECURITY, SOFTWARE, DEFAULT)
```PowerShell
.\Acquisition\DumpRegistryHives.ps1 -SystemOnly
```

### Dump User Hives for Specific User (NTUSER.DAT & UsrClass.dat)
```PowerShell
.\Acquisition\DumpRegistryHives.ps1 -Username "Belk0ruh"
```

# PSReadLine Interactive PowerShell History

### Collect PSReadLine History Across All Users
```PowerShell
.\Acquisition\CollectPSReadLineHistory.ps1 -AllUsers
```

### Collect PSReadLine History for Specific User
```PowerShell
.\Acquisition\CollectPSReadLineHistory.ps1 -Username "Belk0ruh" -OutputDir "C:\IR\PSHistory"
```

# Targeted High-Fidelity EVTX Logs

### Collect Key EVTX Logs (PowerShell Operational, Sysmon, TaskScheduler, RDP, Defender, WMI)
```PowerShell
.\Acquisition\CollectTargetedEvtxLogs.ps1 -OutputDir "C:\IR\TargetedEvtx"
```

### Collect All Available EVTX Channels
```PowerShell
.\Acquisition\CollectTargetedEvtxLogs.ps1 -IncludeAllChannels
```

# User Activity & Jump Lists

### Collect LNK Shortcuts and Jump Lists (Automatic & Custom) for All Users
```PowerShell
.\Acquisition\CollectUserActivity.ps1 -AllUsers
```

# Program Execution Artifacts

### Collect Prefetch, SRUM, BAM/DAM, and Amcache
```PowerShell
.\Acquisition\CollectExecutionArtifacts.ps1 -OutputDir "C:\IR\Execution"
```

### Collect Only Prefetch Files (.pf)
```PowerShell
.\Acquisition\CollectExecutionArtifacts.ps1 -PrefetchOnly
```

# WMI Event Persistence Analysis

### Audit WMI Event Filters, Consumers, and Bindings (Fileless Persistence)
```PowerShell
.\Analysis\Get-WMIPersistence.ps1 -ExportCsv
```

# Named Pipes Enumeration & C2 Detection

### Enumerate Active Named Pipes and Detect C2 Signatures (Cobalt Strike, Sliver, Meterpreter, PsExec)
```PowerShell
.\Analysis\Get-NamedPipes.ps1 -ExportCsv
```

# Volatile Network Triage

### Collect DNS Cache, ARP/Neighbors, Routes, Network Profiles, and Active SMB Sessions
```PowerShell
.\Acquisition\CollectNetworkTriage.ps1 -OutputDir "C:\IR\NetworkTriage"
```

# RDP Forensic Artifacts

### Collect Outbound RDP Connection History & Bitmap Caches
```PowerShell
.\Acquisition\CollectRDPArtifacts.ps1 -AllUsers
```

# Root Certificate Authority Audit

### Audit Trusted Root & Intermediate Certificates (Detect Rogue CAs / MitM Proxies)
```PowerShell
.\Analysis\ListRootCertificates.ps1 -ExportCsv
```

# Evidence Manifest & Chain of Custody

### Hash All Collected Artifacts with SHA-256 and Generate JSON/Checksums Manifest
```PowerShell
.\Acquisition\GenerateEvidenceManifest.ps1 -TargetDir "C:\IR\DFIR-DESKTOP-2026-08-21"
```

# Active Directory & Domain Controller Forensics

### Detect Domain Controller Role & Collect Standard AD Artifacts
```PowerShell
.\Acquisition\CollectActiveDirectoryArtifacts.ps1
```

### Full AD Collection with NTDS Database Dump (IFM) & Complete SYSVOL
```PowerShell
.\Acquisition\CollectActiveDirectoryArtifacts.ps1 -DumpNTDS -IncludeSYSVOL -OutputDir "C:\IR\AD_Dump"
```

### Force AD Artifacts Collection on Member Server or Workstation
```PowerShell
.\Acquisition\CollectActiveDirectoryArtifacts.ps1 -Force
```

# Artificial Intelligence (AI) & LLM User Artifacts

### Collect All AI Artifacts Across All Users (Claude, ChatGPT, Cursor, Windsurf, Copilot, Ollama, HuggingFace, Continue, LM Studio, Jan, Aider, Gemini)
```PowerShell
.\Acquisition\CollectAIArtifacts.ps1 -AllUsers
```

### Collect AI Artifacts for Specific User
```PowerShell
.\Acquisition\CollectAIArtifacts.ps1 -Username "Belk0ruh" -OutputDir "C:\IR\AI_Collection"
```

### Collect AI Artifacts Excluding Heavy LLM Model Files (>100MB / GGUF / Binaries)
```PowerShell
.\Acquisition\CollectAIArtifacts.ps1 -AllUsers -ExcludeModels
```

# SSH Forensics (OpenSSH, PuTTY, WinSCP, MobaXterm)

### Collect All SSH Artifacts Across All Users (known_hosts, authorized_keys, PuTTY, WinSCP, MobaXterm)
```PowerShell
.\Acquisition\CollectSSHArtifacts.ps1 -AllUsers
```

### Collect SSH Artifacts for Specific User
```PowerShell
.\Acquisition\CollectSSHArtifacts.ps1 -Username "Belk0ruh" -OutputDir "C:\IR\SSH_Collection"
```

### Collect SSH Artifacts Including Private Keys (id_*, .ppk, .pem)
```PowerShell
.\Acquisition\CollectSSHArtifacts.ps1 -AllUsers -CollectPrivateKeys
```

# VPN Profiles & Live Sockets Forensics

### Collect All Live Sockets (TCP/UDP with Process Mapping) and VPN Profiles (Windows RAS, Cisco, GlobalProtect, OpenVPN, FortiClient, WireGuard, Tailscale)
```PowerShell
.\Acquisition\CollectVPNAndSockets.ps1 -AllUsers
```

### Collect VPN & Sockets for Specific User with VPN Client Logs
```PowerShell
.\Acquisition\CollectVPNAndSockets.ps1 -Username "Belk0ruh" -OutputDir "C:\IR\VPN_Dump" -IncludeLogs
```