<#
.DESCRIPTION
    The DFIR Script is an automated incident response and triage tool via PowerShell for Windows Operating Systems (Workstation & Server).
    Optimized for high-performance live triage with in-memory caching, single-pass event querying, and minimal disk I/O impact.

    The collected information is saved in an output directory named 'DFIR-_hostname_-_date_'.
    This folder is zipped at the end for rapid collection.
    
    Compatible with Windows PowerShell 5.1, PowerShell 7+, and Microsoft Defender for Endpoint (MDE) Live Response.
	
	The script outputs SIEM-ready CSV files in 'CSV Results (SIEM Import Data)\'.

.EXAMPLE
    Run Script with default 2-day search window:
    .\DFIR-Script.ps1

.EXAMPLE
    Define custom search window in days (e.g. 10 days):
    .\DFIR-Script.ps1 -sw 10

.LINK
    https://github.com/Bert-JanP/Incident-Response-Powershell
#>

param (
    [Parameter(Mandatory = $false)]
    [int]$sw = 2 # Defines the search window in days
)

$Version = '2.3.0 (High-Performance Edition)'
$ASCIIBanner = @"
  _____    ______   _____   _____  
 |  __ \  |  ____| |_   _| |  __ \ 
 | |  | | | |__      | |   | |__) |
 | |  | | |  __|     | |   |  _  / 
 | |__| | | |       _| |_  | | \ \ 
 |_____/  |_|      |_____| |_|  \_\`n
"@
Write-Host $ASCIIBanner -ForegroundColor Cyan
Write-Host "Version: $Version" -ForegroundColor Cyan
Write-Host "Optimized DFIR Triage Engine | Fast In-Memory Caching" -ForegroundColor Cyan
Write-Host "===========================================================" -ForegroundColor DarkGray

$HostName = $env:COMPUTERNAME
$OSProductName = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'ProductName' -ErrorAction SilentlyContinue).ProductName
$OSBuild = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'CurrentBuild' -ErrorAction SilentlyContinue).CurrentBuild

Write-Host "Host: $HostName | OS: $OSProductName (Build $OSBuild)" -ForegroundColor Cyan

$currentUsername = $($env:USERNAME)
$currentUserSid = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' -ErrorAction SilentlyContinue |
    Where-Object { $_.PSChildName -match '^S-1-5-21-' -and $_.ProfileImagePath -like "*\$currentUsername" } |
    Select-Object -ExpandProperty PSChildName -First 1

Write-Host "Current user: $currentUsername $(if ($currentUserSid) { "($currentUserSid)" })" -ForegroundColor Cyan

$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($IsAdmin) {
    Write-Host "[+] Running with elevated Administrator privileges." -ForegroundColor Green
} else {
    Write-Host "[-] Standard user privileges detected. Admin artifacts will be skipped." -ForegroundColor Yellow
}

Write-Host "Creating output directory..."
$CurrentPath = (Get-Location).Path
$ExecutionTime = (Get-Date -Format "yyyy-MM-dd")
$FolderCreation = Join-Path -Path $CurrentPath -ChildPath "DFIR-$env:COMPUTERNAME-$ExecutionTime"
New-Item -Path $FolderCreation -ItemType Directory -Force | Out-Null
Write-Host "Output directory: $FolderCreation"

# CSV Output for SIEM Import
$CSVOutputFolder = Join-Path -Path $FolderCreation -ChildPath "CSV Results (SIEM Import Data)"
New-Item -Path $CSVOutputFolder -ItemType Directory -Force | Out-Null

Write-Host "Collecting forensic data (Event window: last $sw day(s))...`n" -ForegroundColor Cyan

# ---------------------------------------------------------
# 1. Network & System Configuration
# ---------------------------------------------------------
function Get-IPInfo {
    Write-Host "[*] Collecting IP Configuration..."
    $Ipinfoutput = "$FolderCreation\ipinfo.txt"
    $Ipconfigoutput = "$FolderCreation\ipconfig.txt"
    $CSVExportLocation = "$CSVOutputFolder\IPConfiguration.csv"

    $ipAddrs = Get-NetIPAddress -ErrorAction SilentlyContinue
    if ($ipAddrs) {
        $ipAddrs | Out-File -Force -FilePath $Ipinfoutput
        $ipAddrs | Export-Csv -Path $CSVExportLocation -NoTypeInformation -Encoding UTF8
    }
    ipconfig /all | Out-File -Force -FilePath $Ipconfigoutput
}

function Get-ShadowCopies {
    Write-Host "[*] Collecting Shadow Copies..."
    $ShadowCopy = "$FolderCreation\ShadowCopies.txt"
    $CSVExportLocation = "$CSVOutputFolder\ShadowCopy.csv"

    $vss = Get-CimInstance Win32_ShadowCopy -ErrorAction SilentlyContinue
    if ($vss) {
        $vss | Out-File -Force -FilePath $ShadowCopy
        $vss | Export-Csv -Path $CSVExportLocation -NoTypeInformation -Encoding UTF8
    }
}

function Get-OpenConnections {
    Write-Host "[*] Collecting Open TCP Connections..."
    $ConnectionFolder = "$FolderCreation\Connections"
    New-Item -Path $ConnectionFolder -ItemType Directory -Force | Out-Null
    $Ipinfoutput = "$ConnectionFolder\OpenConnections.txt"
    $CSVExportLocation = "$CSVOutputFolder\OpenTCPConnections.csv"

    $conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
    if ($conns) {
        $conns | Out-File -Force -FilePath $Ipinfoutput
        $conns | Export-Csv -Path $CSVExportLocation -NoTypeInformation -Encoding UTF8
    }
}

function Get-AutoRunInfo {
    Write-Host "[*] Collecting AutoRun & Startup persistence..."
    $AutoRunFolder = "$FolderCreation\Persistence"
    New-Item -Path $AutoRunFolder -ItemType Directory -Force | Out-Null
    $RegKeyOutput = "$AutoRunFolder\AutoRunInfo.txt"
    $CSVExportLocation = "$CSVOutputFolder\AutoRun.csv"

    $startup = Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue | Select-Object Name, Command, Location, User
    if ($startup) {
        $startup | Format-List | Out-File -Force -FilePath $RegKeyOutput
        $startup | Export-Csv -Path $CSVExportLocation -NoTypeInformation -Encoding UTF8
    }

    # Win32 Registry Run/RunOnce Keys
    $RegKeyOutputWin32 = "$AutoRunFolder\Win32RegRunKey.txt"
    $CSVExportLocationWin32 = "$CSVOutputFolder\Win32RegRunKey.csv"
    $keys = @(
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    $results = @()
    foreach ($key in $keys) {
        if (Test-Path $key) {
            $p = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
            if ($p) {
                $p | Format-List | Out-File -Append -Force -FilePath $RegKeyOutputWin32
                $results += $p
            }
        }
    }
    if ($results.Count -gt 0) {
        $results | Export-Csv -Path $CSVExportLocationWin32 -NoTypeInformation -Encoding UTF8
    }
}

function Get-InstalledDrivers {
    Write-Host "[*] Collecting Installed Drivers..."
    $AutoRunFolder = "$FolderCreation\Persistence"
    $RegKeyOutput = "$AutoRunFolder\InstalledDrivers.txt"
    $CSVExportLocation = "$CSVOutputFolder\Drivers.csv"

    $drivers = driverquery 2>$null
    if ($drivers) {
        $drivers | Out-File -Force -FilePath $RegKeyOutput
        $drivers -split "\n" -replace '\s\s+', ',' | Out-File -Force -FilePath $CSVExportLocation -Encoding UTF8
    }
}

function Get-ActiveUsers {
    Write-Host "[*] Collecting Active Sessions & Users..."
    $UserFolder = "$FolderCreation\UserInformation"
    New-Item -Path $UserFolder -ItemType Directory -Force | Out-Null
    $ActiveUserOutput = "$UserFolder\ActiveUsers.txt"
    $CSVExportLocation = "$CSVOutputFolder\ActiveUsers.csv"

    $qUser = query user 2>$null
    if ($qUser) {
        $qUser | Out-File -Force -FilePath $ActiveUserOutput
        $qUser -split "\n" -replace '\s\s+', ',' | Out-File -Force -FilePath $CSVExportLocation -Encoding UTF8
    }
}

function Get-LocalUsers {
    Write-Host "[*] Collecting Local User Accounts..."
    $UserFolder = "$FolderCreation\UserInformation"
    New-Item -Path $UserFolder -ItemType Directory -Force | Out-Null
    $ActiveUserOutput = "$UserFolder\LocalUsers.txt"
    $CSVExportLocation = "$CSVOutputFolder\LocalUsers.csv"

    $localUsers = Get-LocalUser -ErrorAction SilentlyContinue
    if ($localUsers) {
        $localUsers | Format-Table | Out-File -Force -FilePath $ActiveUserOutput
        $localUsers | Export-Csv -Path $CSVExportLocation -NoTypeInformation -Encoding UTF8
    }
}

# ---------------------------------------------------------
# 2. High-Performance Process Enumeration & Hash Caching
# ---------------------------------------------------------
function Get-ActiveProcesses {
    Write-Host "[*] Collecting Active Processes (with SHA-256 Hash Caching)..."
    $ProcessFolder = "$FolderCreation\ProcessInformation"
    New-Item -Path $ProcessFolder -ItemType Directory -Force | Out-Null
    $UniqueProcessHashOutput = "$ProcessFolder\UniqueProcessHash.csv"
    $ProcessListOutput = "$ProcessFolder\ProcessList.csv"
    $CSVExportLocation = "$CSVOutputFolder\Processes.csv"

    $processes_list = [System.Collections.Generic.List[PSCustomObject]]::new()
    $hashCache = @{}
    $procQuery = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Select-Object Name, ExecutablePath, CommandLine, ParentProcessId, ProcessId

    foreach ($process in $procQuery) {
        if ($null -ne $process.ExecutablePath) {
            $execPath = $process.ExecutablePath
            $hash = $hashCache[$execPath]
            
            # Hash binary only once across all running instances
            if (-not $hash) {
                try {
                    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $execPath -ErrorAction Stop).Hash
                    $hashCache[$execPath] = $hash
                } catch {
                    $hash = "UNREADABLE / LOCKED"
                }
            }

            $processes_list.Add([PSCustomObject]@{
                Proc_Name            = $process.Name
                Proc_Path            = $execPath
                Proc_CommandLine     = $process.CommandLine
                Proc_ParentProcessId = $process.ParentProcessId
                Proc_ProcessId       = $process.ProcessId
                Proc_Hash            = $hash
            })
        }
    }

    $uniqueHashes = $processes_list | Select-Object Proc_Path, Proc_Hash -Unique
    $uniqueHashes | Export-Csv -NoTypeInformation -Path $UniqueProcessHashOutput -Encoding UTF8
    $processes_list | Export-Csv -NoTypeInformation -Path $CSVExportLocation -Encoding UTF8
    $processes_list | Export-Csv -NoTypeInformation -Path $ProcessListOutput -Encoding UTF8
}

# ---------------------------------------------------------
# 3. Single-Pass Security Event Logs Collection
# ---------------------------------------------------------
function Get-SecurityEvents {
    param (
        [Parameter(Mandatory = $true)][int]$sw
    )
    Write-Host "[*] Querying Security Event Logs (single-pass extraction for last $sw days)..."
    $SecurityEventsFolder = "$FolderCreation\SecurityEvents"
    New-Item -Path $SecurityEventsFolder -ItemType Directory -Force | Out-Null
    $CountOutput = "$SecurityEventsFolder\EventCount.txt"
    $ProcessOutput = "$SecurityEventsFolder\SecurityEvents.txt"
    $CSVExportLocation = "$CSVOutputFolder\SecurityEvents.csv"

    $filter = @{
        LogName   = 'Security'
        StartTime = (Get-Date).AddDays(-$sw)
    }

    try {
        $SecurityEvents = Get-WinEvent -FilterHashtable $filter -ErrorAction Stop
    } catch {
        Write-Warning "No Security events found or insufficient permissions: $($_.Exception.Message)"
        return
    }

    if ($SecurityEvents) {
        # 1. Event breakdown stats
        $SecurityEvents | Group-Object -Property Id -NoElement | Sort-Object -Property Count -Descending | Out-File -Force -FilePath $CountOutput

        # 2. Streaming export to CSV and formatted summary table
        $selectedFields = $SecurityEvents | Select-Object TimeCreated, Id, LevelDisplayName, Message, ProviderName, MachineName, UserId, RecordId
        $selectedFields | Export-Csv -Path $CSVExportLocation -NoTypeInformation -Encoding UTF8
        $selectedFields | Format-Table -AutoSize | Out-File -Force -FilePath $ProcessOutput
        Write-Host " [+] Extracted $($SecurityEvents.Count) Security events." -ForegroundColor Green
    }
}

function Get-EventViewerFiles {
    Write-Host "[*] Copying Key Forensic EVTX Logs..."
    $EventViewer = "$FolderCreation\Event Viewer"
    New-Item -Path $EventViewer -ItemType Directory -Force | Out-Null
    $evtxPath = "$env:SystemRoot\System32\Winevt\Logs"
    $channels = @(
        "Application",
        "Security",
        "System",
        "Microsoft-Windows-Sysmon%4Operational",
        "Microsoft-Windows-TaskScheduler%4Operational",
        "Microsoft-Windows-PowerShell%4Operational"
    )

    Get-ChildItem "$evtxPath\*.evtx" -ErrorAction SilentlyContinue | Where-Object { $_.BaseName -in $channels } | ForEach-Object {
        $dest = Join-Path $EventViewer $_.Name
        try {
            # Use FileShare.ReadWrite to avoid locking collisions with active logging services
            $src = [System.IO.File]::Open($_.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
            $dst = [System.IO.File]::Create($dest)
            $src.CopyTo($dst)
            $dst.Close()
            $src.Close()
        } catch {
            Write-Warning "Could not copy EVTX file: $($_.FullName)"
        }
    }
}

function Get-OfficeConnections {
    param ([string]$UserSid)
    Write-Host "[*] Collecting Office Application Connection History..."
    $ConnectionFolder = "$FolderCreation\Connections"
    $OfficeConnection = "$ConnectionFolder\ConnectionsMadeByOffice.txt"
    $CSVExportLocation = "$CSVOutputFolder\OfficeConnections.csv"

    if ($UserSid) {
        $path = "registry::HKEY_USERS\$UserSid\SOFTWARE\Microsoft\Office\16.0\Common\Internet\Server Cache"
    } else {
        $path = "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Internet\Server Cache"
    }

    if (Test-Path $path) {
        $entries = Get-ChildItem -Path $path -ErrorAction SilentlyContinue
        if ($entries) {
            $entries | Out-File -Force -FilePath $OfficeConnection
            $entries | Export-Csv -Path $CSVExportLocation -NoTypeInformation -Encoding UTF8
        }
    }
}

function Get-NetworkShares {
    param ([string]$UserSid)
    Write-Host "[*] Collecting Active Network Shares & Mount Points..."
    $ConnectionFolder = "$FolderCreation\Connections"
    $ProcessOutput = "$ConnectionFolder\NetworkShares.txt"
    $CSVExportLocation = "$CSVOutputFolder\NetworkShares.csv"

    if ($UserSid) {
        $path = "registry::HKEY_USERS\$UserSid\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2"
    } else {
        $path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2"
    }

    if (Test-Path $path) {
        $shares = Get-ChildItem -Path $path -ErrorAction SilentlyContinue
        if ($shares) {
            $shares | Out-File -Force -FilePath $ProcessOutput
            $shares | Export-Csv -Path $CSVExportLocation -NoTypeInformation -Encoding UTF8
        }
    }
}

function Get-SMBShares {
    Write-Host "[*] Collecting Local SMB Shares..."
    $ConnectionFolder = "$FolderCreation\Connections"
    $ProcessOutput = "$ConnectionFolder\SMBShares.txt"
    $CSVExportLocation = "$CSVOutputFolder\SMBShares.csv"

    $smb = Get-SmbShare -ErrorAction SilentlyContinue
    if ($smb) {
        $smb | Out-File -Force -FilePath $ProcessOutput
        $smb | Export-Csv -Path $CSVExportLocation -NoTypeInformation -Encoding UTF8
    }
}

function Get-RDPSessions {
    Write-Host "[*] Collecting RDP Sessions..."
    $ConnectionFolder = "$FolderCreation\Connections"
    $ProcessOutput = "$ConnectionFolder\RDPSessions.txt"
    $CSVExportLocation = "$CSVOutputFolder\RDPSessions.csv"

    $sessions = qwinsta 2>$null
    if ($sessions) {
        $sessions | Out-File -Force -FilePath $ProcessOutput
        $sessions -split "\n" -replace '\s\s+', ',' | Out-File -Force -FilePath $CSVExportLocation -Encoding UTF8
    }
}

function Get-RemotelyOpenedFiles {
    Write-Host "[*] Collecting Remotely Opened SMB Files..."
    $ConnectionFolder = "$FolderCreation\Connections"
    $ProcessOutput = "$ConnectionFolder\RemotelyOpenedFiles.txt"
    $CSVExportLocation = "$CSVOutputFolder\RemotelyOpenedFiles.csv"

    $openedFiles = Get-SmbOpenFile -ErrorAction SilentlyContinue
    if ($openedFiles) {
        $openedFiles | Out-File -Force -FilePath $ProcessOutput
        $openedFiles | Export-Csv -Path $CSVExportLocation -NoTypeInformation -Encoding UTF8
    }
}

function Get-DNSCache {
    Write-Host "[*] Collecting DNS Client Cache..."
    $ConnectionFolder = "$FolderCreation\Connections"
    $ProcessOutput = "$ConnectionFolder\DNSCache.txt"
    $CSVExportLocation = "$CSVOutputFolder\DNSCache.csv"

    $dns = Get-DnsClientCache -ErrorAction SilentlyContinue
    if ($dns) {
        $dns | Out-File -Force -FilePath $ProcessOutput
        $dns | Export-Csv -Path $CSVExportLocation -NoTypeInformation -Encoding UTF8
    }
}

function Get-PowershellHistoryCurrentUser {
    Write-Host "[*] Collecting Current PowerShell History..."
    $PowershellConsoleHistory = "$FolderCreation\PowerShellHistory"
    New-Item -Path $PowershellConsoleHistory -ItemType Directory -Force | Out-Null
    $PowershellHistoryOutput = "$PowershellConsoleHistory\PowershellHistoryCurrentUser.txt"
    $CSVExportLocation = "$CSVOutputFolder\PowerShellHistory.csv"

    $history = Get-History -ErrorAction SilentlyContinue
    if ($history) {
        $history | Out-File -Force -FilePath $PowershellHistoryOutput
        $history | Export-Csv -Path $CSVExportLocation -NoTypeInformation -Encoding UTF8
    }
}

function Get-PowershellConsoleHistory-AllUsers {
    Write-Host "[*] Collecting PSReadLine Console Host History (All Users)..."
    $PowershellConsoleHistory = "$FolderCreation\PowerShellHistory"
    New-Item -Path $PowershellConsoleHistory -ItemType Directory -Force | Out-Null

    $userDirs = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notmatch '^(Public|Default|Default User|All Users)$' }

    foreach ($userDir in $userDirs) {
        $historyFilePath = Join-Path -Path $userDir.FullName -ChildPath "AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
        if (Test-Path $historyFilePath) {
            $outputDirectory = Join-Path -Path $PowershellConsoleHistory -ChildPath $userDir.Name
            New-Item -Path $outputDirectory -ItemType Directory -Force | Out-Null
            Copy-Item -LiteralPath $historyFilePath -Destination (Join-Path $outputDirectory "ConsoleHost_history.txt") -Force -ErrorAction SilentlyContinue
        }
    }
}

function Get-RecentlyInstalledSoftwareEventLogs {
    Write-Host "[*] Collecting MsiInstaller Software Events..."
    $ApplicationFolder = "$FolderCreation\Applications"
    New-Item -Path $ApplicationFolder -ItemType Directory -Force | Out-Null
    $ProcessOutput = "$ApplicationFolder\RecentlyInstalledSoftwareEventLogs.txt"
    $CSVExportLocation = "$CSVOutputFolder\InstalledSoftware.csv"

    $msiEvents = Get-WinEvent -FilterHashtable @{ ProviderName = 'MsiInstaller'; Id = 1033 } -ErrorAction SilentlyContinue
    if ($msiEvents) {
        $selected = $msiEvents | Select-Object TimeCreated, Message
        $selected | Format-List | Out-File -Force -FilePath $ProcessOutput
        $selected | Export-Csv -Path $CSVExportLocation -NoTypeInformation -Encoding UTF8
    }
}

function Get-RunningServices {
    Write-Host "[*] Collecting Running Services..."
    $ApplicationFolder = "$FolderCreation\Services"
    New-Item -Path $ApplicationFolder -ItemType Directory -Force | Out-Null
    $ProcessOutput = "$ApplicationFolder\RunningServices.txt"
    $CSVExportLocation = "$CSVOutputFolder\RunningServices.csv"

    $services = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Running" }
    if ($services) {
        $services | Format-List | Out-File -Force -FilePath $ProcessOutput
        $services | Export-Csv -Path $CSVExportLocation -NoTypeInformation -Encoding UTF8
    }
}

function Get-ScheduledTasks {
    Write-Host "[*] Collecting Scheduled Tasks..."
    $ScheduledTaskFolder = "$FolderCreation\ScheduledTask"
    New-Item -Path $ScheduledTaskFolder -ItemType Directory -Force | Out-Null
    $ProcessOutput = "$ScheduledTaskFolder\ScheduledTasksList.txt"
    $CSVExportLocation = "$CSVOutputFolder\ScheduledTasks.csv"

    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
        ($_.State -ne 'Disabled') -and (($null -eq $_.LastRunTime) -or ($_.LastRunTime -gt (Get-Date).AddDays(-7)))
    }
    if ($tasks) {
        $tasks | Format-List | Out-File -Force -FilePath $ProcessOutput
        $tasks | Export-Csv -Path $CSVExportLocation -NoTypeInformation -Encoding UTF8
    }
}

function Get-ScheduledTasksRunInfo {
    Write-Host "[*] Collecting Scheduled Tasks Run Information..."
    $ScheduledTaskFolder = "$FolderCreation\ScheduledTask"
    $ProcessOutput = "$ScheduledTaskFolder\ScheduledTasksListRunInfo.txt"
    $CSVExportLocation = "$CSVOutputFolder\ScheduledTasksRunInfo.csv"

    $activeTasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.State -ne "Disabled" }
    if ($activeTasks) {
        $taskInfos = $activeTasks | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
        if ($taskInfos) {
            $taskInfos | Out-File -Force -FilePath $ProcessOutput
            $taskInfos | Export-Csv -Path $CSVExportLocation -NoTypeInformation -Encoding UTF8
        }
    }
}

function Get-ConnectedDevices {
    Write-Host "[*] Collecting Connected PnP Devices..."
    $DeviceFolder = "$FolderCreation\ConnectedDevices"
    New-Item -Path $DeviceFolder -ItemType Directory -Force | Out-Null
    $ConnectedDevicesOutput = "$DeviceFolder\ConnectedDevices.csv"
    $CSVExportLocation = "$CSVOutputFolder\ConnectedDevices.csv"

    $devices = Get-PnpDevice -ErrorAction SilentlyContinue
    if ($devices) {
        $devices | Export-Csv -NoTypeInformation -Path $ConnectedDevicesOutput -Encoding UTF8
        $devices | Export-Csv -NoTypeInformation -Path $CSVExportLocation -Encoding UTF8
    }
}

# ---------------------------------------------------------
# 4. Browser Forensics Collection (Fast Targeted Files)
# ---------------------------------------------------------
function Copy-BrowserProfileFiles {
    param (
        [string]$BasePath,
        [string]$DestinationFolder,
        [string[]]$FilesToCopy
    )

    if (Test-Path $BasePath) {
        $profiles = Get-ChildItem -Path $BasePath -Directory -ErrorAction SilentlyContinue | Where-Object {
            (Test-Path (Join-Path $_.FullName "History")) -or (Test-Path (Join-Path $_.FullName "Preferences"))
        }

        foreach ($profile in $profiles) {
            $destPath = Join-Path $DestinationFolder $profile.Name
            New-Item -Path $destPath -ItemType Directory -Force | Out-Null

            foreach ($fname in $FilesToCopy) {
                $srcFile = Join-Path $profile.FullName $fname
                if (Test-Path $srcFile) {
                    try {
                        # Stream copy with ReadWrite share to read locked active browser databases
                        $src = [System.IO.File]::Open($srcFile, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
                        $dst = [System.IO.File]::Create((Join-Path $destPath $fname))
                        $src.CopyTo($dst)
                        $dst.Close()
                        $src.Close()
                    } catch {
                        Copy-Item -LiteralPath $srcFile -Destination (Join-Path $destPath $fname) -Force -ErrorAction SilentlyContinue
                    }
                }
            }
        }
    }
}

function Get-ChromiumFiles {
    param ([string]$Username)
    Write-Host "[*] Collecting Chrome artifacts..."
    $HistoryFolder = "$FolderCreation\Browsers\Chrome"
    New-Item -Path $HistoryFolder -ItemType Directory -Force | Out-Null
    $files = @('Preferences', 'Secure Preferences', 'History', 'Bookmarks', 'Login Data', 'Web Data')
    Copy-BrowserProfileFiles -BasePath "C:\Users\$Username\AppData\Local\Google\Chrome\User Data" -DestinationFolder $HistoryFolder -FilesToCopy $files
}

function Get-EdgeFiles {
    param ([string]$Username)
    Write-Host "[*] Collecting Microsoft Edge artifacts..."
    $HistoryFolder = "$FolderCreation\Browsers\Edge"
    New-Item -Path $HistoryFolder -ItemType Directory -Force | Out-Null
    $files = @('Preferences', 'Secure Preferences', 'History', 'Bookmarks', 'Login Data', 'Web Data')
    Copy-BrowserProfileFiles -BasePath "C:\Users\$Username\AppData\Local\Microsoft\Edge\User Data" -DestinationFolder $HistoryFolder -FilesToCopy $files
}

function Get-BraveFiles {
    param ([string]$Username)
    Write-Host "[*] Collecting Brave Browser artifacts..."
    $HistoryFolder = "$FolderCreation\Browsers\Brave"
    New-Item -Path $HistoryFolder -ItemType Directory -Force | Out-Null
    $files = @('Preferences', 'Secure Preferences', 'History', 'Bookmarks', 'Login Data', 'Web Data')
    Copy-BrowserProfileFiles -BasePath "C:\Users\$Username\AppData\Local\BraveSoftware\Brave-Browser\User Data" -DestinationFolder $HistoryFolder -FilesToCopy $files
}

function Get-OperaFiles {
    param ([string]$Username)
    Write-Host "[*] Collecting Opera artifacts..."
    $HistoryFolder = "$FolderCreation\Browsers\Opera"
    New-Item -Path $HistoryFolder -ItemType Directory -Force | Out-Null
    $files = @('Preferences', 'Secure Preferences', 'History', 'Bookmarks', 'Login Data', 'Web Data')
    Copy-BrowserProfileFiles -BasePath "C:\Users\$Username\AppData\Roaming\Opera Software\Opera Stable" -DestinationFolder $HistoryFolder -FilesToCopy $files
}

function Get-FirefoxFiles {
    param ([string]$Username)
    $ffBase = "C:\Users\$Username\AppData\Roaming\Mozilla\Firefox\Profiles"
    if (Test-Path $ffBase) {
        Write-Host "[*] Collecting Firefox artifacts..."
        $HistoryFolder = "$FolderCreation\Browsers\Firefox"
        New-Item -Path $HistoryFolder -ItemType Directory -Force | Out-Null
        $files = @('places.sqlite', 'cookies.sqlite', 'formhistory.sqlite', 'permissions.sqlite', 'logins.json', 'key4.db', 'cert9.db', 'prefs.js')

        Get-ChildItem $ffBase -Directory -ErrorAction SilentlyContinue | Where-Object { Test-Path (Join-Path $_.FullName "places.sqlite") } | ForEach-Object {
            $dest = Join-Path $HistoryFolder $_.Name
            New-Item -Path $dest -ItemType Directory -Force | Out-Null
            foreach ($f in $files) {
                $srcFile = Join-Path $_.FullName $f
                if (Test-Path $srcFile) {
                    try {
                        $src = [System.IO.File]::Open($srcFile, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
                        $dst = [System.IO.File]::Create((Join-Path $dest $f))
                        $src.CopyTo($dst)
                        $dst.Close()
                        $src.Close()
                    } catch {
                        Copy-Item -LiteralPath $srcFile -Destination (Join-Path $dest $f) -Force -ErrorAction SilentlyContinue
                    }
                }
            }
        }
    }
}

# ---------------------------------------------------------
# 5. Defender & Registry Hives Collection
# ---------------------------------------------------------
function Get-MPLogs {
    Write-Host "[*] Collecting Defender MPLogs..."
    $MPLogFolder = "$FolderCreation\MPLogs"
    New-Item -Path $MPLogFolder -ItemType Directory -Force | Out-Null
    $MPLogLocation = "$env:ProgramData\Microsoft\Windows Defender\Support"
    if (Test-Path $MPLogLocation) {
        Get-ChildItem -Path $MPLogLocation -Filter "*.log" -File -ErrorAction SilentlyContinue | ForEach-Object {
            Copy-Item -LiteralPath $_.FullName -Destination $MPLogFolder -Force -ErrorAction SilentlyContinue
        }
    }
}

function Get-DefenderExclusions {
    Write-Host "[*] Collecting Defender Exclusions..."
    $DefenderExclusionFolder = "$FolderCreation\DefenderExclusions"
    New-Item -Path $DefenderExclusionFolder -ItemType Directory -Force | Out-Null
    $CSVExportLocation = "$CSVOutputFolder\DefenderExclusions.csv"

    $pref = Get-MpPreference -ErrorAction SilentlyContinue
    if ($pref) {
        $pPath = $pref.ExclusionPath
        $pExt = $pref.ExclusionExtension
        $pIp = $pref.ExclusionIpAddress
        $pProc = $pref.ExclusionProcess

        $pPath | Out-File -Force -FilePath "$DefenderExclusionFolder\ExclusionPath.txt"
        $pExt | Out-File -Force -FilePath "$DefenderExclusionFolder\ExclusionExtension.txt"
        $pIp | Out-File -Force -FilePath "$DefenderExclusionFolder\ExclusionIpAddress.txt"
        $pProc | Out-File -Force -FilePath "$DefenderExclusionFolder\ExclusionProcess.txt"

        $exList = @()
        if ($pPath) { foreach ($x in $pPath) { $exList += [PSCustomObject]@{ Type = "Path"; Value = $x } } }
        if ($pExt) { foreach ($x in $pExt) { $exList += [PSCustomObject]@{ Type = "Extension"; Value = $x } } }
        if ($pIp) { foreach ($x in $pIp) { $exList += [PSCustomObject]@{ Type = "IPAddress"; Value = $x } } }
        if ($pProc) { foreach ($x in $pProc) { $exList += [PSCustomObject]@{ Type = "Process"; Value = $x } } }

        if ($exList.Count -gt 0) {
            $exList | Export-Csv -Path $CSVExportLocation -NoTypeInformation -Encoding UTF8
        }
    }
}

function Get-RegistryHives {
    Write-Host "[*] Dumping System & User Registry Hives..."
    $RegistryFolder = "$FolderCreation\RegistryHives"
    $SystemHivesDir = "$RegistryFolder\System"
    $UserHivesDir = "$RegistryFolder\Users"
    New-Item -Path $SystemHivesDir -ItemType Directory -Force | Out-Null
    New-Item -Path $UserHivesDir -ItemType Directory -Force | Out-Null

    # System Hives
    $sysHives = @(
        @{ Key = "HKLM\SAM"; File = "$SystemHivesDir\SAM" },
        @{ Key = "HKLM\SYSTEM"; File = "$SystemHivesDir\SYSTEM" },
        @{ Key = "HKLM\SECURITY"; File = "$SystemHivesDir\SECURITY" },
        @{ Key = "HKLM\SOFTWARE"; File = "$SystemHivesDir\SOFTWARE" },
        @{ Key = "HKU\.DEFAULT"; File = "$SystemHivesDir\DEFAULT" }
    )

    foreach ($hive in $sysHives) {
        Start-Process -FilePath "reg.exe" -ArgumentList "save `"$($hive.Key)`" `"$($hive.File)`" /y" -Wait -NoNewWindow | Out-Null
    }

    # User Hives (NTUSER.DAT & UsrClass.dat)
    $profileList = @{}
    Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' -ErrorAction SilentlyContinue | Where-Object {
        $_.PSChildName -match '^S-1-5-21-' -and $_.ProfileImagePath
    } | ForEach-Object {
        $profileList[$_.ProfileImagePath.ToLower()] = $_.PSChildName
    }

    $targetUsers = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -notmatch '^(Public|Default|Default User|All Users)$'
    }

    foreach ($user in $targetUsers) {
        $userDestDir = Join-Path -Path $UserHivesDir -ChildPath $user.Name
        New-Item -Path $userDestDir -ItemType Directory -Force | Out-Null

        $sid = $profileList[$user.FullName.ToLower()]

        # NTUSER.DAT
        $ntuserDest = Join-Path $userDestDir "NTUSER.DAT"
        if ($sid -and (Test-Path "registry::HKEY_USERS\$sid")) {
            Start-Process -FilePath "reg.exe" -ArgumentList "save `"HKU\$sid`" `"$ntuserDest`" /y" -Wait -NoNewWindow | Out-Null
        } else {
            $ntuserFile = Join-Path $user.FullName "NTUSER.DAT"
            if (Test-Path $ntuserFile) {
                Copy-Item -LiteralPath $ntuserFile -Destination $ntuserDest -Force -ErrorAction SilentlyContinue
            }
        }

        # UsrClass.dat
        $usrClassDest = Join-Path $userDestDir "UsrClass.dat"
        if ($sid -and (Test-Path "registry::HKEY_USERS\${sid}_Classes")) {
            Start-Process -FilePath "reg.exe" -ArgumentList "save `"HKU\${sid}_Classes`" `"$usrClassDest`" /y" -Wait -NoNewWindow | Out-Null
        } else {
            $usrClassFile = Join-Path $user.FullName "AppData\Local\Microsoft\Windows\UsrClass.dat"
            if (Test-Path $usrClassFile) {
                Copy-Item -LiteralPath $usrClassFile -Destination $usrClassDest -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

function Zip-Results {
    Write-Host "`nCompressing evidence into $FolderCreation.zip..." -ForegroundColor Yellow
    Compress-Archive -Force -LiteralPath $FolderCreation -DestinationPath "$FolderCreation.zip"
    Write-Host "[+] Triage complete! Evidence ZIP archive: $FolderCreation.zip" -ForegroundColor Green
}

# ---------------------------------------------------------
# Execution Flow
# ---------------------------------------------------------
function Run-StandardCollection {
    param ([string]$UserSid, [string]$Username)

    Get-IPInfo
    Get-OpenConnections
    Get-AutoRunInfo
    Get-ActiveUsers
    Get-LocalUsers
    Get-ActiveProcesses
    Get-OfficeConnections -UserSid $UserSid
    Get-NetworkShares -UserSid $UserSid
    Get-SMBShares
    Get-RDPSessions
    Get-PowershellHistoryCurrentUser
    Get-DNSCache
    Get-InstalledDrivers    
    Get-RecentlyInstalledSoftwareEventLogs
    Get-RunningServices
    Get-ScheduledTasks
    Get-ScheduledTasksRunInfo
    Get-ConnectedDevices
    if ($Username) {
        Get-ChromiumFiles -Username $Username
        Get-EdgeFiles -Username $Username
        Get-BraveFiles -Username $Username
        Get-OperaFiles -Username $Username
        Get-FirefoxFiles -Username $Username
    }
}

function Run-AdminCollection {
    Get-SecurityEvents -sw $sw
    Get-RemotelyOpenedFiles
    Get-ShadowCopies
    Get-EventViewerFiles
    Get-MPLogs
    Get-DefenderExclusions
    Get-PowershellConsoleHistory-AllUsers
    Get-RegistryHives
}

$swWatch = [System.Diagnostics.Stopwatch]::StartNew()

Run-StandardCollection -UserSid $currentUserSid -Username $currentUsername

if ($IsAdmin) {
    Run-AdminCollection
}

Zip-Results

$swWatch.Stop()
Write-Host "`n===========================================================" -ForegroundColor Green
Write-Host " Total Triage Execution Time: $([math]::Round($swWatch.Elapsed.TotalSeconds, 2)) seconds" -ForegroundColor Green
Write-Host "===========================================================" -ForegroundColor Green
