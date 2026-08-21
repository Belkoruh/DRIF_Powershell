<#
.DESCRIPTION
    The DFIR Script is a tool to perform incident response via PowerShell on compromised devices with an Windows Operating System (Workstation & Server). The content that the script can collect depends on the permissions of the user that executes the script, if executed with admin privileges more forensic artifacts can be collected.

    The collected information is saved in an output directory in the current folder, this is by creating a folder named 'DFIR-_hostname_-_year_-_month_-_date_'. This folder is zipped at the end to enable easy collection.
    
    This script can be integrated with Defender For Endpoint via Live Response sessions (see https://github.com/Bert-JanP/Incident-Response-Powershell).
	
	The script outputs the results as CSV to be imported in SIEM or data analysis tooling, the folder in which those files are located is named 'CSV Results (SIEM Import Data)'.

.EXAMPLE
    Run Script without any parameters
    .\DFIR-Script.ps1
.EXAMPLE
    Define custom search window, this is done in days. Example below collects the Security Events from the last 10 days.
    .\DFIR-Script.ps1 -sw 10

.LINK
    Integration Defender For Endpoint Live Response: 
    https://github.com/Bert-JanP/Incident-Response-Powershell & https://kqlquery.com/posts/leveraging-live-response/
    
    Individual PowerShell Incident Response Commands: 
    https://github.com/Bert-JanP/Incident-Response-Powershell/blob/main/DFIR-Commands.md
#>

param(
        [Parameter(Mandatory=$false)][int]$sw = 2 # Defines the custom search window, this is done in days.
    )


$Version = '2.2.4'
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
Write-Host "Developed by Bert-Jan Pals | Twitter: @BertJanCyber | Github: Bert-JanP" -ForegroundColor Cyan
Write-Host "===========================================" -ForegroundColor Black
$HostName = $env:COMPUTERNAME
$OSProductName = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'ProductName').ProductName
$OSBuild = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'CurrentBuild').CurrentBuild
Write-Host  -ForegroundColor Cyan
Write-Host "Host Inforation`n (HostName: $HostName | OS: $OSProductName | OS Build: $OSBuild)" -ForegroundColor Cyan

$currentUsername = $($env:USERNAME)
$currentUserSid = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' | Where-Object {$_.PSChildName -match 'S-1-5-21-\d+-\d+\-\d+\-\d+$' -and $_.ProfileImagePath -match "\\$currentUsername$"} | ForEach-Object{$_.PSChildName}
Write-Host "Current user: $currentUsername $currentUserSid" -ForegroundColor Cyan

$IsAdmin = ([Security.Principal.WindowsPrincipal] `
        [Security.Principal.WindowsIdentity]::GetCurrent() `
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($IsAdmin) {
    Write-Host "DFIR Session starting as Administrator..."
}
else {
    Write-Host "No Administrator session detected. For the best performance run as Administrator. Not all artifacts can be collected..." -ForegroundColor Red
    Write-Host "DFIR Session starting..."
}

Write-Host "Creating output directory..."
$CurrentPath = (Get-Location).Path
$ExecutionTime = (Get-Date -Format "yyyy-MM-dd")
$FolderCreation = Join-Path -Path $CurrentPath -ChildPath "DFIR-$env:COMPUTERNAME-$ExecutionTime"
New-Item -Path $FolderCreation -ItemType Directory -Force | Out-Null
Write-Host "Output directory created: $FolderCreation..."

#CSV Output for import in SIEM
$CSVOutputFolder = Join-Path -Path $FolderCreation -ChildPath "CSV Results (SIEM Import Data)"
New-Item -Path $CSVOutputFolder -ItemType Directory -Force | Out-Null
Write-Host "SIEM Export Output directory created: $CSVOutputFolder..."

#Search Window
Write-Host "Collecting data from last $sw days"

function Get-IPInfo {
    Write-Host "Collecting local ip info..."
    $Ipinfoutput = "$FolderCreation\ipinfo.txt"
    Get-NetIPAddress | Out-File -Force -FilePath $Ipinfoutput
    $Ipconfigoutput = "$FolderCreation\ipconfig.txt"
    ipconfig /all | Out-File -Force -FilePath $Ipconfigoutput
	$CSVExportLocation = "$CSVOutputFolder\IPConfiguration.csv"
	Get-NetIPAddress | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $CSVExportLocation -Encoding UTF8
}
function Get-ShadowCopies {
    Write-Host "Collecting Shadow Copies..."
    $ShadowCopy = "$FolderCreation\ShadowCopies.txt"
    Get-CimInstance Win32_ShadowCopy | Out-File -Force -FilePath $ShadowCopy
	$CSVExportLocation = "$CSVOutputFolder\ShadowCopy.csv"
	Get-CimInstance Win32_ShadowCopy | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $CSVExportLocation -Encoding UTF8
}

function Get-OpenConnections {
    Write-Host "Collecting Open Connections..."
    $ConnectionFolder = "$FolderCreation\Connections"
    New-Item -Path $ConnectionFolder -ItemType Directory -Force | Out-Null
    $Ipinfoutput = "$ConnectionFolder\OpenConnections.txt"
    Get-NetTCPConnection -State Established | Out-File -Force -FilePath $Ipinfoutput
	$CSVExportLocation = "$CSVOutputFolder\OpenTCPConnections.csv"
	Get-NetTCPConnection -State Established | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $CSVExportLocation -Encoding UTF8
}

function Get-AutoRunInfo {
    Write-Host "Collecting AutoRun info..."
    $AutoRunFolder = "$FolderCreation\Persistence"
    New-Item -Path $AutoRunFolder -ItemType Directory -Force | Out-Null
    $RegKeyOutput = "$AutoRunFolder\AutoRunInfo.txt"
    Get-CimInstance Win32_StartupCommand | Select-Object Name, command, Location, User | Format-List | Out-File -Force -FilePath $RegKeyOutput
	$CSVExportLocation = "$CSVOutputFolder\AutoRun.csv"
	Get-CimInstance Win32_StartupCommand | Select-Object Name, command, Location, User | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $CSVExportLocation -Encoding UTF8

    # Win32 Registry Run/RunOnce Keys:
    $RegKeyOutputWin32 = "$AutoRunFolder\Win32RegRunKey.txt"
    Get-ItemProperty -Path HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce | Format-List | Out-File -Force -FilePath $RegKeyOutputWin32
    Get-ItemProperty -Path HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run | Format-List | Out-File -Append -Force -FilePath $RegKeyOutputWin32
    $CSVExportLocation = "$CSVOutputFolder\Win32RegRunKey.csv"

    $results = @()
    $keys = @(
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    foreach ($key in $keys) {
        $results += Get-ItemProperty -Path $key
    }

	$results | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $CSVExportLocation -Encoding UTF8

}

function Get-InstalledDrivers {
    Write-Host "Collecting Installed Drivers..."
    $AutoRunFolder = "$FolderCreation\Persistence"
    $RegKeyOutput = "$AutoRunFolder\InstalledDrivers.txt"
    driverquery | Out-File -Force -FilePath $RegKeyOutput
	$CSVExportLocation = "$CSVOutputFolder\Drivers.csv"
	(driverquery) -split "\n" -replace '\s\s+', ','  | Out-File -Force $CSVExportLocation -Encoding UTF8
}

function Get-ActiveUsers {
    Write-Host "Collecting Active users..."
    $UserFolder = "$FolderCreation\UserInformation"
    New-Item -Path $UserFolder -ItemType Directory -Force | Out-Null
    $ActiveUserOutput = "$UserFolder\ActiveUsers.txt"
    query user 2>$null | Out-File -Force -FilePath $ActiveUserOutput
	$CSVExportLocation = "$CSVOutputFolder\ActiveUsers.csv"
	(query user 2>$null) -split "\n" -replace '\s\s+', ','  | Out-File -Force -FilePath $CSVExportLocation -Encoding UTF8
}

function Get-LocalUsers {
    Write-Host "Collecting Local users..."
    $UserFolder = "$FolderCreation\UserInformation"
    $ActiveUserOutput = "$UserFolder\LocalUsers.txt"
    Get-LocalUser | Format-Table | Out-File -Force -FilePath $ActiveUserOutput
	$CSVExportLocation = "$CSVOutputFolder\LocalUsers.csv"
	Get-LocalUser | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $CSVExportLocation -Encoding UTF8
}

function Get-ActiveProcesses {
    Write-Host "Collecting Active Processes..."
    $ProcessFolder = "$FolderCreation\ProcessInformation"
    New-Item -Path $ProcessFolder -ItemType Directory -Force | Out-Null
    $UniqueProcessHashOutput = "$ProcessFolder\UniqueProcessHash.csv"
    $ProcessListOutput = "$ProcessFolder\ProcessList.csv"
	$CSVExportLocation = "$CSVOutputFolder\Processes.csv"

    $processes_list = @()
    foreach ($process in (Get-CimInstance Win32_Process | Select-Object Name, ExecutablePath, CommandLine, ParentProcessId, ProcessId))
    {
        $process_obj = New-Object PSCustomObject
        if ($null -ne $process.ExecutablePath)
        {
            $hash = (Get-FileHash -Algorithm SHA256 -Path $process.ExecutablePath).Hash 
            $process_obj | Add-Member -NotePropertyName Proc_Hash -NotePropertyValue $hash
            $process_obj | Add-Member -NotePropertyName Proc_Name -NotePropertyValue $process.Name
            $process_obj | Add-Member -NotePropertyName Proc_Path -NotePropertyValue $process.ExecutablePath
            $process_obj | Add-Member -NotePropertyName Proc_CommandLine -NotePropertyValue $process.CommandLine
            $process_obj | Add-Member -NotePropertyName Proc_ParentProcessId -NotePropertyValue $process.ParentProcessId
            $process_obj | Add-Member -NotePropertyName Proc_ProcessId -NotePropertyValue $process.ProcessId
            $processes_list += $process_obj
        }   
    }

    ($processes_list | Select-Object Proc_Path, Proc_Hash -Unique).GetEnumerator() | Export-Csv -NoTypeInformation -Path $UniqueProcessHashOutput
	($processes_list | Select-Object Proc_Path, Proc_Hash -Unique).GetEnumerator() | Export-Csv -NoTypeInformation -Path $CSVExportLocation
    ($processes_list | Select-Object Proc_Name, Proc_Path, Proc_CommandLine, Proc_ParentProcessId, Proc_ProcessId, Proc_Hash).GetEnumerator() | Export-Csv -NoTypeInformation -Path $ProcessListOutput
	
}

function Get-SecurityEventCount {
    param(
        [Parameter(Mandatory=$true)][int]$sw
    )
    Write-Host "Collecting stats Security Events last $sw days..."
    $SecurityEventsFolder = "$FolderCreation\SecurityEvents"
    New-Item -Path $SecurityEventsFolder -ItemType Directory -Force | Out-Null
    $ProcessOutput = "$SecurityEventsFolder\EventCount.txt"
    $filter = @{
        LogName   = 'Security'
        StartTime = (Get-Date).AddDays(-$sw)
    }
    $SecurityEvents = Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue
    if ($SecurityEvents) {
        $SecurityEvents | Group-Object -Property Id -NoElement | Sort-Object -Property Count -Descending | Out-File -Force -FilePath $ProcessOutput
    }
}

function Get-SecurityEvents {
    param(
        [Parameter(Mandatory=$true)][int]$sw
    )
    Write-Host "Collecting Security Events last $sw days..."
    $SecurityEventsFolder = "$FolderCreation\SecurityEvents"
    New-Item -Path $SecurityEventsFolder -ItemType Directory -Force | Out-Null
    $ProcessOutput = "$SecurityEventsFolder\SecurityEvents.txt"
    $CSVExportLocation = "$CSVOutputFolder\SecurityEvents.csv"

    $filter = @{
        LogName   = 'Security'
        StartTime = (Get-Date).AddDays(-$sw)
    }
    $SecurityEvents = Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue
    if ($SecurityEvents) {
        $SecurityEvents | Format-List * | Out-File -Force -FilePath $ProcessOutput
        $SecurityEvents | Select-Object TimeCreated, Id, LevelDisplayName, Message, ProviderName, MachineName, UserId | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $CSVExportLocation -Encoding UTF8
    }
}

function Get-EventViewerFiles {
    Write-Host "Collecting Important Event Viewer Files..."
    $EventViewer = "$FolderCreation\Event Viewer"
    New-Item -Path $EventViewer -ItemType Directory -Force | Out-Null
    $evtxPath = "C:\Windows\System32\winevt\Logs"
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
            Copy-Item -Path $_.FullName -Destination $dest -Force -ErrorAction Stop
        } catch {
            try {
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
}

function Get-OfficeConnections {
    param(
        [Parameter(Mandatory=$false)][String]$UserSid
    )

    Write-Host "Collecting connections made from office applications..."
    $ConnectionFolder = "$FolderCreation\Connections"
    $OfficeConnection = "$ConnectionFolder\ConnectionsMadeByOffice.txt"
	$CSVExportLocation = "$CSVOutputFolder\OfficeConnections.csv"
	

    if($UserSid) {
        Get-ChildItem -Path "registry::HKEY_USERS\$UserSid\SOFTWARE\Microsoft\Office\16.0\Common\Internet\Server Cache" -ErrorAction SilentlyContinue | Out-File -Force -FilePath $OfficeConnection
		Get-ChildItem -Path "registry::HKEY_USERS\$UserSid\SOFTWARE\Microsoft\Office\16.0\Common\Internet\Server Cache" -ErrorAction SilentlyContinue | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $CSVExportLocation -Encoding UTF8
    }
    else {
        try {
            Get-ChildItem -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Internet\Server Cache" -ErrorAction Stop | Out-File -Force -FilePath $OfficeConnection
            Get-ChildItem -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Internet\Server Cache" -ErrorAction Stop | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $CSVExportLocation -Encoding UTF8
        } catch {
            Write-Host " Office Server Cache registry not found: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

function Get-NetworkShares {
    param(
        [Parameter(Mandatory=$false)][String]$UserSid
    )

    Write-Host "Collecting Active Network Shares..."
    $ConnectionFolder = "$FolderCreation\Connections"
    $ProcessOutput = "$ConnectionFolder\NetworkShares.txt"
	$CSVExportLocation = "$CSVOutputFolder\NetworkShares.csv"

    if($UserSid) {
        Get-ItemProperty -Path "registry::HKEY_USERS\$UserSid\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\" -ErrorAction SilentlyContinue | Format-Table | Out-File -Force -FilePath $ProcessOutput
		Get-ItemProperty -Path "registry::HKEY_USERS\$UserSid\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\" -ErrorAction SilentlyContinue | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $CSVExportLocation -Encoding UTF8
    }
    else {
        Get-ChildItem -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\" -ErrorAction SilentlyContinue | Format-Table | Out-File -Force -FilePath $ProcessOutput
		Get-ChildItem -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\" -ErrorAction SilentlyContinue | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $CSVExportLocation -Encoding UTF8
    }
}

function Get-SMBShares {
    Write-Host "Collecting SMB Shares..."
    $ConnectionFolder = "$FolderCreation\Connections"
    $ProcessOutput = "$ConnectionFolder\SMBShares.txt"
    Get-SmbShare | Out-File -Force -FilePath $ProcessOutput
	$CSVExportLocation = "$CSVOutputFolder\SMBShares.csv"
	Get-SmbShare | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $CSVExportLocation -Encoding UTF8
}

function Get-RDPSessions {
    Write-Host "Collecting RDS Sessions..."
    $ConnectionFolder = "$FolderCreation\Connections"
    $ProcessOutput = "$ConnectionFolder\RDPSessions.txt"
	$CSVExportLocation = "$CSVOutputFolder\RDPSessions.csv"
    qwinsta /server:localhost | Out-File -Force -FilePath $ProcessOutput
	(qwinsta /server:localhost) -split "\n" -replace '\s\s+', ',' | Out-File -FilePath $CSVExportLocation -Encoding UTF8
}

function Get-RemotelyOpenedFiles {
    Write-Host "Collecting Remotly Opened Files..."
    $ConnectionFolder = "$FolderCreation\Connections"
    $ProcessOutput = "$ConnectionFolder\RemotelyOpenedFiles.txt"
	$CSVExportLocation = "$CSVOutputFolder\RemotelyOpenedFiles.csv"
    openfiles | Out-File -Force -FilePath $ProcessOutput
	(openfiles) -split "\n" -replace '\s\s+', ',' | Out-File -FilePath $CSVExportLocation -Encoding UTF8
}

function Get-DNSCache {
    Write-Host "Collecting DNS Cache..."
    $ConnectionFolder = "$FolderCreation\Connections"
    $ProcessOutput = "$ConnectionFolder\DNSCache.txt"
    Get-DnsClientCache | Format-List | Out-File -Force -FilePath $ProcessOutput
	$CSVExportLocation = "$CSVOutputFolder\DNSCache.csv"
	Get-DnsClientCache | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $CSVExportLocation -Encoding UTF8
}

function Get-PowershellHistoryCurrentUser {
    Write-Host "Collecting Powershell History..."
    $PowershellConsoleHistory = "$FolderCreation\PowerShellHistory"
    New-Item -Path $PowershellConsoleHistory -ItemType Directory -Force | Out-Null
    $PowershellHistoryOutput = "$PowershellConsoleHistory\PowershellHistoryCurrentUser.txt"
    Get-History | Out-File -Force -FilePath $PowershellHistoryOutput
    $CSVExportLocation = "$CSVOutputFolder\PowerShellHistory.csv"
	Get-History | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $CSVExportLocation -Encoding UTF8
}

function Get-PowershellConsoleHistory-AllUsers {
    Write-Host "Collection Console Powershell History All Users..."
    $PowershellConsoleHistory = "$FolderCreation\PowerShellHistory"
    # Specify the directory where user profiles are stored
    $usersDirectory = "C:\Users"
    # Get a list of all user directories in C:\Users
    $userDirectories = Get-ChildItem -Path $usersDirectory -Directory
    foreach ($userDir in $userDirectories) {
        $historyFilePath = Join-Path -Path $userDir.FullName -ChildPath "AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
        if (Test-Path -Path $historyFilePath -PathType Leaf) {
            $outputDirectory = Join-Path -Path $PowershellConsoleHistory -ChildPath $userDir.Name
            New-Item -Path $outputDirectory -ItemType Directory -Force | Out-Null
            Copy-Item -Path $historyFilePath -Destination $outputDirectory -Force
        }
    }
}    

function Get-RecentlyInstalledSoftwareEventLogs {
    Write-Host "Collecting Recently Installed Software EventLogs..."
    $ApplicationFolder = "$FolderCreation\Applications"
    New-Item -Path $ApplicationFolder -ItemType Directory -Force | Out-Null
    $ProcessOutput = "$ApplicationFolder\RecentlyInstalledSoftwareEventLogs.txt"
    Get-WinEvent -ProviderName msiinstaller -ErrorAction SilentlyContinue | Where-Object { $_.Id -eq 1033 } | Select-Object TimeCreated, Message | Format-List * | Out-File -Force -FilePath $ProcessOutput
	$CSVExportLocation = "$CSVOutputFolder\InstalledSoftware.csv"
	Get-WinEvent -ProviderName msiinstaller -ErrorAction SilentlyContinue | Where-Object { $_.Id -eq 1033 } | Select-Object TimeCreated, Message | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $CSVExportLocation -Encoding UTF8
}

function Get-RunningServices {
    Write-Host "Collecting Running Services..."
    $ApplicationFolder = "$FolderCreation\Services"
    New-Item -Path $ApplicationFolder -ItemType Directory -Force | Out-Null
    $ProcessOutput = "$ApplicationFolder\RunningServices.txt"
    Get-Service | Where-Object { $_.Status -eq "Running" } | Format-List | Out-File -Force -FilePath $ProcessOutput
	$CSVExportLocation = "$CSVOutputFolder\RunningServices.csv"
	Get-Service | Where-Object { $_.Status -eq "Running" } | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $CSVExportLocation -Encoding UTF8
}

function Get-ScheduledTasks {
    Write-Host "Collecting Scheduled Tasks..."
    $ScheduledTaskFolder = "$FolderCreation\ScheduledTask"
    New-Item -Path $ScheduledTaskFolder -ItemType Directory -Force | Out-Null
    $ProcessOutput = "$ScheduledTaskFolder\ScheduledTasksList.txt"
    Get-ScheduledTask | Where-Object { ($_.State -ne 'Disabled') -and (($null -eq $_.LastRunTime) -or ($_.LastRunTime -gt (Get-Date).AddDays(-7))) } | Format-List | Out-File -Force -FilePath $ProcessOutput
	$CSVExportLocation = "$CSVOutputFolder\ScheduledTasks.csv"
	Get-ScheduledTask | Where-Object { ($_.State -ne 'Disabled') -and (($null -eq $_.LastRunTime) -or ($_.LastRunTime -gt (Get-Date).AddDays(-7))) } | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $CSVExportLocation -Encoding UTF8
}

function Get-ScheduledTasksRunInfo {
    Write-Host "Collecting Scheduled Tasks Run Info..."
    $ScheduledTaskFolder = "$FolderCreation\ScheduledTask"
    $ProcessOutput = "$ScheduledTaskFolder\ScheduledTasksListRunInfo.txt"
	$CSVExportLocation = "$CSVOutputFolder\ScheduledTasksRunInfo.csv"
    Get-ScheduledTask | Where-Object { $_.State -ne "Disabled" } | Get-ScheduledTaskInfo | Out-File -Force -FilePath $ProcessOutput
	Get-ScheduledTask | Where-Object { $_.State -ne "Disabled" } | Get-ScheduledTaskInfo | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $CSVExportLocation -Encoding UTF8
}

function Get-ConnectedDevices {
    Write-Host "Collecting Information about Connected Devices..."
    $DeviceFolder = "$FolderCreation\ConnectedDevices"
    New-Item -Path $DeviceFolder -ItemType Directory -Force | Out-Null
    $ConnectedDevicesOutput = "$DeviceFolder\ConnectedDevices.csv"
    Get-PnpDevice | Export-Csv -NoTypeInformation -Path $ConnectedDevicesOutput
	$CSVExportLocation = "$CSVOutputFolder\ConnectedDevices.csv"
	Get-PnpDevice | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $CSVExportLocation -Encoding UTF8
}

function Get-ChromiumFiles {
    param(
        [Parameter(Mandatory=$true)][String]$Username
    )

    Write-Host "Collecting raw Chrome history and profile files..."
    $HistoryFolder = "$FolderCreation\Browsers\Chrome"
    New-Item -Path $HistoryFolder -ItemType Directory -Force | Out-Null

    $filesToCopy = @('Preferences', 'Secure Preferences', 'History', 'History-journal', 'Bookmarks', 'Login Data', 'Web Data')
    $dirsToCopy = @('IndexedDB', 'Sessions')

    $chromeBasePath = "C:\Users\$Username\AppData\Local\Google\Chrome\User Data"
    if (Test-Path $chromeBasePath) {
        $profiles = Get-ChildItem -Path $chromeBasePath -Directory -ErrorAction SilentlyContinue | Where-Object {
            (Test-Path (Join-Path $_.FullName "History")) -or (Test-Path (Join-Path $_.FullName "Preferences"))
        }
        foreach ($profile in $profiles) {
            $destpath = Join-Path $HistoryFolder $profile.Name
            New-Item -Path $destpath -ItemType Directory -Force | Out-Null
            foreach ($fname in $filesToCopy) {
                $srcfile = Join-Path $profile.FullName $fname
                if (Test-Path $srcfile) {
                    Copy-Item -Path $srcfile -Destination (Join-Path $destpath $fname) -Force -ErrorAction SilentlyContinue
                }
            }
            foreach ($reldir in $dirsToCopy) {
                $srcdir = Join-Path $profile.FullName $reldir
                if (Test-Path $srcdir) {
                    $targetDir = Join-Path $destpath $reldir
                    New-Item -Path $targetDir -ItemType Directory -Force | Out-Null
                    Copy-Item -Path "$srcdir\*" -Destination $targetDir -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }
}

function Get-EdgeFiles {
    param(
        [Parameter(Mandatory=$true)][String]$Username
    )

    Write-Host "Collecting raw Microsoft Edge history and profile files..."
    $HistoryFolder = "$FolderCreation\Browsers\Edge"
    New-Item -Path $HistoryFolder -ItemType Directory -Force | Out-Null

    $filesToCopy = @('Preferences', 'Secure Preferences', 'History', 'History-journal', 'Bookmarks', 'Login Data', 'Web Data')
    $dirsToCopy = @('IndexedDB', 'Sessions')

    $edgeBasePath = "C:\Users\$Username\AppData\Local\Microsoft\Edge\User Data"
    if (Test-Path $edgeBasePath) {
        $profiles = Get-ChildItem -Path $edgeBasePath -Directory -ErrorAction SilentlyContinue | Where-Object {
            (Test-Path (Join-Path $_.FullName "History")) -or (Test-Path (Join-Path $_.FullName "Preferences"))
        }
        foreach ($profile in $profiles) {
            $destpath = Join-Path $HistoryFolder $profile.Name
            New-Item -Path $destpath -ItemType Directory -Force | Out-Null
            foreach ($fname in $filesToCopy) {
                $srcfile = Join-Path $profile.FullName $fname
                if (Test-Path $srcfile) {
                    Copy-Item -Path $srcfile -Destination (Join-Path $destpath $fname) -Force -ErrorAction SilentlyContinue
                }
            }
            foreach ($reldir in $dirsToCopy) {
                $srcdir = Join-Path $profile.FullName $reldir
                if (Test-Path $srcdir) {
                    $targetDir = Join-Path $destpath $reldir
                    New-Item -Path $targetDir -ItemType Directory -Force | Out-Null
                    Copy-Item -Path "$srcdir\*" -Destination $targetDir -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }
}

function Get-BraveFiles {
    param(
        [Parameter(Mandatory=$true)][String]$Username
    )

    Write-Host "Collecting raw Brave history and profile files..."
    $HistoryFolder = "$FolderCreation\Browsers\Brave"
    New-Item -Path $HistoryFolder -ItemType Directory -Force | Out-Null

    $filesToCopy = @('Preferences', 'Secure Preferences', 'History', 'History-journal', 'Bookmarks', 'Login Data', 'Web Data')
    $dirsToCopy = @('IndexedDB', 'Sessions')

    $braveBasePath = "C:\Users\$Username\AppData\Local\BraveSoftware\Brave-Browser\User Data"
    if (Test-Path $braveBasePath) {
        $profiles = Get-ChildItem -Path $braveBasePath -Directory -ErrorAction SilentlyContinue | Where-Object {
            (Test-Path (Join-Path $_.FullName "History")) -or (Test-Path (Join-Path $_.FullName "Preferences"))
        }
        foreach ($profile in $profiles) {
            $destpath = Join-Path $HistoryFolder $profile.Name
            New-Item -Path $destpath -ItemType Directory -Force | Out-Null
            foreach ($fname in $filesToCopy) {
                $srcfile = Join-Path $profile.FullName $fname
                if (Test-Path $srcfile) {
                    Copy-Item -Path $srcfile -Destination (Join-Path $destpath $fname) -Force -ErrorAction SilentlyContinue
                }
            }
            foreach ($reldir in $dirsToCopy) {
                $srcdir = Join-Path $profile.FullName $reldir
                if (Test-Path $srcdir) {
                    $targetDir = Join-Path $destpath $reldir
                    New-Item -Path $targetDir -ItemType Directory -Force | Out-Null
                    Copy-Item -Path "$srcdir\*" -Destination $targetDir -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }
}

function Get-OperaFiles {
    param(
        [Parameter(Mandatory=$true)][String]$Username
    )

    Write-Host "Collecting raw Opera / Opera GX history and profile files..."
    $HistoryFolder = "$FolderCreation\Browsers\Opera"
    New-Item -Path $HistoryFolder -ItemType Directory -Force | Out-Null

    $filesToCopy = @('Preferences', 'Secure Preferences', 'History', 'History-journal', 'Bookmarks', 'Login Data', 'Web Data')
    $dirsToCopy = @('IndexedDB', 'Sessions')

    $operaRoamingBase = "C:\Users\$Username\AppData\Roaming\Opera Software"
    if (Test-Path $operaRoamingBase) {
        $flavors = Get-ChildItem -Path $operaRoamingBase -Directory -ErrorAction SilentlyContinue
        foreach ($flavor in $flavors) {
            if ((Test-Path (Join-Path $flavor.FullName "History")) -or (Test-Path (Join-Path $flavor.FullName "Preferences"))) {
                $destpath = Join-Path $HistoryFolder $flavor.Name
                New-Item -Path $destpath -ItemType Directory -Force | Out-Null
                foreach ($fname in $filesToCopy) {
                    $srcfile = Join-Path $flavor.FullName $fname
                    if (Test-Path $srcfile) {
                        Copy-Item -Path $srcfile -Destination (Join-Path $destpath $fname) -Force -ErrorAction SilentlyContinue
                    }
                }
                foreach ($reldir in $dirsToCopy) {
                    $srcdir = Join-Path $flavor.FullName $reldir
                    if (Test-Path $srcdir) {
                        $targetDir = Join-Path $destpath $reldir
                        New-Item -Path $targetDir -ItemType Directory -Force | Out-Null
                        Copy-Item -Path "$srcdir\*" -Destination $targetDir -Recurse -Force -ErrorAction SilentlyContinue
                    }
                }
            }
        }
    }
}

function Get-FirefoxFiles {
    param(
        [Parameter(Mandatory=$true)][String]$Username
    )

    if (Test-Path "C:\Users\$Username\AppData\Roaming\Mozilla\Firefox\Profiles\") {
        Write-Host "Collecting raw Firefox history and profile files..."
        $HistoryFolder = "$FolderCreation\Browsers\Firefox"
        New-Item -Path $HistoryFolder -ItemType Directory -Force | Out-Null

        $filesToCopy = @(
            'places.sqlite',
            'places.sqlite-wal',
            'places.sqlite-shm',
            'cookies.sqlite',
            'cookies.sqlite-wal',
            'formhistory.sqlite',
            'permissions.sqlite',
            'content-prefs.sqlite',
            'favicons.sqlite',
            'logins.json',
            'key4.db',
            'cert9.db',
            'handlers.json',
            'extensions.json',
            'prefs.js',
            'sessionstore.jsonlz4'
        )

        $dirsToCopy = @(
            'extensions',
            'sessionstore-backups'
        )

        Get-ChildItem "C:\Users\$Username\AppData\Roaming\Mozilla\Firefox\Profiles\" -Directory -ErrorAction SilentlyContinue | Where-Object {
            (Test-Path "$($_.FullName)\places.sqlite")
        } | ForEach-Object {
            $srcpath = $_.FullName
            $destpath = Join-Path $HistoryFolder $_.Name
            New-Item -Path $destpath -ItemType Directory -Force | Out-Null
            
            foreach ($file in $filesToCopy) {
                $srcfile = Join-Path $srcpath $file
                if (Test-Path $srcfile) {
                    Copy-Item -Path $srcfile -Destination (Join-Path $destpath $file) -Force -ErrorAction SilentlyContinue
                }
            }

            foreach ($dir in $dirsToCopy) {
                $srcdir = Join-Path $srcpath $dir
                if (Test-Path $srcdir) {
                    $targetDir = Join-Path $destpath $dir
                    New-Item -Path $targetDir -ItemType Directory -Force | Out-Null
                    Copy-Item -Path "$srcdir\*" -Destination $targetDir -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }
}

function Get-MPLogs {
    Write-Host "Collecting MPLogs..."
    $MPLogFolder = "$FolderCreation\MPLogs"
    New-Item -Path $MPLogFolder -ItemType Directory -Force | Out-Null
    $MPLogLocation = "C:\ProgramData\Microsoft\Windows Defender\Support\"
    $MPListFiles = Get-ChildItem -Path $MPLogLocation -Name "*.log"
    foreach ($file in $MPListFiles){
    Copy-Item -Path $MPLogLocation$file -Destination $MPLogFolder
    }
}

function Get-DefenderExclusions {
	Write-Host "Collecting Defender Exclusions..."
	$DefenderExclusionFolder = "$FolderCreation\DefenderExclusions"
	New-Item -Path $DefenderExclusionFolder -ItemType Directory -Force | Out-Null
	Get-MpPreference | Select-Object -ExpandProperty ExclusionPath | Out-File -Force -FilePath "$DefenderExclusionFolder\ExclusionPath.txt"
	Get-MpPreference | Select-Object -ExpandProperty ExclusionExtension | Out-File -Force -FilePath "$DefenderExclusionFolder\ExclusionExtension.txt"
	Get-MpPreference | Select-Object -ExpandProperty ExclusionIpAddress | Out-File -Force -FilePath "$DefenderExclusionFolder\ExclusionIpAddress.txt"
	Get-MpPreference | Select-Object -ExpandProperty ExclusionProcess | Out-File -Force -FilePath "$DefenderExclusionFolder\ExclusionProcess.txt"
	
	$CSVExportLocation = "$CSVOutputFolder\DefenderExclusions.csv"
	$ExclusionPaths = (Get-MpPreference | Select-Object -ExpandProperty ExclusionPath) -join "`n"
	$ExclusionExtensions = (Get-MpPreference | Select-Object -ExpandProperty ExclusionExtension) -join "`n"
	$ExclusionIPAddresses = (Get-MpPreference | Select-Object -ExpandProperty ExclusionIpAddress) -join "`n"
	$ExclusionProcesses = (Get-MpPreference | Select-Object -ExpandProperty ExclusionProcess) -join "`n"

	# Combine all results into a single array
	$combinedData = $ExclusionPaths, $ExclusionExtensions, $ExclusionIPAddresses, $ExclusionProcesses
	$combinedData -split "\n" -replace '\s\s+', ',' | Out-File -FilePath $CSVExportLocation -Encoding UTF8
}

function Get-RegistryHives {
    Write-Host "Collecting System and User Registry Hives..."
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
    Write-Host "Write results to $FolderCreation.zip..."
    Compress-Archive -Force -LiteralPath $FolderCreation -DestinationPath "$FolderCreation.zip"
}

#Run all functions that do not require admin priviliges
function Run-WithoutAdminPrivilege {
    param(
        [Parameter(Mandatory=$false)][String]$UserSid,
        [Parameter(Mandatory=$false)][String]$Username
    )

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
    if($Username) {
        Get-ChromiumFiles -Username $Username
        Get-EdgeFiles -Username $Username
        Get-BraveFiles -Username $Username
        Get-OperaFiles -Username $Username
        Get-FirefoxFiles -Username $Username
    }
}

#Run all functions that do require admin priviliges
function Run-WithAdminPrivilges {
    Get-SecurityEventCount $sw
    Get-SecurityEvents $sw
    Get-RemotelyOpenedFiles
    Get-ShadowCopies
    Get-EventViewerFiles
	Get-MPLogs
	Get-DefenderExclusions
    Get-PowershellConsoleHistory-AllUsers
    Get-RegistryHives
}

Run-WithoutAdminPrivilege -UserSid $currentUserSid -Username $currentUsername
if ($IsAdmin) {
    Run-WithAdminPrivilges
}

Zip-Results
