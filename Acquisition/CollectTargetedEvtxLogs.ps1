<#
.Description: Collects targeted, high-fidelity Windows Event Log (.evtx) files for DFIR analysis.
.Documentation: Directly copies key forensic event logs (PowerShell ScriptBlock logging, Sysmon, TaskScheduler, RDP sessions, Defender, WMI, BITS, Security, System, etc.) into an output folder.
.Required Permissions: Administrator

.Example:
    .\CollectTargetedEvtxLogs.ps1
    .\CollectTargetedEvtxLogs.ps1 -OutputDir "C:\IR\EVTX_Logs"
    .\CollectTargetedEvtxLogs.ps1 -IncludeAllChannels
#>

param (
    [String]$OutputDir,
    [Switch]$IncludeAllChannels
)

# Verify Administrator Privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "Administrator privileges are required to copy locked Windows Event Log (.evtx) files. Please run PowerShell as Administrator."
    return
}

if (-not $OutputDir) {
    $OutputDir = Join-Path -Path (Get-Location) -ChildPath "TargetedEvtxLogs"
}

New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null

Write-Host "===========================================================" -ForegroundColor Cyan
Write-Host "         High-Fidelity Windows EVTX Logs Collector" -ForegroundColor Cyan
Write-Host "         Output Directory: $OutputDir" -ForegroundColor Cyan
Write-Host "===========================================================" -ForegroundColor Cyan

$evtxBasePath = "$env:SystemRoot\System32\Winevt\Logs"

# List of high-priority DFIR EVTX log files
$targetLogs = @(
    @{ Name = "PowerShell-Operational"; File = "Microsoft-Windows-PowerShell%4Operational.evtx"; Category = "Execution" },
    @{ Name = "Sysmon-Operational"; File = "Microsoft-Windows-Sysmon%4Operational.evtx"; Category = "Execution" },
    @{ Name = "TaskScheduler-Operational"; File = "Microsoft-Windows-TaskScheduler%4Operational.evtx"; Category = "Persistence" },
    @{ Name = "TaskScheduler-Maintenance"; File = "Microsoft-Windows-TaskScheduler%4Maintenance.evtx"; Category = "Persistence" },
    @{ Name = "TerminalServices-LocalSessionManager"; File = "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx"; Category = "LateralMovement" },
    @{ Name = "TerminalServices-RemoteConnectionManager"; File = "Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx"; Category = "LateralMovement" },
    @{ Name = "TerminalServices-RdpCoreTS"; File = "Microsoft-Windows-TerminalServices-RdpCoreTS%4Operational.evtx"; Category = "LateralMovement" },
    @{ Name = "Defender-Operational"; File = "Microsoft-Windows-Windows Defender%4Operational.evtx"; Category = "Security" },
    @{ Name = "Defender-WHC"; File = "Microsoft-Windows-Windows Defender%4WHC.evtx"; Category = "Security" },
    @{ Name = "WMI-Activity"; File = "Microsoft-Windows-WMI-Activity%4Operational.evtx"; Category = "Persistence" },
    @{ Name = "Bits-Client"; File = "Microsoft-Windows-Bits-Client%4Operational.evtx"; Category = "DefenseEvasion" },
    @{ Name = "CodeIntegrity"; File = "Microsoft-Windows-CodeIntegrity%4Operational.evtx"; Category = "Security" },
    @{ Name = "DNS-Client"; File = "Microsoft-Windows-DNS-Client%4Operational.evtx"; Category = "Network" },
    @{ Name = "SMBClient-Security"; File = "Microsoft-Windows-SMBClient%4Security.evtx"; Category = "LateralMovement" },
    @{ Name = "SMBServer-Security"; File = "Microsoft-Windows-SMBServer%4Security.evtx"; Category = "LateralMovement" },
    @{ Name = "NTLM-Operational"; File = "Microsoft-Windows-NTLM%4Operational.evtx"; Category = "Authentication" },
    @{ Name = "Kerberos-Operational"; File = "Microsoft-Windows-Kerberos-Key-Distribution-Center%4Operational.evtx"; Category = "Authentication" },
    @{ Name = "Windows-Firewall"; File = "Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall.evtx"; Category = "Network" },
    @{ Name = "System"; File = "System.evtx"; Category = "Core" },
    @{ Name = "Security"; File = "Security.evtx"; Category = "Core" },
    @{ Name = "Application"; File = "Application.evtx"; Category = "Core" }
)

function Copy-EvtxFileSafely {
    param (
        [string]$SourcePath,
        [string]$DestinationPath
    )

    try {
        # Use FileStream with ReadWrite sharing to safely read locked active EVTX files
        $sourceStream = [System.IO.File]::Open($SourcePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $destStream = [System.IO.File]::Create($DestinationPath)
        $sourceStream.CopyTo($destStream)
        $destStream.Close()
        $destStream.Dispose()
        $sourceStream.Close()
        $sourceStream.Dispose()
        return $true
    } catch {
        # Fallback to wevtutil export if direct read stream fails
        try {
            $logName = (Get-Item -LiteralPath $SourcePath).BaseName.Replace("%4", "/")
            $proc = Start-Process -FilePath "wevtutil.exe" -ArgumentList "epl `"$logName`" `"$DestinationPath`" /ow:true" -Wait -NoNewWindow -PassThru
            return ($proc.ExitCode -eq 0 -and (Test-Path -LiteralPath $DestinationPath))
        } catch {
            return $false
        }
    }
}

$copiedCount = 0
$summaryResults = @()

foreach ($log in $targetLogs) {
    $sourceFile = Join-Path -Path $evtxBasePath -ChildPath $log.File
    $catFolder = Join-Path -Path $OutputDir -ChildPath $log.Category
    New-Item -Path $catFolder -ItemType Directory -Force | Out-Null
    $destFile = Join-Path -Path $catFolder -ChildPath $log.File

    Write-Host "Copying $($log.Name) ($($log.Category))..." -NoNewline

    if (Test-Path -LiteralPath $sourceFile) {
        $sourceItem = Get-Item -LiteralPath $sourceFile
        $copySuccess = Copy-EvtxFileSafely -SourcePath $sourceFile -DestinationPath $destFile

        if ($copySuccess -and (Test-Path -LiteralPath $destFile)) {
            $destItem = Get-Item -LiteralPath $destFile
            $sizeKB = [math]::Round(($destItem.Length / 1KB), 2)
            Write-Host " [OK] ($sizeKB KB)" -ForegroundColor Green
            $copiedCount++

            $summaryResults += [PSCustomObject]@{
                LogName       = $log.Name
                Category      = $log.Category
                FileName      = $log.File
                SizeBytes     = $destItem.Length
                LastModified  = $sourceItem.LastWriteTimeUtc.ToString("o")
                Status        = "Success"
            }
        } else {
            Write-Host " [FAILED]" -ForegroundColor Red
            $summaryResults += [PSCustomObject]@{
                LogName       = $log.Name
                Category      = $log.Category
                FileName      = $log.File
                SizeBytes     = 0
                LastModified  = $sourceItem.LastWriteTimeUtc.ToString("o")
                Status        = "Failed"
            }
        }
    } else {
        Write-Host " [NOT PRESENT]" -ForegroundColor DarkGray
    }
}

if ($IncludeAllChannels) {
    Write-Host "`nCopying all other available EVTX logs..." -ForegroundColor Yellow
    $allEvtx = Get-ChildItem -Path $evtxBasePath -Filter "*.evtx" -ErrorAction SilentlyContinue
    $otherFolder = Join-Path -Path $OutputDir -ChildPath "AllOtherChannels"
    New-Item -Path $otherFolder -ItemType Directory -Force | Out-Null

    foreach ($file in $allEvtx) {
        $destFile = Join-Path -Path $otherFolder -ChildPath $file.Name
        if (-not (Test-Path -LiteralPath $destFile)) {
            $res = Copy-EvtxFileSafely -SourcePath $file.FullName -DestinationPath $destFile
            if ($res) { $copiedCount++ }
        }
    }
}

# Export Summary CSV
if ($summaryResults.Count -gt 0) {
    $summaryCsv = Join-Path -Path $OutputDir -ChildPath "EVTX_Collection_Summary.csv"
    $summaryResults | Export-Csv -Path $summaryCsv -NoTypeInformation -Encoding UTF8
    Write-Host "`nSummary CSV written to: $summaryCsv" -ForegroundColor Cyan
}

Write-Host "`nCompleted! Successfully collected $copiedCount EVTX file(s)." -ForegroundColor Cyan
