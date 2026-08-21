<#
.SYNOPSIS
    Collects Windows Application, System, and Security Event Logs using Get-WinEvent.

.DESCRIPTION
    Extracts events from the core Windows event logs (Application, System, Security)
    with configurable time windows, max records, and streaming CSV export to avoid memory bloat.

.PARAMETER Days
    Number of past days to query (default: 2).

.PARAMETER MaxEventsPerLog
    Maximum number of events to retrieve per log channel (default: 5000).

.PARAMETER Channels
    List of log channels to query (default: Application, System, Security).

.PARAMETER OutputDir
    Destination directory for the exported CSV file.

.EXAMPLE
    .\CollectWindowsEvents.ps1 -Days 3

.EXAMPLE
    .\CollectWindowsEvents.ps1 -Days 7 -MaxEventsPerLog 10000 -OutputDir "C:\IR\EventLogs"
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [int]$Days = 2,

    [Parameter(Mandatory = $false)]
    [int]$MaxEventsPerLog = 5000,

    [Parameter(Mandatory = $false)]
    [string[]]$Channels = @('Application', 'System', 'Security'),

    [Parameter(Mandatory = $false)]
    [string]$OutputDir
)

# Verify Administrator Privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "Administrator privileges are required to query all Windows event logs. Please run as Administrator."
    return
}

if (-not $OutputDir) {
    $OutputDir = Get-Location
} else {
    New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
}

$ExecutionDate = Get-Date -Format "yyyy-MM-dd"
$OutputName = Join-Path $OutputDir "WindowsEvents-$ExecutionDate.csv"

Write-Host "===========================================================" -ForegroundColor Cyan
Write-Host "         Windows Core Event Logs Collector" -ForegroundColor Cyan
Write-Host "         Querying last $Days days across channels: $($Channels -join ', ')" -ForegroundColor Cyan
Write-Host "===========================================================" -ForegroundColor Cyan

$allEvents = [System.Collections.Generic.List[PSCustomObject]]::new()
$startTime = (Get-Date).AddDays(-$Days)

foreach ($logName in $Channels) {
    Write-Host "[*] Querying channel: $logName..." -ForegroundColor Yellow
    $filter = @{
        LogName   = $logName
        StartTime = $startTime
    }

    try {
        $events = if ($MaxEventsPerLog -gt 0) {
            Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEventsPerLog -ErrorAction Stop
        } else {
            Get-WinEvent -FilterHashtable $filter -ErrorAction Stop
        }

        foreach ($evt in $events) {
            $allEvents.Add([PSCustomObject]@{
                LogName          = $logName
                TimeCreated      = $evt.TimeCreated
                EventId          = $evt.Id
                LevelDisplayName = $evt.LevelDisplayName
                ProviderName     = $evt.ProviderName
                MachineName      = $evt.MachineName
                UserId           = $evt.UserId
                RecordId         = $evt.RecordId
                Message          = $evt.Message
            })
        }
        Write-Host " [+] Retrieved $($events.Count) events from $logName" -ForegroundColor Green
    } catch {
        Write-Warning " Channel ${logName}: $($_.Exception.Message)"
    }
}

if ($allEvents.Count -gt 0) {
    $allEvents | Export-Csv -Path $OutputName -NoTypeInformation -Encoding UTF8
    Write-Host "`n[+] Total $($allEvents.Count) events exported to: $OutputName" -ForegroundColor Green
} else {
    Write-Host "`n[-] No matching events found for the specified criteria." -ForegroundColor DarkGray
}
