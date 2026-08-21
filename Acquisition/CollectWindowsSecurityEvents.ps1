<#
.SYNOPSIS
    Collects Windows Security Event Logs using high-performance Get-WinEvent queries.

.DESCRIPTION
    Extracts security events (Logons 4624/4625, Process Creation 4688, Privilege Escalation, etc.)
    with time filtering and streaming CSV export. Compatible with PowerShell 5.1 and PowerShell 7+.

.PARAMETER Days
    Number of past days to query (default: 2).

.PARAMETER MaxEvents
    Maximum number of events to retrieve (optional).

.PARAMETER OutputDir
    Destination directory for the exported CSV file.

.EXAMPLE
    .\CollectWindowsSecurityEvents.ps1 -Days 7

.EXAMPLE
    .\CollectWindowsSecurityEvents.ps1 -Days 2 -MaxEvents 5000 -OutputDir "C:\IR\SecurityLogs"
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [int]$Days = 2,

    [Parameter(Mandatory = $false)]
    [int]$MaxEvents,

    [Parameter(Mandatory = $false)]
    [string]$OutputDir
)

# Verify Administrator Privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "Administrator privileges are required to query the Windows Security event log. Please run as Administrator."
    return
}

if (-not $OutputDir) {
    $OutputDir = Get-Location
} else {
    New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
}

$ExecutionDate = Get-Date -Format "yyyy-MM-dd"
$OutputName = Join-Path $OutputDir "SecurityEvents-$ExecutionDate.csv"

Write-Host "===========================================================" -ForegroundColor Cyan
Write-Host "       Windows Security Events Collector" -ForegroundColor Cyan
Write-Host "       Querying last $Days days of Security events..." -ForegroundColor Cyan
Write-Host "===========================================================" -ForegroundColor Cyan

$filter = @{
    LogName   = 'Security'
    StartTime = (Get-Date).AddDays(-$Days)
}

try {
    $eventsQuery = if ($MaxEvents -gt 0) {
        Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction Stop
    } else {
        Get-WinEvent -FilterHashtable $filter -ErrorAction Stop
    }

    $eventsQuery | 
        Select-Object TimeCreated, Id, LevelDisplayName, Message, ProviderName, MachineName, UserId, RecordId |
        Export-Csv -Path $OutputName -NoTypeInformation -Encoding UTF8

    Write-Host "[+] Successfully exported $($eventsQuery.Count) Security events to: $OutputName" -ForegroundColor Green
} catch {
    Write-Warning "Could not retrieve Security events: $($_.Exception.Message)"
}