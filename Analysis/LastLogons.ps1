<#
.SYNOPSIS
    Audits recent user logons using Security Event IDs 4624 (Successful Logon) and 4648 (Explicit Logon).

.DESCRIPTION
    Extracts logon events with accurate LogonType decoding (Interactive, Network, RDP, Service, etc.),
    target user names, domains, caller processes, and source IP addresses.

.PARAMETER MaxEvents
    The maximum number of logon events to inspect (default: 25).

.PARAMETER OutputDir
    Optional output directory for CSV export.

.PARAMETER ExportCsv
    Export the logon analysis table to a CSV file.

.EXAMPLE
    .\LastLogons.ps1

.EXAMPLE
    .\LastLogons.ps1 -MaxEvents 50 -ExportCsv
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [int]$MaxEvents = 25,

    [Parameter(Mandatory = $false)]
    [string]$OutputDir,

    [Parameter(Mandatory = $false)]
    [switch]$ExportCsv
)

# Verify Administrator Privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "Administrator privileges are required to query the Security event log. Please run PowerShell as Administrator."
    return
}

$logonTypeMap = @{
    0  = "System"
    2  = "Interactive (Console)"
    3  = "Network (SMB/RPC/WMI)"
    4  = "Batch"
    5  = "Service"
    7  = "Unlock"
    8  = "NetworkCleartext"
    9  = "NewCredentials (Runas)"
    10 = "RemoteInteractive (RDP)"
    11 = "CachedInteractive"
}

Write-Host "===========================================================" -ForegroundColor Cyan
Write-Host "          Recent User Logons Auditor (4624 / 4648)" -ForegroundColor Cyan
Write-Host "===========================================================" -ForegroundColor Cyan

try {
    $logonEvents = Get-WinEvent -LogName 'Security' -FilterXPath "*[System[EventID=4624 or EventID=4648]]" -MaxEvents $MaxEvents -ErrorAction Stop
} catch {
    Write-Warning "Could not query Security logon events: $($_.Exception.Message)"
    return
}

$results = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($logonEvent in $logonEvents) {
    $xml = [xml]$logonEvent.ToXml()
    $eventData = @{}
    foreach ($data in $xml.Event.EventData.Data) {
        if ($data.Name) {
            $eventData[$data.Name] = $data.'#text'
        }
    }

    $eventId = $logonEvent.Id
    $time = $logonEvent.TimeCreated
    $targetUser = $eventData["TargetUserName"]
    $targetDomain = $eventData["TargetDomainName"]
    $targetLogonId = $eventData["TargetLogonId"]
    $workstation = $eventData["WorkstationName"]
    $sourceIp = $eventData["IpAddress"]
    $processName = $eventData["ProcessName"]

    $typeCode = $eventData["LogonType"]
    $logonType = if ($eventId -eq 4648) { 
        "Explicit Credentials (4648)" 
    } elseif ($typeCode -and $logonTypeMap.ContainsKey([int]$typeCode)) { 
        $logonTypeMap[[int]$typeCode] 
    } else { 
        "Type $typeCode" 
    }

    # Skip noise accounts if desired
    if ($targetUser -in @("SYSTEM", "NETWORK SERVICE", "LOCAL SERVICE", "ANONYMOUS LOGON", "DWM-1", "DWM-2", "UMFD-0", "UMFD-1")) {
        continue
    }

    $results.Add([PSCustomObject]@{
        TimeCreated    = $time
        EventID        = $eventId
        TargetUser     = "$targetDomain\$targetUser"
        LogonType      = $logonType
        SourceIp       = if ($sourceIp -and $sourceIp -ne "-") { $sourceIp } else { "Local / Loopback" }
        Workstation    = $workstation
        ProcessName    = if ($processName) { Split-Path $processName -Leaf } else { "-" }
        LogonId        = $targetLogonId
    })
}

$results | Format-Table -Property TimeCreated, EventID, TargetUser, LogonType, SourceIp, Workstation, ProcessName -AutoSize

if ($ExportCsv) {
    if (-not $OutputDir) {
        $OutputDir = Get-Location
    } else {
        New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
    }
    $csvPath = Join-Path $OutputDir "RecentLogons-$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Host "[+] Exported $($results.Count) logons to: $csvPath" -ForegroundColor Green
}
