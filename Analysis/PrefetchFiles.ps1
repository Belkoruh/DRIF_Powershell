<#
.SYNOPSIS
    Lists and analyzes Windows Prefetch (.pf) files for program execution timeline reconstruction.

.DESCRIPTION
    Enumerates prefetch files from C:\Windows\Prefetch, extracting filename, hash, CreationTime,
    and LastWriteTime (which corresponds to the latest execution timestamp).

.PARAMETER MaxFiles
    Maximum number of files to return (optional).

.PARAMETER Filter
    Filter by executable name (e.g. '*powershell*', '*cmd*').

.PARAMETER OutputDir
    Optional output directory for CSV export.

.PARAMETER ExportCsv
    Export the results to CSV.

.EXAMPLE
    .\PrefetchFiles.ps1

.EXAMPLE
    .\PrefetchFiles.ps1 -Filter "*powershell*"

.EXAMPLE
    .\PrefetchFiles.ps1 -ExportCsv
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [int]$MaxFiles,

    [Parameter(Mandatory = $false)]
    [string]$Filter = "*.pf",

    [Parameter(Mandatory = $false)]
    [string]$OutputDir,

    [Parameter(Mandatory = $false)]
    [switch]$ExportCsv
)

# Verify Administrator Privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "Administrator privileges are required to access 'C:\Windows\Prefetch'. Please run as Administrator."
    return
}

$PrefetchPath = 'C:\Windows\Prefetch'
if (-not (Test-Path $PrefetchPath)) {
    Write-Warning "Prefetch directory '$PrefetchPath' not found or Prefetching is disabled on this system."
    return
}

Write-Host "===========================================================" -ForegroundColor Cyan
Write-Host "         Windows Prefetch Execution Timeline Auditor" -ForegroundColor Cyan
Write-Host "===========================================================" -ForegroundColor Cyan

$files = Get-ChildItem -Path $PrefetchPath -Filter $Filter -File -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending

if ($MaxFiles -gt 0) {
    $files = $files | Select-Object -First $MaxFiles
}

$results = $files | ForEach-Object {
    $baseName = $_.BaseName
    $exeName = if ($baseName -match '^(.+)-[0-9A-Fa-f]{8}$') { $Matches[1] } else { $baseName }
    $hash = if ($baseName -match '-([0-9A-Fa-f]{8})$') { $Matches[1] } else { "-" }

    [PSCustomObject]@{
        ExecutableName = $exeName
        PrefetchHash   = $hash
        PrefetchFile   = $_.Name
        LastExecution  = $_.LastWriteTime
        CreationTime   = $_.CreationTime
        SizeKB         = [math]::Round($_.Length / 1KB, 1)
    }
}

$results | Format-Table -Property ExecutableName, PrefetchHash, LastExecution, CreationTime, SizeKB -AutoSize

if ($ExportCsv -and $results.Count -gt 0) {
    if (-not $OutputDir) {
        $OutputDir = Get-Location
    } else {
        New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
    }
    $csvPath = Join-Path $OutputDir "PrefetchTimeline-$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Host "[+] Exported $($results.Count) prefetch entries to: $csvPath" -ForegroundColor Green
}