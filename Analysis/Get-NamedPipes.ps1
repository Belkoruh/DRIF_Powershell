<#
.Description: Enumerates active Windows Named Pipes and highlights patterns associated with C2 frameworks and lateral movement tools.
.Documentation: Threat actors and post-exploitation tools (Cobalt Strike, Sliver, Meterpreter, PsExec) create named pipes for IPC, lateral movement (SMB beacons), and privilege escalation.
.Required Permissions: User / Administrator

.Example:
    .\Get-NamedPipes.ps1
    .\Get-NamedPipes.ps1 -OutputDir "C:\IR\Network"
    .\Get-NamedPipes.ps1 -ExportCsv
#>

param (
    [String]$OutputDir,
    [Switch]$ExportCsv
)

if (-not $OutputDir -and $ExportCsv) {
    $OutputDir = Join-Path -Path (Get-Location) -ChildPath "NamedPipesAnalysis"
}
if ($OutputDir) {
    New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
}

Write-Host "===========================================================" -ForegroundColor Cyan
Write-Host "          Windows Named Pipes Enumeration Tool" -ForegroundColor Cyan
Write-Host "===========================================================" -ForegroundColor Cyan

# Known suspicious / C2 pipe patterns (Regex)
$suspiciousPatterns = @(
    @{ Pattern = '^msagent_\w+'; Description = "Cobalt Strike Default Pipe (msagent_*)" },
    @{ Pattern = '^status_\w+'; Description = "Cobalt Strike SMB Beacon Pipe" },
    @{ Pattern = '^msse-\w+'; Description = "Cobalt Strike Secondary Pipe" },
    @{ Pattern = '^postex_\w+'; Description = "Cobalt Strike Post-Exploitation Pipe" },
    @{ Pattern = '^spoolss_\w+'; Description = "Cobalt Strike / PrintSpoofer Impersonation Pipe" },
    @{ Pattern = '^psexesvc'; Description = "PsExec Service Named Pipe" },
    @{ Pattern = '^paexec'; Description = "PAExec Lateral Movement Pipe" },
    @{ Pattern = '^csexec'; Description = "CSExec Lateral Movement Pipe" },
    @{ Pattern = '^remcom'; Description = "RemCom Remote Execution Pipe" },
    @{ Pattern = '^sliver'; Description = "Sliver C2 Named Pipe" },
    @{ Pattern = '^meterpreter'; Description = "Metasploit Meterpreter Named Pipe" },
    @{ Pattern = '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'; Description = "GUID Named Pipe (Potential Beacon / Injected Payload)" }
)

$pipeList = @()
try {
    $rawPipes = [System.IO.Directory]::GetFiles("\\.\\pipe\\")
} catch {
    Write-Error "Failed to enumerate named pipes: $($_.Exception.Message)"
    return
}

Write-Host "Found $($rawPipes.Count) active Named Pipe(s) on host:`n" -ForegroundColor Yellow

$suspiciousCount = 0

foreach ($rawPipe in $rawPipes) {
    $pipeName = $rawPipe.Replace("\\.\pipe\", "")
    $isSuspicious = $false
    $matchDescription = "Standard / System"

    foreach ($sp in $suspiciousPatterns) {
        if ($pipeName -match $sp.Pattern) {
            $isSuspicious = $true
            $matchDescription = $sp.Description
            break
        }
    }

    if ($isSuspicious) {
        $suspiciousCount++
        Write-Host " [!] SUSPICIOUS PIPE: $pipeName" -ForegroundColor Red
        Write-Host "     Indicator: $matchDescription" -ForegroundColor Red
    } else {
        Write-Host " [.] $pipeName" -ForegroundColor DarkGray
    }

    $pipeList += [PSCustomObject]@{
        PipeName    = $pipeName
        FullPath    = $rawPipe
        IsSuspicious= $isSuspicious
        Category    = $matchDescription
    }
}

# CSV Export
if ($OutputDir) {
    $csvPath = Join-Path -Path $OutputDir -ChildPath "NamedPipes.csv"
    $pipeList | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Host "`nNamed Pipes inventory exported to: $csvPath" -ForegroundColor Cyan
}

Write-Host "`nSummary: Total Pipes: $($pipeList.Count) | Suspicious Detections: $suspiciousCount" -ForegroundColor Cyan
