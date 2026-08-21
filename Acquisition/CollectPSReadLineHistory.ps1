<#
.Description: Collects PowerShell PSReadLine interactive command line history files (ConsoleHost_history.txt) across all or targeted user profiles.
.Documentation: In DFIR investigations, PSReadLine history contains the exact interactive commands executed by attackers or administrators, including downloaded scripts, credentials, or lateral movement commands.
.Required Permissions: Administrator (for -AllUsers or other user profiles) / User (for current user)

.Example:
    .\CollectPSReadLineHistory.ps1
    .\CollectPSReadLineHistory.ps1 -AllUsers
    .\CollectPSReadLineHistory.ps1 -Username "Belk0ruh"
    .\CollectPSReadLineHistory.ps1 -OutputDir "C:\IR\PSHistory"
#>

param (
    [String]$Username,
    [Switch]$AllUsers,
    [String]$OutputDir
)

if (-not $OutputDir) {
    $OutputDir = Join-Path -Path (Get-Location) -ChildPath "PSReadLineHistory"
}

New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null

Write-Host "===========================================================" -ForegroundColor Cyan
Write-Host "      PowerShell PSReadLine Command History Collector" -ForegroundColor Cyan
Write-Host "      Output Directory: $OutputDir" -ForegroundColor Cyan
Write-Host "===========================================================" -ForegroundColor Cyan

function Get-UserProfilesToProcess {
    param([string]$TargetUser, [switch]$ProcessAll)

    $profiles = @()
    if ($TargetUser) {
        $userReg = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' -ErrorAction SilentlyContinue |
            Where-Object { $_.ProfileImagePath -and ($_.ProfileImagePath -like "*\$TargetUser") }
        if ($userReg) {
            $profiles += [PSCustomObject]@{
                Username = Split-Path -Leaf $userReg.ProfileImagePath
                Path     = $userReg.ProfileImagePath
            }
        } else {
            Write-Warning "User profile for '$TargetUser' not found in registry."
        }
    } elseif ($ProcessAll) {
        $regProfiles = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' -ErrorAction SilentlyContinue |
            Where-Object { $_.ProfileImagePath -and (Test-Path $_.ProfileImagePath) }
        foreach ($p in $regProfiles) {
            $uName = Split-Path -Leaf $p.ProfileImagePath
            if ($uName -notmatch '^(systemprofile|LocalService|NetworkService)$') {
                $profiles += [PSCustomObject]@{
                    Username = $uName
                    Path     = $p.ProfileImagePath
                }
            }
        }
    } else {
        $profiles += [PSCustomObject]@{
            Username = $env:USERNAME
            Path     = $env:USERPROFILE
        }
    }
    return $profiles
}

$profilesToProcess = Get-UserProfilesToProcess -TargetUser $Username -ProcessAll:$AllUsers

if (-not $profilesToProcess -or $profilesToProcess.Count -eq 0) {
    Write-Warning "No user profile found to collect PSReadLine history."
    return
}

$collectedCount = 0
$summaryResults = @()

foreach ($profile in $profilesToProcess) {
    $uName = $profile.Username
    $uPath = $profile.Path
    $historyRelativePath = "AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    $fullHistoryPath = Join-Path -Path $uPath -ChildPath $historyRelativePath

    Write-Host "`nChecking user profile: $uName ($uPath)" -ForegroundColor Yellow

    if (Test-Path -LiteralPath $fullHistoryPath) {
        try {
            $fileItem = Get-Item -LiteralPath $fullHistoryPath -ErrorAction Stop
            $lineCount = (Get-Content -LiteralPath $fullHistoryPath -ErrorAction SilentlyContinue | Measure-Object).Count
            $destFileName = "${uName}_ConsoleHost_history.txt"
            $destFilePath = Join-Path -Path $OutputDir -ChildPath $destFileName

            Copy-Item -LiteralPath $fullHistoryPath -Destination $destFilePath -Force -ErrorAction Stop

            Write-Host " [+] PSReadLine history found ($lineCount lines, $($fileItem.Length) bytes)" -ForegroundColor Green
            Write-Host "     Saved to: $destFilePath" -ForegroundColor Green

            $collectedCount++
            $summaryResults += [PSCustomObject]@{
                Username     = $uName
                LinesCount   = $lineCount
                FileSizeBytes= $fileItem.Length
                LastModified = $fileItem.LastWriteTimeUtc.ToString("o")
                SourcePath   = $fullHistoryPath
                Destination  = $destFilePath
            }
        } catch {
            Write-Warning " Failed to copy PSReadLine history for $($uName): $($_.Exception.Message)"
        }
    } else {
        Write-Host " [-] No PSReadLine history file found at: $fullHistoryPath" -ForegroundColor DarkGray
    }
}

# Export Summary CSV
if ($summaryResults.Count -gt 0) {
    $summaryCsv = Join-Path -Path $OutputDir -ChildPath "PSReadLine_Summary.csv"
    $summaryResults | Export-Csv -Path $summaryCsv -NoTypeInformation -Encoding UTF8
    Write-Host "`nSummary CSV written to: $summaryCsv" -ForegroundColor Cyan
}

Write-Host "`nCompleted! Collected $collectedCount PSReadLine history file(s)." -ForegroundColor Cyan
