<#
.Description: Collects User Activity Artifacts (LNK shortcuts, Jump Lists, Recent Files) for DFIR investigations.
.Documentation: Reconstructs files and folders accessed by users, network share interactions (\\server\share), and removable drive usage with timestamps.
.Required Permissions: Administrator (for -AllUsers or other users) / User (for current user)

.Example:
    .\CollectUserActivity.ps1
    .\CollectUserActivity.ps1 -AllUsers
    .\CollectUserActivity.ps1 -Username "Belk0ruh"
    .\CollectUserActivity.ps1 -OutputDir "C:\IR\UserActivity"
#>

param (
    [String]$Username,
    [Switch]$AllUsers,
    [String]$OutputDir
)

if (-not $OutputDir) {
    $OutputDir = Join-Path -Path (Get-Location) -ChildPath "UserActivityArtifacts"
}

New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null

Write-Host "===========================================================" -ForegroundColor Cyan
Write-Host "     User Activity Forensics Collector (LNK / JumpLists)" -ForegroundColor Cyan
Write-Host "     Output Directory: $OutputDir" -ForegroundColor Cyan
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
            Write-Warning "User profile for '$TargetUser' not found."
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
$collectedFiles = @()

foreach ($profile in $profilesToProcess) {
    $uName = $profile.Username
    $uPath = $profile.Path
    $userOutDir = Join-Path -Path $OutputDir -ChildPath "Users\$uName"
    New-Item -Path $userOutDir -ItemType Directory -Force | Out-Null

    Write-Host "`nProcessing profile: $uName ($uPath)" -ForegroundColor Yellow

    $recentPath = Join-Path -Path $uPath -ChildPath "AppData\Roaming\Microsoft\Windows\Recent"

    if (Test-Path -LiteralPath $recentPath) {
        # 1. LNK Files
        $lnkOutDir = Join-Path -Path $userOutDir -ChildPath "LNK_Files"
        New-Item -Path $lnkOutDir -ItemType Directory -Force | Out-Null
        $lnkFiles = Get-ChildItem -LiteralPath $recentPath -Filter "*.lnk" -File -ErrorAction SilentlyContinue

        if ($lnkFiles) {
            Write-Host " [+] Found $($lnkFiles.Count) LNK shortcut file(s)" -ForegroundColor Green
            foreach ($lnk in $lnkFiles) {
                $dest = Join-Path -Path $lnkOutDir -ChildPath $lnk.Name
                Copy-Item -LiteralPath $lnk.FullName -Destination $dest -Force -ErrorAction SilentlyContinue
                $collectedFiles += [PSCustomObject]@{
                    Username     = $uName
                    ArtifactType = "LNK"
                    FileName     = $lnk.Name
                    SizeBytes    = $lnk.Length
                    LastModified = $lnk.LastWriteTimeUtc.ToString("o")
                    CreatedTime  = $lnk.CreationTimeUtc.ToString("o")
                    SourcePath   = $lnk.FullName
                }
            }
        }

        # 2. AutomaticDestinations Jump Lists
        $autoDestPath = Join-Path -Path $recentPath -ChildPath "AutomaticDestinations"
        if (Test-Path -LiteralPath $autoDestPath) {
            $autoDestOutDir = Join-Path -Path $userOutDir -ChildPath "JumpLists_Automatic"
            New-Item -Path $autoDestOutDir -ItemType Directory -Force | Out-Null
            $autoFiles = Get-ChildItem -LiteralPath $autoDestPath -Filter "*.automaticDestinations-ms" -File -ErrorAction SilentlyContinue

            if ($autoFiles) {
                Write-Host " [+] Found $($autoFiles.Count) Automatic JumpList file(s)" -ForegroundColor Green
                foreach ($af in $autoFiles) {
                    $dest = Join-Path -Path $autoDestOutDir -ChildPath $af.Name
                    Copy-Item -LiteralPath $af.FullName -Destination $dest -Force -ErrorAction SilentlyContinue
                    $collectedFiles += [PSCustomObject]@{
                        Username     = $uName
                        ArtifactType = "AutomaticDestinations"
                        FileName     = $af.Name
                        SizeBytes    = $af.Length
                        LastModified = $af.LastWriteTimeUtc.ToString("o")
                        CreatedTime  = $af.CreationTimeUtc.ToString("o")
                        SourcePath   = $af.FullName
                    }
                }
            }
        }

        # 3. CustomDestinations Jump Lists
        $customDestPath = Join-Path -Path $recentPath -ChildPath "CustomDestinations"
        if (Test-Path -LiteralPath $customDestPath) {
            $customDestOutDir = Join-Path -Path $userOutDir -ChildPath "JumpLists_Custom"
            New-Item -Path $customDestOutDir -ItemType Directory -Force | Out-Null
            $customFiles = Get-ChildItem -LiteralPath $customDestPath -Filter "*.customDestinations-ms" -File -ErrorAction SilentlyContinue

            if ($customFiles) {
                Write-Host " [+] Found $($customFiles.Count) Custom JumpList file(s)" -ForegroundColor Green
                foreach ($cf in $customFiles) {
                    $dest = Join-Path -Path $customDestOutDir -ChildPath $cf.Name
                    Copy-Item -LiteralPath $cf.FullName -Destination $dest -Force -ErrorAction SilentlyContinue
                    $collectedFiles += [PSCustomObject]@{
                        Username     = $uName
                        ArtifactType = "CustomDestinations"
                        FileName     = $cf.Name
                        SizeBytes    = $cf.Length
                        LastModified = $cf.LastWriteTimeUtc.ToString("o")
                        CreatedTime  = $cf.CreationTimeUtc.ToString("o")
                        SourcePath   = $cf.FullName
                    }
                }
            }
        }
    } else {
        Write-Host " [-] Recent directory not found: $recentPath" -ForegroundColor DarkGray
    }
}

# Export Inventory CSV
if ($collectedFiles.Count -gt 0) {
    $inventoryCsv = Join-Path -Path $OutputDir -ChildPath "UserActivity_Inventory.csv"
    $collectedFiles | Export-Csv -Path $inventoryCsv -NoTypeInformation -Encoding UTF8
    Write-Host "`nInventory CSV written to: $inventoryCsv" -ForegroundColor Cyan
}

Write-Host "`nCompleted! Collected $($collectedFiles.Count) user activity artifact(s)." -ForegroundColor Cyan
