<#
.Description: Collects RDP Forensic Artifacts (Outbound Connection History, Saved Servers, and Bitmap Cache files).
.Documentation: Reconstructs remote desktop activity, identifying destination servers/IPs accessed by users and preserving bitmap caches for GUI visual reconstruction.
.Required Permissions: User (for current user) / Administrator (for -AllUsers)

.Example:
    .\CollectRDPArtifacts.ps1
    .\CollectRDPArtifacts.ps1 -AllUsers
    .\CollectRDPArtifacts.ps1 -Username "Belk0ruh"
    .\CollectRDPArtifacts.ps1 -OutputDir "C:\IR\RDP"
#>

param (
    [String]$Username,
    [Switch]$AllUsers,
    [String]$OutputDir
)

if (-not $OutputDir) {
    $OutputDir = Join-Path -Path (Get-Location) -ChildPath "RDPArtifacts"
}

New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null

Write-Host "===========================================================" -ForegroundColor Cyan
Write-Host "          RDP Forensic Artifacts Collector" -ForegroundColor Cyan
Write-Host "          Output Directory: $OutputDir" -ForegroundColor Cyan
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

# 1. Query Current User RDP Registry History
$rdpServers = @()
$rdpRegBase = "HKCU:\Software\Microsoft\Terminal Server Client"

if (Test-Path "$rdpRegBase\Servers") {
    $serverKeys = Get-ChildItem -Path "$rdpRegBase\Servers" -ErrorAction SilentlyContinue
    foreach ($sk in $serverKeys) {
        $props = Get-ItemProperty -Path $sk.PSPath -ErrorAction SilentlyContinue
        $rdpServers += [PSCustomObject]@{
            User                 = $env:USERNAME
            TargetServer         = $sk.PSChildName
            UsernameHint         = $props.UsernameHint
            CertHash             = $props.CertHash
        }
    }
}

if (Test-Path "$rdpRegBase\Default") {
    $defaultProps = Get-ItemProperty -Path "$rdpRegBase\Default" -ErrorAction SilentlyContinue
    $mruProps = $defaultProps.PSObject.Properties | Where-Object { $_.Name -match '^MRU\d+' }
    foreach ($mru in $mruProps) {
        $rdpServers += [PSCustomObject]@{
            User         = $env:USERNAME
            TargetServer = $mru.Value
            UsernameHint = "MRU History ($($mru.Name))"
            CertHash     = ""
        }
    }
}

if ($rdpServers.Count -gt 0) {
    $rdpCsv = Join-Path -Path $OutputDir -ChildPath "RDP_Outbound_Servers.csv"
    $rdpServers | Export-Csv -Path $rdpCsv -NoTypeInformation -Encoding UTF8
    Write-Host " [+] Found $($rdpServers.Count) RDP connection entries. Saved to: $rdpCsv" -ForegroundColor Green
} else {
    Write-Host " [-] No active RDP server history found in current user registry." -ForegroundColor DarkGray
}

# 2. Collect Bitmap Caches across profiles
$profilesToProcess = Get-UserProfilesToProcess -TargetUser $Username -ProcessAll:$AllUsers
$collectedCacheFiles = 0

foreach ($profile in $profilesToProcess) {
    $uName = $profile.Username
    $uPath = $profile.Path
    $cacheDir = Join-Path -Path $uPath -ChildPath "AppData\Local\Microsoft\Terminal Server Client\Cache"

    if (Test-Path -LiteralPath $cacheDir) {
        $cacheFiles = Get-ChildItem -LiteralPath $cacheDir -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -in @(".bmc", ".bin") }

        if ($cacheFiles) {
            $destUserCacheDir = Join-Path -Path $OutputDir -ChildPath "BitmapCache\$uName"
            New-Item -Path $destUserCacheDir -ItemType Directory -Force | Out-Null

            Write-Host "`n [+] Found $($cacheFiles.Count) RDP Bitmap Cache files for user '$uName'" -ForegroundColor Green
            foreach ($cf in $cacheFiles) {
                $dest = Join-Path -Path $destUserCacheDir -ChildPath $cf.Name
                Copy-Item -LiteralPath $cf.FullName -Destination $dest -Force -ErrorAction SilentlyContinue
                $collectedCacheFiles++
            }
        }
    }
}

Write-Host "`nCompleted RDP Artifacts collection! Total Bitmap Cache files collected: $collectedCacheFiles" -ForegroundColor Cyan
