<#
.Description: Generates a forensic evidence integrity manifest (manifest.json & checksums.sha256) for Chain of Custody.
.Documentation: Computes SHA-256 hashes of all acquired evidence files and attaches host context (Hostname, OS, UTC timestamp, TimeZone, Collector User).
.Required Permissions: User / Administrator

.Example:
    .\GenerateEvidenceManifest.ps1 -TargetDir "C:\IR\DFIR-DESKTOP-2026-08-21"
    .\GenerateEvidenceManifest.ps1 -TargetDir "C:\IR\Export" -OutputFile "C:\IR\Export\manifest.json"
#>

param (
    [Parameter(Mandatory=$false)]
    [String]$TargetDir,

    [Parameter(Mandatory=$false)]
    [String]$OutputFile
)

if (-not $TargetDir) {
    $TargetDir = Get-Location
}

if (-not (Test-Path -LiteralPath $TargetDir)) {
    Write-Error "Target directory '$TargetDir' does not exist."
    return
}

Write-Host "===========================================================" -ForegroundColor Cyan
Write-Host "       DFIR Evidence Manifest & Chain of Custody" -ForegroundColor Cyan
Write-Host "       Target Directory: $TargetDir" -ForegroundColor Cyan
Write-Host "===========================================================" -ForegroundColor Cyan

$currentTimeUtc = (Get-Date).ToUniversalTime().ToString("o")
$timeZoneInfo = (Get-TimeZone).Id
$timeZoneOffset = (Get-TimeZone).BaseUtcOffset.ToString()

# Host information
$osInfo = $null
try {
    $osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
} catch { }

$osCaption = if ($osInfo) { $osInfo.Caption } else { 
    $prod = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'ProductName' -ErrorAction SilentlyContinue
    if ($prod) { $prod.ProductName } else { "Windows OS" }
}
$osBuild = if ($osInfo) { $osInfo.BuildNumber } else { 
    $bld = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'CurrentBuild' -ErrorAction SilentlyContinue
    if ($bld) { $bld.CurrentBuild } else { "" }
}

$files = Get-ChildItem -LiteralPath $TargetDir -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notin @("manifest.json", "checksums.sha256") }

Write-Host "Hashing $($files.Count) evidence file(s) with SHA-256..." -ForegroundColor Yellow

$fileManifestList = @()
$checksumLines = @()
$counter = 0

foreach ($f in $files) {
    $counter++
    $relPath = $f.FullName.Substring($TargetDir.ToString().Length).TrimStart("\", "/")

    try {
        $hashResult = Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256 -ErrorAction Stop
        $sha256 = $hashResult.Hash.ToLower()

        $fileManifestList += [PSCustomObject]@{
            RelativePath   = $relPath
            SizeBytes      = $f.Length
            SHA256         = $sha256
            CreatedUtc     = $f.CreationTimeUtc.ToString("o")
            LastModifiedUtc= $f.LastWriteTimeUtc.ToString("o")
        }

        $checksumLines += "$sha256  $relPath"
    } catch {
        Write-Warning "Could not hash file '$($f.FullName)': $($_.Exception.Message)"
    }
}

$manifestObject = [PSCustomObject]@{
    AcquisitionMetadata = [PSCustomObject]@{
        ComputerName   = $env:COMPUTERNAME
        OperatingSystem= "$osCaption (Build $osBuild)"
        CollectorUser  = $env:USERNAME
        TimestampUtc   = $currentTimeUtc
        LocalTimeZone  = "$timeZoneInfo (UTC $timeZoneOffset)"
        TotalFiles     = $fileManifestList.Count
    }
    Files = $fileManifestList
}

# Write manifest.json
$jsonPath = if ($OutputFile) { $OutputFile } else { Join-Path -Path $TargetDir -ChildPath "manifest.json" }
$manifestObject | ConvertTo-Json -Depth 5 | Out-File -LiteralPath $jsonPath -Encoding UTF8 -Force
Write-Host " [+] Manifest JSON written to: $jsonPath" -ForegroundColor Green

# Write checksums.sha256
$checksumPath = Join-Path -Path $TargetDir -ChildPath "checksums.sha256"
$checksumLines | Out-File -LiteralPath $checksumPath -Encoding UTF8 -Force
Write-Host " [+] Checksums file written to: $checksumPath" -ForegroundColor Green

Write-Host "`nEvidence hashing completed successfully ($($fileManifestList.Count) files processed)." -ForegroundColor Cyan
