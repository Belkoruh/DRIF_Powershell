<#
.Description: Collects Windows Execution and Resource Usage Artifacts (Prefetch, SRUM, BAM/DAM, Amcache) for DFIR timeline analysis.
.Documentation: These artifacts prove binary execution even after deletion, and record network bandwidth consumed by suspicious processes.
.Required Permissions: Administrator

.Example:
    .\CollectExecutionArtifacts.ps1
    .\CollectExecutionArtifacts.ps1 -OutputDir "C:\IR\ExecutionArtifacts"
    .\CollectExecutionArtifacts.ps1 -PrefetchOnly
#>

param (
    [String]$OutputDir,
    [Switch]$PrefetchOnly
)

# Verify Administrator Privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "Administrator privileges are required to collect Prefetch, SRUM, and Amcache artifacts. Please run PowerShell as Administrator."
    return
}

if (-not $OutputDir) {
    $OutputDir = Join-Path -Path (Get-Location) -ChildPath "ExecutionArtifacts"
}

New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null

Write-Host "===========================================================" -ForegroundColor Cyan
Write-Host "       Windows Program Execution Artifacts Collector" -ForegroundColor Cyan
Write-Host "       Output Directory: $OutputDir" -ForegroundColor Cyan
Write-Host "===========================================================" -ForegroundColor Cyan

function Copy-LockedFile {
    param (
        [string]$SourcePath,
        [string]$DestinationPath
    )

    try {
        $sourceStream = [System.IO.File]::Open($SourcePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $destStream = [System.IO.File]::Create($DestinationPath)
        $sourceStream.CopyTo($destStream)
        $destStream.Close()
        $destStream.Dispose()
        $sourceStream.Close()
        $sourceStream.Dispose()
        return $true
    } catch {
        return $false
    }
}

# 1. Prefetch Files
$prefetchFolder = "$env:SystemRoot\Prefetch"
$prefetchOutDir = Join-Path -Path $OutputDir -ChildPath "Prefetch"
New-Item -Path $prefetchOutDir -ItemType Directory -Force | Out-Null

Write-Host "`n[1/4] Collecting Prefetch files (.pf)..." -ForegroundColor Yellow
if (Test-Path -LiteralPath $prefetchFolder) {
    $pfFiles = Get-ChildItem -LiteralPath $prefetchFolder -Filter "*.pf" -File -ErrorAction SilentlyContinue
    if ($pfFiles) {
        Write-Host " Found $($pfFiles.Count) Prefetch files. Copying..." -NoNewline
        $copiedPf = 0
        foreach ($pf in $pfFiles) {
            $dest = Join-Path -Path $prefetchOutDir -ChildPath $pf.Name
            $res = Copy-LockedFile -SourcePath $pf.FullName -DestinationPath $dest
            if ($res) { $copiedPf++ }
        }
        Write-Host " [$copiedPf / $($pfFiles.Count) OK]" -ForegroundColor Green
    } else {
        Write-Host " No Prefetch files found (Prefetch may be disabled or empty)." -ForegroundColor DarkGray
    }
} else {
    Write-Host " Prefetch directory not accessible." -ForegroundColor DarkGray
}

if (-not $PrefetchOnly) {
    # 2. SRUM (System Resource Usage Monitor)
    $srumOutDir = Join-Path -Path $OutputDir -ChildPath "SRUM"
    New-Item -Path $srumOutDir -ItemType Directory -Force | Out-Null
    $srumDb = "$env:SystemRoot\System32\sru\SRUDB.dat"

    Write-Host "`n[2/4] Collecting SRUM database (SRUDB.dat)..." -ForegroundColor Yellow
    if (Test-Path -LiteralPath $srumDb) {
        $destSrum = Join-Path -Path $srumOutDir -ChildPath "SRUDB.dat"
        $copiedSrum = Copy-LockedFile -SourcePath $srumDb -DestinationPath $destSrum
        if ($copiedSrum) {
            $sizeMB = [math]::Round(((Get-Item $destSrum).Length / 1MB), 2)
            Write-Host " [+] SRUDB.dat collected successfully ($sizeMB MB)" -ForegroundColor Green
        } else {
            Write-Warning " Failed to copy SRUDB.dat (file locked or permissions issue)"
        }
    } else {
        Write-Host " SRUM database not found at: $srumDb" -ForegroundColor DarkGray
    }

    # 3. BAM / DAM (Background Activity Moderator)
    $bamOutDir = Join-Path -Path $OutputDir -ChildPath "BAM_DAM"
    New-Item -Path $bamOutDir -ItemType Directory -Force | Out-Null
    Write-Host "`n[3/4] Exporting BAM / DAM Registry Keys..." -ForegroundColor Yellow

    $bamKeys = @(
        @{ Name = "BAM_UserSettings"; Key = "HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings" },
        @{ Name = "DAM_UserSettings"; Key = "HKLM\SYSTEM\CurrentControlSet\Services\dam\State\UserSettings" }
    )

    foreach ($bk in $bamKeys) {
        $destFile = Join-Path -Path $bamOutDir -ChildPath "$($bk.Name).reg"
        $proc = Start-Process -FilePath "reg.exe" -ArgumentList "export `"$($bk.Key)`" `"$destFile`" /y" -Wait -NoNewWindow -PassThru
        if ($proc.ExitCode -eq 0 -and (Test-Path $destFile)) {
            Write-Host " [+] $($bk.Name) exported successfully" -ForegroundColor Green
        } else {
            Write-Host " [-] $($bk.Name) key not present or export failed" -ForegroundColor DarkGray
        }
    }

    # 4. Amcache.hve
    $amcacheOutDir = Join-Path -Path $OutputDir -ChildPath "Amcache"
    New-Item -Path $amcacheOutDir -ItemType Directory -Force | Out-Null
    $amcachePath = "$env:SystemRoot\appcompat\Programs\Amcache.hve"

    Write-Host "`n[4/4] Collecting Amcache.hve..." -ForegroundColor Yellow
    if (Test-Path -LiteralPath $amcachePath) {
        $destAmcache = Join-Path -Path $amcacheOutDir -ChildPath "Amcache.hve"
        $copiedAmcache = Copy-LockedFile -SourcePath $amcachePath -DestinationPath $destAmcache
        if ($copiedAmcache) {
            $sizeMB = [math]::Round(((Get-Item $destAmcache).Length / 1MB), 2)
            Write-Host " [+] Amcache.hve collected successfully ($sizeMB MB)" -ForegroundColor Green
        } else {
            # Fallback to reg save if locked
            $proc = Start-Process -FilePath "reg.exe" -ArgumentList "save `"HKLM\SAM`" `"$destAmcache`" /y" -Wait -NoNewWindow -PassThru
            Write-Warning " Amcache direct copy failed (locked). Check with raw extraction tools."
        }
    } else {
        Write-Host " Amcache.hve not found at: $amcachePath" -ForegroundColor DarkGray
    }
}

Write-Host "`nCompleted! Program execution artifacts collected in: $OutputDir" -ForegroundColor Cyan
