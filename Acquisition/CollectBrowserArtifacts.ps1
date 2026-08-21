<#
.Description: Master Browser Artifacts Collector for Incident Response and Digital Forensics.
             Supports Google Chrome, Microsoft Edge, Brave Browser, Opera / Opera GX, and Mozilla Firefox.
.Recommended to use https://github.com/sqlitebrowser/sqlitebrowser to view exported SQLite Database files.
.Documentation: -
.Required Permissions: Administrator (for -AllUsers or other users) / User (for current user)

.Example:
    .\CollectBrowserArtifacts.ps1 -Username "Belk0ruh"
    .\CollectBrowserArtifacts.ps1 -AllUsers
    .\CollectBrowserArtifacts.ps1 -AllUsers -CollectAllArtifacts
    .\CollectBrowserArtifacts.ps1 -Browsers "Firefox","Edge","Opera","Brave"
    .\CollectBrowserArtifacts.ps1 -Username "Belk0ruh" -OutputDir "C:\IR\BrowserCollection"
#>

param (
    [String]$Username,
    [Switch]$AllUsers,
    [Switch]$CollectAllArtifacts,
    [String]$OutputDir,
    [ValidateSet('All', 'Chrome', 'Edge', 'Brave', 'Opera', 'Firefox')]
    [String[]]$Browsers = @('All')
)

if ($Browsers -contains 'All') {
    $selectedBrowsers = @('Chrome', 'Edge', 'Brave', 'Opera', 'Firefox')
} else {
    $selectedBrowsers = $Browsers
}

if (-not $OutputDir) {
    $OutputDir = Join-Path -Path (Get-Location) -ChildPath "BrowserArtifactsCollection"
}

New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null

Write-Host "===========================================================" -ForegroundColor Cyan
Write-Host "   DFIR Master Browser Forensics Collector" -ForegroundColor Cyan
Write-Host "   Target Browsers: $($selectedBrowsers -join ', ')" -ForegroundColor Cyan
Write-Host "   Output Directory: $OutputDir" -ForegroundColor Cyan
Write-Host "===========================================================" -ForegroundColor Cyan

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Helper function to invoke individual browser script if exists or execute inline
function Invoke-BrowserCollector {
    param (
        [string]$BrowserName,
        [string]$ScriptName
    )

    $scriptPath = Join-Path -Path $scriptDir -ChildPath $ScriptName
    if (Test-Path $scriptPath) {
        Write-Host "`n--- Running $BrowserName Collection ($ScriptName) ---" -ForegroundColor Blue
        $splat = @{
            OutputDir = $OutputDir
        }
        if ($AllUsers) { $splat['AllUsers'] = $true }
        if ($Username) { $splat['Username'] = $Username }
        if ($CollectAllArtifacts) { $splat['CollectAllArtifacts'] = $true }

        & $scriptPath @splat
    } else {
        Write-Warning "Collector script $ScriptName not found at $scriptPath"
    }
}

if ($selectedBrowsers -contains 'Chrome') {
    Invoke-BrowserCollector -BrowserName "Chromium / Chrome" -ScriptName "ChromiumArtifacts.ps1"
}

if ($selectedBrowsers -contains 'Edge') {
    Invoke-BrowserCollector -BrowserName "Microsoft Edge" -ScriptName "EdgeArtifacts.ps1"
}

if ($selectedBrowsers -contains 'Brave') {
    Invoke-BrowserCollector -BrowserName "Brave Browser" -ScriptName "BraveArtifacts.ps1"
}

if ($selectedBrowsers -contains 'Opera') {
    Invoke-BrowserCollector -BrowserName "Opera / Opera GX" -ScriptName "OperaArtifacts.ps1"
}

if ($selectedBrowsers -contains 'Firefox') {
    Invoke-BrowserCollector -BrowserName "Mozilla Firefox" -ScriptName "FirefoxArtifacts.ps1"
}

Write-Host "`n===========================================================" -ForegroundColor Green
Write-Host " All browser collections completed successfully." -ForegroundColor Green
Write-Host " Artifacts stored at: $OutputDir" -ForegroundColor Green
Write-Host "===========================================================" -ForegroundColor Green
