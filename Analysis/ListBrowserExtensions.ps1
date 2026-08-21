<#
.Description: Lists all installed browser extensions from Chrome, Firefox, Edge, Brave, and Opera.
.Documentation: This script fetches installed browser extensions for the supported browsers and displays them in the terminal.
.Required Permissions: User
.Example:
    .\ListBrowserExtensions.ps1
#>

function Get-ChromeExtensions {
    $chromeUserData = "$env:LOCALAPPDATA\Google\Chrome\User Data"
    $found = $false
    if (Test-Path $chromeUserData) {
        $profiles = Get-ChildItem $chromeUserData -Directory -ErrorAction SilentlyContinue | Where-Object {
            Test-Path (Join-Path $_.FullName "Extensions")
        }
        foreach ($profile in $profiles) {
            $extDir = Join-Path $profile.FullName "Extensions"
            $extensions = Get-ChildItem $extDir -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne "Temp" }
            if ($extensions) {
                $found = $true
                Write-Host "Chrome Extensions (Profile: $($profile.Name)):" -ForegroundColor Blue
                $extensions | ForEach-Object { Write-Host " - $($_.Name)" }
            }
        }
    }
    if (-not $found) {
        Write-Host "Chrome is not installed or no extensions found." -ForegroundColor DarkGray
    }
}

function Get-FirefoxExtensions {
    $firefoxPath = "$env:APPDATA\Mozilla\Firefox\Profiles"
    $found = $false
    if (Test-Path $firefoxPath) {
        Get-ChildItem $firefoxPath -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $extensionsPath = Join-Path $_.FullName "extensions"
            if (Test-Path $extensionsPath) {
                $extFiles = Get-ChildItem $extensionsPath -File -ErrorAction SilentlyContinue
                $extDirs = Get-ChildItem $extensionsPath -Directory -ErrorAction SilentlyContinue
                if ($extFiles -or $extDirs) {
                    $found = $true
                    Write-Host "Firefox Extensions for Profile $($_.Name):" -ForegroundColor Blue
                    $extFiles | ForEach-Object { Write-Host " - $($_.Name)" }
                    $extDirs | ForEach-Object { Write-Host " - $($_.Name)" }
                }
            }
        }
    }
    if (-not $found) {
        Write-Host "Firefox is not installed or no extensions found." -ForegroundColor DarkGray
    }
}

function Get-EdgeExtensions {
    $edgeUserData = "$env:LOCALAPPDATA\Microsoft\Edge\User Data"
    $found = $false
    if (Test-Path $edgeUserData) {
        $profiles = Get-ChildItem $edgeUserData -Directory -ErrorAction SilentlyContinue | Where-Object {
            Test-Path (Join-Path $_.FullName "Extensions")
        }
        foreach ($profile in $profiles) {
            $extDir = Join-Path $profile.FullName "Extensions"
            $extensions = Get-ChildItem $extDir -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne "Temp" }
            if ($extensions) {
                $found = $true
                Write-Host "Edge Extensions (Profile: $($profile.Name)):" -ForegroundColor Blue
                $extensions | ForEach-Object { Write-Host " - $($_.Name)" }
            }
        }
    }
    if (-not $found) {
        Write-Host "Edge is not installed or no extensions found." -ForegroundColor DarkGray
    }
}

function Get-BraveExtensions {
    $braveUserData = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data"
    $found = $false
    if (Test-Path $braveUserData) {
        $profiles = Get-ChildItem $braveUserData -Directory -ErrorAction SilentlyContinue | Where-Object {
            Test-Path (Join-Path $_.FullName "Extensions")
        }
        foreach ($profile in $profiles) {
            $extDir = Join-Path $profile.FullName "Extensions"
            $extensions = Get-ChildItem $extDir -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne "Temp" }
            if ($extensions) {
                $found = $true
                Write-Host "Brave Extensions (Profile: $($profile.Name)):" -ForegroundColor Blue
                $extensions | ForEach-Object { Write-Host " - $($_.Name)" }
            }
        }
    }
    if (-not $found) {
        Write-Host "Brave is not installed or no extensions found." -ForegroundColor DarkGray
    }
}

function Get-OperaExtensions {
    $operaRoamingBase = "$env:APPDATA\Opera Software"
    $found = $false
    if (Test-Path $operaRoamingBase) {
        $flavors = Get-ChildItem $operaRoamingBase -Directory -ErrorAction SilentlyContinue
        foreach ($flavor in $flavors) {
            $extDir = Join-Path $flavor.FullName "Extensions"
            if (Test-Path $extDir) {
                $extensions = Get-ChildItem $extDir -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne "Temp" }
                if ($extensions) {
                    $found = $true
                    Write-Host "Opera Extensions ($($flavor.Name)):" -ForegroundColor Blue
                    $extensions | ForEach-Object { Write-Host " - $($_.Name)" }
                }
            }
        }
    }
    if (-not $found) {
        Write-Host "Opera is not installed or no extensions found." -ForegroundColor DarkGray
    }
}

Write-Host "Collecting Browser Extensions`n" -ForegroundColor Cyan
Get-ChromeExtensions
Write-Host ""
Get-EdgeExtensions
Write-Host ""
Get-BraveExtensions
Write-Host ""
Get-OperaExtensions
Write-Host ""
Get-FirefoxExtensions