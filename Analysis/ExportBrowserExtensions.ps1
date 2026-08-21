<#
.Description: Creates a .zip file containing all browser extensions folders for Chrome, Firefox, Edge, Brave, and Opera.
.Documentation: -
.Required Permissions: User
.Example:
    .\ExportBrowserExtensions.ps1
.Example Live Response:
    run ExportBrowserExtensions.ps1
#>

function Compress-ToZip {
    param (
        [string]$SourcePath,
        [string]$DestinationZip
    )
    if (Test-Path $SourcePath) {
        Compress-Archive -Path "$SourcePath\*" -DestinationPath $DestinationZip -Force
    } else {
        Write-Host "The folder $SourcePath does not exist." -ForegroundColor Red
    }
}

$tempFolder = "$env:TEMP\BrowserExtensions"
if (Test-Path $tempFolder) {
    Remove-Item -Recurse -Force $tempFolder
}
New-Item -ItemType Directory -Path $tempFolder | Out-Null

# Chrome
$chromeUserData = "$env:LOCALAPPDATA\Google\Chrome\User Data"
if (Test-Path $chromeUserData) {
    Get-ChildItem $chromeUserData -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $extPath = Join-Path $_.FullName "Extensions"
        if (Test-Path $extPath) {
            $dest = Join-Path $tempFolder "Chrome_$($_.Name)"
            Copy-Item -Path $extPath -Destination $dest -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

# Edge
$edgeUserData = "$env:LOCALAPPDATA\Microsoft\Edge\User Data"
if (Test-Path $edgeUserData) {
    Get-ChildItem $edgeUserData -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $extPath = Join-Path $_.FullName "Extensions"
        if (Test-Path $extPath) {
            $dest = Join-Path $tempFolder "Edge_$($_.Name)"
            Copy-Item -Path $extPath -Destination $dest -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

# Brave
$braveUserData = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data"
if (Test-Path $braveUserData) {
    Get-ChildItem $braveUserData -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $extPath = Join-Path $_.FullName "Extensions"
        if (Test-Path $extPath) {
            $dest = Join-Path $tempFolder "Brave_$($_.Name)"
            Copy-Item -Path $extPath -Destination $dest -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

# Opera / Opera GX
$operaRoamingBase = "$env:APPDATA\Opera Software"
if (Test-Path $operaRoamingBase) {
    Get-ChildItem $operaRoamingBase -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $extPath = Join-Path $_.FullName "Extensions"
        if (Test-Path $extPath) {
            $dest = Join-Path $tempFolder "Opera_$($_.Name)"
            Copy-Item -Path $extPath -Destination $dest -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

# Firefox
$firefoxProfilesPath = "$env:APPDATA\Mozilla\Firefox\Profiles"
if (Test-Path $firefoxProfilesPath) {
    Get-ChildItem $firefoxProfilesPath -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $extensionsPath = Join-Path $_.FullName "extensions"
        if (Test-Path $extensionsPath) {
            $dest = Join-Path $tempFolder "Firefox_$($_.Name)"
            Copy-Item -Path $extensionsPath -Destination $dest -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

$zipFilePath = "$PWD\BrowserExtensionExport.zip"
Compress-ToZip -SourcePath $tempFolder -DestinationZip $zipFilePath

Remove-Item -Recurse -Force $tempFolder

Write-Host "Browser extensions have been exported to $zipFilePath." -ForegroundColor Green