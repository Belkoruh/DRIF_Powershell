<#
.Description: Collects Artificial Intelligence (AI) and Large Language Model (LLM) user artifacts, prompt histories, API keys, MCP configs, and session databases.
.Documentation: Targets Claude Desktop, ChatGPT Desktop, Cursor IDE, Windsurf, GitHub Copilot, Continue.dev, Ollama, HuggingFace, LM Studio, Jan.ai, Aider, Gemini CLI / Antigravity across all user profiles.
.Required Permissions: Administrator (for -AllUsers or other users) / User (for current user)

.Example:
    .\CollectAIArtifacts.ps1
    .\CollectAIArtifacts.ps1 -AllUsers
    .\CollectAIArtifacts.ps1 -Username "Belk0ruh"
    .\CollectAIArtifacts.ps1 -OutputDir "C:\IR\AI_Dump"
    .\CollectAIArtifacts.ps1 -AllUsers -ExcludeModels
#>

param (
    [String]$Username,
    [Switch]$AllUsers,
    [String]$OutputDir,
    [Switch]$ExcludeModels
)

if (-not $OutputDir) {
    $OutputDir = Join-Path -Path (Get-Location) -ChildPath "AI_Artifacts_Dump_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
}

New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
$csvDir = Join-Path -Path $OutputDir -ChildPath "CSV"
New-Item -Path $csvDir -ItemType Directory -Force | Out-Null

Write-Host "===========================================================" -ForegroundColor Cyan
Write-Host "      Artificial Intelligence (AI / LLM) Forensics Collector" -ForegroundColor Cyan
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

# Heavy model extensions to optionally exclude
$largeModelExtensions = @(".gguf", ".bin", ".safetensors", ".pt", ".onnx", ".ckpt", ".h5")

function Copy-AIDirectorySafely {
    param (
        [string]$SourcePath,
        [string]$DestinationPath,
        [bool]$SkipModels
    )

    if (-not (Test-Path -LiteralPath $SourcePath)) { return 0 }

    New-Item -Path $DestinationPath -ItemType Directory -Force | Out-Null
    $allFiles = Get-ChildItem -LiteralPath $SourcePath -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { -not $_.FullName.StartsWith($DestinationPath) -and -not $_.FullName.StartsWith($OutputDir) }
    $copiedFilesCount = 0

    foreach ($file in $allFiles) {
        if ($SkipModels -and ($file.Extension -in $largeModelExtensions -or $file.Length -gt 100MB)) {
            continue
        }

        $rel = $file.FullName.Substring($SourcePath.Length).TrimStart("\", "/")
        $targetFile = Join-Path -Path $DestinationPath -ChildPath $rel
        $targetDir = Split-Path -Path $targetFile -Parent
        if (-not (Test-Path -LiteralPath $targetDir)) {
            New-Item -Path $targetDir -ItemType Directory -Force | Out-Null
        }

        try {
            $srcStream = [System.IO.File]::Open($file.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
            $dstStream = [System.IO.File]::Create($targetFile)
            $srcStream.CopyTo($dstStream)
            $dstStream.Close()
            $dstStream.Dispose()
            $srcStream.Close()
            $srcStream.Dispose()
            $copiedFilesCount++
        } catch {
            Copy-Item -LiteralPath $file.FullName -Destination $targetFile -Force -ErrorAction SilentlyContinue
            if (Test-Path -LiteralPath $targetFile) { $copiedFilesCount++ }
        }
    }
    return $copiedFilesCount
}

$profilesToProcess = Get-UserProfilesToProcess -TargetUser $Username -ProcessAll:$AllUsers
$aiInventory = @()
$apiKeysFound = @()

# API Key Regex patterns
$apiKeyPatterns = @(
    @{ Type = "OpenAI API Key"; Pattern = 'sk-[a-zA-Z0-9_-]{20,}' },
    @{ Type = "Anthropic Claude API Key"; Pattern = 'sk-ant-[a-zA-Z0-9_-]{20,}' },
    @{ Type = "HuggingFace Token"; Pattern = 'hf_[a-zA-Z0-9]{20,}' },
    @{ Type = "Google AI / Gemini Key"; Pattern = 'AIza[0-9A-Za-z-_]{35}' },
    @{ Type = "GitHub Token"; Pattern = 'gh[pousr]_[A-Za-z0-9_]{36,}' }
)

foreach ($profile in $profilesToProcess) {
    $uName = $profile.Username
    $uPath = $profile.Path
    $userOutDir = Join-Path -Path $OutputDir -ChildPath "Users\$uName"

    Write-Host "`nScanning User Profile: $uName ($uPath)" -ForegroundColor Yellow

    # Target AI Tools Definition
    $aiTargets = @(
        @{ Name = "Claude Desktop"; RelativePath = "AppData\Roaming\Claude"; Category = "Assistant / MCP" },
        @{ Name = "Claude Desktop Local"; RelativePath = "AppData\Local\Claude"; Category = "Assistant / Cache" },
        @{ Name = "ChatGPT Desktop"; RelativePath = "AppData\Roaming\ChatGPT"; Category = "Assistant" },
        @{ Name = "ChatGPT Desktop Local"; RelativePath = "AppData\Local\Packages\OpenAI.ChatGPT-Desktop_2p2nqsr2nd1p0"; Category = "Assistant / UWP" },
        @{ Name = "Cursor IDE"; RelativePath = "AppData\Roaming\Cursor"; Category = "AI Code Editor" },
        @{ Name = "Cursor User Config"; RelativePath = ".cursor"; Category = "AI Code Editor" },
        @{ Name = "Windsurf Codeium"; RelativePath = "AppData\Roaming\Windsurf"; Category = "AI Code Editor" },
        @{ Name = "Codeium User Config"; RelativePath = ".codeium"; Category = "AI Code Editor" },
        @{ Name = "GitHub Copilot Local"; RelativePath = "AppData\Local\github-copilot"; Category = "AI Assistant" },
        @{ Name = "VSCode Copilot Storage"; RelativePath = "AppData\Roaming\Code\User\globalStorage\github.copilot"; Category = "AI Assistant" },
        @{ Name = "VSCode Copilot Chat"; RelativePath = "AppData\Roaming\Code\User\globalStorage\github.copilot-chat"; Category = "AI Assistant" },
        @{ Name = "Continue.dev"; RelativePath = ".continue"; Category = "AI Code Assistant" },
        @{ Name = "Ollama"; RelativePath = ".ollama"; Category = "Local LLM Framework" },
        @{ Name = "HuggingFace Cache"; RelativePath = ".cache\huggingface"; Category = "Model Hub / Tokens" },
        @{ Name = "LM Studio Roaming"; RelativePath = "AppData\Roaming\LM Studio"; Category = "Local LLM UI" },
        @{ Name = "LM Studio Cache"; RelativePath = ".cache\lm-studio"; Category = "Local LLM UI" },
        @{ Name = "LM Studio User"; RelativePath = ".lmstudio"; Category = "Local LLM UI" },
        @{ Name = "Jan AI User"; RelativePath = "jan"; Category = "Local LLM UI" },
        @{ Name = "Jan AI Roaming"; RelativePath = "AppData\Roaming\Jan"; Category = "Local LLM UI" },
        @{ Name = "Aider AI"; RelativePath = ".aider"; Category = "CLI Coding Agent" },
        @{ Name = "Gemini / Antigravity"; RelativePath = ".gemini"; Category = "AI Coding Agent" },
        @{ Name = "Antigravity IDE"; RelativePath = ".antigravity"; Category = "AI Coding Agent" }
    )

    foreach ($ai in $aiTargets) {
        $sourceDir = Join-Path -Path $uPath -ChildPath $ai.RelativePath

        if (Test-Path -LiteralPath $sourceDir) {
            $destDir = Join-Path -Path $userOutDir -ChildPath "$($ai.Name.Replace(' ', '_').Replace('/', '_'))"
            Write-Host " [+] Found $($ai.Name) -> $sourceDir" -ForegroundColor Green

            $count = Copy-AIDirectorySafely -SourcePath $sourceDir -DestinationPath $destDir -SkipModels:$ExcludeModels
            Write-Host "     Archived $count file(s) to: $destDir" -ForegroundColor DarkGray

            $aiInventory += [PSCustomObject]@{
                Username     = $uName
                ToolName     = $ai.Name
                Category     = $ai.Category
                SourcePath   = $sourceDir
                DestPath     = $destDir
                FilesCount   = $count
                DetectedTime = (Get-Date).ToString("o")
            }

            # Scan exported config/JSON files for API keys
            $exportedTextFiles = Get-ChildItem -LiteralPath $destDir -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Extension -in @(".json", ".yml", ".yaml", ".txt", ".env", ".toml", ".ini", ".md") -or $_.Name -in @("token", "config") }

            foreach ($tf in $exportedTextFiles) {
                try {
                    $content = Get-Content -LiteralPath $tf.FullName -Raw -ErrorAction SilentlyContinue
                    if ($content) {
                        foreach ($pat in $apiKeyPatterns) {
                            $matches = [regex]::Matches($content, $pat.Pattern)
                            foreach ($m in $matches) {
                                $maskedKey = $m.Value.Substring(0, [math]::Min(8, $m.Value.Length)) + "..." + $m.Value.Substring([math]::Max(0, $m.Value.Length - 4))
                                Write-Host "     [!] DETECTED $($pat.Type) in $($tf.Name) ($maskedKey)" -ForegroundColor Red

                                $apiKeysFound += [PSCustomObject]@{
                                    Username   = $uName
                                    ToolName   = $ai.Name
                                    KeyType    = $pat.Type
                                    SourceFile = $tf.FullName
                                    MaskedKey  = $maskedKey
                                    RawKey     = $m.Value
                                }
                            }
                        }
                    }
                } catch { }
            }
        }
    }
}

# Export Summaries to CSV
if ($aiInventory.Count -gt 0) {
    $invCsv = Join-Path -Path $csvDir -ChildPath "AI_Artifacts_Inventory.csv"
    $aiInventory | Export-Csv -Path $invCsv -NoTypeInformation -Encoding UTF8
    Write-Host "`nAI Tools Inventory written to: $invCsv" -ForegroundColor Cyan
}

if ($apiKeysFound.Count -gt 0) {
    $keysCsv = Join-Path -Path $csvDir -ChildPath "AI_Exposed_API_Keys.csv"
    $apiKeysFound | Export-Csv -Path $keysCsv -NoTypeInformation -Encoding UTF8
    Write-Host "Exposed AI API Keys written to: $keysCsv" -ForegroundColor Red
}

Write-Host "`n===========================================================" -ForegroundColor Cyan
Write-Host " Completed AI Artifacts Collection!" -ForegroundColor Cyan
Write-Host " Total AI tool instances detected: $($aiInventory.Count)" -ForegroundColor Cyan
Write-Host " Total API keys/tokens exposed:     $($apiKeysFound.Count)" -ForegroundColor $(if ($apiKeysFound.Count -gt 0) { 'Red' } else { 'Green' })
Write-Host " Output Directory: $OutputDir" -ForegroundColor Cyan
Write-Host "===========================================================" -ForegroundColor Cyan
