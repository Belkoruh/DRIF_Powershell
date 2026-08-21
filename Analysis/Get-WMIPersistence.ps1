<#
.Description: Enumerates WMI Event Subscriptions (Filters, Consumers, and Bindings) for detecting fileless persistence mechanisms.
.Documentation: Threat actors frequently use WMI Event Subscriptions to achieve stealthy, fileless persistence triggered by specific system events (e.g. logon, system startup, timer).
.Required Permissions: Administrator

.Example:
    .\Get-WMIPersistence.ps1
    .\Get-WMIPersistence.ps1 -OutputDir "C:\IR\Persistence"
    .\Get-WMIPersistence.ps1 -ExportCsv
#>

param (
    [String]$OutputDir,
    [Switch]$ExportCsv
)

# Verify Administrator Privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning "Administrator privileges recommended to query all WMI subscription namespaces."
}

if (-not $OutputDir -and $ExportCsv) {
    $OutputDir = Join-Path -Path (Get-Location) -ChildPath "WMIPersistenceAnalysis"
}
if ($OutputDir) {
    New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
}

Write-Host "===========================================================" -ForegroundColor Cyan
Write-Host "         WMI Event Subscription Persistence Auditor" -ForegroundColor Cyan
Write-Host "===========================================================" -ForegroundColor Cyan

$namespaces = @("root\subscription", "root\default")
$allBindings = @()
$allFilters = @()
$allConsumers = @()

foreach ($ns in $namespaces) {
    Write-Host "`nScanning WMI Namespace: $ns" -ForegroundColor Yellow

    # 1. Event Filters
    $filters = $null
    try {
        $filters = Get-CimInstance -Namespace $ns -ClassName __EventFilter -ErrorAction Stop
    } catch { }

    if ($filters) {
        Write-Host " [+] Found $($filters.Count) Event Filter(s):" -ForegroundColor Green
        foreach ($f in $filters) {
            Write-Host "     - Filter Name: $($f.Name)" -ForegroundColor White
            Write-Host "       Query:       $($f.Query)" -ForegroundColor DarkGray
            Write-Host "       Language:    $($f.QueryLanguage)" -ForegroundColor DarkGray

            $allFilters += [PSCustomObject]@{
                Namespace     = $ns
                FilterName    = $f.Name
                Query         = $f.Query
                QueryLanguage = $f.QueryLanguage
                EventNamespace= $f.EventNamespace
            }
        }
    } else {
        Write-Host " [-] No Event Filters in $ns" -ForegroundColor DarkGray
    }

    # 2. Event Consumers
    $consumerClasses = @(
        "CommandLineEventConsumer",
        "ActiveScriptEventConsumer",
        "LogFileEventConsumer",
        "NTEventLogEventConsumer",
        "SMTPEventConsumer"
    )

    foreach ($cClass in $consumerClasses) {
        $consumers = $null
        try {
            $consumers = Get-CimInstance -Namespace $ns -ClassName $cClass -ErrorAction Stop
        } catch { }

        if ($consumers) {
            Write-Host " [+] Found $($consumers.Count) $cClass instance(s):" -ForegroundColor Green
            foreach ($c in $consumers) {
                $cmdLine = if ($c.CommandLineTemplate) { $c.CommandLineTemplate } elseif ($c.ScriptText) { $c.ScriptText } else { $c.Name }
                Write-Host "     - Consumer Name: $($c.Name)" -ForegroundColor White
                Write-Host "       Action/Payload: $cmdLine" -ForegroundColor Red

                $allConsumers += [PSCustomObject]@{
                    Namespace    = $ns
                    ConsumerType = $cClass
                    ConsumerName = $c.Name
                    Payload      = $cmdLine
                }
            }
        }
    }

    # 3. FilterToConsumerBindings
    $bindings = $null
    try {
        $bindings = Get-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding -ErrorAction Stop
    } catch { }

    if ($bindings) {
        Write-Host " [+] Found $($bindings.Count) Filter-To-Consumer Binding(s):" -ForegroundColor Red
        foreach ($b in $bindings) {
            Write-Host "     - Binding: $($b.Filter) <===> $($b.Consumer)" -ForegroundColor Red
            $allBindings += [PSCustomObject]@{
                Namespace = $ns
                Filter    = "$($b.Filter)"
                Consumer  = "$($b.Consumer)"
            }
        }
    } else {
        Write-Host " [-] No Active FilterToConsumer Bindings in $ns" -ForegroundColor DarkGray
    }
}

# CSV Exports
if ($OutputDir) {
    if ($allBindings.Count -gt 0) {
        $bCsv = Join-Path -Path $OutputDir -ChildPath "WMI_Bindings.csv"
        $allBindings | Export-Csv -Path $bCsv -NoTypeInformation -Encoding UTF8
        Write-Host "`nBindings exported to: $bCsv" -ForegroundColor Cyan
    }
    if ($allFilters.Count -gt 0) {
        $fCsv = Join-Path -Path $OutputDir -ChildPath "WMI_Filters.csv"
        $allFilters | Export-Csv -Path $fCsv -NoTypeInformation -Encoding UTF8
        Write-Host "Filters exported to: $fCsv" -ForegroundColor Cyan
    }
    if ($allConsumers.Count -gt 0) {
        $cCsv = Join-Path -Path $OutputDir -ChildPath "WMI_Consumers.csv"
        $allConsumers | Export-Csv -Path $cCsv -NoTypeInformation -Encoding UTF8
        Write-Host "Consumers exported to: $cCsv" -ForegroundColor Cyan
    }
}

Write-Host "`nCompleted WMI Persistence scan. Total bindings detected: $($allBindings.Count)" -ForegroundColor Cyan
