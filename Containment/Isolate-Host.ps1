<#
.SYNOPSIS
    Emergency Host & Network Containment Script for Windows Endpoints / Servers.

.DESCRIPTION
    Performs critical emergency containment on a compromised endpoint:
    1. Network Isolation: Activates Windows Defender Firewall emergency rules blocking all inbound
       and outbound traffic while preserving critical SOC / SIEM / MDE Live Response connectivity.
    2. Session Disconnect: Forces immediate logoff of active interactive and RDP sessions (logoff.exe).
    3. Process Termination: Kills all processes running under a compromised user account or specific PIDs.
    4. Credential & Ticket Purge: Flushes Kerberos ticket cache (klist purge) and clears Windows Credential Manager entries (cmdkey).
    5. Isolation Release: Reverts all emergency firewall rules cleanly when containment is lifted.

.PARAMETER IsolateNetwork
    Activates emergency firewall isolation rules (blocks all non-whitelisted inbound & outbound traffic).

.PARAMETER AllowedIPs
    List of IP addresses / subnets to whitelist during network isolation (e.g. SOC IP, VPN gateway, Proxy, SIEM).
    Default includes localhost (127.0.0.1, ::1).

.PARAMETER AllowDNS
    Allows outbound DNS queries (UDP/TCP 53) during isolation. Default: False.

.PARAMETER KillUserProcesses
    Username whose active processes must be immediately killed.

.PARAMETER LogoffUser
    Forces logoff of all active interactive/RDP sessions for the specified user or all non-admin sessions.

.PARAMETER PurgeCredentials
    Purges local Kerberos ticket caches and clears saved credentials from Credential Manager.

.PARAMETER ReleaseIsolation
    Removes all emergency containment firewall rules and restores standard network state.

.PARAMETER FullContainment
    Executes full host containment (Network Isolation + Session Logoff + Process Kill + Credential Purge).

.EXAMPLE
    .\Isolate-Host.ps1 -FullContainment -AllowedIPs "10.0.0.50", "192.168.1.100"

.EXAMPLE
    .\Isolate-Host.ps1 -IsolateNetwork -AllowedIPs "10.10.10.5"

.EXAMPLE
    .\Isolate-Host.ps1 -KillUserProcesses "compromised_user" -LogoffUser "compromised_user" -PurgeCredentials

.EXAMPLE
    .\Isolate-Host.ps1 -ReleaseIsolation

.REQUIRED PERMISSIONS
    Local Administrator
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param (
    [Parameter(Mandatory = $false)]
    [switch]$IsolateNetwork,

    [Parameter(Mandatory = $false)]
    [string[]]$AllowedIPs = @(),

    [Parameter(Mandatory = $false)]
    [switch]$AllowDNS,

    [Parameter(Mandatory = $false)]
    [string]$KillUserProcesses,

    [Parameter(Mandatory = $false)]
    [string]$LogoffUser,

    [Parameter(Mandatory = $false)]
    [switch]$PurgeCredentials,

    [Parameter(Mandatory = $false)]
    [switch]$ReleaseIsolation,

    [Parameter(Mandatory = $false)]
    [switch]$FullContainment
)

$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) {
    Write-Error "This script requires elevated Administrator privileges. Please run PowerShell as Administrator."
    return
}

$RuleGroupPrefix = "DFIR_EMERGENCY_CONTAINMENT"

# --- RELEASE ISOLATION MODE ---
if ($ReleaseIsolation) {
    Write-Host @"
===================================================================
             RELEASING EMERGENCY HOST ISOLATION
===================================================================
"@ -ForegroundColor Green

    if ($PSCmdlet.ShouldProcess("Local Firewall", "Remove all emergency isolation rules")) {
        try {
            $rules = Get-NetFirewallRule -Name "$RuleGroupPrefix*" -ErrorAction SilentlyContinue
            if ($rules) {
                $rules | Remove-NetFirewallRule -ErrorAction Stop
                Write-Host "[+] Successfully removed $($rules.Count) emergency firewall isolation rule(s)." -ForegroundColor Green
            } else {
                Write-Host "[*] No emergency containment rules found." -ForegroundColor Yellow
            }
            Write-Host "[+] Host network traffic has been fully restored." -ForegroundColor Green
        } catch {
            Write-Error "Failed to remove isolation rules: $($_.Exception.Message)"
        }
    }
    return
}

# If no specific switch is given, default to FullContainment
if (-not $IsolateNetwork -and -not $KillUserProcesses -and -not $LogoffUser -and -not $PurgeCredentials -and -not $ReleaseIsolation) {
    $FullContainment = $true
}

if ($FullContainment) {
    $IsolateNetwork = $true
    $PurgeCredentials = $true
}

Write-Host @"
===================================================================
             EMERGENCY HOST CONTAINMENT & ISOLATION
===================================================================
"@ -ForegroundColor Red

# --- 1. NETWORK ISOLATION ---
if ($IsolateNetwork) {
    Write-Host "`n[*] [1/4] Applying Emergency Network Isolation..." -ForegroundColor Cyan
    
    if ($PSCmdlet.ShouldProcess("Windows Defender Firewall", "Enable emergency network isolation rules")) {
        try {
            # Clean any old emergency rules first
            Get-NetFirewallRule -Name "$RuleGroupPrefix*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue

            # 1.1 Inbound Block All Rule
            New-NetFirewallRule -Name "${RuleGroupPrefix}_Block_Inbound" `
                -DisplayName "[DFIR CONTAINMENT] Block All Inbound" `
                -Direction Inbound `
                -Action Block `
                -Profile Any `
                -Enabled True `
                -Description "Emergency containment rule - blocks all inbound traffic" | Out-Null
            Write-Host " [+] Blocked all Inbound network traffic." -ForegroundColor Green

            # 1.2 Outbound Block All Rule
            New-NetFirewallRule -Name "${RuleGroupPrefix}_Block_Outbound" `
                -DisplayName "[DFIR CONTAINMENT] Block All Outbound" `
                -Direction Outbound `
                -Action Block `
                -Profile Any `
                -Enabled True `
                -Description "Emergency containment rule - blocks all outbound traffic" | Out-Null
            Write-Host " [+] Blocked all Outbound network traffic." -ForegroundColor Green

            # 1.3 Allow Loopback
            New-NetFirewallRule -Name "${RuleGroupPrefix}_Allow_Loopback_In" `
                -DisplayName "[DFIR CONTAINMENT] Allow Loopback Inbound" `
                -Direction Inbound `
                -Action Allow `
                -RemoteAddress "127.0.0.1", "::1" `
                -Profile Any `
                -Enabled True | Out-Null

            New-NetFirewallRule -Name "${RuleGroupPrefix}_Allow_Loopback_Out" `
                -DisplayName "[DFIR CONTAINMENT] Allow Loopback Outbound" `
                -Direction Outbound `
                -Action Allow `
                -RemoteAddress "127.0.0.1", "::1" `
                -Profile Any `
                -Enabled True | Out-Null
            Write-Host " [+] Whitelisted local loopback (127.0.0.1 / ::1)." -ForegroundColor Green

            # 1.4 Allow DHCP
            New-NetFirewallRule -Name "${RuleGroupPrefix}_Allow_DHCP_Out" `
                -DisplayName "[DFIR CONTAINMENT] Allow DHCP Outbound" `
                -Direction Outbound `
                -Action Allow `
                -Protocol UDP `
                -LocalPort 68 `
                -RemotePort 67 `
                -Profile Any `
                -Enabled True | Out-Null

            # 1.5 Optional Allow DNS
            if ($AllowDNS) {
                New-NetFirewallRule -Name "${RuleGroupPrefix}_Allow_DNS_Out" `
                    -DisplayName "[DFIR CONTAINMENT] Allow DNS Outbound" `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol UDP `
                    -RemotePort 53 `
                    -Profile Any `
                    -Enabled True | Out-Null
                Write-Host " [+] Whitelisted DNS Outbound (Port 53)." -ForegroundColor Green
            }

            # 1.6 Whitelist specific SOC / Management IPs
            if ($AllowedIPs.Count -gt 0) {
                New-NetFirewallRule -Name "${RuleGroupPrefix}_Allow_SOC_In" `
                    -DisplayName "[DFIR CONTAINMENT] Allow SOC Management Inbound" `
                    -Direction Inbound `
                    -Action Allow `
                    -RemoteAddress $AllowedIPs `
                    -Profile Any `
                    -Enabled True | Out-Null

                New-NetFirewallRule -Name "${RuleGroupPrefix}_Allow_SOC_Out" `
                    -DisplayName "[DFIR CONTAINMENT] Allow SOC Management Outbound" `
                    -Direction Outbound `
                    -Action Allow `
                    -RemoteAddress $AllowedIPs `
                    -Profile Any `
                    -Enabled True | Out-Null
                Write-Host " [+] Whitelisted SOC Management IPs: $($AllowedIPs -join ', ')" -ForegroundColor Green
            }

            Write-Host " [!] HOST IS NOW NETWORK-ISOLATED." -ForegroundColor Red
        } catch {
            Write-Error "Failed to set firewall isolation rules: $($_.Exception.Message)"
        }
    }
}

# --- 2. TERMINATE USER PROCESSES ---
if ($KillUserProcesses) {
    Write-Host "`n[*] [2/4] Terminating processes for user: $KillUserProcesses..." -ForegroundColor Cyan
    if ($PSCmdlet.ShouldProcess($KillUserProcesses, "Kill all user processes")) {
        try {
            $processes = Get-CimInstance Win32_Process | Where-Object {
                $owner = Invoke-CimMethod -InputObject $_ -MethodName GetOwner -ErrorAction SilentlyContinue
                if ($owner -and $owner.User) {
                    $owner.User -ieq $KillUserProcesses
                } else { $false }
            }

            $killedCount = 0
            foreach ($p in $processes) {
                try {
                    Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
                    Write-Host "     [-] Terminated PID $($p.ProcessId) ($($p.Name))" -ForegroundColor Yellow
                    $killedCount++
                } catch {}
            }
            Write-Host " [+] Terminated $killedCount process(es) belonging to $KillUserProcesses." -ForegroundColor Green
        } catch {
            Write-Warning "Failed to enumerate/terminate processes: $($_.Exception.Message)"
        }
    }
}

# --- 3. FORCE SESSION LOGOFF ---
if ($LogoffUser) {
    Write-Host "`n[*] [3/4] Forcing session logoff for user: $LogoffUser..." -ForegroundColor Cyan
    if ($PSCmdlet.ShouldProcess($LogoffUser, "Logoff active user session")) {
        try {
            $quserOutput = quser 2>$null
            if ($quserOutput) {
                $lines = $quserOutput | Select-Object -Skip 1
                foreach ($line in $lines) {
                    $cols = $line -split '\s+' | Where-Object { $_ -ne "" }
                    $sessionUser = $cols[0].TrimStart('>')
                    $sessionId = $null
                    
                    # Identify session ID column
                    for ($i = 1; $i -lt $cols.Count; $i++) {
                        if ($cols[$i] -match '^\d+$') {
                            $sessionId = $cols[$i]
                            break
                        }
                    }

                    if ($sessionUser -ieq $LogoffUser -and $sessionId) {
                        Write-Host "     [-] Logging off Session ID $sessionId ($sessionUser)..." -ForegroundColor Yellow
                        logoff $sessionId
                        Write-Host " [+] Session $sessionId logged off." -ForegroundColor Green
                    }
                }
            } else {
                Write-Host " [*] No active interactive sessions detected via quser." -ForegroundColor Yellow
            }
        } catch {
            Write-Warning "Failed to logoff session: $($_.Exception.Message)"
        }
    }
}

# --- 4. PURGE CREDENTIALS & KERBEROS TICKETS ---
if ($PurgeCredentials) {
    Write-Host "`n[*] [4/4] Purging Kerberos tickets and cached credentials..." -ForegroundColor Cyan
    if ($PSCmdlet.ShouldProcess("Local Credentials", "Purge Kerberos tickets and cached credentials")) {
        # 4.1 Purge Kerberos tickets
        try {
            klist purge | Out-Null
            Write-Host " [+] Kerberos tickets purged (klist purge)." -ForegroundColor Green
        } catch {
            Write-Warning "Failed to purge Kerberos tickets: $($_.Exception.Message)"
        }

        # 4.2 List and clear Generic / Domain credentials via cmdkey
        try {
            $cmdkeyOutput = cmdkey /list 2>$null
            if ($cmdkeyOutput) {
                $targets = $cmdkeyOutput | Where-Object { $_ -match 'Target:\s*(.+)$' } | ForEach-Object { $matches[1].Trim() }
                $clearedCount = 0
                foreach ($target in $targets) {
                    cmdkey /delete:$target 2>$null | Out-Null
                    $clearedCount++
                }
                Write-Host " [+] Cleared $clearedCount credential entry(ies) from Credential Manager." -ForegroundColor Green
            }
        } catch {
            Write-Warning "Failed to clear Credential Manager entries: $($_.Exception.Message)"
        }
    }
}

Write-Host @"

===================================================================
          CONTAINMENT SUMMARY & OPERATIONAL NOTES
===================================================================
- To lift network isolation and restore network connectivity:
  .\Isolate-Host.ps1 -ReleaseIsolation

- Whitelist management IPs:
  .\Isolate-Host.ps1 -IsolateNetwork -AllowedIPs "10.0.0.10", "192.168.1.50"
===================================================================
"@ -ForegroundColor Green
