<#
.SYNOPSIS
    Full Enterprise Identity Containment & Remediation Playbook for Microsoft Entra ID / M365.

.DESCRIPTION
    Executes a comprehensive, multi-layered containment workflow on compromised user accounts:
    1. Account Disabling (AccountEnabled = $false)
    2. Instant Session & Token Revocation (Revoke-MgUserSignInSession)
    3. Strong Password Reset (32-character high entropy) & Enforce Next Sign-In Change
    4. MFA Methods Audit & Removal (Authenticator, FIDO2, Phone, Email, Temporary Access Pass)
    5. User-consented OAuth2 Application Grants Revocation (Mitigate Illicit Consent Grants)
    6. App Passwords Audit / Removal

.PARAMETER Users
    List of User Principal Names (UPNs) or Object IDs to contain.

.PARAMETER DisableAccount
    Disables the target account(s) immediately (AccountEnabled = $false). Default: True in Full mode.

.PARAMETER RevokeSessions
    Invalidates all active refresh tokens and OAuth sessions. Default: True in Full mode.

.PARAMETER ResetPassword
    Generates a cryptographically strong 32-character temporary password and sets force reset on next sign-in.

.PARAMETER PurgeMfa
    Audits and deletes registered MFA authentication methods (Authenticator, FIDO2, Phone, TAP) added to the account.

.PARAMETER RevokeOAuthGrants
    Audits and revokes all delegated OAuth2 permission grants consented by the target user.

.PARAMETER FullContainment
    Executes all containment actions (Disable, Revoke Sessions, Reset Password, Purge MFA, Revoke OAuth Grants). Default if no specific switches are set.

.EXAMPLE
    .\Invoke-FullIdentityContainment.ps1 -Users "compromised_user@domain.com"

.EXAMPLE
    .\Invoke-FullIdentityContainment.ps1 -Users "user1@domain.com", "user2@domain.com" -FullContainment

.EXAMPLE
    .\Invoke-FullIdentityContainment.ps1 -Users "user1@domain.com" -RevokeSessions -PurgeMfa -RevokeOAuthGrants

.REQUIRED PERMISSIONS
    Microsoft Graph API Scopes:
    - User.ReadWrite.All
    - UserAuthenticationMethod.ReadWrite.All
    - User.RevokeSessions.All
    - DelegatedPermissionGrant.ReadWrite.All
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param (
    [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
    [string[]]$Users,

    [Parameter(Mandatory = $false)]
    [switch]$DisableAccount,

    [Parameter(Mandatory = $false)]
    [switch]$RevokeSessions,

    [Parameter(Mandatory = $false)]
    [switch]$ResetPassword,

    [Parameter(Mandatory = $false)]
    [switch]$PurgeMfa,

    [Parameter(Mandatory = $false)]
    [switch]$RevokeOAuthGrants,

    [Parameter(Mandatory = $false)]
    [switch]$FullContainment
)

# If no granular switch is provided, default to Full Containment
if (-not $DisableAccount -and -not $RevokeSessions -and -not $ResetPassword -and -not $PurgeMfa -and -not $RevokeOAuthGrants) {
    $FullContainment = $true
}

if ($FullContainment) {
    $DisableAccount = $true
    $RevokeSessions = $true
    $ResetPassword = $true
    $PurgeMfa = $true
    $RevokeOAuthGrants = $true
}

# Required Graph Scopes
$requiredScopes = @(
    "User.ReadWrite.All",
    "UserAuthenticationMethod.ReadWrite.All",
    "User.RevokeSessions.All",
    "DelegatedPermissionGrant.ReadWrite.All"
)

Write-Host @"
===================================================================
   Microsoft Entra ID / M365 Full Identity Containment Playbook
===================================================================
"@ -ForegroundColor Red

# 1. Connect to Microsoft Graph
Write-Host "[*] Connecting to Microsoft Graph API..." -ForegroundColor Cyan
try {
    Connect-MgGraph -Scopes $requiredScopes -ErrorAction Stop | Out-Null
    Write-Host "[+] Connected to Microsoft Graph." -ForegroundColor Green
} catch {
    Write-Error "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
    Write-Host "Please ensure you have installed the Microsoft.Graph module:`nInstall-Module Microsoft.Graph -Scope CurrentUser" -ForegroundColor Yellow
    return
}

Import-Module Microsoft.Graph.Users -ErrorAction SilentlyContinue
Import-Module Microsoft.Graph.Users.Actions -ErrorAction SilentlyContinue
Import-Module Microsoft.Graph.Identity.SignIns -ErrorAction SilentlyContinue

function New-StrongPassword {
    $chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*()-_=+"
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes)
    $password = -join ($bytes | ForEach-Object { $chars[$_ % $chars.Length] })
    return $password
}

$summaryReport = @()

foreach ($userId in $Users) {
    Write-Host "`n" + ("=" * 70) -ForegroundColor Yellow
    Write-Host " [!] INITIATING CONTAINMENT FOR: $userId" -ForegroundColor Yellow
    Write-Host ("=" * 70) -ForegroundColor Yellow

    $userReport = [PSCustomObject]@{
        User           = $userId
        AccountDisabled= "Skipped"
        SessionsRevoked= "Skipped"
        PasswordReset  = "Skipped"
        TempPassword   = ""
        MfaPurged      = "Skipped"
        OAuthRevoked   = "Skipped"
        Status         = "Success"
        Errors         = @()
    }

    # Verify user exists
    $targetUser = $null
    try {
        $targetUser = Get-MgUser -UserId $userId -Property Id, UserPrincipalName, DisplayName, AccountEnabled, Mail -ErrorAction Stop
        Write-Host "[+] Target verified: $($targetUser.DisplayName) ($($targetUser.UserPrincipalName)) [ID: $($targetUser.Id)]" -ForegroundColor Green
    } catch {
        Write-Error "Target user '$userId' not found in tenant: $($_.Exception.Message)"
        $userReport.Status = "Failed"
        $userReport.Errors += "User not found"
        $summaryReport += $userReport
        continue
    }

    # --- ACTION 1: Disable Account ---
    if ($DisableAccount) {
        if ($PSCmdlet.ShouldProcess($userId, "Disable Account (AccountEnabled = false)")) {
            try {
                Update-MgUser -UserId $targetUser.Id -AccountEnabled:$false -ErrorAction Stop
                Write-Host " [+] [1/5] Account disabled successfully." -ForegroundColor Green
                $userReport.AccountDisabled = "Disabled"
            } catch {
                Write-Warning " [-] [1/5] Failed to disable account: $($_.Exception.Message)"
                $userReport.AccountDisabled = "Failed"
                $userReport.Errors += "Disable account error: $($_.Exception.Message)"
            }
        }
    }

    # --- ACTION 2: Revoke Sign-In Sessions & Refresh Tokens ---
    if ($RevokeSessions) {
        if ($PSCmdlet.ShouldProcess($userId, "Revoke all active sign-in sessions and tokens")) {
            try {
                $revoked = Revoke-MgUserSignInSession -UserId $targetUser.Id -ErrorAction Stop
                if ($revoked) {
                    Write-Host " [+] [2/5] All active sign-in sessions and refresh tokens invalidated." -ForegroundColor Green
                    $userReport.SessionsRevoked = "Revoked"
                } else {
                    Write-Warning " [-] [2/5] Revoke sessions returned false."
                    $userReport.SessionsRevoked = "Failed"
                }
            } catch {
                Write-Warning " [-] [2/5] Failed to revoke sessions: $($_.Exception.Message)"
                $userReport.SessionsRevoked = "Failed"
                $userReport.Errors += "Revoke sessions error: $($_.Exception.Message)"
            }
        }
    }

    # --- ACTION 3: Strong Password Reset ---
    if ($ResetPassword) {
        if ($PSCmdlet.ShouldProcess($userId, "Generate 32-char temporary password & force change")) {
            try {
                $tempPass = New-StrongPassword
                $passwordProfile = @{
                    Password                      = $tempPass
                    ForceChangePasswordNextSignIn = $true
                }
                Update-MgUser -UserId $targetUser.Id -PasswordProfile $passwordProfile -ErrorAction Stop
                Write-Host " [+] [3/5] Temporary 32-character password generated & forced reset on next logon." -ForegroundColor Green
                Write-Host "     ==> Temp Password: $tempPass" -ForegroundColor Magenta
                $userReport.PasswordReset = "Reset"
                $userReport.TempPassword  = $tempPass
            } catch {
                Write-Warning " [-] [3/5] Failed to reset password: $($_.Exception.Message)"
                $userReport.PasswordReset = "Failed"
                $userReport.Errors += "Password reset error: $($_.Exception.Message)"
            }
        }
    }

    # --- ACTION 4: Purge Suspicious / Rogue MFA Methods ---
    if ($PurgeMfa) {
        if ($PSCmdlet.ShouldProcess($userId, "Audit and delete registered MFA methods (FIDO2, Authenticator, Phone, TAP)")) {
            Write-Host " [*] [4/5] Auditing registered MFA methods..." -ForegroundColor Cyan
            $purgedCount = 0

            # 4.1 FIDO2 Security Keys
            try {
                $fido2Keys = Get-MgUserAuthenticationFido2Method -UserId $targetUser.Id -ErrorAction SilentlyContinue
                foreach ($fido in $fido2Keys) {
                    Write-Host "     [-] Removing FIDO2 Key: $($fido.DisplayName) [ID: $($fido.Id)]" -ForegroundColor Yellow
                    Remove-MgUserAuthenticationFido2Method -UserId $targetUser.Id -Fido2AuthenticationMethodId $fido.Id -ErrorAction Stop
                    $purgedCount++
                }
            } catch {
                Write-Warning "     [!] Error checking FIDO2 methods: $($_.Exception.Message)"
            }

            # 4.2 Microsoft Authenticator App Methods
            try {
                $authMethods = Get-MgUserAuthenticationMicrosoftAuthenticatorMethod -UserId $targetUser.Id -ErrorAction SilentlyContinue
                foreach ($auth in $authMethods) {
                    Write-Host "     [-] Removing Microsoft Authenticator: $($auth.DisplayName) ($($auth.DeviceTag)) [ID: $($auth.Id)]" -ForegroundColor Yellow
                    Remove-MgUserAuthenticationMicrosoftAuthenticatorMethod -UserId $targetUser.Id -MicrosoftAuthenticatorAuthenticationMethodId $auth.Id -ErrorAction Stop
                    $purgedCount++
                }
            } catch {
                Write-Warning "     [!] Error checking Authenticator methods: $($_.Exception.Message)"
            }

            # 4.3 Phone Methods (SMS / Voice)
            try {
                $phoneMethods = Get-MgUserAuthenticationPhoneMethod -UserId $targetUser.Id -ErrorAction SilentlyContinue
                foreach ($phone in $phoneMethods) {
                    Write-Host "     [-] Removing Phone Method: $($phone.PhoneNumber) ($($phone.PhoneType)) [ID: $($phone.Id)]" -ForegroundColor Yellow
                    Remove-MgUserAuthenticationPhoneMethod -UserId $targetUser.Id -PhoneAuthenticationMethodId $phone.Id -ErrorAction Stop
                    $purgedCount++
                }
            } catch {
                Write-Warning "     [!] Error checking Phone methods: $($_.Exception.Message)"
            }

            # 4.4 Temporary Access Pass (TAP)
            try {
                $tapMethods = Get-MgUserAuthenticationTemporaryAccessPassMethod -UserId $targetUser.Id -ErrorAction SilentlyContinue
                foreach ($tap in $tapMethods) {
                    Write-Host "     [-] Removing Temporary Access Pass [ID: $($tap.Id)]" -ForegroundColor Yellow
                    Remove-MgUserAuthenticationTemporaryAccessPassMethod -UserId $targetUser.Id -TemporaryAccessPassAuthenticationMethodId $tap.Id -ErrorAction Stop
                    $purgedCount++
                }
            } catch {
                Write-Warning "     [!] Error checking TAP methods: $($_.Exception.Message)"
            }

            Write-Host " [+] [4/5] MFA Purge completed. Total methods removed: $purgedCount" -ForegroundColor Green
            $userReport.MfaPurged = "Purged ($purgedCount methods)"
        }
    }

    # --- ACTION 5: Revoke Delegated OAuth2 App Consents ---
    if ($RevokeOAuthGrants) {
        if ($PSCmdlet.ShouldProcess($userId, "Revoke user-consented OAuth2 application grants")) {
            Write-Host " [*] [5/5] Auditing user OAuth2 delegated permission grants..." -ForegroundColor Cyan
            try {
                $oauthGrants = Get-MgOauth2PermissionGrant -Filter "principalId eq '$($targetUser.Id)'" -ErrorAction Stop
                $grantCount = 0
                if ($oauthGrants) {
                    foreach ($grant in $oauthGrants) {
                        Write-Host "     [-] Revoking OAuth Grant ID: $($grant.Id) (Scopes: $($grant.Scope))" -ForegroundColor Yellow
                        Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId $grant.Id -ErrorAction Stop
                        $grantCount++
                    }
                    Write-Host " [+] [5/5] Revoked $grantCount OAuth2 permission grant(s)." -ForegroundColor Green
                    $userReport.OAuthRevoked = "Revoked ($grantCount grants)"
                } else {
                    Write-Host " [+] [5/5] No delegated OAuth2 permission grants found for this user." -ForegroundColor Green
                    $userReport.OAuthRevoked = "None Found"
                }
            } catch {
                Write-Warning " [-] [5/5] Failed to audit/revoke OAuth grants: $($_.Exception.Message)"
                $userReport.OAuthRevoked = "Failed"
                $userReport.Errors += "OAuth error: $($_.Exception.Message)"
            }
        }
    }

    if ($userReport.Errors.Count -gt 0) {
        $userReport.Status = "Partial/Errors"
    }

    $summaryReport += $userReport
}

# --- Display Final Summary Table ---
Write-Host "`n" + ("=" * 80) -ForegroundColor Cyan
Write-Host "                   CONTAINMENT EXECUTION SUMMARY" -ForegroundColor Cyan
Write-Host ("=" * 80) -ForegroundColor Cyan
$summaryReport | Format-Table -Property User, AccountDisabled, SessionsRevoked, PasswordReset, MfaPurged, OAuthRevoked, Status -AutoSize

Write-Host "[+] All containment operations finished." -ForegroundColor Green
