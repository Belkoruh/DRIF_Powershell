# 🛡️ Containment & Remediation Suite

A robust set of incident containment, identity revocation, and host isolation scripts designed for rapid threat neutralization during active cyber security incidents across **Microsoft Cloud (Entra ID / M365)**, **On-Premises Active Directory**, and **Windows Endpoints / Servers**.

---

## 📋 Script Catalog

| Script | Scope / Target | Description & Actions | Privilege |
|:---|:---|:---|:---|
| [`Invoke-FullIdentityContainment.ps1`](./Invoke-FullIdentityContainment.ps1) | **Entra ID / M365** | **Enterprise Cloud Playbook**:<br>1. Disables account (`AccountEnabled = $false`)<br>2. Revokes active sessions & refresh tokens<br>3. Resets password to strong 32-char string<br>4. Audits & purges rogue MFA methods (FIDO2, Authenticator, Phone, TAP)<br>5. Revokes user-consented OAuth2 app grants | Graph: `User.ReadWrite.All`, `UserAuthenticationMethod.ReadWrite.All`, `DelegatedPermissionGrant.ReadWrite.All` |
| [`Isolate-Host.ps1`](./Isolate-Host.ps1) | **Host / Endpoint** | **Emergency Host Isolation**:<br>1. Firewall isolation (blocks inbound/outbound while keeping SOC IP whitelist)<br>2. Terminates compromised user processes<br>3. Forces interactive & RDP session logoff (`logoff.exe`)<br>4. Purges Kerberos tickets (`klist purge`) & Credential Manager<br>5. Clean isolation release (`-ReleaseIsolation`) | **Local Administrator** |
| [`Revoke-ADUserHybrid.ps1`](./Revoke-ADUserHybrid.ps1) | **Active Directory On-Prem** | **AD / Hybrid User Confinement**:<br>1. Disables AD account (RSAT or ADSI fallback)<br>2. Resets password & forces change on next login<br>3. Strips high-privilege group memberships<br>4. Moves account to Quarantine OU | **Domain Admin** / Delegated AD Admin |
| [`LocalUserResponse.ps1`](./LocalUserResponse.ps1) | **Local Windows Users** | Enumerate local admin/standard accounts (`-List`), rotate password to 20-char (`-Rotate <SID>`), kill processes (`-Kill <SID>`), delete rogue account (`-Delete <SID>`) | **Local Administrator** |
| [`RevokeSessions.ps1`](./RevokeSessions.ps1) | **Entra ID / M365** | Lightweight targeted sign-in session invalidation via Graph API | Graph: `User.RevokeSessions.All` |
| [`ForcePasswordChangeNextSignIn.ps1`](./ForcePasswordChangeNextSignIn.ps1) | **Entra ID / M365** | Sets temporary password and enforces password reset on next sign-in | Graph: `UserAuthenticationMethod.ReadWrite.All` |

---

## ⚡ Quick Usage Examples

### 1. Full Cloud Identity Containment (Entra ID / M365)
```powershell
# Full containment (Disable account + Revoke sessions + Password reset + Purge rogue MFA + Revoke OAuth grants)
.\Invoke-FullIdentityContainment.ps1 -Users "compromised_user@domain.com"

# Granular containment actions on multiple users
.\Invoke-FullIdentityContainment.ps1 -Users "user1@domain.com", "user2@domain.com" -RevokeSessions -PurgeMfa -RevokeOAuthGrants
```

### 2. Emergency Host & Network Isolation
```powershell
# Isolate machine from network while allowing SOC management IPs
.\Isolate-Host.ps1 -FullContainment -AllowedIPs "10.0.0.50", "192.168.1.100"

# Kill rogue user processes, logoff session, and purge cached credentials
.\Isolate-Host.ps1 -KillUserProcesses "attacker_user" -LogoffUser "attacker_user" -PurgeCredentials

# Lift emergency isolation and restore normal network connectivity
.\Isolate-Host.ps1 -ReleaseIsolation
```

### 3. Active Directory User Quarantine
```powershell
# Full AD containment (Disable account + Reset password + Remove admin groups)
.\Revoke-ADUserHybrid.ps1 -Identity "compromised_admin" -FullContainment

# Contain and move to Quarantine OU
.\Revoke-ADUserHybrid.ps1 -Identity "user01" -DisableAccount -ResetPassword -QuarantineOU "OU=Quarantine,DC=corp,DC=local"
```

---

## 📦 Prerequisites

### Microsoft Graph PowerShell SDK
To execute Entra ID / M365 cloud containment scripts:
```powershell
Install-Module Microsoft.Graph -Scope CurrentUser -Repository PSGallery -Force
```
