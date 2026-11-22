# Entra ID Protection: `Resolve-EntraUserRisk.ps1`

Find out why Microsoft Entra keeps forcing you to sign in again every hour, and clear the user risk behind it from PowerShell. You don't need to click through the portal, and you don't need to install any modules.

| | |
|---|---|
| **Author** | dcodev1702 |
| **Date** | 2026-11-22 |
| **Version** | 1.1.0 |
| **Requires** | PowerShell 7.2+, Microsoft Entra ID P2 |

---

## The problem

Every hour, the Azure CLI, the Azure portal and other Microsoft tools stop working until you sign in again. The Azure CLI shows an error like this:

```text
AADSTS70043: The refresh token has expired or is invalid due to sign-in frequency checks by
conditional access. The token was issued on <time> and the maximum allowed lifetime for this
request is 3600.
```

`3600` is seconds: a **1-hour sign-in frequency** set by a Conditional Access (CA) session control. In this case it didn't come from a blanket "re-authenticate every hour" policy. It came from **risk-based** CA policies. They apply only while Entra ID Protection rates the sign-in or the user as risky. If your **user risk** gets stuck at medium or high, for example after a VPN exit node triggers an `anonymizedIPAddress` or `anomalousToken` detection, the 1-hour limit applies to every sign-in until that risk is dismissed or remediated.

## The CA policies that enforce the 1-hour sign-in

These two policies in the author's tenant set the 1-hour sign-in frequency:

| Policy | Applies when | Grant control | Session control |
|---|---|---|---|
| **CA007 - Require Passwordless for risky sign-ins** | **Sign-in risk** is medium or high | Authentication strength: Passwordless MFA | Sign-in frequency: **1 hour** (time-based, primary and secondary authentication) |
| **CA008 - Require Passwordless for high-risk users** | **User risk** is medium or high | Authentication strength: Passwordless MFA | Sign-in frequency: **1 hour** (time-based, primary and secondary authentication) |

Both target all users and all cloud apps, with break-glass exclusions.

- **CA007** acts on each sign-in separately. Once a sign-in is no longer risky, it stops applying.
- **CA008** is the one that sticks. User risk stays at its level until an admin dismisses it, the user remediates it, or it's confirmed safe. Until then, **every** sign-in gets the 1-hour limit. That was the root cause here: the sign-in log showed `CA008 ... SignInFrequency` on every sign-in, while sign-in risk was `none`.

Your tenant's policy names may differ. The script reports whichever policies actually applied to your sign-ins, so you don't need to know the names in advance.

> This script **does not create, modify or delete Conditional Access policies**. Clearing the user risk makes CA008 stop matching your account. The policy itself stays exactly as it was.

## What the script does

1. **Signs in** with OAuth 2.0 authorization code + PKCE against the Microsoft Graph Command Line Tools public client (`14d82eec-204b-4c2f-b7e8-296a70dab67e`). A browser tab opens, the same way `az login` does. The token is held only in memory.
2. **Resolves the target user**: `-User` (a UPN or object ID), or **the signed-in user if `-User` is omitted**.
3. **Reports risk**: the riskyUser state (`riskLevel`, `riskState`, `riskDetail`) and recent risk detections, with type, level, IP address and location.
4. **Dismisses the risk when you pass `-Dismiss`**, but only when `riskState` is `atRisk`. It never automatically dismisses a user whose risk is `confirmedCompromised`. Supports `-WhatIf` and `-Confirm`.
5. **Explains the CA side** by reading recent sign-ins and showing:
   - which CA policies applied
   - which ones enforced a **sign-in frequency** control
   - whether the **5 most recent sign-ins** still had one, which is your "is it fixed?" check

## Why not the Azure CLI?

`az rest` can call Microsoft Graph, but the Azure CLI's Graph token can't carry the `IdentityRiskyUser.*` scopes. As a result:

- `GET /identityProtection/riskyUsers` returns **403** ("required scopes are missing in the token").
- Sign-in logs come back **without** `appliedConditionalAccessPolicies`, so you can't see which policy is forcing the re-authentication.

The Microsoft Graph Command Line Tools client supports dynamic consent to the scopes these calls need.

## Requirements

- **PowerShell 7.2 or later.** The script uses .NET 6+ crypto APIs for PKCE.
- **Microsoft Entra ID P2.** It's required by the Identity Protection APIs.
- **An Entra role for the account that signs in.** Use PIM to activate it if needed.

| Task | Least-privileged roles |
|---|---|
| Read risk state and detections | Security Reader, Security Operator, Global Reader |
| **Dismiss risk (`-Dismiss`)** | **Security Administrator** (or Global Administrator) |
| Read sign-in logs | Reports Reader, Security Reader, Global Reader, Security Operator, Security Administrator |
| See CA policy detail in sign-in logs | Security Reader, Global Reader, Security Administrator, Conditional Access Administrator |

**Delegated Microsoft Graph scopes requested (least privilege):**

| Scope | Used for |
|---|---|
| `IdentityRiskyUser.Read.All`, or `IdentityRiskyUser.ReadWrite.All` only with `-Dismiss` | riskyUsers read / dismiss |
| `IdentityRiskEvent.Read.All` | riskDetections |
| `AuditLog.Read.All` | Sign-in logs |
| `Policy.Read.ConditionalAccess` | `appliedConditionalAccessPolicies` in sign-in logs |
| `User.ReadBasic.All` | Resolving `-User` to an object ID |
| `User.Read`, `openid`, `profile` | The signed-in user (`/me`) |

On first use you may see a consent prompt. Most of these scopes need an admin's consent. As an admin, leave **"Consent on behalf of your organization"** unchecked if you want the grant to apply to your own account only.

## Usage

```powershell
# Read-only report for the signed-in user
.\Resolve-EntraUserRisk.ps1

# Dismiss the signed-in user's risk (if atRisk) and wait up to 5 minutes for it to finish
.\Resolve-EntraUserRisk.ps1 -Dismiss -WaitMinutes 5

# Read-only report for another user
.\Resolve-EntraUserRisk.ps1 -User alice@contoso.com

# Preview a dismissal without changing anything
.\Resolve-EntraUserRisk.ps1 -User alice@contoso.com -Dismiss -WhatIf

# Target a user by object ID in a specific tenant, pre-filling the admin sign-in
.\Resolve-EntraUserRisk.ps1 -User 00000000-0000-0000-0000-000000000000 -Dismiss `
    -TenantId contoso.onmicrosoft.com -LoginHint admin@contoso.com

# Full help
Get-Help .\Resolve-EntraUserRisk.ps1 -Full
```

### Parameters

| Parameter | Default | Description |
|---|---|---|
| `-User` (aliases `-UserPrincipalName`, `-UPN`, `-UserId`) | *signed-in user* | Target user, as a UPN or object ID |
| `-TenantId` | `organizations` | Tenant ID or domain. `organizations` uses your account's home tenant |
| `-LoginHint` | *(none)* | Pre-fills the account on the sign-in page |
| `-Dismiss` | off | Dismisses user risk when `riskState` is `atRisk`. Supports `-WhatIf` and `-Confirm` |
| `-WaitMinutes` | `0` | Polls every 30 seconds until the dismissal finishes processing (it runs asynchronously) |
| `-SignInCount` | `60` | Number of recent interactive sign-ins to analyze |
| `-TimeoutSeconds` | `300` | How long to wait for the browser sign-in |

## Example output

The output below is sanitized.

```text
Signed in as : admin@contoso.com
Target user  : admin@contoso.com (00000000-0000-0000-0000-000000000000)  [signed-in user]

=== Risky-user state ===
riskLevel               : medium
riskState               : atRisk
riskDetail              : none

=== Risk detections (most recent 15 of 6) ===
detectedDateTime      riskEventType       riskLevel riskState     ipAddress    location
10/18/2026 2:28:10 AM anonymizedIPAddress high      confirmedSafe 203.0.113.10 New York, US
10/17/2026 10:45:10 PM anomalousToken     medium    atRisk        203.0.113.10 New York, US

Dismiss request accepted (processed asynchronously).
8:52:22 PM  isProcessing=False  riskState=dismissed  riskLevel=none
=== Risky-user state after dismiss ===
riskLevel               : none
riskState               : dismissed
riskDetail              : adminDismissedAllRiskForUser

=== CA policies that applied (result = success) across the last 60 interactive sign-ins ===
Count Policy, SessionControls
   58 CA004 - Require MFA for all users,
   58 CA008 - Require Passwordless for high-risk users, SignInFrequency

=== Most recent 5 sign-ins: sign-in frequency enforced? ===
Time                  App                                SignInFrequency
11/22/2026 8:02:19 PM Microsoft Graph Command Line Tools none            <- after dismissal
11/22/2026 7:51:52 PM Microsoft Graph Command Line Tools CA008 - Require Passwordless for high-risk users
```

## After you dismiss

- **It takes a minute or two.** Dismissal runs asynchronously (`isProcessing: true`). Use `-WaitMinutes`.
- **The sign-in log lags.** It can be several minutes before new sign-ins appear, so re-run the script to see `SignInFrequency = none` on them.
- **You may need to sign in once more.** Existing CLI and browser sessions may need one more sign-in. After that, tokens refresh normally.
- **Fix the cause, not just the symptom.** If the detection was real, don't just dismiss it: reset the password, revoke sessions and investigate. If it was your own VPN or travel, the risk can come back the next time the same signal fires. The detections table tells you what triggered it.

## Security notes

- **Token handling:** the access token is never written to disk or printed.
- **Extra scopes:** tokens from the Microsoft Graph Command Line Tools app include **every scope previously consented to that app in your tenant**, not just the ones this script requests. Review that app's delegated permission grants under **Enterprise applications** in Entra if the list is broader than you expect.
- **Dismissal is audited:** the riskyUser history records it as `adminDismissedAllRiskForUser`.

## Microsoft Graph endpoints used

| Method | Endpoint |
|---|---|
| GET | `/v1.0/me`, `/v1.0/users/{id or UPN}` |
| GET | `/v1.0/identityProtection/riskyUsers/{id}` |
| GET | `/v1.0/identityProtection/riskDetections?$filter=userId eq '{id}'` |
| POST | `/v1.0/identityProtection/riskyUsers/dismiss` |
| GET | `/beta/auditLogs/signIns?$filter=userId eq '{id}'` |

## References

- [riskyUser: dismiss](https://learn.microsoft.com/graph/api/riskyuser-dismiss)
- [List signIns: permissions and CA data](https://learn.microsoft.com/graph/api/signin-list)
- [Conditional Access: sign-in frequency](https://learn.microsoft.com/entra/identity/conditional-access/concept-session-lifetime)
- [Remediate risks and unblock users](https://learn.microsoft.com/entra/id-protection/howto-identity-protection-remediate-unblock)
