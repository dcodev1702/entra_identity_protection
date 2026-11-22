#Requires -Version 7.2

<#
.SYNOPSIS
    Reports on, and optionally dismisses, Microsoft Entra ID Protection user risk, and shows
    which Conditional Access (CA) policies enforced sign-in frequency on the user's sign-ins.

.DESCRIPTION
    Risk-based CA policies (for example "Require Passwordless for high-risk users") often pair a
    grant control with a 1-hour sign-in frequency session control. While a user sits at medium or
    high user risk, every token refresh past 60 minutes fails with:

        AADSTS70043: The refresh token has expired or is invalid due to sign-in frequency checks
        by conditional access ... the maximum allowed lifetime for this request is 3600.

    This script finds out why and, if you ask it to, clears the risk:

      1. Signs you in with OAuth 2.0 authorization code + PKCE against the
         "Microsoft Graph Command Line Tools" public client. No PowerShell modules required.
      2. Resolves the target user: the -User you pass, or the signed-in user if you omit it.
      3. Reads the user's riskyUser state and recent risk detections.
      4. With -Dismiss, dismisses the user's risk (only when riskState is 'atRisk').
      5. Reads the user's recent sign-ins and reports which CA policies applied, including which
         ones enforced a sign-in-frequency session control.

    The script never creates, modifies, or deletes Conditional Access policies.
    The access token is held in memory only and is never written to disk.

.PARAMETER User
    Target user: a UPN (user@contoso.com) or an Entra object ID (GUID).
    If omitted, the script targets the signed-in user.
    Aliases: -UserPrincipalName, -UPN, -UserId.

.PARAMETER TenantId
    Tenant ID or verified domain (for example contoso.onmicrosoft.com) to authenticate against.
    Defaults to 'organizations', which signs you in to your account's home tenant. Pass a
    tenant explicitly when you are working as a guest/B2B admin in another tenant.

.PARAMETER LoginHint
    Optional UPN to pre-fill on the sign-in page (the account that signs in, which can differ
    from -User when an admin is acting on someone else).

.PARAMETER Dismiss
    Dismiss the target user's risk. Acts only when riskState is 'atRisk'. Users whose riskState
    is 'confirmedCompromised' are never dismissed automatically. Supports -WhatIf and -Confirm.
    Requests IdentityRiskyUser.ReadWrite.All instead of IdentityRiskyUser.Read.All.

.PARAMETER WaitMinutes
    Dismissal is processed asynchronously (riskyUser.isProcessing = true). When greater than 0,
    poll every 30 seconds for up to this many minutes until processing completes.

.PARAMETER SignInCount
    Number of recent interactive sign-ins to analyze for applied CA policies. Default 60.

.PARAMETER TimeoutSeconds
    How long to wait for the browser sign-in to complete. Default 300.

.EXAMPLE
    .\Resolve-EntraUserRisk.ps1

    Read-only report for the signed-in user: risk state, risk detections, and which CA policies
    (including sign-in frequency) applied to recent sign-ins.

.EXAMPLE
    .\Resolve-EntraUserRisk.ps1 -Dismiss -WaitMinutes 5

    Dismiss the signed-in user's risk (if atRisk) and wait up to 5 minutes for it to finish.

.EXAMPLE
    .\Resolve-EntraUserRisk.ps1 -User alice@contoso.com

    Read-only report for another user. Requires a role that can read Identity Protection data
    (for example Security Reader) and sign-in logs.

.EXAMPLE
    .\Resolve-EntraUserRisk.ps1 -User alice@contoso.com -Dismiss -WhatIf

    Show what would be dismissed for alice without changing anything.

.EXAMPLE
    .\Resolve-EntraUserRisk.ps1 -User 00000000-0000-0000-0000-000000000000 -Dismiss -TenantId contoso.onmicrosoft.com -LoginHint admin@contoso.com

    Target a user by object ID in a specific tenant, pre-filling the admin account to sign in with.

.NOTES
    Author  : dcodev1702
    Date    : 2026-11-22
    Version : 1.1.0

    Requirements
      - PowerShell 7.2 or later (uses .NET 6+ crypto APIs).
      - Microsoft Entra ID P2 (Identity Protection) for the riskyUsers / riskDetections APIs.
      - Entra role for the signed-in account:
          Read risk ............ Security Reader, Security Operator, Global Reader (or higher)
          Dismiss risk ......... Security Administrator (least privileged), or Global Administrator
          Sign-in logs ......... Reports Reader, Security Reader, Global Reader (or higher)
          CA detail in logs .... Security Reader, Global Reader, Security Administrator, or
                                 Conditional Access Administrator
      - Delegated Graph scopes requested (admin consent needed for most of them on first use):
          IdentityRiskyUser.Read.All (or .ReadWrite.All with -Dismiss), IdentityRiskEvent.Read.All,
          AuditLog.Read.All, Policy.Read.ConditionalAccess, User.ReadBasic.All, User.Read

    Why not Azure CLI (az rest)? The Azure CLI's Microsoft Graph token cannot carry the
    IdentityRiskyUser.* scopes, so riskyUsers calls return 403. This script uses the
    Microsoft Graph Command Line Tools client, which supports dynamic consent to these scopes.

.LINK
    https://learn.microsoft.com/graph/api/riskyuser-dismiss

.LINK
    https://learn.microsoft.com/entra/identity/conditional-access/concept-session-lifetime
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param(
    [Parameter(Position = 0)]
    [Alias('UserPrincipalName', 'UPN', 'UserId')]
    [string]$User,

    [string]$TenantId = 'organizations',

    [string]$LoginHint,

    [switch]$Dismiss,

    [ValidateRange(0, 60)]
    [int]$WaitMinutes = 0,

    [ValidateRange(1, 999)]
    [int]$SignInCount = 60,

    [ValidateRange(30, 1800)]
    [int]$TimeoutSeconds = 300
)

$ErrorActionPreference = 'Stop'

# ------------------------------------------------------------------------------------------------
# Constants
# ------------------------------------------------------------------------------------------------
$ClientId = '14d82eec-204b-4c2f-b7e8-296a70dab67e'   # Microsoft Graph Command Line Tools (public client)
$Graph    = 'https://graph.microsoft.com'

# Least-privileged delegated scopes. The risky-user scope is only escalated to ReadWrite for -Dismiss.
$RequiredScopes = @(
    $(if ($Dismiss) { 'IdentityRiskyUser.ReadWrite.All' } else { 'IdentityRiskyUser.Read.All' }),
    'IdentityRiskEvent.Read.All',    # riskDetections
    'AuditLog.Read.All',             # sign-in logs
    'Policy.Read.ConditionalAccess', # appliedConditionalAccessPolicies in sign-in logs
    'User.ReadBasic.All',            # resolve -User to an object ID
    'User.Read'                      # resolve the signed-in user (/me)
)
$ScopeString = (($RequiredScopes | ForEach-Object { "$Graph/$_" }) + 'openid', 'profile') -join ' '

# ------------------------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------------------------
function ConvertTo-Base64Url([byte[]]$Bytes) {
    [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Get-HttpStatusCode($ErrorRecord) {
    try { [int]$ErrorRecord.Exception.Response.StatusCode } catch { 0 }
}

function Invoke-Graph {
    param([string]$Uri, [string]$Method = 'Get', $Body)
    $params = @{ Method = $Method; Uri = $Uri; Headers = $script:AuthHeader }
    if ($null -ne $Body) { $params.Body = ($Body | ConvertTo-Json -Depth 5); $params.ContentType = 'application/json' }
    Invoke-RestMethod @params
}

function Get-RiskyUser([string]$UserObjectId) {
    # 404 means Identity Protection has never flagged this user.
    try { Invoke-Graph -Uri "$Graph/v1.0/identityProtection/riskyUsers/$UserObjectId" }
    catch { if ((Get-HttpStatusCode $_) -eq 404) { $null } else { throw } }
}

function Wait-RiskProcessing([string]$UserObjectId, [int]$Minutes) {
    # Dismissal is asynchronous; poll until isProcessing is false or the deadline passes.
    $state    = Get-RiskyUser $UserObjectId
    $deadline = (Get-Date).AddMinutes($Minutes)
    while ($state -and $state.isProcessing -and (Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 30
        $state = Get-RiskyUser $UserObjectId
        Write-Host ("{0}  isProcessing={1}  riskState={2}  riskLevel={3}" -f (Get-Date -Format T), $state.isProcessing, $state.riskState, $state.riskLevel)
    }
    $state
}

function Show-RiskyUser($State) {
    if ($State) {
        $State | Select-Object userPrincipalName, riskLevel, riskState, riskDetail, riskLastUpdatedDateTime, isProcessing |
            Format-List | Out-String -Width 200
    } else {
        'No riskyUser record: Identity Protection has never flagged this user.'
    }
}

# ------------------------------------------------------------------------------------------------
# 1. Sign in: OAuth 2.0 authorization code + PKCE with a localhost redirect
# ------------------------------------------------------------------------------------------------
$codeVerifier  = ConvertTo-Base64Url ([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
$codeChallenge = ConvertTo-Base64Url ([System.Security.Cryptography.SHA256]::HashData([Text.Encoding]::ASCII.GetBytes($codeVerifier)))
$oauthState    = ConvertTo-Base64Url ([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(16))

# Pick a free loopback port, then listen on it for the redirect.
$probe = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
$probe.Start(); $port = ([System.Net.IPEndPoint]$probe.LocalEndpoint).Port; $probe.Stop()
$redirectUri = "http://localhost:$port/"
$listener = [System.Net.HttpListener]::new()
$listener.Prefixes.Add($redirectUri)
$listener.Start()

$authQuery = @(
    "client_id=$ClientId"
    'response_type=code'
    'response_mode=query'
    "redirect_uri=$([uri]::EscapeDataString($redirectUri))"
    "scope=$([uri]::EscapeDataString($ScopeString))"
    "state=$oauthState"
    "code_challenge=$codeChallenge"
    'code_challenge_method=S256'
)
if ($LoginHint) { $authQuery += "login_hint=$([uri]::EscapeDataString($LoginHint))" }
$authorizeUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/authorize?" + ($authQuery -join '&')

Write-Output "Opening the browser to sign in (waiting up to $TimeoutSeconds seconds)..."
# -WhatIf must not suppress the sign-in itself; only the dismiss call is gated by ShouldProcess.
Start-Process $authorizeUrl -WhatIf:$false -Confirm:$false
try {
    $contextTask = $listener.GetContextAsync()
    if (-not $contextTask.Wait([TimeSpan]::FromSeconds($TimeoutSeconds))) { throw 'Timed out waiting for the browser sign-in.' }
    $context = $contextTask.Result
    $query   = $context.Request.QueryString

    $message = if ($query['error']) { "Sign-in failed: $($query['error'])" } else { 'Sign-in complete. You can close this tab and return to PowerShell.' }
    $html    = [Text.Encoding]::UTF8.GetBytes("<html><body style='font-family:Segoe UI,sans-serif;padding:2em'>$message</body></html>")
    $context.Response.ContentType     = 'text/html'
    $context.Response.ContentLength64 = $html.Length
    $context.Response.OutputStream.Write($html, 0, $html.Length)
    $context.Response.OutputStream.Close()
} finally {
    $listener.Stop(); $listener.Close()
}

if ($query['error'])                 { throw "Authorization error: $($query['error']) - $($query['error_description'])" }
if ($query['state'] -ne $oauthState) { throw 'OAuth state mismatch; aborting.' }

$token = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
    -ContentType 'application/x-www-form-urlencoded' -Body @{
        client_id     = $ClientId
        grant_type    = 'authorization_code'
        code          = $query['code']
        redirect_uri  = $redirectUri
        code_verifier = $codeVerifier
        scope         = $ScopeString
    }
$script:AuthHeader = @{ Authorization = "Bearer $($token.access_token)" }

# Warn about any required scope that consent did not grant (calls that need it will fail).
$granted = $token.scope -split ' ' | ForEach-Object { $_ -replace '^https://graph\.microsoft\.com/', '' }
$missing = $RequiredScopes | Where-Object { $_ -notin $granted }
if ($missing) { Write-Warning "Token is missing scopes: $($missing -join ', '). Related sections may fail with 403." }

# ------------------------------------------------------------------------------------------------
# 2. Resolve the signed-in user and the target user
# ------------------------------------------------------------------------------------------------
$me = Invoke-Graph -Uri "$Graph/v1.0/me?`$select=id,userPrincipalName,displayName"
if ($User) {
    $target = Invoke-Graph -Uri "$Graph/v1.0/users/$([uri]::EscapeDataString($User))?`$select=id,userPrincipalName,displayName"
} else {
    $target = $me
}
$userObjectId = $target.id

Write-Output ''
Write-Output "Signed in as : $($me.userPrincipalName)"
Write-Output "Target user  : $($target.userPrincipalName) ($userObjectId)$(if (-not $User) { '  [signed-in user]' })"

# ------------------------------------------------------------------------------------------------
# 3. Risky-user state and risk detections
# ------------------------------------------------------------------------------------------------
$riskyUser = Get-RiskyUser $userObjectId
Write-Output ''
Write-Output '=== Risky-user state ==='
Show-RiskyUser $riskyUser

$userFilter = [uri]::EscapeDataString("userId eq '$userObjectId'")
$detections = @((Invoke-Graph -Uri "$Graph/v1.0/identityProtection/riskDetections?`$filter=$userFilter&`$top=50").value)
Write-Output "=== Risk detections (most recent 15 of $($detections.Count)) ==="
$detections | Sort-Object detectedDateTime -Descending | Select-Object -First 15 |
    Select-Object detectedDateTime, riskEventType, riskLevel, riskState, detectionTimingType, ipAddress,
        @{ Name = 'location'; Expression = { "$($_.location.city), $($_.location.countryOrRegion)" } } |
    Format-Table -AutoSize -Wrap | Out-String -Width 220

# ------------------------------------------------------------------------------------------------
# 4. Dismiss user risk (guarded; supports -WhatIf / -Confirm)
# ------------------------------------------------------------------------------------------------
if ($Dismiss) {
    if (-not $riskyUser -or $riskyUser.riskState -in 'none', 'dismissed', 'remediated') {
        Write-Output "Dismiss requested, but riskState is '$($riskyUser.riskState)'. Nothing to dismiss."
    } elseif ($riskyUser.riskState -eq 'confirmedCompromised') {
        Write-Output 'Dismiss requested, but riskState is confirmedCompromised (an admin confirmed it). Not dismissing automatically.'
    } elseif ($PSCmdlet.ShouldProcess($target.userPrincipalName, 'Dismiss Entra ID Protection user risk')) {
        Invoke-Graph -Method Post -Uri "$Graph/v1.0/identityProtection/riskyUsers/dismiss" -Body @{ userIds = @($userObjectId) } | Out-Null
        Write-Output 'Dismiss request accepted (processed asynchronously).'
        $riskyUser = if ($WaitMinutes -gt 0) { Wait-RiskProcessing $userObjectId $WaitMinutes } else { Get-RiskyUser $userObjectId }
        Write-Output '=== Risky-user state after dismiss ==='
        Show-RiskyUser $riskyUser
        if ($riskyUser.isProcessing) { Write-Output 'Still processing. Re-run with -WaitMinutes 5 to confirm completion.' }
    }
} elseif ($WaitMinutes -gt 0 -and $riskyUser.isProcessing) {
    Write-Output 'A previous dismissal is still processing; waiting...'
    Show-RiskyUser (Wait-RiskProcessing $userObjectId $WaitMinutes)
}

# ------------------------------------------------------------------------------------------------
# 5. Which CA policies applied to recent sign-ins, and which enforced sign-in frequency
#    (appliedConditionalAccessPolicies is only returned when the caller can read CA data)
# ------------------------------------------------------------------------------------------------
try {
    $signIns = @((Invoke-Graph -Uri "$Graph/beta/auditLogs/signIns?`$filter=$userFilter&`$top=$SignInCount").value)
} catch {
    Write-Warning "Could not read sign-in logs (HTTP $(Get-HttpStatusCode $_)). Requires AuditLog.Read.All and a role such as Reports Reader or Security Reader."
    $signIns = @()
}

if ($signIns.Count -gt 0) {
    $applied = foreach ($s in $signIns) {
        foreach ($p in $s.appliedConditionalAccessPolicies) {
            if ($p.result -eq 'success') {
                [pscustomobject]@{ Policy = $p.displayName; SessionControls = ($p.enforcedSessionControls -join ',') }
            }
        }
    }
    Write-Output "=== CA policies that applied (result = success) across the last $($signIns.Count) interactive sign-ins ==="
    if ($applied) {
        $applied | Group-Object Policy, SessionControls | Sort-Object Count -Descending |
            Select-Object Count, @{ Name = 'Policy, SessionControls'; Expression = { $_.Name } } |
            Format-Table -AutoSize -Wrap | Out-String -Width 220
    } else {
        'No applied-policy detail returned. The signed-in account may lack a role that can read CA data (see .NOTES).'
    }

    $frequencyHits = foreach ($s in $signIns) {
        foreach ($p in $s.appliedConditionalAccessPolicies) {
            if ($p.result -eq 'success' -and (($p.enforcedSessionControls -join ',') -like '*Frequency*')) {
                [pscustomobject]@{ Time = $s.createdDateTime; App = $s.appDisplayName; Policy = $p.displayName; SignInRisk = $s.riskLevelDuringSignIn }
            }
        }
    }
    Write-Output '=== Sign-ins where a sign-in frequency control was enforced (latest 10) ==='
    if ($frequencyHits) { $frequencyHits | Select-Object -First 10 | Format-Table -AutoSize | Out-String -Width 200 }
    else { 'None in this window.' }

    # Quick "is it fixed?" view: after a dismissal, new sign-ins should no longer show the
    # risk-based policy's sign-in frequency control. Sign-in logs can lag by several minutes.
    if ($applied) {
        Write-Output '=== Most recent 5 sign-ins: sign-in frequency enforced? ==='
        $signIns | Sort-Object createdDateTime -Descending | Select-Object -First 5 | ForEach-Object {
            $sifPolicies = @($_.appliedConditionalAccessPolicies |
                Where-Object { $_.result -eq 'success' -and (($_.enforcedSessionControls -join ',') -like '*Frequency*') } |
                ForEach-Object { $_.displayName })   # script-block form: 'ForEach-Object <member>' honors -WhatIf
            [pscustomobject]@{
                Time            = $_.createdDateTime
                App             = $_.appDisplayName
                SignInFrequency = if ($sifPolicies) { $sifPolicies -join '; ' } else { 'none' }
            }
        } | Format-Table -AutoSize | Out-String -Width 200
    }
}
