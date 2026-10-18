$script:TRGoogleScopeBase = 'https://www.googleapis.com/auth/'

$script:TRGoogleScopes = @(
    'openid', 'email', 'profile',
    'admin.directory.customer.readonly', 'admin.directory.domain.readonly', 'admin.directory.orgunit.readonly',
    'admin.directory.user.readonly', 'admin.directory.group.readonly', 'admin.directory.rolemanagement.readonly',
    'admin.directory.user.security', 'admin.directory.device.mobile.readonly', 'admin.directory.device.chromeos.readonly',
    'admin.reports.audit.readonly', 'admin.reports.usage.readonly',
    'apps.licensing', 'apps.groups.settings', 'apps.alerts',
    'cloud-identity.policies.readonly', 'cloud-identity.inboundsso.readonly', 'cloud-identity.devices.readonly'
)

$script:TRGoogleScopeAreas = [ordered]@{
    'admin.directory.customer.readonly'      = 'organisation details'
    'admin.directory.domain.readonly'        = 'domains'
    'admin.directory.orgunit.readonly'       = 'organisational units'
    'admin.directory.user.readonly'          = 'users'
    'admin.directory.group.readonly'         = 'groups and members'
    'admin.directory.rolemanagement.readonly' = 'admin roles'
    'admin.directory.user.security'          = 'third-party app tokens and app passwords'
    'admin.directory.device.mobile.readonly' = 'mobile devices'
    'admin.directory.device.chromeos.readonly' = 'ChromeOS devices'
    'admin.reports.audit.readonly'           = 'audit logs (admin, login, Drive and token events)'
    'admin.reports.usage.readonly'           = 'usage reports'
    'apps.licensing'                         = 'licence assignments'
    'apps.groups.settings'                   = 'group settings'
    'apps.alerts'                            = 'Alert Center'
    'cloud-identity.policies.readonly'       = 'Admin console settings (Policy API)'
    'cloud-identity.inboundsso.readonly'     = 'SSO profiles'
    'cloud-identity.devices.readonly'        = 'endpoint management devices'
}

function Get-TRGoogleScopeString {
    (@($script:TRGoogleScopes | ForEach-Object { if ($_ -in @('openid', 'email', 'profile')) { $_ } else { $script:TRGoogleScopeBase + $_ } }) -join ' ')
}

function Get-TRGoogleFriendlyError {
    param([string]$Code, [string]$Description)
    $t = ('{0} {1}' -f $Code, $Description)
    if ($t -match 'admin_policy_enforced') { return 'The client''s Google Workspace blocks this app. A super admin must mark the review app as Trusted in the Admin console (Security, Access and data control, API controls), then try again.' }
    if ($t -match 'org_internal') { return 'The review app is set to Internal in Google Cloud, so only accounts in your own Google organisation can use it. Set the OAuth consent screen user type to External.' }
    if ($t -match 'access_denied') { return 'Access was not approved in the browser. Sign in again and select Allow, ticking every permission listed.' }
    if ($t -match 'invalid_client|unauthorized_client') { return 'Google did not recognise the review app OAuth client. Check GoogleClientId and GoogleClientSecret in config.json match the Desktop app client in the Google Cloud project for the review app.' }
    if ($t -match 'redirect_uri_mismatch') { return 'Redirect URI mismatch. The OAuth client in Google Cloud must be of type Desktop app.' }
    if ($t -match 'invalid_grant') { return 'The Google sign-in has expired or was revoked. Sign in again.' }
    if ($t -match 'disabled_client') { return 'The review app OAuth client has been disabled in Google Cloud.' }
    $first = ([string]$Description -split "`r?`n")[0]
    if ($Code -and $first) { return "$Code - $first" }
    if ($Code) { return $Code }
    $first
}

function Invoke-TRGoogleTokenRequest {
    param([hashtable]$Form)
    $ctx = $script:TRContext
    try {
        Invoke-RestMethod -Method Post -Uri ($ctx.GoogleTokenBase + '/token') -Body $Form -ContentType 'application/x-www-form-urlencoded' -UseBasicParsing -ErrorAction Stop -TimeoutSec 60
    }
    catch {
        $info = Get-TRErrorInfo $_
        $code = [string]$info.Code
        $desc = $info.Message
        try {
            $j = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction Stop
            if ($j.error -is [string]) { $code = $j.error }
            if ($j.error_description) { $desc = $j.error_description }
        }
        catch { }
        $ex = New-Object System.Exception((Get-TRGoogleFriendlyError -Code $code -Description $desc))
        $ex.Data['HttpStatus'] = $info.Status
        $ex.Data['ErrorCode'] = $code
        $ex.Data['AuthError'] = $true
        throw $ex
    }
}

function Set-TRGoogleToken {
    param($TokenResponse)
    $ctx = $script:TRContext
    $ctx.Tokens['Google'] = [pscustomobject]@{ AccessToken = [string]$TokenResponse.access_token; ExpiresOn = (Get-Date).ToUniversalTime().AddSeconds([int]$TokenResponse.expires_in - 60) }
    if ($TokenResponse.refresh_token) { $ctx.RefreshToken = [string]$TokenResponse.refresh_token }
    if ($TokenResponse.scope) { $ctx.Scopes['Google'] = [string]$TokenResponse.scope }
}

function Get-TRGoogleToken {
    $ctx = $script:TRContext
    if (-not $ctx) { throw 'Not signed in.' }
    $t = $ctx.Tokens['Google']
    if ($t -and $t.ExpiresOn -gt (Get-Date).ToUniversalTime().AddMinutes(3)) { return $t.AccessToken }
    if (-not $ctx.RefreshToken) {
        if ($t) { return $t.AccessToken }
        throw 'Not signed in.'
    }
    $form = @{ client_id = $ctx.ClientId; client_secret = $ctx.ClientSecret; grant_type = 'refresh_token'; refresh_token = $ctx.RefreshToken }
    $tok = Invoke-TRGoogleTokenRequest -Form $form
    Set-TRGoogleToken -TokenResponse $tok
    $tok.access_token
}

function Get-TRGoogleBase {
    param([ValidateSet('Admin', 'Identity', 'Licensing', 'Groups', 'Alert', 'UserInfo')][string]$Service)
    $ctx = $script:TRContext
    switch ($Service) {
        'Admin' { $ctx.GoogleAdminBase }
        'Identity' { $ctx.GoogleIdentityBase }
        'Licensing' { $ctx.GoogleLicensingBase }
        'Groups' { $ctx.GoogleGroupsBase }
        'Alert' { $ctx.GoogleAlertBase }
        'UserInfo' { $ctx.GoogleUserInfoBase }
    }
}

function ConvertTo-TRQuery {
    param([hashtable]$Query)
    if (-not $Query -or -not $Query.Count) { return '' }
    $parts = foreach ($k in ($Query.Keys | Sort-Object)) {
        $v = $Query[$k]
        if ($null -eq $v -or [string]$v -eq '') { continue }
        '{0}={1}' -f [uri]::EscapeDataString([string]$k), [uri]::EscapeDataString([string]$v)
    }
    '?' + (@($parts) -join '&')
}

function Invoke-TRGoogle {
    param(
        [ValidateSet('Admin', 'Identity', 'Licensing', 'Groups', 'Alert', 'UserInfo')][string]$Service = 'Admin',
        [Parameter(Mandatory = $true)][string]$Path,
        [hashtable]$Query = @{},
        [string]$Method = 'GET',
        $Body,
        [switch]$All,
        [string]$ItemsKey,
        [int]$MaxItems = 0,
        [int]$PageDelayMs = 0,
        [int]$MaxRetry = 6
    )
    $base = Get-TRGoogleBase $Service
    $q = @{}
    foreach ($k in $Query.Keys) { $q[$k] = $Query[$k] }
    $json = $null
    if ($null -ne $Body) { $json = if ($Body -is [string]) { $Body } else { ConvertTo-Json -InputObject $Body -Depth 20 -Compress } }
    $results = New-Object System.Collections.ArrayList
    while ($true) {
        $uri = $base + $Path + (ConvertTo-TRQuery $q)
        $headers = @{ Authorization = 'Bearer ' + (Get-TRGoogleToken) }
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $r = Invoke-TRRest -Method $Method -Uri $uri -Headers $headers -Body $json -MaxRetry $MaxRetry
        if (-not $All) { return $r }
        if ($ItemsKey -and (Test-TRHasProperty $r $ItemsKey)) {
            foreach ($i in @($r.$ItemsKey)) { if ($null -ne $i) { [void]$results.Add($i) } }
        }
        if ($MaxItems -gt 0 -and $results.Count -ge $MaxItems) { break }
        $next = $null
        if (Test-TRHasProperty $r 'nextPageToken') { $next = [string]$r.nextPageToken }
        if (-not $next) { break }
        $q['pageToken'] = $next
        if ($PageDelayMs -gt 0 -and $sw.ElapsedMilliseconds -lt $PageDelayMs) { Start-Sleep -Milliseconds ($PageDelayMs - [int]$sw.ElapsedMilliseconds) }
    }
    , $results.ToArray()
}

function Connect-TRGoogle {
    param(
        [string]$Domain,
        [Parameter(Mandatory = $true)][string]$ClientId,
        [Parameter(Mandatory = $true)][string]$ClientSecret,
        [string]$LoginHint,
        [int]$TimeoutSeconds = 300,
        [scriptblock]$OnAuthUrl,
        [switch]$NoBrowser
    )
    $existing = $script:TRContext
    if ($existing -and $existing.Platform -eq 'Google') {
        New-TRContext -Tenant $Domain -ClientId $ClientId -Platform Google -ClientSecret $ClientSecret -DohBase $existing.DohBase -DnsMode $existing.DnsMode -GoogleAuthBase $existing.GoogleAuthBase -GoogleTokenBase $existing.GoogleTokenBase -GoogleAdminBase $existing.GoogleAdminBase -GoogleIdentityBase $existing.GoogleIdentityBase -GoogleLicensingBase $existing.GoogleLicensingBase -GoogleGroupsBase $existing.GoogleGroupsBase -GoogleAlertBase $existing.GoogleAlertBase -GoogleUserInfoBase $existing.GoogleUserInfoBase | Out-Null
    }
    else {
        $dns = 'Auto'
        try { $dns = [string](Get-TRSetting 'DnsMode' 'Auto') } catch { }
        if ($dns -notin @('Auto', 'Native', 'DoH')) { $dns = 'Auto' }
        New-TRContext -Tenant $Domain -ClientId $ClientId -Platform Google -ClientSecret $ClientSecret -DnsMode $dns | Out-Null
    }
    $ctx = $script:TRContext
    $pkce = New-TRPkce
    $state = [guid]::NewGuid().ToString('N')
    $lb = Start-TRLoopback
    try {
        $q = [ordered]@{
            client_id             = $ClientId
            redirect_uri          = $lb.RedirectUri
            response_type         = 'code'
            scope                 = (Get-TRGoogleScopeString)
            state                 = $state
            code_challenge        = $pkce.Challenge
            code_challenge_method = 'S256'
            access_type           = 'offline'
            prompt                = 'consent select_account'
            include_granted_scopes = 'true'
        }
        if ($LoginHint) { $q['login_hint'] = $LoginHint }
        if ($Domain -and $Domain -match '\.') { $q['hd'] = $Domain }
        $parts = foreach ($k in $q.Keys) { '{0}={1}' -f $k, [uri]::EscapeDataString([string]$q[$k]) }
        $authUrl = $ctx.GoogleAuthBase + '/o/oauth2/v2/auth?' + (@($parts) -join '&')
        if ($OnAuthUrl) { & $OnAuthUrl $authUrl }
        elseif ($script:TRAuthUrlSink) { & $script:TRAuthUrlSink $authUrl }
        Write-TRLog 'Opening the browser for Google sign-in. Sign in as a super admin of the client, approve every permission listed, then return here.'
        if (-not $NoBrowser) { Start-Process $authUrl }
        $resp = Wait-TRLoopbackRequest -Listener $lb -TimeoutSeconds $TimeoutSeconds
    }
    finally {
        Stop-TRLoopback $lb
    }
    if ($resp.ContainsKey('error')) {
        $ex = New-Object System.Exception((Get-TRGoogleFriendlyError -Code $resp['error'] -Description $resp['error_description']))
        $ex.Data['AuthError'] = $true
        throw $ex
    }
    if ($resp['state'] -ne $state) { throw 'Sign-in response did not match the request. Try again.' }
    $tok = Invoke-TRGoogleTokenRequest -Form @{
        client_id     = $ClientId
        client_secret = $ClientSecret
        grant_type    = 'authorization_code'
        code          = $resp['code']
        redirect_uri  = $lb.RedirectUri
        code_verifier = $pkce.Verifier
    }
    Set-TRGoogleToken -TokenResponse $tok
    try {
        $me = Invoke-TRGoogle -Service UserInfo -Path '/v1/userinfo'
        $ctx.Account = [string]$me.email
        $ctx.AccountName = [string]$me.name
    }
    catch { Write-TRLog ('Signed in, but could not read the account profile: ' + $_.Exception.Message) 'Warn' }
    try {
        $cust = Invoke-TRGoogle -Path '/admin/directory/v1/customers/my_customer'
        $ctx.CustomerId = [string]$cust.id
        $ctx.TenantId = [string]$cust.id
        $ctx.DefaultDomain = [string]$cust.customerDomain
        $ctx.InitialDomain = [string]$cust.customerDomain
        $org = $null
        try { $org = [string]$cust.postalAddress.organizationName } catch { }
        $ctx.TenantName = $(if ($org) { $org } else { [string]$cust.customerDomain })
    }
    catch {
        $ctx.Tokens = @{}
        $ctx.RefreshToken = $null
        $code = [int]$_.Exception.Data['HttpStatus']
        if ($code -eq 403) { throw ('Signed in as {0}, but this account cannot read the Google Workspace directory. Sign in with a super admin account of the client.' -f $ctx.Account) }
        throw ('Signed in, but the Google Workspace directory could not be read: ' + $_.Exception.Message)
    }
    try {
        $doms = Invoke-TRGoogle -Path '/admin/directory/v1/customer/my_customer/domains'
        $ctx.Domains = @(@($doms.domains) | Where-Object { $_ -and $_.domainName } | ForEach-Object { [string]$_.domainName })
    }
    catch { }
    try {
        $u = Invoke-TRGoogle -Path ('/admin/directory/v1/users/' + [uri]::EscapeDataString($ctx.Account)) -Query @{ fields = 'isAdmin,isDelegatedAdmin' }
        $ctx.IsSuperAdmin = [bool]$u.isAdmin
    }
    catch { $ctx.IsSuperAdmin = $null }
    $missing = @(Get-TRGoogleMissingScopes)
    Write-TRLog ('Signed in as {0} to {1} ({2})' -f $ctx.Account, $ctx.TenantName, $ctx.CustomerId) 'Success'
    if ($ctx.IsSuperAdmin -eq $false) { Write-TRLog 'This account is not a super admin. Admin console settings, audit logs and licences need a super admin, so many checks will show Not assessed.' 'Warn' }
    if ($missing.Count) { Write-TRLog ('Some permissions were not approved, so these areas will show Not assessed: {0}. Sign in again and tick every permission to include them.' -f (($missing | ForEach-Object { $script:TRGoogleScopeAreas[$_] }) -join ', ')) 'Warn' }
    $ctx
}

function Get-TRGoogleMissingScopes {
    $ctx = $script:TRContext
    $granted = @(([string]$ctx.Scopes['Google']) -split '\s+' | Where-Object { $_ } | ForEach-Object { $_ -replace [regex]::Escape($script:TRGoogleScopeBase), '' })
    if (-not $granted.Count) { return @() }
    @($script:TRGoogleScopeAreas.Keys | Where-Object { $granted -notcontains $_ })
}

function Test-TRGoogleScope {
    param([string]$Scope)
    $ctx = $script:TRContext
    $granted = [string]$ctx.Scopes['Google']
    if (-not $granted) { return $true }
    ($granted -split '\s+') -contains ($script:TRGoogleScopeBase + $Scope)
}

function Remove-TRGoogleAccess {
    $ctx = $script:TRContext
    if (-not $ctx -or $ctx.Platform -ne 'Google') { throw 'Sign in to the Google Workspace tenant first.' }
    $token = if ($ctx.RefreshToken) { $ctx.RefreshToken } elseif ($ctx.Tokens['Google']) { $ctx.Tokens['Google'].AccessToken } else { $null }
    if (-not $token) { throw 'There is no Google sign-in to revoke.' }
    try {
        Invoke-RestMethod -Method Post -Uri ($ctx.GoogleTokenBase + '/revoke') -Body @{ token = $token } -ContentType 'application/x-www-form-urlencoded' -UseBasicParsing -ErrorAction Stop -TimeoutSec 60 | Out-Null
    }
    catch {
        $info = Get-TRErrorInfo $_
        if ($info.Status -ne 400) { throw ('Google did not confirm the access was removed: ' + $info.Message) }
    }
    $name = if ($ctx.TenantName) { $ctx.TenantName } else { $ctx.Tenant }
    Write-TRLog ('Removed the review app''s access to {0} for {1}. Google has deleted its sign-in tokens.' -f $name, $ctx.Account) 'Success'
    Write-TRLog 'If the app was marked as Trusted for this client, remove it from the Admin console list as well: Security, Access and data control, API controls, Manage third-party app access.'
    $ctx.Tokens = @{}
    $ctx.RefreshToken = $null
    $true
}

function Set-TRGoogleTestToken {
    param([string]$CustomerId, [string]$Domain, [string]$Name, [string]$Account = 'engineer@reviewer.example', [string]$AccessToken = 'test-token')
    $ctx = $script:TRContext
    $ctx.Platform = 'Google'
    $ctx.CustomerId = $CustomerId
    $ctx.TenantId = $CustomerId
    $ctx.TenantName = $Name
    $ctx.DefaultDomain = $Domain
    $ctx.InitialDomain = $Domain
    $ctx.Account = $Account
    $ctx.IsSuperAdmin = $true
    $ctx.Tokens['Google'] = [pscustomobject]@{ AccessToken = $AccessToken; ExpiresOn = (Get-Date).ToUniversalTime().AddHours(2) }
}
