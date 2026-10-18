function ConvertTo-TRBase64Url {
    param([byte[]]$Bytes)
    [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function New-TRPkce {
    $bytes = New-Object byte[] 64
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes)
    $verifier = ConvertTo-TRBase64Url $bytes
    $sha = [Security.Cryptography.SHA256]::Create()
    $challenge = ConvertTo-TRBase64Url ($sha.ComputeHash([Text.Encoding]::ASCII.GetBytes($verifier)))
    [pscustomobject]@{ Verifier = $verifier; Challenge = $challenge }
}

function ConvertFrom-TRJwt {
    param([string]$Token)
    $part = $Token.Split('.')[1].Replace('-', '+').Replace('_', '/')
    switch ($part.Length % 4) { 2 { $part += '==' } 3 { $part += '=' } }
    [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($part)) | ConvertFrom-Json
}

function ConvertFrom-TRQueryString {
    param([string]$Query)
    $result = @{}
    foreach ($pair in ($Query.TrimStart('?') -split '&')) {
        if (-not $pair) { continue }
        $kv = $pair -split '=', 2
        $key = [uri]::UnescapeDataString($kv[0].Replace('+', ' '))
        $val = ''
        if ($kv.Count -gt 1) { $val = [uri]::UnescapeDataString($kv[1].Replace('+', ' ')) }
        $result[$key] = $val
    }
    $result
}

function Start-TRLoopback {
    $v4 = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
    $v4.Start()
    $port = $v4.LocalEndpoint.Port
    $v6 = $null
    try {
        $v6 = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::IPv6Loopback, $port)
        $v6.Start()
    }
    catch { $v6 = $null }
    [pscustomobject]@{ V4 = $v4; V6 = $v6; Port = $port; RedirectUri = "http://localhost:$port" }
}

function Stop-TRLoopback {
    param($Listener)
    foreach ($l in @($Listener.V4, $Listener.V6)) { if ($l) { try { $l.Stop() } catch { } } }
}

function Get-TRLandingPage {
    param([string]$Heading, [string]$Text, [bool]$Ok = $true)
    $colour = if ($Ok) { '#0F4761' } else { '#B03A2E' }
    @"
<!doctype html><html><head><meta charset="utf-8"><title>Tenant Review</title>
<style>body{font-family:Arial,sans-serif;background:#F4F6F8;margin:0;display:flex;align-items:center;justify-content:center;height:100vh}
.card{background:#fff;border-top:6px solid $colour;padding:32px 40px;max-width:520px;box-shadow:0 2px 12px rgba(0,0,0,.08)}
h1{color:$colour;font-size:22px;margin:0 0 12px}p{color:#333;font-size:15px;line-height:1.5;margin:0}</style></head>
<body><div class="card"><h1>$Heading</h1><p>$Text</p></div></body></html>
"@
}

function Wait-TRLoopbackRequest {
    param($Listener, [int]$TimeoutSeconds = 300)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        Test-TRCancelled
        foreach ($l in @($Listener.V4, $Listener.V6)) {
            if (-not $l -or -not $l.Pending()) { continue }
            $client = $l.AcceptTcpClient()
            try {
                $stream = $client.GetStream()
                $stream.ReadTimeout = 5000
                $reader = New-Object System.IO.StreamReader($stream, [Text.Encoding]::ASCII, $false, 8192, $true)
                $requestLine = $reader.ReadLine()
                while ($true) {
                    $h = $reader.ReadLine()
                    if ($null -eq $h -or $h -eq '') { break }
                }
                $target = ''
                if ($requestLine -match '^GET\s+(\S+)\s+HTTP') { $target = $Matches[1] }
                $query = $null
                if ($target -match '\?(.*)$') { $query = ConvertFrom-TRQueryString $Matches[1] }
                if ($query -and ($query.ContainsKey('code') -or $query.ContainsKey('error') -or $query.ContainsKey('admin_consent'))) {
                    if ($query.ContainsKey('error')) {
                        $page = Get-TRLandingPage -Heading 'Sign-in did not complete' -Text ('Return to the review app for details. ' + [Net.WebUtility]::HtmlEncode($query['error'])) -Ok $false
                    }
                    else {
                        $page = Get-TRLandingPage -Heading 'Signed in' -Text 'You can close this tab and return to the review app.'
                    }
                    $bytes = [Text.Encoding]::UTF8.GetBytes($page)
                    $head = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 200 OK`r`nContent-Type: text/html; charset=utf-8`r`nContent-Length: $($bytes.Length)`r`nConnection: close`r`nCache-Control: no-store`r`n`r`n")
                    $stream.Write($head, 0, $head.Length)
                    $stream.Write($bytes, 0, $bytes.Length)
                    $stream.Flush()
                    return $query
                }
                $nf = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 404 Not Found`r`nContent-Length: 0`r`nConnection: close`r`n`r`n")
                $stream.Write($nf, 0, $nf.Length)
            }
            catch { }
            finally { $client.Close() }
        }
        Start-Sleep -Milliseconds 200
    }
    throw 'Timed out waiting for the browser sign-in to complete.'
}

function Get-TRFriendlyAuthError {
    param([string]$Code, [string]$Description)
    $d = [string]$Description
    if ($d -match 'AADSTS65001|AADSTS650051|AADSTS90094|AADSTS90008') { return 'The review app has not been consented in this tenant yet. Use Grant consent first (Cloud Application Administrator via GDAP, or the client''s Global Administrator).' }
    if ($d -match 'AADSTS700016') { return 'The app ID was not found. Check ClientId in config.json matches the review app registration.' }
    if ($d -match 'AADSTS50020') { return 'This account has no access to the tenant. Check the GDAP relationship is active and includes your security group.' }
    if ($d -match 'AADSTS53003') { return 'Blocked by a Conditional Access policy in the client tenant. Review the sign-in log entry for this attempt.' }
    if ($d -match 'AADSTS50076|AADSTS50079') { return 'Multi-factor authentication is required. Complete MFA in the browser and try again.' }
    if ($d -match 'AADSTS90002|AADSTS900023') { return 'The tenant name or ID was not recognised. Use the client''s onmicrosoft.com domain, a verified domain or the tenant ID.' }
    if ($d -match 'AADSTS50011') { return 'Redirect URI mismatch. The app registration must include http://localhost as a Mobile and desktop redirect URI.' }
    if ($d -match 'AADSTS7000218') { return 'The app registration is not a public client. Set Allow public client flows to Yes on the app registration.' }
    if ($d -match 'AADSTS650057|AADSTS500011') { return 'The review app does not include the permission for this service. Run New-TenantReviewApp.ps1 -UpdateExisting in your own tenant, then use Grant consent again for this client.' }
    $first = ($d -split "`r?`n")[0]
    if ($Code) { return "$Code - $first" }
    $first
}

function Invoke-TRTokenRequest {
    param([hashtable]$Form)
    $ctx = $script:TRContext
    $uri = '{0}/{1}/oauth2/v2.0/token' -f $ctx.LoginBase, $(if ($ctx.TenantId) { $ctx.TenantId } else { $ctx.Tenant })
    try {
        Invoke-RestMethod -Method Post -Uri $uri -Body $Form -ContentType 'application/x-www-form-urlencoded' -UseBasicParsing -ErrorAction Stop -TimeoutSec 60
    }
    catch {
        $info = Get-TRErrorInfo $_
        $desc = $info.Message
        try {
            $j = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction Stop
            if ($j.error_description) { $desc = $j.error_description }
        }
        catch { }
        $msg = Get-TRFriendlyAuthError -Code $info.Code -Description $desc
        $ex = New-Object System.Exception($msg)
        $ex.Data['HttpStatus'] = $info.Status
        $ex.Data['ErrorCode'] = $info.Code
        $ex.Data['AuthError'] = $true
        throw $ex
    }
}

function Set-TRToken {
    param([string]$Resource, $TokenResponse)
    $ctx = $script:TRContext
    $expires = (Get-Date).ToUniversalTime().AddSeconds([int]$TokenResponse.expires_in - 60)
    $ctx.Tokens[$Resource] = [pscustomobject]@{ AccessToken = $TokenResponse.access_token; ExpiresOn = $expires }
    if ($TokenResponse.refresh_token) { $ctx.RefreshToken = $TokenResponse.refresh_token }
    try {
        $claims = ConvertFrom-TRJwt $TokenResponse.access_token
        $ctx.Scopes[$Resource] = [string]$claims.scp
    }
    catch { }
}

$script:TRServices = [ordered]@{
    Teams           = [pscustomobject]@{ AppId = '48ac35b8-9aa8-4d74-927d-1f4a14a0b239'; Name = 'Microsoft Teams admin settings'; Markers = @('48ac35b8-9aa8-4d74-927d-1f4a14a0b239', 'Skype and Teams Tenant Admin') }
    SharePointAdmin = [pscustomobject]@{ AppId = '00000003-0000-0ff1-ce00-000000000000'; Name = 'SharePoint and OneDrive admin settings'; Markers = @('00000003-0000-0ff1-ce00-000000000000', 'sharepoint.com', 'SharePoint') }
    PowerBI         = [pscustomobject]@{ AppId = '00000009-0000-0000-c000-000000000000'; Name = 'Power BI and Fabric tenant settings'; Markers = @('00000009-0000-0000-c000-000000000000', 'analysis.windows.net', 'Power BI') }
    PowerPlatform   = [pscustomobject]@{ AppId = '475226c6-020e-4fb2-8a90-7a972cbfc1d4'; Name = 'Power Platform admin settings'; Markers = @('475226c6-020e-4fb2-8a90-7a972cbfc1d4', 'service.powerapps.com', 'PowerApps') }
    Azure           = [pscustomobject]@{ AppId = '797f4846-ba00-4fd7-ba43-dac1f8f63013'; Name = 'Azure Resource Manager (subscriptions and resources)'; Markers = @('797f4846-ba00-4fd7-ba43-dac1f8f63013', 'management.azure.com', 'Windows Azure Service Management') }
}

$script:TRSettingsServices = @('Teams', 'SharePointAdmin', 'PowerBI', 'PowerPlatform')

function Get-TRSpoAdminUrl {
    $ctx = $script:TRContext
    if ($ctx.SpoAdminUrl) { return $ctx.SpoAdminUrl }
    $configured = ''
    try { $configured = [string](Get-TRSetting 'SharePointAdminUrl' '') } catch { }
    if ($configured) { return $configured.TrimEnd('/') }
    $initial = [string]$ctx.InitialDomain
    if ($initial -match '^([A-Za-z0-9-]+)\.onmicrosoft\.com$') { return ('https://{0}-admin.sharepoint.com' -f $Matches[1].ToLower()) }
    $null
}

function Get-TRResourceScope {
    param([string]$Resource, [switch]$Consent)
    $ctx = $script:TRContext
    switch ($Resource) {
        'Graph' { 'https://graph.microsoft.com/.default' }
        'Exchange' { 'https://outlook.office365.com/.default' }
        'Compliance' { 'https://ps.compliance.protection.outlook.com/.default' }
        'Teams' { '48ac35b8-9aa8-4d74-927d-1f4a14a0b239/user_impersonation' }
        'SharePointAdmin' {
            $u = $ctx.SpoAdminUrl
            if (-not $u) { $u = Get-TRSpoAdminUrl }
            if (-not $u) { throw 'The SharePoint admin address could not be worked out. Set SharePointAdminUrl in config.json, for example https://contoso-admin.sharepoint.com.' }
            $u.TrimEnd('/') + '/AllSites.FullControl'
        }
        'PowerBI' { 'https://analysis.windows.net/powerbi/api/Tenant.Read.All' }
        'PowerPlatform' { 'https://service.powerapps.com//User' }
        'Azure' { 'https://management.azure.com/user_impersonation' }
        default { throw "Unknown resource $Resource" }
    }
}

function Get-TRAccessToken {
    param([ValidateSet('Graph', 'Exchange', 'Compliance', 'Teams', 'SharePointAdmin', 'PowerBI', 'PowerPlatform', 'Azure')][string]$Resource)
    $ctx = $script:TRContext
    if (-not $ctx) { throw 'Not signed in.' }
    $t = $ctx.Tokens[$Resource]
    if ($t -and $t.ExpiresOn -gt (Get-Date).ToUniversalTime().AddMinutes(3)) { return $t.AccessToken }
    if (-not $ctx.RefreshToken) {
        if ($t) { return $t.AccessToken }
        throw 'Not signed in.'
    }
    $form = @{
        client_id     = $ctx.ClientId
        grant_type    = 'refresh_token'
        refresh_token = $ctx.RefreshToken
        scope         = (Get-TRResourceScope $Resource) + ' offline_access'
    }
    $tok = Invoke-TRTokenRequest -Form $form
    Set-TRToken -Resource $Resource -TokenResponse $tok
    $tok.access_token
}

function Invoke-TRAuthCode {
    param(
        [Parameter(Mandatory = $true)][string]$Tenant,
        [Parameter(Mandatory = $true)][string]$ClientId,
        [Parameter(Mandatory = $true)][string]$Scope,
        [string]$TokenScope,
        [string]$LoginHint,
        [string]$Prompt = 'select_account',
        [int]$TimeoutSeconds = 300,
        [scriptblock]$OnAuthUrl,
        [switch]$NoBrowser,
        [string]$Message = 'Opening the browser for sign-in. Complete sign-in and MFA, then return here.'
    )
    $ctx = $script:TRContext
    if (-not $TokenScope) { $TokenScope = $Scope }
    $pkce = New-TRPkce
    $state = [guid]::NewGuid().ToString('N')
    $lb = Start-TRLoopback
    try {
        $q = @(
            'client_id=' + [uri]::EscapeDataString($ClientId)
            'response_type=code'
            'redirect_uri=' + [uri]::EscapeDataString($lb.RedirectUri)
            'response_mode=query'
            'scope=' + [uri]::EscapeDataString($Scope)
            'state=' + $state
            'code_challenge=' + $pkce.Challenge
            'code_challenge_method=S256'
        )
        if ($Prompt) { $q += 'prompt=' + $Prompt }
        if ($LoginHint) { $q += 'login_hint=' + [uri]::EscapeDataString($LoginHint) }
        $authUrl = '{0}/{1}/oauth2/v2.0/authorize?{2}' -f $ctx.LoginBase, [uri]::EscapeDataString($Tenant), ($q -join '&')
        if ($OnAuthUrl) { & $OnAuthUrl $authUrl }
        elseif ($script:TRAuthUrlSink) { & $script:TRAuthUrlSink $authUrl }
        Write-TRLog $Message
        if (-not $NoBrowser) { Start-Process $authUrl }
        $resp = Wait-TRLoopbackRequest -Listener $lb -TimeoutSeconds $TimeoutSeconds
    }
    finally {
        Stop-TRLoopback $lb
    }
    if ($resp.ContainsKey('error')) {
        $ex = New-Object System.Exception((Get-TRFriendlyAuthError -Code $resp['error'] -Description $resp['error_description']))
        $ex.Data['RawError'] = ('{0} {1}' -f $resp['error'], $resp['error_description'])
        $ex.Data['AuthError'] = $true
        throw $ex
    }
    if ($resp['state'] -ne $state) { throw 'Sign-in response did not match the request. Try again.' }
    $form = @{
        client_id     = $ClientId
        grant_type    = 'authorization_code'
        code          = $resp['code']
        redirect_uri  = $lb.RedirectUri
        code_verifier = $pkce.Verifier
        scope         = $TokenScope
    }
    Invoke-TRTokenRequest -Form $form
}

function Request-TRServiceAccess {
    param([string[]]$Services = $script:TRSettingsServices, [int]$TimeoutSeconds = 240, [scriptblock]$OnAuthUrl, [switch]$NoBrowser)
    $ctx = $script:TRContext
    if (-not $ctx -or -not $ctx.TenantId) { throw 'Sign in to the client tenant first.' }
    if (-not $ctx.SpoAdminUrl) { $ctx.SpoAdminUrl = Get-TRSpoAdminUrl }
    $result = [ordered]@{}
    $wanted = New-Object System.Collections.ArrayList
    foreach ($k in $Services) {
        $svc = $script:TRServices[$k]
        if (-not $svc) { continue }
        if ($k -eq 'SharePointAdmin' -and -not $ctx.SpoAdminUrl) { $result[$k] = 'Skipped: the SharePoint admin address is not known. Set SharePointAdminUrl in config.json.'; continue }
        $t = $ctx.Tokens[$k]
        if ($t -and $t.ExpiresOn -gt (Get-Date).ToUniversalTime().AddMinutes(3)) { $result[$k] = 'Ready'; continue }
        try {
            Invoke-TRGraph -Path ("/servicePrincipals(appId='{0}')?`$select=id,appId" -f $svc.AppId) | Out-Null
            [void]$wanted.Add($k)
        }
        catch {
            if ([int]$_.Exception.Data['HttpStatus'] -eq 404) { $result[$k] = 'Skipped: this service is not set up in the tenant.' }
            else { [void]$wanted.Add($k) }
        }
    }
    foreach ($k in @($wanted)) {
        try { Get-TRAccessToken -Resource $k | Out-Null; $result[$k] = 'Ready'; $wanted.Remove($k) }
        catch { }
    }
    $attempt = 0
    while ($wanted.Count -and $attempt -lt 2) {
        $attempt++
        $scopes = @(@($wanted | ForEach-Object { Get-TRResourceScope $_ }) + 'offline_access')
        $first = [string]$wanted[0]
        $names = (@($wanted | ForEach-Object { $script:TRServices[$_].Name }) -join ', ')
        try {
            $tok = Invoke-TRAuthCode -Tenant $ctx.TenantId -ClientId $ctx.ClientId -Scope ($scopes -join ' ') -TokenScope ((Get-TRResourceScope $first) + ' offline_access') -LoginHint $ctx.Account -Prompt '' -TimeoutSeconds $TimeoutSeconds -OnAuthUrl $OnAuthUrl -NoBrowser:$NoBrowser -Message ('Approve read access to {0} in the browser. The review continues without them if you skip this.' -f $names)
            Set-TRToken -Resource $first -TokenResponse $tok
            foreach ($k in @($wanted)) {
                try { Get-TRAccessToken -Resource $k | Out-Null; $result[$k] = 'Ready' }
                catch { $result[$k] = 'Failed: ' + $_.Exception.Message }
            }
            $wanted.Clear()
        }
        catch {
            if ($_.Exception.Message -eq 'Operation cancelled by user.') { throw }
            $msg = $_.Exception.Message
            $raw = [string]$_.Exception.Data['RawError']
            $text = $msg + ' ' + $raw
            $bad = @($wanted | Where-Object { $svcKey = $_; @($script:TRServices[$svcKey].Markers | Where-Object { $text -match [regex]::Escape($_) }).Count -gt 0 })
            $stop = ($attempt -ge 2) -or (-not $bad.Count) -or ($bad.Count -eq $wanted.Count) -or ($text -match 'Timed out|access_denied|cancel')
            $failed = if ($stop) { @($wanted) } else { $bad }
            foreach ($k in $failed) {
                $result[$k] = 'Failed: ' + $(if ($raw) { ($raw -split "`r?`n")[0] } else { $msg })
                [void]$wanted.Remove($k)
            }
            if ($stop) { $wanted.Clear() }
        }
    }
    $ctx.ServiceAccess = $result
    foreach ($k in $result.Keys) {
        $state = [string]$result[$k]
        $level = if ($state -eq 'Ready') { 'Success' } elseif ($state -like 'Skipped*') { 'Info' } else { 'Warn' }
        Write-TRLog ('{0}: {1}' -f $script:TRServices[$k].Name, $(if ($state -eq 'Ready') { 'access granted' } else { $state })) $level
    }
    $result
}

function Connect-TRTenant {
    param(
        [Parameter(Mandatory = $true)][string]$Tenant,
        [Parameter(Mandatory = $true)][string]$ClientId,
        [string]$Scope = 'https://graph.microsoft.com/.default offline_access openid profile',
        [string]$LoginHint,
        [int]$TimeoutSeconds = 300,
        [scriptblock]$OnAuthUrl,
        [switch]$NoBrowser
    )
    $existing = $script:TRContext
    if (-not $existing -or $existing.Tenant -ne $Tenant -or $existing.ClientId -ne $ClientId) {
        if ($existing) {
            New-TRContext -Tenant $Tenant -ClientId $ClientId -LoginBase $existing.LoginBase -GraphBase $existing.GraphBase -ExoBase $existing.ExoBase -SccBase $existing.SccBase -DohBase $existing.DohBase -DnsMode $existing.DnsMode -TeamsBase $existing.TeamsBase -FabricBase $existing.FabricBase -PowerBIBase $existing.PowerBIBase -BapBase $existing.BapBase | Out-Null
        }
        else {
            $dns = 'Auto'
            try { $dns = [string](Get-TRSetting 'DnsMode' 'Auto') } catch { }
            if ($dns -notin @('Auto', 'Native', 'DoH')) { $dns = 'Auto' }
            New-TRContext -Tenant $Tenant -ClientId $ClientId -DnsMode $dns | Out-Null
        }
    }
    $ctx = $script:TRContext
    $ctx.Tokens = @{}
    $ctx.RefreshToken = $null
    $ctx.TenantId = $null
    $ctx.ExoAnchor = $null
    $ctx.SccUri = $null
    $ctx.SccAnchor = $null
    $ctx.Domains = @()
    if (-not $ctx.SpoAdminFixed) { $ctx.SpoAdminUrl = $null }
    $ctx.ServiceAccess = @{}
    Reset-TRSccClient
    $tok = Invoke-TRAuthCode -Tenant $Tenant -ClientId $ClientId -Scope $Scope -LoginHint $LoginHint -TimeoutSeconds $TimeoutSeconds -OnAuthUrl $OnAuthUrl -NoBrowser:$NoBrowser
    $claims = ConvertFrom-TRJwt $tok.access_token
    $ctx.TenantId = [string]$claims.tid
    $ctx.Account = if ($claims.upn) { [string]$claims.upn } elseif ($claims.unique_name) { [string]$claims.unique_name } else { [string]$claims.preferred_username }
    $ctx.AccountName = [string]$claims.name
    $resource = 'Graph'
    if ($Scope -match 'outlook\.office365\.com' -and $Scope -notmatch 'graph\.microsoft\.com') { $resource = 'Exchange' }
    Set-TRToken -Resource $resource -TokenResponse $tok
    if ($resource -eq 'Graph') {
        try {
            $org = Invoke-TRGraph -Path '/organization?$select=id,displayName,verifiedDomains'
            $o = @($org.value)[0]
            if ($o) {
                $ctx.TenantName = $o.displayName
                $ctx.Domains = @($o.verifiedDomains | Where-Object { $_ -and $_.name } | ForEach-Object { [string]$_.name })
                foreach ($d in @($o.verifiedDomains)) {
                    if ($d.isInitial) { $ctx.InitialDomain = $d.name }
                    if ($d.isDefault) { $ctx.DefaultDomain = $d.name }
                }
            }
        }
        catch {
            Write-TRLog ("Signed in, but could not read the organisation: " + $_.Exception.Message) 'Warn'
        }
    }
    Write-TRLog ("Signed in as {0} to {1} ({2})" -f $ctx.Account, $(if ($ctx.TenantName) { $ctx.TenantName } else { $Tenant }), $ctx.TenantId) 'Success'
    $ctx
}

function Request-TRAdminConsent {
    param(
        [Parameter(Mandatory = $true)][string]$Tenant,
        [Parameter(Mandatory = $true)][string]$ClientId,
        [int]$TimeoutSeconds = 300,
        [scriptblock]$OnAuthUrl,
        [switch]$NoBrowser
    )
    if (-not $script:TRContext) { New-TRContext -Tenant $Tenant -ClientId $ClientId | Out-Null }
    $ctx = $script:TRContext
    $lb = Start-TRLoopback
    $state = [guid]::NewGuid().ToString('N')
    try {
        $url = '{0}/{1}/adminconsent?client_id={2}&redirect_uri={3}&state={4}' -f $ctx.LoginBase, [uri]::EscapeDataString($Tenant), [uri]::EscapeDataString($ClientId), [uri]::EscapeDataString($lb.RedirectUri), $state
        if ($OnAuthUrl) { & $OnAuthUrl $url }
        Write-TRLog 'Opening the browser for admin consent. Sign in as an administrator of the client tenant and accept the permissions.'
        if (-not $NoBrowser) { Start-Process $url }
        $resp = Wait-TRLoopbackRequest -Listener $lb -TimeoutSeconds $TimeoutSeconds
    }
    finally {
        Stop-TRLoopback $lb
    }
    if ($resp.ContainsKey('error')) {
        throw (Get-TRFriendlyAuthError -Code $resp['error'] -Description $resp['error_description'])
    }
    Write-TRLog 'Admin consent granted. Allow a minute for it to apply, then sign in.' 'Success'
    $true
}

function Clear-TRSession {
    $ctx = $script:TRContext
    if ($ctx) {
        $ctx.Tokens = @{}
        $ctx.RefreshToken = $null
        $ctx.ExoAnchor = $null
        $ctx.SccUri = $null
        $ctx.SccAnchor = $null
    }
    Reset-TRSccClient
}

function Remove-TRTenantApp {
    param(
        [Parameter(Mandatory = $true)][string]$Tenant,
        [Parameter(Mandatory = $true)][string]$ClientId,
        [string]$LoginHint,
        [int]$TimeoutSeconds = 300,
        [scriptblock]$OnAuthUrl,
        [switch]$NoBrowser
    )
    Write-TRLog 'Removing the review app from this tenant. Sign in again and approve the one-off permission to remove applications.'
    $ctx = Connect-TRTenant -Tenant $Tenant -ClientId $ClientId -Scope 'https://graph.microsoft.com/Application.ReadWrite.All offline_access openid profile' -LoginHint $LoginHint -TimeoutSeconds $TimeoutSeconds -OnAuthUrl $OnAuthUrl -NoBrowser:$NoBrowser
    $granted = @(([string]$ctx.Scopes['Graph']) -split '\s+')
    if ($granted -notcontains 'Application.ReadWrite.All') {
        Clear-TRSession
        throw 'The sign-in did not grant permission to remove applications, so nothing was removed. Approve the permission request when you sign in.'
    }
    $name = if ($ctx.TenantName) { $ctx.TenantName } else { $Tenant }
    $sp = $null
    try { $sp = Invoke-TRGraph -Path ("/servicePrincipals(appId='{0}')?`$select=id,appId,displayName" -f $ClientId) }
    catch {
        if ([int]$_.Exception.Data['HttpStatus'] -eq 404) {
            Write-TRLog ('The review app is not present in {0}. Nothing to remove.' -f $name)
            Clear-TRSession
            return $false
        }
        throw
    }
    Invoke-TRGraph -Path ('/servicePrincipals/{0}' -f $sp.id) -Method DELETE | Out-Null
    Write-TRLog ('Removed the {0} enterprise application and all of its permissions from {1}.' -f $sp.displayName, $name) 'Success'
    try {
        Invoke-TRGraph -Path ('/directory/deletedItems/{0}' -f $sp.id) -Method DELETE | Out-Null
        Write-TRLog 'Also removed it from the tenant''s deleted items.' 'Success'
    }
    catch { Write-TRLog 'Microsoft removes it from the tenant''s deleted items automatically after 30 days.' }
    Clear-TRSession
    $true
}

function Set-TRTestToken {
    param([string]$TenantId, [string]$InitialDomain, [string]$AccessToken = 'test-token')
    $ctx = $script:TRContext
    $ctx.TenantId = $TenantId
    $ctx.InitialDomain = $InitialDomain
    $ctx.Account = 'tester@review.test'
    foreach ($r in 'Graph', 'Exchange', 'Compliance', 'Teams', 'SharePointAdmin', 'PowerBI', 'PowerPlatform', 'Azure') {
        $ctx.Tokens[$r] = [pscustomobject]@{ AccessToken = $AccessToken; ExpiresOn = (Get-Date).ToUniversalTime().AddHours(2) }
    }
}
