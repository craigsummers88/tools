$script:TRContext = $null
$script:TRLogSink = $null
$script:TRProgressSink = $null
$script:TRCancelCheck = $null
$script:TRLogFile = $null
$script:TRSccClient = $null
$script:TRAuthUrlSink = $null

function Write-TRLog {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet('Info', 'Warn', 'Error', 'Success')][string]$Level = 'Info'
    )
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'HH:mm:ss'), $Level.ToUpper(), $Message
    if ($script:TRLogSink) {
        & $script:TRLogSink $line $Level
    }
    else {
        $colour = switch ($Level) { 'Warn' { 'Yellow' } 'Error' { 'Red' } 'Success' { 'Green' } default { 'Gray' } }
        Write-Host $line -ForegroundColor $colour
    }
    if ($script:TRLogFile) {
        try { Add-Content -LiteralPath $script:TRLogFile -Value $line -Encoding UTF8 } catch { }
    }
}

function Set-TRProgress {
    param([int]$Percent, [string]$Activity)
    if ($script:TRProgressSink) { & $script:TRProgressSink $Percent $Activity }
}

function Test-TRCancelled {
    if ($script:TRCancelCheck -and (& $script:TRCancelCheck)) { throw 'Operation cancelled by user.' }
}

function Set-TRHost {
    param([scriptblock]$LogSink, [scriptblock]$ProgressSink, [scriptblock]$CancelCheck, [scriptblock]$AuthUrlSink)
    $script:TRLogSink = $LogSink
    $script:TRProgressSink = $ProgressSink
    $script:TRCancelCheck = $CancelCheck
    $script:TRAuthUrlSink = $AuthUrlSink
}

function New-TRContext {
    param(
        [string]$Tenant,
        [string]$ClientId,
        [string]$LoginBase = 'https://login.microsoftonline.com',
        [string]$GraphBase = 'https://graph.microsoft.com',
        [string]$ExoBase = 'https://outlook.office365.com',
        [string]$DohBase = 'https://dns.google/resolve',
        [string]$SccBase = 'https://ps.compliance.protection.outlook.com',
        [ValidateSet('Auto', 'Native', 'DoH')][string]$DnsMode = 'Auto',
        [string]$TeamsBase = 'https://api.interfaces.records.teams.microsoft.com',
        [string]$FabricBase = 'https://api.fabric.microsoft.com',
        [string]$PowerBIBase = 'https://api.powerbi.com',
        [string]$BapBase = 'https://api.bap.microsoft.com',
        [string]$ArmBase = 'https://management.azure.com',
        [string]$SpoAdminUrl,
        [ValidateSet('Microsoft', 'Google')][string]$Platform = 'Microsoft',
        [string]$ClientSecret,
        [string]$GoogleAuthBase = 'https://accounts.google.com',
        [string]$GoogleTokenBase = 'https://oauth2.googleapis.com',
        [string]$GoogleAdminBase = 'https://admin.googleapis.com',
        [string]$GoogleIdentityBase = 'https://cloudidentity.googleapis.com',
        [string]$GoogleLicensingBase = 'https://licensing.googleapis.com',
        [string]$GoogleGroupsBase = 'https://www.googleapis.com',
        [string]$GoogleAlertBase = 'https://alertcenter.googleapis.com',
        [string]$GoogleUserInfoBase = 'https://openidconnect.googleapis.com'
    )
    Reset-TRSccClient
    $script:TRContext = [pscustomobject]@{
        Tenant        = $Tenant
        TenantId      = $null
        ClientId      = $ClientId
        LoginBase     = $LoginBase.TrimEnd('/')
        GraphBase     = $GraphBase.TrimEnd('/')
        ExoBase       = $ExoBase.TrimEnd('/')
        SccBase       = $SccBase.TrimEnd('/')
        DohBase       = $DohBase
        DnsMode       = $DnsMode
        Tokens        = @{}
        RefreshToken  = $null
        Account       = $null
        AccountName   = $null
        TenantName    = $null
        InitialDomain = $null
        DefaultDomain = $null
        Domains       = @()
        ExoAnchor     = $null
        SccUri        = $null
        SccAnchor     = $null
        Scopes        = @{}
        TeamsBase     = $TeamsBase.TrimEnd('/')
        FabricBase    = $FabricBase.TrimEnd('/')
        PowerBIBase   = $PowerBIBase.TrimEnd('/')
        BapBase       = $BapBase.TrimEnd('/')
        ArmBase       = $ArmBase.TrimEnd('/')
        SpoAdminUrl   = $(if ($SpoAdminUrl) { $SpoAdminUrl.TrimEnd('/') } else { $null })
        SpoAdminFixed = [bool]$SpoAdminUrl
        ServiceAccess = @{}
        Platform      = $Platform
        ClientSecret  = $ClientSecret
        CustomerId    = $null
        IsSuperAdmin  = $null
        GoogleAuthBase      = $GoogleAuthBase.TrimEnd('/')
        GoogleTokenBase     = $GoogleTokenBase.TrimEnd('/')
        GoogleAdminBase     = $GoogleAdminBase.TrimEnd('/')
        GoogleIdentityBase  = $GoogleIdentityBase.TrimEnd('/')
        GoogleLicensingBase = $GoogleLicensingBase.TrimEnd('/')
        GoogleGroupsBase    = $GoogleGroupsBase.TrimEnd('/')
        GoogleAlertBase     = $GoogleAlertBase.TrimEnd('/')
        GoogleUserInfoBase  = $GoogleUserInfoBase.TrimEnd('/')
    }
    $script:TRContext
}

function Get-TRContext { $script:TRContext }

function Get-TRMemberAnchor {
    $ctx = $script:TRContext
    if (-not $ctx -or -not $ctx.Account -or $ctx.Account -notmatch '@(.+)$') { return $null }
    $domain = $Matches[1].ToLower()
    $known = @(@($ctx.Domains) + @($ctx.InitialDomain, $ctx.DefaultDomain) | Where-Object { $_ } | ForEach-Object { ([string]$_).ToLower() })
    if ($known -contains $domain) { return ('UPN:' + $ctx.Account) }
    $null
}

function ConvertTo-TRDate {
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    if ($Value -is [datetimeoffset]) { return $Value.UtcDateTime }
    $s = [string]$Value
    if ([string]::IsNullOrWhiteSpace($s)) { return $null }
    if ($s -match '^/Date\((-?\d+)') {
        return ([datetime]'1970-01-01Z').ToUniversalTime().AddMilliseconds([double]$Matches[1])
    }
    $d = [datetime]::MinValue
    $styles = [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal
    if ([datetime]::TryParse($s, [Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$d)) {
        if ($d.Year -lt 1901) { return $null }
        return $d
    }
    $null
}

function Format-TRDate {
    param($Value, [switch]$WithTime)
    $d = ConvertTo-TRDate $Value
    if ($null -eq $d) { return '' }
    if ($WithTime) { return $d.ToLocalTime().ToString('dd/MM/yyyy HH:mm') }
    $d.ToString('dd/MM/yyyy')
}

function Get-TRErrorInfo {
    param($ErrorRecord)
    $status = 0
    $retryAfter = $null
    $code = $null
    $message = $ErrorRecord.Exception.Message
    $resp = $null
    try { $resp = $ErrorRecord.Exception.Response } catch { }
    if ($resp) {
        try { $status = [int]$resp.StatusCode } catch { }
        try {
            if ($resp.Headers -and $resp.Headers.RetryAfter) {
                if ($resp.Headers.RetryAfter.Delta) { $retryAfter = [int]$resp.Headers.RetryAfter.Delta.TotalSeconds }
            }
        }
        catch { }
        if (-not $retryAfter) {
            try {
                $ra = $resp.Headers['Retry-After']
                if ($ra) { $retryAfter = [int]([string]$ra) }
            }
            catch { }
        }
    }
    $details = $null
    try { $details = $ErrorRecord.ErrorDetails.Message } catch { }
    if (-not $details -and $resp -and $resp -is [System.Net.WebResponse]) {
        try {
            $stream = $resp.GetResponseStream()
            if ($stream.CanSeek) { $stream.Position = 0 }
            $reader = New-Object System.IO.StreamReader($stream)
            $details = $reader.ReadToEnd()
            $reader.Dispose()
        }
        catch { }
    }
    if ($details) {
        try {
            $j = $details | ConvertFrom-Json -ErrorAction Stop
            if ($j.error) {
                if ($j.error -is [string]) {
                    $code = $j.error
                    if ($j.error_description) { $message = ($j.error_description -split "`r?`n")[0] } else { $message = $j.error }
                }
                else {
                    $code = if ($j.error.status -and $j.error.code -is [ValueType]) { $j.error.status } else { $j.error.code }
                    if ($j.error.message) { $message = $j.error.message }
                    if ($j.error.details -and $j.error.details[0].message) { $message = $message + ' ' + $j.error.details[0].message }
                }
            }
            elseif ($j.message) { $message = $j.message }
        }
        catch {
            if ($details.Length -lt 400) { $message = $details }
        }
    }
    if ($message -and ([string]$message).TrimStart().StartsWith('{')) {
        try {
            $inner = ConvertFrom-Json -InputObject ([string]$message) -ErrorAction Stop
            if ($inner.Message) { $message = [string]$inner.Message }
            elseif ($inner.message) { $message = [string]$inner.message }
        }
        catch { }
    }
    [pscustomobject]@{ Status = $status; Code = $code; Message = $message; RetryAfter = $retryAfter }
}

function New-TRHttpException {
    param([int]$Status, [string]$Code, [string]$Message, [string]$Uri)
    $text = if ($Status -gt 0) { "HTTP $Status" } else { 'Request failed' }
    if ($Code) { $text = "$text $Code" }
    $text = "$text - $Message"
    $ex = New-Object System.Exception($text)
    $ex.Data['HttpStatus'] = $Status
    $ex.Data['ErrorCode'] = $Code
    $ex.Data['Uri'] = $Uri
    $ex
}

function Invoke-TRRest {
    param(
        [string]$Method = 'GET',
        [Parameter(Mandatory = $true)][string]$Uri,
        [hashtable]$Headers = @{},
        $Body,
        [string]$ContentType = 'application/json; charset=utf-8',
        [int]$MaxRetry = 6,
        [int]$TimeoutSec = 180
    )
    $attempt = 0
    while ($true) {
        $attempt++
        Test-TRCancelled
        $p = @{
            Method          = $Method
            Uri             = $Uri
            Headers         = $Headers
            ErrorAction     = 'Stop'
            UseBasicParsing = $true
            TimeoutSec      = $TimeoutSec
        }
        if ($null -ne $Body) {
            if ($Body -is [string]) { $p.Body = [Text.Encoding]::UTF8.GetBytes($Body) } else { $p.Body = $Body }
            $p.ContentType = $ContentType
        }
        try {
            return Invoke-RestMethod @p
        }
        catch {
            $info = Get-TRErrorInfo $_
            $transient = ($info.Status -eq 429) -or ($info.Status -ge 500) -or ($info.Status -eq 0 -and $_.Exception.Message -match 'timed out|underlying connection|forcibly closed|actively refused|connection was closed')
            if ($transient -and $attempt -lt $MaxRetry) {
                $wait = if ($info.RetryAfter) { [Math]::Min([int]$info.RetryAfter, 120) } else { [Math]::Min([int]([Math]::Pow(2, $attempt)), 60) }
                if ($info.Status -eq 429) { Write-TRLog "Throttled by service, waiting $wait seconds" 'Warn' }
                Start-Sleep -Seconds $wait
                continue
            }
            throw (New-TRHttpException -Status $info.Status -Code $info.Code -Message $info.Message -Uri $Uri)
        }
    }
}

function Test-TRHasProperty {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $false }
    if ($Object -is [System.Collections.IDictionary]) { return $Object.Contains($Name) }
    [bool]($Object.PSObject.Properties[$Name])
}

function Invoke-TRGraph {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [string]$Method = 'GET',
        $Body,
        [switch]$Beta,
        [switch]$All,
        [switch]$Eventual,
        [int]$MaxItems = 0,
        [hashtable]$ExtraHeaders,
        [int]$MaxRetry = 6
    )
    $ctx = $script:TRContext
    $version = if ($Beta) { 'beta' } else { 'v1.0' }
    $uri = if ($Path -match '^https?://') { $Path } else { '{0}/{1}{2}' -f $ctx.GraphBase, $version, $Path }
    $json = $null
    if ($null -ne $Body) {
        if ($Body -is [string]) { $json = $Body } else { $json = ConvertTo-Json -InputObject $Body -Depth 20 -Compress }
    }
    $results = New-Object System.Collections.ArrayList
    $page = 0
    while ($uri) {
        $headers = @{ Authorization = 'Bearer ' + (Get-TRAccessToken -Resource Graph) }
        if ($Eventual) { $headers['ConsistencyLevel'] = 'eventual' }
        if ($ExtraHeaders) { foreach ($k in $ExtraHeaders.Keys) { $headers[$k] = $ExtraHeaders[$k] } }
        $r = Invoke-TRRest -Method $Method -Uri $uri -Headers $headers -Body $json -MaxRetry $MaxRetry
        if (-not $All) { return $r }
        $page++
        if (Test-TRHasProperty $r 'value') {
            foreach ($item in @($r.value)) { if ($null -ne $item) { [void]$results.Add($item) } }
        }
        elseif ($null -ne $r) {
            [void]$results.Add($r)
        }
        if ($MaxItems -gt 0 -and $results.Count -ge $MaxItems) { break }
        $uri = $null
        if (Test-TRHasProperty $r '@odata.nextLink') { $uri = $r.'@odata.nextLink' }
        if ($uri -and $ctx.GraphBase -ne 'https://graph.microsoft.com') {
            $uri = $uri -replace '^https://graph\.microsoft\.com', $ctx.GraphBase
        }
    }
    , $results.ToArray()
}

function Invoke-TRServiceRest {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('Teams', 'SharePointAdmin', 'PowerBI', 'PowerPlatform', 'Azure')][string]$Resource,
        [Parameter(Mandatory = $true)][string]$Uri,
        [string]$Method = 'GET',
        $Body,
        [string]$Accept = 'application/json',
        [int]$MaxRetry = 4
    )
    $headers = @{ Authorization = 'Bearer ' + (Get-TRAccessToken -Resource $Resource); Accept = $Accept }
    $json = $null
    if ($null -ne $Body) {
        if ($Body -is [string]) { $json = $Body } else { $json = ConvertTo-Json -InputObject $Body -Depth 20 -Compress }
    }
    elseif ($Method -eq 'POST') { $json = '{}' }
    $ct = if ($Accept -like '*odata=verbose*') { 'application/json;odata=verbose' } else { 'application/json; charset=utf-8' }
    Invoke-TRRest -Method $Method -Uri $Uri -Headers $headers -Body $json -ContentType $ct -MaxRetry $MaxRetry
}

function ConvertFrom-TRReportResponse {
    param($Response)
    $r = $Response
    if ($null -eq $r) { return , @() }
    if ($r -is [byte[]]) { $r = [Text.Encoding]::UTF8.GetString($r) }
    if ($r -is [string]) {
        $text = $r.TrimStart([char]0xFEFF).Trim()
        if (-not $text) { return , @() }
        if ($text.StartsWith('{') -or $text.StartsWith('[')) {
            try {
                $j = ConvertFrom-Json -InputObject $text -ErrorAction Stop
                if (Test-TRHasProperty $j 'value') { return , @($j.value) }
                return , @($j)
            }
            catch { }
        }
        return , @($text | ConvertFrom-Csv)
    }
    if (Test-TRHasProperty $r 'value') { return , @($r.value) }
    , @($r)
}

function Invoke-TRGraphReport {
    param([Parameter(Mandatory = $true)][string]$Report, [string]$Period = 'D30', [switch]$NoPeriod)
    $path = if ($NoPeriod) { '/reports/{0}' -f $Report } else { "/reports/{0}(period='{1}')" -f $Report, $Period }
    ConvertFrom-TRReportResponse (Invoke-TRGraph -Path $path)
}

function Invoke-TRHunting {
    param([Parameter(Mandatory = $true)][string]$Query)
    $r = Invoke-TRGraph -Path '/security/runHuntingQuery' -Method POST -Body @{ Query = $Query }
    if ($null -eq $r -or -not (Test-TRHasProperty $r 'results')) { return , @() }
    , @($r.results | Where-Object { $null -ne $_ })
}

function Reset-TRSccClient {
    if ($script:TRSccClient) {
        try { $script:TRSccClient.Dispose() } catch { }
    }
    $script:TRSccClient = $null
}

function Get-TRSccClient {
    if (-not $script:TRSccClient) {
        if ($PSVersionTable.PSEdition -ne 'Core') { Add-Type -AssemblyName System.Net.Http }
        $handler = New-Object System.Net.Http.HttpClientHandler
        $handler.AllowAutoRedirect = $false
        $handler.UseCookies = $true
        $handler.CookieContainer = New-Object System.Net.CookieContainer
        $client = New-Object System.Net.Http.HttpClient($handler)
        $client.Timeout = [TimeSpan]::FromSeconds(180)
        $script:TRSccClient = $client
    }
    $script:TRSccClient
}

function Get-TRInnerMessage {
    param([Exception]$Exception)
    $e = $Exception
    while ($e.InnerException) { $e = $e.InnerException }
    $e.Message
}

function Send-TRSccRequest {
    param([string]$Uri, [string]$Body, [string]$Anchor, [int]$MaxRetry = 4)
    $client = Get-TRSccClient
    $attempt = 0
    $hops = 0
    while ($true) {
        Test-TRCancelled
        $attempt++
        $token = Get-TRAccessToken -Resource Compliance
        $req = New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::Post, $Uri)
        [void]$req.Headers.TryAddWithoutValidation('Authorization', 'Bearer ' + $token)
        [void]$req.Headers.TryAddWithoutValidation('Accept', 'application/json')
        [void]$req.Headers.TryAddWithoutValidation('Prefer', 'odata.maxpagesize=1000')
        if ($Anchor) { [void]$req.Headers.TryAddWithoutValidation('X-AnchorMailbox', $Anchor) }
        $req.Content = New-Object System.Net.Http.StringContent($Body, [Text.Encoding]::UTF8, 'application/json')
        $resp = $null
        try {
            $resp = $client.SendAsync($req).GetAwaiter().GetResult()
        }
        catch {
            $req.Dispose()
            $msg = Get-TRInnerMessage $_.Exception
            if ($attempt -lt $MaxRetry) {
                Start-Sleep -Seconds ([Math]::Min([int][Math]::Pow(2, $attempt), 30))
                continue
            }
            throw (New-TRHttpException -Status 0 -Code '' -Message $msg -Uri $Uri)
        }
        $status = [int]$resp.StatusCode
        $text = ''
        try { if ($resp.Content) { $text = $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult() } } catch { }
        $location = $resp.Headers.Location
        $retryAfter = $null
        try { if ($resp.Headers.RetryAfter -and $null -ne $resp.Headers.RetryAfter.Delta) { $retryAfter = [int]$resp.Headers.RetryAfter.Delta.TotalSeconds } } catch { }
        $resp.Dispose()
        $req.Dispose()
        if ($status -ge 300 -and $status -lt 400 -and $location) {
            $hops++
            if ($hops -gt 5) { throw (New-TRHttpException -Status $status -Code 'TooManyRedirects' -Message 'The compliance endpoint redirected too many times.' -Uri $Uri) }
            if (-not $location.IsAbsoluteUri) { $location = New-Object System.Uri((New-Object System.Uri($Uri)), $location) }
            $builder = New-Object System.UriBuilder($location)
            if ($builder.Port -eq 446) { $builder.Port = -1 }
            $Uri = $builder.Uri.AbsoluteUri
            $attempt = [Math]::Max($attempt - 1, 0)
            continue
        }
        if ($status -ge 200 -and $status -lt 300) {
            $data = $null
            if ($text -and $text.Trim()) { $data = ConvertFrom-Json -InputObject $text }
            return [pscustomobject]@{ Data = $data; Uri = $Uri }
        }
        if (($status -eq 429 -or $status -ge 500) -and $attempt -lt $MaxRetry) {
            $wait = if ($retryAfter) { [Math]::Min($retryAfter, 120) } else { [Math]::Min([int][Math]::Pow(2, $attempt), 60) }
            if ($status -eq 429) { Write-TRLog "Throttled by the compliance service, waiting $wait seconds" 'Warn' }
            Start-Sleep -Seconds $wait
            continue
        }
        $code = $null
        $message = 'The compliance service returned an error.'
        if ($text) {
            try {
                $j = ConvertFrom-Json -InputObject $text -ErrorAction Stop
                if ($j.error) {
                    if ($j.error -is [string]) { $code = $j.error; $message = [string]$j.error_description }
                    else {
                        $code = $j.error.code
                        if ($j.error.message) { $message = [string]$j.error.message }
                        if ($j.error.details -and $j.error.details[0].message) { $message = $message + ' ' + $j.error.details[0].message }
                    }
                }
                elseif ($j.message) { $message = [string]$j.message }
            }
            catch { if ($text.Length -lt 400) { $message = $text } }
        }
        throw (New-TRHttpException -Status $status -Code $code -Message $message -Uri $Uri)
    }
}

function Invoke-TRCompliance {
    param(
        [Parameter(Mandatory = $true)][string]$Cmdlet,
        [hashtable]$Parameters = @{},
        [int]$MaxItems = 0
    )
    $ctx = $script:TRContext
    if (-not $ctx.TenantId) { throw 'Not signed in.' }
    $body = ConvertTo-Json -InputObject @{ CmdletInput = @{ CmdletName = $Cmdlet; Parameters = $Parameters } } -Depth 10 -Compress
    $base = '{0}/adminapi/beta/{1}/InvokeCommand' -f $ctx.SccBase, $ctx.TenantId
    $anchors = @()
    if ($ctx.SccAnchor) { $anchors = @($ctx.SccAnchor) }
    else {
        $member = Get-TRMemberAnchor
        if ($member) { $anchors += $member }
        if ($ctx.InitialDomain) { $anchors += 'UPN:OAuthUser@' + $ctx.InitialDomain }
        $anchors += 'TID:' + $ctx.TenantId
        if ($ctx.InitialDomain) { $anchors += 'UPN:SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c}@' + $ctx.InitialDomain }
        $anchors += ''
    }
    $lastError = $null
    foreach ($anchor in $anchors) {
        $uri = if ($ctx.SccUri) { $ctx.SccUri } else { $base }
        $results = New-Object System.Collections.ArrayList
        $firstCall = $true
        try {
            while ($uri) {
                $retries = if ($ctx.SccAnchor) { 5 } else { 2 }
                $r = Send-TRSccRequest -Uri $uri -Body $body -Anchor $anchor -MaxRetry $retries
                if ($firstCall -and -not $ctx.SccUri -and $r.Uri -ne $base) { $ctx.SccUri = $r.Uri }
                $firstCall = $false
                $d = $r.Data
                if (Test-TRHasProperty $d 'value') {
                    foreach ($item in @($d.value)) { if ($null -ne $item) { [void]$results.Add($item) } }
                }
                elseif ($null -ne $d) { [void]$results.Add($d) }
                if ($MaxItems -gt 0 -and $results.Count -ge $MaxItems) { break }
                $uri = $null
                if (Test-TRHasProperty $d '@odata.nextLink') { $uri = [string]$d.'@odata.nextLink' }
            }
            if (-not $ctx.SccAnchor) { $ctx.SccAnchor = $anchor }
            return , $results.ToArray()
        }
        catch {
            $lastError = $_.Exception
            if ($_.Exception.Data['AuthError']) { break }
            $status = [int]$_.Exception.Data['HttpStatus']
            if ($ctx.SccAnchor -or $status -eq 401 -or $status -eq 403) { break }
            if ($_.Exception.Message -match "isn't recognized|is not recognized|cannot be found|couldn't be found|not found on|NotFound") { break }
        }
    }
    throw $lastError
}

function Invoke-TRExo {
    param(
        [Parameter(Mandatory = $true)][string]$Cmdlet,
        [hashtable]$Parameters = @{},
        [int]$MaxItems = 0
    )
    $ctx = $script:TRContext
    if (-not $ctx.TenantId) { throw 'Not signed in.' }
    $body = ConvertTo-Json -InputObject @{ CmdletInput = @{ CmdletName = $Cmdlet; Parameters = $Parameters } } -Depth 10 -Compress
    $anchors = @()
    if ($ctx.ExoAnchor) { $anchors = @($ctx.ExoAnchor) }
    else {
        $member = Get-TRMemberAnchor
        if ($member) { $anchors += $member }
        if ($ctx.InitialDomain) { $anchors += 'UPN:SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c}@' + $ctx.InitialDomain }
        $anchors += 'APP:SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c}@' + $ctx.TenantId
        if ($ctx.InitialDomain) { $anchors += 'UPN:SystemMailbox{8cc370d3-822a-4ab8-a926-bb94bd0641a9}@' + $ctx.InitialDomain }
        $anchors += ''
    }
    $lastError = $null
    foreach ($anchor in $anchors) {
        $uri = '{0}/adminapi/beta/{1}/InvokeCommand' -f $ctx.ExoBase, $ctx.TenantId
        $results = New-Object System.Collections.ArrayList
        try {
            while ($uri) {
                $headers = @{
                    Authorization = 'Bearer ' + (Get-TRAccessToken -Resource Exchange)
                    Prefer        = 'odata.maxpagesize=1000'
                }
                if ($anchor) { $headers['X-AnchorMailbox'] = $anchor }
                $retries = if ($ctx.ExoAnchor) { 6 } else { 2 }
                $r = Invoke-TRRest -Method POST -Uri $uri -Headers $headers -Body $body -MaxRetry $retries
                if (Test-TRHasProperty $r 'value') {
                    foreach ($item in @($r.value)) { if ($null -ne $item) { [void]$results.Add($item) } }
                }
                elseif ($null -ne $r -and -not ($r -is [string] -and [string]::IsNullOrWhiteSpace($r))) {
                    [void]$results.Add($r)
                }
                if ($MaxItems -gt 0 -and $results.Count -ge $MaxItems) { break }
                $uri = $null
                if (Test-TRHasProperty $r '@odata.nextLink') {
                    $uri = $r.'@odata.nextLink'
                    if ($ctx.ExoBase -ne 'https://outlook.office365.com') { $uri = $uri -replace '^https://outlook\.office365\.com', $ctx.ExoBase }
                }
            }
            if (-not $ctx.ExoAnchor) { $ctx.ExoAnchor = $anchor }
            return , $results.ToArray()
        }
        catch {
            $lastError = $_.Exception
            if ($_.Exception.Data['AuthError']) { break }
            $status = [int]$_.Exception.Data['HttpStatus']
            if ($ctx.ExoAnchor -or $status -eq 401 -or $status -eq 403) { break }
            if ($_.Exception.Message -match "isn't recognized|is not recognized|cannot be found|couldn't be found|not found on|NotFound") { break }
        }
    }
    throw $lastError
}

function Resolve-TRDns {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [ValidateSet('TXT', 'MX', 'CNAME')][string]$Type
    )
    $ctx = $script:TRContext
    $mode = 'DoH'
    if ($ctx -and $ctx.DnsMode -eq 'Native') { $mode = 'Native' }
    elseif (($null -eq $ctx -or $ctx.DnsMode -eq 'Auto') -and (Get-Command -Name Resolve-DnsName -ErrorAction SilentlyContinue)) { $mode = 'Native' }
    $out = New-Object System.Collections.ArrayList
    if ($mode -eq 'Native') {
        try {
            $records = Resolve-DnsName -Name $Name -Type $Type -DnsOnly -QuickTimeout -ErrorAction Stop
        }
        catch {
            if ($_.Exception.Message -match 'does not exist|DNS name does not exist|No records|9003|9501|NXDOMAIN') { return , @() }
            throw
        }
        foreach ($rec in @($records)) {
            switch ($Type) {
                'TXT' { if ($rec.Type -eq 'TXT' -and $rec.Strings) { [void]$out.Add((@($rec.Strings) -join '')) } }
                'MX' { if ($rec.Type -eq 'MX' -and $rec.NameExchange) { [void]$out.Add(('{0} {1}' -f $rec.Preference, $rec.NameExchange.TrimEnd('.'))) } }
                'CNAME' { if ($rec.Type -eq 'CNAME' -and $rec.NameHost) { [void]$out.Add($rec.NameHost.TrimEnd('.')) } }
            }
        }
        return , $out.ToArray()
    }
    $base = if ($ctx) { $ctx.DohBase } else { 'https://dns.google/resolve' }
    $uri = '{0}?name={1}&type={2}' -f $base, [uri]::EscapeDataString($Name), $Type
    $r = Invoke-TRRest -Uri $uri -Headers @{ Accept = 'application/dns-json' } -MaxRetry 3 -TimeoutSec 30
    $typeCode = @{ 'TXT' = 16; 'MX' = 15; 'CNAME' = 5 }[$Type]
    foreach ($a in @($r.Answer)) {
        if ($null -eq $a -or [int]$a.type -ne $typeCode) { continue }
        $data = [string]$a.data
        switch ($Type) {
            'TXT' {
                $parts = [regex]::Matches($data, '"((?:[^"\\]|\\.)*)"')
                if ($parts.Count -gt 0) { $data = (@($parts | ForEach-Object { $_.Groups[1].Value }) -join '') }
                [void]$out.Add($data)
            }
            'MX' {
                $bits = $data -split '\s+'
                if ($bits.Count -ge 2) { [void]$out.Add(('{0} {1}' -f $bits[0], $bits[1].TrimEnd('.'))) }
            }
            'CNAME' { [void]$out.Add($data.TrimEnd('.')) }
        }
    }
    , $out.ToArray()
}
