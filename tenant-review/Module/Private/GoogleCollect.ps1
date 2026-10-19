$script:TRGoogleAreas = [ordered]@{
    Identity        = 'Users, sign-in and administrators'
    Licensing       = 'Licensing'
    Applications    = 'Third-party apps and API access'
    Gmail           = 'Gmail security settings'
    Dns             = 'Email DNS (MX, SPF, DKIM, DMARC)'
    Drive           = 'Drive and Docs sharing'
    Collaboration   = 'Calendar, Chat, Meet, Groups and Sites'
    Devices         = 'Endpoint management (mobile, Windows, ChromeOS)'
    Security        = 'Alert Center, rules and data protection'
    Opportunities   = 'Licence utilisation opportunities'
    Benchmarks      = 'CIS Google Workspace v1.4.0 and CISA SCuBA benchmarks'
    GroupMembership = 'Group membership'
    DriveSharing    = 'Drive sharing activity from audit log (30 days)'
    Servers         = 'Servers (imported server data)'
}

$script:TRGoogleDefaultAreas = @('Identity', 'Licensing', 'Applications', 'Gmail', 'Dns', 'Drive', 'Collaboration', 'Devices', 'Security', 'Opportunities', 'Benchmarks', 'GroupMembership')

$script:TRGoogleProducts = @('Google-Apps', '101031', '101034', 'Google-Vault', '101001', '101005', '101033', '101038', '101039', '101040', '101047', '101068', '101043', '101036', '101037', '101049', '101052')

$script:TRGoogleUsageParams = @(
    'accounts:is_2sv_enrolled', 'accounts:is_2sv_enforced', 'accounts:num_security_keys', 'accounts:num_passkeys_enrolled',
    'accounts:password_strength', 'accounts:password_length_compliance', 'accounts:timestamp_last_login', 'accounts:timestamp_last_sso',
    'accounts:num_authorized_apps', 'accounts:is_less_secure_apps_access_allowed', 'accounts:used_quota_in_mb', 'accounts:total_quota_in_mb',
    'gmail:timestamp_last_interaction', 'gmail:timestamp_last_imap', 'gmail:timestamp_last_pop', 'gmail:num_emails_sent',
    'drive:timestamp_last_active_usage'
)

$script:TRGoogleLoginEvents = @('suspicious_login', 'suspicious_login_less_secure_app', 'suspicious_programmatic_login', 'gov_attack_warning', 'account_disabled_password_leak', 'account_disabled_hijacked')

function Get-TRGwsRaw { param([string]$Key) $script:TRRaw[$Key] }

function Get-TRGwsActiveUsers {
    @(@($script:TRRaw['GwsUsers']) | Where-Object { $_ -and -not $_.suspended -and -not $_.archived })
}

function ConvertFrom-TRUsageReport {
    param($Report)
    $o = [ordered]@{ Email = [string]$Report.entity.userEmail; ProfileId = [string]$Report.entity.profileId; Date = [string]$Report.date }
    foreach ($p in @($Report.parameters)) {
        if (-not $p) { continue }
        $n = ([string]$p.name) -replace ':', '_'
        $v = $null
        if (Test-TRHasProperty $p 'boolValue') { $v = [bool]$p.boolValue }
        elseif (Test-TRHasProperty $p 'intValue') { $v = [long]$p.intValue }
        elseif (Test-TRHasProperty $p 'datetimeValue') { $v = [string]$p.datetimeValue }
        elseif (Test-TRHasProperty $p 'stringValue') { $v = [string]$p.stringValue }
        $o[$n] = $v
    }
    [pscustomobject]$o
}

function Get-TRGwsUsageReport {
    param([string[]]$Parameters)
    $date = (Get-Date).ToUniversalTime().Date.AddDays(-3)
    for ($i = 0; $i -lt 6; $i++) {
        try {
            $rows = Invoke-TRGoogle -Path ('/admin/reports/v1/usage/users/all/dates/' + $date.ToString('yyyy-MM-dd')) -Query @{ parameters = ($Parameters -join ','); maxResults = 1000 } -All -ItemsKey 'usageReports'
            $out = @($rows | ForEach-Object { ConvertFrom-TRUsageReport $_ })
            if ($out.Count) { Write-TRLog ('Usage reports are for {0}; Google publishes them two to four days in arrears.' -f (Format-TRDate $date)) }
            if ($out.Count -or $i -ge 3) { return , $out }
            $date = $date.AddDays(-1)
        }
        catch {
            $m = $_.Exception.Message
            if ($m -match 'later than (\d{4}-\d{2}-\d{2})') { $date = [datetime]::ParseExact($Matches[1], 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture); continue }
            if ($m -match 'not yet available|Start date can not be later') { $date = $date.AddDays(-1); continue }
            throw
        }
    }
    , @()
}

function Get-TRGwsActivities {
    param([string]$Application, [string]$EventName, [int]$Days = 30, [int]$MaxItems = 20000)
    $q = @{ startTime = (Get-Date).ToUniversalTime().AddDays(-$Days).ToString('yyyy-MM-ddTHH:mm:ss.000Z'); maxResults = 1000 }
    if ($EventName) { $q['eventName'] = $EventName }
    $items = Invoke-TRGoogle -Path ('/admin/reports/v1/activity/users/all/applications/' + $Application) -Query $q -All -ItemsKey 'items' -MaxItems $MaxItems
    foreach ($a in @($items)) {
        foreach ($e in @($a.events)) {
            if (-not $e) { continue }
            $o = [ordered]@{ Time = [string]$a.id.time; Actor = [string]$a.actor.email; IpAddress = [string]$a.ipAddress; Type = [string]$e.type; Event = [string]$e.name }
            foreach ($p in @($e.parameters)) {
                if (-not $p) { continue }
                $v = $null
                if (Test-TRHasProperty $p 'value') { $v = [string]$p.value }
                elseif (Test-TRHasProperty $p 'boolValue') { $v = [string]$p.boolValue }
                elseif (Test-TRHasProperty $p 'intValue') { $v = [string]$p.intValue }
                elseif (Test-TRHasProperty $p 'multiValue') { $v = (@($p.multiValue) -join ', ') }
                $o[[string]$p.name] = $v
            }
            [pscustomobject]$o
        }
    }
}

function Invoke-TRGwsCollectIdentity {
    param([int]$MaxUsers)
    Set-TRProgress 8 'Reading the Google Workspace customer, domains and organisational units'
    Invoke-TRStep 'Identity' 'GwsCustomer' { Invoke-TRGoogle -Path '/admin/directory/v1/customers/my_customer' } | Out-Null
    Invoke-TRStep 'Identity' 'GwsDomains' -List { (Invoke-TRGoogle -Path '/admin/directory/v1/customer/my_customer/domains').domains } | Out-Null
    Invoke-TRStep 'Identity' 'GwsDomainAliases' -List -Optional { (Invoke-TRGoogle -Path '/admin/directory/v1/customer/my_customer/domainaliases').domainAliases } | Out-Null
    Invoke-TRStep 'Identity' 'GwsOrgUnits' -List { (Invoke-TRGoogle -Path '/admin/directory/v1/customer/my_customer/orgunits' -Query @{ type = 'allIncludingParent' }).organizationUnits } | Out-Null
    Set-TRProgress 12 'Reading users'
    Invoke-TRStep 'Identity' 'GwsUsers' -List {
        Invoke-TRGoogle -Path '/admin/directory/v1/users' -Query @{ customer = 'my_customer'; projection = 'full'; maxResults = 500; fields = 'nextPageToken,users(id,primaryEmail,name/fullName,isAdmin,isDelegatedAdmin,suspended,suspensionReason,archived,isEnrolledIn2Sv,isEnforcedIn2Sv,lastLoginTime,creationTime,orgUnitPath,isMailboxSetup,agreedToTerms,changePasswordAtNextLogin,recoveryEmail,recoveryPhone,aliases,ipWhitelisted)' } -All -ItemsKey 'users'
    } | Out-Null
    Invoke-TRStep 'Identity' 'GwsRoles' -List { Invoke-TRGoogle -Path '/admin/directory/v1/customer/my_customer/roles' -Query @{ maxResults = 100 } -All -ItemsKey 'items' } | Out-Null
    Invoke-TRStep 'Identity' 'GwsRoleAssignments' -List { Invoke-TRGoogle -Path '/admin/directory/v1/customer/my_customer/roleassignments' -Query @{ maxResults = 200 } -All -ItemsKey 'items' } | Out-Null
    Set-TRProgress 16 'Reading Admin console settings'
    Invoke-TRStep 'Identity' 'GwsPolicies' -List { Invoke-TRGoogle -Service Identity -Path '/v1/policies' -Query @{ pageSize = 100 } -All -ItemsKey 'policies' -PageDelayMs 1000 } | Out-Null
    $cust = Get-TRGwsRaw 'GwsCustomer'
    $cid = if ($cust -and $cust.id) { [string]$cust.id } else { [string](Get-TRContext).CustomerId }
    if ($cid) {
        $filter = 'customer=="customers/{0}"' -f $cid
        Invoke-TRStep 'Identity' 'GwsSsoProfiles' -List -Optional { Invoke-TRGoogle -Service Identity -Path '/v1/inboundSamlSsoProfiles' -Query @{ filter = $filter } -All -ItemsKey 'inboundSamlSsoProfiles' } | Out-Null
        Invoke-TRStep 'Identity' 'GwsSsoAssignments' -List -Optional { Invoke-TRGoogle -Service Identity -Path '/v1/inboundSsoAssignments' -Query @{ filter = $filter } -All -ItemsKey 'inboundSsoAssignments' } | Out-Null
    }
    Set-TRProgress 20 'Reading usage reports'
    Invoke-TRStep 'Identity' 'GwsUserUsage' -List { Get-TRGwsUsageReport -Parameters $script:TRGoogleUsageParams } | Out-Null
}

function Invoke-TRGwsCollectLicensing {
    Set-TRProgress 24 'Reading licence assignments'
    Invoke-TRStep 'Licensing' 'GwsLicences' -List {
        $ctx = Get-TRContext
        $cust = if ($ctx.DefaultDomain) { $ctx.DefaultDomain } else { $ctx.CustomerId }
        $ok = 0
        $errs = @()
        foreach ($p in $script:TRGoogleProducts) {
            Test-TRCancelled
            try {
                Invoke-TRGoogle -Service Licensing -Path ('/apps/licensing/v1/product/{0}/users' -f [uri]::EscapeDataString($p)) -Query @{ customerId = $cust; maxResults = 1000 } -All -ItemsKey 'items' -MaxRetry 3
                $ok++
            }
            catch {
                $errs += ('{0}: {1}' -f $p, $_.Exception.Message)
                if ([int]$_.Exception.Data['HttpStatus'] -in @(401, 403) -and $ok -eq 0 -and $errs.Count -ge 2) { break }
            }
        }
        if (-not $ok) { throw ('Licence assignments could not be read. ' + ((@($errs) | Select-Object -First 2) -join ' ')) }
    } | Out-Null
}

function Invoke-TRGwsCollectApplications {
    param([int]$MaxUsers)
    Set-TRProgress 30 'Reading third-party app access and app passwords'
    $users = @(Get-TRGwsActiveUsers)
    $usage = @{}
    foreach ($u in @($script:TRRaw['GwsUserUsage'])) { if ($u -and $u.Email) { $usage[$u.Email.ToLower()] = $u } }
    $tokenUsers = @($users | Where-Object { $x = $usage[([string]$_.primaryEmail).ToLower()]; (-not $x) -or ($null -eq $x.accounts_num_authorized_apps) -or ([long]$x.accounts_num_authorized_apps -gt 0) })
    if ($tokenUsers.Count -gt $MaxUsers) {
        Write-TRLog ('Third-party app grants were read for the first {0} of {1} users.' -f $MaxUsers, $tokenUsers.Count) 'Warn'
        $tokenUsers = @($tokenUsers | Select-Object -First $MaxUsers)
    }
    Invoke-TRStep 'Applications' 'GwsTokens' -List {
        $n = 0
        foreach ($u in $tokenUsers) {
            $n++
            if ($n % 50 -eq 0) { Set-TRProgress 30 ('Reading third-party app grants ({0} of {1} users)' -f $n, $tokenUsers.Count) }
            $r = Invoke-TRGoogle -Path ('/admin/directory/v1/users/{0}/tokens' -f [uri]::EscapeDataString([string]$u.id))
            foreach ($t in @($r.items)) {
                if (-not $t) { continue }
                [pscustomobject][ordered]@{ User = [string]$u.primaryEmail; ClientId = [string]$t.clientId; App = [string]$t.displayText; Scopes = @($t.scopes); Anonymous = [bool]$t.anonymous; NativeApp = [bool]$t.nativeApp }
            }
        }
    } | Out-Null
    $aspUsers = @($users | Where-Object { $_.isEnrolledIn2Sv } | Select-Object -First $MaxUsers)
    Invoke-TRStep 'Applications' 'GwsAsps' -List {
        foreach ($u in $aspUsers) {
            $r = Invoke-TRGoogle -Path ('/admin/directory/v1/users/{0}/asps' -f [uri]::EscapeDataString([string]$u.id))
            foreach ($a in @($r.items)) {
                if (-not $a) { continue }
                [pscustomobject][ordered]@{ User = [string]$u.primaryEmail; Name = [string]$a.name; Created = [string]$a.creationTime; LastUsed = [string]$a.lastTimeUsed }
            }
        }
    } | Out-Null
}

function Get-TRGwsMailDomains {
    $rows = New-Object System.Collections.ArrayList
    foreach ($d in @($script:TRRaw['GwsDomains'])) {
        if (-not $d -or -not $d.verified) { continue }
        [void]$rows.Add([pscustomobject]@{ Name = [string]$d.domainName; Primary = [bool]$d.isPrimary; Alias = $false })
        foreach ($a in @($d.domainAliases)) { if ($a -and $a.verified) { [void]$rows.Add([pscustomobject]@{ Name = [string]$a.domainAliasName; Primary = $false; Alias = $true }) } }
    }
    foreach ($a in @($script:TRRaw['GwsDomainAliases'])) {
        if ($a -and $a.verified -and -not @($rows | Where-Object { $_.Name -eq [string]$a.domainAliasName }).Count) { [void]$rows.Add([pscustomobject]@{ Name = [string]$a.domainAliasName; Primary = $false; Alias = $true }) }
    }
    , $rows.ToArray()
}

function Invoke-TRGwsCollectDns {
    Set-TRProgress 40 'Checking email DNS records'
    Invoke-TRStep 'Dns' 'GwsDnsRecords' -List {
        foreach ($d in (Get-TRGwsMailDomains)) {
            Test-TRCancelled
            $name = $d.Name
            $errors = @()
            $mx = @(); $txt = @(); $dmarc = @(); $dkim = @(); $sts = @()
            try { $mx = @(Get-TRDnsRecord $name 'MX') } catch { $errors += $_.Exception.Message }
            try { $txt = @(Get-TRDnsRecord $name 'TXT') } catch { $errors += $_.Exception.Message }
            try { $dmarc = @(Get-TRDnsRecord ('_dmarc.' + $name) 'TXT') } catch { $errors += $_.Exception.Message }
            $selector = ''
            foreach ($sel in 'google', 'google2048', 'selector1', 'selector2') {
                try { $dkim = @(Get-TRDnsRecord ($sel + '._domainkey.' + $name) 'TXT') | Where-Object { $_ -match 'v=DKIM1|p=' } } catch { $dkim = @() }
                if (@($dkim).Count) { $selector = $sel; break }
            }
            try { $sts = @(Get-TRDnsRecord ('_mta-sts.' + $name) 'TXT') } catch { }
            [pscustomobject][ordered]@{
                Domain       = $name
                IsPrimary    = $d.Primary
                IsAlias      = $d.Alias
                Mx           = @($mx)
                Spf          = @($txt | Where-Object { $_ -match '^\s*"?v=spf1' })
                Dmarc        = @($dmarc | Where-Object { $_ -match '^\s*"?v=DMARC1' })
                Dkim         = @($dkim)
                DkimSelector = $selector
                MtaSts       = @($sts | Where-Object { $_ -match '^\s*"?v=STSv1' })
                Errors       = ($errors -join '; ')
            }
        }
    } | Out-Null
}

function Invoke-TRGwsCollectGroups {
    param([switch]$Members, [int]$MaxGroups = 1000)
    Set-TRProgress 48 'Reading groups and group settings'
    Invoke-TRStep 'Collaboration' 'GwsGroups' -List { Invoke-TRGoogle -Path '/admin/directory/v1/groups' -Query @{ customer = 'my_customer'; maxResults = 200 } -All -ItemsKey 'groups' } | Out-Null
    $groups = @(@($script:TRRaw['GwsGroups']) | Where-Object { $_ })
    if ($groups.Count -gt $MaxGroups) {
        Write-TRLog ('Group settings and members were read for the first {0} of {1} groups.' -f $MaxGroups, $groups.Count) 'Warn'
        $groups = @($groups | Select-Object -First $MaxGroups)
    }
    Invoke-TRStep 'Collaboration' 'GwsGroupSettings' -List {
        $n = 0
        foreach ($g in $groups) {
            $n++
            if ($n % 25 -eq 0) { Set-TRProgress 50 ('Reading group settings ({0} of {1})' -f $n, $groups.Count) }
            $s = Invoke-TRGoogle -Service Groups -Path ('/groups/v1/groups/' + [uri]::EscapeDataString([string]$g.email)) -Query @{ alt = 'json' }
            if ($s) { $s | Add-Member -NotePropertyName 'GroupId' -NotePropertyValue ([string]$g.id) -Force; $s }
        }
    } | Out-Null
    if ($Members) {
        Invoke-TRStep 'Collaboration' 'GwsGroupMembers' -List {
            $n = 0
            foreach ($g in $groups) {
                $n++
                if ($n % 25 -eq 0) { Set-TRProgress 52 ('Reading group members ({0} of {1})' -f $n, $groups.Count) }
                $m = Invoke-TRGoogle -Path ('/admin/directory/v1/groups/{0}/members' -f [uri]::EscapeDataString([string]$g.id)) -Query @{ maxResults = 200 } -All -ItemsKey 'members'
                foreach ($x in @($m)) {
                    if (-not $x) { continue }
                    [pscustomobject][ordered]@{ Group = [string]$g.email; GroupName = [string]$g.name; Member = [string]$x.email; Role = [string]$x.role; Type = [string]$x.type; Status = [string]$x.status }
                }
            }
        } | Out-Null
    }
}

function Invoke-TRGwsCollectDevices {
    Set-TRProgress 58 'Reading managed devices'
    $cid = [string](Get-TRContext).CustomerId
    $cust = 'customers/' + $(if ($cid) { $cid } else { 'my_customer' })
    Invoke-TRStep 'Devices' 'GwsDevices' -List { Invoke-TRGoogle -Service Identity -Path '/v1/devices' -Query @{ customer = $cust; pageSize = 100 } -All -ItemsKey 'devices' } | Out-Null
    Invoke-TRStep 'Devices' 'GwsDeviceUsers' -List { Invoke-TRGoogle -Service Identity -Path '/v1/devices/-/deviceUsers' -Query @{ customer = $cust; pageSize = 100 } -All -ItemsKey 'deviceUsers' } | Out-Null
    Invoke-TRStep 'Devices' 'GwsChromeDevices' -List -Optional { Invoke-TRGoogle -Path '/admin/directory/v1/customer/my_customer/devices/chromeos' -Query @{ projection = 'BASIC'; maxResults = 300 } -All -ItemsKey 'chromeosdevices' } | Out-Null
}

function Invoke-TRGwsCollectSecurity {
    Set-TRProgress 64 'Reading Alert Center and audit events'
    $since = (Get-Date).ToUniversalTime().AddDays(-90).ToString('yyyy-MM-ddTHH:mm:ssZ')
    Invoke-TRStep 'Security' 'GwsAlerts' -List { Invoke-TRGoogle -Service Alert -Path '/v1beta1/alerts' -Query @{ pageSize = 100; filter = ('createTime >= "{0}"' -f $since) } -All -ItemsKey 'alerts' -MaxItems 2000 } | Out-Null
    Invoke-TRStep 'Security' 'GwsLoginEvents' -List {
        foreach ($e in $script:TRGoogleLoginEvents) {
            try { Get-TRGwsActivities -Application 'login' -EventName $e -Days 30 -MaxItems 2000 }
            catch { if ([int]$_.Exception.Data['HttpStatus'] -ne 400) { throw } }
        }
    } | Out-Null
}

function Invoke-TRGwsCollectAdminEvents {
    Set-TRProgress 68 'Reading admin audit events (180 days)'
    Invoke-TRStep 'Security' 'GwsAdminEvents' -List { Get-TRGwsActivities -Application 'admin' -Days 180 -MaxItems 30000 } | Out-Null
}

function Invoke-TRGwsCollectOpportunities {
    Set-TRProgress 72 'Reading service usage for licence utilisation'
    Invoke-TRStep 'Opportunities' 'GwsVaultEvents' -List -Optional { Get-TRGwsActivities -Application 'vault' -Days 180 -MaxItems 200 } | Out-Null
    Invoke-TRStep 'Opportunities' 'GwsMeetEvents' -List -Optional { Get-TRGwsActivities -Application 'meet' -EventName 'call_ended' -Days 30 -MaxItems 5000 } | Out-Null
}

function Invoke-TRGwsCollectDriveSharing {
    Set-TRProgress 76 'Reading Drive sharing events (30 days)'
    Invoke-TRStep 'DriveSharing' 'GwsDriveSharing' -List {
        foreach ($e in 'change_document_visibility', 'change_user_access') {
            Get-TRGwsActivities -Application 'drive' -EventName $e -Days 30 -MaxItems 20000 | Where-Object {
                ([string]$_.visibility -in @('shared_externally', 'people_with_link', 'public_on_the_web', 'public_in_the_domain')) -or ([string]$_.target_domain -and [string]$_.target_domain -notin @('all', 'all_of_domain'))
            }
        }
    } | Out-Null
}

function Invoke-TRGoogleCollection {
    param(
        [string[]]$Areas = $script:TRGoogleDefaultAreas,
        [string]$ClientName,
        [int]$MaxUsers = 3000,
        [int]$MaxGroups = 1000,
        [string]$ToolVersion = '1.5.0'
    )
    $ctx = Get-TRContext
    if (-not $ctx -or $ctx.Platform -ne 'Google' -or -not $ctx.CustomerId) { throw 'Sign in to the client''s Google Workspace first.' }
    $script:TRRaw = [ordered]@{}
    $script:TRDiag = New-Object System.Collections.ArrayList
    $script:TRRaw['Meta'] = [ordered]@{
        Platform      = 'Google'
        ToolVersion   = $ToolVersion
        ClientName    = $ClientName
        TenantId      = $ctx.CustomerId
        TenantName    = $ctx.TenantName
        InitialDomain = $ctx.InitialDomain
        DefaultDomain = $ctx.DefaultDomain
        Reviewer      = $ctx.Account
        ReviewerName  = $ctx.AccountName
        IsSuperAdmin  = $ctx.IsSuperAdmin
        StartedUtc    = (Get-Date).ToUniversalTime().ToString('o')
        FinishedUtc   = $null
        Areas         = @($Areas)
        GrantedScopes = $(if ($ctx.Scopes['Google']) { $ctx.Scopes['Google'] } else { '' })
    }
    Write-TRLog ('Starting Google Workspace collection for {0}: {1}' -f $ctx.TenantName, ($Areas -join ', '))
    Invoke-TRGwsCollectIdentity -MaxUsers $MaxUsers
    Invoke-TRGwsCollectLicensing
    if ($Areas -contains 'Applications') { Invoke-TRGwsCollectApplications -MaxUsers $MaxUsers }
    if ($Areas -contains 'Dns') { Invoke-TRGwsCollectDns }
    $needGroups = ($Areas -contains 'Collaboration') -or ($Areas -contains 'GroupMembership') -or ($Areas -contains 'Benchmarks')
    if ($needGroups) { Invoke-TRGwsCollectGroups -Members:(($Areas -contains 'Collaboration') -or ($Areas -contains 'GroupMembership')) -MaxGroups $MaxGroups }
    if ($Areas -contains 'Devices') { Invoke-TRGwsCollectDevices }
    if ($Areas -contains 'Security') { Invoke-TRGwsCollectSecurity }
    if (($Areas -contains 'Security') -or ($Areas -contains 'Benchmarks')) { Invoke-TRGwsCollectAdminEvents }
    if ($Areas -contains 'Opportunities') { Invoke-TRGwsCollectOpportunities }
    if ($Areas -contains 'DriveSharing') { Invoke-TRGwsCollectDriveSharing }
    $script:TRRaw['Meta']['FinishedUtc'] = (Get-Date).ToUniversalTime().ToString('o')
    $script:TRRaw['Diagnostics'] = $script:TRDiag.ToArray()
    $failed = @($script:TRDiag | Where-Object { $_.Status -eq 'Failed' }).Count
    Write-TRLog ('Collection finished. {0} items collected, {1} failed.' -f @($script:TRDiag | Where-Object { $_.Status -eq 'OK' }).Count, $failed) $(if ($failed) { 'Warn' } else { 'Success' })
    $script:TRRaw
}
