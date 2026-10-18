$script:TROsLifecycle = @(
    @{ Match = 'Windows Server 2008'; End = '2020-01-14'; Esu = '2024-01-09' }
    @{ Match = 'Windows Server 2012'; End = '2023-10-10'; Esu = '2026-10-13' }
    @{ Match = 'Windows Server 2016'; End = '2027-01-12' }
    @{ Match = 'Windows Server 2019'; End = '2029-01-09' }
    @{ Match = 'Windows Server 2022'; End = '2031-10-14' }
    @{ Match = 'Windows Server 2025'; End = '2034-10-10' }
    @{ Match = 'Windows 10'; End = '2025-10-14' }
    @{ Match = 'Ubuntu 16.04'; End = '2021-04-30' }
    @{ Match = 'Ubuntu 18.04'; End = '2023-05-31' }
    @{ Match = 'Ubuntu 20.04'; End = '2025-05-31' }
    @{ Match = 'Ubuntu 22.04'; End = '2027-06-01' }
    @{ Match = 'Ubuntu 24.04'; End = '2029-05-31' }
    @{ Match = 'CentOS 7'; End = '2024-06-30' }
    @{ Match = 'CentOS 8'; End = '2021-12-31' }
    @{ Match = 'Red Hat Enterprise Linux 7'; End = '2024-06-30' }
    @{ Match = 'Red Hat Enterprise Linux 8'; End = '2029-05-31' }
    @{ Match = 'Red Hat Enterprise Linux 9'; End = '2032-05-31' }
    @{ Match = 'Debian 10'; End = '2024-06-30' }
    @{ Match = 'Debian 11'; End = '2026-08-31' }
    @{ Match = 'Debian 12'; End = '2028-06-30' }
    @{ Match = 'SUSE Linux Enterprise Server 12'; End = '2024-10-31' }
)

$script:TRMgmtPorts = @{ 22 = 'SSH'; 3389 = 'RDP'; 5985 = 'WinRM'; 5986 = 'WinRM over HTTPS'; 23 = 'Telnet'; 445 = 'SMB'; 135 = 'RPC'; 139 = 'NetBIOS'; 1433 = 'SQL Server'; 3306 = 'MySQL'; 5432 = 'PostgreSQL'; 21 = 'FTP'; 5900 = 'VNC' }

$script:TRAzRoleIds = @{
    '8e3af657-a8ff-443c-a75c-2fe8c4bcb635' = 'Owner'
    '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9' = 'User Access Administrator'
    'f58310d9-a9f6-439a-9e8d-f62e7b41a168' = 'Role Based Access Control Administrator'
    'b24988ac-6180-42a0-ab88-20f7382dd24c' = 'Contributor'
    'acdd72a7-3385-48ef-bd42-f606fba81ae7' = 'Reader'
}

function Get-TROsName {
    param([string]$Name, [string]$Version, [string]$Offer, [string]$Sku)
    $n = ('{0} {1}' -f $Name, $Version).Trim()
    $img = ('{0} {1}' -f $Offer, $Sku)
    if ($n -match 'Windows Server (\d{4})( R2)?') { return 'Windows Server ' + $Matches[1] + $Matches[2] }
    if ($img -match 'Windows Server (\d{4})( R2)?') { return 'Windows Server ' + $Matches[1] + $Matches[2] }
    if ($n -match 'Windows (1[01])\b(?!\.)') { return 'Windows ' + $Matches[1] }
    if ($n -match '^windows\s+(\d+\.\d+)\.(\d+)') {
        $builds = @{ '7601' = 'Windows Server 2008 R2'; '9200' = 'Windows Server 2012'; '9600' = 'Windows Server 2012 R2'; '14393' = 'Windows Server 2016'; '17763' = 'Windows Server 2019'; '20348' = 'Windows Server 2022'; '26100' = 'Windows Server 2025' }
        if ($builds[$Matches[2]]) { return $builds[$Matches[2]] }
    }
    if ($img -match 'WindowsServer.*?(2008|2012|2016|2019|2022|2025)(-R2)?' -or $img -match '^(?:\S+\s)?(2008|2012|2016|2019|2022|2025)(-R2)?-') { return 'Windows Server ' + $Matches[1] + $(if ($Matches[2]) { ' R2' } else { '' }) }
    if ($n -match 'ubuntu\D*(\d{2}\.\d{2})' -or ($Name -match 'ubuntu' -and $Version -match '^(\d{2}\.\d{2})')) { return 'Ubuntu ' + $Matches[1] }
    if ($img -match 'ubuntu' -and $img -match '(\d{2})[._](04|10)') { return ('Ubuntu {0}.{1}' -f $Matches[1], $Matches[2]) }
    if ($n -match 'centos\D*(\d)' -or $img -match 'centos\D*(\d)') { return 'CentOS ' + $Matches[1] }
    if ($n -match '(red ?hat|rhel)\D*(\d)' -or $img -match '(rhel)\D*(\d)') { return 'Red Hat Enterprise Linux ' + $Matches[2] }
    if ($n -match 'debian\D*(\d{1,2})' -or $img -match 'debian\D*(\d{1,2})') { return 'Debian ' + $Matches[1] }
    if ($n -match '(sles|suse)\D*(\d{2})' -or $img -match '(sles)\D*(\d{2})') { return 'SUSE Linux Enterprise Server ' + $Matches[2] }
    if ($Name) { return $n }
    if ($Offer) { return $img.Trim() }
    ''
}

function Get-TROsSupport {
    param([string]$Os)
    if (-not $Os) { return $null }
    $now = Get-TRNow
    foreach ($l in $script:TROsLifecycle) {
        if ($Os -notlike ($l.Match + '*')) { continue }
        $utc = [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
        $end = [datetime]::ParseExact($l.End, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture, $utc)
        $esu = if ($l.Esu) { [datetime]::ParseExact($l.Esu, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture, $utc) } else { $null }
        $days = [int]($end - $now).TotalDays
        $state = if ($days -lt 0) { if ($esu -and $esu -gt $now) { 'Esu' } else { 'Ended' } } elseif ($days -le 180) { 'Ending' } else { 'Supported' }
        return [pscustomobject]@{ Os = $Os; End = $end; Esu = $esu; Days = $days; State = $state }
    }
    $null
}

function Get-TRAzSubName {
    param([string]$Id)
    $idx = Get-TRCached 'AzSubIndex' { $h = @{}; foreach ($s in (Get-TRItems 'AzSubscriptions')) { $h[[string]$s.subscriptionId] = [string]$s.displayName }; $h }
    if ($idx[$Id]) { return $idx[$Id] }
    $Id
}

function Get-TRAzPrincipal {
    param([string]$Id)
    $idx = Get-TRCached 'AzPrincipalIndex' { $h = @{}; foreach ($p in (Get-TRItems 'AzPrincipals')) { $h[[string]$p.id] = $p }; $h }
    $idx[$Id]
}

function Get-TRAzRoleName {
    param([string]$RoleDefinitionId)
    $guid = ([string]$RoleDefinitionId -split '/')[-1].ToLower()
    $idx = Get-TRCached 'AzRoleIndex' { $h = @{}; foreach ($r in (Get-TRItems 'AzRoleDefinitions')) { $h[([string]$r.name).ToLower()] = [string]$r.roleName }; $h }
    if ($idx[$guid]) { return $idx[$guid] }
    if ($script:TRAzRoleIds[$guid]) { return $script:TRAzRoleIds[$guid] }
    $guid
}

function Get-TRAzNsgAttached {
    Get-TRCached 'AzNsgAttached' {
        $h = @{}
        foreach ($n in (Get-TRItems 'AzNics')) { if ($n.nsgId) { $h[[string]$n.nsgId] = $true } }
        foreach ($s in (Get-TRItems 'AzSubnets')) { if ($s.nsgId) { $h[[string]$s.nsgId] = $true } }
        $h
    }
}

function Test-TRAzInternetSource {
    param([string]$Source, [string]$Sources)
    $all = @($Source) + @(([string]$Sources).Trim('[]') -split ',' | ForEach-Object { $_.Trim().Trim('"') })
    [bool]@($all | Where-Object { $_ -in @('*', 'Internet', '0.0.0.0/0', 'Any', '::/0', '0.0.0.0') }).Count
}

function Get-TRAzRulePorts {
    param([string]$Port, [string]$Ports)
    $specs = @($Port) + @(([string]$Ports).Trim('[]') -split ',' | ForEach-Object { $_.Trim().Trim('"') }) | Where-Object { $_ }
    $hit = @()
    foreach ($p in $script:TRMgmtPorts.Keys) {
        foreach ($s in $specs) {
            if ($s -eq '*') { $hit += $p; break }
            if ($s -match '^(\d+)-(\d+)$') { if ($p -ge [int]$Matches[1] -and $p -le [int]$Matches[2]) { $hit += $p; break } }
            elseif ($s -match '^\d+$' -and [int]$s -eq $p) { $hit += $p; break }
        }
    }
    , @($hit)
}

function Get-TRAzVms {
    Get-TRCached 'AzVmList' {
        $nics = @{}
        foreach ($n in (Get-TRItems 'AzNics')) { if ($n.vmId) { if (-not $nics.ContainsKey([string]$n.vmId)) { $nics[[string]$n.vmId] = @() }; $nics[[string]$n.vmId] += $n } }
        $ext = @{}
        foreach ($e in (Get-TRItems 'AzVmExtensions')) { $k = [string]$e.vmId; if (-not $ext.ContainsKey($k)) { $ext[$k] = @() }; $ext[$k] += $e }
        $backup = @{}
        foreach ($b in (Get-TRItems 'AzBackupItems')) { if ($b.sourceId) { $backup[[string]$b.sourceId] = $b } }
        $patch = @{}
        foreach ($p in (Get-TRItems 'AzPatchAssessments')) { $patch[[string]$p.vmId] = $p }
        $subnetNsg = @{}
        foreach ($s in (Get-TRItems 'AzSubnets')) { $subnetNsg[[string]$s.subnetId] = [string]$s.nsgId }
        $rows = foreach ($v in (Get-TRItems 'AzVms')) {
            $id = [string]$v.id
            $vn = @($nics[$id])
            $ex = @($ext[$id])
            $os = Get-TROsName -Name $v.osName -Version $v.osVersion -Offer $v.imageOffer -Sku $v.imageSku
            [pscustomobject]@{
                Id = $id; Name = [string]$v.name; ResourceGroup = [string]$v.resourceGroup; SubscriptionId = [string]$v.subscriptionId; Location = [string]$v.location
                Size = [string]$v.vmSize; OsType = [string]$v.osType; Os = $os; Support = (Get-TROsSupport $os)
                Running = ([string]$v.powerState -eq 'PowerState/running'); PowerState = ([string]$v.powerState -replace '^PowerState/', '')
                PublicIp = [bool]@($vn | Where-Object { $_.publicIpId }).Count
                Nsg = [bool]@($vn | Where-Object { $_.nsgId -or $subnetNsg[[string]$_.subnetId] }).Count
                Mde = [bool]@($ex | Where-Object { [string]$_.extensionType -match '^MDE\.' }).Count
                Ama = [bool]@($ex | Where-Object { [string]$_.extensionType -match 'AzureMonitor(Windows|Linux)Agent' }).Count
                Mma = [bool]@($ex | Where-Object { [string]$_.extensionType -match '^(MicrosoftMonitoringAgent|OmsAgentForLinux)$' }).Count
                Backup = $backup[$id]; Patch = $patch[$id]
                SecurityType = [string]$v.securityType; LicenseType = [string]$v.licenseType
            }
        }
        @($rows)
    }
}

function Get-TRAzDefenderNames {
    Get-TRCached 'AzDefenderNames' {
        $h = @{}
        foreach ($d in (Get-TRItems 'DefenderDevices')) {
            $n = ([string]$d.DeviceName -split '\.')[0].ToLower()
            if ($n) { $h[$n] = $true }
        }
        $h
    }
}

function Test-TRAzTrue { param($Value) ([string]$Value) -eq 'true' -or $Value -eq $true }

function New-TRAzAffected {
    param($Item, [string]$Detail)
    New-TRAffected ('{0} ({1})' -f $Item.name, (Get-TRAzSubName ([string]$Item.subscriptionId))) $Detail
}

Register-TRCheck -Id 'AZ-01' -Area 'Azure' -Category 'Azure governance and cost' -Severity Info -Effort 0 `
    -Title 'Azure subscriptions in scope' `
    -Needs 'AzSubscriptions' `
    -Recommendation 'Confirm with the client that every Azure subscription is listed. Subscriptions where the signed-in account has no role are not visible, for example a pay-as-you-go or Enterprise Agreement subscription outside the CSP relationship. Give the review account Reader (and Security Reader) on any that are missing.' `
    -Reference 'https://learn.microsoft.com/azure/cost-management-billing/manage/view-all-accounts' `
    -Test {
    $subs = @(Get-TRItems 'AzSubscriptions')
    if (-not $subs.Count) { return New-TRResult Info 'No Azure subscription is visible to the signed-in account.' }
    $counts = @{}
    foreach ($r in (Get-TRItems 'AzResourceCounts')) { $counts[[string]$r.subscriptionId] += [int]$r.count }
    $byOffer = @($subs | Group-Object offer | ForEach-Object { '{0} {1}' -f $_.Count, $_.Name })
    $denied = @(Get-TRItems 'AzAccess' | Select-Object -ExpandProperty subscription -Unique)
    $text = '{0} visible ({1}).' -f (Format-TRN $subs.Count 'subscription is' 'subscriptions are'), ($byOffer -join ', ')
    if ($denied.Count) { $text += (' Some settings could not be read in {0}, because the account''s role there does not allow it.' -f (Join-TRList $denied 3)) }
    New-TRResult Info $text @($subs | ForEach-Object { New-TRAffected $_.displayName ('{0}; {1}; access {2}; {3}' -f $_.offer, $_.state, $_.authorizationSource, (Format-TRN ([int]$counts[[string]$_.subscriptionId]) 'resource')) })
}

Register-TRCheck -Id 'AZ-02' -Area 'Azure' -Category 'Azure security' -Severity High -Effort 3 `
    -Title 'Microsoft Defender for Cloud protects servers and data services' `
    -Needs 'AzDefenderPlans', 'AzResourceCounts' `
    -Recommendation 'Turn on Defender for Servers (Plan 1 at least, which includes Defender for Endpoint) in every subscription with virtual machines or Arc servers, and Defender for Storage, SQL and Key Vault where those resources hold client data. (MCSB LT-1, ES-1)' `
    -Reference 'https://learn.microsoft.com/azure/defender-for-cloud/connect-azure-subscription' `
    -Test {
    $types = @{}
    foreach ($r in (Get-TRItems 'AzResourceCounts')) { $types[('{0}|{1}' -f $r.subscriptionId, ([string]$r.type).ToLower())] = [int]$r.count }
    $plans = @{}
    foreach ($p in (Get-TRItems 'AzDefenderPlans')) { $plans[('{0}|{1}' -f $p.subscriptionId, $p.name)] = $p }
    $map = [ordered]@{
        VirtualMachines = @{ Name = 'Defender for Servers'; Types = @('microsoft.compute/virtualmachines', 'microsoft.hybridcompute/machines') }
        StorageAccounts = @{ Name = 'Defender for Storage'; Types = @('microsoft.storage/storageaccounts') }
        SqlServers      = @{ Name = 'Defender for SQL'; Types = @('microsoft.sql/servers') }
        KeyVaults       = @{ Name = 'Defender for Key Vault'; Types = @('microsoft.keyvault/vaults') }
        AppServices     = @{ Name = 'Defender for App Service'; Types = @('microsoft.web/sites') }
    }
    $aff = @(); $serversOff = 0; $unread = @()
    $denied = @{}
    foreach ($x in (Get-TRItems 'AzAccess' | Where-Object { $_.item -eq 'AzDefenderPlans' })) { $denied[[string]$x.subscriptionId] = $true }
    foreach ($s in (Get-TRItems 'AzSubscriptions' | Where-Object { $_.state -eq 'Enabled' })) {
        if ($denied[[string]$s.subscriptionId]) { $unread += $s.displayName; continue }
        foreach ($k in $map.Keys) {
            $n = 0
            foreach ($t in $map[$k].Types) { $n += [int]$types[('{0}|{1}' -f $s.subscriptionId, $t)] }
            if (-not $n) { continue }
            $p = $plans[('{0}|{1}' -f $s.subscriptionId, $k)]
            $tier = if ($p) { [string]$p.properties.pricingTier } else { 'Unknown' }
            if ($tier -ne 'Standard') {
                $aff += (New-TRAffected ('{0}: {1}' -f $s.displayName, $map[$k].Name) ('Off ({0}); {1}' -f $tier, (Format-TRN $n 'resource')))
                if ($k -eq 'VirtualMachines') { $serversOff++ }
            }
        }
    }
    $note = if ($unread.Count) { (' The plans in {0} could not be read (the account needs Security Reader or Reader there).' -f (Join-TRList $unread 3)) } else { '' }
    $aff += @($unread | ForEach-Object { New-TRAffected $_ 'Defender plans could not be read' })
    if (-not $serversOff -and -not @($aff | Where-Object { $_.Detail -like 'Off*' }).Count) { return New-TRResult $(if ($unread.Count) { 'Warning' } else { 'Pass' }) ('Defender for Cloud plans are on for every resource type in use where they could be read.' + $note) $aff }
    $off = @($aff | Where-Object { $_.Detail -like 'Off*' })
    $status = if ($serversOff) { 'Fail' } else { 'Warning' }
    New-TRResult $status (('{0} not on for resources in use{1}.' -f (Format-TRN $off.Count 'Defender plan is' 'Defender plans are'), $(if ($serversOff) { (', including Defender for Servers in {0}' -f (Format-TRN $serversOff 'subscription')) } else { '' })) + $note) $aff
}

Register-TRCheck -Id 'AZ-03' -Area 'Azure' -Category 'Azure security' -Severity Medium -Effort 8 `
    -Title 'Defender for Cloud secure score' `
    -Needs 'AzSecureScores' `
    -Recommendation 'Work through the Defender for Cloud recommendations (see the Defender for Cloud recommendations inventory), starting with high-severity items on the most resources, to raise the secure score above 70%.' `
    -Reference 'https://learn.microsoft.com/azure/defender-for-cloud/secure-score-security-controls' `
    -Test {
    $sc = @(Get-TRItems 'AzSecureScores')
    if (-not $sc.Count) { return New-TRResult Info 'Defender for Cloud returned no secure score. It may not have assessed these subscriptions yet.' }
    $aff = @($sc | Sort-Object percentage | ForEach-Object { New-TRAffected (Get-TRAzSubName $_.subscriptionId) ('{0}% ({1} of {2})' -f [Math]::Round(100 * [double]$_.percentage), [Math]::Round([double]$_.current, 1), $_.max) })
    $low = [double]($sc | Measure-Object -Property percentage -Minimum).Minimum
    $text = 'Secure score: {0}.' -f (Join-TRList (@($aff | ForEach-Object { $_.Item + ' ' + ($_.Detail -split ' ')[0] })) 5)
    if ($low -lt 0.4) { return New-TRResult Fail $text $aff }
    if ($low -lt 0.7) { return New-TRResult Warning $text $aff }
    New-TRResult Pass $text $aff
}

Register-TRCheck -Id 'AZ-04' -Area 'Azure' -Category 'Azure security' -Severity Medium -Effort 8 `
    -Title 'Microsoft cloud security benchmark compliance' `
    -Needs 'AzRegulatory' `
    -Recommendation 'Use the Defender for Cloud regulatory compliance dashboard to work through the failed Microsoft cloud security benchmark (MCSB) controls listed here. Each one links to the recommendations that make it pass.' `
    -Reference 'https://learn.microsoft.com/security/benchmark/azure/overview' `
    -Test {
    $std = @(Get-TRItems 'AzRegulatory' | Where-Object { [string]$_.standard -match 'Microsoft-cloud-security-benchmark' })
    if (-not $std.Count) { return New-TRResult Info 'The Microsoft cloud security benchmark standard was not returned by Defender for Cloud.' }
    $p = ($std | Measure-Object -Property passed -Sum).Sum
    $f = ($std | Measure-Object -Property failed -Sum).Sum
    $pct = Get-TRPercent $p ($p + $f)
    $ctl = @(Get-TRItems 'AzRegulatoryControls' | Group-Object control | Sort-Object Name | ForEach-Object { New-TRAffected ('MCSB ' + $_.Name) ('{0}; failing in {1}' -f $_.Group[0].description, (Format-TRN $_.Count 'subscription')) })
    $text = '{0}% of assessed MCSB controls pass ({1} passed, {2} failed across {3}).' -f $pct, $p, $f, (Format-TRN $std.Count 'subscription')
    if ($f -eq 0) { return New-TRResult Pass $text }
    New-TRResult $(if ($pct -lt 50) { 'Fail' } else { 'Warning' }) $text $ctl
}

Register-TRCheck -Id 'AZ-05' -Area 'Azure' -Category 'Azure security' -Severity Low -Effort 0.5 `
    -Title 'Defender for Cloud alert emails reach the right people' `
    -Needs 'AzSecurityContacts', 'AzSubscriptions' `
    -Recommendation 'In Defender for Cloud, Environment settings, Email notifications, add your security team mailbox and the client contact, notify subscription owners, and send alerts of Medium severity or higher. (MCSB IR-2)' `
    -Reference 'https://learn.microsoft.com/azure/defender-for-cloud/configure-email-notifications' `
    -Test {
    $c = @{}
    foreach ($x in (Get-TRItems 'AzSecurityContacts')) { $c[[string]$x.subscriptionId] = $x }
    $bad = @()
    $denied = @{}
    foreach ($x in (Get-TRItems 'AzAccess' | Where-Object { $_.item -eq 'AzSecurityContacts' })) { $denied[[string]$x.subscriptionId] = $true }
    foreach ($s in (Get-TRItems 'AzSubscriptions' | Where-Object { $_.state -eq 'Enabled' })) {
        if ($denied[[string]$s.subscriptionId]) { $bad += (New-TRAffected $s.displayName 'Could not be read with the account''s role'); continue }
        $x = $c[[string]$s.subscriptionId]
        $emails = if ($x) { [string]$x.properties.emails } else { '' }
        $alertsOn = $x -and (([string]$x.properties.alertNotifications.state -eq 'On') -or (@($x.properties.notificationsSources | Where-Object { [string]$_.sourceType -eq 'Alert' }).Count -gt 0))
        if (-not $emails -or -not $alertsOn) { $bad += (New-TRAffected $s.displayName $(if (-not $emails) { 'No notification email address' } else { 'Alert emails are off' })) }
    }
    $real = @($bad | Where-Object { $_.Detail -notlike 'Could not*' })
    if ($real.Count) { return New-TRResult Warning ('{0} no working security alert email.' -f (Format-TRN $real.Count 'subscription has' 'subscriptions have')) $bad }
    if ($bad.Count) { return New-TRResult Info ('The email settings could not be read in {0}.' -f (Join-TRList (@($bad | ForEach-Object { $_.Item })) 3)) $bad }
    New-TRResult Pass 'Every subscription sends Defender for Cloud alerts by email.'
}

Register-TRCheck -Id 'AZ-06' -Area 'Azure' -Category 'Azure security' -Severity High -Effort 2 `
    -Title 'Management ports are not open to the internet' `
    -Needs 'AzNsgRules', 'AzNics', 'AzSubnets' `
    -Recommendation 'Remove network security group rules that allow RDP, SSH, WinRM, SMB or database ports from Any or Internet. Use Azure Bastion, Defender for Cloud just-in-time access or a VPN for administration, and limit any remaining rules to known source addresses. (MCSB NS-1, NS-2)' `
    -Reference 'https://learn.microsoft.com/azure/bastion/bastion-overview' `
    -Test {
    $attached = Get-TRAzNsgAttached
    $hits = @()
    foreach ($r in (Get-TRItems 'AzNsgRules')) {
        if (-not (Test-TRAzInternetSource $r.source $r.sources)) { continue }
        $ports = Get-TRAzRulePorts $r.port $r.ports
        if (-not $ports.Count) { continue }
        $hits += [pscustomobject]@{ Rule = $r; Ports = $ports; Attached = [bool]$attached[[string]$r.nsgId] }
    }
    if (-not $hits.Count) { return New-TRResult Pass 'No network security group allows management or database ports from the internet.' }
    $live = @($hits | Where-Object { $_.Attached })
    $aff = @($hits | ForEach-Object { New-TRAffected ('{0} / {1} ({2})' -f $_.Rule.nsg, $_.Rule.rule, (Get-TRAzSubName $_.Rule.subscriptionId)) ('Allows {0} from {1}{2}' -f (Join-TRList (@($_.Ports | ForEach-Object { '{0} ({1})' -f $script:TRMgmtPorts[$_], $_ })) 4), $(if ($_.Rule.source) { $_.Rule.source } else { 'Any' }), $(if ($_.Attached) { '' } else { '; NSG not attached to anything' })) })
    if ($live.Count) { return New-TRResult Fail ('{0} in use {1} management or database ports from the internet.' -f (Format-TRN $live.Count 'rule' 'rules'), (Select-TRText $live.Count 'allows' 'allow')) $aff }
    New-TRResult Warning ('{0} would allow management ports from the internet, but the NSGs are not attached.' -f (Format-TRN $hits.Count 'rule' 'rules')) $aff
}

Register-TRCheck -Id 'AZ-07' -Area 'Azure' -Category 'Azure security' -Severity Medium -Effort 2 `
    -Title 'Virtual machines do not have public IP addresses' `
    -Needs 'AzVms', 'AzNics' `
    -Recommendation 'Remove public IP addresses from virtual machines that do not publish a service. Publish services through a load balancer, Application Gateway or Front Door, and administer servers through Azure Bastion or a VPN. (MCSB NS-1)' `
    -Reference 'https://learn.microsoft.com/azure/virtual-network/ip-services/remove-public-ip-address-vm' `
    -Test {
    $vms = @(Get-TRAzVms)
    if (-not $vms.Count) { return New-TRResult Info 'No Azure virtual machines were found.' }
    $pub = @($vms | Where-Object { $_.PublicIp })
    $bastion = @(Get-TRItems 'AzBastions').Count
    if (-not $pub.Count) { return New-TRResult Pass ('None of the {0} has a public IP address.' -f (Format-TRN $vms.Count 'virtual machine')) }
    New-TRResult Warning ('{0} of {1} virtual machines {3} a public IP address.{2}' -f $pub.Count, $vms.Count, $(if ($bastion) { '' } else { ' There is no Azure Bastion host.' }), (Select-TRText $pub.Count 'has' 'have')) @($pub | ForEach-Object { New-TRAffected ('{0} ({1})' -f $_.Name, (Get-TRAzSubName $_.SubscriptionId)) ('{0}; {1}' -f $_.Os, $_.PowerState) })
}

Register-TRCheck -Id 'AZ-08' -Area 'Azure' -Category 'Azure security' -Severity Medium -Effort 2 `
    -Title 'Subnets are protected by network security groups' `
    -Needs 'AzSubnets' `
    -Recommendation 'Associate a network security group with every workload subnet so traffic between subnets and from the internet is filtered by default. Gateway, Bastion and Firewall subnets are excluded. (MCSB NS-1)' `
    -Reference 'https://learn.microsoft.com/azure/virtual-network/network-security-groups-overview' `
    -Test {
    $skip = '^(GatewaySubnet|AzureBastionSubnet|AzureFirewallSubnet|AzureFirewallManagementSubnet|RouteServerSubnet)$'
    $subnets = @(Get-TRItems 'AzSubnets' | Where-Object { [string]$_.subnet -notmatch $skip -and [int]$_.delegated -eq 0 })
    if (-not $subnets.Count) { return New-TRResult Info 'No workload subnets were found.' }
    $bad = @($subnets | Where-Object { -not $_.nsgId })
    if (-not $bad.Count) { return New-TRResult Pass ('All {0} have a network security group.' -f (Format-TRN $subnets.Count 'workload subnet')) }
    New-TRResult Warning ('{0} of {1} workload subnets {2} no network security group.' -f $bad.Count, $subnets.Count, (Select-TRText $bad.Count 'has' 'have')) @($bad | ForEach-Object { New-TRAffected ('{0}/{1} ({2})' -f $_.vnet, $_.subnet, (Get-TRAzSubName $_.subscriptionId)) $_.prefix })
}

Register-TRCheck -Id 'AZ-09' -Area 'Azure' -Category 'Azure resilience' -Severity High -Effort 4 `
    -Title 'No retired Basic SKU public IPs or load balancers' `
    -Needs 'AzPublicIps', 'AzLoadBalancers' `
    -Recommendation 'Upgrade Basic SKU public IP addresses and Basic load balancers to Standard. Microsoft retired both on 30 September 2025, so Basic resources are no longer supported and can stop working.' `
    -Reference 'https://learn.microsoft.com/azure/virtual-network/ip-services/public-ip-basic-upgrade-guidance' `
    -Test {
    $ips = @(Get-TRItems 'AzPublicIps' | Where-Object { [string]$_.sku -eq 'Basic' })
    $lbs = @(Get-TRItems 'AzLoadBalancers' | Where-Object { [string]$_.sku -eq 'Basic' })
    if (-not $ips.Count -and -not $lbs.Count) { return New-TRResult Pass 'No Basic SKU public IP addresses or load balancers.' }
    $parts = @()
    if ($ips.Count) { $parts += (Format-TRN $ips.Count 'public IP address' 'public IP addresses') }
    if ($lbs.Count) { $parts += (Format-TRN $lbs.Count 'load balancer') }
    New-TRResult Fail ('{0} still {1} the retired Basic SKU.' -f ($parts -join ' and '), (Select-TRText ($ips.Count + $lbs.Count) 'uses' 'use')) (@($ips | ForEach-Object { New-TRAzAffected $_ ('Public IP ' + $_.ipAddress) }) + @($lbs | ForEach-Object { New-TRAzAffected $_ 'Load balancer' }))
}

Register-TRCheck -Id 'AZ-10' -Area 'Azure' -Category 'Azure resilience' -Severity High -Effort 3 `
    -Title 'Virtual machines are backed up' `
    -Needs 'AzVms', 'AzBackupItems' `
    -Recommendation 'Protect every virtual machine with Azure Backup (or confirm another backup product covers it), with daily backups, at least 30 days of retention and alerts on failed jobs. Investigate any backup that has not completed in the last two days. (MCSB BR-1, BR-3)' `
    -Reference 'https://learn.microsoft.com/azure/backup/backup-azure-vms-introduction' `
    -Test {
    $vms = @(Get-TRAzVms)
    if (-not $vms.Count) { return New-TRResult Info 'No Azure virtual machines were found.' }
    $none = @($vms | Where-Object { -not $_.Backup })
    $stale = @($vms | Where-Object { $_.Backup -and ((Get-TRDaysSince $_.Backup.lastBackup) -gt 2 -or [string]$_.Backup.health -notin @('Passed', 'Healthy', '')) })
    $aff = @($none | ForEach-Object { New-TRAffected ('{0} ({1})' -f $_.Name, (Get-TRAzSubName $_.SubscriptionId)) ('Not protected by Azure Backup; {0}' -f $_.PowerState) }) + @($stale | ForEach-Object { New-TRAffected ('{0} ({1})' -f $_.Name, (Get-TRAzSubName $_.SubscriptionId)) ('Last backup {0}; {1}; health {2}' -f (Format-TRDate $_.Backup.lastBackup), $_.Backup.lastBackupStatus, $_.Backup.health) })
    if ($none.Count) { return New-TRResult Fail ('{0} of {1} virtual machines {3} not protected by Azure Backup{2}.' -f $none.Count, $vms.Count, $(if ($stale.Count) { (', and {0} more {1} not backed up recently' -f $stale.Count, (Select-TRText $stale.Count 'has' 'have')) } else { '' }), (Select-TRText $none.Count 'is' 'are')) $aff }
    if ($stale.Count) { return New-TRResult Warning ('{0} have not completed a healthy backup in the last two days.' -f (Format-TRN $stale.Count 'virtual machine' 'virtual machines')) $aff }
    New-TRResult Pass ('All {0} are backed up and their last backup is recent.' -f (Format-TRN $vms.Count 'virtual machine'))
}

Register-TRCheck -Id 'AZ-11' -Area 'Azure' -Category 'Azure resilience' -Severity Medium -Effort 1 `
    -Title 'Backup vaults are protected against deletion and ransomware' `
    -Needs 'AzRecoveryVaults' `
    -Recommendation 'On each Recovery Services vault, keep soft delete always on, turn on immutability (and lock it once tested), use geo-redundant storage with cross-region restore for production, and protect critical operations with multi-user authorisation (Resource Guard). (MCSB BR-2)' `
    -Reference 'https://learn.microsoft.com/azure/backup/guidance-best-practices' `
    -Test {
    $v = @(Get-TRItems 'AzRecoveryVaults')
    if (-not $v.Count) { return New-TRResult Info 'No Recovery Services vaults were found.' }
    $aff = @()
    foreach ($x in $v) {
        $gaps = @()
        if ([string]$x.softDelete -notin @('Enabled', 'AlwaysON', '')) { $gaps += 'soft delete off' }
        if ([string]$x.immutability -notin @('Unlocked', 'Locked')) { $gaps += 'immutability off' }
        if ([string]$x.redundancy -eq 'LocallyRedundant') { $gaps += 'locally redundant storage only' }
        if (-not [int]$x.resourceGuard) { $gaps += 'no multi-user authorisation' }
        if ($gaps.Count) { $aff += (New-TRAzAffected $x ($gaps -join ', ')) }
    }
    $hard = @($aff | Where-Object { $_.Detail -match 'soft delete off|immutability off' })
    if ($hard.Count) { return New-TRResult Warning ('{0} of {1} vaults {2} soft delete or immutability.' -f $hard.Count, $v.Count, (Select-TRText $hard.Count 'lacks' 'lack')) $aff }
    if ($aff.Count) { return New-TRResult Warning ('{0} of {1} vaults could be hardened further.' -f $aff.Count, $v.Count) $aff }
    New-TRResult Pass ('All {0} have soft delete, immutability, geo-redundancy and multi-user authorisation.' -f (Format-TRN $v.Count 'vault'))
}

Register-TRCheck -Id 'AZ-12' -Area 'Azure' -Category 'Azure security' -Severity High -Effort 8 `
    -Title 'Servers run a supported operating system' `
    -Needs 'AzVms' `
    -Recommendation 'Upgrade or replace servers whose operating system is out of support (Windows Server 2012 and 2012 R2 extended security updates ended on 13 October 2026; Windows Server 2016 support ends on 12 January 2027). Plan upgrades for anything ending within six months. (MCSB PV-6)' `
    -Reference 'https://learn.microsoft.com/lifecycle/products/' `
    -Test {
    $rows = @()
    foreach ($v in (Get-TRAzVms)) { $rows += [pscustomobject]@{ Name = $v.Name; Sub = $v.SubscriptionId; Os = $v.Os; Support = $v.Support; Kind = 'Azure VM' } }
    foreach ($a in (Get-TRItems 'AzArcMachines')) { $os = Get-TROsName -Name $(if ($a.osSku) { $a.osSku } else { $a.osName }) -Version $(if ($a.osSku) { '' } else { $a.osVersion }); $rows += [pscustomobject]@{ Name = [string]$a.name; Sub = [string]$a.subscriptionId; Os = $os; Support = (Get-TROsSupport $os); Kind = 'Arc server' } }
    if (-not $rows.Count) { return New-TRResult Info 'No Azure virtual machines or Arc servers were found.' }
    $ended = @($rows | Where-Object { $_.Support -and $_.Support.State -eq 'Ended' })
    $esu = @($rows | Where-Object { $_.Support -and $_.Support.State -eq 'Esu' })
    $ending = @($rows | Where-Object { $_.Support -and $_.Support.State -eq 'Ending' })
    $aff = @($ended + $esu + $ending | ForEach-Object { $sup = $_.Support; New-TRAffected ('{0} ({1})' -f $_.Name, (Get-TRAzSubName $_.Sub)) ('{0}; {1}; {2}' -f $_.Os, $_.Kind, $(switch ($sup.State) { 'Ended' { 'support ended ' + (Format-TRDate $sup.End) } 'Esu' { 'only extended security updates until ' + (Format-TRDate $sup.Esu) } default { 'support ends ' + (Format-TRDate $sup.End) } })) })
    $soon = $esu.Count + $ending.Count
    $soonVerb = Select-TRText $soon 'loses' 'lose'
    if ($ended.Count) {
        $t = '{0} out of support.' -f (Format-TRN $ended.Count 'server is' 'servers are')
        if ($soon) { $t += (' {0} on extended security updates or {1} support within six months.' -f (Format-TRN $soon 'more server is' 'more servers are'), $soonVerb) }
        return New-TRResult Fail $t $aff
    }
    if ($soon) { return New-TRResult Warning ('{0} on extended security updates or {1} support within six months.' -f (Format-TRN $soon 'server is' 'servers are'), $soonVerb) $aff }
    New-TRResult Pass ('All {0} run a supported operating system.' -f (Format-TRN $rows.Count 'server'))
}

Register-TRCheck -Id 'AZ-13' -Area 'Azure' -Category 'Azure security' -Severity High -Effort 3 `
    -Title 'Azure servers are onboarded to Defender for Endpoint' `
    -Needs 'AzVms', 'AzVmExtensions' `
    -Recommendation 'Onboard every running server to Microsoft Defender for Endpoint (Defender for Servers deploys the MDE extension automatically). Replace the retired Log Analytics agent (MMA/OMS) with the Azure Monitor agent where monitoring data is needed. (MCSB ES-1, LT-1)' `
    -Reference 'https://learn.microsoft.com/azure/defender-for-cloud/integration-defender-for-endpoint' `
    -Test {
    $vms = @(Get-TRAzVms | Where-Object { $_.Running })
    if (-not $vms.Count) { return New-TRResult Info 'No running Azure virtual machines were found.' }
    $mdeNames = Get-TRAzDefenderNames
    $no = @($vms | Where-Object { -not $_.Mde -and -not $mdeNames[([string]$_.Name).ToLower()] })
    $mma = @($vms | Where-Object { $_.Mma })
    $aff = @($vms | Where-Object { $no -contains $_ -or $mma -contains $_ } | ForEach-Object { $g = @(); if ($no -contains $_) { $g += 'no Defender for Endpoint' }; if ($_.Mma) { $g += 'retired Log Analytics agent installed' }; New-TRAffected ('{0} ({1})' -f $_.Name, (Get-TRAzSubName $_.SubscriptionId)) ('{0}; {1}' -f $_.Os, ($g -join ', ')) })
    if ($no.Count) { return New-TRResult Fail ('{0} of {1} running servers {2} not onboarded to Defender for Endpoint.' -f $no.Count, $vms.Count, (Select-TRText $no.Count 'is' 'are')) $aff }
    if ($mma.Count) { return New-TRResult Warning ('All running servers have Defender for Endpoint, but {0} still {1} the retired Log Analytics agent.' -f (Format-TRN $mma.Count 'server' 'servers'), (Select-TRText $mma.Count 'has' 'have')) $aff }
    New-TRResult Pass ('All {0} are onboarded to Defender for Endpoint.' -f (Format-TRN $vms.Count 'running server'))
}

Register-TRCheck -Id 'AZ-14' -Area 'Azure' -Category 'Azure security' -Severity Low -Effort 2 `
    -Title 'Virtual machines use Trusted Launch' `
    -Needs 'AzVms' `
    -Recommendation 'Use Trusted Launch (Secure Boot and vTPM) for new virtual machines and upgrade existing Generation 2 machines, so boot-level malware is blocked and BitLocker and Credential Guard can use a TPM. (MCSB PV-3)' `
    -Reference 'https://learn.microsoft.com/azure/virtual-machines/trusted-launch-existing-vm' `
    -Test {
    $vms = @(Get-TRAzVms)
    if (-not $vms.Count) { return New-TRResult Info 'No Azure virtual machines were found.' }
    $std = @($vms | Where-Object { $_.SecurityType -notin @('TrustedLaunch', 'ConfidentialVM') })
    if (-not $std.Count) { return New-TRResult Pass 'All virtual machines use Trusted Launch or confidential computing.' }
    New-TRResult Warning ('{0} of {1} virtual machines {2} not use Trusted Launch.' -f $std.Count, $vms.Count, (Select-TRText $std.Count 'does' 'do')) @($std | ForEach-Object { New-TRAffected ('{0} ({1})' -f $_.Name, (Get-TRAzSubName $_.SubscriptionId)) ('{0}; {1}' -f $_.Size, $_.Os) })
}

Register-TRCheck -Id 'AZ-15' -Area 'Azure' -Category 'Azure security' -Severity High -Effort 2 `
    -Title 'Storage accounts block public access and require TLS 1.2' `
    -Needs 'AzStorage' `
    -Recommendation 'On every storage account, turn off anonymous blob access, require secure transfer with TLS 1.2 or later, restrict network access to selected networks or private endpoints, and disable shared key access where applications support Entra ID authentication. (MCSB NS-2, DP-3, IM-1)' `
    -Reference 'https://learn.microsoft.com/azure/storage/common/security-recommendations' `
    -Test {
    $st = @(Get-TRItems 'AzStorage')
    if (-not $st.Count) { return New-TRResult Info 'No storage accounts were found.' }
    $hard = @(); $soft = @()
    foreach ($s in $st) {
        $h = @(); $w = @()
        if (Test-TRAzTrue $s.allowBlobPublicAccess) { $h += 'anonymous blob access allowed' }
        if ([string]$s.minimumTlsVersion -in @('TLS1_0', 'TLS1_1')) { $h += ('minimum ' + ($s.minimumTlsVersion -replace '_', '.')) }
        if ([string]$s.httpsOnly -eq 'false') { $h += 'HTTP allowed' }
        if ([string]$s.publicNetworkAccess -ne 'Disabled' -and [string]$s.defaultAction -ne 'Deny') { $w += 'open to all networks' }
        if ([string]$s.allowSharedKeyAccess -ne 'false') { $w += 'shared key access allowed' }
        if ($h.Count) { $hard += (New-TRAzAffected $s (($h + $w) -join ', ')) } elseif ($w.Count) { $soft += (New-TRAzAffected $s ($w -join ', ')) }
    }
    if ($hard.Count) { return New-TRResult Fail ('{0} of {1} storage accounts {2} anonymous access, HTTP or old TLS.' -f $hard.Count, $st.Count, (Select-TRText $hard.Count 'allows' 'allow')) @($hard + $soft) }
    if ($soft.Count) { return New-TRResult Warning ('{0} of {1} storage accounts {2} open to all networks or {3} shared key access.' -f $soft.Count, $st.Count, (Select-TRText $soft.Count 'is' 'are'), (Select-TRText $soft.Count 'allows' 'allow')) $soft }
    New-TRResult Pass ('All {0} are locked down.' -f (Format-TRN $st.Count 'storage account'))
}

Register-TRCheck -Id 'AZ-16' -Area 'Azure' -Category 'Azure security' -Severity Medium -Effort 1 `
    -Title 'Key vaults have purge protection and restricted network access' `
    -Needs 'AzKeyVaults' `
    -Recommendation 'Turn on purge protection, use the Azure RBAC permission model rather than access policies, and restrict network access to selected networks or private endpoints. (MCSB DP-8)' `
    -Reference 'https://learn.microsoft.com/azure/key-vault/general/security-features' `
    -Test {
    $kv = @(Get-TRItems 'AzKeyVaults')
    if (-not $kv.Count) { return New-TRResult Info 'No key vaults were found.' }
    $aff = @()
    foreach ($k in $kv) {
        $g = @()
        if (-not (Test-TRAzTrue $k.purgeProtection)) { $g += 'purge protection off' }
        if ([string]$k.softDelete -eq 'false') { $g += 'soft delete off' }
        if (-not (Test-TRAzTrue $k.rbac)) { $g += 'access policies instead of RBAC' }
        if ([string]$k.publicNetworkAccess -ne 'Disabled' -and [string]$k.defaultAction -ne 'Deny') { $g += 'open to all networks' }
        if ($g.Count) { $aff += (New-TRAzAffected $k ($g -join ', ')) }
    }
    if (-not $aff.Count) { return New-TRResult Pass ('All {0} are protected.' -f (Format-TRN $kv.Count 'key vault')) }
    New-TRResult Warning ('{0} of {1} key vaults {2} gaps.' -f $aff.Count, $kv.Count, (Select-TRText $aff.Count 'has' 'have')) $aff
}

Register-TRCheck -Id 'AZ-17' -Area 'Azure' -Category 'Azure security' -Severity High -Effort 2 `
    -Title 'Azure SQL servers use Entra authentication, TLS 1.2 and private access' `
    -Needs 'AzSqlServers' `
    -Recommendation 'Require TLS 1.2, switch to Microsoft Entra-only authentication, and disable public network access in favour of private endpoints (or limit firewall rules to known addresses). Turn on auditing and Defender for SQL. (MCSB IM-1, NS-2, DP-3)' `
    -Reference 'https://learn.microsoft.com/azure/azure-sql/database/security-best-practice' `
    -Test {
    $sql = @(Get-TRItems 'AzSqlServers')
    if (-not $sql.Count) { return New-TRResult Info 'No Azure SQL servers were found.' }
    $hard = @(); $soft = @()
    foreach ($s in $sql) {
        $h = @(); $w = @()
        if ([string]$s.minimalTlsVersion -in @('1.0', '1.1', 'None', '')) { $h += ('minimum TLS ' + $(if ($s.minimalTlsVersion) { $s.minimalTlsVersion } else { 'not set' })) }
        if (-not (Test-TRAzTrue $s.entraOnly)) { $w += 'SQL authentication allowed' }
        if ([string]$s.publicNetworkAccess -ne 'Disabled') { $w += 'public network access on' }
        if ($h.Count) { $hard += (New-TRAzAffected $s (($h + $w) -join ', ')) } elseif ($w.Count) { $soft += (New-TRAzAffected $s ($w -join ', ')) }
    }
    if ($hard.Count) { return New-TRResult Fail ('{0} of {1} SQL servers {2} old TLS versions.' -f $hard.Count, $sql.Count, (Select-TRText $hard.Count 'accepts' 'accept')) @($hard + $soft) }
    if ($soft.Count) { return New-TRResult Warning ('{0} of {1} SQL servers {2} SQL authentication or public network access.' -f $soft.Count, $sql.Count, (Select-TRText $soft.Count 'allows' 'allow')) $soft }
    New-TRResult Pass ('All {0} are locked down.' -f (Format-TRN $sql.Count 'SQL server'))
}

Register-TRCheck -Id 'AZ-18' -Area 'Azure' -Category 'Azure security' -Severity Medium -Effort 1 `
    -Title 'App Service apps enforce HTTPS and TLS 1.2' `
    -Needs 'AzWebApps' `
    -Recommendation 'Turn on HTTPS Only, set the minimum TLS version to 1.2, and set FTP to FTPS only or disabled on every App Service app and function app. (MCSB DP-3)' `
    -Reference 'https://learn.microsoft.com/azure/app-service/overview-security' `
    -Test {
    $apps = @(Get-TRItems 'AzWebApps')
    if (-not $apps.Count) { return New-TRResult Info 'No App Service apps were found.' }
    $aff = @()
    foreach ($a in $apps) {
        $g = @()
        if ([string]$a.httpsOnly -ne 'true') { $g += 'HTTP allowed' }
        if ([string]$a.minTlsVersion -in @('1.0', '1.1')) { $g += ('minimum TLS ' + $a.minTlsVersion) }
        if ([string]$a.ftpsState -eq 'AllAllowed') { $g += 'plain FTP allowed' }
        if ($g.Count) { $aff += (New-TRAzAffected $a ($g -join ', ')) }
    }
    if (-not $aff.Count) { return New-TRResult Pass ('All {0} enforce HTTPS.' -f (Format-TRN $apps.Count 'app')) }
    New-TRResult $(if (@($aff | Where-Object { $_.Detail -match 'HTTP allowed|TLS' }).Count) { 'Fail' } else { 'Warning' }) ('{0} of {1} apps {2} HTTP, old TLS or plain FTP.' -f $aff.Count, $apps.Count, (Select-TRText $aff.Count 'allows' 'allow')) $aff
}

Register-TRCheck -Id 'AZ-19' -Area 'Azure' -Category 'Azure governance and cost' -Severity High -Effort 2 `
    -Title 'Subscription owners are limited and not guests' `
    -Needs 'AzRoleAssignments', 'AzPrincipals' `
    -Recommendation 'Keep subscription Owner and User Access Administrator to two or three named admins through groups, make them eligible through Privileged Identity Management rather than permanent, remove guests and unused service principals, and review the CSP partner access. (MCSB PA-1, PA-7)' `
    -Reference 'https://learn.microsoft.com/azure/role-based-access-control/best-practices' `
    -Test {
    $priv = @('Owner', 'User Access Administrator', 'Role Based Access Control Administrator')
    $rows = @()
    foreach ($a in (Get-TRItems 'AzRoleAssignments')) {
        $scope = [string]$a.scope
        if ($scope -notmatch '^/subscriptions/[^/]+$' -and $scope -notmatch '^/providers/microsoft\.management/managementgroups/' -and $scope -ne '/') { continue }
        $role = Get-TRAzRoleName $a.roleDefinitionId
        if ($priv -notcontains $role) { continue }
        $p = Get-TRAzPrincipal $a.principalId
        $name = if ($p) { if ($p.userPrincipalName) { $p.userPrincipalName } else { $p.displayName } } elseif ([string]$a.principalType -eq 'ForeignGroup') { 'CSP partner admin agents' } else { [string]$a.principalId }
        $rows += [pscustomobject]@{ Name = $name; Role = $role; Type = [string]$a.principalType; Guest = ($p -and [string]$p.userType -eq 'Guest'); Scope = $(if ($scope -match '^/subscriptions/([^/]+)$') { Get-TRAzSubName $Matches[1] } else { 'Management group ' + ($scope -split '/')[-1] }) }
    }
    if (-not $rows.Count) { return New-TRResult Info 'No Owner or User Access Administrator assignments were returned at subscription level.' }
    $guests = @($rows | Where-Object { $_.Guest })
    $users = @($rows | Where-Object { $_.Type -eq 'User' })
    $sps = @($rows | Where-Object { $_.Type -eq 'ServicePrincipal' })
    $aff = @($rows | Sort-Object Scope, Role, Name | ForEach-Object { New-TRAffected $_.Name ('{0} on {1}; {2}{3}' -f $_.Role, $_.Scope, $_.Type, $(if ($_.Guest) { ' (guest)' } else { '' })) })
    $perScope = @($rows | Where-Object { $_.Type -eq 'User' } | Group-Object Scope | Where-Object { $_.Count -gt 3 })
    $text = '{0} privileged role assignments at subscription or management group level ({1} to users directly, {2} to service principals, {3} to guests).' -f $rows.Count, $users.Count, $sps.Count, $guests.Count
    if ($guests.Count) { return New-TRResult Fail $text $aff }
    if ($perScope.Count -or $sps.Count) { return New-TRResult Warning $text $aff }
    New-TRResult Pass $text $aff
}

Register-TRCheck -Id 'AZ-20' -Area 'Azure' -Category 'Azure governance and cost' -Severity Low -Effort 1 `
    -Title 'Critical resources have delete locks' `
    -Needs 'AzLocks', 'AzRecoveryVaults', 'AzKeyVaults' `
    -Recommendation 'Add CanNotDelete locks to Recovery Services vaults, key vaults and other resources whose loss would be hard to recover from, so they cannot be deleted by mistake or by a compromised account.' `
    -Reference 'https://learn.microsoft.com/azure/azure-resource-manager/management/lock-resources' `
    -Test {
    $scopes = @(Get-TRItems 'AzLocks' | ForEach-Object { (([string]$_.id).ToLower() -split '/providers/microsoft\.authorization/locks/')[0] })
    $crit = @(@(Get-TRItems 'AzRecoveryVaults') + @(Get-TRItems 'AzKeyVaults'))
    if (-not $crit.Count) { return New-TRResult Info 'No Recovery Services vaults or key vaults were found.' }
    $bad = @($crit | Where-Object { $rid = ([string]$_.id).ToLower(); -not @($scopes | Where-Object { $_ -and $rid.StartsWith($_) }).Count })
    if (-not $bad.Count) { return New-TRResult Pass ('All {0} are protected by a lock.' -f (Format-TRN $crit.Count 'vault')) }
    New-TRResult Warning ('{0} of {1} vaults {2} no delete lock.' -f $bad.Count, $crit.Count, (Select-TRText $bad.Count 'has' 'have')) @($bad | ForEach-Object { New-TRAzAffected $_ $(if ([string]$_.id -match 'keyvault') { 'Key vault' } else { 'Recovery Services vault' }) })
}

Register-TRCheck -Id 'AZ-21' -Area 'Azure' -Category 'Azure governance and cost' -Severity Medium -Effort 1 `
    -Title 'The Azure activity log is kept beyond 90 days' `
    -Needs 'AzActivityLogSettings', 'AzSubscriptions' `
    -Recommendation 'Send each subscription''s activity log (administrative, security, policy and alert categories) to a Log Analytics workspace or storage account with at least one year of retention, so changes can be investigated after the 90-day default. (MCSB LT-3, LT-6)' `
    -Reference 'https://learn.microsoft.com/azure/azure-monitor/essentials/activity-log' `
    -Test {
    $have = @{}
    foreach ($d in (Get-TRItems 'AzActivityLogSettings')) { $have[[string]$d.subscriptionId] = $true }
    $bad = @(Get-TRItems 'AzSubscriptions' | Where-Object { $_.state -eq 'Enabled' -and -not $have[[string]$_.subscriptionId] })
    if (-not $bad.Count) { return New-TRResult Pass 'Every subscription exports its activity log.' }
    New-TRResult Warning ('{0} not export the activity log, so changes are only kept for 90 days.' -f (Format-TRN $bad.Count 'subscription does' 'subscriptions do')) @($bad | ForEach-Object { New-TRAffected $_.displayName 'No diagnostic setting for the activity log' })
}

Register-TRCheck -Id 'AZ-22' -Area 'Azure' -Category 'Azure governance and cost' -Severity Low -Effort 1 `
    -Title 'No unattached disks or unused public IP addresses' `
    -Needs 'AzDisks', 'AzPublicIps' `
    -Recommendation 'Delete unattached managed disks and public IP addresses that are no longer needed (take a snapshot first if in doubt). They are charged whether or not they are used.' `
    -Reference 'https://learn.microsoft.com/azure/virtual-machines/disks-find-unattached-portal' `
    -Test {
    $disks = @(Get-TRItems 'AzDisks' | Where-Object { [string]$_.diskState -eq 'Unattached' })
    $ips = @(Get-TRItems 'AzPublicIps' | Where-Object { -not $_.attachedTo })
    if (-not $disks.Count -and -not $ips.Count) { return New-TRResult Pass 'No unattached disks or unused public IP addresses.' }
    $gb = ($disks | Measure-Object -Property sizeGb -Sum).Sum
    New-TRResult Warning ('{0} ({1} GB) and {2} are not attached to anything.' -f (Format-TRN $disks.Count 'managed disk'), [int]$gb, (Format-TRN $ips.Count 'public IP address' 'public IP addresses')) (@($disks | ForEach-Object { New-TRAzAffected $_ ('Disk {0} GB {1}; created {2}' -f $_.sizeGb, $_.sku, (Format-TRDate $_.timeCreated)) }) + @($ips | ForEach-Object { New-TRAzAffected $_ ('Public IP {0} ({1})' -f $_.ipAddress, $_.sku) }))
}

Register-TRCheck -Id 'AZ-23' -Area 'Azure' -Category 'Azure governance and cost' -Severity Low -Effort 2 `
    -Title 'Azure Advisor cost recommendations' `
    -Needs 'AzAdvisor' `
    -Recommendation 'Review the Azure Advisor cost recommendations with the client: right-size or shut down under-used virtual machines, buy reservations or savings plans for steady workloads, and apply Azure Hybrid Benefit where Windows Server and SQL licences allow.' `
    -Reference 'https://learn.microsoft.com/azure/advisor/advisor-cost-recommendations' `
    -Test {
    $c = @(Get-TRItems 'AzAdvisor' | Where-Object { [string]$_.category -eq 'Cost' })
    if (-not $c.Count) { return New-TRResult Pass 'Azure Advisor has no cost recommendations.' }
    $sum = ($c | Measure-Object -Property annualSavings -Sum).Sum
    $cur = @($c | Where-Object { $_.currency } | Select-Object -ExpandProperty currency -Unique)[0]
    $text = '{0}' -f (Format-TRN $c.Count 'cost recommendation')
    if ($sum -gt 0) { $text += (' with potential savings of about {0} {1:N0} a year' -f $cur, $sum) }
    New-TRResult Warning ($text + '.') @($c | Sort-Object { -[double]$_.annualSavings } | ForEach-Object { $sn = Get-TRAzSubName $_.subscriptionId; New-TRAffected $(if ([string]$_.resource -eq $sn) { $sn } else { '{0} ({1})' -f $_.resource, $sn }) ('{0}{1}' -f $_.problem, $(if ([double]$_.annualSavings -gt 0) { '. Saves about {0} {1:N0} a year.' -f $_.currency, [double]$_.annualSavings } else { '' })) })
}

Register-TRCheck -Id 'AZ-24' -Area 'Azure' -Category 'Azure resilience' -Severity Medium -Effort 4 `
    -Title 'High-impact Azure Advisor recommendations' `
    -Needs 'AzAdvisor' `
    -Recommendation 'Work through the high-impact Azure Advisor recommendations for reliability, security and operational excellence.' `
    -Reference 'https://learn.microsoft.com/azure/advisor/advisor-overview' `
    -Test {
    $h = @(Get-TRItems 'AzAdvisor' | Where-Object { [string]$_.category -ne 'Cost' -and [string]$_.impact -eq 'High' })
    if (-not $h.Count) { return New-TRResult Pass 'Azure Advisor has no high-impact reliability, security or operational recommendations.' }
    $byCat = @($h | Group-Object category | ForEach-Object { '{0} {1}' -f $_.Count, $(switch ($_.Name) { 'HighAvailability' { 'reliability' } 'OperationalExcellence' { 'operational excellence' } default { ([string]$_).ToLower() } }) })
    New-TRResult Warning ('{0} ({1}).' -f (Format-TRN $h.Count 'high-impact recommendation'), ($byCat -join ', ')) @($h | ForEach-Object { New-TRAffected ('{0} ({1})' -f $_.resource, (Get-TRAzSubName $_.subscriptionId)) ('{0}: {1}' -f $_.category, $_.problem) })
}

Register-TRCheck -Id 'AZ-25' -Area 'Azure' -Category 'Azure governance and cost' -Severity Low -Effort 0.5 `
    -Title 'Every subscription has a budget alert' `
    -Needs 'AzBudgets', 'AzSubscriptions' `
    -Recommendation 'Create a monthly budget on each subscription with email alerts at 80% and 100% of forecast and actual spend, sent to the client and their IT provider, so unexpected costs are caught early.' `
    -Reference 'https://learn.microsoft.com/azure/cost-management-billing/costs/tutorial-acm-create-budgets' `
    -Test {
    $have = @{}
    foreach ($b in (Get-TRItems 'AzBudgets')) { $have[[string]$b.subscriptionId] = $true }
    $bad = @(Get-TRItems 'AzSubscriptions' | Where-Object { $_.state -eq 'Enabled' -and -not $have[[string]$_.subscriptionId] })
    if (-not $bad.Count) { return New-TRResult Pass 'Every subscription has a budget.' }
    New-TRResult Warning ('{0} no budget.' -f (Format-TRN $bad.Count 'subscription has' 'subscriptions have')) @($bad | ForEach-Object { New-TRAffected $_.displayName $_.offer })
}

Register-TRCheck -Id 'AZ-26' -Area 'Azure' -Category 'Azure governance and cost' -Severity Low -Effort 1 `
    -Title 'The Microsoft cloud security benchmark policy is assigned' `
    -Needs 'AzPolicyAssignments', 'AzSubscriptions' `
    -Recommendation 'Keep the Microsoft cloud security benchmark initiative (the Defender for Cloud default policy) assigned to every subscription or the management group above them, so Defender for Cloud can assess the resources.' `
    -Reference 'https://learn.microsoft.com/azure/defender-for-cloud/security-policy-concept' `
    -Test {
    $mcsb = @(Get-TRItems 'AzPolicyAssignments' | Where-Object { [string]$_.policyDefinitionId -match '1f3afdf9-d0c9-4c3d-847f-89da613e70a8' })
    $mg = @($mcsb | Where-Object { [string]$_.scope -match 'managementgroups' })
    $covered = @{}
    foreach ($a in $mcsb) { if ([string]$a.scope -match '^/subscriptions/([^/]+)$') { $covered[$Matches[1]] = $true } }
    $bad = @(Get-TRItems 'AzSubscriptions' | Where-Object { $_.state -eq 'Enabled' -and -not $covered[([string]$_.subscriptionId).ToLower()] -and -not $covered[[string]$_.subscriptionId] })
    if ($mg.Count -or -not $bad.Count) { return New-TRResult Pass 'The Microsoft cloud security benchmark initiative is assigned.' }
    New-TRResult Warning ('{0} not have the Microsoft cloud security benchmark initiative assigned.' -f (Format-TRN $bad.Count 'subscription does' 'subscriptions do')) @($bad | ForEach-Object { New-TRAffected $_.displayName 'Not assigned' })
}

Register-TRCheck -Id 'AZ-27' -Area 'Azure' -Category 'Azure governance and cost' -Severity Low -Effort 0.5 `
    -Title 'Network Watcher is enabled where networks exist' `
    -Needs 'AzVnets', 'AzNetworkWatchers' `
    -Recommendation 'Make sure Network Watcher is enabled in every region that has virtual networks, and turn on virtual network flow logs for production networks. (MCSB LT-4)' `
    -Reference 'https://learn.microsoft.com/azure/network-watcher/network-watcher-create' `
    -Test {
    $nw = @{}
    foreach ($w in (Get-TRItems 'AzNetworkWatchers')) { $nw[('{0}|{1}' -f $w.subscriptionId, $w.location)] = $true }
    $need = @(Get-TRItems 'AzVnets' | ForEach-Object { '{0}|{1}' -f $_.subscriptionId, $_.location } | Select-Object -Unique)
    if (-not $need.Count) { return New-TRResult Info 'No virtual networks were found.' }
    $bad = @($need | Where-Object { -not $nw[$_] })
    if (-not $bad.Count) { return New-TRResult Pass 'Network Watcher is enabled in every region with a virtual network.' }
    New-TRResult Warning ('Network Watcher is missing in {0}.' -f (Format-TRN $bad.Count 'region')) @($bad | ForEach-Object { $p = $_ -split '\|'; New-TRAffected (Get-TRAzSubName $p[0]) $p[1] })
}

Register-TRCheck -Id 'AZ-28' -Area 'Azure' -Category 'Azure security' -Severity Medium -Effort 3 `
    -Title 'Servers have no outstanding critical or security updates' `
    -Needs 'AzVms', 'AzPatchAssessments' `
    -Recommendation 'Install outstanding critical and security updates, and make sure every server is covered by one patching tool (the RMM or Azure Update Manager, not both). Turn on periodic assessment in Azure Update Manager so missing updates are visible. (MCSB PV-6)' `
    -Reference 'https://learn.microsoft.com/azure/update-manager/overview' `
    -Test {
    $vms = @(Get-TRAzVms | Where-Object { $_.Running })
    if (-not $vms.Count) { return New-TRResult Info 'No running Azure virtual machines were found.' }
    $assessed = @($vms | Where-Object { $_.Patch })
    $behind = @($assessed | Where-Object { [int]$_.Patch.critical + [int]$_.Patch.security -gt 0 })
    $rmm = [bool](Get-TRSetting 'PatchingViaRmm' $true)
    if (-not $assessed.Count) { return New-TRResult Info ('Azure Update Manager has no assessment for the {0}.{1}' -f (Format-TRN $vms.Count 'running server'), $(if ($rmm) { ' Patching is expected through the RMM; check its patch report.' } else { '' })) }
    if ($behind.Count) { return New-TRResult Warning ('{0} of {1} assessed servers {2} missing critical or security updates.' -f $behind.Count, $assessed.Count, (Select-TRText $behind.Count 'is' 'are')) @($behind | ForEach-Object { New-TRAffected ('{0} ({1})' -f $_.Name, (Get-TRAzSubName $_.SubscriptionId)) ('{0} critical, {1} security; assessed {2}' -f [int]$_.Patch.critical, [int]$_.Patch.security, (Format-TRDate $_.Patch.lastModified)) }) }
    New-TRResult Pass ('All {0} have no outstanding critical or security updates.' -f (Format-TRN $assessed.Count 'assessed server'))
}

Register-TRCheck -Id 'AZ-29' -Area 'Azure' -Category 'Azure resilience' -Severity Medium -Effort 1 `
    -Title 'Azure Arc servers are connected' `
    -Needs 'AzArcMachines' `
    -Recommendation 'Reconnect or remove Azure Arc servers that are disconnected or expired, so Defender for Servers, Update Manager and extended security updates keep working on them.' `
    -Reference 'https://learn.microsoft.com/azure/azure-arc/servers/troubleshoot-agent-onboard' `
    -Test {
    $arc = @(Get-TRItems 'AzArcMachines')
    if (-not $arc.Count) { return New-TRResult Info 'No Azure Arc servers were found.' }
    $bad = @($arc | Where-Object { [string]$_.status -ne 'Connected' })
    if (-not $bad.Count) { return New-TRResult Pass ('All {0} are connected.' -f (Format-TRN $arc.Count 'Arc server')) }
    New-TRResult Warning ('{0} of {1} Arc servers {2} not connected.' -f $bad.Count, $arc.Count, (Select-TRText $bad.Count 'is' 'are')) @($bad | ForEach-Object { New-TRAzAffected $_ ('{0}; status {1} since {2}' -f $_.osName, $_.status, (Format-TRDate $_.lastStatusChange)) })
}

function Add-TRAzureInventories {
    param($Inv)
    if (-not (Test-TRCollected @('AzSubscriptions'))) { return }
    $counts = @{}
    foreach ($r in (Get-TRItems 'AzResourceCounts')) { $counts[[string]$r.subscriptionId] += [int]$r.count }
    $score = @{}
    foreach ($s in (Get-TRItems 'AzSecureScores')) { $score[[string]$s.subscriptionId] = $s }
    $reg = @{}
    foreach ($r in (Get-TRItems 'AzRegulatory' | Where-Object { [string]$_.standard -match 'Microsoft-cloud-security-benchmark' })) { $reg[[string]$r.subscriptionId] = $r }
    $plans = @{}
    foreach ($p in (Get-TRItems 'AzDefenderPlans' | Where-Object { [string]$_.properties.pricingTier -eq 'Standard' })) { $plans[[string]$p.subscriptionId] += @([string]$p.name) }
    $rows = foreach ($s in (Get-TRItems 'AzSubscriptions' | Sort-Object displayName)) {
        $sc = $score[[string]$s.subscriptionId]
        $rg = $reg[[string]$s.subscriptionId]
        [pscustomobject][ordered]@{
            'Subscription'   = $s.displayName
            'ID'             = $s.subscriptionId
            'Offer'          = $s.offer
            'State'          = $s.state
            'Access'         = $s.authorizationSource
            'Resources'      = [int]$counts[[string]$s.subscriptionId]
            'Secure score'   = $(if ($sc) { '{0}%' -f [Math]::Round(100 * [double]$sc.percentage) } else { '' })
            'MCSB controls'  = $(if ($rg) { '{0} passed, {1} failed' -f $rg.passed, $rg.failed } else { '' })
            'Defender plans' = (@($plans[[string]$s.subscriptionId]) -join ', ')
        }
    }
    Add-TRInventory $Inv 'AzSubscriptions' 'Azure subscriptions' 'Azure subscriptions visible to the review account, with Defender for Cloud secure score, MCSB compliance and the Defender plans that are on.' $rows
    if (Test-TRCollected @('AzVms')) {
        $rows = foreach ($v in (Get-TRAzVms | Sort-Object SubscriptionId, Name)) {
            [pscustomobject][ordered]@{
                'VM'             = $v.Name
                'Subscription'   = (Get-TRAzSubName $v.SubscriptionId)
                'Resource group' = $v.ResourceGroup
                'Location'       = $v.Location
                'Size'           = $v.Size
                'OS'             = $v.Os
                'OS support'     = $(if ($v.Support) { switch ($v.Support.State) { 'Ended' { 'Ended ' + (Format-TRDate $v.Support.End) } 'Esu' { 'ESU until ' + (Format-TRDate $v.Support.Esu) } default { 'Until ' + (Format-TRDate $v.Support.End) } } } else { '' })
                'Power'          = $v.PowerState
                'Public IP'      = ConvertTo-TRYesNo $v.PublicIp
                'NSG'            = ConvertTo-TRYesNo $v.Nsg
                'Defender for Endpoint' = ConvertTo-TRYesNo $v.Mde
                'Backed up'      = $(if ($v.Backup) { 'Yes, last ' + (Format-TRDate $v.Backup.lastBackup) } else { 'No' })
                'Missing updates' = $(if ($v.Patch) { '{0} critical, {1} security' -f [int]$v.Patch.critical, [int]$v.Patch.security } else { '' })
                'Trusted Launch' = ConvertTo-TRYesNo ($v.SecurityType -in @('TrustedLaunch', 'ConfidentialVM'))
                'Hybrid Benefit' = $(if ($v.LicenseType) { $v.LicenseType } else { 'No' })
            }
        }
        Add-TRInventory $Inv 'AzVms' 'Azure virtual machines' 'Azure virtual machines with OS support, exposure, Defender, backup and patch status.' $rows
    }
    if (Test-TRCollected @('AzNsgRules')) {
        $attached = Get-TRAzNsgAttached
        $rows = foreach ($r in (Get-TRItems 'AzNsgRules' | Where-Object { Test-TRAzInternetSource $_.source $_.sources } | Sort-Object nsg, priority)) {
            [pscustomobject][ordered]@{ 'NSG' = $r.nsg; 'Subscription' = (Get-TRAzSubName $r.subscriptionId); 'Rule' = $r.rule; 'Priority' = $r.priority; 'Protocol' = $r.protocol; 'Ports' = $(if ($r.port) { $r.port } else { $r.ports }); 'Source' = $(if ($r.source) { $r.source } else { $r.sources }); 'Attached' = ConvertTo-TRYesNo ([bool]$attached[[string]$r.nsgId]) }
        }
        Add-TRInventory $Inv 'AzInternetRules' 'Azure inbound internet rules' 'Network security group rules that allow inbound traffic from any address or the internet.' $rows
    }
    if (Test-TRCollected @('AzStorage')) {
        $rows = foreach ($s in (Get-TRItems 'AzStorage' | Sort-Object name)) {
            [pscustomobject][ordered]@{ 'Storage account' = $s.name; 'Subscription' = (Get-TRAzSubName $s.subscriptionId); 'Kind' = $s.kind; 'SKU' = $s.sku; 'Anonymous blob access' = $s.allowBlobPublicAccess; 'Minimum TLS' = $s.minimumTlsVersion; 'HTTPS only' = $s.httpsOnly; 'Shared key' = $s.allowSharedKeyAccess; 'Public network' = $s.publicNetworkAccess; 'Default action' = $s.defaultAction }
        }
        Add-TRInventory $Inv 'AzStorage' 'Azure storage accounts' 'Storage accounts and their access settings.' $rows
    }
    if (Test-TRCollected @('AzRoleAssignments')) {
        $rows = foreach ($a in (Get-TRItems 'AzRoleAssignments')) {
            $scope = [string]$a.scope
            if ($scope -notmatch '^/subscriptions/[^/]+$' -and $scope -notmatch '^/subscriptions/[^/]+/resourcegroups/[^/]+$' -and $scope -notmatch 'managementgroups') { continue }
            $p = Get-TRAzPrincipal $a.principalId
            [pscustomobject][ordered]@{
                'Principal' = $(if ($p) { if ($p.userPrincipalName) { $p.userPrincipalName } else { $p.displayName } } elseif ([string]$a.principalType -eq 'ForeignGroup') { 'CSP partner admin agents' } else { $a.principalId })
                'Type'      = $a.principalType
                'Guest'     = ConvertTo-TRYesNo ($p -and [string]$p.userType -eq 'Guest')
                'Role'      = (Get-TRAzRoleName $a.roleDefinitionId)
                'Scope'     = $(if ($scope -match '^/subscriptions/([^/]+)(/resourcegroups/([^/]+))?$') { (Get-TRAzSubName $Matches[1]) + $(if ($Matches[3]) { ' / ' + $Matches[3] } else { '' }) } else { $scope })
                'Created'   = (Format-TRDate $a.createdOn)
            }
        }
        Add-TRInventory $Inv 'AzRoles' 'Azure role assignments' 'Azure RBAC role assignments at management group, subscription and resource group level.' ($rows | Sort-Object Scope, Role, Principal)
    }
    if (Test-TRCollected @('AzSecurityAssessments')) {
        $rows = foreach ($r in (Get-TRItems 'AzSecurityAssessments' | Sort-Object @{ e = { @{ High = 0; Medium = 1; Low = 2 }[[string]$_.severity] } }, @{ e = { -[int]$_.resources } })) {
            [pscustomobject][ordered]@{ 'Recommendation' = $r.recommendation; 'Severity' = $r.severity; 'Unhealthy resources' = $r.resources; 'Subscription' = (Get-TRAzSubName $r.subscriptionId) }
        }
        Add-TRInventory $Inv 'AzRecommendations' 'Defender for Cloud recommendations' 'Defender for Cloud recommendations with unhealthy resources, highest severity first.' $rows
    }
    if (Test-TRCollected @('AzAdvisor')) {
        $rows = foreach ($r in (Get-TRItems 'AzAdvisor' | Sort-Object category, @{ e = { -[double]$_.annualSavings } })) {
            [pscustomobject][ordered]@{ 'Category' = $r.category; 'Impact' = $r.impact; 'Resource' = $r.resource; 'Problem' = $r.problem; 'Solution' = $r.solution; 'Annual savings' = $(if ([double]$r.annualSavings -gt 0) { '{0} {1:N0}' -f $r.currency, [double]$r.annualSavings } else { '' }); 'Subscription' = (Get-TRAzSubName $r.subscriptionId) }
        }
        Add-TRInventory $Inv 'AzAdvisor' 'Azure Advisor' 'Azure Advisor recommendations for cost, reliability, security, performance and operational excellence.' $rows
    }
    if (Test-TRCollected @('AzResourceCounts')) {
        $rows = foreach ($g in (Get-TRItems 'AzResourceCounts' | Group-Object type | Sort-Object { -(($_.Group | Measure-Object -Property count -Sum).Sum) })) {
            [pscustomobject][ordered]@{ 'Resource type' = $g.Name; 'Count' = ($g.Group | Measure-Object -Property count -Sum).Sum; 'Subscriptions' = (Join-TRList (@($g.Group | ForEach-Object { Get-TRAzSubName $_.subscriptionId } | Select-Object -Unique)) 5) }
        }
        Add-TRInventory $Inv 'AzResources' 'Azure resources by type' 'Count of Azure resources by type across the visible subscriptions.' $rows
    }
}
