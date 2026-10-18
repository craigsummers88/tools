$script:TRControls = New-Object System.Collections.ArrayList

$script:TRFrameworkInfoByPlatform = @{
    Microsoft = [ordered]@{
        CIS   = [pscustomobject]@{ Key = 'CIS'; Name = 'CIS Microsoft 365 Foundations Benchmark'; Version = 'v7.0.0'; Short = 'CIS v7.0.0'; Url = 'https://www.cisecurity.org/benchmark/microsoft_365' }
        SCuBA = [pscustomobject]@{ Key = 'SCuBA'; Name = 'CISA SCuBA secure configuration baselines for Microsoft 365'; Version = 'ScubaGear 2.0'; Short = 'CISA SCuBA'; Url = 'https://github.com/cisagov/ScubaGear/tree/main/PowerShell/ScubaGear/baselines' }
    }
    Google    = [ordered]@{
        CIS   = [pscustomobject]@{ Key = 'CIS'; Name = 'CIS Google Workspace Foundations Benchmark'; Version = 'v1.4.0'; Short = 'CIS v1.4.0'; Url = 'https://www.cisecurity.org/benchmark/google_workspace' }
        SCuBA = [pscustomobject]@{ Key = 'SCuBA'; Name = 'CISA SCuBA secure configuration baselines for Google Workspace'; Version = 'ScubaGoggles 1.0'; Short = 'CISA SCuBA'; Url = 'https://github.com/cisagov/ScubaGoggles/tree/main/scubagoggles/baselines' }
    }
}
$script:TRFrameworkInfo = $script:TRFrameworkInfoByPlatform['Microsoft']

function Get-TRFrameworkInfo {
    $p = 'Microsoft'
    try { $p = Get-TRPlatform } catch { }
    $script:TRFrameworkInfoByPlatform[$p]
}

$script:TRGwsCisSections = [ordered]@{
    '1.1'   = 'Directory: users'
    '1.2'   = 'Directory: settings'
    '3.1.1' = 'Calendar'
    '3.1.2' = 'Drive and Docs'
    '3.1.3' = 'Gmail'
    '3.1.4' = 'Google Chat'
    '3.1.6' = 'Groups for Business'
    '3.1.7' = 'Sites'
    '3.1.8' = 'Additional Google services'
    '3.1.9' = 'Google Workspace Marketplace'
    '4.1'   = 'Authentication'
    '4.2'   = 'Access and data control'
    '4.3'   = 'Security centre'
    '5'     = 'Reporting'
    '6'     = 'Alert rules'
}

$script:TRGwsScubaSections = @{
    'ASSUREDCONTROLS' = 'Assured Controls'
    'CALENDAR'        = 'Calendar'
    'CHAT'            = 'Google Chat'
    'CLASSROOM'       = 'Classroom'
    'COMMONCONTROLS'  = 'Common controls'
    'DRIVEDOCS'       = 'Drive and Docs'
    'GEMINI'          = 'Gemini'
    'GMAIL'           = 'Gmail'
    'GROUPS'          = 'Groups for Business'
    'MEET'            = 'Google Meet'
    'SITES'           = 'Sites'
}

$script:TRCisSections = @{
    '1' = 'Microsoft 365 admin centre'
    '2' = 'Microsoft Defender'
    '3' = 'Microsoft Purview'
    '4' = 'Microsoft Intune'
    '5' = 'Microsoft Entra ID'
    '6' = 'Exchange Online'
    '7' = 'SharePoint and OneDrive'
    '8' = 'Microsoft Teams'
    '9' = 'Microsoft Fabric (Power BI)'
}

$script:TRScubaSections = @{
    'AAD'            = 'Microsoft Entra ID'
    'SECURITYSUITE'  = 'Defender and Purview'
    'EXO'            = 'Exchange Online'
    'SHAREPOINT'     = 'SharePoint and OneDrive'
    'TEAMS'          = 'Microsoft Teams'
    'POWERBI'        = 'Power BI'
    'POWERPLATFORM'  = 'Power Platform'
}

$script:TRLicenceNames = @{
    P1                = 'Entra ID P1'
    P2                = 'Entra ID P2'
    Intune            = 'Microsoft Intune'
    DefenderO365      = 'Defender for Office 365'
    DefenderO365P2    = 'Defender for Office 365 Plan 2'
    DefenderEndpoint  = 'Defender for Endpoint or Business'
    DefenderCloudApps = 'Defender for Cloud Apps'
    CustomerLockbox   = 'Customer Lockbox'
    ComplianceE5      = 'Microsoft 365 E5 Compliance'
    Dlp               = 'Data loss prevention'
    EndpointDlp       = 'Endpoint data loss prevention'
    AuditPremium      = 'Audit (Premium)'
    Copilot           = 'Microsoft 365 Copilot'
}

$script:TRCisAdminRoles = [ordered]@{
    '62e90394-69f5-4237-9190-012177145e10' = 'Global Administrator'
    'e8611ab8-c189-46e8-94e1-60213ab1f814' = 'Privileged Role Administrator'
    '7be44c8a-adaf-4e2a-84d6-ab2649e08a13' = 'Privileged Authentication Administrator'
    '194ae4cb-b126-40b2-bd5b-6091b380977d' = 'Security Administrator'
    '29232cdf-9323-42fd-ade2-1d097af3e4de' = 'Exchange Administrator'
    'f28a1f50-f6e7-4571-818b-6a12f2af6b6c' = 'SharePoint Administrator'
    'fe930be7-5e62-47db-91af-98c3a49a38b1' = 'User Administrator'
    'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9' = 'Conditional Access Administrator'
    '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3' = 'Application Administrator'
    '158c047a-c907-4556-b7ef-446551a6b5f7' = 'Cloud Application Administrator'
    'c4e39bd9-1100-46d3-8c65-fb160da0071f' = 'Authentication Administrator'
    '729827e3-9c14-49f7-bb1b-9608f156bbb8' = 'Helpdesk Administrator'
    '966707d0-3269-4727-9be2-8c3a10f19b9d' = 'Password Administrator'
    'b0f54661-2d74-4c50-afa3-1ec803f12efe' = 'Billing Administrator'
}

$script:TRGlobalAdminRole = '62e90394-69f5-4237-9190-012177145e10'
$script:TRPrivRoleAdminRole = 'e8611ab8-c189-46e8-94e1-60213ab1f814'
$script:TRGlobalReaderRole = 'f2ef992c-3afb-46b9-b7cf-a126ee74c451'

function Register-TRControl {
    param(
        [ValidateSet('CIS', 'SCuBA')][string]$Framework,
        [string]$Id,
        [string]$Title,
        [string]$Level,
        [Alias('Profile')][string]$LicenceProfile = '',
        [string[]]$Licence = @(),
        [string[]]$Needs = @(),
        [string[]]$Checks = @(),
        [string[]]$Map = @(),
        [string]$Guidance = '',
        [switch]$ManualOnly,
        [scriptblock]$Test,
        [ValidateSet('Microsoft', 'Google')][string]$Platform = 'Microsoft'
    )
    $section = ''
    if ($Platform -eq 'Google') {
        if ($Framework -eq 'CIS') {
            foreach ($k in $script:TRGwsCisSections.Keys) { if ($Id -eq $k -or $Id.StartsWith($k + '.')) { $section = $script:TRGwsCisSections[$k]; break } }
        }
        else { $section = $script:TRGwsScubaSections[($Id -split '\.')[1]] }
    }
    elseif ($Framework -eq 'CIS') { $section = $script:TRCisSections[($Id -split '\.')[0]] }
    else { $section = $script:TRScubaSections[($Id -split '\.')[1]] }
    [void]$script:TRControls.Add([pscustomobject]@{
            Framework  = $Framework
            Id         = $Id
            Section    = $section
            Title      = $Title
            Level      = $Level
            Profile    = $LicenceProfile
            Licence    = @($Licence)
            Needs      = @($Needs)
            Checks     = @($Checks)
            Map        = @($Map)
            Guidance   = $Guidance
            ManualOnly = [bool]$ManualOnly
            Test       = $Test
            Platform   = $Platform
        })
}

function New-TRCtl {
    param(
        [ValidateSet('Pass', 'Fail', 'Manual', 'NotAssessed', 'NotApplicable')][string]$Status,
        [string]$Evidence,
        $Affected = @()
    )
    [pscustomobject]@{ Status = $Status; Evidence = $Evidence; Affected = @($Affected | Where-Object { $null -ne $_ }) }
}

function Get-TRV {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] }
        foreach ($k in @($Object.Keys)) { if ([string]$k -ieq $Name) { return $Object[$k] } }
        return $null
    }
    if ($Object -is [string] -or $Object -is [ValueType]) { return $null }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    $null
}

function Get-TRPath {
    param($Object, [string]$Path)
    $o = $Object
    foreach ($seg in ($Path -split '\.')) {
        if ($null -eq $o) { return $null }
        $o = Get-TRV $o $seg
    }
    $o
}

function Test-TRTrue { param($Value) ($Value -is [bool] -and $Value) -or ([string]$Value -eq 'True') }
function Test-TRFalse { param($Value) ($Value -is [bool] -and -not $Value) -or ([string]$Value -eq 'False') }

function Get-TRStrings {
    param($Value)
    @(@($Value) | Where-Object { $null -ne $_ -and [string]$_ -ne '' } | ForEach-Object { [string]$_ })
}

function Format-TRN {
    param([int]$N, [string]$One, [string]$Many)
    if ($N -eq 1) { return ('1 ' + $One) }
    if (-not $Many) { $Many = $One + 's' }
    ('{0} {1}' -f $N, $Many)
}

function Select-TRText {
    param([int]$N, [string]$One, [string]$Many)
    if ($N -eq 1) { return $One }
    $Many
}

function Format-TRConsentPolicy {
    param([string]$Id)
    $n = $Id -replace '^ManagePermissionGrantsForSelf\.', ''
    switch -Regex ($n) {
        '^microsoft-user-default-legacy$' { return 'Allow user consent for apps (legacy setting)' }
        '^microsoft-user-default-recommended$' { return 'Let Microsoft manage your consent settings' }
        '^microsoft-user-default-low$' { return 'Allow user consent for apps from verified publishers, for selected permissions' }
        default { return ('custom policy ' + $n) }
    }
}

function Join-TRList {
    param($Items, [int]$Max = 8)
    $list = @(Get-TRStrings $Items)
    if ($list.Count -le $Max) { return ($list -join ', ') }
    (($list | Select-Object -First $Max) -join ', ') + (' and {0} more' -f ($list.Count - $Max))
}

function Get-TRFirstItem {
    param([string]$Key)
    @(Get-TRItems $Key)[0]
}

function Test-TRLicenceAny {
    param([string[]]$Capabilities)
    foreach ($c in $Capabilities) { if (Test-TRLicensed $c) { return $true } }
    $false
}

function Get-TRLicenceText {
    param([string[]]$Capabilities)
    $names = if ((Get-TRPlatform) -eq 'Google') { $script:TRGwsCapabilityNames } else { $script:TRLicenceNames }
    (@($Capabilities | ForEach-Object { if ($names[$_]) { $names[$_] } else { $_ } }) -join ' or ')
}

function Get-TRBlCaKey {
    if (Test-TRCollected @('ConditionalAccessBeta')) { return 'ConditionalAccessBeta' }
    'ConditionalAccessPolicies'
}

function Get-TRBlCaNames {
    param($Policies)
    Join-TRList (@($Policies) | ForEach-Object { [string]$_.displayName }) 5
}

function Test-TRBlAllUsers { param($P) @(Get-TRStrings $P.conditions.users.includeUsers) -contains 'All' }
function Test-TRBlAllApps { param($P) @(Get-TRStrings $P.conditions.applications.includeApplications) -contains 'All' }
function Get-TRBlGrant { param($P) @(Get-TRStrings $P.grantControls.builtInControls) }
function Test-TRBlMfa { param($P) (@(Get-TRBlGrant $P) -contains 'mfa') -or ($null -ne $P.grantControls.authenticationStrength) }
function Test-TRBlBlock { param($P) @(Get-TRBlGrant $P) -contains 'block' }

function Test-TRBlRoles {
    param($P, [string[]]$Roles)
    if (Test-TRBlAllUsers $P) { return $true }
    $inc = @(Get-TRStrings $P.conditions.users.includeRoles)
    foreach ($r in $Roles) { if ($inc -notcontains $r) { return $false } }
    $true
}

function Get-TRBlMissingRoles {
    param($P, $RoleMap)
    if (Test-TRBlAllUsers $P) { return @() }
    $inc = @(Get-TRStrings $P.conditions.users.includeRoles)
    @($RoleMap.Keys | Where-Object { $inc -notcontains $_ } | ForEach-Object { $RoleMap[$_] })
}

function Test-TRBlSignInEveryTime {
    param($P)
    $f = $P.sessionControls.signInFrequency
    $f -and (Test-TRTrue $f.isEnabled) -and ([string]$f.frequencyInterval -eq 'everyTime')
}

function Test-TRBlCaRule {
    param([scriptblock]$Filter, [string]$Requirement)
    $all = @(Get-TRItems (Get-TRBlCaKey))
    $on = @($all | Where-Object { [string]$_.state -eq 'enabled' } | Where-Object $Filter)
    if ($on.Count) { return New-TRCtl Pass ('Met by: ' + (Get-TRBlCaNames $on) + '.') }
    $ro = @($all | Where-Object { [string]$_.state -eq 'enabledForReportingButNotEnforced' } | Where-Object $Filter)
    $text = 'No enabled Conditional Access policy ' + $Requirement + '.'
    if ($ro.Count) { $text += ' Report-only policies that would meet it once switched on: ' + (Get-TRBlCaNames $ro) + '.' }
    $sd = Get-TRRawValue 'SecurityDefaults'
    if ($sd -and (Test-TRTrue $sd.isEnabled)) { $text += ' Security defaults are on, but the benchmark expects a Conditional Access policy.' }
    if (-not (Test-TRLicensed 'P1')) { $text += ' Entra ID P1 is not licensed, so Conditional Access is not available.' }
    New-TRCtl Fail $text
}

function Get-TRExoDefault {
    param([string]$Key)
    $items = @(Get-TRItems $Key)
    $d = @($items | Where-Object { Test-TRTrue $_.IsDefault })[0]
    if (-not $d) { $d = @($items | Where-Object { [string]$_.Identity -eq 'Default' -or [string]$_.Name -eq 'Default' })[0] }
    $d
}

function Test-TRPresetOn {
    param([ValidateSet('Strict', 'Standard')][string]$Kind, [ValidateSet('EOP', 'ATP')][string]$Plane)
    $key = if ($Plane -eq 'EOP') { 'ExoPresetEop' } else { 'ExoPresetAtp' }
    foreach ($r in (Get-TRItems $key)) {
        $n = [string]$r.Identity + ' ' + [string]$r.Name
        if ($n -match ($Kind + ' Preset Security Policy') -and [string]$r.State -eq 'Enabled') { return $true }
    }
    $false
}

function Get-TRPresetRule {
    param([ValidateSet('Strict', 'Standard')][string]$Kind, [ValidateSet('EOP', 'ATP')][string]$Plane)
    $key = if ($Plane -eq 'EOP') { 'ExoPresetEop' } else { 'ExoPresetAtp' }
    @(Get-TRItems $key | Where-Object { ([string]$_.Identity + ' ' + [string]$_.Name) -match ($Kind + ' Preset Security Policy') })[0]
}

function Get-TRActiveExoPolicies {
    param([string]$PolicyKey, [string]$RuleKey, [string]$RuleField, [ValidateSet('EOP', 'ATP')][string]$Plane)
    $rules = @(Get-TRItems $RuleKey)
    foreach ($p in (Get-TRItems $PolicyKey)) {
        $name = [string]$p.Name
        $id = [string]$p.Identity
        $rpt = [string]$p.RecommendedPolicyType
        $label = $(if ($name) { $name } else { $id })
        if (Test-TRTrue $p.IsDefault) { [pscustomobject]@{ Policy = $p; Source = 'Default'; Name = $label; Order = 3 }; continue }
        if ($rpt -eq 'Strict' -or $name -match 'Strict Preset Security Policy') {
            if (Test-TRPresetOn Strict $Plane) { [pscustomobject]@{ Policy = $p; Source = 'Strict preset'; Name = 'Strict preset'; Order = 0 } }
            continue
        }
        if ($rpt -eq 'Standard' -or $name -match 'Standard Preset Security Policy') {
            if (Test-TRPresetOn Standard $Plane) { [pscustomobject]@{ Policy = $p; Source = 'Standard preset'; Name = 'Standard preset'; Order = 1 } }
            continue
        }
        if ((Test-TRTrue $p.IsBuiltInProtection) -or $name -match 'Built-In Protection' -or $rpt -eq 'BuiltInProtection') {
            [pscustomobject]@{ Policy = $p; Source = 'Built-in protection'; Name = 'Built-in protection'; Order = 4 }
            continue
        }
        $rule = @($rules | Where-Object { $rf = [string](Get-TRV $_ $RuleField); ($rf -eq $name -or $rf -eq $id) -and [string]$_.State -eq 'Enabled' })[0]
        if ($rule) { [pscustomobject]@{ Policy = $p; Source = 'Custom'; Name = $label; Order = 2 } }
    }
}

function Get-TRTopExoPolicy {
    param($Active)
    @(@($Active) | Sort-Object Order)[0]
}

function ConvertFrom-TRDmarc {
    param([string]$Record)
    $tags = @{}
    foreach ($part in ($Record -split ';')) {
        $kv = $part -split '=', 2
        if ($kv.Count -eq 2) { $tags[$kv[0].Trim().ToLower()] = $kv[1].Trim() }
    }
    $tags
}

function Get-TRMailRows {
    @(Get-TRItems 'DnsRecords' | Where-Object { $_.SupportsEmail -or @($_.Mx).Count -gt 0 })
}

function Test-TRSpfOk {
    param($Row)
    $spf = @(Get-TRStrings $Row.Spf)
    if ($spf.Count -eq 0) { return 'No SPF record' }
    if ($spf.Count -gt 1) { return ('{0} SPF records (only one is allowed)' -f $spf.Count) }
    $s = $spf[0]
    if ($s -match '[+?]all\b') { return ('Permissive qualifier: ' + $s) }
    if ($s -notmatch '[-~]all\b' -and $s -notmatch 'redirect=') { return ('Does not end in -all or ~all: ' + $s) }
    ''
}

function Get-TRSpo { Get-TRFirstItem 'SpoTenant' }

function ConvertTo-TRSharingCap {
    param($Value)
    if ($null -eq $Value -or [string]$Value -eq '') { return $null }
    $s = [string]$Value
    if ($s -match '^\d+$') { return [int]$s }
    switch -Regex ($s) {
        '^disabled$' { return 0 }
        '^externalUserSharingOnly$' { return 1 }
        '^externalUserAndGuestSharing$' { return 2 }
        '^existingExternalUserSharingOnly$' { return 3 }
    }
    $null
}

$script:TRSharingCapNames = @{ 0 = 'Only people in your organisation'; 1 = 'New and existing guests'; 2 = 'Anyone'; 3 = 'Existing guests only' }

function Get-TRSpoSharing {
    param([switch]$OneDrive)
    $spo = Get-TRSpo
    if ($spo) {
        $name = if ($OneDrive) { 'ODBSharingCapability' } else { 'SharingCapability' }
        $v = ConvertTo-TRSharingCap (Get-TRV $spo $name)
        if ($null -eq $v -and $OneDrive) { $v = ConvertTo-TRSharingCap (Get-TRV $spo 'OneDriveSharingCapability') }
        if ($null -ne $v) { return $v }
    }
    if (-not $OneDrive) {
        $g = Get-TRRawValue 'SharePointSettings'
        if ($g) { return (ConvertTo-TRSharingCap $g.sharingCapability) }
    }
    $null
}

function Get-TRSpoEnum {
    param([string]$Name, $Names)
    $v = Get-TRV (Get-TRSpo) $Name
    if ($null -eq $v) { return $null }
    $s = [string]$v
    if ($s -match '^\d+$') { return [int]$s }
    for ($i = 0; $i -lt $Names.Count; $i++) { if ($s -ieq $Names[$i]) { return $i } }
    $null
}

function Get-TRTeamsPolicy {
    param([string]$Key, [string]$Identity = 'Global')
    $items = @(Get-TRItems $Key)
    $g = @($items | Where-Object { [string](Get-TRV $_ 'Identity') -eq $Identity -or [string](Get-TRV $_ 'Identity') -eq ('Tag:' + $Identity) })[0]
    if (-not $g -and $Identity -eq 'Global' -and $items.Count -eq 1) { $g = $items[0] }
    $g
}

function Test-TRTeamsAll {
    param([string]$Key, [scriptblock]$Ok, [string]$Setting, [switch]$GlobalOnly)
    $items = @(Get-TRItems $Key)
    if ($GlobalOnly) { $items = @(@(Get-TRTeamsPolicy $Key) | Where-Object { $_ }) }
    if (-not $items.Count) { return New-TRCtl NotAssessed 'No Teams policies were returned.' }
    $bad = foreach ($p in $items) {
        $v = Get-TRV $p $Setting
        if (-not (& $Ok $v)) { New-TRAffected ([string](Get-TRV $p 'Identity')) ('{0} = {1}' -f $Setting, $(if ($null -eq $v) { 'not set' } else { [string]$v })) }
    }
    $bad = @($bad)
    if ($bad.Count -and $items.Count -eq 1) { return New-TRCtl Fail ('{0} policy: {1}.' -f $bad[0].Item, $bad[0].Detail) $bad }
    if ($bad.Count) { return New-TRCtl Fail ('{0} of {1} policies do not meet this: {2}.' -f $bad.Count, $items.Count, (Join-TRList ($bad | ForEach-Object { $_.Item + ' (' + $_.Detail + ')' }) 4)) $bad }
    $g = Get-TRTeamsPolicy $Key
    New-TRCtl Pass ('{0} = {1} in {2}.' -f $Setting, $(if ($g) { [string](Get-TRV $g $Setting) } else { 'a compliant value' }), $(if ($items.Count -eq 1) { 'the ' + [string](Get-TRV $items[0] 'Identity') + ' policy' } else { 'all ' + $items.Count + ' policies' }))
}

function Get-TRTeamsAllowedDomains {
    param($Federation)
    $a = Get-TRV $Federation 'AllowedDomains'
    $names = New-Object System.Collections.ArrayList
    $mode = 'All'
    if ($null -eq $a) { return [pscustomobject]@{ Mode = 'All'; Domains = @() } }
    if ($a -is [string]) {
        if ($a -match 'AllowAllKnownDomains' -or -not $a.Trim()) { return [pscustomobject]@{ Mode = 'All'; Domains = @() } }
        return [pscustomobject]@{ Mode = 'List'; Domains = @($a -split '[,;\s]+' | Where-Object { $_ }) }
    }
    $items = @()
    if ($a -is [System.Collections.IDictionary] -or ($a -isnot [System.Collections.IEnumerable])) {
        if ($null -ne (Get-TRV $a 'AllowAllKnownDomains')) { return [pscustomobject]@{ Mode = 'All'; Domains = @() } }
        $inner = Get-TRV $a 'AllowedDomain'
        if ($null -eq $inner) { $inner = Get-TRV $a 'Domains' }
        if ($null -eq $inner) { return [pscustomobject]@{ Mode = 'All'; Domains = @() } }
        $items = @($inner)
        $mode = 'List'
    }
    else {
        $items = @($a)
        if ($items.Count) { $mode = 'List' }
    }
    foreach ($i in $items) {
        if ($null -eq $i) { continue }
        if ($i -is [string]) { [void]$names.Add($i); continue }
        foreach ($k in 'Domain', 'domain', 'Name', 'name', 'Identity') { $v = Get-TRV $i $k; if ($v) { [void]$names.Add([string]$v); break } }
    }
    [pscustomobject]@{ Mode = $mode; Domains = @($names) }
}

function Get-TRFabric {
    param([string]$Name)
    @(Get-TRItems 'PowerBISettings' | Where-Object { [string](Get-TRV $_ 'SettingName') -eq $Name })[0]
}

function Test-TRFabricRestricted {
    param([string]$Name, [switch]$MustBeOff)
    $s = Get-TRFabric $Name
    if (-not $s) { return New-TRCtl NotAssessed ("The tenant setting {0} was not returned by the Fabric admin API." -f $Name) }
    $title = [string](Get-TRV $s 'Title')
    $label = if ($title) { "'$title'" } else { $Name }
    if (Test-TRFalse (Get-TRV $s 'Enabled')) { return New-TRCtl Pass ("{0} is turned off." -f $label) }
    $groups = @(Get-TRStrings (Get-TRV $s 'EnabledSecurityGroups'))
    if ($MustBeOff) { return New-TRCtl Fail ("{0} is turned on{1}." -f $label, $(if ($groups.Count) { ' for ' + (Join-TRList $groups 4) } else { ' for the whole organisation' })) }
    if ($groups.Count) { return New-TRCtl Pass ("{0} is limited to these security groups: {1}." -f $label, (Join-TRList $groups 6)) }
    New-TRCtl Fail ("{0} is turned on for the whole organisation." -f $label)
}

function Test-TRFabricOn {
    param([string]$Name)
    $s = Get-TRFabric $Name
    if (-not $s) { return New-TRCtl NotAssessed ("The tenant setting {0} was not returned by the Fabric admin API." -f $Name) }
    $title = [string](Get-TRV $s 'Title')
    $label = if ($title) { "'$title'" } else { $Name }
    if (Test-TRTrue (Get-TRV $s 'Enabled')) { return New-TRCtl Pass ("{0} is turned on." -f $label) }
    New-TRCtl Fail ("{0} is turned off." -f $label)
}

function Get-TRPimRule {
    param([string]$Role, [string]$RuleId)
    $p = @(Get-TRItems 'RoleManagementPolicies' | Where-Object { [string]$_.RoleTemplate -eq $Role })[0]
    if (-not $p) { return $null }
    @(@($p.Rules) | Where-Object { [string]$_.id -eq $RuleId })[0]
}

function Get-TRPrivilegedUsers {
    param($RoleMap, [switch]$IncludeEligible)
    $rows = @(Get-TRRoleRows | Where-Object { $RoleMap.Contains([string]$_.RoleTemplate) -and ($IncludeEligible -or $_.Assignment -eq 'Active') })
    $rows
}

function Get-TRDurationDays {
    param([string]$Duration)
    if (-not $Duration) { return $null }
    try { return [int][Xml.XmlConvert]::ToTimeSpan($Duration).TotalDays } catch { return $null }
}

function Get-TRAppRestriction {
    param([string]$Type, [ValidateSet('passwordCredentials', 'keyCredentials')][string]$Kind = 'passwordCredentials')
    $p = Get-TRRawValue 'DefaultAppMgmtPolicy'
    $out = [ordered]@{}
    foreach ($scope in 'applicationRestrictions', 'servicePrincipalRestrictions') {
        $out[$scope] = @(@(Get-TRPath $p ($scope + '.' + $Kind)) | Where-Object { $_ -and [string]$_.restrictionType -eq $Type })[0]
    }
    [pscustomobject]@{ Enabled = (Test-TRTrue $p.isEnabled); App = $out['applicationRestrictions']; Sp = $out['servicePrincipalRestrictions'] }
}

function Test-TRAppRestriction {
    param([string]$Type, [ValidateSet('passwordCredentials', 'keyCredentials')][string]$Kind = 'passwordCredentials', [int]$MaxDays = 0, [string]$Label)
    $r = Get-TRAppRestriction -Type $Type -Kind $Kind
    if (-not $r.Enabled) { return New-TRCtl Fail 'The tenant default app management policy is not enabled.' }
    $problems = @()
    foreach ($pair in @(@{ N = 'applications'; V = $r.App }, @{ N = 'service principals'; V = $r.Sp })) {
        $x = $pair.V
        if (-not $x -or [string]$x.state -ne 'enabled') { $problems += ('not enforced for ' + $pair.N); continue }
        if ($MaxDays -gt 0) {
            $days = Get-TRDurationDays ([string]$x.maxLifetime)
            if ($null -eq $days -or $days -gt $MaxDays) { $problems += ('{0} allowed for {1}' -f $(if ($null -eq $days) { 'no maximum' } else { "$days days" }), $pair.N) }
        }
    }
    if ($problems.Count) { return New-TRCtl Fail ($Label + ': ' + ($problems -join '; ') + '.') }
    New-TRCtl Pass ($Label + ': enforced for applications and service principals' + $(if ($MaxDays) { " ($MaxDays days or less)" } else { '' }) + '.')
}

function Get-TRAuthMethod {
    param([string]$Id, [switch]$Beta)
    $key = if ($Beta -and (Test-TRCollected @('AuthMethodsPolicyBeta'))) { 'AuthMethodsPolicyBeta' } else { 'AuthMethodsPolicy' }
    $p = Get-TRRawValue $key
    @(@($p.authenticationMethodConfigurations) | Where-Object { $_ -and [string]$_.id -ieq $Id })[0]
}

function Get-TRPasswordRule {
    param([string]$Name)
    Get-TRGroupSettingValue 'Password Rule Settings' $Name
}

function Get-TRAlertState {
    param([string[]]$Names)
    $alerts = @(Get-TRItems 'SccAlertPolicies')
    foreach ($n in $Names) {
        $a = @($alerts | Where-Object { [string]$_.Name -eq $n })[0]
        [pscustomobject]@{ Name = $n; Found = [bool]$a; Enabled = $(if ($a) { -not (Test-TRTrue $a.Disabled) } else { $false }); NotifyUser = $(if ($a) { Join-TRList $a.NotifyUser 3 } else { '' }) }
    }
}

function Get-TRDlpActive {
    @(Get-TRItems 'SccDlpPolicies' | Where-Object { -not (Test-TRFalse $_.Enabled) -and [string]$_.Mode -eq 'Enable' })
}

function Get-TRDlpRulesFor {
    param($Policies)
    $names = @(@($Policies) | Where-Object { $_ } | ForEach-Object { [string]$_.Name } | Where-Object { $_ })
    if (-not $names.Count) { return @() }
    @(Get-TRItems 'SccDlpRules' | Where-Object { (($_.ParentPolicyName -and $names -contains [string]$_.ParentPolicyName) -or ($_.Policy -and $names -contains [string]$_.Policy)) -and -not (Test-TRTrue $_.Disabled) })
}

function Get-TRBenchmarkSummary {
    param($Rows)
    $info = Get-TRFrameworkInfo
    foreach ($fw in $info.Keys) {
        $r = @(@($Rows) | Where-Object { $_.Framework -eq $fw })
        if (-not $r.Count) { continue }
        $pass = @($r | Where-Object { $_.Status -eq 'Pass' }).Count
        $fail = @($r | Where-Object { $_.Status -eq 'Fail' }).Count
        $l1 = @($r | Where-Object { $_.Level -in @('L1', 'Shall') })
        $l1p = @($l1 | Where-Object { $_.Status -eq 'Pass' }).Count
        $l1f = @($l1 | Where-Object { $_.Status -eq 'Fail' }).Count
        [pscustomobject][ordered]@{
            Framework     = $fw
            Name          = $info[$fw].Name
            Version       = $info[$fw].Version
            Short         = $info[$fw].Short
            Total         = $r.Count
            Pass          = $pass
            Fail          = $fail
            Manual        = @($r | Where-Object { $_.Status -eq 'Manual' }).Count
            NotAssessed   = @($r | Where-Object { $_.Status -eq 'NotAssessed' }).Count
            NotApplicable = @($r | Where-Object { $_.Status -eq 'NotApplicable' }).Count
            Score         = $(if (($pass + $fail) -gt 0) { [int][Math]::Round(100 * $pass / ($pass + $fail)) } else { 0 })
            CoreScore     = $(if (($l1p + $l1f) -gt 0) { [int][Math]::Round(100 * $l1p / ($l1p + $l1f)) } else { 0 })
            CoreLabel     = $(if ($fw -eq 'CIS') { 'Level 1' } else { 'SHALL' })
        }
    }
}

$script:TRCtlStatus = [ordered]@{
    Fail          = 'Not met'
    Pass          = 'Met'
    Manual        = 'Check manually'
    NotAssessed   = 'Not assessed'
    NotApplicable = 'Not applicable'
}

function Invoke-TRBenchmarks {
    param($Findings)
    $checkIndex = @{}
    foreach ($f in @($Findings)) { if ($f) { $checkIndex[[string]$f.Id] = $f } }
    $mapIndex = @{}
    $platform = Get-TRPlatform
    $controls = @($script:TRControls | Where-Object { $_.Platform -eq $platform })
    foreach ($c in $controls) {
        foreach ($m in $c.Map) {
            if (-not $mapIndex.ContainsKey($c.Id)) { $mapIndex[$c.Id] = New-Object System.Collections.ArrayList }
            if (-not $mapIndex.ContainsKey($m)) { $mapIndex[$m] = New-Object System.Collections.ArrayList }
            if (-not $mapIndex[$c.Id].Contains($m)) { [void]$mapIndex[$c.Id].Add($m) }
            if (-not $mapIndex[$m].Contains($c.Id)) { [void]$mapIndex[$m].Add($c.Id) }
        }
    }
    $rows = New-Object System.Collections.ArrayList
    foreach ($c in $controls) {
        $res = $null
        if ($c.Licence.Count -and -not (Test-TRLicenceAny $c.Licence) -and -not (Test-TRLicenceDataKnown)) {
            $res = New-TRCtl NotAssessed ('The licences could not be read, so it is not known whether the tenant has {0}. See Collection diagnostics.' -f (Get-TRLicenceText $c.Licence))
        }
        elseif ($c.Licence.Count -and -not (Test-TRLicenceAny $c.Licence)) {
            $res = New-TRCtl NotApplicable ('Requires {0}, which this tenant does not have.' -f (Get-TRLicenceText $c.Licence))
        }
        elseif ($c.Needs.Count -and -not (Test-TRCollected $c.Needs)) {
            $res = New-TRCtl NotAssessed ('Data not available. ' + (Get-TRMissingReason $c.Needs))
        }
        elseif ($c.Test) {
            try {
                $res = & $c.Test
                if ($res -is [System.Array]) { $res = $res[-1] }
                if (-not $res) { $res = New-TRCtl NotAssessed 'The control returned no result.' }
            }
            catch { $res = New-TRCtl NotAssessed ('The control could not be evaluated: ' + $_.Exception.Message) }
        }
        else {
            $res = New-TRCtl Manual 'This control cannot be read through an API. Check it by hand using the guidance.'
        }
        $mapped = @()
        if ($mapIndex.ContainsKey($c.Id)) { $mapped = @($mapIndex[$c.Id] | Sort-Object | ForEach-Object { if ($_ -like 'MS.*' -or $_ -like 'GWS.*') { $_ } else { 'CIS ' + $_ } }) }
        $checks = foreach ($id in $c.Checks) {
            $f = $checkIndex[$id]
            if ($f) { '{0} ({1})' -f $id, (Get-TRStatusLabel $f.Status) } else { $id }
        }
        [void]$rows.Add([pscustomobject][ordered]@{
                Framework     = $c.Framework
                Id            = $c.Id
                Section       = $c.Section
                Title         = $c.Title
                Level         = $c.Level
                Profile       = $c.Profile
                Status        = $res.Status
                StatusLabel   = $script:TRCtlStatus[$res.Status]
                Evidence      = $res.Evidence
                Guidance      = $c.Guidance
                Mapped        = ($mapped -join '; ')
                RelatedChecks     = (@($checks) -join '; ')
                Licence       = $(if ($c.Licence.Count) { Get-TRLicenceText $c.Licence } else { '' })
                AffectedCount = @($res.Affected).Count
                Affected      = @($res.Affected)
            })
    }
    $refs = @{}
    foreach ($c in $controls) {
        foreach ($id in $c.Checks) {
            if (-not $refs.ContainsKey($id)) { $refs[$id] = New-Object System.Collections.ArrayList }
            $label = $(if ($c.Framework -eq 'CIS') { 'CIS ' + $c.Id } else { $c.Id })
            if (-not $refs[$id].Contains($label)) { [void]$refs[$id].Add($label) }
        }
    }
    foreach ($f in @($Findings)) {
        if (-not $f) { continue }
        $v = if ($refs.ContainsKey([string]$f.Id)) { (@($refs[[string]$f.Id]) -join '; ') } else { '' }
        $f | Add-Member -NotePropertyName 'Frameworks' -NotePropertyValue $v -Force
    }
    , $rows.ToArray()
}
