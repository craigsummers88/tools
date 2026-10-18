$script:TRGwsSkus = [ordered]@{
    '1010020027' = 'Business Starter'
    '1010020028' = 'Business Standard'
    '1010020025' = 'Business Plus'
    '1010060003' = 'Enterprise Essentials'
    '1010020029' = 'Enterprise Starter'
    '1010020026' = 'Enterprise Standard'
    '1010020020' = 'Enterprise Plus'
    '1010060001' = 'Essentials'
    '1010060005' = 'Enterprise Essentials Plus'
    '1010020030' = 'Frontline Starter'
    '1010020031' = 'Frontline Standard'
    '1010020034' = 'Frontline Plus'
    '1010020035' = 'Business Continuity'
    '1010020036' = 'Business Continuity Plus'
    'Google-Apps-Unlimited' = 'G Suite Business'
    'Google-Apps-For-Business' = 'G Suite Basic'
    'Google-Apps-Lite' = 'G Suite Lite'
    'Google-Apps-For-Nonprofits' = 'Google Workspace for Nonprofits'
    'Google-Apps-For-Education' = 'Education Fundamentals'
    '1010070001' = 'Education Fundamentals'
    '1010310005' = 'Education Standard'
    '1010310006' = 'Education Standard (Staff)'
    '1010310007' = 'Education Standard (Extra Student)'
    '1010310008' = 'Education Plus'
    '1010310009' = 'Education Plus (Staff)'
    '1010310010' = 'Education Plus (Extra Student)'
    '1010310002' = 'Education Plus (Legacy)'
    '1010310003' = 'Education Plus (Legacy, Student)'
    '1010370001' = 'Teaching and Learning Upgrade'
    'Google-Vault' = 'Google Vault'
    'Google-Vault-Former-Employee' = 'Google Vault (Former Employee)'
    '1010010001' = 'Cloud Identity Free'
    '1010050001' = 'Cloud Identity Premium'
    '1010400001' = 'Chrome Enterprise Premium'
    '1010390001' = 'Assured Controls'
    '1010390002' = 'Assured Controls Plus'
    '1010330003' = 'Google Voice Starter'
    '1010330004' = 'Google Voice Standard'
    '1010330002' = 'Google Voice Premier'
    '1010380001' = 'AppSheet Core'
    '1010380002' = 'AppSheet Enterprise Standard'
    '1010380003' = 'AppSheet Enterprise Plus'
    '1010680001' = 'Gemini Enterprise Business Edition'
    '1010470002' = 'Gemini Labs'
    '1010470006' = 'Gemini Security'
    '1010470007' = 'Gemini Meet'
    '1010470009' = 'AI Expanded Access'
    '1010430001' = 'Additional Storage 10TB'
    '1010430002' = 'Additional Storage 100 GB'
    '1010430003' = 'Additional Storage 1TB'
    '1010360001' = 'Meet Global Dialing'
}

$script:TRGwsEdu = @('Google-Apps-For-Education', '1010070001', '1010310005', '1010310006', '1010310007', '1010310008', '1010310009', '1010310010', '1010310002', '1010310003', '1010370001')
$script:TRGwsEduPaid = @('1010310005', '1010310006', '1010310007', '1010310008', '1010310009', '1010310010', '1010310002', '1010310003')
$script:TRGwsEduPlus = @('1010310008', '1010310009', '1010310010', '1010310002', '1010310003')

$script:TRGwsCapabilities = @{
    Workspace       = @('1010020027', '1010020028', '1010020025', '1010020029', '1010020026', '1010020020', '1010020030', '1010020031', '1010020034', '1010020035', '1010020036', 'Google-Apps-Unlimited', 'Google-Apps-For-Business', 'Google-Apps-Lite', 'Google-Apps-For-Nonprofits') + $script:TRGwsEdu
    Gmail           = @('1010020027', '1010020028', '1010020025', '1010020029', '1010020026', '1010020020', '1010020030', '1010020031', '1010020034', '1010020035', '1010020036', 'Google-Apps-Unlimited', 'Google-Apps-For-Business', 'Google-Apps-Lite', 'Google-Apps-For-Nonprofits') + $script:TRGwsEdu
    Vault           = @('1010020025', '1010020026', '1010020020', '1010020031', '1010020034', 'Google-Apps-Unlimited', 'Google-Vault', 'Google-Vault-Former-Employee') + $script:TRGwsEdu
    Dlp             = @('1010020026', '1010020020', '1010020031', '1010020034') + $script:TRGwsEduPaid
    ContextAware    = @('1010020026', '1010020020', '1010020031', '1010020034', '1010060005', '1010050001', '1010400001') + $script:TRGwsEduPaid
    SecurityCenter  = @('1010020026', '1010020020', '1010020031', '1010020034') + $script:TRGwsEduPaid
    ActivityRules   = @('1010020026', '1010020020', '1010020031', '1010020034') + $script:TRGwsEduPaid
    AdvancedEndpoint = @('1010020025', '1010020026', '1010020020', '1010020030', '1010020031', '1010020034', '1010060005', '1010050001', 'Google-Apps-Unlimited') + $script:TRGwsEduPaid
    WindowsManagement = @('1010020025', '1010020026', '1010020020', '1010020030', '1010020031', '1010020034', '1010050001') + $script:TRGwsEduPaid
    SecuritySandbox = @('1010020020', '1010020034') + $script:TRGwsEduPlus
    DataRegions     = @('1010020028', '1010020025', '1010020026', '1010020020', '1010020030', '1010020031', '1010020034', '1010390001', '1010390002') + $script:TRGwsEduPlus
    DataRegionsEnterprise = @('1010020020', '1010020034', '1010390001', '1010390002') + $script:TRGwsEduPlus
    AssuredControls = @('1010390001', '1010390002')
    Classroom       = $script:TRGwsEdu
    MeetRecording   = @('1010020028', '1010020025', '1010020029', '1010020026', '1010020020', '1010370001') + $script:TRGwsEduPlus
    AppointmentPayments = @('1010020028', '1010020025', '1010020026', '1010020020')
    SecureLdap      = @('1010020025', '1010020026', '1010020020', '1010020031', '1010020034', '1010050001') + $script:TRGwsEdu
    GeminiDocs      = @('1010020028', '1010020025', '1010020026', '1010020020', '1010020034', '1010680001')
    Voice           = @('1010330003', '1010330004', '1010330002')
    AppSheet        = @('1010380001', '1010380002', '1010380003', '1010020027', '1010020028', '1010020025', '1010020026', '1010020020')
    ClientSideEncryption = @('1010020020', '1010020034') + $script:TRGwsEduPlus
}

$script:TRGwsCapabilityNames = @{
    Vault = 'Google Vault (Business Plus, Enterprise, Frontline Standard or Education)'
    Dlp = 'data loss prevention (Enterprise, Frontline Standard or Education Standard/Plus)'
    ContextAware = 'context-aware access (Enterprise, Frontline Standard, Cloud Identity Premium or Education Standard/Plus)'
    SecurityCenter = 'the security centre (Enterprise or Frontline Standard)'
    ActivityRules = 'activity rules (Enterprise or Frontline Standard)'
    AdvancedEndpoint = 'advanced endpoint management (Business Plus, Enterprise or Frontline)'
    WindowsManagement = 'Windows device management (Business Plus, Enterprise or Frontline)'
    SecuritySandbox = 'the security sandbox (Enterprise Plus, Frontline Plus or Education Plus)'
    DataRegions = 'data regions'
    DataRegionsEnterprise = 'enterprise data regions (Enterprise Plus or Assured Controls)'
    AssuredControls = 'Assured Controls'
    Classroom = 'Google Workspace for Education (Classroom)'
    MeetRecording = 'Meet recording (Business Standard or higher)'
    AppointmentPayments = 'paid appointment schedules (Business Standard or higher)'
    SecureLdap = 'Secure LDAP'
    GeminiDocs = 'Gemini in Docs, Sheets and Drive'
    Gmail = 'Gmail'
    Workspace = 'a Google Workspace edition'
    ClientSideEncryption = 'client-side encryption (Enterprise Plus)'
}

$script:TRGwsDefaults = @{
    'calendar.external_invitations' = @{ warnOnInvite = $true }
    'calendar.interoperability' = @{ enableInteroperability = $false }
    'calendar.primary_calendar_max_allowed_external_sharing' = @{ maxAllowedExternalSharing = 'EXTERNAL_FREE_BUSY_ONLY' }
    'calendar.secondary_calendar_max_allowed_external_sharing' = @{ maxAllowedExternalSharing = 'EXTERNAL_ALL_INFO_READ_ONLY' }
    'chat.chat_history' = @{ allowUserModification = $true; historyOnByDefault = $false }
    'chat.external_chat_restriction' = @{ allowExternalChat = $false; externalChatRestriction = 'NO_RESTRICTION' }
    'drive_and_docs.drive_sdk' = @{ enableDriveSdkApiAccess = $true }
    'drive_and_docs.external_sharing' = @{ accessCheckerSuggestions = 'RECIPIENTS_OR_AUDIENCE_OR_PUBLIC'; allowNonGoogleInvites = $true; allowNonGoogleInvitesInAllowlistedDomains = $false; allowPublishingFiles = $true; allowReceivingExternalFiles = $true; allowReceivingFilesOutsideAllowlistedDomains = $true; allowedPartiesForDistributingContent = 'ALL_ELIGIBLE_USERS'; externalSharingMode = 'ALLOWED'; warnForExternalSharing = $true; warnForSharingOutsideAllowlistedDomains = $true }
    'drive_and_docs.general_access_default' = @{ defaultFileAccess = 'PRIVATE_TO_OWNER' }
    'gmail.auto_forwarding' = @{ enableAutoForwarding = $true }
    'gmail.email_spam_filter_ip_allowlist' = @{ allowedIpAddresses = @() }
    'gmail.links_and_external_images' = @{ applyFutureSettingsAutomatically = $true; enableAggressiveWarningsOnUntrustedLinks = $false }
    'gmail.mail_delegation' = @{ enableMailDelegation = $false }
    'gmail.spoofing_and_authentication' = @{ applyFutureSettingsAutomatically = $true }
    'gmail.workspace_sync_for_outlook' = @{ enableGoogleWorkspaceSyncForMicrosoftOutlook = $true }
    'groups_for_business.groups_sharing' = @{ collaborationCapability = 'DOMAIN_USERS_ONLY'; createGroupsAccessLevel = 'USERS_IN_DOMAIN'; newGroupsAreHidden = $false; ownersCanAllowExternalMembers = $false; ownersCanAllowIncomingMailFromPublic = $true; ownersCanHideGroups = $false; viewTopicsDefaultAccessLevel = 'DOMAIN_USERS' }
    'security.less_secure_apps' = @{ allowLessSecureApps = $false }
    'security.super_admin_account_recovery' = @{ enableAccountRecovery = $false }
    'security.two_step_verification_device_trust' = @{ allowTrustingDevice = $true }
    'security.two_step_verification_enforcement' = @{ enforcedFrom = '1970-01-01T00:00:00Z' }
    'security.two_step_verification_enforcement_factor' = @{ allowedSignInFactorSet = 'ALL' }
    'security.two_step_verification_enrollment' = @{ allowEnrollment = $true }
    'security.two_step_verification_grace_period' = @{ enrollmentGracePeriod = '0s' }
    'security.user_account_recovery' = @{ enableAccountRecovery = $false }
    'workspace_marketplace.apps_access_options' = @{ accessLevel = 'ALLOW_ALL'; allowAllInternalApps = $false }
    'access_management.user_scoping' = @{ accessManagementRegime = 'PREFERENCE_UNSPECIFIED' }
    'access_approval.axa_user_scoping' = @{ requiresCustomerApproval = $false }
}

function Get-TRPlatform {
    $p = [string](Get-TRMeta 'Platform')
    if ($p) { return $p }
    'Microsoft'
}

function Test-TRGwsCapability {
    param([string]$Capability)
    $set = $script:TRGwsCapabilities[$Capability]
    if (-not $set) { return $false }
    $have = Get-TRGwsSkuCounts
    foreach ($s in $set) { if ($have.ContainsKey($s)) { return $true } }
    $false
}

function Get-TRGwsSkuCounts {
    Get-TRCached 'GwsSkuCounts' {
        $h = @{}
        foreach ($l in (Get-TRItems 'GwsLicences')) {
            $k = [string]$l.skuId
            if (-not $k) { continue }
            if ($h.ContainsKey($k)) { $h[$k]++ } else { $h[$k] = 1 }
        }
        $h
    }
}

function Get-TRGwsSkuName {
    param([string]$SkuId, [string]$Fallback)
    if ($script:TRGwsSkus[$SkuId]) { return $script:TRGwsSkus[$SkuId] }
    if ($Fallback) { return $Fallback }
    $n = (Get-TRGwsSkuNameIndex)[$SkuId]
    if ($n) { return $n }
    $SkuId
}

function Get-TRGwsRoleName {
    param([string]$Name)
    $known = @{ '_SEED_ADMIN_ROLE' = 'Super Admin'; '_GROUPS_ADMIN_ROLE' = 'Groups Admin'; '_USER_MANAGEMENT_ADMIN_ROLE' = 'User Management Admin'; '_HELP_DESK_ADMIN_ROLE' = 'Help Desk Admin'; '_SERVICES_ADMIN_ROLE' = 'Services Admin'; '_MOBILE_ADMIN_ROLE' = 'Mobile Admin'; '_GROUPS_EDITOR_ROLE' = 'Groups Editor'; '_GROUPS_READER_ROLE' = 'Groups Reader'; '_STORAGE_ADMIN_ROLE' = 'Storage Admin'; '_RESELLER_ADMIN_ROLE' = 'Reseller Admin' }
    if ($known[$Name]) { return $known[$Name] }
    if ($Name -match '^_(.+?)(_ROLE)?$') { return ((($Matches[1] -split '_') | ForEach-Object { if ($_.Length -le 2) { $_ } else { $_.Substring(0, 1) + $_.Substring(1).ToLower() } }) -join ' ') }
    $Name
}

function Get-TRGwsFactorText {
    param([string]$Value)
    $t = @{ ALL = 'any method'; NO_TELEPHONY = 'any method except text and voice codes'; PASSKEY_ONLY = 'passkeys and security keys only'; SECURITY_KEY_ONLY = 'security keys only' }[$Value]
    if ($t) { return $t }
    $Value
}

function Get-TRGwsSkuNameIndex {
    Get-TRCached 'GwsSkuNames' {
        $h = @{}
        foreach ($l in (Get-TRItems 'GwsLicences')) {
            if ($l.skuId -and $l.skuName) { $h[[string]$l.skuId] = ([string]$l.skuName) -replace '^Google Workspace ', '' }
        }
        $h
    }
}

function Get-TRGwsUserLicences {
    Get-TRCached 'GwsUserLicences' {
        $h = @{}
        foreach ($l in (Get-TRItems 'GwsLicences')) {
            $u = ([string]$l.userId).ToLower()
            if (-not $u) { continue }
            if (-not $h.ContainsKey($u)) { $h[$u] = New-Object System.Collections.ArrayList }
            [void]$h[$u].Add([string]$l.skuId)
        }
        $h
    }
}

function Get-TRGwsUserIndex {
    Get-TRCached 'GwsUserIndex' {
        $h = @{}
        foreach ($u in (Get-TRItems 'GwsUsers')) {
            $h[([string]$u.primaryEmail).ToLower()] = $u
            $h['id:' + [string]$u.id] = $u
        }
        $h
    }
}

function Get-TRGwsUsage {
    Get-TRCached 'GwsUsageIndex' {
        $h = @{}
        foreach ($u in (Get-TRItems 'GwsUserUsage')) { if ($u.Email) { $h[([string]$u.Email).ToLower()] = $u } }
        $h
    }
}

function Get-TRGwsEnabledUsers {
    @(Get-TRItems 'GwsUsers' | Where-Object { -not $_.suspended -and -not $_.archived })
}

function Get-TRGwsDomainNames {
    Get-TRCached 'GwsDomainNames' {
        $names = New-Object System.Collections.ArrayList
        foreach ($d in (Get-TRItems 'GwsDomains')) {
            if ($d.domainName) { [void]$names.Add(([string]$d.domainName).ToLower()) }
            foreach ($a in @($d.domainAliases)) { if ($a -and $a.domainAliasName) { [void]$names.Add(([string]$a.domainAliasName).ToLower()) } }
        }
        foreach ($a in (Get-TRItems 'GwsDomainAliases')) { if ($a.domainAliasName) { [void]$names.Add(([string]$a.domainAliasName).ToLower()) } }
        , @($names | Select-Object -Unique)
    }
}

function Test-TRGwsInternal {
    param([string]$Email)
    if (-not $Email -or $Email -notmatch '@(.+)$') { return $true }
    $d = $Matches[1].ToLower()
    $known = @(Get-TRGwsDomainNames)
    foreach ($k in $known) { if ($d -eq $k -or $d.EndsWith('.' + $k)) { return $true } }
    $false
}

function Get-TRGwsSuperAdmins {
    @(Get-TRGwsEnabledUsers | Where-Object { $_.isAdmin })
}

function Get-TRGwsRoleRows {
    Get-TRCached 'GwsRoleRows' {
        $roles = @{}
        foreach ($r in (Get-TRItems 'GwsRoles')) { $roles[[string]$r.roleId] = $r }
        $users = Get-TRGwsUserIndex
        $rows = foreach ($a in (Get-TRItems 'GwsRoleAssignments')) {
            $r = $roles[[string]$a.roleId]
            $u = $users['id:' + [string]$a.assignedTo]
            [pscustomobject][ordered]@{
                RoleId       = [string]$a.roleId
                Role         = $(if ($r) { Get-TRGwsRoleName ([string]$r.roleName) } else { [string]$a.roleId })
                IsSuperAdmin = [bool]($r -and $r.isSuperAdminRole)
                IsSystemRole = [bool]($r -and $r.isSystemRole)
                Privileges   = @($(if ($r) { @($r.rolePrivileges) | ForEach-Object { [string]$_.privilegeName } }))
                AssigneeType = $(if ($a.assigneeType) { [string]$a.assigneeType } else { 'USER' })
                AssignedTo   = [string]$a.assignedTo
                Email        = $(if ($u) { [string]$u.primaryEmail } else { [string]$a.assignedTo })
                Suspended    = [bool]($u -and $u.suspended)
                Scope        = $(if ([string]$a.scopeType -eq 'ORG_UNIT') { 'OU ' + [string]$a.orgUnitId } else { 'Organisation' })
            }
        }
        , @($rows)
    }
}

$script:TRGwsPrivileged = @('ADMIN_OAUTH_PRIVILEGE_GROUP', 'ADMIN_ROLE_MANAGEMENT', 'GROUPS_ALL', 'MANAGE_USER_LICENSES', 'MOBILE_ALL', 'ORGANIZATION_UNITS_ALL', 'SERVICES_ALL', 'USERS_ALL', 'USERS_CREATE', 'USERS_SECURITY', 'USERS_UPDATE')

function Get-TRGwsPrivilegedUsers {
    $h = @{}
    foreach ($u in (Get-TRGwsSuperAdmins)) { $h[([string]$u.primaryEmail).ToLower()] = 'Super Admin' }
    foreach ($r in (Get-TRGwsRoleRows)) {
        if ($r.AssigneeType -ne 'USER' -or $r.Suspended) { continue }
        $priv = $r.IsSuperAdmin -or @($r.Privileges | Where-Object { $script:TRGwsPrivileged -contains $_ }).Count -gt 0
        if (-not $priv) { continue }
        $k = $r.Email.ToLower()
        if (-not $h.ContainsKey($k)) { $h[$k] = $r.Role }
    }
    $o = [ordered]@{}
    foreach ($k in ($h.Keys | Sort-Object)) { $o[$k] = $h[$k] }
    $o
}

function Get-TRGwsOuIndex {
    Get-TRCached 'GwsOuIndex' {
        $h = @{}
        foreach ($o in (Get-TRItems 'GwsOrgUnits')) { $h[([string]$o.orgUnitId) -replace '^id:', ''] = [string]$o.orgUnitPath }
        $h
    }
}

function Get-TRGwsRootOuId {
    Get-TRCached 'GwsRootOu' {
        $root = @(Get-TRItems 'GwsOrgUnits' | Where-Object { [string]$_.orgUnitPath -eq '/' })[0]
        if ($root) { return (([string]$root.orgUnitId) -replace '^id:', '') }
        $parents = @(Get-TRItems 'GwsOrgUnits' | Where-Object { [string]$_.parentOrgUnitPath -eq '/' } | ForEach-Object { ([string]$_.parentOrgUnitId) -replace '^id:', '' } | Select-Object -Unique)
        if ($parents.Count -eq 1) { return $parents[0] }
        $null
    }
}

function Get-TRGwsGroupEmails {
    Get-TRCached 'GwsGroupEmails' {
        $h = @{}
        foreach ($g in (Get-TRItems 'GwsGroups')) { $h[[string]$g.id] = [string]$g.email }
        $h
    }
}

function Get-TRGwsPolicyIndex {
    Get-TRCached 'GwsPolicyIndex' {
        $root = Get-TRGwsRootOuId
        $ous = Get-TRGwsOuIndex
        $groups = Get-TRGwsGroupEmails
        $best = @{}
        foreach ($p in (Get-TRItems 'GwsPolicies')) {
            $type = ([string]$p.setting.type) -replace '^settings/', ''
            if (-not $type) { continue }
            $ou = ([string]$p.policyQuery.orgUnit) -replace '^orgUnits/', ''
            $grp = ([string]$p.policyQuery.group) -replace '^groups/', ''
            $isRoot = (-not $grp) -and ((-not $ou) -or ($root -and $ou -eq $root))
            $scope = if ($isRoot) { 'Whole organisation' } else {
                $ouName = if ($ou -and $ous[$ou]) { 'OU ' + $ous[$ou] } elseif ($ou) { 'OU ' + $ou } else { '' }
                if ($grp) {
                    $gName = if ($groups[$grp]) { $groups[$grp] } else { $grp }
                    if ($ouName -and -not ($root -and $ou -eq $root)) { 'Group ' + $gName + ' in ' + $ouName } else { 'Group ' + $gName }
                }
                else { $ouName }
            }
            $sort = 0.0
            try { $sort = [double]$p.policyQuery.sortOrder } catch { }
            $isRule = $type -like 'rule.*' -or $type -like 'detector.*'
            $key = if ($isRule) { $type + '|' + [string]$p.name } else { $type + '|' + $scope }
            if ($best.ContainsKey($key) -and $best[$key].Sort -ge $sort) { continue }
            $best[$key] = [pscustomobject]@{ Type = $type; Scope = $scope; IsRoot = $isRoot; Sort = $sort; Value = $p.setting.value; Name = [string]$p.name }
        }
        $idx = @{}
        foreach ($v in $best.Values) {
            if (-not $idx.ContainsKey($v.Type)) { $idx[$v.Type] = New-Object System.Collections.ArrayList }
            [void]$idx[$v.Type].Add($v)
        }
        $idx
    }
}

function ConvertTo-TRGwsHash {
    param($Value)
    $h = New-Object System.Collections.Hashtable ([StringComparer]::OrdinalIgnoreCase)
    if ($null -eq $Value) { return $h }
    if ($Value -is [System.Collections.IDictionary]) { foreach ($k in $Value.Keys) { $h[[string]$k] = $Value[$k] } }
    else { foreach ($p in $Value.PSObject.Properties) { $h[$p.Name] = $p.Value } }
    $h
}

function Merge-TRGwsHash {
    param($Base, $Over)
    $h = New-Object System.Collections.Hashtable ([StringComparer]::OrdinalIgnoreCase)
    foreach ($k in $Base.Keys) { $h[$k] = $Base[$k] }
    foreach ($k in $Over.Keys) { $h[$k] = $Over[$k] }
    $h
}

function Get-TRGwsSetting {
    param([string]$Type)
    $idx = Get-TRGwsPolicyIndex
    $list = @($idx[$Type])
    $rootP = @($list | Where-Object { $_.IsRoot })[0]
    $def = $script:TRGwsDefaults[$Type]
    $known = [bool]$rootP -or [bool]$def
    $rootVal = Merge-TRGwsHash (ConvertTo-TRGwsHash $def) (ConvertTo-TRGwsHash $(if ($rootP) { $rootP.Value } else { $null }))
    $over = foreach ($p in @($list | Where-Object { -not $_.IsRoot } | Sort-Object Scope)) {
        [pscustomobject]@{ Scope = $p.Scope; Value = (Merge-TRGwsHash $rootVal (ConvertTo-TRGwsHash $p.Value)) }
    }
    [pscustomobject]@{ Type = $Type; Known = $known; Explicit = [bool]$rootP; Root = $rootVal; Overrides = @($over) }
}

function Get-TRGwsRootValue {
    param([string]$Type, [string]$Field)
    $s = Get-TRGwsSetting $Type
    if (-not $s.Known) { return $null }
    $s.Root[$Field]
}

function Test-TRGwsPolicy {
    param(
        [Parameter(Mandatory = $true)][string]$Type,
        [Parameter(Mandatory = $true)][scriptblock]$Ok,
        [Parameter(Mandatory = $true)][string]$Good,
        [Parameter(Mandatory = $true)][string]$Bad,
        [scriptblock]$Detail
    )
    $s = Get-TRGwsSetting $Type
    if (-not $s.Known -and -not $s.Overrides.Count) {
        return [pscustomobject]@{ Status = 'Unknown'; Text = 'This setting was not returned by the Google Policy API.'; Affected = @(); RootOk = $null }
    }
    $rootOk = $null
    if ($s.Known) { $rootOk = [bool](& $Ok $s.Root) }
    $badOver = @($s.Overrides | Where-Object { -not [bool](& $Ok $_.Value) })
    $okOver = @($s.Overrides | Where-Object { [bool](& $Ok $_.Value) })
    $aff = New-Object System.Collections.ArrayList
    $describe = { param($v) if ($Detail) { [string](& $Detail $v) } else { '' } }
    if ($rootOk -eq $false) { [void]$aff.Add((New-TRAffected 'Whole organisation' $(if ($Detail) { & $describe $s.Root } else { $Bad }))) }
    foreach ($b in $badOver) { [void]$aff.Add((New-TRAffected $b.Scope $(if ($Detail) { & $describe $b.Value } else { $Bad }))) }
    $cap = { param($t) if ($t) { $t.Substring(0, 1).ToUpper() + $t.Substring(1) } else { $t } }
    $dflt = if ($s.Known -and -not $s.Explicit) { ' (Google default)' } else { '' }
    if ($rootOk -eq $false) {
        $text = (& $cap $Bad) + ' for the whole organisation' + $dflt + '.'
        if ($Detail) {
            $dt = ([string](& $describe $s.Root)).Trim()
            if ($dt -cmatch '^[A-Z0-9_]+$') { $dt = 'Current setting: ' + $dt }
            if ($dt) { $text += ' ' + (& $cap $dt) + $(if ($dt -match '[.!?]$') { '' } else { '.' }) }
        }
        if ($badOver.Count) { $text += (' Also in {0}: {1}.' -f (Format-TRN $badOver.Count 'override'), (Join-TRList ($badOver | ForEach-Object { $_.Scope }) 4)) }
        if ($okOver.Count) { $text += (' {0} {2} the control: {1}.' -f (Format-TRN $okOver.Count 'override'), (Join-TRList ($okOver | ForEach-Object { $_.Scope }) 3), (Select-TRText $okOver.Count 'meets' 'meet')) }
        return [pscustomobject]@{ Status = 'Fail'; Text = $text; Affected = $aff.ToArray(); RootOk = $false }
    }
    if ($badOver.Count) {
        $lead = if ($null -eq $rootOk) { 'The organisation-wide setting was not returned.' } else { (& $cap $Good) + ' for the organisation' + $dflt + '.' }
        $text = '{0} But {1} in {2}: {3}.' -f $lead, $Bad, (Format-TRN $badOver.Count 'override'), (Join-TRList ($badOver | ForEach-Object { $_.Scope }) 5)
        return [pscustomobject]@{ Status = 'Fail'; Text = $text; Affected = $aff.ToArray(); RootOk = $rootOk }
    }
    if ($null -eq $rootOk) { return [pscustomobject]@{ Status = 'Unknown'; Text = 'The organisation-wide setting was not returned by the Google Policy API.'; Affected = @(); RootOk = $null } }
    $text = (& $cap $Good) + ' for the whole organisation' + $dflt + '.'
    if ($s.Overrides.Count) { $text += (' {0} also meet it.' -f (Format-TRN $s.Overrides.Count 'override')) }
    [pscustomobject]@{ Status = 'Pass'; Text = $text; Affected = @(); RootOk = $true }
}

function ConvertTo-TRGwsResult {
    param($Eval, [ValidateSet('Fail', 'Warning')][string]$FailAs = 'Fail')
    switch ($Eval.Status) {
        'Pass' { New-TRResult Pass $Eval.Text }
        'Fail' { New-TRResult $FailAs $Eval.Text $Eval.Affected }
        default { New-TRResult NotAssessed $Eval.Text }
    }
}

function ConvertTo-TRGwsCtl {
    param($Eval)
    switch ($Eval.Status) {
        'Pass' { New-TRCtl Pass $Eval.Text }
        'Fail' { New-TRCtl Fail $Eval.Text $Eval.Affected }
        default { New-TRCtl NotAssessed $Eval.Text }
    }
}

function Test-TRGwsTrue { param($Value) $Value -eq $true -or [string]$Value -eq 'True' -or [string]$Value -eq 'true' }

function ConvertTo-TRGwsSeconds {
    param($Duration)
    if ($null -eq $Duration) { return $null }
    $s = [string]$Duration
    if ($s -match '^(\d+(?:\.\d+)?)s$') { return [double]$Matches[1] }
    if ($s -match '^(\d+)h$') { return [double]$Matches[1] * 3600 }
    if ($s -match '^(\d+)m$') { return [double]$Matches[1] * 60 }
    if ($s -match '^\d+$') { return [double]$s }
    $null
}

function Format-TRGwsDuration {
    param($Seconds)
    if ($null -eq $Seconds) { return 'not set' }
    $s = [double]$Seconds
    if ($s -eq 0) { return 'never' }
    if ($s % 86400 -eq 0) { return (Format-TRN ([int]($s / 86400)) 'day') }
    if ($s % 3600 -eq 0) { return (Format-TRN ([int]($s / 3600)) 'hour') }
    if ($s % 60 -eq 0) { return (Format-TRN ([int]($s / 60)) 'minute') }
    ('{0} seconds' -f $s)
}

function Get-TRGwsRules {
    param([string]$Type)
    @(@((Get-TRGwsPolicyIndex)[$Type]) | Where-Object { $_ } | ForEach-Object { $_.Value })
}

function Get-TRGwsLogSetting {
    param([string]$Setting)
    $events = @(Get-TRItems 'GwsAdminEvents' | Where-Object { [string]$_.SETTING_NAME -eq $Setting -and $_.Event -in @('CHANGE_APPLICATION_SETTING', 'CREATE_APPLICATION_SETTING', 'DELETE_APPLICATION_SETTING') })
    if (-not $events.Count) { return $null }
    $byScope = @{}
    foreach ($e in ($events | Sort-Object Time)) {
        $scope = if ([string]$e.GROUP_EMAIL) { 'Group ' + [string]$e.GROUP_EMAIL } elseif ([string]$e.ORG_UNIT_NAME) { 'OU ' + [string]$e.ORG_UNIT_NAME } else { 'Whole organisation' }
        $byScope[$scope] = [pscustomobject]@{ Scope = $scope; Value = $(if ($e.Event -eq 'DELETE_APPLICATION_SETTING') { $null } else { [string]$e.NEW_VALUE }); Deleted = ($e.Event -eq 'DELETE_APPLICATION_SETTING'); Time = [string]$e.Time; Actor = [string]$e.Actor }
    }
    $root = Get-TRGwsRootOuName
    $out = foreach ($k in ($byScope.Keys | Sort-Object)) {
        $v = $byScope[$k]
        if ($root -and $v.Scope -eq ('OU ' + $root)) { $v.Scope = 'Whole organisation' }
        $v
    }
    , @($out)
}

function Get-TRGwsRootOuName {
    Get-TRCached 'GwsRootOuName' {
        $root = @(Get-TRItems 'GwsOrgUnits' | Where-Object { [string]$_.orgUnitPath -eq '/' })[0]
        if ($root) { return [string]$root.name }
        $c = Get-TRRawValue 'GwsCustomer'
        if ($c -and $c.postalAddress -and $c.postalAddress.organizationName) { return [string]$c.postalAddress.organizationName }
        $null
    }
}

function Test-TRGwsLogSetting {
    param([string]$Setting, [scriptblock]$Ok, [string]$Good, [string]$Bad, [bool]$DefaultOk, [string]$DefaultText)
    $vals = Get-TRGwsLogSetting $Setting
    if ($null -eq $vals -or -not @($vals).Count) {
        $t = 'No change to this setting was found in the admin audit log for the last 180 days, so the Google default applies'
        if ($DefaultText) { $t += ': ' + $DefaultText }
        return [pscustomobject]@{ Status = $(if ($DefaultOk) { 'Pass' } else { 'Fail' }); Text = $t + '.'; Affected = @(); RootOk = $DefaultOk }
    }
    $badVals = @($vals | Where-Object { -not $_.Deleted -and -not [bool](& $Ok $_.Value) })
    $rootDel = @($vals | Where-Object { $_.Scope -eq 'Whole organisation' -and $_.Deleted })
    if ($rootDel.Count -and -not $DefaultOk) { $badVals += $rootDel[0] }
    $cap = { param($t) if ($t) { $t.Substring(0, 1).ToUpper() + $t.Substring(1) } else { $t } }
    if ($badVals.Count) {
        $aff = @($badVals | ForEach-Object { New-TRAffected $_.Scope ('Last changed ' + (Format-TRDate $_.Time) + ' by ' + $_.Actor) })
        $rootBad = @($badVals | Where-Object { $_.Scope -eq 'Whole organisation' })
        $others = @($badVals | Where-Object { $_.Scope -ne 'Whole organisation' })
        if ($rootBad.Count) {
            $text = '{0} for the whole organisation (admin audit log, changed {1} by {2}).' -f (& $cap $Bad), (Format-TRDate $rootBad[0].Time), $rootBad[0].Actor
            if ($others.Count) { $text += (' Also in {0}: {1}.' -f (Format-TRN $others.Count 'override'), (Join-TRList ($others | ForEach-Object { $_.Scope }) 4)) }
        }
        else { $text = '{0} in {1} (from the admin audit log): {2}.' -f (& $cap $Bad), (Format-TRN $others.Count 'override'), (Join-TRList ($others | ForEach-Object { $_.Scope }) 4) }
        return [pscustomobject]@{ Status = 'Fail'; Text = $text; Affected = $aff; RootOk = ($rootBad.Count -eq 0) }
    }
    [pscustomobject]@{ Status = 'Pass'; Text = ((& $cap $Good) + ' (from the admin audit log).'); Affected = @(); RootOk = $true }
}

function Get-TRGwsFeatureUserCount {
    param([string[]]$Capabilities)
    $skus = @{}
    foreach ($c in $Capabilities) { foreach ($s in @($script:TRGwsCapabilities[$c])) { $skus[$s] = $true } }
    $users = Get-TRGwsUserIndex
    $n = 0
    $lic = Get-TRGwsUserLicences
    foreach ($k in $lic.Keys) {
        $u = $users[$k]
        if ($u -and ($u.suspended -or $u.archived)) { continue }
        if (@($lic[$k] | Where-Object { $skus.ContainsKey($_) }).Count) { $n++ }
    }
    $n
}

function Get-TRGwsFeatureSkus {
    param([string[]]$Capabilities)
    $skus = @{}
    foreach ($c in $Capabilities) { foreach ($s in @($script:TRGwsCapabilities[$c])) { $skus[$s] = $true } }
    $have = Get-TRGwsSkuCounts
    (@($have.Keys | Where-Object { $skus.ContainsKey($_) } | ForEach-Object { Get-TRGwsSkuName $_ } | Sort-Object -Unique) -join ', ')
}
