$script:TRRaw = $null
$script:TRDiag = $null

$script:TRAreas = [ordered]@{
    Identity           = 'Identity and access'
    Applications       = 'Applications and consents'
    Licensing          = 'Licensing'
    Exchange           = 'Exchange Online and email security'
    Dns                = 'Email DNS (SPF, DKIM, DMARC)'
    Collaboration      = 'SharePoint, OneDrive and Teams'
    Intune             = 'Intune and devices'
    Defender           = 'Microsoft Defender XDR'
    Purview            = 'Microsoft Purview'
    SecureScore        = 'Microsoft Secure Score'
    Opportunities      = 'Licence utilisation opportunities'
    Benchmarks         = 'CIS v7 and CISA SCuBA benchmarks'
    ServiceSettings    = 'Teams, SharePoint, Power BI and Power Platform settings'
    MailboxPermissions = 'Mailbox permissions'
    GroupMembership    = 'Group, Team and site membership'
    SharingAudit       = 'Sharing activity from audit log (30 days)'
    Azure              = 'Azure subscriptions and resources'
    Servers            = 'Servers (imported server data)'
}

$script:TRDefaultAreas = @('Identity', 'Applications', 'Licensing', 'Exchange', 'Dns', 'Collaboration', 'Intune', 'Defender', 'Purview', 'SecureScore', 'Opportunities', 'Benchmarks', 'ServiceSettings', 'MailboxPermissions', 'GroupMembership', 'Azure')

$script:TRPlanSets = @{
    P1               = @('AAD_PREMIUM', 'AAD_PREMIUM_P2')
    P2               = @('AAD_PREMIUM_P2')
    Intune           = @('INTUNE_A', 'INTUNE_SMBIZ', 'INTUNE_EDU', 'INTUNE_A_VL')
    DefenderO365     = @('ATP_ENTERPRISE', 'THREAT_INTELLIGENCE')
    DefenderO365P2   = @('THREAT_INTELLIGENCE')
    DefenderEndpoint = @('WINDEFATP', 'MDE_SMB', 'MDE_LITE', 'DEFENDER_ENDPOINT_P1')
    DefenderIdentity = @('ATA')
    DefenderCloudApps = @('ADALLOM_S_STANDALONE', 'ADALLOM_S_O365')
    Exchange         = @('EXCHANGE_S_STANDARD', 'EXCHANGE_S_ENTERPRISE', 'EXCHANGE_S_DESKLESS')
    ExchangeArchive  = @('EXCHANGE_S_ARCHIVE_ADDON', 'EXCHANGE_S_ENTERPRISE')
    SharePoint       = @('SHAREPOINTSTANDARD', 'SHAREPOINTENTERPRISE')
    Teams            = @('TEAMS1')
    TeamsPhone       = @('MCOEV')
    OfficeApps       = @('OFFICESUBSCRIPTION', 'OFFICE_BUSINESS')
    UniversalPrint   = @('UNIVERSAL_PRINT_01')
    Copilot          = @('M365_COPILOT_APPS', 'M365_COPILOT_TEAMS', 'M365_COPILOT_BUSINESS_CHAT', 'SKU:Microsoft_365_Copilot')
    InfoProtection   = @('MIP_S_CLP1', 'MIP_S_CLP2', 'RMS_S_PREMIUM', 'RMS_S_PREMIUM2')
    AutoLabelling    = @('MIP_S_CLP2')
    Dlp              = @('BPOS_S_DlpAddOn', 'EXCHANGE_S_ENTERPRISE', 'MIP_S_CLP1', 'MIP_S_CLP2')
    EndpointDlp      = @('MICROSOFTENDPOINTDLP')
    Retention        = @('EXCHANGE_S_STANDARD', 'EXCHANGE_S_ENTERPRISE', 'EXCHANGE_S_ARCHIVE_ADDON', 'SHAREPOINTSTANDARD', 'SHAREPOINTENTERPRISE')
    EdiscoveryPremium = @('EQUIVIO_ANALYTICS')
    InsiderRisk      = @('INSIDER_RISK', 'INSIDER_RISK_MANAGEMENT')
    AuditPremium     = @('M365_ADVANCED_AUDITING')
    CustomerLockbox  = @('LOCKBOX_ENTERPRISE')
    ComplianceE5     = @('MIP_S_CLP2', 'MICROSOFTENDPOINTDLP', 'INSIDER_RISK', 'M365_ADVANCED_AUDITING')
}

$script:TRMicrosoftTenants = @('f8cdef31-a31e-4b4a-93e4-5f571e91255a', '72f988bf-86f1-41af-91ab-2d7cd011db47', '33e01921-4d64-4f8c-a055-5bdaffd5e33d', 'cdc5aeea-15c5-4db6-b079-fcadd2505dc2')

function Add-TRDiag {
    param([string]$Area, [string]$Key, [string]$Status, [int]$Count = 0, [string]$Message = '', [int]$Ms = 0, [int]$Http = 0)
    [void]$script:TRDiag.Add([pscustomobject][ordered]@{
            Area       = $Area
            Item       = $Key
            Status     = $Status
            Count      = $Count
            HttpStatus = $Http
            Message    = $Message
            DurationMs = $Ms
        })
}

function Invoke-TRStep {
    param(
        [Parameter(Mandatory = $true)][string]$Area,
        [Parameter(Mandatory = $true)][string]$Key,
        [Parameter(Mandatory = $true)][scriptblock]$Script,
        [switch]$List,
        [switch]$Optional
    )
    Test-TRCancelled
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try {
        if ($List) {
            $out = New-Object System.Collections.ArrayList
            foreach ($o in @(& $Script)) {
                if ($null -eq $o) { continue }
                if ($o -is [System.Array]) {
                    foreach ($i in $o) { if ($null -ne $i) { [void]$out.Add($i) } }
                }
                else { [void]$out.Add($o) }
            }
            $data = $out.ToArray()
            $count = $data.Count
        }
        else {
            $data = & $Script
            if ($data -is [System.Array] -and $data.Count -eq 1) { $data = $data[0] }
            $count = if ($null -eq $data) { 0 } else { 1 }
        }
        $script:TRRaw[$Key] = $data
        Add-TRDiag -Area $Area -Key $Key -Status 'OK' -Count $count -Ms $sw.ElapsedMilliseconds
        Write-TRLog ("Collected {0} ({1})" -f $Key, $count)
        return $true
    }
    catch {
        if ($_.Exception.Message -eq 'Operation cancelled by user.') { throw }
        $script:TRRaw[$Key] = $null
        $http = 0
        try { $http = [int]$_.Exception.Data['HttpStatus'] } catch { }
        $status = if ($Optional) { 'Unavailable' } else { 'Failed' }
        Add-TRDiag -Area $Area -Key $Key -Status $status -Message $_.Exception.Message -Ms $sw.ElapsedMilliseconds -Http $http
        $level = if ($Optional) { 'Info' } else { 'Warn' }
        Write-TRLog ("{0}: {1}" -f $Key, $_.Exception.Message) $level
        return $false
    }
}

function Skip-TRStep {
    param([string]$Area, [string[]]$Keys, [string]$Reason)
    foreach ($k in $Keys) {
        $script:TRRaw[$k] = $null
        Add-TRDiag -Area $Area -Key $k -Status 'Skipped' -Message $Reason
    }
}

function Select-TRProps {
    param([Parameter(ValueFromPipeline = $true)]$InputObject, [string[]]$Property)
    process {
        if ($null -ne $InputObject) { $InputObject | Select-Object -Property $Property }
    }
}

function Test-TRCollectPlan {
    param([string[]]$Plans)
    $skus = @($script:TRRaw['SubscribedSkus'] | Where-Object { $null -ne $_ })
    if (-not $script:TRRaw.Contains('SubscribedSkus') -or $null -eq $script:TRRaw['SubscribedSkus']) { return $true }
    foreach ($s in $skus) {
        if ([string]$s.capabilityStatus -notin @('Enabled', 'Warning')) { continue }
        if ($Plans -contains ('SKU:' + [string]$s.skuPartNumber)) { return $true }
        foreach ($p in @($s.servicePlans)) {
            if ($p -and $Plans -contains [string]$p.servicePlanName) { return $true }
        }
    }
    $false
}

function Get-TRLocationText {
    param($Value)
    $names = foreach ($v in @($Value)) {
        if ($null -eq $v) { continue }
        if ($v -is [string]) { $v; continue }
        foreach ($n in 'Name', 'DisplayName', 'ImmutableIdentity', 'Identity') {
            if ((Test-TRHasProperty $v $n) -and $v.$n) { [string]$v.$n; break }
        }
    }
    $names = @($names | Where-Object { $_ })
    if ($names -contains 'All') { return 'All' }
    ($names -join '; ')
}

function ConvertTo-TRSccPolicy {
    param($Policy)
    $p = $Policy
    $o = [ordered]@{}
    foreach ($k in 'Name', 'Guid', 'Identity', 'Mode', 'Enabled', 'Workload', 'Type', 'DistributionStatus', 'Priority', 'WhenCreatedUTC', 'WhenChangedUTC', 'IsAdaptivePolicy', 'Labels', 'ApplySensitivityLabel', 'Settings', 'EnforcementPlanes') {
        $o[$k] = $(if (Test-TRHasProperty $p $k) { $p.$k } else { $null })
    }
    foreach ($loc in 'ExchangeLocation', 'SharePointLocation', 'OneDriveLocation', 'ModernGroupLocation', 'TeamsChannelLocation', 'TeamsChatLocation', 'TeamsLocation', 'TeamsLocationException', 'EndpointDlpLocation', 'PublicFolderLocation', 'SkypeLocation', 'LocationInclusions', 'LocationExclusions') {
        $o[$loc] = $(if (Test-TRHasProperty $p $loc) { Get-TRLocationText $p.$loc } else { '' })
    }
    [pscustomobject]$o
}

$script:TRAuditActions = [ordered]@{
    AuditAdmin    = @('ApplyRecord', 'Copy', 'Create', 'FolderBind', 'HardDelete', 'MailItemsAccessed', 'Move', 'MoveToDeletedItems', 'SendAs', 'SendOnBehalf', 'Send', 'SoftDelete', 'Update', 'UpdateCalendarDelegation', 'UpdateFolderPermissions', 'UpdateInboxRules')
    AuditDelegate = @('ApplyRecord', 'Create', 'FolderBind', 'HardDelete', 'Move', 'MailItemsAccessed', 'MoveToDeletedItems', 'SendAs', 'SendOnBehalf', 'SoftDelete', 'Update', 'UpdateFolderPermissions', 'UpdateInboxRules')
    AuditOwner    = @('ApplyRecord', 'Create', 'HardDelete', 'MailboxLogin', 'Move', 'MailItemsAccessed', 'MoveToDeletedItems', 'Send', 'SoftDelete', 'Update', 'UpdateCalendarDelegation', 'UpdateFolderPermissions', 'UpdateInboxRules')
}

function Get-TRAuditGaps {
    param($Mailbox)
    if ([string]$Mailbox.RecipientTypeDetails -ne 'UserMailbox') { return $null }
    $gaps = @()
    foreach ($k in $script:TRAuditActions.Keys) {
        if (-not (Test-TRHasProperty $Mailbox $k)) { return $null }
        $have = @(@($Mailbox.$k) | ForEach-Object { [string]$_ })
        $missing = @($script:TRAuditActions[$k] | Where-Object { $have -notcontains $_ })
        if ($missing.Count) { $gaps += ('{0}: {1}' -f ($k -replace '^Audit', ''), ($missing -join ', ')) }
    }
    ($gaps -join '; ')
}

function ConvertTo-TRDlpRule {
    param($Rule)
    $types = New-Object System.Collections.ArrayList
    $stack = New-Object System.Collections.Stack
    if (Test-TRHasProperty $Rule 'ContentContainsSensitiveInformation') { $stack.Push($Rule.ContentContainsSensitiveInformation) }
    $guard = 0
    while ($stack.Count -and $guard -lt 5000) {
        $guard++
        $o = $stack.Pop()
        if ($null -eq $o -or $o -is [string]) { continue }
        if ($o -is [System.Collections.IDictionary]) {
            foreach ($k in @($o.Keys)) {
                if ([string]$k -eq 'name' -and $o[$k] -is [string]) { [void]$types.Add([string]$o[$k]) }
                elseif ($null -ne $o[$k] -and $o[$k] -isnot [string]) { $stack.Push($o[$k]) }
            }
            continue
        }
        if ($o -is [System.Collections.IEnumerable]) { foreach ($i in $o) { $stack.Push($i) }; continue }
        foreach ($p in $o.PSObject.Properties) {
            if ($p.Name -eq 'name' -and $p.Value -is [string]) { [void]$types.Add([string]$p.Value) }
            elseif ($null -ne $p.Value -and $p.Value -isnot [string] -and $p.Value -isnot [ValueType]) { $stack.Push($p.Value) }
        }
    }
    $adv = if (Test-TRHasProperty $Rule 'AdvancedRule') { [string]$Rule.AdvancedRule } else { '' }
    foreach ($m in [regex]::Matches($adv, '"[Nn]ame"\s*:\s*"([^"]+)"')) { [void]$types.Add($m.Groups[1].Value) }
    $o = [ordered]@{}
    foreach ($k in 'Name', 'ParentPolicyName', 'Policy', 'Disabled', 'Mode', 'BlockAccess', 'BlockAccessScope', 'NotifyUser', 'NotifyPolicyTipCustomText', 'GenerateAlert', 'GenerateIncidentReport', 'ReportSeverityLevel', 'AccessScope') {
        $o[$k] = $(if (Test-TRHasProperty $Rule $k) { $Rule.$k } else { $null })
    }
    $o['SensitiveTypes'] = ((@($types | Select-Object -Unique)) -join '; ')
    [pscustomobject]$o
}

function Get-TRFirst {
    param($Value)
    if ($null -eq $Value) { return $null }
    if (Test-TRHasProperty $Value 'value') { return @($Value.value)[0] }
    if ($Value -is [System.Array]) { return $Value[0] }
    $Value
}

function Invoke-TRCollectIdentity {
    Set-TRProgress 6 'Collecting tenant and directory data'
    Invoke-TRStep 'Identity' 'Organization' { Get-TRFirst (Invoke-TRGraph -Path '/organization') } | Out-Null
    Invoke-TRStep 'Identity' 'Domains' -List { Invoke-TRGraph -Path '/domains' -All } | Out-Null
    Invoke-TRStep 'Identity' 'Users' -List {
        $sel = 'id,displayName,userPrincipalName,userType,accountEnabled,createdDateTime,assignedLicenses,onPremisesSyncEnabled,mail,passwordPolicies,lastPasswordChangeDateTime,externalUserState,usageLocation,jobTitle,department'
        try {
            $u = Invoke-TRGraph -Path ('/users?$select={0},signInActivity&$top=500' -f $sel) -All
            $script:TRRaw['Meta']['SignInActivity'] = $true
            $u
        }
        catch {
            Write-TRLog ('Sign-in activity not available (' + $_.Exception.Message + '). Inactive account checks will be limited.') 'Info'
            $script:TRRaw['Meta']['SignInActivity'] = $false
            $u = Invoke-TRGraph -Path ('/users?$select={0}&$top=999' -f $sel) -All
            $u
        }
    } | Out-Null
    Set-TRProgress 12 'Collecting authentication and Conditional Access data'
    Invoke-TRStep 'Identity' 'RegistrationDetails' -List { Invoke-TRGraph -Path '/reports/authenticationMethods/userRegistrationDetails' -All } | Out-Null
    Invoke-TRStep 'Identity' 'SecurityDefaults' { Invoke-TRGraph -Path '/policies/identitySecurityDefaultsEnforcementPolicy' } | Out-Null
    Invoke-TRStep 'Identity' 'ConditionalAccessPolicies' -List { Invoke-TRGraph -Path '/identity/conditionalAccess/policies' -All } | Out-Null
    Invoke-TRStep 'Identity' 'NamedLocations' -List -Optional { Invoke-TRGraph -Path '/identity/conditionalAccess/namedLocations' -All } | Out-Null
    Invoke-TRStep 'Identity' 'AuthorizationPolicy' { Get-TRFirst (Invoke-TRGraph -Path '/policies/authorizationPolicy') } | Out-Null
    Invoke-TRStep 'Identity' 'AuthMethodsPolicy' { Invoke-TRGraph -Path '/policies/authenticationMethodsPolicy' } | Out-Null
    Invoke-TRStep 'Identity' 'AdminConsentPolicy' -Optional { Invoke-TRGraph -Path '/policies/adminConsentRequestPolicy' } | Out-Null
    Invoke-TRStep 'Identity' 'DeviceRegistrationPolicy' -Optional { Invoke-TRGraph -Path '/policies/deviceRegistrationPolicy' -Beta } | Out-Null
    Invoke-TRStep 'Identity' 'GroupSettings' -List -Optional { Invoke-TRGraph -Path '/groupSettings' -All } | Out-Null
    Invoke-TRStep 'Identity' 'OnPremSync' -Optional { Get-TRFirst (Invoke-TRGraph -Path '/directory/onPremisesSynchronization' -Beta) } | Out-Null
    Set-TRProgress 18 'Collecting administrative roles'
    Invoke-TRStep 'Identity' 'RoleDefinitions' -List {
        try { Invoke-TRGraph -Path '/roleManagement/directory/roleDefinitions?$select=id,displayName,templateId,isBuiltIn,isPrivileged' -All }
        catch { Invoke-TRGraph -Path '/roleManagement/directory/roleDefinitions?$select=id,displayName,templateId,isBuiltIn' -All }
    } | Out-Null
    Invoke-TRStep 'Identity' 'RoleAssignments' -List { Invoke-TRGraph -Path '/roleManagement/directory/roleAssignments?$expand=principal' -All } | Out-Null
    Invoke-TRStep 'Identity' 'RoleEligibility' -List -Optional { Invoke-TRGraph -Path '/roleManagement/directory/roleEligibilitySchedules?$expand=principal' -All } | Out-Null
    Invoke-TRStep 'Identity' 'RiskyUsers' -List -Optional { Invoke-TRGraph -Path "/identityProtection/riskyUsers?`$filter=riskState%20eq%20'atRisk'" -All } | Out-Null
    Invoke-TRStep 'Identity' 'Devices' -List { Invoke-TRGraph -Path '/devices?$select=id,deviceId,displayName,operatingSystem,operatingSystemVersion,trustType,isCompliant,isManaged,approximateLastSignInDateTime,accountEnabled,registrationDateTime&$top=999' -All } | Out-Null
}

$script:TRPimRoleTemplates = [ordered]@{
    '62e90394-69f5-4237-9190-012177145e10' = 'Global Administrator'
    'e8611ab8-c189-46e8-94e1-60213ab1f814' = 'Privileged Role Administrator'
    'fe930be7-5e62-47db-91af-98c3a49a38b1' = 'User Administrator'
    'f28a1f50-f6e7-4571-818b-6a12f2af6b6c' = 'SharePoint Administrator'
    '29232cdf-9323-42fd-ade2-1d097af3e4de' = 'Exchange Administrator'
    '8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2' = 'Hybrid Identity Administrator'
    '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3' = 'Application Administrator'
    '158c047a-c907-4556-b7ef-446551a6b5f7' = 'Cloud Application Administrator'
}

function Get-TRLegacyB2BPolicy {
    $all = Invoke-TRGraph -Path '/legacy/policies' -Beta -All
    $p = $null
    foreach ($x in @($all)) {
        if ($x -and ([string]$x.type -eq 'B2BManagementPolicy' -or [string]$x.displayName -eq 'B2BManagementPolicy')) { $p = $x; break }
    }
    if (-not $p) { return [pscustomobject][ordered]@{ Present = $false; AllowedDomains = $null; BlockedDomains = $null } }
    $def = @($p.definition)[0]
    if ($def -is [string]) { $def = ConvertFrom-Json -InputObject $def }
    $d = $def.B2BManagementPolicy.InvitationsAllowedAndBlockedDomainsPolicy
    [pscustomobject][ordered]@{
        Present        = $true
        AllowedDomains = $(if ($d -and (Test-TRHasProperty $d 'AllowedDomains')) { @($d.AllowedDomains | ForEach-Object { [string]$_ }) } else { $null })
        BlockedDomains = $(if ($d -and (Test-TRHasProperty $d 'BlockedDomains')) { @($d.BlockedDomains | ForEach-Object { [string]$_ }) } else { $null })
    }
}

function Invoke-TRCollectBenchmarkData {
    Set-TRProgress 20 'Collecting settings used by the CIS and SCuBA benchmarks'
    Invoke-TRStep 'Benchmarks' 'DefaultAppMgmtPolicy' -Optional { Invoke-TRGraph -Path '/policies/defaultAppManagementPolicy' } | Out-Null
    Invoke-TRStep 'Benchmarks' 'ActivityTimeoutPolicies' -List -Optional { Invoke-TRGraph -Path '/policies/activityBasedTimeoutPolicies' -All } | Out-Null
    Invoke-TRStep 'Benchmarks' 'AuthMethodsPolicyBeta' -Optional { Invoke-TRGraph -Path '/policies/authenticationMethodsPolicy' -Beta } | Out-Null
    Invoke-TRStep 'Benchmarks' 'ConditionalAccessBeta' -List -Optional { Invoke-TRGraph -Path '/identity/conditionalAccess/policies' -Beta -All } | Out-Null
    Invoke-TRStep 'Benchmarks' 'B2BManagementPolicy' -Optional { Get-TRLegacyB2BPolicy } | Out-Null
    Invoke-TRStep 'Benchmarks' 'AppsAndServicesSettings' -Optional {
        try { Invoke-TRGraph -Path '/admin/appsAndServices/settings' -Beta }
        catch { (Invoke-TRGraph -Path '/admin/appsAndServices' -Beta).settings }
    } | Out-Null
    Invoke-TRStep 'Benchmarks' 'FormsSettings' -Optional {
        try { Invoke-TRGraph -Path '/admin/forms/settings' -Beta }
        catch { (Invoke-TRGraph -Path '/admin/forms' -Beta).settings }
    } | Out-Null
    if (Test-TRCollectPlan $script:TRPlanSets.P2) {
        Invoke-TRStep 'Benchmarks' 'RoleAssignmentInstances' -List -Optional {
            $instances = Invoke-TRGraph -Path '/roleManagement/directory/roleAssignmentScheduleInstances?$expand=principal' -All
            foreach ($i in @($instances)) {
                if ($null -eq $i) { continue }
                $pr = $i.principal
                [pscustomobject][ordered]@{
                    RoleDefinitionId = [string]$i.roleDefinitionId
                    PrincipalId      = [string]$i.principalId
                    PrincipalName    = $(if ($pr) { [string]$pr.displayName } else { '' })
                    PrincipalUpn     = $(if ($pr -and $pr.userPrincipalName) { [string]$pr.userPrincipalName } elseif ($pr -and $pr.appId) { [string]$pr.appId } else { '' })
                    PrincipalType    = $(if ($pr) { ([string]$pr.'@odata.type') -replace '^#microsoft\.graph\.', '' } else { '' })
                    AssignmentType   = [string]$i.assignmentType
                    MemberType       = [string]$i.memberType
                    StartDateTime    = $i.startDateTime
                    EndDateTime      = $i.endDateTime
                    Scope            = [string]$i.directoryScopeId
                }
            }
        } | Out-Null
        Invoke-TRStep 'Benchmarks' 'RoleManagementPolicies' -List -Optional {
            foreach ($t in $script:TRPimRoleTemplates.Keys) {
                $filter = [uri]::EscapeDataString("scopeId eq '/' and scopeType eq 'DirectoryRole' and roleDefinitionId eq '$t'")
                $list = Invoke-TRGraph -Path ('/policies/roleManagementPolicyAssignments?$filter={0}&$expand=policy($expand=rules)' -f $filter) -All
                $a = @($list | Where-Object { $null -ne $_ })[0]
                if (-not $a) { continue }
                [pscustomobject][ordered]@{
                    RoleTemplate = $t
                    RoleName     = $script:TRPimRoleTemplates[$t]
                    PolicyId     = [string]$a.policyId
                    Rules        = @($a.policy.rules)
                }
            }
        } | Out-Null
        Invoke-TRStep 'Benchmarks' 'AccessReviewDefinitions' -List -Optional { Invoke-TRGraph -Path '/identityGovernance/accessReviews/definitions' -All } | Out-Null
    }
    else { Skip-TRStep 'Benchmarks' @('RoleAssignmentInstances', 'RoleManagementPolicies', 'AccessReviewDefinitions') 'Entra ID P2 is not licensed.' }
}

function Invoke-TRCollectLicensing {
    Set-TRProgress 22 'Collecting licences'
    Invoke-TRStep 'Licensing' 'SubscribedSkus' -List { Invoke-TRGraph -Path '/subscribedSkus' -All } | Out-Null
}

function Invoke-TRCollectApplications {
    Set-TRProgress 26 'Collecting applications and consents'
    Invoke-TRStep 'Applications' 'ServicePrincipals' -List { Invoke-TRGraph -Path '/servicePrincipals?$select=id,appId,displayName,appOwnerOrganizationId,servicePrincipalType,accountEnabled,tags,publisherName,verifiedPublisher&$top=999' -All } | Out-Null
    Invoke-TRStep 'Applications' 'OAuth2Grants' -List { Invoke-TRGraph -Path '/oauth2PermissionGrants' -All } | Out-Null
    Invoke-TRStep 'Applications' 'Applications' -List { Invoke-TRGraph -Path '/applications?$select=id,appId,displayName,passwordCredentials,keyCredentials,signInAudience,createdDateTime&$top=999' -All } | Out-Null
    Invoke-TRStep 'Applications' 'AppPermissions' -List {
        $resources = [ordered]@{
            '00000003-0000-0000-c000-000000000000' = 'Microsoft Graph'
            '00000002-0000-0ff1-ce00-000000000000' = 'Office 365 Exchange Online'
            '00000003-0000-0ff1-ce00-000000000000' = 'Office 365 SharePoint Online'
        }
        $rows = New-Object System.Collections.ArrayList
        foreach ($appId in $resources.Keys) {
            try {
                $sp = Invoke-TRGraph -Path ("/servicePrincipals(appId='{0}')?`$select=id,appId,displayName,appRoles" -f $appId)
            }
            catch { continue }
            $roleMap = @{}
            foreach ($r in @($sp.appRoles)) { if ($r) { $roleMap[[string]$r.id] = [string]$r.value } }
            $assigned = Invoke-TRGraph -Path ('/servicePrincipals/{0}/appRoleAssignedTo?$top=999' -f $sp.id) -All
            foreach ($a in $assigned) {
                $perm = $roleMap[[string]$a.appRoleId]
                if (-not $perm) { $perm = [string]$a.appRoleId }
                [void]$rows.Add([pscustomobject][ordered]@{
                        ClientId        = $a.principalId
                        ClientName      = $a.principalDisplayName
                        PrincipalType   = $a.principalType
                        Resource        = $resources[$appId]
                        Permission      = $perm
                        CreatedDateTime = $a.createdDateTime
                    })
            }
        }
        $rows.ToArray()
    } | Out-Null
}

function Invoke-TRCollectExchange {
    param([switch]$IncludePermissions, [switch]$IncludeConfig)
    Set-TRProgress 32 'Connecting to Exchange Online'
    $exoKeys = @('ExoOrganizationConfig', 'ExoAdminAuditLogConfig', 'ExoTransportConfig', 'ExoMailboxes', 'ExoCasMailboxes', 'ExoRemoteDomains', 'ExoOutboundSpamPolicies', 'ExoContentFilterPolicies', 'ExoMalwarePolicies', 'ExoAntiPhishPolicies', 'ExoSafeLinksPolicies', 'ExoSafeLinksRules', 'ExoSafeAttachmentPolicies', 'ExoSafeAttachmentRules', 'ExoAtpPolicy', 'ExoPresetEop', 'ExoPresetAtp', 'ExoDkim', 'ExoTransportRules', 'ExoInboundConnectors', 'ExoOutboundConnectors', 'ExoSharingPolicies', 'ExoOwaPolicies', 'ExoExternalInOutlook', 'ExoReportSubmissionPolicy', 'ExoAcceptedDomains', 'ExoConnectionFilter', 'ExoAntiPhishRules', 'ExoMalwareRules', 'ExoContentFilterRules', 'ExoRoleAssignmentPolicies', 'ExoAuditBypass', 'ExoTeamsProtection', 'ExoTeamsProtectionRules', 'ExoEmailTenantSettings', 'MailboxUsage')
    $ok = Invoke-TRStep 'Exchange' 'ExoOrganizationConfig' {
        (Invoke-TRExo -Cmdlet 'Get-OrganizationConfig')[0] | Select-TRProps -Property Name, DisplayName, AuditDisabled, OAuth2ClientProfileEnabled, CustomerLockBoxEnabled, MailTipsExternalRecipientsTipsEnabled, MailTipsAllTipsEnabled, MailTipsGroupMetricsEnabled, MailTipsLargeAudienceThreshold, BookingsEnabled, RejectDirectSend, IsDehydrated, AutoExpandingArchiveEnabled, EwsEnabled, DefaultAuthenticationPolicy
    }
    if (-not $ok) {
        $reason = 'Exchange Online connection failed. See ExoOrganizationConfig for the error.'
        Write-TRLog 'Exchange Online is not reachable with this sign-in. Exchange checks will be marked Not assessed.' 'Warn'
        Skip-TRStep 'Exchange' ($exoKeys | Where-Object { $_ -ne 'ExoOrganizationConfig' -and $_ -ne 'MailboxUsage' }) $reason
        if ($IncludePermissions) { Skip-TRStep 'MailboxPermissions' @('MailboxPermissions') $reason }
        $script:TRRaw['Meta']['ExchangeAvailable'] = $false
    }
    else {
        $script:TRRaw['Meta']['ExchangeAvailable'] = $true
        Invoke-TRStep 'Exchange' 'ExoMailboxes' -List {
            foreach ($m in (Invoke-TRExo -Cmdlet 'Get-Mailbox' -Parameters @{ ResultSize = 'Unlimited' })) {
                if ($null -eq $m) { continue }
                $row = $m | Select-Object -Property Identity, Name, Alias, DisplayName, UserPrincipalName, PrimarySmtpAddress, RecipientTypeDetails, ForwardingSmtpAddress, ForwardingAddress, DeliverToMailboxAndForward, AuditEnabled, GrantSendOnBehalfTo, LitigationHoldEnabled, ArchiveStatus, ExternalDirectoryObjectId, WhenCreated, HiddenFromAddressListsEnabled
                $row | Add-Member -NotePropertyName AuditGaps -NotePropertyValue (Get-TRAuditGaps $m)
                $row
            }
        } | Out-Null
        if ($IncludeConfig) {
            Set-TRProgress 36 'Collecting Exchange Online configuration'
            Invoke-TRStep 'Exchange' 'ExoAdminAuditLogConfig' { (Invoke-TRExo -Cmdlet 'Get-AdminAuditLogConfig')[0] | Select-TRProps -Property UnifiedAuditLogIngestionEnabled, AdminAuditLogEnabled } | Out-Null
            Invoke-TRStep 'Exchange' 'ExoTransportConfig' { (Invoke-TRExo -Cmdlet 'Get-TransportConfig')[0] | Select-TRProps -Property SmtpClientAuthenticationDisabled, AllowLegacyTLSClients } | Out-Null
            Invoke-TRStep 'Exchange' 'ExoCasMailboxes' -List { Invoke-TRExo -Cmdlet 'Get-CASMailbox' -Parameters @{ ResultSize = 'Unlimited' } | Select-TRProps -Property Name, PrimarySmtpAddress, SmtpClientAuthenticationEnabled, PopEnabled, ImapEnabled, ActiveSyncEnabled, OWAEnabled, MAPIEnabled, EwsEnabled } | Out-Null
            Invoke-TRStep 'Exchange' 'ExoRemoteDomains' -List { Invoke-TRExo -Cmdlet 'Get-RemoteDomain' | Select-TRProps -Property Identity, DomainName, AutoForwardEnabled } | Out-Null
            Invoke-TRStep 'Exchange' 'ExoOutboundSpamPolicies' -List { Invoke-TRExo -Cmdlet 'Get-HostedOutboundSpamFilterPolicy' | Select-TRProps -Property Identity, Name, IsDefault, AutoForwardingMode, RecipientLimitExternalPerHour, RecipientLimitInternalPerHour, RecipientLimitPerDay, ActionWhenThresholdReached, BccSuspiciousOutboundMail, BccSuspiciousOutboundAdditionalRecipients, NotifyOutboundSpam, NotifyOutboundSpamRecipients, RecommendedPolicyType } | Out-Null
            Invoke-TRStep 'Exchange' 'ExoContentFilterPolicies' -List { Invoke-TRExo -Cmdlet 'Get-HostedContentFilterPolicy' | Select-TRProps -Property Identity, Name, IsDefault, BulkThreshold, SpamAction, HighConfidenceSpamAction, PhishSpamAction, HighConfidencePhishAction, BulkSpamAction, QuarantineRetentionPeriod, AllowedSenderDomains, AllowedSenders, InlineSafetyTipsEnabled, SpamZapEnabled, PhishZapEnabled, RecommendedPolicyType } | Out-Null
            Invoke-TRStep 'Exchange' 'ExoMalwarePolicies' -List { Invoke-TRExo -Cmdlet 'Get-MalwareFilterPolicy' | Select-TRProps -Property Identity, Name, IsDefault, EnableFileFilter, FileTypeAction, FileTypes, ZapEnabled, EnableInternalSenderAdminNotifications, InternalSenderAdminAddress, RecommendedPolicyType } | Out-Null
            Invoke-TRStep 'Exchange' 'ExoAntiPhishPolicies' -List { Invoke-TRExo -Cmdlet 'Get-AntiPhishPolicy' | Select-TRProps -Property Identity, Name, IsDefault, Enabled, EnableSpoofIntelligence, EnableFirstContactSafetyTips, EnableUnauthenticatedSender, EnableViaTag, EnableMailboxIntelligence, EnableMailboxIntelligenceProtection, EnableTargetedUserProtection, EnableOrganizationDomainsProtection, EnableTargetedDomainsProtection, PhishThresholdLevel, HonorDmarcPolicy, TargetedUserProtectionAction, TargetedDomainProtectionAction, MailboxIntelligenceProtectionAction, EnableSimilarUsersSafetyTips, EnableSimilarDomainsSafetyTips, EnableUnusualCharactersSafetyTips, TargetedUsersToProtect, TargetedDomainsToProtect, RecommendedPolicyType } | Out-Null
            Invoke-TRStep 'Exchange' 'ExoSafeLinksPolicies' -List -Optional { Invoke-TRExo -Cmdlet 'Get-SafeLinksPolicy' | Select-TRProps -Property Identity, Name, IsBuiltInProtection, EnableSafeLinksForEmail, EnableSafeLinksForTeams, EnableSafeLinksForOffice, TrackClicks, AllowClickThrough, ScanUrls, EnableForInternalSenders, DeliverMessageAfterScan, DisableUrlRewrite, RecommendedPolicyType } | Out-Null
            Invoke-TRStep 'Exchange' 'ExoSafeLinksRules' -List -Optional { Invoke-TRExo -Cmdlet 'Get-SafeLinksRule' | Select-TRProps -Property Name, State, SafeLinksPolicy, Priority, SentTo, SentToMemberOf, RecipientDomainIs } | Out-Null
            Invoke-TRStep 'Exchange' 'ExoSafeAttachmentPolicies' -List -Optional { Invoke-TRExo -Cmdlet 'Get-SafeAttachmentPolicy' | Select-TRProps -Property Identity, Name, IsBuiltInProtection, Enable, Action, Redirect, QuarantineTag, RecommendedPolicyType } | Out-Null
            Invoke-TRStep 'Exchange' 'ExoSafeAttachmentRules' -List -Optional { Invoke-TRExo -Cmdlet 'Get-SafeAttachmentRule' | Select-TRProps -Property Name, State, SafeAttachmentPolicy, Priority, SentTo, SentToMemberOf, RecipientDomainIs } | Out-Null
            Invoke-TRStep 'Exchange' 'ExoAtpPolicy' -Optional { (Invoke-TRExo -Cmdlet 'Get-AtpPolicyForO365')[0] | Select-TRProps -Property EnableATPForSPOTeamsODB, EnableSafeDocs, AllowSafeDocsOpen } | Out-Null
            Invoke-TRStep 'Exchange' 'ExoPresetEop' -List -Optional { Invoke-TRExo -Cmdlet 'Get-EOPProtectionPolicyRule' | Select-TRProps -Property Name, State, Identity, SentTo, SentToMemberOf, RecipientDomainIs } | Out-Null
            Invoke-TRStep 'Exchange' 'ExoPresetAtp' -List -Optional { Invoke-TRExo -Cmdlet 'Get-ATPProtectionPolicyRule' | Select-TRProps -Property Name, State, Identity, SentTo, SentToMemberOf, RecipientDomainIs } | Out-Null
            Invoke-TRStep 'Exchange' 'ExoDkim' -List { Invoke-TRExo -Cmdlet 'Get-DkimSigningConfig' | Select-TRProps -Property Domain, Enabled, Status, Selector1CNAME, Selector2CNAME } | Out-Null
            Invoke-TRStep 'Exchange' 'ExoTransportRules' -List { Invoke-TRExo -Cmdlet 'Get-TransportRule' | Select-TRProps -Property Name, State, Mode, Priority, SetSCL, RedirectMessageTo, BlindCopyTo, AddToRecipients, CopyTo, SenderDomainIs, SenderIpRanges, Description } | Out-Null
            Invoke-TRStep 'Exchange' 'ExoInboundConnectors' -List -Optional { Invoke-TRExo -Cmdlet 'Get-InboundConnector' | Select-TRProps -Property Name, Enabled, ConnectorType, SenderDomains, RequireTls, RestrictDomainsToIPAddresses, SenderIPAddresses } | Out-Null
            Invoke-TRStep 'Exchange' 'ExoOutboundConnectors' -List -Optional { Invoke-TRExo -Cmdlet 'Get-OutboundConnector' | Select-TRProps -Property Name, Enabled, ConnectorType, RecipientDomains, SmartHosts, TlsSettings, UseMXRecord } | Out-Null
            Invoke-TRStep 'Exchange' 'ExoSharingPolicies' -List -Optional { Invoke-TRExo -Cmdlet 'Get-SharingPolicy' | Select-TRProps -Property Name, Default, Enabled, Domains } | Out-Null
            Invoke-TRStep 'Exchange' 'ExoOwaPolicies' -List -Optional { Invoke-TRExo -Cmdlet 'Get-OwaMailboxPolicy' | Select-TRProps -Property Name, IsDefault, AdditionalStorageProvidersAvailable, BookingsMailboxCreationEnabled, PersonalAccountsEnabled, PersonalAccountCalendarsEnabled } | Out-Null
            Invoke-TRStep 'Exchange' 'ExoExternalInOutlook' -Optional { (Invoke-TRExo -Cmdlet 'Get-ExternalInOutlook')[0] | Select-TRProps -Property Identity, Enabled, AllowList } | Out-Null
            Invoke-TRStep 'Exchange' 'ExoReportSubmissionPolicy' -Optional { (Invoke-TRExo -Cmdlet 'Get-ReportSubmissionPolicy')[0] | Select-TRProps -Property EnableReportToMicrosoft, ReportJunkToCustomizedAddress, ReportNotJunkToCustomizedAddress, ReportPhishToCustomizedAddress, ReportJunkAddresses, ReportNotJunkAddresses, ReportPhishAddresses, ReportChatMessageEnabled, ReportChatMessageToCustomizedAddressEnabled, EnableThirdPartyAddress } | Out-Null
            Invoke-TRStep 'Exchange' 'ExoAcceptedDomains' -List -Optional { Invoke-TRExo -Cmdlet 'Get-AcceptedDomain' | Select-TRProps -Property DomainName, DomainType, Default } | Out-Null
            Invoke-TRStep 'Exchange' 'ExoConnectionFilter' -List -Optional { Invoke-TRExo -Cmdlet 'Get-HostedConnectionFilterPolicy' | Select-TRProps -Property Identity, Name, IsDefault, IPAllowList, IPBlockList, EnableSafeList } | Out-Null
            Invoke-TRStep 'Exchange' 'ExoAntiPhishRules' -List -Optional { Invoke-TRExo -Cmdlet 'Get-AntiPhishRule' | Select-TRProps -Property Name, AntiPhishPolicy, State, Priority, SentTo, SentToMemberOf, RecipientDomainIs } | Out-Null
            Invoke-TRStep 'Exchange' 'ExoMalwareRules' -List -Optional { Invoke-TRExo -Cmdlet 'Get-MalwareFilterRule' | Select-TRProps -Property Name, MalwareFilterPolicy, State, Priority, SentTo, SentToMemberOf, RecipientDomainIs } | Out-Null
            Invoke-TRStep 'Exchange' 'ExoContentFilterRules' -List -Optional { Invoke-TRExo -Cmdlet 'Get-HostedContentFilterRule' | Select-TRProps -Property Name, HostedContentFilterPolicy, State, Priority, SentTo, SentToMemberOf, RecipientDomainIs } | Out-Null
            Invoke-TRStep 'Exchange' 'ExoRoleAssignmentPolicies' -List -Optional { Invoke-TRExo -Cmdlet 'Get-RoleAssignmentPolicy' | Select-TRProps -Property Name, IsDefault, AssignedRoles } | Out-Null
            Invoke-TRStep 'Exchange' 'ExoAuditBypass' -List -Optional {
                $bypass = Invoke-TRExo -Cmdlet 'Get-MailboxAuditBypassAssociation' -Parameters @{ ResultSize = 'Unlimited' }
                foreach ($b in @($bypass)) { if ($b -and $b.AuditBypassEnabled -eq $true) { $b | Select-Object -Property Name, Identity, AuditBypassEnabled } }
            } | Out-Null
            Invoke-TRStep 'Exchange' 'ExoTeamsProtection' -Optional { (Invoke-TRExo -Cmdlet 'Get-TeamsProtectionPolicy')[0] | Select-TRProps -Property Identity, ZapEnabled } | Out-Null
            Invoke-TRStep 'Exchange' 'ExoTeamsProtectionRules' -List -Optional { Invoke-TRExo -Cmdlet 'Get-TeamsProtectionPolicyRule' | Select-TRProps -Property Name, ExceptIfSentTo, ExceptIfSentToMemberOf, ExceptIfRecipientDomainIs } | Out-Null
            Invoke-TRStep 'Exchange' 'ExoEmailTenantSettings' -Optional { (Invoke-TRExo -Cmdlet 'Get-EmailTenantSettings')[0] | Select-TRProps -Property Identity, EnablePriorityAccountProtection } | Out-Null
        }
    }
    if ($IncludeConfig) {
        Invoke-TRStep 'Exchange' 'MailboxUsage' -List -Optional { Invoke-TRGraphReport -Report 'getMailboxUsageDetail' } | Out-Null
    }
}

function Invoke-TRCollectMailboxPermissions {
    param([int]$MaxMailboxes = 3000)
    if (-not $script:TRRaw['Meta']['ExchangeAvailable']) { return }
    Set-TRProgress 44 'Collecting mailbox permissions'
    Invoke-TRStep 'MailboxPermissions' 'MailboxPermissions' -List {
        $rows = New-Object System.Collections.ArrayList
        $mailboxes = @($script:TRRaw['ExoMailboxes'] | Where-Object { $_ -and $_.RecipientTypeDetails -match 'UserMailbox|SharedMailbox|RoomMailbox|EquipmentMailbox' })
        $byAddress = @{}
        foreach ($m in $mailboxes) {
            foreach ($key in @($m.PrimarySmtpAddress, $m.UserPrincipalName, $m.Identity, $m.Name, $m.Alias, $m.DisplayName, $m.ExternalDirectoryObjectId)) {
                if ($key -and -not $byAddress.ContainsKey([string]$key)) { $byAddress[[string]$key] = $m }
            }
            foreach ($d in @($m.GrantSendOnBehalfTo)) {
                if (-not $d) { continue }
                [void]$rows.Add([pscustomobject][ordered]@{ Mailbox = $m.PrimarySmtpAddress; MailboxName = $m.DisplayName; MailboxType = $m.RecipientTypeDetails; Delegate = [string]$d; Permission = 'SendOnBehalf'; Inherited = $false })
            }
        }
        try {
            $sendAs = Invoke-TRExo -Cmdlet 'Get-RecipientPermission' -Parameters @{ ResultSize = 'Unlimited' }
            foreach ($p in $sendAs) {
                if ($p.Trustee -match '^NT AUTHORITY\\SELF$' -or $p.IsInherited) { continue }
                if (@($p.AccessRights) -notcontains 'SendAs') { continue }
                $mb = $byAddress[[string]$p.Identity]
                [void]$rows.Add([pscustomobject][ordered]@{ Mailbox = $(if ($mb) { $mb.PrimarySmtpAddress } else { $p.Identity }); MailboxName = $(if ($mb) { $mb.DisplayName } else { $p.Identity }); MailboxType = $(if ($mb) { $mb.RecipientTypeDetails } else { '' }); Delegate = [string]$p.Trustee; Permission = 'SendAs'; Inherited = $false })
            }
        }
        catch { Write-TRLog ('Send As permissions could not be read: ' + $_.Exception.Message) 'Warn' }
        $i = 0
        $total = [Math]::Min($mailboxes.Count, $MaxMailboxes)
        foreach ($m in ($mailboxes | Select-Object -First $MaxMailboxes)) {
            $i++
            if ($i % 25 -eq 0) {
                Set-TRProgress (44 + [int](10 * $i / [Math]::Max($total, 1))) ("Mailbox permissions {0} of {1}" -f $i, $total)
                Test-TRCancelled
            }
            try {
                $perms = Invoke-TRExo -Cmdlet 'Get-MailboxPermission' -Parameters @{ Identity = [string]$m.PrimarySmtpAddress }
                foreach ($p in $perms) {
                    if ($p.IsInherited -or $p.Deny) { continue }
                    if ([string]$p.User -match '^NT AUTHORITY\\SELF$|^S-1-5-10$') { continue }
                    if (@($p.AccessRights) -notcontains 'FullAccess') { continue }
                    [void]$rows.Add([pscustomobject][ordered]@{ Mailbox = $m.PrimarySmtpAddress; MailboxName = $m.DisplayName; MailboxType = $m.RecipientTypeDetails; Delegate = [string]$p.User; Permission = 'FullAccess'; Inherited = $false })
                }
            }
            catch { Write-TRLog ("Mailbox permissions for {0}: {1}" -f $m.PrimarySmtpAddress, $_.Exception.Message) 'Warn' }
        }
        if ($mailboxes.Count -gt $MaxMailboxes) { Write-TRLog ("Full Access was read for the first {0} of {1} mailboxes." -f $MaxMailboxes, $mailboxes.Count) 'Warn' }
        $rows.ToArray()
    } | Out-Null
}

function Get-TRDnsRecord {
    param([string]$Name, [string]$Type)
    try { $r = Resolve-TRDns -Name $Name -Type $Type; $r }
    catch { throw ("DNS lookup {0} {1} failed: {2}" -f $Type, $Name, $_.Exception.Message) }
}

function Invoke-TRCollectDns {
    Set-TRProgress 56 'Checking email DNS records'
    Invoke-TRStep 'Dns' 'DnsRecords' -List {
        $rows = New-Object System.Collections.ArrayList
        $domains = @($script:TRRaw['Domains'] | Where-Object { $_ -and $_.isVerified -and $_.id -notmatch '\.onmicrosoft\.com$|\.mail\.onmicrosoft\.com$' })
        foreach ($d in $domains) {
            Test-TRCancelled
            $name = [string]$d.id
            $errors = @()
            $mx = @(); $txt = @(); $dmarc = @(); $dk1 = @(); $dk2 = @(); $sts = @()
            try { $mx = @(Get-TRDnsRecord $name 'MX') } catch { $errors += $_.Exception.Message }
            try { $txt = @(Get-TRDnsRecord $name 'TXT') } catch { $errors += $_.Exception.Message }
            try { $dmarc = @(Get-TRDnsRecord ('_dmarc.' + $name) 'TXT') } catch { $errors += $_.Exception.Message }
            try { $dk1 = @(Get-TRDnsRecord ('selector1._domainkey.' + $name) 'CNAME') } catch { $errors += $_.Exception.Message }
            try { $dk2 = @(Get-TRDnsRecord ('selector2._domainkey.' + $name) 'CNAME') } catch { $errors += $_.Exception.Message }
            try { $sts = @(Get-TRDnsRecord ('_mta-sts.' + $name) 'TXT') } catch { }
            [void]$rows.Add([pscustomobject][ordered]@{
                    Domain           = $name
                    IsDefault        = [bool]$d.isDefault
                    SupportsEmail    = (@($d.supportedServices) -contains 'Email')
                    Mx               = @($mx)
                    Spf              = @($txt | Where-Object { $_ -match '^\s*v=spf1' })
                    Dmarc            = @($dmarc | Where-Object { $_ -match '^\s*v=DMARC1' })
                    DkimSelector1    = @($dk1)
                    DkimSelector2    = @($dk2)
                    MtaSts           = @($sts | Where-Object { $_ -match '^\s*v=STSv1' })
                    Errors           = ($errors -join '; ')
                })
        }
        $rows.ToArray()
    } | Out-Null
    $moera = @($script:TRRaw['Domains'] | Where-Object { $_ -and $_.isInitial } | ForEach-Object { [string]$_.id })[0]
    if ($moera) {
        Invoke-TRStep 'Dns' 'DnsMoera' -Optional {
            $dmarc = @()
            $err = ''
            try { $dmarc = @(Get-TRDnsRecord ('_dmarc.' + $moera) 'TXT') } catch { $err = $_.Exception.Message }
            [pscustomobject][ordered]@{ Domain = $moera; Dmarc = @($dmarc | Where-Object { $_ -match '^\s*v=DMARC1' }); Errors = $err }
        } | Out-Null
    }
}

function Invoke-TRCollectCollaboration {
    param([switch]$IncludeConfig)
    Set-TRProgress 60 'Collecting SharePoint, OneDrive and Teams data'
    if ($IncludeConfig) {
        Invoke-TRStep 'Collaboration' 'SharePointSettings' { Invoke-TRGraph -Path '/admin/sharepoint/settings' } | Out-Null
        Invoke-TRStep 'Collaboration' 'ReportSettings' -Optional { Invoke-TRGraph -Path '/admin/reportSettings' } | Out-Null
        Invoke-TRStep 'Collaboration' 'OneDriveUsage' -List -Optional { Invoke-TRGraphReport -Report 'getOneDriveUsageAccountDetail' } | Out-Null
    }
    if (-not $script:TRRaw.Contains('Groups') -or $null -eq $script:TRRaw['Groups']) {
        Invoke-TRStep 'Collaboration' 'Groups' -List { Invoke-TRGraph -Path '/groups?$select=id,displayName,groupTypes,mailEnabled,securityEnabled,visibility,resourceProvisioningOptions,createdDateTime,membershipRule,onPremisesSyncEnabled,mail&$top=999' -All } | Out-Null
    }
    if (-not $script:TRRaw.Contains('SiteUsage') -or $null -eq $script:TRRaw['SiteUsage']) {
        Invoke-TRStep 'Collaboration' 'SiteUsage' -List -Optional { Invoke-TRGraphReport -Report 'getSharePointSiteUsageDetail' } | Out-Null
    }
}

function Invoke-TRCollectGroupMembership {
    Set-TRProgress 64 'Collecting group, Team and site membership'
    Invoke-TRStep 'GroupMembership' 'GroupMembers' -List {
        $rows = New-Object System.Collections.ArrayList
        $groups = @($script:TRRaw['Groups'] | Where-Object { $_ -and (@($_.groupTypes) -contains 'Unified') })
        $i = 0
        foreach ($g in $groups) {
            $i++
            if ($i % 10 -eq 0) {
                Set-TRProgress (64 + [int](8 * $i / [Math]::Max($groups.Count, 1))) ("Group membership {0} of {1}" -f $i, $groups.Count)
                Test-TRCancelled
            }
            $isTeam = (@($g.resourceProvisioningOptions) -contains 'Team')
            foreach ($role in 'Owner', 'Member') {
                $path = if ($role -eq 'Owner') { '/groups/{0}/owners?$select=id,displayName,userPrincipalName,userType,mail' } else { '/groups/{0}/members?$select=id,displayName,userPrincipalName,userType,mail&$top=999' }
                try {
                    $list = Invoke-TRGraph -Path ($path -f $g.id) -All
                    foreach ($m in $list) {
                        $type = ([string]$m.'@odata.type') -replace '^#microsoft\.graph\.', ''
                        [void]$rows.Add([pscustomobject][ordered]@{
                                GroupId    = $g.id
                                GroupName  = $g.displayName
                                IsTeam     = $isTeam
                                Visibility = $g.visibility
                                Role       = $role
                                Member     = $m.displayName
                                MemberUpn  = $(if ($m.userPrincipalName) { $m.userPrincipalName } else { $m.mail })
                                UserType   = $m.userType
                                ObjectType = $type
                            })
                    }
                }
                catch { Write-TRLog ("{0} {1}s: {2}" -f $g.displayName, $role.ToLower(), $_.Exception.Message) 'Warn' }
            }
        }
        $rows.ToArray()
    } | Out-Null
}

function Invoke-TRCollectIntune {
    Set-TRProgress 72 'Collecting Intune data'
    $ok = Invoke-TRStep 'Intune' 'ManagedDevices' -List { Invoke-TRGraph -Path '/deviceManagement/managedDevices?$select=id,deviceName,operatingSystem,osVersion,complianceState,lastSyncDateTime,isEncrypted,managedDeviceOwnerType,enrolledDateTime,userPrincipalName,model,manufacturer,jailBroken,deviceEnrollmentType,serialNumber,azureADDeviceId' -All }
    $keys = @('DeviceManagement', 'CompliancePolicies', 'DeviceConfigurations', 'ConfigurationPolicies', 'Intents', 'EnrollmentConfigurations', 'AutopilotDevices', 'IosAppProtection', 'AndroidAppProtection') + $script:TRIntuneDeepKeys
    if (-not $ok) {
        Skip-TRStep 'Intune' $keys 'Intune data could not be read. The tenant may not be licensed for Intune, or the account lacks an Intune read role.'
        $script:TRRaw['Meta']['IntuneAvailable'] = $false
        return
    }
    $script:TRRaw['Meta']['IntuneAvailable'] = $true
    Invoke-TRStep 'Intune' 'DeviceManagement' -Optional { Invoke-TRGraph -Path '/deviceManagement?$select=settings,subscriptionState' } | Out-Null
    Invoke-TRStep 'Intune' 'CompliancePolicies' -List { Invoke-TRGraph -Path '/deviceManagement/deviceCompliancePolicies?$expand=assignments' -All } | Out-Null
    Invoke-TRStep 'Intune' 'DeviceConfigurations' -List { Invoke-TRGraph -Path '/deviceManagement/deviceConfigurations?$expand=assignments' -All } | Out-Null
    Invoke-TRStep 'Intune' 'ConfigurationPolicies' -List -Optional {
        try { Invoke-TRGraph -Path '/deviceManagement/configurationPolicies?$select=id,name,platforms,technologies,templateReference&$expand=assignments' -Beta -All }
        catch { Invoke-TRGraph -Path '/deviceManagement/configurationPolicies?$select=id,name,platforms,technologies,templateReference' -Beta -All }
    } | Out-Null
    Invoke-TRStep 'Intune' 'Intents' -List -Optional { Invoke-TRGraph -Path '/deviceManagement/intents?$select=id,displayName,templateId,isAssigned' -Beta -All } | Out-Null
    Invoke-TRStep 'Intune' 'EnrollmentConfigurations' -List -Optional { Invoke-TRGraph -Path '/deviceManagement/deviceEnrollmentConfigurations' -All } | Out-Null
    Invoke-TRStep 'Intune' 'AutopilotDevices' -List -Optional {
        $props = 'id', 'serialNumber', 'model', 'groupTag', 'enrollmentState', 'lastContactedDateTime', 'managedDeviceId', 'deploymentProfileAssignmentStatus'
        try { Invoke-TRGraph -Path '/deviceManagement/windowsAutopilotDeviceIdentities' -Beta -All -MaxRetry 2 | Select-TRProps -Property $props }
        catch {
            try { Invoke-TRGraph -Path '/deviceManagement/windowsAutopilotDeviceIdentities?$select=id,serialNumber,model,groupTag,enrollmentState' -All -MaxRetry 2 }
            catch { Invoke-TRGraph -Path '/deviceManagement/windowsAutopilotDeviceIdentities' -All -MaxRetry 3 | Select-TRProps -Property id, serialNumber, model, groupTag, enrollmentState }
        }
    } | Out-Null
    Invoke-TRStep 'Intune' 'IosAppProtection' -List -Optional { Invoke-TRGraph -Path '/deviceAppManagement/iosManagedAppProtections?$expand=assignments' -All } | Out-Null
    Invoke-TRStep 'Intune' 'AndroidAppProtection' -List -Optional { Invoke-TRGraph -Path '/deviceAppManagement/androidManagedAppProtections?$expand=assignments' -All } | Out-Null
    Invoke-TRCollectIntuneDeep
}

$script:TRIntuneDeepKeys = @('ConfigPolicyAssignments', 'IntunePolicySettings', 'IntunePolicyStatus', 'IntuneBaselineTemplates', 'IntuneIntentTemplates', 'IntuneApplePush', 'IntuneDepTokens', 'IntuneVppTokens', 'IntuneAndroidEnterprise', 'AutopilotProfiles', 'IntuneAppInstall', 'IntuneCleanupRules')

$script:TRIntuneSettingFamilies = @('endpointSecurityAntivirus', 'endpointSecurityDiskEncryption', 'endpointSecurityFirewall', 'endpointSecurityAttackSurfaceReduction', 'endpointSecurityAccountProtection', 'endpointSecurityEndpointDetectionAndResponse', 'none', '')

function Get-TRIntuneSettingRows {
    param($Instance)
    if ($null -eq $Instance) { return }
    $id = [string]$Instance.settingDefinitionId
    if ($null -ne $Instance.choiceSettingValue) {
        [pscustomobject]@{ Setting = $id; Value = [string]$Instance.choiceSettingValue.value }
        foreach ($c in @($Instance.choiceSettingValue.children)) { Get-TRIntuneSettingRows $c }
    }
    elseif ($null -ne $Instance.simpleSettingValue) { [pscustomobject]@{ Setting = $id; Value = [string]$Instance.simpleSettingValue.value } }
    elseif ($null -ne $Instance.groupSettingCollectionValue) {
        foreach ($g in @($Instance.groupSettingCollectionValue)) { foreach ($c in @($g.children)) { Get-TRIntuneSettingRows $c } }
    }
    elseif ($null -ne $Instance.groupSettingValue) { foreach ($c in @($Instance.groupSettingValue.children)) { Get-TRIntuneSettingRows $c } }
    elseif ($null -ne $Instance.simpleSettingCollectionValue) { [pscustomobject]@{ Setting = $id; Value = (@($Instance.simpleSettingCollectionValue | ForEach-Object { [string]$_.value }) -join ', ') } }
    elseif ($null -ne $Instance.choiceSettingCollectionValue) {
        foreach ($v in @($Instance.choiceSettingCollectionValue)) {
            [pscustomobject]@{ Setting = $id; Value = [string]$v.value }
            foreach ($c in @($v.children)) { Get-TRIntuneSettingRows $c }
        }
    }
}

function ConvertFrom-TRIntuneReport {
    param($Response)
    $r = $Response
    if ($null -eq $r) { return , @() }
    if ($r -is [byte[]]) { $r = [Text.Encoding]::UTF8.GetString($r) }
    if ($r -is [string]) {
        $t = $r.TrimStart([char]0xFEFF).Trim()
        if (-not $t) { return , @() }
        $r = ConvertFrom-Json -InputObject $t
    }
    $cols = @($r.Schema | ForEach-Object { [string]$_.Column })
    if (-not $cols.Count) { return , @() }
    $rows = foreach ($v in @($r.Values)) {
        $o = [ordered]@{}
        for ($i = 0; $i -lt $cols.Count; $i++) { $o[$cols[$i]] = @($v)[$i] }
        [pscustomobject]$o
    }
    , @($rows)
}

function Get-TRReportValue {
    param($Row, [string[]]$Patterns, [string[]]$Exclude = @())
    foreach ($pat in $Patterns) {
        foreach ($p in $Row.PSObject.Properties) {
            if ($p.Name -match $pat -and -not @($Exclude | Where-Object { $p.Name -match $_ }).Count) { return $p.Value }
        }
    }
    $null
}

function Invoke-TRCollectIntuneDeep {
    Set-TRProgress 73 'Reviewing Intune configuration in depth'
    Invoke-TRStep 'Intune' 'ConfigPolicyAssignments' -Optional {
        $n = 0
        foreach ($p in @(@($script:TRRaw['ConfigurationPolicies']) | Where-Object { $null -ne $_ })) {
            if (Test-TRHasProperty $p 'assignments') { continue }
            if ($n -ge 300) { break }
            Test-TRCancelled
            $a = Invoke-TRGraph -Path ('/deviceManagement/configurationPolicies/{0}/assignments' -f $p.id) -Beta -All -MaxRetry 3
            $a = @($a | Where-Object { $null -ne $_ })
            $p | Add-Member -NotePropertyName 'assignments' -NotePropertyValue $a -Force
            $n++
        }
        $n
    } | Out-Null
    Invoke-TRStep 'Intune' 'IntunePolicySettings' -List -Optional {
        $done = 0
        foreach ($p in @(@($script:TRRaw['ConfigurationPolicies']) | Where-Object { $null -ne $_ })) {
            $fam = [string]$p.templateReference.templateFamily
            if ($script:TRIntuneSettingFamilies -notcontains $fam) { continue }
            if ($done -ge 150) { break }
            Test-TRCancelled
            $settings = Invoke-TRGraph -Path ('/deviceManagement/configurationPolicies/{0}/settings' -f $p.id) -Beta -All -MaxRetry 3
            $settings = @($settings | Where-Object { $null -ne $_ })
            $done++
            $assigned = (Test-TRHasProperty $p 'assignments') -and @($p.assignments).Count -gt 0
            foreach ($st in $settings) {
                foreach ($row in @(Get-TRIntuneSettingRows $st.settingInstance)) {
                    [pscustomobject]@{ PolicyId = [string]$p.id; Policy = [string]$p.name; Family = $fam; Template = [string]$p.templateReference.templateDisplayName; Assigned = $assigned; Setting = $row.Setting; Value = $row.Value }
                }
            }
        }
    } | Out-Null
    Invoke-TRStep 'Intune' 'IntunePolicyStatus' -List -Optional {
        $out = @()
        try {
            $resp = Invoke-TRGraph -Path '/deviceManagement/reports/getConfigurationPolicyNonComplianceSummaryReport' -Method POST -Body @{ top = 1000; skip = 0 } -MaxRetry 3
            $reportRows = ConvertFrom-TRIntuneReport $resp
            foreach ($row in $reportRows) {
                $id = [string](Get-TRReportValue $row @('^PolicyId$', 'PolicyId'))
                if (-not $id) { continue }
                $out += [pscustomobject]@{ PolicyId = $id; Policy = [string](Get-TRReportValue $row @('^PolicyName$', 'PolicyName', 'DisplayName')); Kind = 'Configuration'; Source = 'Report'
                    Errors = [int](Get-TRReportValue $row @('NumberOfErrorDevices', 'Error')); Conflicts = [int](Get-TRReportValue $row @('NumberOfConflictDevices', 'Conflict')); Succeeded = [int](Get-TRReportValue $row @('NumberOfCompliantDevices', 'Succeeded', 'Success')) }
            }
        }
        catch { Write-TRLog ('Intune policy status report could not be read, using per-policy status instead: ' + $_.Exception.Message) 'Info' }
        if (-not $out.Count) {
            $n = 0
            foreach ($kind in 'deviceConfigurations', 'deviceCompliancePolicies') {
                $src = if ($kind -eq 'deviceConfigurations') { 'DeviceConfigurations' } else { 'CompliancePolicies' }
                foreach ($p in @(@($script:TRRaw[$src]) | Where-Object { $null -ne $_ } | Where-Object { @($_.assignments).Count -gt 0 })) {
                    if ($n -ge 200) { break }
                    Test-TRCancelled
                    $o = Invoke-TRGraph -Path ('/deviceManagement/{0}/{1}/deviceStatusOverview' -f $kind, $p.id) -MaxRetry 3
                    $n++
                    $out += [pscustomobject]@{ PolicyId = [string]$p.id; Policy = [string]$p.displayName; Kind = $(if ($kind -eq 'deviceConfigurations') { 'Configuration' } else { 'Compliance' }); Source = 'Overview'
                        Errors = [int]$o.errorCount; Conflicts = [int]$o.conflictCount; Succeeded = [int]$o.successCount }
                }
            }
        }
        $out
    } | Out-Null
    Invoke-TRStep 'Intune' 'IntuneBaselineTemplates' -List -Optional {
        Invoke-TRGraph -Path "/deviceManagement/configurationPolicyTemplates?`$filter=templateFamily eq 'baseline'&`$select=id,baseId,version,displayName,displayVersion,lifecycleState,templateFamily" -Beta -All -MaxRetry 3
    } | Out-Null
    if (@(@($script:TRRaw['Intents']) | Where-Object { $null -ne $_ }).Count) {
        Invoke-TRStep 'Intune' 'IntuneIntentTemplates' -List -Optional { Invoke-TRGraph -Path '/deviceManagement/templates?$select=id,displayName,templateType,templateSubtype,versionInfo,isDeprecated' -Beta -All -MaxRetry 3 } | Out-Null
    }
    else { Invoke-TRStep 'Intune' 'IntuneIntentTemplates' -List -Optional { @() } | Out-Null }
    Invoke-TRStep 'Intune' 'IntuneApplePush' -List -Optional {
        try { Invoke-TRGraph -Path '/deviceManagement/applePushNotificationCertificate' -MaxRetry 3 | Select-TRProps -Property appleIdentifier, topicIdentifier, expirationDateTime, lastModifiedDateTime, certificateUploadStatus, certificateSerialNumber }
        catch { if ([int]$_.Exception.Data['HttpStatus'] -ne 404) { throw } }
    } | Out-Null
    Invoke-TRStep 'Intune' 'IntuneDepTokens' -List -Optional { Invoke-TRGraph -Path '/deviceManagement/depOnboardingSettings' -Beta -All -MaxRetry 3 | Select-TRProps -Property id, tokenName, tokenType, appleIdentifier, tokenExpirationDateTime, lastSuccessfulSyncDateTime, lastSyncTriggeredDateTime, lastSyncErrorCode, syncedDeviceCount } | Out-Null
    Invoke-TRStep 'Intune' 'IntuneVppTokens' -List -Optional { Invoke-TRGraph -Path '/deviceAppManagement/vppTokens' -All -MaxRetry 3 | Select-TRProps -Property id, organizationName, appleId, vppTokenAccountType, expirationDateTime, lastSyncDateTime, state, lastSyncStatus, automaticallyUpdateApps, lastAppCount } | Out-Null
    Invoke-TRStep 'Intune' 'IntuneAndroidEnterprise' -List -Optional {
        try { Invoke-TRGraph -Path '/deviceManagement/androidManagedStoreAccountEnterpriseSettings' -Beta -MaxRetry 3 | Select-TRProps -Property bindStatus, lastAppSyncDateTime, lastAppSyncStatus, ownerUserPrincipalName, ownerOrganizationName, lastModifiedDateTime, deviceOwnerManagementEnabled }
        catch { if ([int]$_.Exception.Data['HttpStatus'] -ne 404) { throw } }
    } | Out-Null
    Invoke-TRStep 'Intune' 'AutopilotProfiles' -List -Optional {
        try { Invoke-TRGraph -Path '/deviceManagement/windowsAutopilotDeploymentProfiles?$expand=assignments' -Beta -All -MaxRetry 2 }
        catch { Invoke-TRGraph -Path '/deviceManagement/windowsAutopilotDeploymentProfiles' -Beta -All -MaxRetry 3 }
    } | Out-Null
    Invoke-TRStep 'Intune' 'IntuneAppInstall' -List -Optional {
        $apps = @()
        try { $apps = Invoke-TRGraph -Path '/deviceAppManagement/mobileApps?$filter=isAssigned eq true&$expand=assignments' -All -MaxRetry 3 }
        catch { $apps = Invoke-TRGraph -Path '/deviceAppManagement/mobileApps?$expand=assignments' -All -MaxRetry 3 }
        $apps = @($apps | Where-Object { $null -ne $_ -and $_.isAssigned -ne $false })
        $req = @($apps | Where-Object { @($_.assignments | Where-Object { [string]$_.intent -eq 'required' }).Count -gt 0 })
        if (-not $req.Count) { return }
        $cols = @('ApplicationId', 'DisplayName', 'Publisher', 'Platform', 'InstalledDeviceCount', 'FailedDeviceCount', 'PendingInstallDeviceCount', 'NotInstalledDeviceCount', 'FailedUserCount')
        $byId = @{}
        $useSelect = $true
        $skip = 0
        $page = 0
        while ($page -lt 40) {
            Test-TRCancelled
            $body = @{ skip = $skip; top = 50 }
            if ($useSelect) { $body['select'] = $cols }
            try { $resp = Invoke-TRGraph -Path '/deviceManagement/reports/getAppsInstallSummaryReport' -Method POST -Body $body -Beta -MaxRetry 3 }
            catch {
                if ($useSelect -and $skip -eq 0) { $useSelect = $false; continue }
                throw
            }
            $page++
            $rows = ConvertFrom-TRIntuneReport $resp
            foreach ($row in $rows) {
                $id = [string](Get-TRReportValue $row @('^ApplicationId$', 'ApplicationId'))
                if ($id) { $byId[$id.ToLower()] = $row }
            }
            if (@($rows).Count -lt 50) { break }
            $skip += 50
        }
        foreach ($a in $req) {
            $row = $byId[([string]$a.id).ToLower()]
            if (-not $row) { continue }
            [pscustomobject]@{ AppId = [string]$a.id; App = [string]$a.displayName; Type = ([string]$a.'@odata.type' -replace '^#microsoft\.graph\.', ''); Publisher = [string]$a.publisher
                Installed = [int](Get-TRReportValue $row @('^InstalledDeviceCount$')); Failed = [int](Get-TRReportValue $row @('^FailedDeviceCount$')); Pending = [int](Get-TRReportValue $row @('^PendingInstallDeviceCount$'))
                NotInstalled = [int](Get-TRReportValue $row @('^NotInstalledDeviceCount$')); FailedUsers = [int](Get-TRReportValue $row @('^FailedUserCount$')) }
        }
    } | Out-Null
    Invoke-TRStep 'Intune' 'IntuneCleanupRules' -List -Optional {
        try { Invoke-TRGraph -Path '/deviceManagement/managedDeviceCleanupRules' -Beta -All -MaxRetry 2 | Select-TRProps -Property id, displayName, deviceCleanupRulePlatformType, deviceInactivityBeforeRetirementInDays }
        catch {
            $c = Invoke-TRGraph -Path '/deviceManagement/managedDeviceCleanupSettings' -Beta -MaxRetry 3
            if ($c) { [pscustomobject]@{ id = 'legacy'; displayName = 'Device clean-up rule'; deviceCleanupRulePlatformType = 'all'; deviceInactivityBeforeRetirementInDays = $c.deviceInactivityBeforeRetirementInDays } }
        }
    } | Out-Null
}

function Invoke-TRCollectDefender {
    Set-TRProgress 75 'Collecting Microsoft Defender XDR data'
    $mdeKeys = @('DefenderDevices', 'DefenderDeviceVulns', 'DefenderVulnSoftware', 'DefenderConfigGaps')
    if (Test-TRCollectPlan $script:TRPlanSets.DefenderEndpoint) {
        $ok = Invoke-TRStep 'Defender' 'DefenderDevices' -List {
            try {
                Invoke-TRHunting -Query @'
DeviceInfo
| where Timestamp > ago(30d)
| summarize arg_max(Timestamp, *) by DeviceId
| project DeviceId, DeviceName, OSPlatform, OSVersion, DeviceType, OnboardingStatus, SensorHealthState, ExposureLevel, JoinType, AadDeviceId, MachineGroup, LastSeen = Timestamp
'@
            }
            catch {
                if ($_.Exception.Message -notmatch "resolve table or column expression named 'DeviceInfo'") { throw }
                $script:TRRaw['Meta']['DefenderNotProvisioned'] = $true
                Write-TRLog 'Defender for Endpoint has not been set up in this tenant: advanced hunting has no device data.' 'Warn'
                , @()
            }
        }
        $script:TRRaw['Meta']['DefenderAvailable'] = [bool]$ok
        if ($ok -and $script:TRRaw['Meta']['DefenderNotProvisioned']) {
            Skip-TRStep 'Defender' @('DefenderDeviceVulns', 'DefenderVulnSoftware', 'DefenderConfigGaps') 'Defender for Endpoint has not been set up in this tenant, so there is no vulnerability or configuration data.'
        }
        elseif ($ok) {
            Invoke-TRStep 'Defender' 'DefenderDeviceVulns' -List -Optional {
                Invoke-TRHunting -Query @'
DeviceTvmSoftwareVulnerabilities
| summarize Critical = dcountif(CveId, VulnerabilitySeverityLevel == 'Critical'), High = dcountif(CveId, VulnerabilitySeverityLevel == 'High'), Medium = dcountif(CveId, VulnerabilitySeverityLevel == 'Medium') by DeviceId
'@
            } | Out-Null
            Invoke-TRStep 'Defender' 'DefenderVulnSoftware' -List -Optional {
                Invoke-TRHunting -Query @'
DeviceTvmSoftwareVulnerabilities
| where VulnerabilitySeverityLevel in ('Critical', 'High')
| join kind=leftouter (DeviceTvmSoftwareVulnerabilitiesKB | project CveId, CvssScore, IsExploitAvailable) on CveId
| summarize Devices = dcount(DeviceId), CriticalCves = dcountif(CveId, VulnerabilitySeverityLevel == 'Critical'), HighCves = dcountif(CveId, VulnerabilitySeverityLevel == 'High'), ExploitableCves = dcountif(CveId, IsExploitAvailable == 1), MaxCvss = max(todouble(CvssScore)), ExampleCves = make_set(CveId, 5), Updates = make_set(RecommendedSecurityUpdate, 3) by SoftwareVendor, SoftwareName
'@
            } | Out-Null
            Invoke-TRStep 'Defender' 'DefenderConfigGaps' -List -Optional {
                Invoke-TRHunting -Query @'
DeviceTvmSecureConfigurationAssessment
| where IsApplicable == 1
| summarize Assessed = dcount(DeviceId), Failing = dcountif(DeviceId, IsCompliant == 0) by ConfigurationId, ConfigurationCategory, ConfigurationSubcategory, ConfigurationImpact
| where Failing > 0
| join kind=leftouter (DeviceTvmSecureConfigurationAssessmentKB | project ConfigurationId, ConfigurationName, RiskDescription, RemediationOptions) on ConfigurationId
| project ConfigurationId, ConfigurationName, ConfigurationCategory, ConfigurationSubcategory, ConfigurationImpact, Assessed, Failing, RiskDescription, RemediationOptions
'@
            } | Out-Null
        }
        else {
            Skip-TRStep 'Defender' @('DefenderDeviceVulns', 'DefenderVulnSoftware', 'DefenderConfigGaps') 'Advanced hunting could not be read. See DefenderDevices for the error.'
        }
    }
    else {
        Skip-TRStep 'Defender' $mdeKeys 'Defender for Endpoint or Defender for Business is not licensed.'
        $script:TRRaw['Meta']['DefenderAvailable'] = $false
    }
    Invoke-TRStep 'Defender' 'DefenderIncidents' -List -Optional {
        $since = (Get-Date).ToUniversalTime().AddDays(-90).ToString('yyyy-MM-ddTHH:mm:ssZ')
        try { Invoke-TRGraph -Path ('/security/incidents?$top=50&$filter=createdDateTime%20ge%20{0}' -f $since) -All -MaxItems 500 }
        catch { Invoke-TRGraph -Path '/security/incidents?$top=50' -All -MaxItems 500 }
    } | Out-Null
    if (Test-TRCollectPlan $script:TRPlanSets.DefenderO365P2) {
        Invoke-TRStep 'Defender' 'AttackSimulations' -List -Optional { Invoke-TRGraph -Path '/security/attackSimulation/simulations?$top=100' -All -MaxItems 500 } | Out-Null
    }
    else { Skip-TRStep 'Defender' @('AttackSimulations') 'Defender for Office 365 Plan 2 is not licensed.' }
    if (Test-TRCollectPlan $script:TRPlanSets.Intune) {
        Invoke-TRStep 'Defender' 'MtdConnectors' -List -Optional { Invoke-TRGraph -Path '/deviceManagement/mobileThreatDefenseConnectors' -All } | Out-Null
    }
    else { Skip-TRStep 'Defender' @('MtdConnectors') 'Intune is not licensed.' }
    if (Test-TRCollectPlan $script:TRPlanSets.DefenderIdentity) {
        Invoke-TRStep 'Defender' 'DefenderIdentitySensors' -List -Optional { Invoke-TRGraph -Path '/security/identities/sensors' -Beta -All } | Out-Null
    }
    else { Skip-TRStep 'Defender' @('DefenderIdentitySensors') 'Defender for Identity is not licensed.' }
}

function Invoke-TRCollectPurview {
    Set-TRProgress 78 'Collecting Microsoft Purview configuration'
    Invoke-TRStep 'Purview' 'RetentionLabels' -List -Optional { Invoke-TRGraph -Path '/security/labels/retentionLabels' -All } | Out-Null
    Invoke-TRStep 'Purview' 'EdiscoveryCases' -List -Optional { Invoke-TRGraph -Path '/security/cases/ediscoveryCases' -All } | Out-Null
    $sccKeys = @('SccDlpRules', 'SccRetentionPolicies', 'SccRetentionRules', 'SccLabels', 'SccLabelPolicies', 'SccAutoLabelPolicies', 'SccAlertPolicies', 'SccAuditRetention', 'SccInsiderRisk')
    $ok = Invoke-TRStep 'Purview' 'SccDlpPolicies' -List {
        foreach ($p in (Invoke-TRCompliance -Cmdlet 'Get-DlpCompliancePolicy')) { ConvertTo-TRSccPolicy $p }
    }
    if (-not $ok) {
        $first = @($script:TRDiag | Where-Object { $_.Item -eq 'SccDlpPolicies' }) | Select-Object -Last 1
        if ([int]$first.HttpStatus -ne 403) {
            $script:TRRaw['Meta']['PurviewAvailable'] = $false
            Write-TRLog 'The Security & Compliance endpoint is not reachable with this sign-in. Purview policy checks will use Secure Score evidence where possible.' 'Warn'
            Skip-TRStep 'Purview' $sccKeys 'Security & Compliance connection failed. See SccDlpPolicies for the error.'
            return
        }
        Write-TRLog 'Security & Compliance connected, but this account is not allowed to read DLP policies. It needs a Purview role such as Compliance Administrator, or membership of the Purview Organization Management role group. Reading the other Purview settings individually.' 'Warn'
    }
    Invoke-TRStep 'Purview' 'SccDlpRules' -List -Optional { foreach ($r in (Invoke-TRCompliance -Cmdlet 'Get-DlpComplianceRule')) { if ($null -ne $r) { ConvertTo-TRDlpRule $r } } } | Out-Null
    Invoke-TRStep 'Purview' 'SccRetentionPolicies' -List {
        foreach ($p in (Invoke-TRCompliance -Cmdlet 'Get-RetentionCompliancePolicy')) { ConvertTo-TRSccPolicy $p }
    } | Out-Null
    Invoke-TRStep 'Purview' 'SccRetentionRules' -List -Optional { Invoke-TRCompliance -Cmdlet 'Get-RetentionComplianceRule' | Select-TRProps -Property Name, Policy, ParentPolicyName, Disabled, RetentionDuration, RetentionDurationDisplayHint, RetentionComplianceAction, ExpirationDateOption } | Out-Null
    Invoke-TRStep 'Purview' 'SccLabels' -List { Invoke-TRCompliance -Cmdlet 'Get-Label' | Select-TRProps -Property Name, DisplayName, Guid, ImmutableId, Priority, ParentId, ContentType, Disabled, Mode, Tooltip, EncryptionEnabled, LabelActions } | Out-Null
    Invoke-TRStep 'Purview' 'SccLabelPolicies' -List {
        foreach ($p in (Invoke-TRCompliance -Cmdlet 'Get-LabelPolicy')) { ConvertTo-TRSccPolicy $p }
    } | Out-Null
    if (Test-TRCollectPlan $script:TRPlanSets.AutoLabelling) {
        Invoke-TRStep 'Purview' 'SccAutoLabelPolicies' -List -Optional {
            foreach ($p in (Invoke-TRCompliance -Cmdlet 'Get-AutoSensitivityLabelPolicy')) { ConvertTo-TRSccPolicy $p }
        } | Out-Null
    }
    else { Skip-TRStep 'Purview' @('SccAutoLabelPolicies') 'Auto-labelling (Information Protection Premium) is not licensed.' }
    Invoke-TRStep 'Purview' 'SccAlertPolicies' -List -Optional { Invoke-TRCompliance -Cmdlet 'Get-ProtectionAlert' | Select-TRProps -Property Name, Category, Severity, Disabled, IsSystemRule, NotifyUser, NotificationEnabled, Filter, RecipientTags } | Out-Null
    if (Test-TRCollectPlan $script:TRPlanSets.AuditPremium) {
        Invoke-TRStep 'Purview' 'SccAuditRetention' -List -Optional { Invoke-TRCompliance -Cmdlet 'Get-UnifiedAuditLogRetentionPolicy' | Select-TRProps -Property Name, Priority, RetentionDuration, RecordTypes, Operations } | Out-Null
    }
    else { Skip-TRStep 'Purview' @('SccAuditRetention') 'Audit (Premium) is not licensed.' }
    if (Test-TRCollectPlan $script:TRPlanSets.InsiderRisk) {
        Invoke-TRStep 'Purview' 'SccInsiderRisk' -List -Optional { Invoke-TRCompliance -Cmdlet 'Get-InsiderRiskPolicy' | Select-TRProps -Property Name, InsiderRiskScenario, Enabled, Mode } | Out-Null
    }
    else { Skip-TRStep 'Purview' @('SccInsiderRisk') 'Insider Risk Management is not licensed.' }
    $script:TRRaw['Meta']['PurviewAvailable'] = [bool](@($script:TRDiag | Where-Object { $_.Area -eq 'Purview' -and $_.Item -like 'Scc*' -and $_.Status -eq 'OK' }).Count)
}

function ConvertTo-TRList {
    param($Response)
    if ($null -eq $Response) { return , @() }
    if ($Response -is [string]) { return , @() }
    if (Test-TRHasProperty $Response 'value') { return , @(@($Response.value) | Where-Object { $null -ne $_ }) }
    , @(@($Response) | Where-Object { $null -ne $_ })
}

function Get-TRProps {
    param($Object)
    if ($null -eq $Object) { return @() }
    if ($Object -is [System.Collections.IDictionary]) { return @($Object.Keys | ForEach-Object { [pscustomobject]@{ Name = [string]$_; Value = $Object[$_] } }) }
    @($Object.PSObject.Properties | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Value = $_.Value } })
}

function Select-TRScalars {
    param($Object)
    $o = [ordered]@{}
    foreach ($p in (Get-TRProps $Object)) {
        if ($p.Name -like '__*' -or $p.Name -like '@odata*') { continue }
        $v = $p.Value
        if ($null -eq $v -or $v -is [string] -or $v -is [ValueType]) { $o[$p.Name] = $v; continue }
        if (Test-TRHasProperty $v 'results') { $o[$p.Name] = @(@($v.results) | Where-Object { $null -ne $_ -and ($_ -is [string] -or $_ -is [ValueType]) }); continue }
        if ($v -is [System.Collections.IEnumerable] -and $v -isnot [System.Collections.IDictionary]) {
            $items = @($v)
            if (@($items | Where-Object { $null -ne $_ -and -not ($_ -is [string] -or $_ -is [ValueType]) }).Count -eq 0) { $o[$p.Name] = $items }
        }
    }
    [pscustomobject]$o
}

function Get-TRTeamsConfig {
    param([string]$Type)
    $ctx = Get-TRContext
    ConvertTo-TRList (Invoke-TRServiceRest -Resource Teams -Uri ('{0}/Skype.Policy/configurations/{1}' -f $ctx.TeamsBase, $Type))
}

function Get-TRGroupNames {
    param($Groups)
    @(@($Groups) | Where-Object { $_ } | ForEach-Object {
            if (Test-TRHasProperty $_ 'name') { [string]$_.name }
            elseif (Test-TRHasProperty $_ 'graphId') { [string]$_.graphId }
            else { [string]$_ }
        })
}

function ConvertTo-TRFabricSetting {
    param($Setting)
    $props = @(@($Setting.properties) | Where-Object { $_ } | ForEach-Object { [pscustomobject][ordered]@{ Name = [string]$_.name; Value = [string]$_.value; Type = [string]$_.type } })
    [pscustomobject][ordered]@{
        SettingName            = [string]$Setting.settingName
        Title                  = [string]$Setting.title
        Enabled                = $Setting.enabled
        Group                  = [string]$Setting.tenantSettingGroup
        EnabledSecurityGroups  = @(Get-TRGroupNames $Setting.enabledSecurityGroups)
        ExcludedSecurityGroups = @(Get-TRGroupNames $Setting.excludedSecurityGroups)
        Properties             = $props
    }
}

function Get-TRFabricSettings {
    $ctx = Get-TRContext
    $rows = New-Object System.Collections.ArrayList
    $uri = '{0}/v1/admin/tenantsettings' -f $ctx.FabricBase
    try {
        $guard = 0
        while ($uri -and $guard -lt 20) {
            $guard++
            $r = Invoke-TRServiceRest -Resource PowerBI -Uri $uri
            foreach ($s in @($r.tenantSettings) + @($r.value)) { if ($s) { [void]$rows.Add((ConvertTo-TRFabricSetting $s)) } }
            $uri = $null
            if ((Test-TRHasProperty $r 'continuationUri') -and $r.continuationUri) { $uri = [string]$r.continuationUri }
        }
    }
    catch {
        if ($rows.Count) { throw }
        try {
            $r = Invoke-TRServiceRest -Resource PowerBI -Uri ('{0}/v1/admin/tenantsettings' -f $ctx.PowerBIBase)
            foreach ($s in @($r.tenantSettings) + @($r.value)) { if ($s) { [void]$rows.Add((ConvertTo-TRFabricSetting $s)) } }
        }
        catch {
            if ([int]$_.Exception.Data['HttpStatus'] -eq 401 -and $_.Exception.Message -match 'not licensed') {
                throw 'The signed-in account has no Power BI or Fabric licence, which the Power BI admin API needs. Assign it the free Microsoft Fabric (Free) licence, or sign in once at app.powerbi.com with it, then run the review again.'
            }
            throw
        }
    }
    , $rows.ToArray()
}

function ConvertTo-TRPpDlpPolicy {
    param($Policy)
    $def = $Policy.properties.definition
    $ef = $null
    if ($def -and $def.constraints) { $ef = $def.constraints.environmentFilter1 }
    $type = 'AllEnvironments'
    $envs = @()
    if ($ef) {
        $envs = @(@($ef.parameters.environments) | Where-Object { $_ } | ForEach-Object { if (Test-TRHasProperty $_ 'name') { [string]$_.name } else { [string]$_ } })
        $type = if ([string]$ef.parameters.filterType -eq 'include') { 'OnlyEnvironments' } else { 'ExceptEnvironments' }
    }
    [pscustomobject][ordered]@{
        Name            = [string]$Policy.name
        DisplayName     = [string]$Policy.properties.displayName
        EnvironmentType = $type
        Environments    = $envs
    }
}

function Request-TRServiceSettingsAccess {
    param([string[]]$Services = $script:TRSettingsServices)
    $script:TRRaw['Meta']['ServiceAccess'] = [ordered]@{}
    $access = $null
    try { $access = Request-TRServiceAccess -Services $Services }
    catch {
        if ($_.Exception.Message -eq 'Operation cancelled by user.') { throw }
        Write-TRLog ('Access to {0} could not be requested: {1}' -f ((@($Services | ForEach-Object { $script:TRServices[$_].Name })) -join ', '), $_.Exception.Message) 'Warn'
    }
    foreach ($k in $Services) {
        $state = 'Failed: access was not requested.'
        if ($access -and $access.Contains($k)) { $state = [string]$access[$k] }
        $script:TRRaw['Meta']['ServiceAccess'][$k] = $state
    }
}

function Invoke-TRCollectServiceSettings {
    Set-TRProgress 70 'Collecting Teams, SharePoint, Power BI and Power Platform settings'
    $ctx = Get-TRContext
    $keys = [ordered]@{
        Teams           = @('TeamsMeetingPolicies', 'TeamsFederation', 'TeamsClientConfig', 'TeamsAppPolicies', 'TeamsBroadcastPolicies', 'TeamsMessagingPolicies')
        SharePointAdmin = @('SpoTenant')
        PowerBI         = @('PowerBISettings')
        PowerPlatform   = @('PpTenantSettings', 'PpEnvironments', 'PpDlpPolicies', 'PpTenantIsolation')
    }
    $access = $script:TRRaw['Meta']['ServiceAccess']
    foreach ($svc in $keys.Keys) {
        $state = if ($access -and $access.Contains($svc)) { [string]$access[$svc] } else { 'Failed: access was not requested.' }
        if ($state -ne 'Ready') {
            Skip-TRStep 'ServiceSettings' $keys[$svc] ('{0} could not be read. {1}' -f $script:TRServices[$svc].Name, $state)
            continue
        }
        switch ($svc) {
            'Teams' {
                Invoke-TRStep 'ServiceSettings' 'TeamsMeetingPolicies' -List { Get-TRTeamsConfig 'TeamsMeetingPolicy' } | Out-Null
                Invoke-TRStep 'ServiceSettings' 'TeamsFederation' -List { Get-TRTeamsConfig 'TenantFederationSettings' } | Out-Null
                Invoke-TRStep 'ServiceSettings' 'TeamsClientConfig' -List { Get-TRTeamsConfig 'TeamsClientConfiguration' } | Out-Null
                Invoke-TRStep 'ServiceSettings' 'TeamsAppPolicies' -List -Optional { Get-TRTeamsConfig 'TeamsAppPermissionPolicy' } | Out-Null
                Invoke-TRStep 'ServiceSettings' 'TeamsBroadcastPolicies' -List -Optional { Get-TRTeamsConfig 'TeamsMeetingBroadcastPolicy' } | Out-Null
                Invoke-TRStep 'ServiceSettings' 'TeamsMessagingPolicies' -List -Optional { Get-TRTeamsConfig 'TeamsMessagingPolicy' } | Out-Null
            }
            'SharePointAdmin' {
                Invoke-TRStep 'ServiceSettings' 'SpoTenant' {
                    $r = Invoke-TRServiceRest -Resource SharePointAdmin -Uri ('{0}/_api/SPO.Tenant' -f $ctx.SpoAdminUrl) -Accept 'application/json;odata=verbose'
                    if (Test-TRHasProperty $r 'd') { $r = $r.d }
                    Select-TRScalars $r
                } | Out-Null
            }
            'PowerBI' {
                Invoke-TRStep 'ServiceSettings' 'PowerBISettings' -List { Get-TRFabricSettings } | Out-Null
            }
            'PowerPlatform' {
                $bap = $ctx.BapBase
                Invoke-TRStep 'ServiceSettings' 'PpTenantSettings' {
                    $t = Invoke-TRServiceRest -Resource PowerPlatform -Uri ('{0}/providers/Microsoft.BusinessAppPlatform/listTenantSettings?api-version=2023-06-01' -f $bap) -Method POST
                    $o = Select-TRScalars $t
                    $share = $null
                    if ($t.powerPlatform -and $t.powerPlatform.powerApps) { $share = $t.powerPlatform.powerApps.disableShareWithEveryone }
                    $o | Add-Member -NotePropertyName 'DisableShareWithEveryone' -NotePropertyValue $share -Force
                    $o
                } | Out-Null
                Invoke-TRStep 'ServiceSettings' 'PpEnvironments' -List {
                    foreach ($e in (ConvertTo-TRList (Invoke-TRServiceRest -Resource PowerPlatform -Uri ('{0}/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments?api-version=2023-06-01' -f $bap)))) {
                        [pscustomobject][ordered]@{
                            Name            = [string]$e.name
                            DisplayName     = [string]$e.properties.displayName
                            IsDefault       = [bool]$e.properties.isDefault
                            EnvironmentType = [string]$e.properties.environmentSku
                            Location        = [string]$e.location
                            CreatedTime     = $e.properties.createdTime
                        }
                    }
                } | Out-Null
                Invoke-TRStep 'ServiceSettings' 'PpDlpPolicies' -List {
                    foreach ($d in (ConvertTo-TRList (Invoke-TRServiceRest -Resource PowerPlatform -Uri ('{0}/providers/Microsoft.BusinessAppPlatform/scopes/admin/apiPolicies?api-version=2016-11-01' -f $bap)))) { ConvertTo-TRPpDlpPolicy $d }
                } | Out-Null
                Invoke-TRStep 'ServiceSettings' 'PpTenantIsolation' -Optional {
                    $r = Invoke-TRServiceRest -Resource PowerPlatform -Uri ('{0}/providers/PowerPlatform.Governance/v1/tenants/{1}/tenantIsolationPolicy?api-version=2020-06-01' -f $bap, $ctx.TenantId)
                    $p = if ($r -and (Test-TRHasProperty $r 'properties')) { $r.properties } else { $r }
                    [pscustomobject][ordered]@{
                        IsDisabled = $(if ($p -and (Test-TRHasProperty $p 'isDisabled')) { $p.isDisabled } else { $null })
                        Rules      = @(@($p.allowedTenants) | Where-Object { $_ }).Count
                    }
                } | Out-Null
            }
        }
    }
}

function ConvertTo-TRUsageRow {
    param($Row)
    $upn = $null; $name = $null; $last = $null
    foreach ($k in 'userPrincipalName', 'User Principal Name') { if (Test-TRHasProperty $Row $k) { $upn = [string]$Row.$k; break } }
    foreach ($k in 'displayName', 'Display Name') { if (Test-TRHasProperty $Row $k) { $name = [string]$Row.$k; break } }
    foreach ($k in 'lastActivityDate', 'Last Activity Date') { if (Test-TRHasProperty $Row $k) { $last = [string]$Row.$k; break } }
    [pscustomobject][ordered]@{ UserPrincipalName = $upn; DisplayName = $name; LastActivityDate = $last }
}

function Invoke-TRCollectOpportunities {
    Set-TRProgress 83 'Collecting usage data for licence utilisation'
    Invoke-TRStep 'Opportunities' 'ActiveUserDetail' -List -Optional { Invoke-TRGraphReport -Report 'getOffice365ActiveUserDetail' | Select-TRProps -Property 'User Principal Name', 'Is Deleted', 'Has Exchange License', 'Has OneDrive License', 'Has SharePoint License', 'Has Teams License', 'Exchange Last Activity Date', 'OneDrive Last Activity Date', 'SharePoint Last Activity Date', 'Teams Last Activity Date', 'Assigned Products' } | Out-Null
    Invoke-TRStep 'Opportunities' 'AppActivations' -List -Optional { Invoke-TRGraphReport -Report 'getOffice365ActivationsUserDetail' -NoPeriod } | Out-Null
    if (Test-TRCollectPlan $script:TRPlanSets.Copilot) {
        Invoke-TRStep 'Opportunities' 'CopilotUsage' -List -Optional {
            $raw = $null
            try { $raw = Invoke-TRGraph -Path "/copilot/reports/getMicrosoft365CopilotUsageUserDetail(period='D28')" -All }
            catch { $raw = Invoke-TRGraph -Path "/reports/getMicrosoft365CopilotUsageUserDetail(period='D30')?`$format=application/json" -Beta -All }
            foreach ($item in @($raw)) {
                if ($item -is [string] -or $item -is [byte[]]) {
                    foreach ($row in (ConvertFrom-TRReportResponse $item)) { ConvertTo-TRUsageRow $row }
                }
                elseif ($null -ne $item) { ConvertTo-TRUsageRow $item }
            }
        } | Out-Null
    }
    else { Skip-TRStep 'Opportunities' @('CopilotUsage') 'Microsoft 365 Copilot is not licensed.' }
    if (Test-TRCollectPlan $script:TRPlanSets.TeamsPhone) {
        Invoke-TRStep 'Opportunities' 'TeamsNumbers' -List -Optional { Invoke-TRGraph -Path '/admin/teams/telephoneNumberManagement/numberAssignments' -All | Select-TRProps -Property telephoneNumber, assignmentStatus, assignmentCategory, numberType, assignmentTargetId } | Out-Null
    }
    else { Skip-TRStep 'Opportunities' @('TeamsNumbers') 'Teams Phone is not licensed.' }
    if (Test-TRCollectPlan $script:TRPlanSets.UniversalPrint) {
        Invoke-TRStep 'Opportunities' 'Printers' -List -Optional {
            try { Invoke-TRGraph -Path '/print/printers' -All | Select-TRProps -Property id, displayName, manufacturer, model, isShared }
            catch {
                if ([int]$_.Exception.Data['HttpStatus'] -eq 403) { throw 'Universal Print only lets accounts with a Universal Print licence or the Printer Administrator role read printers.' }
                throw
            }
        } | Out-Null
    }
    else { Skip-TRStep 'Opportunities' @('Printers') 'Universal Print is not licensed.' }
    if (Test-TRCollectPlan $script:TRPlanSets.P2) {
        Invoke-TRStep 'Opportunities' 'AccessReviews' -List -Optional { Invoke-TRGraph -Path '/identityGovernance/accessReviews/definitions?$select=id,displayName,status,createdDateTime' -All } | Out-Null
    }
    else { Skip-TRStep 'Opportunities' @('AccessReviews') 'Entra ID P2 is not licensed.' }
}

function Invoke-TRCollectSecureScore {
    Set-TRProgress 81 'Collecting Microsoft Secure Score'
    Invoke-TRStep 'SecureScore' 'SecureScore' { Get-TRFirst (Invoke-TRGraph -Path '/security/secureScores?$top=1') } | Out-Null
    Invoke-TRStep 'SecureScore' 'SecureScoreProfiles' -List { Invoke-TRGraph -Path '/security/secureScoreControlProfiles' -All } | Out-Null
}

function Invoke-TRCollectSharingAudit {
    param([int]$Days = 30, [int]$TimeoutMinutes = 20)
    Set-TRProgress 85 'Querying the audit log for sharing activity'
    Invoke-TRStep 'SharingAudit' 'SharingAudit' -List {
        $end = (Get-Date).ToUniversalTime()
        $start = $end.AddDays(-1 * $Days)
        $body = @{
            displayName         = 'Tenant Review sharing activity'
            filterStartDateTime = $start.ToString('yyyy-MM-ddTHH:mm:ssZ')
            filterEndDateTime   = $end.ToString('yyyy-MM-ddTHH:mm:ssZ')
            operationFilters    = @('AnonymousLinkCreated', 'AnonymousLinkUpdated', 'CompanyLinkCreated', 'SecureLinkCreated', 'AddedToSecureLink', 'SharingInvitationCreated', 'SharingSet')
        }
        $q = Invoke-TRGraph -Path '/security/auditLog/queries' -Method POST -Body $body
        $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
        $status = [string]$q.status
        while ($status -notin @('succeeded', 'failed', 'cancelled')) {
            if ((Get-Date) -gt $deadline) { throw ("Audit log query did not finish within {0} minutes (status {1})." -f $TimeoutMinutes, $status) }
            Test-TRCancelled
            Start-Sleep -Seconds 15
            $q = Invoke-TRGraph -Path ('/security/auditLog/queries/{0}' -f $q.id)
            $status = [string]$q.status
            Write-TRLog ("Audit log query status: {0}" -f $status)
        }
        if ($status -ne 'succeeded') { throw "Audit log query $status." }
        $records = Invoke-TRGraph -Path ('/security/auditLog/queries/{0}/records?$top=1000' -f $q.id) -All -MaxItems 25000
        foreach ($r in $records) {
            $ad = $r.auditData
            [pscustomobject][ordered]@{
                Date       = $r.createdDateTime
                Operation  = $r.operation
                User       = $r.userPrincipalName
                Service    = $r.service
                Item       = $r.objectId
                Target     = $(if ($ad) { $ad.TargetUserOrGroupName } else { $null })
                TargetType = $(if ($ad) { $ad.TargetUserOrGroupType } else { $null })
                SiteUrl    = $(if ($ad) { $ad.SiteUrl } else { $null })
                EventData  = $(if ($ad) { $ad.EventData } else { $null })
            }
        }
    } | Out-Null
}

function Invoke-TenantCollection {
    param(
        [string[]]$Areas = $script:TRDefaultAreas,
        [string]$ClientName,
        [int]$MaxMailboxes = 3000,
        [string]$ToolVersion = '1.4.3'
    )
    $ctx = Get-TRContext
    if (-not $ctx -or -not $ctx.TenantId) { throw 'Sign in to the client tenant first.' }
    $script:TRRaw = [ordered]@{}
    $script:TRDiag = New-Object System.Collections.ArrayList
    $script:TRRaw['Meta'] = [ordered]@{
        ToolVersion       = $ToolVersion
        ClientName        = $ClientName
        TenantId          = $ctx.TenantId
        TenantName        = $ctx.TenantName
        InitialDomain     = $ctx.InitialDomain
        DefaultDomain     = $ctx.DefaultDomain
        Reviewer          = $ctx.Account
        ReviewerName      = $ctx.AccountName
        StartedUtc        = (Get-Date).ToUniversalTime().ToString('o')
        FinishedUtc       = $null
        Areas             = @($Areas)
        GrantedScopes     = $(if ($ctx.Scopes['Graph']) { $ctx.Scopes['Graph'] } else { '' })
        SignInActivity    = $false
        ExchangeAvailable = $false
        IntuneAvailable   = $false
        DefenderAvailable = $false
        DefenderNotProvisioned = $false
        PurviewAvailable  = $false
        ServiceAccess     = [ordered]@{}
    }
    Write-TRLog ("Starting collection for {0}: {1}" -f $(if ($ctx.TenantName) { $ctx.TenantName } else { $ctx.TenantId }), ($Areas -join ', '))
    $svcWanted = @()
    if ($Areas -contains 'ServiceSettings') { $svcWanted += $script:TRSettingsServices }
    if ($Areas -contains 'Azure') { $svcWanted += 'Azure' }
    if ($svcWanted.Count) { Request-TRServiceSettingsAccess -Services $svcWanted }
    $needIdentity = $true
    if ($needIdentity) { Invoke-TRCollectIdentity }
    Invoke-TRCollectLicensing
    if ($Areas -contains 'Benchmarks') { Invoke-TRCollectBenchmarkData }
    if ($Areas -contains 'Applications') { Invoke-TRCollectApplications }
    $needExo = ($Areas -contains 'Exchange') -or ($Areas -contains 'MailboxPermissions') -or ($Areas -contains 'Dns')
    if ($needExo) { Invoke-TRCollectExchange -IncludePermissions:($Areas -contains 'MailboxPermissions') -IncludeConfig:(($Areas -contains 'Exchange') -or ($Areas -contains 'Dns')) }
    if ($Areas -contains 'MailboxPermissions') { Invoke-TRCollectMailboxPermissions -MaxMailboxes $MaxMailboxes }
    if ($Areas -contains 'Dns') { Invoke-TRCollectDns }
    $needGroups = ($Areas -contains 'Collaboration') -or ($Areas -contains 'GroupMembership') -or ($Areas -contains 'Opportunities')
    if ($needGroups) { Invoke-TRCollectCollaboration -IncludeConfig:($Areas -contains 'Collaboration') }
    if ($Areas -contains 'GroupMembership') { Invoke-TRCollectGroupMembership }
    if ($Areas -contains 'ServiceSettings') { Invoke-TRCollectServiceSettings }
    if ($Areas -contains 'Intune') { Invoke-TRCollectIntune }
    if ($Areas -contains 'Defender') { Invoke-TRCollectDefender }
    if ($Areas -contains 'Purview') { Invoke-TRCollectPurview }
    if ($Areas -contains 'SecureScore') { Invoke-TRCollectSecureScore }
    if ($Areas -contains 'Opportunities') { Invoke-TRCollectOpportunities }
    if ($Areas -contains 'SharingAudit') { Invoke-TRCollectSharingAudit }
    if ($Areas -contains 'Azure') { Invoke-TRCollectAzure }
    $script:TRRaw['Meta']['FinishedUtc'] = (Get-Date).ToUniversalTime().ToString('o')
    $script:TRRaw['Diagnostics'] = $script:TRDiag.ToArray()
    $failed = @($script:TRDiag | Where-Object { $_.Status -eq 'Failed' }).Count
    Write-TRLog ("Collection finished. {0} items collected, {1} failed." -f @($script:TRDiag | Where-Object { $_.Status -eq 'OK' }).Count, $failed) $(if ($failed) { 'Warn' } else { 'Success' })
    $script:TRRaw
}
