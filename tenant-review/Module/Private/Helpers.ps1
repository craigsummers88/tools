$script:TRR = $null
$script:TRDiagIndex = @{}
$script:TRCache = @{}
$script:TRSettings = $null

$script:TRPrivilegedTemplates = @{
    '62e90394-69f5-4237-9190-012177145e10' = 'Global Administrator'
    'e8611ab8-c189-46e8-94e1-60213ab1f814' = 'Privileged Role Administrator'
    '7be44c8a-adaf-4e2a-84d6-ab2649e08a13' = 'Privileged Authentication Administrator'
    '194ae4cb-b126-40b2-bd5b-6091b380977d' = 'Security Administrator'
    '29232cdf-9323-42fd-ade2-1d097af3e4de' = 'Exchange Administrator'
    'f28a1f50-f6e7-4571-818b-6a12f2af6b6c' = 'SharePoint Administrator'
    'fe930be7-5e62-47db-91af-98c3a49a38b1' = 'User Administrator'
    '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3' = 'Application Administrator'
    '158c047a-c907-4556-b7ef-446551a6b5f7' = 'Cloud Application Administrator'
    'c4e39bd9-1100-46d3-8c65-fb160da0071f' = 'Authentication Administrator'
    'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9' = 'Conditional Access Administrator'
    '3a2c62db-5318-420d-8d74-23affee5d9d5' = 'Intune Administrator'
    '8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2' = 'Hybrid Identity Administrator'
    '729827e3-9c14-49f7-bb1b-9608f156bbb8' = 'Helpdesk Administrator'
    '69091246-20e8-4a56-aa4d-066075b2a7a8' = 'Teams Administrator'
    '966707d0-3269-4727-9be2-8c3a10f19b9d' = 'Password Administrator'
    'be2f45a1-457d-42af-a067-6ec1fa63bc45' = 'External Identity Provider Administrator'
    'd29b2b05-8046-44ba-8758-1e26182fcf32' = 'Directory Synchronization Accounts'
    '8329153b-31d0-4727-b945-745eb3bc5f31' = 'Domain Name Administrator'
}

$script:TRSkuNames = @{
    'SPB'                              = 'Microsoft 365 Business Premium'
    'O365_BUSINESS_PREMIUM'            = 'Microsoft 365 Business Standard'
    'O365_BUSINESS_ESSENTIALS'         = 'Microsoft 365 Business Basic'
    'O365_BUSINESS'                    = 'Microsoft 365 Apps for business'
    'SMB_BUSINESS'                     = 'Microsoft 365 Apps for business'
    'OFFICESUBSCRIPTION'               = 'Microsoft 365 Apps for enterprise'
    'SPE_E3'                           = 'Microsoft 365 E3'
    'SPE_E5'                           = 'Microsoft 365 E5'
    'SPE_F1'                           = 'Microsoft 365 F3'
    'M365_F1'                          = 'Microsoft 365 F1'
    'ENTERPRISEPACK'                   = 'Office 365 E3'
    'ENTERPRISEPREMIUM'                = 'Office 365 E5'
    'STANDARDPACK'                     = 'Office 365 E1'
    'DESKLESSPACK'                     = 'Office 365 F3'
    'EXCHANGESTANDARD'                 = 'Exchange Online (Plan 1)'
    'EXCHANGEENTERPRISE'               = 'Exchange Online (Plan 2)'
    'EXCHANGEDESKLESS'                 = 'Exchange Online Kiosk'
    'EXCHANGEARCHIVE_ADDON'            = 'Exchange Online Archiving'
    'AAD_PREMIUM'                      = 'Microsoft Entra ID P1'
    'AAD_PREMIUM_P2'                   = 'Microsoft Entra ID P2'
    'EMS'                              = 'Enterprise Mobility + Security E3'
    'EMSPREMIUM'                       = 'Enterprise Mobility + Security E5'
    'INTUNE_A'                         = 'Microsoft Intune Plan 1'
    'ATP_ENTERPRISE'                   = 'Microsoft Defender for Office 365 (Plan 1)'
    'THREAT_INTELLIGENCE'              = 'Microsoft Defender for Office 365 (Plan 2)'
    'DEFENDER_ENDPOINT_P1'             = 'Microsoft Defender for Endpoint P1'
    'WIN_DEF_ATP'                      = 'Microsoft Defender for Endpoint P2'
    'MDATP_Server'                     = 'Microsoft Defender for Servers'
    'Microsoft_365_Copilot'            = 'Microsoft 365 Copilot'
    'POWER_BI_PRO'                     = 'Power BI Pro'
    'POWER_BI_STANDARD'                = 'Power BI (free)'
    'FLOW_FREE'                        = 'Power Automate (free)'
    'POWERAPPS_VIRAL'                  = 'Power Apps (trial)'
    'TEAMS_EXPLORATORY'                = 'Teams Exploratory'
    'MCOEV'                            = 'Teams Phone Standard'
    'MCOPSTN1'                         = 'Teams Domestic Calling Plan'
    'MCOPSTN2'                         = 'Teams Domestic and International Calling Plan'
    'PHONESYSTEM_VIRTUALUSER'          = 'Teams Phone Resource Account'
    'Microsoft_Teams_Rooms_Pro'        = 'Teams Rooms Pro'
    'Microsoft_Teams_Rooms_Basic'      = 'Teams Rooms Basic'
    'VISIOCLIENT'                      = 'Visio Plan 2'
    'VISIOONLINE_PLAN1'                = 'Visio Plan 1'
    'PROJECTPROFESSIONAL'              = 'Project Plan 3'
    'PROJECT_P1'                       = 'Project Plan 1'
    'WINDOWS_STORE'                    = 'Windows Store for Business'
    'STREAM'                           = 'Microsoft Stream'
    'RIGHTSMANAGEMENT_ADHOC'           = 'Rights Management Adhoc'
    'Microsoft_365_E3'                 = 'Microsoft 365 E3'
    'Microsoft_365_E5'                 = 'Microsoft 365 E5'
    'O365_w/o_Teams_Bundle_M3'         = 'Microsoft 365 E3 (no Teams)'
    'Microsoft_Teams_Enterprise_New'   = 'Microsoft Teams Enterprise'
    'Office_365_E3_(no_Teams)'         = 'Office 365 E3 (no Teams)'
    'Microsoft_365_Business_Premium_(no_Teams)' = 'Microsoft 365 Business Premium (no Teams)'
    'Microsoft_365_Business_Standard_(no_Teams)' = 'Microsoft 365 Business Standard (no Teams)'
    'Microsoft_365_E5_(no_Teams)'      = 'Microsoft 365 E5 (no Teams)'
    'IDENTITY_THREAT_PROTECTION'       = 'Microsoft 365 E5 Security'
    'INFORMATION_PROTECTION_COMPLIANCE' = 'Microsoft 365 E5 Compliance'
    'MDE_SMB'                          = 'Microsoft Defender for Business'
    'ATA'                              = 'Microsoft Defender for Identity'
    'ADALLOM_STANDALONE'               = 'Microsoft Defender for Cloud Apps'
    'UNIVERSAL_PRINT'                  = 'Universal Print'
    'Microsoft_Intune_Suite'           = 'Microsoft Intune Suite'
    'Microsoft_365_Copilot_EDU'        = 'Microsoft 365 Copilot (Education)'
    'M365_COPILOT'                     = 'Microsoft 365 Copilot'
    'Microsoft_Entra_ID_Governance'    = 'Microsoft Entra ID Governance'
    'EXCHANGEARCHIVE'                  = 'Exchange Online Archiving for Exchange Server'
}

$script:TRFreeSkus = @('FLOW_FREE', 'POWER_BI_STANDARD', 'TEAMS_EXPLORATORY', 'WINDOWS_STORE', 'STREAM', 'POWERAPPS_VIRAL', 'CCIBOTS_PRIVPREV_VIRAL', 'MICROSOFT_BUSINESS_CENTER', 'RIGHTSMANAGEMENT_ADHOC', 'POWERAPPS_DEV', 'POWER_PAGES_VTRIAL_FOR_MAKERS', 'MCOMEETADV', 'Power_Pages_vTrial_for_Makers', 'DYN365_ENTERPRISE_P1_IW', 'FORMS_PRO', 'PBI_PREMIUM_PER_USER_VIRAL', 'POWERAUTOMATE_ATTENDED_RPA_VIRAL', 'Microsoft_Teams_Exploratory_Dept', 'AAD_BASIC')

function Get-TRSetting {
    param([string]$Name, $Default)
    $s = $script:TRSettings
    if ($s -and (Test-TRHasProperty $s $Name)) {
        $v = if ($s -is [System.Collections.IDictionary]) { $s[$Name] } else { $s.$Name }
        if ($null -ne $v -and [string]$v -ne '') { return $v }
    }
    $Default
}

function Get-TRRawValue {
    param([string]$Key)
    $r = $script:TRR
    if ($null -eq $r) { return $null }
    if ($r -is [System.Collections.IDictionary]) {
        if ($r.Contains($Key)) { return $r[$Key] }
        return $null
    }
    $p = $r.PSObject.Properties[$Key]
    if ($p) { return $p.Value }
    $null
}

function Get-TRItems {
    param([string]$Key)
    $v = Get-TRRawValue $Key
    if ($null -eq $v) { return }
    foreach ($i in @($v)) { if ($null -ne $i) { $i } }
}

function Get-TRMeta {
    param([string]$Name)
    $m = Get-TRRawValue 'Meta'
    if ($null -eq $m) { return $null }
    if ($m -is [System.Collections.IDictionary]) { if ($m.Contains($Name)) { return $m[$Name] } else { return $null } }
    $p = $m.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    $null
}

$script:TRDataParents = @{
    AppPermissions = @('ServicePrincipals'); DnsRecords = @('Domains'); GroupMembers = @('Groups')
    GwsTokens = @('GwsUsers'); GwsAsps = @('GwsUsers'); GwsDnsRecords = @('GwsDomains'); GwsGroupSettings = @('GwsGroups'); GwsGroupMembers = @('GwsGroups')
}

function Get-TRNeedKeys {
    param([string[]]$Keys)
    $out = New-Object System.Collections.ArrayList
    foreach ($k in $Keys) {
        foreach ($p in @($script:TRDataParents[$k])) { if ($p -and -not $out.Contains($p)) { [void]$out.Add($p) } }
        if (-not $out.Contains($k)) { [void]$out.Add($k) }
    }
    $out.ToArray()
}

function Test-TRLicenceDataKnown {
    if ((Get-TRPlatform) -eq 'Google') { return (Test-TRCollected @('GwsLicences')) }
    Test-TRCollected @('SubscribedSkus')
}

function Test-TRCollected {
    param([string[]]$Keys)
    foreach ($k in (Get-TRNeedKeys $Keys)) {
        $d = $script:TRDiagIndex[$k]
        if (-not $d -or $d.Status -ne 'OK') { return $false }
    }
    $true
}

function Get-TRMissingReason {
    param([string[]]$Keys)
    $reasons = @()
    foreach ($k in (Get-TRNeedKeys $Keys)) {
        $d = $script:TRDiagIndex[$k]
        if (-not $d) {
            $ver = [string](Get-TRMeta 'ToolVersion')
            if ($ver -and $script:TRToolVersion -and $ver -ne $script:TRToolVersion) { $reasons += ('{0} was not collected (area not selected, or the saved data is from version {1} of the tool)' -f $k, $ver) }
            else { $reasons += "$k was not collected (area not selected)" }
        }
        elseif ($d.Status -ne 'OK') {
            $msg = [string]$d.Message
            if ($msg.Length -gt 220) { $msg = $msg.Substring(0, 220) + '...' }
            $reasons += ('{0}: {1}' -f $k, $msg)
        }
    }
    $reasons -join '; '
}

function Get-TRCached {
    param([string]$Name, [scriptblock]$Build)
    if (-not $script:TRCache.ContainsKey($Name)) {
        $value = & $Build
        $script:TRCache[$Name] = $value
    }
    $script:TRCache[$Name]
}

function Get-TRUserIndex {
    Get-TRCached 'UserIndex' {
        $h = @{}
        foreach ($u in (Get-TRItems 'Users')) { $h[[string]$u.id] = $u }
        $h
    }
}

function Get-TRRegIndex {
    Get-TRCached 'RegIndex' {
        $h = @{}
        foreach ($r in (Get-TRItems 'RegistrationDetails')) { $h[[string]$r.id] = $r }
        $h
    }
}

function Get-TRResourceAccountIds {
    Get-TRCached 'ResourceIds' {
        $h = @{}
        foreach ($m in (Get-TRItems 'ExoMailboxes')) {
            if ($m.RecipientTypeDetails -match 'SharedMailbox|RoomMailbox|EquipmentMailbox|SchedulingMailbox' -and $m.ExternalDirectoryObjectId) {
                $h[[string]$m.ExternalDirectoryObjectId] = [string]$m.RecipientTypeDetails
            }
        }
        $h
    }
}

function Get-TRPeople {
    Get-TRCached 'People' {
        $res = Get-TRResourceAccountIds
        @(Get-TRItems 'Users' | Where-Object {
                $_.userType -eq 'Member' -and $_.accountEnabled -eq $true -and @($_.assignedLicenses).Count -gt 0 -and -not $res.ContainsKey([string]$_.id)
            })
    }
}

function Get-TRServicePlans {
    Get-TRCached 'ServicePlans' {
        $h = @{}
        foreach ($s in (Get-TRItems 'SubscribedSkus')) {
            if ($s.capabilityStatus -notin @('Enabled', 'Warning')) { continue }
            if ([int]$s.prepaidUnits.enabled -le 0 -and [int]$s.consumedUnits -le 0) { continue }
            foreach ($p in @($s.servicePlans)) {
                if ($p -and $p.servicePlanName) { $h[[string]$p.servicePlanName] = $true }
            }
            $h['SKU:' + [string]$s.skuPartNumber] = $true
        }
        $h
    }
}

function Test-TRPlan {
    param([string[]]$Plans)
    $sp = Get-TRServicePlans
    foreach ($p in $Plans) { if ($sp[$p]) { return $true } }
    $false
}

function Test-TRLicensed {
    param([string]$Capability)
    if ((Get-TRPlatform) -eq 'Google') { return (Test-TRGwsCapability $Capability) }
    $set = $script:TRPlanSets[$Capability]
    if (-not $set) { return $false }
    Test-TRPlan $set
}

function Get-TRUserPlanIndex {
    Get-TRCached 'UserPlans' {
        $skuPlans = @{}
        foreach ($s in (Get-TRItems 'SubscribedSkus')) {
            $list = New-Object System.Collections.ArrayList
            foreach ($p in @($s.servicePlans)) {
                if ($p -and $p.servicePlanName) { [void]$list.Add([pscustomobject]@{ Id = [string]$p.servicePlanId; Name = [string]$p.servicePlanName }) }
            }
            $skuPlans[[string]$s.skuId] = [pscustomobject]@{ PartNumber = [string]$s.skuPartNumber; Plans = $list.ToArray() }
        }
        $index = @{}
        foreach ($u in (Get-TRPeople)) {
            $set = @{}
            foreach ($l in @($u.assignedLicenses)) {
                if (-not $l -or -not $l.skuId) { continue }
                $sku = $skuPlans[[string]$l.skuId]
                if (-not $sku) { continue }
                $set['SKU:' + $sku.PartNumber] = $true
                $disabled = @{}
                foreach ($d in @($l.disabledPlans)) { if ($d) { $disabled[[string]$d] = $true } }
                foreach ($p in $sku.Plans) {
                    if ($p.Id -and $disabled.ContainsKey($p.Id)) { continue }
                    $set[$p.Name] = $true
                }
            }
            $index[[string]$u.id] = $set
        }
        $index
    }
}

function Get-TRFeatureUserCount {
    param([string[]]$Plans)
    $n = 0
    foreach ($set in (Get-TRUserPlanIndex).Values) {
        foreach ($p in $Plans) { if ($set.ContainsKey($p)) { $n++; break } }
    }
    $n
}

function Get-TRFeatureSkus {
    param([string[]]$Plans)
    $names = New-Object System.Collections.ArrayList
    foreach ($s in (Get-TRItems 'SubscribedSkus')) {
        if ([string]$s.capabilityStatus -notin @('Enabled', 'Warning')) { continue }
        if ([int]$s.prepaidUnits.enabled -le 0 -and [int]$s.consumedUnits -le 0) { continue }
        $hit = $Plans -contains ('SKU:' + [string]$s.skuPartNumber)
        if (-not $hit) {
            foreach ($p in @($s.servicePlans)) { if ($p -and $Plans -contains [string]$p.servicePlanName) { $hit = $true; break } }
        }
        if ($hit) {
            $n = Get-TRSkuName ([string]$s.skuPartNumber)
            if (-not $names.Contains($n)) { [void]$names.Add($n) }
        }
    }
    (@($names) -join ', ')
}

function Get-TRSkuName {
    param([string]$PartNumber)
    $n = $script:TRSkuNames[$PartNumber]
    if ($n) { return $n }
    $PartNumber
}

function Get-TRSkuIndex {
    Get-TRCached 'SkuIndex' {
        $h = @{}
        foreach ($s in (Get-TRItems 'SubscribedSkus')) { $h[[string]$s.skuId] = [string]$s.skuPartNumber }
        $h
    }
}

function Get-TRUserLicenceNames {
    param($User)
    $idx = Get-TRSkuIndex
    $names = foreach ($l in @($User.assignedLicenses)) {
        if ($l -and $l.skuId) {
            $pn = $idx[[string]$l.skuId]
            if ($pn) { Get-TRSkuName $pn } else { [string]$l.skuId }
        }
    }
    (@($names) -join '; ')
}

function Get-TRRoleRows {
    Get-TRCached 'RoleRows' {
        $defs = @{}
        foreach ($d in (Get-TRItems 'RoleDefinitions')) {
            $defs[[string]$d.id] = $d
            if ($d.templateId) { $defs[[string]$d.templateId] = $d }
        }
        $rows = New-Object System.Collections.ArrayList
        foreach ($set in @(@{ Key = 'RoleAssignments'; Type = 'Active' }, @{ Key = 'RoleEligibility'; Type = 'Eligible' })) {
            foreach ($a in (Get-TRItems $set.Key)) {
                $def = $defs[[string]$a.roleDefinitionId]
                $template = if ($def -and $def.templateId) { [string]$def.templateId } else { [string]$a.roleDefinitionId }
                $name = if ($def) { [string]$def.displayName } elseif ($script:TRPrivilegedTemplates[$template]) { $script:TRPrivilegedTemplates[$template] } else { $template }
                $priv = $false
                if ($def -and (Test-TRHasProperty $def 'isPrivileged') -and $def.isPrivileged -eq $true) { $priv = $true }
                if ($script:TRPrivilegedTemplates.ContainsKey($template)) { $priv = $true }
                $p = $a.principal
                $ptype = ([string]$p.'@odata.type') -replace '^#microsoft\.graph\.', ''
                [void]$rows.Add([pscustomobject][ordered]@{
                        Role          = $name
                        RoleTemplate  = $template
                        Privileged    = $priv
                        Assignment    = $set.Type
                        PrincipalId   = [string]$a.principalId
                        PrincipalName = $(if ($p) { [string]$p.displayName } else { [string]$a.principalId })
                        PrincipalUpn  = $(if ($p -and $p.userPrincipalName) { [string]$p.userPrincipalName } elseif ($p -and $p.appId) { [string]$p.appId } else { '' })
                        PrincipalType = $ptype
                        Scope         = [string]$a.directoryScopeId
                    })
            }
        }
        , $rows.ToArray()
    }
}

function Get-TRCaPolicies {
    param([string[]]$State = @('enabled'))
    @(Get-TRItems 'ConditionalAccessPolicies' | Where-Object { $State -contains [string]$_.state })
}

function Test-TRCaAllUsers { param($P) @($P.conditions.users.includeUsers) -contains 'All' }
function Test-TRCaAllApps { param($P) @($P.conditions.applications.includeApplications) -contains 'All' }
function Test-TRCaMfa { param($P) (@($P.grantControls.builtInControls) -contains 'mfa') -or ($null -ne $P.grantControls.authenticationStrength) }
function Test-TRCaBlock { param($P) @($P.grantControls.builtInControls) -contains 'block' }
function Test-TRCaLegacy {
    param($P)
    $t = @($P.conditions.clientAppTypes)
    ($t -contains 'exchangeActiveSync') -and ($t -contains 'other')
}
function Test-TRCaPhishResistant {
    param($P)
    $s = $P.grantControls.authenticationStrength
    if (-not $s) { return $false }
    if ([string]$s.id -eq '00000000-0000-0000-0000-000000000004') { return $true }
    $combos = @($s.allowedCombinations)
    if ($combos.Count -eq 0) { return $false }
    foreach ($c in $combos) {
        if ([string]$c -notmatch '^(fido2|windowsHelloForBusiness|x509CertificateMultiFactor)') { return $false }
    }
    $true
}
function Test-TRCaTargetsAdmins {
    param($P)
    if (Test-TRCaAllUsers $P) { return $true }
    @($P.conditions.users.includeRoles).Count -gt 0
}

function Format-TRCaUsers {
    param($P)
    $u = $P.conditions.users
    $inc = @()
    if (@($u.includeUsers).Count) { $inc += ('Users: ' + (@($u.includeUsers) -join ', ')) }
    if (@($u.includeGroups).Count) { $inc += ('Groups: ' + @($u.includeGroups).Count) }
    if (@($u.includeRoles).Count) { $inc += ('Roles: ' + @($u.includeRoles).Count) }
    if ($u.includeGuestsOrExternalUsers) { $inc += 'Guests or external users' }
    $exc = @($u.excludeUsers).Count + @($u.excludeGroups).Count + @($u.excludeRoles).Count
    $text = ($inc -join '; ')
    if ($exc) { $text += " (exclusions: $exc)" }
    $text
}

function Format-TRCaGrant {
    param($P)
    $g = $P.grantControls
    $parts = @()
    if ($g) {
        $parts += @($g.builtInControls)
        if ($g.authenticationStrength) { $parts += ('Strength: ' + $g.authenticationStrength.displayName) }
        if (@($g.builtInControls).Count -gt 1) { $parts = @(($parts -join (' ' + [string]$g.operator + ' '))) }
    }
    $s = $P.sessionControls
    if ($s) {
        if ($s.signInFrequency -and $s.signInFrequency.isEnabled) { $parts += ('Sign-in frequency ' + $s.signInFrequency.value + ' ' + $s.signInFrequency.type) }
        if ($s.persistentBrowser -and $s.persistentBrowser.isEnabled) { $parts += ('Persistent browser ' + $s.persistentBrowser.mode) }
    }
    (@($parts | Where-Object { $_ }) -join '; ')
}

function New-TRAffected {
    param([string]$Item, [string]$Detail = '')
    [pscustomobject][ordered]@{ Item = $Item; Detail = $Detail }
}

function New-TRResult {
    param(
        [ValidateSet('Pass', 'Fail', 'Warning', 'Info', 'Manual', 'NotAssessed')][string]$Status,
        [string]$Current,
        $Affected = @()
    )
    [pscustomobject]@{ Status = $Status; Current = $Current; Affected = @($Affected | Where-Object { $null -ne $_ }) }
}

function Get-TRNow {
    Get-TRCached 'ReviewTime' {
        $t = ConvertTo-TRDate (Get-TRMeta 'FinishedUtc')
        if ($null -eq $t) { $t = ConvertTo-TRDate (Get-TRMeta 'StartedUtc') }
        if ($null -eq $t) { $t = (Get-Date).ToUniversalTime() }
        $t
    }
}

function Get-TRDaysSince {
    param($Date)
    $d = ConvertTo-TRDate $Date
    if ($null -eq $d) { return $null }
    [int]((Get-TRNow) - $d).TotalDays
}

function Get-TRPercent {
    param([double]$Part, [double]$Whole)
    if ($Whole -le 0) { return 0 }
    [Math]::Round(100 * $Part / $Whole, 1)
}

function ConvertTo-TRPlainText {
    param([string]$Html)
    if (-not $Html) { return '' }
    $t = [regex]::Replace($Html, '<br\s*/?>|</p>|</li>', ' ')
    $t = [regex]::Replace($t, '<[^>]+>', '')
    $t = [Net.WebUtility]::HtmlDecode($t)
    $t = $t -replace [char]0x2014, '-' -replace [char]0x2013, '-'
    ([regex]::Replace($t, '\s+', ' ')).Trim()
}

function Get-TRGroupSettingValue {
    param([string]$Template, [string]$Name)
    foreach ($g in (Get-TRItems 'GroupSettings')) {
        if ([string]$g.displayName -ne $Template -and [string]$g.templateId -ne $Template) { continue }
        foreach ($v in @($g.values)) { if ([string]$v.name -eq $Name) { return [string]$v.value } }
    }
    $null
}
