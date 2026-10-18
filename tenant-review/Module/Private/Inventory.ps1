function ConvertTo-TRYesNo {
    param($Value)
    if ($null -eq $Value -or [string]$Value -eq '') { return '' }
    if ($Value -eq $true -or [string]$Value -eq 'True') { return 'Yes' }
    if ($Value -eq $false -or [string]$Value -eq 'False') { return 'No' }
    [string]$Value
}

function ConvertTo-TRGb {
    param($Bytes)
    $b = 0.0
    if (-not [double]::TryParse([string]$Bytes, [ref]$b)) { return '' }
    [Math]::Round($b / 1GB, 2)
}

function Add-TRInventory {
    param([System.Collections.Specialized.OrderedDictionary]$Target, [string]$Name, [string]$Title, [string]$Description, $Rows)
    $Target[$Name] = [pscustomobject]@{ Name = $Name; Title = $Title; Description = $Description; Rows = @($Rows | Where-Object { $null -ne $_ }) }
}

function Get-TRInventories {
    if ((Get-TRPlatform) -eq 'Google') { return (Get-TRGwsInventories) }
    $inv = New-Object System.Collections.Specialized.OrderedDictionary
    $reg = Get-TRRegIndex
    $res = Get-TRResourceAccountIds
    $roleRows = @(Get-TRRoleRows)
    $rolesByUser = @{}
    foreach ($r in $roleRows) {
        if ($r.PrincipalType -ne 'user') { continue }
        if (-not $rolesByUser.ContainsKey($r.PrincipalId)) { $rolesByUser[$r.PrincipalId] = New-Object System.Collections.ArrayList }
        $label = if ($r.Assignment -eq 'Eligible') { $r.Role + ' (eligible)' } else { $r.Role }
        if (-not $rolesByUser[$r.PrincipalId].Contains($label)) { [void]$rolesByUser[$r.PrincipalId].Add($label) }
    }

    if (Test-TRCollected @('Users')) {
        $rows = foreach ($u in (Get-TRItems 'Users')) {
            $rg = $reg[[string]$u.id]
            $last = $null
            if ($u.signInActivity) {
                $last = ConvertTo-TRDate $u.signInActivity.lastSignInDateTime
                $ni = ConvertTo-TRDate $u.signInActivity.lastNonInteractiveSignInDateTime
                if ($ni -and (-not $last -or $ni -gt $last)) { $last = $ni }
            }
            $kind = if ($res.ContainsKey([string]$u.id)) { $res[[string]$u.id] -replace 'Mailbox$', ' mailbox' } else { 'User' }
            [pscustomobject][ordered]@{
                'Display name'   = $u.displayName
                'UPN'            = $u.userPrincipalName
                'User type'      = $u.userType
                'Account'        = $kind
                'Sign-in'        = $(if ($u.accountEnabled -eq $true) { 'Enabled' } else { 'Blocked' })
                'Licences'       = (Get-TRUserLicenceNames $u)
                'MFA capable'    = $(if ($rg) { ConvertTo-TRYesNo $rg.isMfaCapable } else { '' })
                'Methods'        = $(if ($rg) { (@($rg.methodsRegistered)) -join ', ' } else { '' })
                'Admin roles'    = $(if ($rolesByUser.ContainsKey([string]$u.id)) { ($rolesByUser[[string]$u.id] -join ', ') } else { '' })
                'Last sign-in'   = $(if ($last) { Format-TRDate $last } else { '' })
                'Created'        = (Format-TRDate $u.createdDateTime)
                'Source'         = $(if ($u.onPremisesSyncEnabled -eq $true) { 'Synced' } else { 'Cloud' })
                'Department'     = $u.department
                'Job title'      = $u.jobTitle
            }
        }
        Add-TRInventory $inv 'Users' 'Users' 'All user accounts with licences, MFA registration and admin roles.' $rows
    }

    if ($roleRows.Count) {
        $idx = Get-TRUserIndex
        $rows = foreach ($r in ($roleRows | Sort-Object @{ e = { -not $_.Privileged } }, Role, PrincipalName)) {
            $u = $idx[$r.PrincipalId]
            $rg = $reg[$r.PrincipalId]
            [pscustomobject][ordered]@{
                'Role'         = $r.Role
                'Privileged'   = ConvertTo-TRYesNo $r.Privileged
                'Assignment'   = $r.Assignment
                'Principal'    = $r.PrincipalName
                'UPN or app'   = $r.PrincipalUpn
                'Type'         = $r.PrincipalType
                'MFA capable'  = $(if ($rg) { ConvertTo-TRYesNo $rg.isMfaCapable } else { '' })
                'Source'       = $(if ($u -and $u.onPremisesSyncEnabled -eq $true) { 'Synced' } elseif ($u) { 'Cloud' } else { '' })
                'Licensed'     = $(if ($u) { ConvertTo-TRYesNo (@($u.assignedLicenses).Count -gt 0) } else { '' })
                'Scope'        = $r.Scope
            }
        }
        Add-TRInventory $inv 'Admins' 'Admin roles' 'Active and eligible directory role assignments.' $rows
    }

    if (Test-TRCollected @('ConditionalAccessPolicies')) {
        $rows = foreach ($p in (Get-TRItems 'ConditionalAccessPolicies' | Sort-Object state, displayName)) {
            $apps = $p.conditions.applications
            $appText = @()
            if (@($apps.includeApplications).Count) { $appText += ('Include: ' + ((@($apps.includeApplications)) -join ', ')) }
            if (@($apps.excludeApplications).Count) { $appText += ('Exclude: ' + @($apps.excludeApplications).Count) }
            if (@($apps.includeUserActions).Count) { $appText += ('Actions: ' + ((@($apps.includeUserActions)) -join ', ')) }
            $cond = @()
            if (@($p.conditions.clientAppTypes).Count -and (@($p.conditions.clientAppTypes) -join ',') -ne 'all') { $cond += ('Client apps: ' + ((@($p.conditions.clientAppTypes)) -join ', ')) }
            if (@($p.conditions.platforms.includePlatforms).Count) { $cond += ('Platforms: ' + ((@($p.conditions.platforms.includePlatforms)) -join ', ')) }
            if (@($p.conditions.locations.includeLocations).Count) { $cond += ('Locations: ' + ((@($p.conditions.locations.includeLocations)) -join ', ')) }
            if (@($p.conditions.userRiskLevels).Count) { $cond += ('User risk: ' + ((@($p.conditions.userRiskLevels)) -join ', ')) }
            if (@($p.conditions.signInRiskLevels).Count) { $cond += ('Sign-in risk: ' + ((@($p.conditions.signInRiskLevels)) -join ', ')) }
            [pscustomobject][ordered]@{
                'Policy'     = $p.displayName
                'State'      = $(switch ([string]$p.state) { 'enabled' { 'On' } 'disabled' { 'Off' } 'enabledForReportingButNotEnforced' { 'Report-only' } default { $p.state } })
                'Users'      = (Format-TRCaUsers $p)
                'Apps'       = ($appText -join '; ')
                'Conditions' = ($cond -join '; ')
                'Controls'   = (Format-TRCaGrant $p)
                'Modified'   = (Format-TRDate $(if ($p.modifiedDateTime) { $p.modifiedDateTime } else { $p.createdDateTime }))
            }
        }
        Add-TRInventory $inv 'ConditionalAccess' 'Conditional Access' 'All Conditional Access policies and their main settings.' $rows
    }

    if (Test-TRCollected @('SubscribedSkus')) {
        $rows = foreach ($s in (Get-TRItems 'SubscribedSkus' | Sort-Object { Get-TRSkuName $_.skuPartNumber })) {
            $en = [int]$s.prepaidUnits.enabled
            [pscustomobject][ordered]@{
                'Product'    = (Get-TRSkuName $s.skuPartNumber)
                'SKU'        = $s.skuPartNumber
                'Purchased'  = $en
                'Assigned'   = [int]$s.consumedUnits
                'Available'  = ($en - [int]$s.consumedUnits)
                'Status'     = $s.capabilityStatus
                'Warning'    = [int]$s.prepaidUnits.warning
                'Suspended'  = [int]$s.prepaidUnits.suspended
            }
        }
        Add-TRInventory $inv 'Licences' 'Licences' 'Subscriptions, purchased and assigned quantities.' $rows
    }

    if (Test-TRCollected @('Domains')) {
        $dns = @{}
        foreach ($d in (Get-TRItems 'DnsRecords')) { $dns[([string]$d.Domain).ToLower()] = $d }
        $dkim = @{}
        foreach ($d in (Get-TRItems 'ExoDkim')) { $dkim[([string]$d.Domain).ToLower()] = $d }
        $rows = foreach ($d in (Get-TRItems 'Domains')) {
            $r = $dns[([string]$d.id).ToLower()]
            $k = $dkim[([string]$d.id).ToLower()]
            [pscustomobject][ordered]@{
                'Domain'          = $d.id
                'Verified'        = ConvertTo-TRYesNo $d.isVerified
                'Default'         = ConvertTo-TRYesNo $d.isDefault
                'Authentication'  = $d.authenticationType
                'Services'        = ((@($d.supportedServices)) -join ', ')
                'MX'              = $(if ($r) { (@($r.Mx)) -join '; ' } else { '' })
                'SPF'             = $(if ($r) { (@($r.Spf)) -join ' | ' } else { '' })
                'DMARC'           = $(if ($r) { (@($r.Dmarc)) -join ' | ' } else { '' })
                'DKIM signing'    = $(if ($k) { ConvertTo-TRYesNo $k.Enabled } else { '' })
                'DKIM CNAMEs'     = $(if ($r) { ConvertTo-TRYesNo ((@($r.DkimSelector1).Count -gt 0) -and (@($r.DkimSelector2).Count -gt 0)) } else { '' })
                'MTA-STS'         = $(if ($r) { ConvertTo-TRYesNo (@($r.MtaSts).Count -gt 0) } else { '' })
                'Password expiry' = $(if ($d.passwordValidityPeriodInDays -and [int64]$d.passwordValidityPeriodInDays -lt 2147483647) { [string]$d.passwordValidityPeriodInDays + ' days' } elseif ($d.authenticationType -eq 'Managed') { 'Never' } else { '' })
            }
        }
        Add-TRInventory $inv 'Domains' 'Domains and DNS' 'Domains with email authentication records.' $rows
    }

    if (Test-TRCollected @('ExoMailboxes')) {
        $usage = @{}
        foreach ($m in (Get-TRItems 'MailboxUsage')) { if ($m.'User Principal Name') { $usage[([string]$m.'User Principal Name').ToLower()] = $m } }
        $rows = foreach ($m in (Get-TRItems 'ExoMailboxes' | Sort-Object RecipientTypeDetails, DisplayName)) {
            $u = $usage[([string]$m.UserPrincipalName).ToLower()]
            $fwd = if ($m.ForwardingSmtpAddress) { ([string]$m.ForwardingSmtpAddress) -replace '^smtp:', '' } else { [string]$m.ForwardingAddress }
            [pscustomobject][ordered]@{
                'Name'            = $m.DisplayName
                'Address'         = $m.PrimarySmtpAddress
                'Type'            = $m.RecipientTypeDetails
                'Forwarding'      = $fwd
                'Audit'           = ConvertTo-TRYesNo $m.AuditEnabled
                'Litigation hold' = ConvertTo-TRYesNo $m.LitigationHoldEnabled
                'Archive'         = $m.ArchiveStatus
                'Size GB'         = $(if ($u) { ConvertTo-TRGb $u.'Storage Used (Byte)' } else { '' })
                'Items'           = $(if ($u) { $u.'Item Count' } else { '' })
                'Last activity'   = $(if ($u) { Format-TRDate $u.'Last Activity Date' } else { '' })
                'Hidden from GAL' = ConvertTo-TRYesNo $m.HiddenFromAddressListsEnabled
                'Created'         = (Format-TRDate $m.WhenCreated)
            }
        }
        Add-TRInventory $inv 'Mailboxes' 'Mailboxes' 'Exchange Online mailboxes with forwarding, audit, archive and size.' $rows
    }

    if (Test-TRCollected @('MailboxPermissions')) {
        $rows = foreach ($p in (Get-TRItems 'MailboxPermissions' | Sort-Object MailboxType, Mailbox, Permission)) {
            [pscustomobject][ordered]@{
                'Mailbox'      = $p.Mailbox
                'Mailbox name' = $p.MailboxName
                'Mailbox type' = $p.MailboxType
                'Delegate'     = $p.Delegate
                'Permission'   = $p.Permission
            }
        }
        Add-TRInventory $inv 'MailboxPermissions' 'Mailbox permissions' 'Full Access, Send As and Send on Behalf permissions.' $rows
    }

    if (Test-TRCollected @('Groups')) {
        $counts = @{}
        foreach ($m in (Get-TRItems 'GroupMembers')) {
            $k = [string]$m.GroupId
            if (-not $counts.ContainsKey($k)) { $counts[$k] = @{ Owners = 0; Members = 0; Guests = 0 } }
            if ($m.Role -eq 'Owner') { $counts[$k].Owners++ } else { $counts[$k].Members++ }
            if ($m.Role -eq 'Member' -and $m.UserType -eq 'Guest') { $counts[$k].Guests++ }
        }
        $haveMembers = Test-TRCollected @('GroupMembers')
        $rows = foreach ($g in (Get-TRItems 'Groups' | Sort-Object displayName)) {
            $kind = if (@($g.groupTypes) -contains 'Unified') { if (@($g.resourceProvisioningOptions) -contains 'Team') { 'Team' } else { 'Microsoft 365 group' } } elseif ($g.mailEnabled -and $g.securityEnabled) { 'Mail-enabled security' } elseif ($g.mailEnabled) { 'Distribution list' } else { 'Security group' }
            $c = $counts[[string]$g.id]
            [pscustomobject][ordered]@{
                'Name'       = $g.displayName
                'Kind'       = $kind
                'Visibility' = $g.visibility
                'Owners'     = $(if ($haveMembers -and @($g.groupTypes) -contains 'Unified') { if ($c) { $c.Owners } else { 0 } } else { '' })
                'Members'    = $(if ($haveMembers -and @($g.groupTypes) -contains 'Unified') { if ($c) { $c.Members } else { 0 } } else { '' })
                'Guests'     = $(if ($haveMembers -and @($g.groupTypes) -contains 'Unified') { if ($c) { $c.Guests } else { 0 } } else { '' })
                'Dynamic'    = ConvertTo-TRYesNo ([bool]$g.membershipRule)
                'Source'     = $(if ($g.onPremisesSyncEnabled -eq $true) { 'Synced' } else { 'Cloud' })
                'Email'      = $g.mail
                'Created'    = (Format-TRDate $g.createdDateTime)
            }
        }
        Add-TRInventory $inv 'Groups' 'Groups and Teams' 'All groups, with owner, member and guest counts for Microsoft 365 groups and Teams.' $rows
    }

    if (Test-TRCollected @('GroupMembers')) {
        $rows = foreach ($m in (Get-TRItems 'GroupMembers' | Sort-Object GroupName, Role, Member)) {
            [pscustomobject][ordered]@{
                'Group or Team' = $m.GroupName
                'Team'          = ConvertTo-TRYesNo $m.IsTeam
                'Visibility'    = $m.Visibility
                'Role'          = $m.Role
                'Member'        = $m.Member
                'UPN or email'  = $m.MemberUpn
                'User type'     = $m.UserType
                'Object type'   = $m.ObjectType
            }
        }
        Add-TRInventory $inv 'GroupMembers' 'Group and Team membership' 'Owners and members of every Microsoft 365 group and Team (site membership for group-connected sites).' $rows
    }

    if (Test-TRCollected @('SiteUsage')) {
        $rows = foreach ($s in (Get-TRItems 'SiteUsage' | Where-Object { [string]$_.'Is Deleted' -ne 'True' } | Sort-Object { -1 * [double]$_.'Storage Used (Byte)' })) {
            [pscustomobject][ordered]@{
                'Site URL'      = $s.'Site URL'
                'Owner'         = $s.'Owner Display Name'
                'Owner UPN'     = $s.'Owner Principal Name'
                'Template'      = $s.'Root Web Template'
                'Files'         = $s.'File Count'
                'Active files'  = $s.'Active File Count'
                'Storage GB'    = (ConvertTo-TRGb $s.'Storage Used (Byte)')
                'Page views'    = $s.'Page View Count'
                'Last activity' = (Format-TRDate $s.'Last Activity Date')
            }
        }
        Add-TRInventory $inv 'Sites' 'SharePoint sites' 'SharePoint sites from the 30-day usage report.' $rows
    }

    if (Test-TRCollected @('OneDriveUsage')) {
        $rows = foreach ($s in (Get-TRItems 'OneDriveUsage' | Where-Object { [string]$_.'Is Deleted' -ne 'True' } | Sort-Object { -1 * [double]$_.'Storage Used (Byte)' })) {
            [pscustomobject][ordered]@{
                'Owner'         = $s.'Owner Display Name'
                'Owner UPN'     = $s.'Owner Principal Name'
                'Files'         = $s.'File Count'
                'Active files'  = $s.'Active File Count'
                'Storage GB'    = (ConvertTo-TRGb $s.'Storage Used (Byte)')
                'Last activity' = (Format-TRDate $s.'Last Activity Date')
            }
        }
        Add-TRInventory $inv 'OneDrive' 'OneDrive accounts' 'OneDrive accounts from the 30-day usage report.' $rows
    }

    if (Test-TRCollected @('ManagedDevices')) {
        $rows = foreach ($d in (Get-TRItems 'ManagedDevices' | Sort-Object operatingSystem, deviceName)) {
            [pscustomobject][ordered]@{
                'Device'      = $d.deviceName
                'OS'          = $d.operatingSystem
                'Version'     = $d.osVersion
                'Compliance'  = $d.complianceState
                'Encrypted'   = ConvertTo-TRYesNo $d.isEncrypted
                'Ownership'   = $d.managedDeviceOwnerType
                'User'        = $d.userPrincipalName
                'Model'       = ('{0} {1}' -f $d.manufacturer, $d.model).Trim()
                'Serial'      = $d.serialNumber
                'Enrolment'   = $d.deviceEnrollmentType
                'Last sync'   = (Format-TRDate $d.lastSyncDateTime)
                'Enrolled'    = (Format-TRDate $d.enrolledDateTime)
            }
        }
        Add-TRInventory $inv 'IntuneDevices' 'Intune devices' 'Devices managed by Intune.' $rows
    }

    if (Test-TRCollected @('DeviceConfigurations', 'CompliancePolicies')) {
        $status = @{}
        foreach ($st in (Get-TRItems 'IntunePolicyStatus')) { $status[[string]$st.PolicyId] = $st }
        $rows = foreach ($p in (Get-TRIntunePolicyList | Sort-Object Kind, Name)) {
            $st = $status[$p.Id]
            [pscustomobject][ordered]@{
                'Policy'        = $p.Name
                'Kind'          = $p.Kind
                'Type'          = $p.Type
                'Platform'      = $p.Platform
                'Assigned'      = $(if ($p.Known) { ConvertTo-TRYesNo $p.Assigned } else { 'Unknown' })
                'Assigned to'   = $p.Targets
                'Errors'        = $(if ($st) { [int]$st.Errors } else { '' })
                'Conflicts'     = $(if ($st) { [int]$st.Conflicts } else { '' })
                'Last modified' = (Format-TRDate $p.Modified)
            }
        }
        Add-TRInventory $inv 'IntunePolicies' 'Intune policies' 'Configuration profiles, settings catalog, endpoint security, baselines, compliance, app protection and Autopilot profiles, with assignments and device errors or conflicts.' $rows
    }

    if (Test-TRCollected @('IntuneApplePush')) {
        $rows = @()
        foreach ($c in (Get-TRItems 'IntuneApplePush')) { $rows += [pscustomobject][ordered]@{ 'Connection' = 'Apple MDM push certificate'; 'Name' = $c.topicIdentifier; 'Account' = $c.appleIdentifier; 'State' = $c.certificateUploadStatus; 'Expires' = (Format-TRDate $c.expirationDateTime); 'Last sync' = ''; 'Detail' = '' } }
        foreach ($t in (Get-TRItems 'IntuneDepTokens')) { $rows += [pscustomobject][ordered]@{ 'Connection' = 'Apple Business Manager enrolment token'; 'Name' = $t.tokenName; 'Account' = $t.appleIdentifier; 'State' = $(if ([int]$t.lastSyncErrorCode) { 'Sync error ' + $t.lastSyncErrorCode } else { 'OK' }); 'Expires' = (Format-TRDate $t.tokenExpirationDateTime); 'Last sync' = (Format-TRDate $t.lastSuccessfulSyncDateTime); 'Detail' = (Format-TRN ([int]$t.syncedDeviceCount) 'device') } }
        foreach ($t in (Get-TRItems 'IntuneVppTokens')) { $rows += [pscustomobject][ordered]@{ 'Connection' = 'Apple Apps and Books token'; 'Name' = $t.organizationName; 'Account' = $t.appleId; 'State' = $t.state; 'Expires' = (Format-TRDate $t.expirationDateTime); 'Last sync' = (Format-TRDate $t.lastSyncDateTime); 'Detail' = ('Sync {0}; {1}' -f $t.lastSyncStatus, (Format-TRN ([int]$t.lastAppCount) 'app')) } }
        foreach ($a in (Get-TRItems 'IntuneAndroidEnterprise')) { $rows += [pscustomobject][ordered]@{ 'Connection' = 'Managed Google Play (Android Enterprise)'; 'Name' = $a.ownerOrganizationName; 'Account' = $a.ownerUserPrincipalName; 'State' = $a.bindStatus; 'Expires' = ''; 'Last sync' = (Format-TRDate $a.lastAppSyncDateTime); 'Detail' = ('App sync ' + $a.lastAppSyncStatus) } }
        Add-TRInventory $inv 'IntuneConnections' 'Intune connections' 'Apple push certificate, Apple Business Manager and Apps and Books tokens, and the Managed Google Play connection.' $rows
    }

    if (Test-TRCollected @('IntunePolicySettings')) {
        $rows = foreach ($r in (Get-TRAsrRules | Sort-Object Name, Policy)) {
            [pscustomobject][ordered]@{ 'Rule' = $r.Name; 'Mode' = $r.Mode; 'Policy' = $r.Policy; 'Standard protection rule' = ConvertTo-TRYesNo ($script:TRAsrStandardRules -contains $r.Rule) }
        }
        Add-TRInventory $inv 'AsrRules' 'Attack surface reduction rules' 'Attack surface reduction rules set by assigned Intune policies, and their mode.' $rows
    }

    if (Test-TRCollected @('AutopilotDevices')) {
        $md = @{}
        foreach ($d in (Get-TRItems 'ManagedDevices')) { if ($d.serialNumber) { $md[[string]$d.serialNumber] = $d } }
        $rows = foreach ($a in (Get-TRItems 'AutopilotDevices' | Sort-Object groupTag, serialNumber)) {
            $m = $md[[string]$a.serialNumber]
            [pscustomobject][ordered]@{
                'Serial'         = $a.serialNumber
                'Model'          = $a.model
                'Group tag'      = $a.groupTag
                'Enrolment'      = $a.enrollmentState
                'Profile'        = $a.deploymentProfileAssignmentStatus
                'Intune device'  = $(if ($m) { $m.deviceName } else { '' })
                'User'           = $(if ($m) { $m.userPrincipalName } else { '' })
                'Last contacted' = (Format-TRDate $a.lastContactedDateTime)
            }
        }
        Add-TRInventory $inv 'AutopilotDevices' 'Autopilot devices' 'Windows Autopilot registrations, profile status and the matching Intune device.' $rows
    }

    if (Test-TRCollected @('IntuneAppInstall')) {
        $rows = foreach ($a in (Get-TRItems 'IntuneAppInstall' | Sort-Object { -[int]$_.Failed }, App)) {
            [pscustomobject][ordered]@{ 'App' = $a.App; 'Type' = $a.Type; 'Publisher' = $a.Publisher; 'Installed' = $a.Installed; 'Failed' = $a.Failed; 'Pending' = $a.Pending; 'Not installed' = $a.NotInstalled; 'Failed users' = $a.FailedUsers }
        }
        Add-TRInventory $inv 'IntuneApps' 'Required apps' 'Apps assigned as required, with device install results.' $rows
    }

    if (Test-TRCollected @('Devices')) {
        $rows = foreach ($d in (Get-TRItems 'Devices' | Sort-Object operatingSystem, displayName)) {
            [pscustomobject][ordered]@{
                'Device'       = $d.displayName
                'OS'           = $d.operatingSystem
                'Version'      = $d.operatingSystemVersion
                'Join type'    = $(switch ([string]$d.trustType) { 'AzureAd' { 'Entra joined' } 'ServerAd' { 'Hybrid joined' } 'Workplace' { 'Registered' } default { $d.trustType } })
                'Compliant'    = ConvertTo-TRYesNo $d.isCompliant
                'Managed'      = ConvertTo-TRYesNo $d.isManaged
                'Enabled'      = ConvertTo-TRYesNo $d.accountEnabled
                'Last sign-in' = (Format-TRDate $d.approximateLastSignInDateTime)
                'Registered'   = (Format-TRDate $d.registrationDateTime)
            }
        }
        Add-TRInventory $inv 'EntraDevices' 'Entra devices' 'Devices registered or joined in Microsoft Entra ID.' $rows
    }

    if (Test-TRCollected @('ServicePrincipals')) {
        $perms = @{}
        foreach ($p in (Get-TRItems 'AppPermissions')) {
            $k = [string]$p.ClientId
            if (-not $perms.ContainsKey($k)) { $perms[$k] = New-Object System.Collections.ArrayList }
            [void]$perms[$k].Add(('{0}: {1}' -f ($p.Resource -replace '^Office 365 ', '' -replace '^Microsoft ', ''), $p.Permission))
        }
        $admin = @{}; $userCount = @{}
        foreach ($g in (Get-TRItems 'OAuth2Grants')) {
            $k = [string]$g.clientId
            if ($g.consentType -eq 'AllPrincipals') {
                if (-not $admin.ContainsKey($k)) { $admin[$k] = New-Object System.Collections.ArrayList }
                foreach ($s in (([string]$g.scope).Trim() -split '\s+')) { if ($s -and -not $admin[$k].Contains($s)) { [void]$admin[$k].Add($s) } }
            }
            else { $userCount[$k] = 1 + [int]$userCount[$k] }
        }
        $rows = foreach ($s in (Get-TRItems 'ServicePrincipals')) {
            $owner = Get-TRSpOwner $s
            $k = [string]$s.id
            if ($owner -eq 'Microsoft' -and -not $perms.ContainsKey($k) -and -not $admin.ContainsKey($k)) { continue }
            [pscustomobject][ordered]@{
                'Application'             = $s.displayName
                'Owner'                   = $owner
                'Publisher'               = $(if ($s.verifiedPublisher.displayName) { $s.verifiedPublisher.displayName + ' (verified)' } else { $s.publisherName })
                'App ID'                  = $s.appId
                'Enabled'                 = ConvertTo-TRYesNo $s.accountEnabled
                'Application permissions' = $(if ($perms.ContainsKey($k)) { ($perms[$k] -join ', ') } else { '' })
                'Admin consented scopes'  = $(if ($admin.ContainsKey($k)) { ($admin[$k] -join ' ') } else { '' })
                'User consents'           = $(if ($userCount.ContainsKey($k)) { $userCount[$k] } else { 0 })
            }
        }
        Add-TRInventory $inv 'Applications' 'Applications' 'Non-Microsoft enterprise applications, plus Microsoft apps with granted permissions.' ($rows | Sort-Object Owner, Application)
    }

    if (Test-TRCollected @('Applications')) {
        $now = Get-TRNow
        $rows = foreach ($a in (Get-TRItems 'Applications')) {
            foreach ($set in @(@{ T = 'Secret'; L = $a.passwordCredentials }, @{ T = 'Certificate'; L = $a.keyCredentials })) {
                foreach ($c in @($set.L)) {
                    if (-not $c) { continue }
                    $end = ConvertTo-TRDate $c.endDateTime
                    $days = if ($end) { [int]($end - $now).TotalDays } else { $null }
                    [pscustomobject][ordered]@{
                        'Application' = $a.displayName
                        'App ID'      = $a.appId
                        'Type'        = $set.T
                        'Description' = $c.displayName
                        'Expires'     = (Format-TRDate $end)
                        'Status'      = $(if ($null -eq $days) { '' } elseif ($days -lt 0) { 'Expired' } elseif ($days -le 30) { 'Expiring' } else { 'Valid' })
                        'Audience'    = $a.signInAudience
                    }
                }
            }
        }
        Add-TRInventory $inv 'AppCredentials' 'App credentials' 'Secrets and certificates on app registrations in this tenant.' $rows
    }

    if (Test-TRCollected @('DefenderDevices')) {
        $vuln = @{}
        foreach ($v in (Get-TRItems 'DefenderDeviceVulns')) { $vuln[[string]$v.DeviceId] = $v }
        $intune = @{}
        foreach ($m in (Get-TRItems 'ManagedDevices')) { if ($m.azureADDeviceId) { $intune[([string]$m.azureADDeviceId).ToLower()] = $true } }
        $haveIntune = Test-TRCollected @('ManagedDevices')
        $rows = foreach ($d in (Get-TRItems 'DefenderDevices' | Sort-Object OnboardingStatus, DeviceName)) {
            $v = $vuln[[string]$d.DeviceId]
            [pscustomobject][ordered]@{
                'Device'        = $d.DeviceName
                'OS'            = $d.OSPlatform
                'OS version'    = $d.OSVersion
                'Type'          = $d.DeviceType
                'Onboarding'    = $d.OnboardingStatus
                'Sensor health' = $d.SensorHealthState
                'Exposure'      = $d.ExposureLevel
                'Critical CVEs' = $(if ($v) { [int]$v.Critical } else { '' })
                'High CVEs'     = $(if ($v) { [int]$v.High } else { '' })
                'Join type'     = $d.JoinType
                'In Intune'     = $(if (-not $haveIntune) { '' } elseif ($d.AadDeviceId -and $intune.ContainsKey(([string]$d.AadDeviceId).ToLower())) { 'Yes' } else { 'No' })
                'Device group'  = $d.MachineGroup
                'Last seen'     = (Format-TRDate $d.LastSeen)
            }
        }
        Add-TRInventory $inv 'DefenderDevices' 'Defender devices' 'Devices seen by Defender for Endpoint in the last 30 days, including discovered devices that are not onboarded.' $rows
    }

    if (Test-TRCollected @('DefenderVulnSoftware')) {
        $rows = foreach ($s in (Get-TRItems 'DefenderVulnSoftware' | Sort-Object @{ e = { [int]$_.ExploitableCves }; Descending = $true }, @{ e = { [int]$_.CriticalCves }; Descending = $true }, @{ e = { [int]$_.Devices }; Descending = $true })) {
            [pscustomobject][ordered]@{
                'Software'         = (Format-TRSoftware $s.SoftwareVendor $s.SoftwareName)
                'Critical CVEs'    = [int]$s.CriticalCves
                'High CVEs'        = [int]$s.HighCves
                'CVEs with exploits' = [int]$s.ExploitableCves
                'Highest CVSS'     = $(if ($null -ne $s.MaxCvss -and [string]$s.MaxCvss -ne '') { [Math]::Round([double]$s.MaxCvss, 1) } else { '' })
                'Devices'          = [int]$s.Devices
                'Example CVEs'     = (@($s.ExampleCves | Where-Object { $_ }) -join ', ')
                'Recommended update' = (@($s.Updates | Where-Object { $_ }) -join ', ')
            }
        }
        Add-TRInventory $inv 'Vulnerabilities' 'Vulnerable software' 'Software with high or critical vulnerabilities on onboarded devices, from Defender Vulnerability Management.' $rows
    }

    if (Test-TRCollected @('DefenderConfigGaps')) {
        $rows = foreach ($c in (Get-TRItems 'DefenderConfigGaps' | Sort-Object @{ e = { [double]$_.ConfigurationImpact }; Descending = $true }, @{ e = { [int]$_.Failing }; Descending = $true })) {
            [pscustomobject][ordered]@{
                'Recommendation' = $(if ($c.ConfigurationName) { $c.ConfigurationName } else { $c.ConfigurationId })
                'Category'       = $c.ConfigurationCategory
                'Subcategory'    = $c.ConfigurationSubcategory
                'Impact'         = [Math]::Round([double]$c.ConfigurationImpact, 1)
                'Failing devices' = [int]$c.Failing
                'Assessed devices' = [int]$c.Assessed
                'Risk'           = $c.RiskDescription
                'Remediation'    = $(if ($c.RemediationOptions) { $t = ConvertTo-TRPlainText ([string]$c.RemediationOptions); if ($t.Length -gt 400) { $t.Substring(0, 400) + '...' } else { $t } } else { '' })
                'ID'             = $c.ConfigurationId
            }
        }
        Add-TRInventory $inv 'ConfigGaps' 'Security recommendations' 'Secure configuration assessments that fail on at least one device, highest impact first.' $rows
    }

    if (Test-TRCollected @('DefenderIncidents')) {
        $rows = foreach ($i in (Get-TRItems 'DefenderIncidents' | Sort-Object { ConvertTo-TRDate $_.createdDateTime } -Descending)) {
            [pscustomobject][ordered]@{
                'Created'        = (Format-TRDate $i.createdDateTime -WithTime)
                'Incident'       = $i.displayName
                'Severity'       = $i.severity
                'Status'         = $i.status
                'Classification' = $i.classification
                'Determination'  = $i.determination
                'Assigned to'    = $i.assignedTo
                'Last update'    = (Format-TRDate $i.lastUpdateDateTime -WithTime)
                'Link'           = $i.incidentWebUrl
            }
        }
        Add-TRInventory $inv 'Incidents' 'Security incidents' 'Defender XDR incidents created in the last 90 days.' $rows
    }

    if (Test-TRCollected @('SccDlpPolicies')) {
        $ruleCount = @{}
        foreach ($r in (Get-TRItems 'SccDlpRules')) {
            $k = [string]$r.ParentPolicyName
            if ($k) { if ($ruleCount.ContainsKey($k)) { $ruleCount[$k]++ } else { $ruleCount[$k] = 1 } }
        }
        $rows = foreach ($p in (Get-TRItems 'SccDlpPolicies')) {
            [pscustomobject][ordered]@{
                'Policy'    = $p.Name
                'Mode'      = $p.Mode
                'Enabled'   = (ConvertTo-TRYesNo $p.Enabled)
                'Workloads' = ((Get-TRPolicyWorkloads $p) -join ', ')
                'Rules'     = $(if ($ruleCount.ContainsKey([string]$p.Name)) { $ruleCount[[string]$p.Name] } else { '' })
                'Created'   = (Format-TRDate $p.WhenCreatedUTC)
                'Changed'   = (Format-TRDate $p.WhenChangedUTC)
            }
        }
        Add-TRInventory $inv 'DlpPolicies' 'DLP policies' 'Microsoft Purview data loss prevention policies.' $rows
    }

    if (Test-TRCollected @('SccRetentionPolicies')) {
        $rules = @(Get-TRItems 'SccRetentionRules')
        $rows = foreach ($p in (Get-TRItems 'SccRetentionPolicies')) {
            $r = @($rules | Where-Object { ($p.Guid -and [string]$_.Policy -eq [string]$p.Guid) -or [string]$_.ParentPolicyName -eq [string]$p.Name -or ($p.Identity -and [string]$_.Policy -eq [string]$p.Identity) }) | Select-Object -First 1
            [pscustomobject][ordered]@{
                'Policy'         = $p.Name
                'Enabled'        = (ConvertTo-TRYesNo $p.Enabled)
                'Retention'      = $(if ($r) { Format-TRRetention $r } else { '' })
                'Exchange'       = $p.ExchangeLocation
                'SharePoint'     = $p.SharePointLocation
                'OneDrive'       = $p.OneDriveLocation
                'M365 Groups'    = $p.ModernGroupLocation
                'Teams channels' = $p.TeamsChannelLocation
                'Teams chats'    = $p.TeamsChatLocation
                'Adaptive'       = (ConvertTo-TRYesNo $p.IsAdaptivePolicy)
                'Status'         = $p.DistributionStatus
            }
        }
        Add-TRInventory $inv 'RetentionPolicies' 'Retention policies' 'Microsoft Purview retention policies and the locations they cover.' $rows
    }

    if (Test-TRCollected @('SccLabels')) {
        $byId = @{}
        foreach ($l in (Get-TRItems 'SccLabels')) { foreach ($k in @($l.Guid, $l.ImmutableId)) { if ($k) { $byId[[string]$k] = $l } } }
        $published = @{}
        foreach ($p in (Get-TRItems 'SccLabelPolicies' | Where-Object { Test-TRPolicyActive $_ })) {
            foreach ($n in @($p.Labels)) { if ($n) { $published[[string]$n] = $true } }
        }
        $rows = foreach ($l in (Get-TRItems 'SccLabels' | Sort-Object { [int]$_.Priority })) {
            $parent = if ($l.ParentId -and $byId.ContainsKey([string]$l.ParentId)) { $byId[[string]$l.ParentId].DisplayName } else { '' }
            $isPub = $published.ContainsKey([string]$l.Name) -or $published.ContainsKey([string]$l.Guid) -or $published.ContainsKey([string]$l.ImmutableId) -or $published.ContainsKey([string]$l.DisplayName)
            [pscustomobject][ordered]@{
                'Label'      = $(if ($l.DisplayName) { $l.DisplayName } else { $l.Name })
                'Parent'     = $parent
                'Priority'   = $l.Priority
                'Scope'      = $l.ContentType
                'Encryption' = $(if ($l.EncryptionEnabled -eq $true -or ((@($l.LabelActions) -join ' ') -match '"?[Tt]ype"?\s*:\s*"?encrypt')) { 'Yes' } else { 'No' })
                'Published'  = $(if ($isPub) { 'Yes' } else { 'No' })
                'Enabled'    = $(if ($l.Disabled -eq $true) { 'No' } else { 'Yes' })
                'Tooltip'    = $l.Tooltip
            }
        }
        Add-TRInventory $inv 'SensitivityLabels' 'Sensitivity labels' 'Microsoft Purview sensitivity labels and whether a label policy publishes them.' $rows
    }

    if (Test-TRCollected @('SccAlertPolicies')) {
        $rows = foreach ($a in (Get-TRItems 'SccAlertPolicies' | Sort-Object @{ e = { if ($_.IsSystemRule -eq $true) { 0 } else { 1 } } }, Name)) {
            [pscustomobject][ordered]@{
                'Policy'    = $a.Name
                'Category'  = $a.Category
                'Severity'  = $a.Severity
                'Default'   = (ConvertTo-TRYesNo $a.IsSystemRule)
                'Enabled'   = $(if ($a.Disabled -eq $true) { 'No' } else { 'Yes' })
                'Notify'    = (@($a.NotifyUser | Where-Object { $_ }) -join ', ')
            }
        }
        Add-TRInventory $inv 'AlertPolicies' 'Alert policies' 'Microsoft Purview and Defender alert policies.' $rows
    }

    if (Test-TRCollected @('RetentionLabels')) {
        $rows = foreach ($l in (Get-TRItems 'RetentionLabels')) {
            $dur = ''
            $rd = $l.retentionDuration
            if ($rd) { if (Test-TRHasProperty $rd 'days') { $dur = '{0} days' -f $rd.days } else { $dur = 'Unlimited' } }
            [pscustomobject][ordered]@{
                'Label'          = $l.displayName
                'Retention'      = $dur
                'Behaviour'      = $l.behaviorDuringRetentionPeriod
                'At end'         = $l.actionAfterRetentionPeriod
                'Starts from'    = $l.retentionTrigger
                'Record label'   = $(if ([string]$l.behaviorDuringRetentionPeriod -match 'Record') { 'Yes' } else { 'No' })
                'In use'         = (ConvertTo-TRYesNo $l.isInUse)
            }
        }
        Add-TRInventory $inv 'RetentionLabels' 'Retention labels' 'Microsoft Purview retention labels (records management).' $rows
    }

    if (Test-TRCollected @('SecureScore')) {
        $profiles = @{}
        foreach ($p in (Get-TRItems 'SecureScoreProfiles')) { $profiles[[string]$p.id] = $p }
        $ss = Get-TRRawValue 'SecureScore'
        $rows = foreach ($c in @($ss.controlScores)) {
            if (-not $c) { continue }
            $p = $profiles[[string]$c.controlName]
            if ($p -and $p.deprecated -eq $true) { continue }
            $max = if ($p) { [double]$p.maxScore } else { 0 }
            $score = [double]$c.score
            [pscustomobject][ordered]@{
                'Action'      = $(if ($p) { $p.title } else { $c.controlName })
                'Category'    = $c.controlCategory
                'Service'     = $(if ($p) { $p.service } else { '' })
                'Score'       = [Math]::Round($score, 2)
                'Max'         = $max
                'Gap'         = [Math]::Round([Math]::Max($max - $score, 0), 2)
                'Status'      = $(if ($max -gt 0 -and $score -ge $max) { 'Completed' } elseif ($score -gt 0) { 'Partial' } else { 'To address' })
                'User impact' = $(if ($p) { $p.userImpact } else { '' })
                'Cost'        = $(if ($p) { $p.implementationCost } else { '' })
                'Guidance'    = $(if ($p) { $t = ConvertTo-TRPlainText $p.remediation; if ($t.Length -gt 400) { $t.Substring(0, 400) + '...' } else { $t } } else { '' })
                'Link'        = $(if ($p) { $p.actionUrl } else { '' })
            }
        }
        Add-TRInventory $inv 'SecureScore' 'Secure Score actions' 'Microsoft Secure Score improvement actions, largest gaps first.' ($rows | Sort-Object { -1 * [double]$_.Gap })
    }

    if (Test-TRCollected @('SharingAudit')) {
        $rows = foreach ($s in (Get-TRItems 'SharingAudit' | Sort-Object { ConvertTo-TRDate $_.Date } -Descending)) {
            [pscustomobject][ordered]@{
                'Date'      = (Format-TRDate $s.Date -WithTime)
                'Operation' = $s.Operation
                'User'      = $s.User
                'Item'      = $s.Item
                'Target'    = $s.Target
                'Target type' = $s.TargetType
                'Site'      = $s.SiteUrl
                'Detail'    = $s.EventData
            }
        }
        Add-TRInventory $inv 'SharingActivity' 'Sharing activity' 'Sharing links and invitations created in the last 30 days (audit log).' $rows
    }

    $diag = foreach ($d in (Get-TRItems 'Diagnostics')) {
        [pscustomobject][ordered]@{
            'Area'        = $d.Area
            'Item'        = $d.Item
            'Status'      = $d.Status
            'Count'       = $d.Count
            'HTTP'        = $(if ([int]$d.HttpStatus) { $d.HttpStatus } else { '' })
            'Message'     = $d.Message
            'Duration ms' = $d.DurationMs
        }
    }
    Add-TRAzureInventories $inv
    Add-TRServerInventories $inv
    Add-TRInventory $inv 'Diagnostics' 'Collection diagnostics' 'Every data collection step, with errors where something could not be read.' $diag
    $inv
}
