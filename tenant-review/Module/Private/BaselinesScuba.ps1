function Test-TRScubaRoles {
    param($P)
    Test-TRBlRoles $P @($script:TRPimRoleTemplates.Keys)
}

function Get-TRScubaPrivRows {
    param([switch]$ActiveOnly)
    @(Get-TRRoleRows | Where-Object { $script:TRPimRoleTemplates.Contains([string]$_.RoleTemplate) -and (-not $ActiveOnly -or $_.Assignment -eq 'Active') })
}

function Get-TRDmarcRecord {
    param([string]$Domain, $Rows)
    $d = $Domain.ToLower()
    while ($d -match '\.') {
        $r = @($Rows | Where-Object { ([string]$_.Domain).ToLower() -eq $d })[0]
        if ($r) {
            $rec = @(Get-TRStrings $r.Dmarc)[0]
            if ($rec) { return [pscustomobject]@{ Record = $rec; From = $d } }
        }
        $d = $d.Substring($d.IndexOf('.') + 1)
    }
    $null
}

function Test-TRPimNotify {
    param([string[]]$Roles, [string[]]$RuleIds)
    $gaps = @()
    $seen = 0
    foreach ($role in $Roles) {
        $name = $script:TRPimRoleTemplates[$role]
        $p = @(Get-TRItems 'RoleManagementPolicies' | Where-Object { [string]$_.RoleTemplate -eq $role })[0]
        if (-not $p) { continue }
        $seen++
        foreach ($id in $RuleIds) {
            $r = @(@($p.Rules) | Where-Object { [string]$_.id -eq $id })[0]
            if (-not $r -or -not @(Get-TRStrings $r.notificationRecipients).Count) { $gaps += ('{0}: {1}' -f $name, ($id -replace '^Notification_Admin_', '' -replace '_', ' ')) }
        }
    }
    if (-not $seen) { return New-TRCtl NotAssessed 'PIM role settings were not returned.' }
    if ($gaps.Count) { return New-TRCtl Fail ('No additional alert recipient for: {0}.' -f (Join-TRList $gaps 6)) (@($gaps | ForEach-Object { New-TRAffected $_ 'No alert recipient' })) }
    New-TRCtl Pass 'Alerts go to an additional recipient for every role checked.'
}

function Get-TRActiveAntiPhish {
    @(Get-TRActiveExoPolicies -PolicyKey 'ExoAntiPhishPolicies' -RuleKey 'ExoAntiPhishRules' -RuleField 'AntiPhishPolicy' -Plane EOP | Where-Object { $_.Source -ne 'Custom' -or (Test-TRTrue $_.Policy.Enabled) })
}

function Test-TRAnyPolicy {
    param($Active, [scriptblock]$Ok, [string]$PassText, [string]$FailText)
    $hit = @(@($Active) | Where-Object { & $Ok $_.Policy })
    if ($hit.Count) { return New-TRCtl Pass ($PassText + ' (' + (Join-TRList ($hit | ForEach-Object { $_.Name }) 4) + ').') }
    if (-not @($Active).Count) { return New-TRCtl Fail 'No applicable policy is applied.' }
    New-TRCtl Fail $FailText
}

function Test-TREveryPolicy {
    param($Active, [scriptblock]$Ok, [string]$PassText, [string]$Label)
    $all = @($Active)
    if (-not $all.Count) { return New-TRCtl Fail 'No applicable policy is applied.' }
    $bad = @($all | Where-Object { -not (& $Ok $_.Policy) })
    if ($bad.Count) { return New-TRCtl Fail ('{0} of {1} applied policies do not meet this: {2}.' -f $bad.Count, $all.Count, (Join-TRList ($bad | ForEach-Object { $_.Name }) 4)) (@($bad | ForEach-Object { New-TRAffected $_.Name $Label })) }
    New-TRCtl Pass ($PassText + ' (' + (Format-TRN $all.Count 'applied policy' 'applied policies') + ').')
}

function Test-TRSpoNeedsAnyone {
    param([scriptblock]$Ok, [string]$Text)
    $c = Get-TRSpoSharing
    if ($null -eq $c) { return New-TRCtl NotAssessed 'The sharing level was not returned.' }
    if ($c -ne 2) { return New-TRCtl Pass ('Anyone links are not allowed ({0}).' -f $script:TRSharingCapNames[$c]) }
    & $Ok
}

Register-TRControl -Framework SCuBA -Id 'MS.AAD.1.1v1' -Level Shall -Title 'Legacy authentication is blocked' `
    -Needs 'ConditionalAccessPolicies' -Checks 'IAM-02' `
    -Guidance 'Create a Conditional Access policy for all users and all resources that blocks Exchange ActiveSync and other legacy clients.' `
    -Test { Test-TRBlCaRule -Requirement 'blocks legacy authentication for all users' -Filter { (Test-TRBlAllUsers $_) -and (Test-TRBlAllApps $_) -and (Test-TRCaLegacy $_) -and (Test-TRBlBlock $_) } }

Register-TRControl -Framework SCuBA -Id 'MS.AAD.2.1v1' -Level Shall -Title 'High-risk users are blocked' `
    -Licence 'P2' -Needs 'ConditionalAccessPolicies' -Checks 'IAM-09' `
    -Guidance 'Create a Conditional Access policy for all users and all resources that blocks access when user risk is high.' `
    -Test { Test-TRBlCaRule -Requirement 'blocks high-risk users' -Filter { (Test-TRBlAllUsers $_) -and (Test-TRBlAllApps $_) -and @(Get-TRStrings $_.conditions.userRiskLevels) -contains 'high' -and (Test-TRBlBlock $_) } }

Register-TRControl -Framework SCuBA -Id 'MS.AAD.2.2v1' -Level Should -Title 'Admins are alerted to high-risk users' -ManualOnly `
    -Licence 'P2' `
    -Guidance 'In Entra ID Protection, Users at risk detected alerts, add a monitored mailbox and set the alert level to High.'

Register-TRControl -Framework SCuBA -Id 'MS.AAD.2.3v1' -Level Shall -Title 'High-risk sign-ins are blocked' `
    -Licence 'P2' -Needs 'ConditionalAccessPolicies' -Checks 'IAM-09' `
    -Guidance 'Create a Conditional Access policy for all users and all resources that blocks high sign-in risk.' `
    -Test { Test-TRBlCaRule -Requirement 'blocks high-risk sign-ins' -Filter { (Test-TRBlAllUsers $_) -and (Test-TRBlAllApps $_) -and @(Get-TRStrings $_.conditions.signInRiskLevels) -contains 'high' -and (Test-TRBlBlock $_) } }

Register-TRControl -Framework SCuBA -Id 'MS.AAD.3.1v1' -Level Shall -Title 'Phishing-resistant MFA for all users' `
    -Needs 'ConditionalAccessPolicies' -Checks 'IAM-04' `
    -Guidance 'Require the phishing-resistant MFA authentication strength (passkeys, Windows Hello or certificates) for all users and all resources.' `
    -Test { Test-TRBlCaRule -Requirement 'requires phishing-resistant MFA for all users' -Filter { (Test-TRBlAllUsers $_) -and (Test-TRBlAllApps $_) -and (Test-TRCaPhishResistant $_) } }

Register-TRControl -Framework SCuBA -Id 'MS.AAD.3.2v2' -Level Shall -Title 'MFA for all users' `
    -Needs 'ConditionalAccessPolicies' -Checks 'IAM-01' `
    -Guidance 'Require MFA for all users and all resources with Conditional Access, excluding only emergency access accounts.' `
    -Test { Test-TRBlCaRule -Requirement 'requires MFA for all users on all resources' -Filter { (Test-TRBlAllUsers $_) -and (Test-TRBlAllApps $_) -and (Test-TRBlMfa $_) } }

Register-TRControl -Framework SCuBA -Id 'MS.AAD.3.3v2' -Level Shall -Title 'Authenticator shows sign-in context' `
    -Needs 'AuthMethodsPolicy' `
    -Guidance 'Where Microsoft Authenticator is enabled, show the application name and location in notifications for all users.' `
    -Test {
    $m = Get-TRAuthMethod 'MicrosoftAuthenticator'
    if (-not $m -or [string]$m.state -ne 'enabled') { return New-TRCtl NotApplicable 'Microsoft Authenticator is not enabled.' }
    $gaps = @()
    foreach ($k in 'displayAppInformationRequiredState', 'displayLocationInformationRequiredState') {
        $s = Get-TRV $m.featureSettings $k
        if (-not $s -or [string]$s.state -ne 'enabled' -or [string]$s.includeTarget.id -ne 'all_users') { $gaps += $(if ($k -match 'App') { 'app name' } else { 'location' }) }
    }
    if ($gaps.Count) { return New-TRCtl Fail ('Not shown to all users: {0}.' -f ($gaps -join ', ')) }
    New-TRCtl Pass 'App name and location are shown for all users.'
}

Register-TRControl -Framework SCuBA -Id 'MS.AAD.3.4v1' -Level Shall -Title 'Authentication methods migration is complete' `
    -Needs 'AuthMethodsPolicy' `
    -Guidance 'Move legacy MFA and SSPR method settings into the authentication methods policy and set the migration to Complete.' `
    -Test {
    $s = [string](Get-TRRawValue 'AuthMethodsPolicy').policyMigrationState
    if ($s -eq 'migrationComplete') { return New-TRCtl Pass 'Migration is complete.' }
    New-TRCtl Fail ('Migration state: {0}.' -f $(if ($s) { $s } else { 'not started' }))
}

Register-TRControl -Framework SCuBA -Id 'MS.AAD.3.5v2' -Level Shall -Title 'SMS, voice and email OTP are off' `
    -Needs 'AuthMethodsPolicy' -Checks 'IAM-07' `
    -Guidance 'Disable SMS, voice call and email one-time passcode in the authentication methods policy.' `
    -Test {
    $on = @('Sms', 'Voice', 'Email' | Where-Object { $m = Get-TRAuthMethod $_; $m -and [string]$m.state -eq 'enabled' })
    if ($on.Count) { return New-TRCtl Fail ('Still enabled: {0}.' -f ($on -join ', ')) }
    New-TRCtl Pass 'SMS, voice and email OTP are disabled.'
}

Register-TRControl -Framework SCuBA -Id 'MS.AAD.3.6v1' -Level Shall -Title 'Phishing-resistant MFA for highly privileged roles' `
    -Needs 'ConditionalAccessPolicies' -Checks 'IAM-04' `
    -Guidance 'Require phishing-resistant MFA for Global, Privileged Role, User, SharePoint, Exchange, Hybrid Identity, Application and Cloud Application Administrators.' `
    -Test {
    $r = Test-TRBlCaRule -Requirement 'requires phishing-resistant MFA for every highly privileged role' -Filter { (Test-TRBlAllApps $_) -and (Test-TRCaPhishResistant $_) -and (Test-TRScubaRoles $_) }
    if ($r.Status -eq 'Fail') {
        $near = @(Get-TRItems (Get-TRBlCaKey) | Where-Object { [string]$_.state -eq 'enabled' -and (Test-TRBlAllApps $_) -and (Test-TRCaPhishResistant $_) -and @(Get-TRStrings $_.conditions.users.includeRoles).Count })
        if ($near.Count) { $r.Evidence += ' ' + (Get-TRBlCaNames $near) + ' misses: ' + (Join-TRList (Get-TRBlMissingRoles $near[0] $script:TRPimRoleTemplates) 8) + '.' }
    }
    $r
}

Register-TRControl -Framework SCuBA -Id 'MS.AAD.3.7v1' -Level Should -Title 'Managed devices are required' `
    -Needs 'ConditionalAccessPolicies' -Checks 'IAM-11' `
    -Guidance 'Require a compliant or hybrid joined device for all users and all resources.' `
    -Test {
    Test-TRBlCaRule -Requirement 'requires a compliant or hybrid joined device for all users' -Filter {
        $g = @(Get-TRBlGrant $_)
        (Test-TRBlAllUsers $_) -and (Test-TRBlAllApps $_) -and ($g -contains 'compliantDevice' -or $g -contains 'domainJoinedDevice') -and ($g.Count -eq 1 -or ([string]$_.grantControls.operator -eq 'OR' -and -not @($g | Where-Object { $_ -notin @('compliantDevice', 'domainJoinedDevice') }).Count))
    }
}

Register-TRControl -Framework SCuBA -Id 'MS.AAD.3.8v1' -Level Should -Title 'Managed devices are required to register MFA' `
    -Needs 'ConditionalAccessPolicies' `
    -Guidance 'Require a compliant or hybrid joined device for the Register security information user action.' `
    -Test {
    Test-TRBlCaRule -Requirement 'requires a managed device to register security information' -Filter {
        $g = @(Get-TRBlGrant $_)
        (Test-TRBlAllUsers $_) -and @(Get-TRStrings $_.conditions.applications.includeUserActions) -contains 'urn:user:registersecurityinfo' -and ($g -contains 'compliantDevice' -or $g -contains 'domainJoinedDevice')
    }
}

Register-TRControl -Framework SCuBA -Id 'MS.AAD.3.9v1' -Level Should -Title 'Device code sign-in is blocked' `
    -Needs 'ConditionalAccessPolicies' `
    -Guidance 'Block the device code flow for all users and all resources with Conditional Access.' `
    -Test { Test-TRBlCaRule -Requirement 'blocks the device code flow for all users' -Filter { (Test-TRBlAllUsers $_) -and (Test-TRBlAllApps $_) -and ([string](Get-TRPath $_ 'conditions.authenticationFlows.transferMethods')) -match 'deviceCodeFlow' -and (Test-TRBlBlock $_) } }

Register-TRControl -Framework SCuBA -Id 'MS.AAD.4.1v1' -Level Shall -Title 'Security logs go to a security operations centre' -ManualOnly `
    -Guidance 'Send Entra sign-in and audit logs to the SIEM or SOC through diagnostic settings, Sentinel or a log forwarder.'

Register-TRControl -Framework SCuBA -Id 'MS.AAD.5.1v1' -Level Shall -Title 'Only administrators register applications' `
    -Needs 'AuthorizationPolicy' -Checks 'IAM-15' `
    -Guidance 'Set Users can register applications to No.' `
    -Test {
    if (Test-TRFalse (Get-TRPath (Get-TRRawValue 'AuthorizationPolicy') 'defaultUserRolePermissions.allowedToCreateApps')) { return New-TRCtl Pass 'Users cannot register applications.' }
    New-TRCtl Fail 'Users can register applications.'
}

Register-TRControl -Framework SCuBA -Id 'MS.AAD.5.2v1' -Level Shall -Title 'User consent to applications is restricted' `
    -Needs 'AuthorizationPolicy' -Checks 'IAM-13' `
    -Guidance 'Do not allow user consent, or allow it only for verified publishers and low-impact permissions you have classified.' `
    -Test {
    $p = @(Get-TRStrings (Get-TRPath (Get-TRRawValue 'AuthorizationPolicy') 'defaultUserRolePermissions.permissionGrantPoliciesAssigned') | Where-Object { $_ -like 'ManagePermissionGrantsForSelf.*' })
    $bad = @($p | Where-Object { $_ -match 'microsoft-user-default-legacy|microsoft-user-default-recommended' })
    if ($bad.Count) { return New-TRCtl Fail ('User consent is allowed: {0}.' -f (($bad | ForEach-Object { Format-TRConsentPolicy $_ }) -join '; ')) }
    if ($p.Count) { return New-TRCtl Pass ('Users can consent only to low-impact permissions from verified publishers ({0}). Review the permission classifications.' -f (($p | ForEach-Object { Format-TRConsentPolicy $_ }) -join '; ')) }
    New-TRCtl Pass 'Users cannot consent to applications.'
}

Register-TRControl -Framework SCuBA -Id 'MS.AAD.5.3v1' -Level Shall -Title 'An admin consent workflow is configured' `
    -Needs 'AdminConsentPolicy' -Checks 'IAM-14' `
    -Guidance 'Turn on the admin consent request workflow and name reviewers.' `
    -Test {
    $a = Get-TRRawValue 'AdminConsentPolicy'
    if ((Test-TRTrue $a.isEnabled) -and @($a.reviewers).Count) { return New-TRCtl Pass ('The workflow is on with {0}.' -f (Format-TRN @($a.reviewers).Count 'reviewer entry' 'reviewer entries')) }
    New-TRCtl Fail $(if (Test-TRTrue $a.isEnabled) { 'The workflow is on but has no reviewers.' } else { 'The admin consent workflow is off.' })
}

Register-TRControl -Framework SCuBA -Id 'MS.AAD.5.5v1' -Level Should -Title 'Apps cannot add password credentials' `
    -Needs 'DefaultAppMgmtPolicy' `
    -Guidance 'Enable the tenant app management policy restriction that blocks new client secrets.' `
    -Test { Test-TRAppRestriction -Type 'passwordAddition' -Label 'New client secrets blocked' }

Register-TRControl -Framework SCuBA -Id 'MS.AAD.5.6v1' -Level Should -Title 'App secrets last 180 days or less' `
    -Needs 'DefaultAppMgmtPolicy' `
    -Guidance 'Limit client secret lifetime to 180 days or less in the tenant app management policy.' `
    -Test { Test-TRAppRestriction -Type 'passwordLifetime' -MaxDays 180 -Label 'Client secret lifetime limit' }

Register-TRControl -Framework SCuBA -Id 'MS.AAD.5.7v1' -Level Should -Title 'App certificates last a year or less' `
    -Needs 'DefaultAppMgmtPolicy' `
    -Guidance 'Limit certificate credential lifetime to 365 days or less in the tenant app management policy.' `
    -Test { Test-TRAppRestriction -Type 'asymmetricKeyLifetime' -Kind keyCredentials -MaxDays 365 -Label 'Certificate lifetime limit' }

Register-TRControl -Framework SCuBA -Id 'MS.AAD.6.1v1' -Level Shall -Title 'Passwords do not expire' `
    -Needs 'Domains' -Checks 'IAM-19' `
    -Guidance 'Set passwords to never expire.' `
    -Test {
    $bad = @(Get-TRItems 'Domains' | Where-Object { (Test-TRTrue $_.isVerified) -and $null -ne $_.passwordValidityPeriodInDays -and [long]$_.passwordValidityPeriodInDays -ne 2147483647 })
    if ($bad.Count) { return New-TRCtl Fail ('Passwords expire on {0}.' -f (Format-TRN $bad.Count 'domain')) (@($bad | ForEach-Object { New-TRAffected ([string]$_.id) ('Expires after {0}' -f (Format-TRN ([int]$_.passwordValidityPeriodInDays) 'day')) })) }
    New-TRCtl Pass 'Passwords never expire on any verified domain.'
}

Register-TRControl -Framework SCuBA -Id 'MS.AAD.7.1v1' -Level Shall -Title 'Two to eight Global Administrators' `
    -Needs 'RoleAssignments' -Checks 'PRV-01' `
    -Guidance 'Keep between two and eight users in the Global Administrator role, counting active and eligible assignments.' `
    -Test {
    $ga = @(Get-TRRoleRows | Where-Object { $_.RoleTemplate -eq $script:TRGlobalAdminRole -and $_.PrincipalType -eq 'user' } | Select-Object -ExpandProperty PrincipalUpn -Unique)
    $text = '{0}: {1}.' -f (Format-TRN $ga.Count 'Global Administrator'), (Join-TRList $ga 8)
    if ($ga.Count -ge 2 -and $ga.Count -le 8) { return New-TRCtl Pass $text }
    New-TRCtl Fail $text
}

Register-TRControl -Framework SCuBA -Id 'MS.AAD.7.2v1' -Level Shall -Title 'Narrower roles are used instead of Global Administrator' `
    -Needs 'RoleAssignments' -Checks 'PRV-01' `
    -Guidance 'Give administrators the least privileged role they need so there are no more Global Administrators than holders of other highly privileged roles.' `
    -Test {
    $rows = Get-TRScubaPrivRows
    $ga = @($rows | Where-Object { $_.RoleTemplate -eq $script:TRGlobalAdminRole -and $_.PrincipalType -eq 'user' } | Select-Object -ExpandProperty PrincipalId -Unique)
    $other = @($rows | Where-Object { $_.RoleTemplate -ne $script:TRGlobalAdminRole -and $_.PrincipalType -eq 'user' -and $ga -notcontains $_.PrincipalId } | Select-Object -ExpandProperty PrincipalId -Unique)
    if (-not $other.Count) { return New-TRCtl Fail ('{0} and nobody in the other highly privileged roles.' -f (Format-TRN $ga.Count 'Global Administrator')) }
    $x = [Math]::Round($ga.Count / $other.Count, 2)
    $text = '{0} to {1} in other highly privileged roles (ratio {2}).' -f (Format-TRN $ga.Count 'Global Administrator'), (Format-TRN $other.Count 'user'), $x
    if ($x -le 1) { return New-TRCtl Pass $text }
    New-TRCtl Fail $text
}

Register-TRControl -Framework SCuBA -Id 'MS.AAD.7.3v1' -Level Shall -Title 'Privileged users are cloud-only' `
    -Needs 'RoleAssignments', 'Users' -Checks 'PRV-03' `
    -Guidance 'Use cloud-only accounts for every highly privileged role.' `
    -Test {
    $users = Get-TRUserIndex
    $ids = @(Get-TRScubaPrivRows | Where-Object { $_.PrincipalType -eq 'user' } | Select-Object -ExpandProperty PrincipalId -Unique)
    $bad = @($ids | ForEach-Object { $users[$_] } | Where-Object { $_ -and (Test-TRTrue $_.onPremisesSyncEnabled) } | ForEach-Object { New-TRAffected ([string]$_.userPrincipalName) 'Synchronised from on-premises' })
    if ($bad.Count) { return New-TRCtl Fail ('{0} of {1} privileged users are synchronised from on-premises.' -f $bad.Count, $ids.Count) $bad }
    New-TRCtl Pass ((Select-TRText $ids.Count 'The only privileged user is cloud-only.' 'All {0} privileged users are cloud-only.') -f $ids.Count)
}

Register-TRControl -Framework SCuBA -Id 'MS.AAD.7.4v1' -Level Shall -Title 'No permanent active privileged assignments' `
    -Licence 'P2' -Needs 'RoleAssignmentInstances' -Checks 'PRV-05' `
    -Guidance 'Make highly privileged role assignments eligible in PIM, keeping permanent assignments only for documented emergency access accounts.' `
    -Test {
    $perm = @(Get-TRItems 'RoleAssignmentInstances' | Where-Object { $script:TRPimRoleTemplates.Contains([string]$_.RoleDefinitionId) -and [string]$_.AssignmentType -eq 'Assigned' -and -not $_.EndDateTime -and $_.PrincipalType -in @('user', 'group') })
    if ($perm.Count) { return New-TRCtl Fail ('{0}. Emergency access accounts are acceptable exceptions if documented.' -f (Format-TRN $perm.Count 'permanent active assignment')) (@($perm | ForEach-Object { New-TRAffected $_.PrincipalUpn $script:TRPimRoleTemplates[[string]$_.RoleDefinitionId] })) }
    New-TRCtl Pass 'No permanent active assignments to highly privileged roles.'
}

Register-TRControl -Framework SCuBA -Id 'MS.AAD.7.5v1' -Level Shall -Title 'Privileged roles are assigned only through PIM' `
    -Licence 'P2' -Needs 'RoleAssignmentInstances' -Checks 'PRV-05' `
    -Guidance 'Assign highly privileged roles through PIM so every assignment has a start date and an audit trail.' `
    -Test {
    $out = @(Get-TRItems 'RoleAssignmentInstances' | Where-Object { $script:TRPimRoleTemplates.Contains([string]$_.RoleDefinitionId) -and -not $_.StartDateTime })
    if ($out.Count) { return New-TRCtl Fail ((Select-TRText $out.Count '1 assignment was made outside PIM.' '{0} assignments were made outside PIM.') -f $out.Count) (@($out | ForEach-Object { New-TRAffected $(if ($_.PrincipalUpn) { $_.PrincipalUpn } else { $_.PrincipalName }) $script:TRPimRoleTemplates[[string]$_.RoleDefinitionId] })) }
    New-TRCtl Pass 'All highly privileged assignments were made through PIM.'
}

Register-TRControl -Framework SCuBA -Id 'MS.AAD.7.6v1' -Level Shall -Title 'Global Administrator activation needs approval' `
    -Licence 'P2' -Needs 'RoleManagementPolicies' `
    -Guidance 'In PIM, require approval to activate Global Administrator and name approvers.' `
    -Test {
    $r = Get-TRPimRule $script:TRGlobalAdminRole 'Approval_EndUser_Assignment'
    if (-not $r) { return New-TRCtl NotAssessed 'The PIM settings for Global Administrator were not returned.' }
    if (Test-TRTrue $r.setting.isApprovalRequired) { return New-TRCtl Pass 'Activation requires approval.' }
    New-TRCtl Fail 'Activation does not need approval.'
}

Register-TRControl -Framework SCuBA -Id 'MS.AAD.7.7v1' -Level Shall -Title 'Privileged role assignments raise alerts' `
    -Licence 'P2' -Needs 'RoleManagementPolicies' `
    -Guidance 'In PIM role settings for each highly privileged role, send eligible and active assignment notifications to a monitored mailbox.' `
    -Test { Test-TRPimNotify -Roles @($script:TRPimRoleTemplates.Keys) -RuleIds @('Notification_Admin_Admin_Eligibility', 'Notification_Admin_Admin_Assignment') }

Register-TRControl -Framework SCuBA -Id 'MS.AAD.7.8v1' -Level Shall -Title 'Global Administrator activation raises an alert' `
    -Licence 'P2' -Needs 'RoleManagementPolicies' `
    -Guidance 'In PIM role settings for Global Administrator, send activation notifications to a monitored mailbox.' `
    -Test { Test-TRPimNotify -Roles @($script:TRGlobalAdminRole) -RuleIds @('Notification_Admin_EndUser_Assignment') }

Register-TRControl -Framework SCuBA -Id 'MS.AAD.7.9v1' -Level Should -Title 'Other privileged role activations raise alerts' `
    -Licence 'P2' -Needs 'RoleManagementPolicies' `
    -Guidance 'Send activation notifications for the other highly privileged roles to a monitored mailbox, separate from the Global Administrator one.' `
    -Test { Test-TRPimNotify -Roles @($script:TRPimRoleTemplates.Keys | Where-Object { $_ -ne $script:TRGlobalAdminRole }) -RuleIds @('Notification_Admin_EndUser_Assignment') }

Register-TRControl -Framework SCuBA -Id 'MS.AAD.8.1v1' -Level Should -Title 'Guest directory access is limited' `
    -Needs 'AuthorizationPolicy' -Checks 'IAM-17' `
    -Guidance 'Set guest user access to limited or restricted.' `
    -Test {
    $g = [string](Get-TRRawValue 'AuthorizationPolicy').guestUserRoleId
    if ($g -in @('10dae51f-b6af-4016-8d66-8c2a99b929b3', '2af84b1e-32c8-42b7-82bc-daa82404023b')) { return New-TRCtl Pass 'Guest access is limited or restricted.' }
    New-TRCtl Fail 'Guests have the same access as members.'
}

Register-TRControl -Framework SCuBA -Id 'MS.AAD.8.2v1' -Level Should -Title 'Only Guest Inviters can invite guests' `
    -Needs 'AuthorizationPolicy' -Checks 'IAM-16' `
    -Guidance 'Set guest invite restrictions so only admins and users in the Guest Inviter role can invite.' `
    -Test {
    $v = [string](Get-TRRawValue 'AuthorizationPolicy').allowInvitesFrom
    if ($v -eq 'adminsAndGuestInviters') { return New-TRCtl Pass 'Only admins and Guest Inviters can invite guests.' }
    if ($v -eq 'none') { return New-TRCtl Pass 'Nobody can invite guests, which is stricter than required.' }
    New-TRCtl Fail ('Invitations: {0}.' -f $v)
}

Register-TRControl -Framework SCuBA -Id 'MS.AAD.8.3v1' -Level Should -Title 'Guest invitations go only to approved domains' `
    -Needs 'B2BManagementPolicy' `
    -Guidance 'Allow invitations only to specified domains approved for business collaboration.' `
    -Test {
    $b = Get-TRRawValue 'B2BManagementPolicy'
    if ($b -and (Test-TRTrue $b.Present) -and $null -ne $b.AllowedDomains) { return New-TRCtl Pass ('Invitations are limited to: {0}. Confirm these are approved.' -f $(if (@($b.AllowedDomains).Count) { Join-TRList $b.AllowedDomains 6 } else { 'no domains' })) }
    New-TRCtl Fail 'Invitations are not limited to an allow list of domains.'
}

Register-TRControl -Framework SCuBA -Id 'MS.AAD.9.1v1' -Level Shall -Title 'Risky AI agents are blocked' -ManualOnly `
    -Guidance 'Block agent identities flagged as risky by Entra ID Protection with a Conditional Access policy for agents.'

Register-TRControl -Framework SCuBA -Id 'MS.SECURITYSUITE.1.1v1' -Level Shall -Title 'Click-to-run attachments are blocked' `
    -Needs 'ExoMalwarePolicies' -Checks 'EXO-12' `
    -Guidance 'Turn on the common attachments filter in every applied anti-malware policy, including at least .exe, .cmd and .vbe.' `
    -Test {
    $active = @(Get-TRActiveExoPolicies -PolicyKey 'ExoMalwarePolicies' -RuleKey 'ExoMalwareRules' -RuleField 'MalwareFilterPolicy' -Plane EOP)
    Test-TREveryPolicy -Active $active -Label 'Filter off or exe, cmd or vbe missing' -PassText 'Every applied anti-malware policy blocks exe, cmd and vbe' -Ok {
        param($p)
        $t = @(Get-TRStrings $p.FileTypes | ForEach-Object { $_.ToLower() })
        (Test-TRTrue $p.EnableFileFilter) -and ($t.Count -eq 0 -or (@('exe', 'cmd', 'vbe') | Where-Object { $t -notcontains $_ }).Count -eq 0)
    }
}

Register-TRControl -Framework SCuBA -Id 'MS.SECURITYSUITE.1.2v1' -Level Shall -Title 'Email is rescanned after delivery' `
    -Needs 'ExoMalwarePolicies' -Checks 'EXO-12' `
    -Guidance 'Keep zero-hour auto purge for malware on in every applied anti-malware policy.' `
    -Test {
    $active = @(Get-TRActiveExoPolicies -PolicyKey 'ExoMalwarePolicies' -RuleKey 'ExoMalwareRules' -RuleField 'MalwareFilterPolicy' -Plane EOP)
    Test-TREveryPolicy -Active $active -Label 'ZAP off' -PassText 'Zero-hour auto purge is on' -Ok { param($p) Test-TRTrue $p.ZapEnabled }
}

Register-TRControl -Framework SCuBA -Id 'MS.SECURITYSUITE.1.3v1' -Level Shall -Title 'Malware is quarantined or dropped' `
    -Needs 'ExoMalwarePolicies' -Checks 'EXO-11' `
    -Guidance 'With Defender for Office 365, apply Safe Attachments with the Block or Dynamic Delivery action. Exchange Online Protection always quarantines detected malware.' `
    -Test {
    if (-not (Test-TRLicensed 'DefenderO365')) { return New-TRCtl Pass 'Exchange Online Protection quarantines detected malware; Safe Attachments is not licensed.' }
    if (-not (Test-TRCollected @('ExoSafeAttachmentPolicies'))) { return New-TRCtl NotAssessed 'Safe Attachments policies were not collected.' }
    $top = Get-TRTopExoPolicy (Get-TRActiveExoPolicies -PolicyKey 'ExoSafeAttachmentPolicies' -RuleKey 'ExoSafeAttachmentRules' -RuleField 'SafeAttachmentPolicy' -Plane ATP)
    if (-not $top) { return New-TRCtl Fail 'No Safe Attachments policy is applied.' }
    if ((Test-TRTrue $top.Policy.Enable) -and [string]$top.Policy.Action -in @('Block', 'DynamicDelivery')) { return New-TRCtl Pass ('{0} uses {1}.' -f $top.Name, $top.Policy.Action) }
    New-TRCtl Fail ('{0} uses {1}.' -f $top.Name, $(if (Test-TRTrue $top.Policy.Enable) { $top.Policy.Action } else { 'no action (disabled)' }))
}

Register-TRControl -Framework SCuBA -Id 'MS.SECURITYSUITE.1.4v1' -Level Should -Title 'SharePoint, OneDrive and Teams files are scanned' `
    -Licence 'DefenderO365' -Needs 'ExoAtpPolicy' `
    -Guidance 'Turn on Defender for Office 365 for SharePoint, OneDrive and Teams.' `
    -Test {
    if (Test-TRTrue (Get-TRRawValue 'ExoAtpPolicy').EnableATPForSPOTeamsODB) { return New-TRCtl Pass 'Files in SharePoint, OneDrive and Teams are scanned.' }
    New-TRCtl Fail 'Safe Attachments for SharePoint, OneDrive and Teams is off.'
}

Register-TRControl -Framework SCuBA -Id 'MS.SECURITYSUITE.2.1v1' -Level Should -Title 'Sensitive accounts have impersonation protection' `
    -Licence 'DefenderO365' -Needs 'ExoAntiPhishPolicies' -Checks 'EXO-09' `
    -Guidance 'Add executives and other sensitive accounts to user impersonation protection in an applied anti-phishing policy.' `
    -Test { Test-TRAnyPolicy -Active (Get-TRActiveAntiPhish) -PassText 'User impersonation protection covers named users' -FailText 'No applied anti-phishing policy protects named users from impersonation.' -Ok { param($p) (Test-TRTrue $p.EnableTargetedUserProtection) -and @(Get-TRStrings $p.TargetedUsersToProtect).Count } }

Register-TRControl -Framework SCuBA -Id 'MS.SECURITYSUITE.2.2v1' -Level Should -Title 'Owned domains have impersonation protection' `
    -Licence 'DefenderO365' -Needs 'ExoAntiPhishPolicies' -Checks 'EXO-09' `
    -Guidance 'Turn on domain impersonation protection for the organisation''s own domains.' `
    -Test { Test-TRAnyPolicy -Active (Get-TRActiveAntiPhish) -PassText 'Owned domains are protected' -FailText 'No applied anti-phishing policy protects the organisation''s domains from impersonation.' -Ok { param($p) Test-TRTrue $p.EnableOrganizationDomainsProtection } }

Register-TRControl -Framework SCuBA -Id 'MS.SECURITYSUITE.2.3v1' -Level Should -Title 'Partner domains have impersonation protection' `
    -Licence 'DefenderO365' -Needs 'ExoAntiPhishPolicies' `
    -Guidance 'Add key suppliers'' and partners'' domains to domain impersonation protection.' `
    -Test { Test-TRAnyPolicy -Active (Get-TRActiveAntiPhish) -PassText 'Partner domains are protected' -FailText 'No partner domains are listed for impersonation protection.' -Ok { param($p) (Test-TRTrue $p.EnableTargetedDomainsProtection) -and @(Get-TRStrings $p.TargetedDomainsToProtect).Count } }

Register-TRControl -Framework SCuBA -Id 'MS.SECURITYSUITE.2.4v1' -Level Should -Title 'Impersonation safety tips are shown' `
    -Licence 'DefenderO365' -Needs 'ExoAntiPhishPolicies' `
    -Guidance 'Turn on user, domain and unusual character impersonation safety tips.' `
    -Test { Test-TRAnyPolicy -Active (Get-TRActiveAntiPhish) -PassText 'Impersonation safety tips are on' -FailText 'Impersonation safety tips are not all on in any applied policy.' -Ok { param($p) (Test-TRTrue $p.EnableSimilarUsersSafetyTips) -and (Test-TRTrue $p.EnableSimilarDomainsSafetyTips) -and (Test-TRTrue $p.EnableUnusualCharactersSafetyTips) } }

Register-TRControl -Framework SCuBA -Id 'MS.SECURITYSUITE.3.1v1' -Level Shall -Title 'DLP blocks sharing of card numbers and identifiers' `
    -Licence 'Dlp' -Needs 'SccDlpPolicies', 'SccDlpRules' -Checks 'PUR-01' `
    -Guidance 'Enforce a DLP policy that blocks credit card numbers and the national identifiers the organisation holds. SCuBA names US SSN and ITIN; UK clients should use National Insurance and passport numbers.' `
    -Test {
    $rules = @(Get-TRDlpRulesFor (Get-TRDlpActive))
    $cc = @($rules | Where-Object { [string]$_.SensitiveTypes -match 'Credit Card' -and (Test-TRTrue $_.BlockAccess) })
    if (-not $cc.Count) { return New-TRCtl Fail 'No enforced DLP rule blocks credit card numbers.' }
    $types = @($rules | ForEach-Object { [string]$_.SensitiveTypes -split ';\s*' } | Where-Object { $_ } | Select-Object -Unique)
    New-TRCtl Pass ('Credit card numbers are blocked by {0}. Sensitive types covered: {1}.' -f (Join-TRList ($cc | ForEach-Object { $_.Name }) 3), (Join-TRList $types 6))
}

Register-TRControl -Framework SCuBA -Id 'MS.SECURITYSUITE.3.2v1' -Level Should -Title 'DLP covers mail, files, Teams and devices' `
    -Licence 'Dlp' -Needs 'SccDlpPolicies' -Checks 'PUR-01' `
    -Guidance 'Make sure enforced DLP policies cover Exchange, OneDrive, SharePoint, Teams chat and devices.' `
    -Test {
    $on = Get-TRDlpActive
    $map = [ordered]@{ Exchange = 'ExchangeLocation'; SharePoint = 'SharePointLocation'; OneDrive = 'OneDriveLocation'; Teams = 'TeamsLocation'; Devices = 'EndpointDlpLocation' }
    $missing = @($map.Keys | Where-Object { $k = $map[$_]; -not @($on | Where-Object { [string](Get-TRV $_ $k) -eq 'All' -or ($k -eq 'TeamsLocation' -and ([string]$_.TeamsChatLocation -eq 'All')) }).Count })
    if ($missing.Count) { return New-TRCtl Fail ('No enforced DLP policy covers: {0}.' -f ($missing -join ', ')) }
    New-TRCtl Pass 'Enforced DLP policies cover mail, SharePoint, OneDrive, Teams and devices.'
}

Register-TRControl -Framework SCuBA -Id 'MS.SECURITYSUITE.3.3v1' -Level Should -Title 'DLP blocks sharing sensitive data with everyone' `
    -Licence 'Dlp' -Needs 'SccDlpPolicies', 'SccDlpRules' `
    -Guidance 'Set DLP rule actions to block access for everyone when sensitive information is detected.' `
    -Test {
    $rules = @(Get-TRDlpRulesFor (Get-TRDlpActive) | Where-Object { Test-TRTrue $_.BlockAccess })
    if ($rules.Count) { return New-TRCtl Pass ('Blocking rules: {0}.' -f (Join-TRList ($rules | ForEach-Object { $_.Name }) 4)) }
    New-TRCtl Fail 'No enforced DLP rule blocks access.'
}

Register-TRControl -Framework SCuBA -Id 'MS.SECURITYSUITE.3.4v1' -Level Should -Title 'DLP notifies users' `
    -Licence 'Dlp' -Needs 'SccDlpPolicies', 'SccDlpRules' `
    -Guidance 'Turn on user notifications and policy tips in DLP rules.' `
    -Test {
    $rules = @(Get-TRDlpRulesFor (Get-TRDlpActive) | Where-Object { @(Get-TRStrings $_.NotifyUser).Count })
    if ($rules.Count) { return New-TRCtl Pass ('Rules that notify users: {0}.' -f (Join-TRList ($rules | ForEach-Object { $_.Name }) 4)) }
    New-TRCtl Fail 'No enforced DLP rule notifies users.'
}

Register-TRControl -Framework SCuBA -Id 'MS.SECURITYSUITE.3.5v1' -Level Should -Title 'Endpoint DLP blocks restricted apps' -ManualOnly `
    -Licence 'EndpointDlp' `
    -Guidance 'In endpoint DLP settings, define restricted apps and unwanted Bluetooth apps, and block access to sensitive files from them.'

Register-TRControl -Framework SCuBA -Id 'MS.SECURITYSUITE.4.1v1' -Level Shall -Title 'Required alert policies are on' `
    -Needs 'SccAlertPolicies' -Checks 'PUR-04' `
    -Guidance 'Make sure the default alert policies for suspicious sending, connectors, forwarding, delayed and restricted mail and malicious URL clicks are enabled.' `
    -Test {
    $names = @('Suspicious email sending patterns detected', 'Suspicious Connector Activity', 'Suspicious Email Forwarding Activity', 'Messages have been delayed', 'Tenant restricted from sending unprovisioned email', 'Tenant restricted from sending email', 'A potentially malicious URL click was detected')
    $st = @(Get-TRAlertState $names)
    $bad = @($st | Where-Object { -not $_.Enabled })
    if ($bad.Count) { return New-TRCtl Fail ('Missing or disabled: {0}.' -f (Join-TRList ($bad | ForEach-Object { $_.Name }) 7)) }
    New-TRCtl Pass 'All seven required alert policies are enabled.'
}

Register-TRControl -Framework SCuBA -Id 'MS.SECURITYSUITE.4.2v1' -Level Should -Title 'Alerts reach a monitored mailbox or SIEM' `
    -Needs 'SccAlertPolicies' `
    -Guidance 'Send the required alerts to a monitored mailbox, or forward them to the SIEM.' `
    -Test {
    $st = @(Get-TRAlertState @('Suspicious email sending patterns detected', 'Suspicious Email Forwarding Activity', 'A potentially malicious URL click was detected'))
    New-TRCtl Manual ('Recipients: {0}. Confirm these are monitored or that alerts reach the SIEM.' -f (Join-TRList ($st | ForEach-Object { $_.Name + ' -> ' + $(if ($_.NotifyUser) { $_.NotifyUser } else { 'none' }) }) 3))
}

Register-TRControl -Framework SCuBA -Id 'MS.SECURITYSUITE.5.1v1' -Level Shall -Title 'Unified audit logging is on' `
    -Needs 'ExoAdminAuditLogConfig' -Checks 'EXO-01' `
    -Guidance 'Turn on audit log ingestion in Microsoft Purview.' `
    -Test {
    if (Test-TRTrue (Get-TRRawValue 'ExoAdminAuditLogConfig').UnifiedAuditLogIngestionEnabled) { return New-TRCtl Pass 'Unified audit logging is on.' }
    New-TRCtl Fail 'Unified audit logging is off.'
}

Register-TRControl -Framework SCuBA -Id 'MS.SECURITYSUITE.5.2v1' -Level Shall -Title 'Audit logs are kept for 12 months' `
    -Guidance 'Keep audit logs searchable for 3 months and retrievable for 12, using Audit (Premium) retention policies or export to a SIEM or log store.' `
    -Test {
    $p = @(Get-TRItems 'SccAuditRetention' | Where-Object { [string]$_.RetentionDuration -match 'OneYear|TenYears|SevenYears|FiveYears|ThreeYears' })
    if ($p.Count) { return New-TRCtl Pass ('Audit retention policies keep logs for a year or more: {0}.' -f (Join-TRList ($p | ForEach-Object { $_.Name }) 3)) }
    New-TRCtl Manual $(if (Test-TRLicensed 'AuditPremium') { 'No audit retention policy of a year or more was found. Confirm logs are exported to a SIEM or log store.' } else { 'Audit (Premium) is not licensed, so standard retention is 180 days. Confirm logs are exported to a SIEM or log store for 12 months.' })
}

Register-TRControl -Framework SCuBA -Id 'MS.SECURITYSUITE.6.1v1' -Level Shall -Title 'Spam and phishing do not reach the inbox' `
    -Needs 'ExoContentFilterPolicies' `
    -Guidance 'In every applied anti-spam policy, move spam to Junk or quarantine, and quarantine high confidence spam and phishing.' `
    -Test {
    $active = @(Get-TRActiveExoPolicies -PolicyKey 'ExoContentFilterPolicies' -RuleKey 'ExoContentFilterRules' -RuleField 'HostedContentFilterPolicy' -Plane EOP)
    Test-TREveryPolicy -Active $active -Label 'Delivers spam or phishing to the inbox' -PassText 'Spam and phishing are moved to Junk or quarantined' -Ok {
        param($p)
        $ok = @('MoveToJmf', 'Quarantine', 'Redirect', 'Delete')
        (@('SpamAction', 'HighConfidenceSpamAction', 'PhishSpamAction', 'HighConfidencePhishAction') | Where-Object { [string](Get-TRV $p $_) -notin $ok }).Count -eq 0
    }
}

Register-TRControl -Framework SCuBA -Id 'MS.SECURITYSUITE.6.2v1' -Level Shall -Title 'Anti-spam policies allow no sender domains' `
    -Needs 'ExoContentFilterPolicies' -Checks 'EXO-08' `
    -Guidance 'Remove allowed sender domains from all inbound anti-spam policies.' `
    -Test {
    $bad = @(Get-TRItems 'ExoContentFilterPolicies' | Where-Object { @(Get-TRStrings $_.AllowedSenderDomains).Count })
    if ($bad.Count) { return New-TRCtl Fail ('Policies with allowed domains: {0}.' -f (Join-TRList ($bad | ForEach-Object { $_.Name }) 4)) }
    New-TRCtl Pass 'No anti-spam policy allows whole sender domains.'
}

Register-TRControl -Framework SCuBA -Id 'MS.SECURITYSUITE.7.1v1' -Level Should -Title 'Safe Links checks URLs in email, Teams and Office' `
    -Licence 'DefenderO365' -Needs 'ExoSafeLinksPolicies' -Checks 'EXO-10' `
    -Guidance 'Apply Safe Links to email, Teams and Office apps.' `
    -Test { Test-TRAnyPolicy -Active (Get-TRActiveExoPolicies -PolicyKey 'ExoSafeLinksPolicies' -RuleKey 'ExoSafeLinksRules' -RuleField 'SafeLinksPolicy' -Plane ATP) -PassText 'Safe Links covers email, Teams and Office' -FailText 'No applied Safe Links policy covers email, Teams and Office.' -Ok { param($p) (Test-TRTrue $p.EnableSafeLinksForEmail) -and (Test-TRTrue $p.EnableSafeLinksForTeams) -and (Test-TRTrue $p.EnableSafeLinksForOffice) } }

Register-TRControl -Framework SCuBA -Id 'MS.SECURITYSUITE.7.2v1' -Level Should -Title 'Safe Links scans download links' `
    -Licence 'DefenderO365' -Needs 'ExoSafeLinksPolicies' `
    -Guidance 'Turn on real-time URL scanning for suspicious links and links to files.' `
    -Test { Test-TRAnyPolicy -Active (Get-TRActiveExoPolicies -PolicyKey 'ExoSafeLinksPolicies' -RuleKey 'ExoSafeLinksRules' -RuleField 'SafeLinksPolicy' -Plane ATP) -PassText 'Real-time URL scanning is on' -FailText 'No applied Safe Links policy scans URLs in real time.' -Ok { param($p) Test-TRTrue $p.ScanUrls } }

Register-TRControl -Framework SCuBA -Id 'MS.SECURITYSUITE.7.3v1' -Level Should -Title 'Safe Links tracks user clicks' `
    -Licence 'DefenderO365' -Needs 'ExoSafeLinksPolicies' `
    -Guidance 'Turn on Track user clicks in Safe Links.' `
    -Test { Test-TRAnyPolicy -Active (Get-TRActiveExoPolicies -PolicyKey 'ExoSafeLinksPolicies' -RuleKey 'ExoSafeLinksRules' -RuleField 'SafeLinksPolicy' -Plane ATP) -PassText 'Click tracking is on' -FailText 'No applied Safe Links policy tracks clicks.' -Ok { param($p) Test-TRTrue $p.TrackClicks } }

Register-TRControl -Framework SCuBA -Id 'MS.SECURITYSUITE.8.1v1' -Level Should -Title 'No IP allow lists' `
    -Needs 'ExoConnectionFilter' `
    -Guidance 'Remove all entries from the connection filter IP allow list.' `
    -Test {
    $bad = @(Get-TRItems 'ExoConnectionFilter' | Where-Object { @(Get-TRStrings $_.IPAllowList).Count })
    if ($bad.Count) { return New-TRCtl Fail ('IP allow list entries: {0}.' -f (Join-TRList ($bad | ForEach-Object { $_.IPAllowList }) 5)) }
    New-TRCtl Pass 'No IP allow list entries.'
}

Register-TRControl -Framework SCuBA -Id 'MS.SECURITYSUITE.8.2v1' -Level Should -Title 'The safe list is off' `
    -Needs 'ExoConnectionFilter' `
    -Guidance 'Turn off the safe list in the connection filter policy.' `
    -Test {
    $bad = @(Get-TRItems 'ExoConnectionFilter' | Where-Object { Test-TRTrue $_.EnableSafeList })
    if ($bad.Count) { return New-TRCtl Fail 'The connection filter safe list is on.' }
    New-TRCtl Pass 'The safe list is off.'
}

Register-TRControl -Framework SCuBA -Id 'MS.EXO.1.1v2' -Level Shall -Title 'Automatic forwarding to external domains is off' `
    -Needs 'ExoRemoteDomains' -Checks 'EXO-05' `
    -Guidance 'Turn off automatic forwarding on the default remote domain and any others not explicitly approved.' `
    -Test {
    $bad = @(Get-TRItems 'ExoRemoteDomains' | Where-Object { Test-TRTrue $_.AutoForwardEnabled })
    if ($bad.Count) { return New-TRCtl Fail ('Remote domains allowing automatic forwarding: {0}.' -f (Join-TRList ($bad | ForEach-Object { $_.DomainName }) 5)) (@($bad | ForEach-Object { New-TRAffected ([string]$_.DomainName) 'Auto forward enabled' })) }
    New-TRCtl Pass 'No remote domain allows automatic forwarding.'
}

Register-TRControl -Framework SCuBA -Id 'MS.EXO.2.2v3' -Level Shall -Title 'SPF fails unapproved senders' `
    -Needs 'DnsRecords' -Checks 'DNS-01' `
    -Guidance 'Publish an SPF record for every domain ending in -all, ~all or a redirect to a record that does.' `
    -Test {
    $rows = @(Get-TRItems 'DnsRecords')
    if (-not $rows.Count) { return New-TRCtl NotApplicable 'There are no custom domains.' }
    $bad = @($rows | ForEach-Object { $p = Test-TRSpfOk $_; if ($p) { New-TRAffected ([string]$_.Domain) $p } })
    if ($bad.Count) { return New-TRCtl Fail ('{0} of {1} domains lack a compliant SPF record.' -f $bad.Count, $rows.Count) $bad }
    New-TRCtl Pass ((Select-TRText $rows.Count 'The only domain publishes a compliant SPF record.' 'All {0} domains publish a compliant SPF record.') -f $rows.Count)
}

Register-TRControl -Framework SCuBA -Id 'MS.EXO.3.1v1' -Level Should -Title 'DKIM is on for all domains' `
    -Needs 'DnsRecords', 'ExoDkim' -Checks 'DNS-02' `
    -Guidance 'Enable DKIM signing for every custom domain.' `
    -Test {
    $rows = Get-TRMailRows
    if (-not $rows.Count) { return New-TRCtl NotApplicable 'No custom domains send mail.' }
    $dk = @{}
    foreach ($d in (Get-TRItems 'ExoDkim')) { $dk[([string]$d.Domain).ToLower()] = $d }
    $bad = @($rows | Where-Object { $c = $dk[([string]$_.Domain).ToLower()]; -not ($c -and (Test-TRTrue $c.Enabled)) })
    if ($bad.Count) { return New-TRCtl Fail ('DKIM is off for: {0}.' -f (Join-TRList ($bad | ForEach-Object { $_.Domain }) 6)) }
    New-TRCtl Pass 'DKIM is on for all mail domains.'
}

Register-TRControl -Framework SCuBA -Id 'MS.EXO.4.1v1' -Level Shall -Title 'DMARC is published for every domain' `
    -Needs 'DnsRecords' -Checks 'DNS-03' `
    -Guidance 'Publish a DMARC record for every second-level domain.' `
    -Test {
    $rows = @(Get-TRItems 'DnsRecords')
    $bad = @($rows | Where-Object { -not (Get-TRDmarcRecord ([string]$_.Domain) $rows) })
    if ($bad.Count) { return New-TRCtl Fail ('No DMARC record for: {0}.' -f (Join-TRList ($bad | ForEach-Object { $_.Domain }) 6)) }
    New-TRCtl Pass ((Select-TRText $rows.Count 'DMARC is published for the only domain.' 'DMARC is published for all {0} domains.') -f $rows.Count)
}

Register-TRControl -Framework SCuBA -Id 'MS.EXO.4.2v1' -Level Shall -Title 'DMARC policy is reject' `
    -Needs 'DnsRecords' -Checks 'DNS-03' `
    -Guidance 'Move every DMARC record to p=reject once legitimate senders pass SPF or DKIM.' `
    -Test {
    $rows = @(Get-TRItems 'DnsRecords')
    $bad = @($rows | Where-Object { $r = Get-TRDmarcRecord ([string]$_.Domain) $rows; -not $r -or ([string](ConvertFrom-TRDmarc $r.Record)['p']).ToLower() -ne 'reject' })
    if ($bad.Count) { return New-TRCtl Fail ('Not at p=reject: {0}.' -f (Join-TRList ($bad | ForEach-Object { $_.Domain }) 6)) }
    New-TRCtl Pass 'Every domain uses p=reject.'
}

Register-TRControl -Framework SCuBA -Id 'MS.EXO.4.3v1' -Level Shall -Title 'DMARC reports go to CISA' `
    -Guidance 'This applies only to US federal agencies, which must include reports@dmarc.cyber.dhs.gov.' `
    -Test { New-TRCtl NotApplicable 'This requirement applies only to US federal agencies.' }

Register-TRControl -Framework SCuBA -Id 'MS.EXO.4.4v1' -Level Should -Title 'DMARC reports go to the organisation' `
    -Needs 'DnsRecords' -Checks 'DNS-04' `
    -Guidance 'Add an organisation contact for both aggregate (rua) and failure (ruf) reports.' `
    -Test {
    $rows = @(Get-TRItems 'DnsRecords')
    $bad = @($rows | Where-Object { $r = Get-TRDmarcRecord ([string]$_.Domain) $rows; if (-not $r) { $true } else { $t = ConvertFrom-TRDmarc $r.Record; -not $t['rua'] -or -not $t['ruf'] } })
    if ($bad.Count) { return New-TRCtl Fail ('Missing rua or ruf: {0}.' -f (Join-TRList ($bad | ForEach-Object { $_.Domain }) 6)) }
    New-TRCtl Pass 'Every DMARC record has aggregate and failure report contacts.'
}

Register-TRControl -Framework SCuBA -Id 'MS.EXO.5.1v1' -Level Shall -Title 'SMTP AUTH is off' `
    -Needs 'ExoTransportConfig' -Checks 'EXO-04' `
    -Guidance 'Turn off SMTP AUTH for the organisation.' `
    -Test {
    if (Test-TRTrue (Get-TRRawValue 'ExoTransportConfig').SmtpClientAuthenticationDisabled) { return New-TRCtl Pass 'SMTP AUTH is off.' }
    New-TRCtl Fail 'SMTP AUTH is on.'
}

Register-TRControl -Framework SCuBA -Id 'MS.EXO.6.1v1' -Level Shall -Title 'Contacts are not shared with all domains' `
    -Needs 'ExoSharingPolicies' `
    -Guidance 'Remove contact sharing for all domains (*) from sharing policies.' `
    -Test {
    $bad = @(Get-TRItems 'ExoSharingPolicies' | Where-Object { -not (Test-TRFalse $_.Enabled) -and @(Get-TRStrings $_.Domains | Where-Object { $_ -match '^\*:.*Contacts' }).Count })
    if ($bad.Count) { return New-TRCtl Fail ('Policies sharing contacts with all domains: {0}.' -f (Join-TRList ($bad | ForEach-Object { $_.Name }) 4)) }
    New-TRCtl Pass 'Contacts are not shared with all domains.'
}

Register-TRControl -Framework SCuBA -Id 'MS.EXO.6.2v1' -Level Shall -Title 'Calendars are not shared with all domains' `
    -Needs 'ExoSharingPolicies' -Checks 'EXO-14' `
    -Guidance 'Remove calendar sharing for all domains (*) and anonymous users from sharing policies.' `
    -Test {
    $bad = @(Get-TRItems 'ExoSharingPolicies' | Where-Object { -not (Test-TRFalse $_.Enabled) -and @(Get-TRStrings $_.Domains | Where-Object { $_ -match '^(\*|Anonymous):.*Calendar' }).Count })
    if ($bad.Count) { return New-TRCtl Fail ('Policies sharing calendars with all domains: {0}.' -f (Join-TRList ($bad | ForEach-Object { $_.Name + ' (' + (Join-TRList $_.Domains 3) + ')' }) 3)) }
    New-TRCtl Pass 'Calendars are not shared with all domains.'
}

Register-TRControl -Framework SCuBA -Id 'MS.EXO.7.1v1' -Level Shall -Title 'External senders are flagged' `
    -Needs 'ExoExternalInOutlook' -Checks 'EXO-13' `
    -Guidance 'Turn on external sender tagging in Outlook, or add a mail flow rule that warns about external senders.' `
    -Test {
    if (Test-TRTrue (Get-TRRawValue 'ExoExternalInOutlook').Enabled) { return New-TRCtl Pass 'External sender tagging is on.' }
    $r = @(Get-TRItems 'ExoTransportRules' | Where-Object { [string]$_.State -eq 'Enabled' -and ([string]$_.Name + ' ' + [string]$_.Description) -match 'external' })
    if ($r.Count) { return New-TRCtl Manual ('Outlook tagging is off. These mail flow rules may add a warning: {0}. Confirm.' -f (Join-TRList ($r | ForEach-Object { $_.Name }) 3)) }
    New-TRCtl Fail 'External senders are not flagged.'
}

Register-TRControl -Framework SCuBA -Id 'MS.EXO.13.1v1' -Level Shall -Title 'Mailbox auditing is on' `
    -Needs 'ExoOrganizationConfig' -Checks 'EXO-02' `
    -Guidance 'Keep mailbox auditing on by default for the organisation.' `
    -Test {
    if (Test-TRFalse (Get-TRRawValue 'ExoOrganizationConfig').AuditDisabled) { return New-TRCtl Pass 'Mailbox auditing is on.' }
    New-TRCtl Fail 'Mailbox auditing is off.'
}

Register-TRControl -Framework SCuBA -Id 'MS.SHAREPOINT.1.1v1' -Level Shall -Title 'SharePoint sharing is existing guests or internal only' `
    -Needs 'SharePointSettings' -Checks 'SPO-01' `
    -Guidance 'Set SharePoint external sharing to Existing guests or Only people in your organisation.' `
    -Test {
    $c = Get-TRSpoSharing
    if ($null -eq $c) { return New-TRCtl NotAssessed 'The sharing level was not returned.' }
    if ($c -in @(0, 3)) { return New-TRCtl Pass ('SharePoint sharing: {0}.' -f $script:TRSharingCapNames[$c]) }
    New-TRCtl Fail ('SharePoint sharing: {0}.' -f $script:TRSharingCapNames[$c])
}

Register-TRControl -Framework SCuBA -Id 'MS.SHAREPOINT.1.2v1' -Level Shall -Title 'OneDrive sharing is existing guests or internal only' `
    -Needs 'SpoTenant' `
    -Guidance 'Set OneDrive external sharing to Existing guests or Only people in your organisation.' `
    -Test {
    $c = Get-TRSpoSharing -OneDrive
    if ($null -eq $c) { return New-TRCtl NotAssessed 'The OneDrive sharing level was not returned.' }
    if ($c -in @(0, 3)) { return New-TRCtl Pass ('OneDrive sharing: {0}.' -f $script:TRSharingCapNames[$c]) }
    New-TRCtl Fail ('OneDrive sharing: {0}.' -f $script:TRSharingCapNames[$c])
}

Register-TRControl -Framework SCuBA -Id 'MS.SHAREPOINT.1.3v1' -Level Shall -Title 'External sharing is limited to approved domains' `
    -Needs 'SharePointSettings' -Checks 'SPO-05' `
    -Guidance 'Limit external sharing to an allow list of approved domains, or to approved security groups.' `
    -Test {
    if ((Get-TRSpoSharing) -eq 0) { return New-TRCtl Pass 'External sharing is off.' }
    $mode = Get-TRSpoEnum 'SharingDomainRestrictionMode' @('None', 'AllowList', 'BlockList')
    if ($null -eq $mode) { $mode = @{ 'none' = 0; 'allowList' = 1; 'blockList' = 2 }[[string](Get-TRRawValue 'SharePointSettings').sharingDomainRestrictionMode] }
    if ($mode -eq 1) { return New-TRCtl Pass 'External sharing is limited to allowed domains.' }
    New-TRCtl Fail 'External sharing is not limited to an allow list of domains.'
}

Register-TRControl -Framework SCuBA -Id 'MS.SHAREPOINT.2.1v1' -Level Shall -Title 'Default sharing scope is specific people' `
    -Needs 'SpoTenant' `
    -Guidance 'Set the default link type to Specific people.' `
    -Test {
    $v = Get-TRSpoEnum 'DefaultSharingLinkType' @('None', 'Direct', 'Internal', 'AnonymousAccess')
    if ($v -eq 1) { return New-TRCtl Pass 'Default link: Specific people.' }
    New-TRCtl Fail ('Default link: {0}.' -f $(switch ($v) { 2 { 'People in the organisation' } 3 { 'Anyone' } default { 'not set' } }))
}

Register-TRControl -Framework SCuBA -Id 'MS.SHAREPOINT.2.2v1' -Level Shall -Title 'Default link permission is view' `
    -Needs 'SpoTenant' `
    -Guidance 'Set the default link permission to View.' `
    -Test {
    if ((Get-TRSpoEnum 'DefaultLinkPermission' @('None', 'View', 'Edit')) -eq 1) { return New-TRCtl Pass 'Default permission: View.' }
    New-TRCtl Fail 'Default permission is not View.'
}

Register-TRControl -Framework SCuBA -Id 'MS.SHAREPOINT.3.1v1' -Level Shall -Title 'Anyone links expire within 30 days' `
    -Needs 'SpoTenant' `
    -Guidance 'Where Anyone links are allowed, make them expire within 30 days.' `
    -Test {
    Test-TRSpoNeedsAnyone -Ok {
        $d = [int](Get-TRV (Get-TRSpo) 'RequireAnonymousLinksExpireInDays')
        if ($d -gt 0 -and $d -le 30) { return New-TRCtl Pass ('Anyone links expire after {0}.' -f (Format-TRN $d 'day')) }
        New-TRCtl Fail $(if ($d -gt 0) { "Anyone links expire after $d days." } else { 'Anyone links never expire.' })
    }
}

Register-TRControl -Framework SCuBA -Id 'MS.SHAREPOINT.3.2v1' -Level Shall -Title 'Anyone links are view only' `
    -Needs 'SpoTenant' `
    -Guidance 'Where Anyone links are allowed, set file and folder link permissions to View.' `
    -Test {
    Test-TRSpoNeedsAnyone -Ok {
        $f = Get-TRSpoEnum 'FileAnonymousLinkType' @('None', 'View', 'Edit')
        $d = Get-TRSpoEnum 'FolderAnonymousLinkType' @('None', 'View', 'Edit')
        if ($f -eq 1 -and $d -eq 1) { return New-TRCtl Pass 'Anyone links are view only.' }
        New-TRCtl Fail ('Anyone link permissions: files {0}, folders {1}.' -f $(if ($f -eq 2) { 'edit' } else { 'view' }), $(if ($d -eq 2) { 'edit' } else { 'view' }))
    }
}

Register-TRControl -Framework SCuBA -Id 'MS.SHAREPOINT.3.3v2' -Level Shall -Title 'Verification code users re-authenticate within 30 days' `
    -Needs 'SpoTenant' `
    -Guidance 'Require people who use a verification code to re-authenticate after 30 days or less.' `
    -Test {
    if ((Get-TRSpoSharing) -eq 0) { return New-TRCtl Pass 'External sharing is off.' }
    $spo = Get-TRSpo
    $req = Test-TRTrue (Get-TRV $spo 'EmailAttestationRequired')
    $days = [int](Get-TRV $spo 'EmailAttestationReAuthDays')
    if ($req -and $days -gt 0 -and $days -le 30) { return New-TRCtl Pass ('Re-authentication every {0}.' -f (Format-TRN $days 'day')) }
    New-TRCtl Fail $(if ($req) { "Re-authentication every $days days." } else { 'Re-authentication is not required.' })
}

Register-TRControl -Framework SCuBA -Id 'MS.TEAMS.1.1v1' -Level Should -Title 'External participants cannot request control' `
    -Needs 'TeamsMeetingPolicies' `
    -Guidance 'Turn off giving or requesting control for external participants in all meeting policies.' `
    -Test { Test-TRTeamsAll -Key 'TeamsMeetingPolicies' -Setting 'AllowExternalParticipantGiveRequestControl' -Ok { param($v) Test-TRFalse $v } }

Register-TRControl -Framework SCuBA -Id 'MS.TEAMS.1.2v2' -Level Shall -Title 'Anonymous users cannot start meetings' `
    -Needs 'TeamsMeetingPolicies' `
    -Guidance 'Turn off anonymous users starting meetings in all meeting policies.' `
    -Test { Test-TRTeamsAll -Key 'TeamsMeetingPolicies' -Setting 'AllowAnonymousUsersToStartMeeting' -Ok { param($v) Test-TRFalse $v } }

Register-TRControl -Framework SCuBA -Id 'MS.TEAMS.1.3v1' -Level Should -Title 'Anonymous and dial-in users wait in the lobby' `
    -Needs 'TeamsMeetingPolicies' `
    -Guidance 'Do not let everyone bypass the lobby, and keep dial-in users in the lobby.' `
    -Test {
    $g = Get-TRTeamsPolicy 'TeamsMeetingPolicies'
    if (-not $g) { return New-TRCtl NotAssessed 'The Global meeting policy was not returned.' }
    $a = [string](Get-TRV $g 'AutoAdmittedUsers')
    $p = Get-TRV $g 'AllowPSTNUsersToBypassLobby'
    if ($a -ne 'Everyone' -and (Test-TRFalse $p)) { return New-TRCtl Pass ('Lobby bypass: {0}; dial-in users wait.' -f $a) }
    New-TRCtl Fail ('Lobby bypass: {0}; dial-in bypass: {1}.' -f $a, [string]$p)
}

Register-TRControl -Framework SCuBA -Id 'MS.TEAMS.1.4v1' -Level Should -Title 'Internal users join meetings directly' `
    -Needs 'TeamsMeetingPolicies' `
    -Guidance 'Let people in the organisation bypass the lobby.' `
    -Test { Test-TRTeamsAll -Key 'TeamsMeetingPolicies' -Setting 'AutoAdmittedUsers' -GlobalOnly -Ok { param($v) [string]$v -in @('EveryoneInCompany', 'EveryoneInSameAndFederatedCompany', 'EveryoneInCompanyExcludingGuests') } }

Register-TRControl -Framework SCuBA -Id 'MS.TEAMS.1.5v1' -Level Should -Title 'Dial-in users cannot bypass the lobby' `
    -Needs 'TeamsMeetingPolicies' `
    -Guidance 'Turn off dial-in lobby bypass in all meeting policies.' `
    -Test { Test-TRTeamsAll -Key 'TeamsMeetingPolicies' -Setting 'AllowPSTNUsersToBypassLobby' -Ok { param($v) Test-TRFalse $v } }

Register-TRControl -Framework SCuBA -Id 'MS.TEAMS.1.6v1' -Level Should -Title 'Meeting recording is off' `
    -Needs 'TeamsMeetingPolicies' `
    -Guidance 'Turn off cloud recording in the Global meeting policy.' `
    -Test { Test-TRTeamsAll -Key 'TeamsMeetingPolicies' -Setting 'AllowCloudRecording' -GlobalOnly -Ok { param($v) Test-TRFalse $v } }

Register-TRControl -Framework SCuBA -Id 'MS.TEAMS.1.7v2' -Level Should -Title 'Events are not always recorded' `
    -Needs 'TeamsBroadcastPolicies' `
    -Guidance 'Do not set live event recording to Always record.' `
    -Test { Test-TRTeamsAll -Key 'TeamsBroadcastPolicies' -Setting 'BroadcastRecordingMode' -GlobalOnly -Ok { param($v) [string]$v -ne 'AlwaysEnabled' } }

Register-TRControl -Framework SCuBA -Id 'MS.TEAMS.2.1v2' -Level Shall -Title 'External access is per domain only' `
    -Needs 'TeamsFederation' -Checks 'COL-05' `
    -Guidance 'Allow external access only for specific domains, or turn it off.' `
    -Test {
    $f = Get-TRTeamsPolicy 'TeamsFederation'
    if (-not $f) { return New-TRCtl NotAssessed 'The Teams federation settings were not returned.' }
    if (Test-TRFalse (Get-TRV $f 'AllowFederatedUsers')) { return New-TRCtl Pass 'External access is off.' }
    $d = Get-TRTeamsAllowedDomains $f
    if ($d.Mode -eq 'List' -and $d.Domains.Count) { return New-TRCtl Pass ('External access is limited to: {0}.' -f (Join-TRList $d.Domains 6)) }
    New-TRCtl Fail 'External access is open to all domains.'
}

Register-TRControl -Framework SCuBA -Id 'MS.TEAMS.2.2v2' -Level Shall -Title 'Unmanaged users cannot start contact' `
    -Needs 'TeamsFederation' `
    -Guidance 'Stop unmanaged Teams accounts from starting conversations with staff.' `
    -Test {
    $f = Get-TRTeamsPolicy 'TeamsFederation'
    if ((Test-TRFalse (Get-TRV $f 'AllowTeamsConsumer')) -or (Test-TRFalse (Get-TRV $f 'AllowTeamsConsumerInbound'))) { return New-TRCtl Pass 'Unmanaged users cannot start contact.' }
    New-TRCtl Fail 'Unmanaged Teams users can start conversations with staff.'
}

Register-TRControl -Framework SCuBA -Id 'MS.TEAMS.2.3v2' -Level Should -Title 'Staff cannot contact unmanaged users' `
    -Needs 'TeamsFederation' `
    -Guidance 'Turn off communication with unmanaged Teams accounts.' `
    -Test {
    if (Test-TRFalse (Get-TRV (Get-TRTeamsPolicy 'TeamsFederation') 'AllowTeamsConsumer')) { return New-TRCtl Pass 'Communication with unmanaged Teams accounts is off.' }
    New-TRCtl Fail 'Staff can communicate with unmanaged Teams accounts.'
}

Register-TRControl -Framework SCuBA -Id 'MS.TEAMS.4.1v1' -Level Shall -Title 'Teams email integration is off' `
    -Needs 'TeamsClientConfig' `
    -Guidance 'Turn off sending email to channel addresses.' `
    -Test {
    if (Test-TRFalse (Get-TRV (Get-TRTeamsPolicy 'TeamsClientConfig') 'AllowEmailIntoChannel')) { return New-TRCtl Pass 'Channel email is off.' }
    New-TRCtl Fail 'Channel email is on.'
}

Register-TRControl -Framework SCuBA -Id 'MS.TEAMS.5.1v2' -Level Should -Title 'Only approved Microsoft apps can be installed' `
    -Needs 'TeamsAppPolicies' `
    -Guidance 'Allow only approved Microsoft apps in org-wide app settings or app permission policies.' `
    -Test { Test-TRTeamsAll -Key 'TeamsAppPolicies' -Setting 'DefaultCatalogAppsType' -Ok { param($v) [string]$v -eq 'AllowedAppList' } }

Register-TRControl -Framework SCuBA -Id 'MS.TEAMS.5.2v2' -Level Should -Title 'Only approved third-party apps can be installed' `
    -Needs 'TeamsAppPolicies' `
    -Guidance 'Allow only approved third-party apps in org-wide app settings or app permission policies.' `
    -Test { Test-TRTeamsAll -Key 'TeamsAppPolicies' -Setting 'GlobalCatalogAppsType' -Ok { param($v) [string]$v -eq 'AllowedAppList' } }

Register-TRControl -Framework SCuBA -Id 'MS.TEAMS.5.3v2' -Level Should -Title 'Only approved custom apps can be installed' `
    -Needs 'TeamsAppPolicies' `
    -Guidance 'Allow only approved custom apps in org-wide app settings or app permission policies.' `
    -Test { Test-TRTeamsAll -Key 'TeamsAppPolicies' -Setting 'PrivateCatalogAppsType' -Ok { param($v) [string]$v -eq 'AllowedAppList' } }

Register-TRControl -Framework SCuBA -Id 'MS.POWERBI.1.1v1' -Level Should -Title 'Publish to web is off' `
    -Needs 'PowerBISettings' `
    -Guidance 'Turn off Publish to web unless there is a business need.' `
    -Test { Test-TRFabricRestricted 'PublishToWeb' -MustBeOff }

Register-TRControl -Framework SCuBA -Id 'MS.POWERBI.2.1v1' -Level Should -Title 'Guest access to Power BI is off' `
    -Needs 'PowerBISettings' `
    -Guidance 'Turn off guest access to Power BI unless there is a business need.' `
    -Test { Test-TRFabricRestricted 'AllowGuestUserToAccessSharedContent' -MustBeOff }

Register-TRControl -Framework SCuBA -Id 'MS.POWERBI.3.1v1' -Level Should -Title 'Inviting external users is off' `
    -Needs 'PowerBISettings' `
    -Guidance 'Turn off inviting external users through Power BI sharing unless there is a business need.' `
    -Test { Test-TRFabricRestricted 'ExternalSharingV2' -MustBeOff }

Register-TRControl -Framework SCuBA -Id 'MS.POWERBI.4.1v1' -Level Should -Title 'Service principal API access is limited to groups' `
    -Needs 'PowerBISettings' `
    -Guidance 'Limit service principal access to Fabric APIs to specific security groups.' `
    -Test { Test-TRFabricRestricted 'ServicePrincipalAccessPermissionAPIs' }

Register-TRControl -Framework SCuBA -Id 'MS.POWERBI.4.2v1' -Level Should -Title 'Service principal profiles are limited to groups' `
    -Needs 'PowerBISettings' `
    -Guidance 'Limit service principals creating and using profiles to specific security groups.' `
    -Test { Test-TRFabricRestricted 'AllowServicePrincipalsCreateAndUseProfiles' }

Register-TRControl -Framework SCuBA -Id 'MS.POWERBI.5.1v1' -Level Should -Title 'ResourceKey authentication is blocked' `
    -Needs 'PowerBISettings' `
    -Guidance 'Turn on Block ResourceKey Authentication unless streaming or push datasets need it.' `
    -Test { Test-TRFabricOn 'BlockResourceKeyAuthentication' }

Register-TRControl -Framework SCuBA -Id 'MS.POWERBI.6.1v1' -Level Should -Title 'R and Python visuals are off' `
    -Needs 'PowerBISettings' `
    -Guidance 'Turn off R and Python visuals.' `
    -Test { Test-TRFabricRestricted 'RScriptVisual' -MustBeOff }

Register-TRControl -Framework SCuBA -Id 'MS.POWERBI.7.1v1' -Level Should -Title 'Sensitivity labels are used in Power BI' `
    -Needs 'PowerBISettings' `
    -Guidance 'Let users apply sensitivity labels to Power BI content.' `
    -Test { Test-TRFabricOn 'EimInformationProtectionEdit' }

Register-TRControl -Framework SCuBA -Id 'MS.POWERPLATFORM.1.1v1' -Level Shall -Title 'Only admins create production and sandbox environments' `
    -Needs 'PpTenantSettings' `
    -Guidance 'In the Power Platform admin centre, restrict creating production and sandbox environments to admins.' `
    -Test {
    if (Test-TRTrue (Get-TRV (Get-TRRawValue 'PpTenantSettings') 'disableEnvironmentCreationByNonAdminUsers')) { return New-TRCtl Pass 'Only admins can create environments.' }
    New-TRCtl Fail 'Anyone can create production and sandbox environments.'
}

Register-TRControl -Framework SCuBA -Id 'MS.POWERPLATFORM.1.2v1' -Level Shall -Title 'Only admins create trial environments' `
    -Needs 'PpTenantSettings' `
    -Guidance 'Restrict creating trial environments to admins.' `
    -Test {
    if (Test-TRTrue (Get-TRV (Get-TRRawValue 'PpTenantSettings') 'disableTrialEnvironmentCreationByNonAdminUsers')) { return New-TRCtl Pass 'Only admins can create trial environments.' }
    New-TRCtl Fail 'Anyone can create trial environments.'
}

Register-TRControl -Framework SCuBA -Id 'MS.POWERPLATFORM.2.1v1' -Level Shall -Title 'A DLP policy covers the default environment' `
    -Needs 'PpDlpPolicies', 'PpEnvironments' `
    -Guidance 'Create a Power Platform DLP policy that restricts connectors in the default environment.' `
    -Test {
    $def = @(Get-TRItems 'PpEnvironments' | Where-Object { Test-TRTrue $_.IsDefault })[0]
    $pol = @(Get-TRItems 'PpDlpPolicies')
    if (-not $pol.Count) { return New-TRCtl Fail 'There are no Power Platform DLP policies.' }
    $name = if ($def) { [string]$def.Name } else { '' }
    $hit = @($pol | Where-Object { $_.EnvironmentType -eq 'AllEnvironments' -or ($_.EnvironmentType -eq 'OnlyEnvironments' -and @($_.Environments) -contains $name) -or ($_.EnvironmentType -eq 'ExceptEnvironments' -and @($_.Environments) -notcontains $name) })
    if ($hit.Count) { return New-TRCtl Pass ('The default environment is covered by: {0}.' -f (Join-TRList ($hit | ForEach-Object { $_.DisplayName }) 3)) }
    New-TRCtl Fail 'No DLP policy covers the default environment.'
}

Register-TRControl -Framework SCuBA -Id 'MS.POWERPLATFORM.2.2v1' -Level Should -Title 'Every other environment has a DLP policy' `
    -Needs 'PpDlpPolicies', 'PpEnvironments' `
    -Guidance 'Apply at least one DLP policy to every non-default environment.' `
    -Test {
    $pol = @(Get-TRItems 'PpDlpPolicies')
    $envs = @(Get-TRItems 'PpEnvironments' | Where-Object { -not (Test-TRTrue $_.IsDefault) })
    if (-not $envs.Count) { return New-TRCtl Pass 'There are no non-default environments.' }
    $bad = @($envs | Where-Object { $n = [string]$_.Name; -not @($pol | Where-Object { $_.EnvironmentType -eq 'AllEnvironments' -or ($_.EnvironmentType -eq 'OnlyEnvironments' -and @($_.Environments) -contains $n) -or ($_.EnvironmentType -eq 'ExceptEnvironments' -and @($_.Environments) -notcontains $n) }).Count })
    if ($bad.Count) { return New-TRCtl Fail ((Select-TRText $bad.Count '1 environment has no DLP policy: {1}.' '{0} environments have no DLP policy: {1}.') -f $bad.Count, (Join-TRList ($bad | ForEach-Object { $_.DisplayName }) 5)) (@($bad | ForEach-Object { New-TRAffected ([string]$_.DisplayName) ([string]$_.EnvironmentType) })) }
    New-TRCtl Pass ((Select-TRText $envs.Count 'The only other environment has a DLP policy.' 'All {0} other environments have a DLP policy.') -f $envs.Count)
}

Register-TRControl -Framework SCuBA -Id 'MS.POWERPLATFORM.3.1v1' -Level Shall -Title 'Tenant isolation is on' `
    -Needs 'PpTenantIsolation' `
    -Guidance 'Turn on Power Platform tenant isolation and allow only approved partner tenants.' `
    -Test {
    $t = Get-TRRawValue 'PpTenantIsolation'
    if (Test-TRFalse $t.IsDisabled) { return New-TRCtl Pass ('Tenant isolation is on ({0}).' -f (Format-TRN ([int]$t.Rules) 'allowed tenant rule')) }
    New-TRCtl Fail 'Tenant isolation is off.'
}

Register-TRControl -Framework SCuBA -Id 'MS.POWERPLATFORM.3.2v1' -Level Should -Title 'Inbound and outbound connections use an allow list' -ManualOnly `
    -Guidance 'Add an allow list of inbound and outbound tenant connections in the tenant isolation settings.'

Register-TRControl -Framework SCuBA -Id 'MS.POWERPLATFORM.4.1v1' -Level Shall -Title 'Content Security Policy is enforced' -ManualOnly `
    -Guidance 'Turn on and enforce Content Security Policy for model-driven and canvas apps in each environment''s privacy and security settings.'

Register-TRControl -Framework SCuBA -Id 'MS.POWERPLATFORM.5.1v1' -Level Should -Title 'Only admins create Power Pages sites' `
    -Needs 'PpTenantSettings' `
    -Guidance 'Restrict creating Power Pages sites to admins.' `
    -Test {
    if (Test-TRTrue (Get-TRV (Get-TRRawValue 'PpTenantSettings') 'disablePortalsCreationByNonAdminUsers')) { return New-TRCtl Pass 'Only admins can create Power Pages sites.' }
    New-TRCtl Fail 'Anyone can create Power Pages sites.'
}

Register-TRControl -Framework SCuBA -Id 'MS.POWERPLATFORM.6.1v1' -Level Should -Title 'Share with everyone is off' `
    -Needs 'PpTenantSettings' `
    -Guidance 'Turn off sharing canvas apps with everyone.' `
    -Test {
    if (Test-TRTrue (Get-TRV (Get-TRRawValue 'PpTenantSettings') 'DisableShareWithEveryone')) { return New-TRCtl Pass 'Share with everyone is off.' }
    New-TRCtl Fail 'Makers can share apps with everyone.'
}
