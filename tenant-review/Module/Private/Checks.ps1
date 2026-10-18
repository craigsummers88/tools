$script:TRCheckDefs = New-Object System.Collections.ArrayList

function Register-TRCheck {
    param(
        [string]$Id,
        [string]$Area,
        [string]$Category,
        [string]$Title,
        [ValidateSet('High', 'Medium', 'Low', 'Info')][string]$Severity,
        [double]$Effort = 0,
        [string[]]$Needs = @(),
        [string]$Recommendation,
        [string]$Reference,
        [scriptblock]$Test,
        [ValidateSet('Microsoft', 'Google', 'Any')][string]$Platform = 'Microsoft'
    )
    [void]$script:TRCheckDefs.Add([pscustomobject]@{
            Id = $Id; Area = $Area; Category = $Category; Title = $Title; Severity = $Severity; Effort = $Effort
            Needs = $Needs; Recommendation = $Recommendation; Reference = $Reference; Test = $Test; Platform = $Platform
        })
}

Register-TRCheck -Id 'IAM-01' -Area 'Identity' -Category 'Identity and access' -Severity High -Effort 6 `
    -Title 'Multi-factor authentication is enforced for all users' `
    -Needs 'SecurityDefaults', 'ConditionalAccessPolicies' `
    -Recommendation 'Enforce MFA for all users and all cloud apps with a Conditional Access policy (Entra ID P1) or enable security defaults where P1 is not licensed. Exclude only documented emergency access accounts.' `
    -Reference 'https://learn.microsoft.com/entra/identity/conditional-access/policy-all-users-mfa-strength' `
    -Test {
    $sd = Get-TRRawValue 'SecurityDefaults'
    if ($sd -and $sd.isEnabled -eq $true) { return New-TRResult Pass 'Security defaults are enabled.' }
    $enabled = @(Get-TRCaPolicies | Where-Object { (Test-TRCaAllUsers $_) -and (Test-TRCaMfa $_) })
    $full = @($enabled | Where-Object { Test-TRCaAllApps $_ })
    if ($full.Count) { return New-TRResult Pass ('Enforced by: ' + ((@($full | ForEach-Object { $_.displayName })) -join ', ')) }
    if ($enabled.Count) { return New-TRResult Warning ('MFA policies target all users but not all cloud apps: ' + ((@($enabled | ForEach-Object { $_.displayName })) -join ', ')) }
    $ro = @(Get-TRCaPolicies -State 'enabledForReportingButNotEnforced' | Where-Object { (Test-TRCaAllUsers $_) -and (Test-TRCaMfa $_) })
    if ($ro.Count) { return New-TRResult Fail ('Only report-only MFA policies exist: ' + ((@($ro | ForEach-Object { $_.displayName })) -join ', ')) }
    New-TRResult Fail 'Security defaults are off and no enabled Conditional Access policy requires MFA for all users.'
}

Register-TRCheck -Id 'IAM-02' -Area 'Identity' -Category 'Identity and access' -Severity High -Effort 2 `
    -Title 'Legacy authentication is blocked' `
    -Needs 'SecurityDefaults', 'ConditionalAccessPolicies' `
    -Recommendation 'Create a Conditional Access policy that blocks Exchange ActiveSync and other legacy clients for all users. Check sign-in logs for legacy clients first, then enforce.' `
    -Reference 'https://learn.microsoft.com/entra/identity/conditional-access/policy-block-legacy-authentication' `
    -Test {
    $sd = Get-TRRawValue 'SecurityDefaults'
    if ($sd -and $sd.isEnabled -eq $true) { return New-TRResult Pass 'Security defaults block legacy authentication.' }
    $p = @(Get-TRCaPolicies | Where-Object { (Test-TRCaAllUsers $_) -and (Test-TRCaLegacy $_) -and (Test-TRCaBlock $_) })
    if ($p.Count) { return New-TRResult Pass ('Blocked by: ' + ((@($p | ForEach-Object { $_.displayName })) -join ', ')) }
    $ro = @(Get-TRCaPolicies -State 'enabledForReportingButNotEnforced' | Where-Object { (Test-TRCaLegacy $_) -and (Test-TRCaBlock $_) })
    if ($ro.Count) { return New-TRResult Warning ('Legacy authentication block is in report-only mode: ' + ((@($ro | ForEach-Object { $_.displayName })) -join ', ')) }
    New-TRResult Fail 'No enabled policy blocks legacy authentication for all users.'
}

Register-TRCheck -Id 'IAM-03' -Area 'Identity' -Category 'Identity and access' -Severity High -Effort 1 `
    -Title 'MFA is enforced for administrator roles' `
    -Needs 'SecurityDefaults', 'ConditionalAccessPolicies' `
    -Recommendation 'Require MFA, ideally phishing-resistant MFA, for all privileged directory roles with a dedicated Conditional Access policy.' `
    -Reference 'https://learn.microsoft.com/entra/identity/conditional-access/policy-admin-phish-resistant-mfa' `
    -Test {
    $sd = Get-TRRawValue 'SecurityDefaults'
    if ($sd -and $sd.isEnabled -eq $true) { return New-TRResult Pass 'Security defaults require MFA for administrators.' }
    $p = @(Get-TRCaPolicies | Where-Object { (Test-TRCaTargetsAdmins $_) -and (Test-TRCaMfa $_) })
    if ($p.Count) { return New-TRResult Pass ('Covered by: ' + ((@($p | ForEach-Object { $_.displayName })) -join ', ')) }
    New-TRResult Fail 'No enabled policy requires MFA for administrator roles.'
}

Register-TRCheck -Id 'IAM-04' -Area 'Identity' -Category 'Identity and access' -Severity Medium -Effort 3 `
    -Title 'Administrators use phishing-resistant MFA' `
    -Needs 'ConditionalAccessPolicies' `
    -Recommendation 'Issue FIDO2 security keys, passkeys or Windows Hello for Business to administrators and require the built-in Phishing-resistant MFA authentication strength for admin roles.' `
    -Reference 'https://learn.microsoft.com/entra/identity/conditional-access/policy-admin-phish-resistant-mfa' `
    -Test {
    $p = @(Get-TRCaPolicies | Where-Object { (Test-TRCaTargetsAdmins $_) -and (Test-TRCaPhishResistant $_) })
    if ($p.Count) { return New-TRResult Pass ('Required by: ' + ((@($p | ForEach-Object { $_.displayName })) -join ', ')) }
    New-TRResult Warning 'No enabled policy requires phishing-resistant MFA for administrators.'
}

Register-TRCheck -Id 'IAM-05' -Area 'Identity' -Category 'Identity and access' -Severity High -Effort 4 `
    -Title 'Licensed users are registered for MFA' `
    -Needs 'Users', 'RegistrationDetails' `
    -Recommendation 'Run an MFA registration campaign and follow up with users who are not registered. Unregistered accounts can be registered by an attacker who has the password.' `
    -Reference 'https://learn.microsoft.com/entra/identity/authentication/how-to-mfa-registration-campaign' `
    -Test {
    $reg = Get-TRRegIndex
    $people = @(Get-TRPeople)
    if (-not $people.Count) { return New-TRResult Info 'No enabled licensed member users found.' }
    $missing = @($people | Where-Object { $r = $reg[[string]$_.id]; -not ($r -and $r.isMfaCapable -eq $true) })
    $pct = Get-TRPercent ($people.Count - $missing.Count) $people.Count
    $aff = foreach ($u in $missing) { $r = $reg[[string]$u.id]; New-TRAffected $u.userPrincipalName $(if ($r) { 'Methods: ' + ((@($r.methodsRegistered)) -join ', ') } else { 'No registration record' }) }
    $cur = '{0}% of {1} enabled licensed users are MFA capable ({2} not capable).' -f $pct, $people.Count, $missing.Count
    if ($missing.Count -eq 0) { return New-TRResult Pass $cur }
    if ($pct -ge 95) { return New-TRResult Warning $cur $aff }
    New-TRResult Fail $cur $aff
}

Register-TRCheck -Id 'IAM-06' -Area 'Identity' -Category 'Identity and access' -Severity High -Effort 1 `
    -Title 'All administrators are registered for MFA' `
    -Needs 'RoleAssignments', 'RegistrationDetails' `
    -Recommendation 'Register strong MFA methods for every account that holds an admin role before anything else. Remove roles from accounts that do not need them.' `
    -Reference 'https://learn.microsoft.com/entra/identity/role-based-access-control/best-practices' `
    -Test {
    $reg = Get-TRRegIndex
    $admins = @(Get-TRRoleRows | Where-Object { $_.PrincipalType -eq 'user' } | Group-Object PrincipalId)
    if (-not $admins.Count) { return New-TRResult Info 'No user accounts hold directory roles.' }
    $bad = foreach ($g in $admins) {
        $r = $reg[[string]$g.Name]
        if (-not ($r -and $r.isMfaCapable -eq $true)) { New-TRAffected $g.Group[0].PrincipalUpn ('Roles: ' + ((@($g.Group | ForEach-Object { $_.Role } | Select-Object -Unique)) -join ', ')) }
    }
    $bad = @($bad)
    if ($bad.Count) { return New-TRResult Fail ('Admin accounts not MFA capable: {0} of {1}.' -f $bad.Count, $admins.Count) $bad }
    New-TRResult Pass ('All {0} admin accounts are MFA capable.' -f $admins.Count)
}

Register-TRCheck -Id 'IAM-07' -Area 'Identity' -Category 'Identity and access' -Severity Medium -Effort 2 `
    -Title 'Weak MFA methods (SMS and voice) are disabled' `
    -Needs 'AuthMethodsPolicy' `
    -Recommendation 'Move users to Microsoft Authenticator or passkeys, then disable SMS and voice call in the authentication methods policy.' `
    -Reference 'https://learn.microsoft.com/entra/identity/authentication/concept-authentication-methods-manage' `
    -Test {
    $p = Get-TRRawValue 'AuthMethodsPolicy'
    $weak = @(@($p.authenticationMethodConfigurations) | Where-Object { $_.id -in @('Sms', 'Voice') -and $_.state -eq 'enabled' } | ForEach-Object { $_.id })
    if ($weak.Count) { return New-TRResult Warning ('Enabled: ' + ($weak -join ', ')) }
    New-TRResult Pass 'SMS and voice call are disabled.'
}

Register-TRCheck -Id 'IAM-08' -Area 'Identity' -Category 'Identity and access' -Severity Low -Effort 1 `
    -Title 'Strong authentication methods are enabled' `
    -Needs 'AuthMethodsPolicy' `
    -Recommendation 'Enable Microsoft Authenticator and passkeys (FIDO2) in the authentication methods policy, and enable the registration campaign to nudge users onto Authenticator.' `
    -Reference 'https://learn.microsoft.com/entra/identity/authentication/how-to-mfa-registration-campaign' `
    -Test {
    $p = Get-TRRawValue 'AuthMethodsPolicy'
    $cfg = @{}
    foreach ($c in @($p.authenticationMethodConfigurations)) { if ($c) { $cfg[[string]$c.id] = [string]$c.state } }
    $missing = @()
    if ($cfg['MicrosoftAuthenticator'] -ne 'enabled') { $missing += 'Microsoft Authenticator' }
    if ($cfg['Fido2'] -ne 'enabled') { $missing += 'Passkeys (FIDO2)' }
    $campaign = [string]$p.registrationEnforcement.authenticationMethodsRegistrationCampaign.state
    $cur = 'Authenticator: {0}; FIDO2: {1}; Registration campaign: {2}' -f $cfg['MicrosoftAuthenticator'], $cfg['Fido2'], $campaign
    if ($missing.Count -eq 0 -and $campaign -in @('enabled', 'default')) { return New-TRResult Pass $cur }
    New-TRResult Warning $cur
}

Register-TRCheck -Id 'IAM-09' -Area 'Identity' -Category 'Identity and access' -Severity Medium -Effort 3 `
    -Title 'Risk-based Conditional Access policies are in place' `
    -Needs 'ConditionalAccessPolicies', 'SubscribedSkus' `
    -Recommendation 'With Entra ID P2, require MFA for medium and high sign-in risk and a secure password change for high user risk.' `
    -Reference 'https://learn.microsoft.com/entra/identity/conditional-access/policy-risk-based-user' `
    -Test {
    if (-not (Test-TRLicensed P2)) { return New-TRResult Info 'Entra ID P2 is not licensed, so risk-based policies are not available.' }
    $user = @(Get-TRCaPolicies | Where-Object { @($_.conditions.userRiskLevels).Count -gt 0 })
    $sign = @(Get-TRCaPolicies | Where-Object { @($_.conditions.signInRiskLevels).Count -gt 0 })
    $cur = 'User risk policies: {0}; Sign-in risk policies: {1}' -f $user.Count, $sign.Count
    if ($user.Count -and $sign.Count) { return New-TRResult Pass $cur }
    New-TRResult Fail $cur
}

Register-TRCheck -Id 'IAM-10' -Area 'Identity' -Category 'Identity and access' -Severity Medium -Effort 2 `
    -Title 'Emergency access accounts are excluded from Conditional Access' `
    -Needs 'ConditionalAccessPolicies', 'Users' `
    -Recommendation 'Maintain two cloud-only emergency access accounts with phishing-resistant credentials, exclude them from blocking policies, and alert on their use.' `
    -Reference 'https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access' `
    -Test {
    $enforcing = @(Get-TRCaPolicies | Where-Object { (Test-TRCaAllUsers $_) -and ((Test-TRCaMfa $_) -or (Test-TRCaBlock $_)) })
    if (-not $enforcing.Count) { return New-TRResult Info 'No enabled all-user MFA or block policies to evaluate.' }
    $common = $null
    foreach ($p in $enforcing) {
        $ex = @($p.conditions.users.excludeUsers)
        if ($null -eq $common) { $common = $ex } else { $common = @($common | Where-Object { $ex -contains $_ }) }
    }
    $idx = Get-TRUserIndex
    $aff = foreach ($id in @($common)) { $u = $idx[[string]$id]; New-TRAffected $(if ($u) { $u.userPrincipalName } else { $id }) 'Excluded from every enforcing all-user policy' }
    $aff = @($aff)
    if ($aff.Count -eq 0) { return New-TRResult Warning 'No account is excluded from all enforcing policies. Confirm an emergency access process exists.' }
    if ($aff.Count -gt 3) { return New-TRResult Warning ('Accounts excluded from every enforcing policy: {0}. Review that each is a genuine emergency access account.' -f $aff.Count) $aff }
    New-TRResult Pass ('Accounts excluded from every enforcing policy: {0}. Confirm these are emergency access accounts.' -f $aff.Count) $aff
}

Register-TRCheck -Id 'IAM-11' -Area 'Identity' -Category 'Identity and access' -Severity Medium -Effort 4 `
    -Title 'Conditional Access requires compliant or managed devices' `
    -Needs 'ConditionalAccessPolicies', 'SubscribedSkus' `
    -Recommendation 'Once Intune compliance policies are in place, require a compliant or hybrid-joined device for access to Microsoft 365 on desktops, and app protection on mobile.' `
    -Reference 'https://learn.microsoft.com/entra/identity/conditional-access/policy-all-users-device-compliance' `
    -Test {
    if (-not (Test-TRLicensed P1)) { return New-TRResult Info 'Entra ID P1 is not licensed.' }
    $p = @(Get-TRCaPolicies | Where-Object { $c = @($_.grantControls.builtInControls); ($c -contains 'compliantDevice') -or ($c -contains 'domainJoinedDevice') -or ($c -contains 'approvedApplication') -or ($c -contains 'compliantApplication') })
    if ($p.Count) { return New-TRResult Pass ('Device or app controls in: ' + ((@($p | ForEach-Object { $_.displayName })) -join ', ')) }
    New-TRResult Warning 'No enabled policy requires a compliant device, hybrid-joined device or protected app.'
}

Register-TRCheck -Id 'IAM-12' -Area 'Identity' -Category 'Identity and access' -Severity Low -Effort 1 `
    -Title 'Report-only and disabled Conditional Access policies' `
    -Needs 'ConditionalAccessPolicies' `
    -Recommendation 'Review report-only policies with the sign-in log impact data, then enable or remove them. Delete disabled policies that are no longer needed.' `
    -Reference 'https://learn.microsoft.com/entra/identity/conditional-access/concept-conditional-access-report-only' `
    -Test {
    $ro = @(Get-TRCaPolicies -State 'enabledForReportingButNotEnforced')
    $off = @(Get-TRCaPolicies -State 'disabled')
    $aff = @(@($ro | ForEach-Object { New-TRAffected $_.displayName 'Report-only' }) + @($off | ForEach-Object { New-TRAffected $_.displayName 'Disabled' }))
    $cur = 'Enabled: {0}; Report-only: {1}; Disabled: {2}' -f @(Get-TRCaPolicies).Count, $ro.Count, $off.Count
    if ($ro.Count) { return New-TRResult Warning $cur $aff }
    New-TRResult Info $cur $aff
}

Register-TRCheck -Id 'IAM-13' -Area 'Identity' -Category 'Identity and access' -Severity High -Effort 1 `
    -Title 'Users cannot consent to applications' `
    -Needs 'AuthorizationPolicy' `
    -Recommendation 'Set user consent to "Do not allow" or "Allow for verified publishers, for selected low-impact permissions", and turn on the admin consent workflow.' `
    -Reference 'https://learn.microsoft.com/entra/identity/enterprise-apps/configure-user-consent' `
    -Test {
    $a = Get-TRRawValue 'AuthorizationPolicy'
    $pols = @($a.defaultUserRolePermissions.permissionGrantPoliciesAssigned)
    $legacy = @($pols | Where-Object { $_ -match 'microsoft-user-default-legacy' })
    $low = @($pols | Where-Object { $_ -match 'microsoft-user-default-low' })
    if ($legacy.Count) { return New-TRResult Fail 'Users can consent to any application for any delegated permission.' }
    if ($low.Count) { return New-TRResult Pass 'Users can consent only to verified publishers for low-impact permissions.' }
    New-TRResult Pass 'User consent is disabled.'
}

Register-TRCheck -Id 'IAM-14' -Area 'Identity' -Category 'Identity and access' -Severity Low -Effort 1 `
    -Title 'Admin consent workflow is enabled' `
    -Needs 'AdminConsentPolicy' `
    -Recommendation 'Enable the admin consent workflow so users can request apps rather than work around the block.' `
    -Reference 'https://learn.microsoft.com/entra/identity/enterprise-apps/configure-admin-consent-workflow' `
    -Test {
    $p = Get-TRRawValue 'AdminConsentPolicy'
    if ($p.isEnabled -eq $true) { return New-TRResult Pass 'Admin consent workflow is enabled.' }
    New-TRResult Warning 'Admin consent workflow is disabled.'
}

Register-TRCheck -Id 'IAM-15' -Area 'Identity' -Category 'Identity and access' -Severity Medium -Effort 0.5 `
    -Title 'Users cannot register applications or create tenants' `
    -Needs 'AuthorizationPolicy' `
    -Recommendation 'Set "Users can register applications" and "Restrict non-admin users from creating tenants" so only administrators can do these.' `
    -Reference 'https://learn.microsoft.com/entra/fundamentals/users-default-permissions' `
    -Test {
    $d = (Get-TRRawValue 'AuthorizationPolicy').defaultUserRolePermissions
    $issues = @()
    if ($d.allowedToCreateApps -eq $true) { $issues += 'Users can register applications' }
    if ($d.allowedToCreateTenants -eq $true) { $issues += 'Users can create tenants' }
    if ($d.allowedToCreateSecurityGroups -eq $true) { $issues += 'Users can create security groups' }
    if ($issues.Count -eq 0) { return New-TRResult Pass 'Application registration, tenant and security group creation are restricted.' }
    if ($issues -contains 'Users can register applications' -or $issues -contains 'Users can create tenants') { return New-TRResult Warning ($issues -join '; ') }
    New-TRResult Info ($issues -join '; ')
}

Register-TRCheck -Id 'IAM-16' -Area 'Identity' -Category 'Identity and access' -Severity Medium -Effort 0.5 `
    -Title 'Guest invitations are restricted' `
    -Needs 'AuthorizationPolicy' `
    -Recommendation 'Limit guest invitations to admins and users in the Guest Inviter role, or to members only, in line with the client''s collaboration needs.' `
    -Reference 'https://learn.microsoft.com/entra/external-id/external-collaboration-settings-configure' `
    -Test {
    $v = [string](Get-TRRawValue 'AuthorizationPolicy').allowInvitesFrom
    switch ($v) {
        'everyone' { return New-TRResult Fail 'Anyone in the organisation, including guests, can invite guests.' }
        'adminsGuestInvitersAndAllMembers' { return New-TRResult Warning 'All member users can invite guests.' }
        'adminsAndGuestInviters' { return New-TRResult Pass 'Only admins and Guest Inviters can invite guests.' }
        'none' { return New-TRResult Pass 'Guest invitations are disabled.' }
    }
    New-TRResult Info ('Setting: ' + $v)
}

Register-TRCheck -Id 'IAM-17' -Area 'Identity' -Category 'Identity and access' -Severity Medium -Effort 0.5 `
    -Title 'Guest user access to the directory is restricted' `
    -Needs 'AuthorizationPolicy' `
    -Recommendation 'Set guest user access to "Guest user access is restricted to properties and memberships of their own directory objects".' `
    -Reference 'https://learn.microsoft.com/entra/identity/users/users-restrict-guest-permissions' `
    -Test {
    $v = [string](Get-TRRawValue 'AuthorizationPolicy').guestUserRoleId
    switch ($v) {
        '2af84b1e-32c8-42b7-82bc-daa82404023b' { return New-TRResult Pass 'Most restrictive guest access is configured.' }
        '10dae51f-b6af-4016-8d66-8c2a99b929b3' { return New-TRResult Warning 'Default limited guest access. Guests can see membership of non-hidden groups.' }
        'a0b1b346-4d3e-4e8b-98f8-753987be4970' { return New-TRResult Fail 'Guests have the same directory access as members.' }
    }
    New-TRResult Info ('Guest role: ' + $v)
}

Register-TRCheck -Id 'IAM-18' -Area 'Identity' -Category 'Identity and access' -Severity Low -Effort 0.5 `
    -Title 'Self-service sign-up is disabled' `
    -Needs 'AuthorizationPolicy' `
    -Recommendation 'Disable email-verified self-service sign-up and self-service subscription sign-up to stop unmanaged accounts and trials appearing in the tenant.' `
    -Reference 'https://learn.microsoft.com/entra/identity/users/directory-self-service-signup' `
    -Test {
    $a = Get-TRRawValue 'AuthorizationPolicy'
    $issues = @()
    if ($a.allowEmailVerifiedUsersToJoinOrganization -eq $true) { $issues += 'Email-verified users can join the organisation' }
    if ($a.allowedToSignUpEmailBasedSubscriptions -eq $true) { $issues += 'Users can sign up for email-based subscriptions' }
    if ($issues.Count) { return New-TRResult Warning ($issues -join '; ') }
    New-TRResult Pass 'Self-service sign-up is disabled.'
}

Register-TRCheck -Id 'IAM-19' -Area 'Identity' -Category 'Identity and access' -Severity Low -Effort 0.5 `
    -Title 'Passwords are set not to expire' `
    -Needs 'Domains' `
    -Recommendation 'With MFA enforced, set passwords to never expire in line with NCSC and Microsoft guidance. Forced rotation encourages weak, predictable passwords.' `
    -Reference 'https://learn.microsoft.com/microsoft-365/admin/misc/password-policy-recommendations' `
    -Test {
    $exp = @(Get-TRItems 'Domains' | Where-Object { $_.isVerified -and $_.authenticationType -eq 'Managed' -and $_.passwordValidityPeriodInDays -and [int64]$_.passwordValidityPeriodInDays -lt 2147483647 })
    if ($exp.Count) { return New-TRResult Warning 'Password expiry is configured on one or more domains.' @($exp | ForEach-Object { New-TRAffected $_.id ('Expires every {0} days' -f $_.passwordValidityPeriodInDays) }) }
    New-TRResult Pass 'Passwords are set to never expire.'
}

Register-TRCheck -Id 'IAM-20' -Area 'Identity' -Category 'Identity and access' -Severity Medium -Effort 3 `
    -Title 'No inactive enabled user accounts' `
    -Needs 'Users' `
    -Recommendation 'Confirm leavers with the client, then block sign-in, remove licences and convert or delete accounts that have not signed in within the inactivity window.' `
    -Reference 'https://learn.microsoft.com/entra/identity/monitoring-health/howto-manage-inactive-user-accounts' `
    -Test {
    if (-not (Get-TRMeta 'SignInActivity')) { return New-TRResult NotAssessed 'Sign-in activity is not available (requires Entra ID P1 and AuditLog.Read.All).' }
    $days = [int](Get-TRSetting 'InactiveDays' 90)
    $res = Get-TRResourceAccountIds
    $stale = foreach ($u in (Get-TRItems 'Users')) {
        if ($u.userType -ne 'Member' -or $u.accountEnabled -ne $true -or $res.ContainsKey([string]$u.id)) { continue }
        $last = ConvertTo-TRDate $u.signInActivity.lastSignInDateTime
        $lastNi = ConvertTo-TRDate $u.signInActivity.lastNonInteractiveSignInDateTime
        if ($lastNi -and (-not $last -or $lastNi -gt $last)) { $last = $lastNi }
        $created = ConvertTo-TRDate $u.createdDateTime
        if ($null -eq $last) {
            if ($created -and ((Get-TRNow) - $created).TotalDays -gt $days) { New-TRAffected $u.userPrincipalName ('Never signed in; created ' + (Format-TRDate $created) + '; licences: ' + (Get-TRUserLicenceNames $u)) }
        }
        elseif (((Get-TRNow) - $last).TotalDays -gt $days) {
            New-TRAffected $u.userPrincipalName ('Last sign-in ' + (Format-TRDate $last) + '; licences: ' + (Get-TRUserLicenceNames $u))
        }
    }
    $stale = @($stale)
    if ($stale.Count) { return New-TRResult Warning ('Enabled member accounts not signed in for {1}+ days: {0}.' -f $stale.Count, $days) $stale }
    New-TRResult Pass ('No enabled member account is inactive for more than {0} days.' -f $days)
}

Register-TRCheck -Id 'IAM-21' -Area 'Identity' -Category 'Identity and access' -Severity Low -Effort 1 `
    -Title 'No inactive guest accounts' `
    -Needs 'Users' `
    -Recommendation 'Remove guests who have not signed in within the inactivity window, or put an Entra access review in place for guests.' `
    -Reference 'https://learn.microsoft.com/entra/id-governance/access-reviews-overview' `
    -Test {
    $guests = @(Get-TRItems 'Users' | Where-Object { $_.userType -eq 'Guest' })
    if (-not $guests.Count) { return New-TRResult Pass 'No guest accounts.' }
    if (-not (Get-TRMeta 'SignInActivity')) { return New-TRResult Info ('Guest accounts: {0}. Sign-in activity is not available to assess inactivity.' -f $guests.Count) }
    $days = [int](Get-TRSetting 'InactiveDays' 90)
    $stale = foreach ($u in $guests) {
        $last = ConvertTo-TRDate $u.signInActivity.lastSignInDateTime
        $created = ConvertTo-TRDate $u.createdDateTime
        if (($null -eq $last -and $created -and ((Get-TRNow) - $created).TotalDays -gt $days) -or ($last -and ((Get-TRNow) - $last).TotalDays -gt $days)) {
            New-TRAffected $(if ($u.mail) { $u.mail } else { $u.userPrincipalName }) $(if ($last) { 'Last sign-in ' + (Format-TRDate $last) } else { 'Never signed in; invited ' + (Format-TRDate $created) })
        }
    }
    $stale = @($stale)
    $cur = 'Guest accounts: {0}; inactive for {2}+ days: {1}.' -f $guests.Count, $stale.Count, $days
    if ($stale.Count) { return New-TRResult Warning $cur $stale }
    New-TRResult Pass $cur
}

Register-TRCheck -Id 'IAM-22' -Area 'Identity' -Category 'Identity and access' -Severity High -Effort 2 `
    -Title 'Directory synchronisation is healthy' `
    -Needs 'Organization' `
    -Recommendation 'Investigate the Entra Connect or Cloud Sync server. A stalled sync means leavers disabled on-premises keep cloud access.' `
    -Reference 'https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-health-sync' `
    -Test {
    $o = Get-TRRawValue 'Organization'
    if ($o.onPremisesSyncEnabled -ne $true) { return New-TRResult Info 'Cloud-only tenant. Directory synchronisation is not enabled.' }
    $last = ConvertTo-TRDate $o.onPremisesLastSyncDateTime
    if ($null -eq $last) { return New-TRResult Warning 'Synchronisation is enabled but no last sync time is recorded.' }
    $hours = [Math]::Round(((Get-TRNow) - $last).TotalHours, 1)
    $cur = 'Last sync {0} ({1} hours ago).' -f (Format-TRDate $last -WithTime), $hours
    if ($hours -gt 24) { return New-TRResult Fail $cur }
    if ($hours -gt 3) { return New-TRResult Warning $cur }
    New-TRResult Pass $cur
}

Register-TRCheck -Id 'IAM-23' -Area 'Identity' -Category 'Identity and access' -Severity High -Effort 2 `
    -Title 'No users are flagged as at risk' `
    -Needs 'SubscribedSkus' `
    -Recommendation 'Investigate each risky user in Entra ID Protection, reset credentials and revoke sessions where compromise is confirmed, then dismiss or confirm the risk.' `
    -Reference 'https://learn.microsoft.com/entra/id-protection/howto-identity-protection-investigate-risk' `
    -Test {
    if (-not (Test-TRLicensed P2)) { return New-TRResult Info 'Entra ID P2 is not licensed, so risky user detection is not available.' }
    if (-not (Test-TRCollected @('RiskyUsers'))) { return New-TRResult NotAssessed (Get-TRMissingReason @('RiskyUsers')) }
    $r = @(Get-TRItems 'RiskyUsers')
    if ($r.Count) { return New-TRResult Fail ('Users currently at risk: {0}.' -f $r.Count) @($r | ForEach-Object { New-TRAffected $_.userPrincipalName ('Risk level ' + $_.riskLevel + '; updated ' + (Format-TRDate $_.riskLastUpdatedDateTime)) }) }
    New-TRResult Pass 'No users are currently at risk.'
}

Register-TRCheck -Id 'IAM-24' -Area 'Identity' -Category 'Identity and access' -Severity Low -Effort 2 `
    -Title 'No stale devices in Entra ID' `
    -Needs 'Devices' `
    -Recommendation 'Disable, then delete, devices that have not signed in for the stale window, after checking for BitLocker and LAPS recovery needs.' `
    -Reference 'https://learn.microsoft.com/entra/identity/devices/manage-stale-devices' `
    -Test {
    $days = [int](Get-TRSetting 'StaleDeviceDays' 180)
    $all = @(Get-TRItems 'Devices')
    $stale = @($all | Where-Object { $d = Get-TRDaysSince $_.approximateLastSignInDateTime; $null -ne $d -and $d -gt $days })
    $cur = 'Devices not signed in for {2}+ days: {0} of {1}.' -f $stale.Count, $all.Count, $days
    if ($stale.Count) { return New-TRResult Warning $cur @($stale | ForEach-Object { New-TRAffected $_.displayName ('{0} {1}; last sign-in {2}' -f $_.operatingSystem, $_.trustType, (Format-TRDate $_.approximateLastSignInDateTime)) }) }
    New-TRResult Pass $cur
}

Register-TRCheck -Id 'IAM-25' -Area 'Identity' -Category 'Identity and access' -Severity Medium -Effort 2 `
    -Title 'Windows LAPS is enabled' `
    -Needs 'DeviceRegistrationPolicy' `
    -Recommendation 'Enable Windows LAPS in Entra device settings and deploy an Intune LAPS policy so local administrator passwords are unique and rotated.' `
    -Reference 'https://learn.microsoft.com/entra/identity/devices/howto-manage-local-admin-passwords' `
    -Test {
    $p = Get-TRRawValue 'DeviceRegistrationPolicy'
    if ($p.localAdminPassword.isEnabled -eq $true) { return New-TRResult Pass 'Microsoft Entra LAPS is enabled.' }
    New-TRResult Warning 'Microsoft Entra LAPS is not enabled in device settings.'
}

Register-TRCheck -Id 'PRV-01' -Area 'Identity' -Category 'Privileged access' -Severity Medium -Effort 1 `
    -Title 'Between two and four Global Administrators' `
    -Needs 'RoleAssignments' `
    -Recommendation 'Keep at least two (including emergency access) and no more than four Global Administrators. Move day-to-day admin work to least-privileged roles.' `
    -Reference 'https://learn.microsoft.com/entra/identity/role-based-access-control/best-practices' `
    -Test {
    $ga = @(Get-TRRoleRows | Where-Object { $_.RoleTemplate -eq '62e90394-69f5-4237-9190-012177145e10' })
    $principals = @($ga | Group-Object PrincipalId)
    $aff = @($principals | ForEach-Object { New-TRAffected $_.Group[0].PrincipalUpn ('{0} ({1})' -f $_.Group[0].PrincipalType, ((@($_.Group | ForEach-Object { $_.Assignment } | Select-Object -Unique)) -join ', ')) })
    $n = $principals.Count
    if ($n -gt 4) { return New-TRResult Fail ('Global Administrators: {0}.' -f $n) $aff }
    if ($n -lt 2) { return New-TRResult Warning ('Global Administrators: {0}. Keep at least two so access is not lost with a single account.' -f $n) $aff }
    New-TRResult Pass ('Global Administrators: {0}.' -f $n) $aff
}

Register-TRCheck -Id 'PRV-02' -Area 'Identity' -Category 'Privileged access' -Severity High -Effort 0.5 `
    -Title 'No guest accounts hold admin roles' `
    -Needs 'RoleAssignments', 'Users' `
    -Recommendation 'Remove admin roles from guest accounts. Partner access should use GDAP, not guest accounts with roles.' `
    -Reference 'https://learn.microsoft.com/partner-center/customers/gdap-introduction' `
    -Test {
    $idx = Get-TRUserIndex
    $bad = @(Get-TRRoleRows | Where-Object { $_.PrincipalType -eq 'user' -and $idx[$_.PrincipalId] -and $idx[$_.PrincipalId].userType -eq 'Guest' })
    if ($bad.Count) { return New-TRResult Fail ('Admin role assignments held by guests: {0}.' -f $bad.Count) @($bad | ForEach-Object { New-TRAffected $_.PrincipalUpn $_.Role }) }
    New-TRResult Pass 'No guest accounts hold admin roles.'
}

Register-TRCheck -Id 'PRV-03' -Area 'Identity' -Category 'Privileged access' -Severity Medium -Effort 2 `
    -Title 'Privileged accounts are cloud-only' `
    -Needs 'RoleAssignments', 'Users' `
    -Recommendation 'Use cloud-only accounts for privileged roles so an on-premises compromise cannot take over the tenant.' `
    -Reference 'https://learn.microsoft.com/entra/architecture/protect-m365-from-on-premises-attacks' `
    -Test {
    $idx = Get-TRUserIndex
    $bad = @(Get-TRRoleRows | Where-Object { $_.Privileged -and $_.PrincipalType -eq 'user' -and $idx[$_.PrincipalId] -and $idx[$_.PrincipalId].onPremisesSyncEnabled -eq $true })
    if ($bad.Count) { return New-TRResult Warning ('Privileged role assignments held by synced accounts: {0}.' -f $bad.Count) @($bad | ForEach-Object { New-TRAffected $_.PrincipalUpn $_.Role }) }
    New-TRResult Pass 'All privileged role holders are cloud-only accounts.'
}

Register-TRCheck -Id 'PRV-04' -Area 'Identity' -Category 'Privileged access' -Severity Low -Effort 3 `
    -Title 'Admins use separate accounts from daily email accounts' `
    -Needs 'RoleAssignments', 'Users' `
    -Recommendation 'Give administrators a separate unlicensed admin account and remove admin roles from their mailbox-enabled daily accounts.' `
    -Reference 'https://learn.microsoft.com/microsoft-365/admin/add-users/about-admin-roles' `
    -Test {
    $idx = Get-TRUserIndex
    $bad = @(Get-TRRoleRows | Where-Object { $_.Privileged -and $_.PrincipalType -eq 'user' -and $idx[$_.PrincipalId] -and @($idx[$_.PrincipalId].assignedLicenses).Count -gt 0 } | Group-Object PrincipalId)
    if ($bad.Count) { return New-TRResult Warning ('Licensed privileged accounts, likely used for daily work: {0}.' -f $bad.Count) @($bad | ForEach-Object { New-TRAffected $_.Group[0].PrincipalUpn ('Roles: ' + ((@($_.Group | ForEach-Object { $_.Role } | Select-Object -Unique)) -join ', ') + '; licences: ' + (Get-TRUserLicenceNames $idx[$_.Name])) }) }
    New-TRResult Pass 'Privileged accounts are unlicensed admin accounts.'
}

Register-TRCheck -Id 'PRV-05' -Area 'Identity' -Category 'Privileged access' -Severity Low -Effort 4 `
    -Title 'Privileged Identity Management is used' `
    -Needs 'RoleAssignments', 'SubscribedSkus' `
    -Recommendation 'With Entra ID P2, make privileged roles eligible rather than permanent and require approval or justification to activate.' `
    -Reference 'https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-configure' `
    -Test {
    if (-not (Test-TRLicensed P2)) { return New-TRResult Info 'Entra ID P2 is not licensed.' }
    $rows = @(Get-TRRoleRows | Where-Object { $_.Privileged -and $_.PrincipalType -eq 'user' })
    $eligible = @($rows | Where-Object { $_.Assignment -eq 'Eligible' })
    $active = @($rows | Where-Object { $_.Assignment -eq 'Active' })
    $cur = 'Eligible privileged assignments: {0}; permanent active: {1}' -f $eligible.Count, $active.Count
    if ($eligible.Count -eq 0) { return New-TRResult Warning $cur }
    New-TRResult Pass $cur
}

Register-TRCheck -Id 'PRV-06' -Area 'Identity' -Category 'Privileged access' -Severity Medium -Effort 1 `
    -Title 'Service principals with privileged directory roles' `
    -Needs 'RoleAssignments' `
    -Recommendation 'Confirm each application that holds a privileged directory role is known and still required. Replace with least-privileged Graph permissions where possible.' `
    -Reference 'https://learn.microsoft.com/entra/identity/role-based-access-control/best-practices' `
    -Test {
    $sp = @(Get-TRRoleRows | Where-Object { $_.Privileged -and $_.PrincipalType -eq 'servicePrincipal' })
    if ($sp.Count) { return New-TRResult Warning ('Privileged role assignments held by applications: {0}.' -f $sp.Count) @($sp | ForEach-Object { New-TRAffected $_.PrincipalName $_.Role }) }
    New-TRResult Pass 'No applications hold privileged directory roles.'
}

$script:TRRiskyAppPermissions = @('Mail.ReadWrite', 'Mail.Read', 'Mail.Send', 'MailboxSettings.ReadWrite', 'Files.ReadWrite.All', 'Files.Read.All', 'Sites.ReadWrite.All', 'Sites.FullControl.All', 'Sites.Read.All', 'Directory.ReadWrite.All', 'RoleManagement.ReadWrite.Directory', 'AppRoleAssignment.ReadWrite.All', 'Application.ReadWrite.All', 'User.ReadWrite.All', 'Group.ReadWrite.All', 'GroupMember.ReadWrite.All', 'Policy.ReadWrite.ConditionalAccess', 'UserAuthenticationMethod.ReadWrite.All', 'Domain.ReadWrite.All', 'full_access_as_app', 'Exchange.ManageAsApp', 'Exchange.ManageAsAppV2', 'Calendars.ReadWrite', 'Chat.Read.All', 'ChannelMessage.Read.All', 'DeviceManagementConfiguration.ReadWrite.All', 'DeviceManagementManagedDevices.PrivilegedOperations.All')
$script:TRRiskyDelegatedScopes = @('Mail.ReadWrite', 'Mail.Read', 'Mail.Send', 'Mail.ReadWrite.Shared', 'Mail.Send.Shared', 'Files.ReadWrite.All', 'Files.Read.All', 'Sites.ReadWrite.All', 'Sites.FullControl.All', 'Directory.ReadWrite.All', 'Directory.AccessAsUser.All', 'full_access_as_user', 'EWS.AccessAsUser.All', 'User.ReadWrite.All', 'Group.ReadWrite.All', 'RoleManagement.ReadWrite.Directory', 'Application.ReadWrite.All', 'MailboxSettings.ReadWrite', 'Calendars.ReadWrite', 'Contacts.ReadWrite', 'Chat.ReadWrite', 'IMAP.AccessAsUser.All', 'POP.AccessAsUser.All', 'SMTP.Send')

function Get-TRSpIndex {
    Get-TRCached 'SpIndex' {
        $h = @{}
        foreach ($s in (Get-TRItems 'ServicePrincipals')) { $h[[string]$s.id] = $s }
        $h
    }
}

function Get-TRSpOwner {
    param($Sp)
    if (-not $Sp) { return 'Unknown' }
    $owner = [string]$Sp.appOwnerOrganizationId
    if ($script:TRMicrosoftTenants -contains $owner) { return 'Microsoft' }
    if ($owner -and $owner -eq [string](Get-TRMeta 'TenantId')) { return 'Internal' }
    if ([string]$Sp.servicePrincipalType -eq 'ManagedIdentity') { return 'Managed identity' }
    'Third party'
}

Register-TRCheck -Id 'APP-01' -Area 'Applications' -Category 'Applications' -Severity High -Effort 3 `
    -Title 'High-risk application permissions are reviewed' `
    -Needs 'AppPermissions', 'ServicePrincipals' `
    -Recommendation 'Review each non-Microsoft application holding high-impact application permissions (mail, files, directory write). Remove apps that are unused or unknown and reduce permissions where possible.' `
    -Reference 'https://learn.microsoft.com/entra/identity/enterprise-apps/manage-application-permissions' `
    -Test {
    $sps = Get-TRSpIndex
    $risky = @(Get-TRItems 'AppPermissions' | Where-Object { $script:TRRiskyAppPermissions -contains [string]$_.Permission -and (Get-TRSpOwner $sps[[string]$_.ClientId]) -ne 'Microsoft' })
    if (-not $risky.Count) { return New-TRResult Pass 'No non-Microsoft application holds high-risk application permissions.' }
    $groups = @($risky | Group-Object ClientId)
    $aff = @($groups | ForEach-Object { $sp = $sps[[string]$_.Name]; New-TRAffected $_.Group[0].ClientName ((Get-TRSpOwner $sp) + ': ' + ((@($_.Group | ForEach-Object { $_.Permission } | Select-Object -Unique)) -join ', ')) })
    New-TRResult Warning ('Applications with high-risk application permissions: {0}.' -f $groups.Count) $aff
}

Register-TRCheck -Id 'APP-02' -Area 'Applications' -Category 'Applications' -Severity Medium -Effort 2 `
    -Title 'Tenant-wide delegated consents are reviewed' `
    -Needs 'OAuth2Grants', 'ServicePrincipals' `
    -Recommendation 'Review admin-consented (all users) delegated permissions to non-Microsoft apps, particularly mail and file access, and revoke anything not required.' `
    -Reference 'https://learn.microsoft.com/entra/identity/enterprise-apps/manage-application-permissions' `
    -Test {
    $sps = Get-TRSpIndex
    $aff = foreach ($g in (Get-TRItems 'OAuth2Grants')) {
        if ($g.consentType -ne 'AllPrincipals') { continue }
        $sp = $sps[[string]$g.clientId]
        if ((Get-TRSpOwner $sp) -eq 'Microsoft') { continue }
        $scopes = @(([string]$g.scope).Trim() -split '\s+' | Where-Object { $_ })
        $hit = @($scopes | Where-Object { $script:TRRiskyDelegatedScopes -contains $_ })
        if ($hit.Count) { New-TRAffected $(if ($sp) { $sp.displayName } else { $g.clientId }) ($hit -join ', ') }
    }
    $aff = @($aff)
    if ($aff.Count) { return New-TRResult Warning ('Non-Microsoft apps with tenant-wide consent to high-impact delegated permissions: {0}.' -f $aff.Count) $aff }
    New-TRResult Pass 'No tenant-wide high-impact delegated consents to non-Microsoft apps.'
}

Register-TRCheck -Id 'APP-03' -Area 'Applications' -Category 'Applications' -Severity Medium -Effort 2 `
    -Title 'User-consented applications are reviewed' `
    -Needs 'OAuth2Grants', 'ServicePrincipals', 'Users' `
    -Recommendation 'Review applications individual users have consented to with mail, file or offline access. These are a common route for consent phishing.' `
    -Reference 'https://learn.microsoft.com/entra/identity/enterprise-apps/investigate-risky-oauth-app' `
    -Test {
    $sps = Get-TRSpIndex
    $idx = Get-TRUserIndex
    $aff = foreach ($g in (Get-TRItems 'OAuth2Grants')) {
        if ($g.consentType -ne 'Principal') { continue }
        $sp = $sps[[string]$g.clientId]
        if ((Get-TRSpOwner $sp) -eq 'Microsoft') { continue }
        $scopes = @(([string]$g.scope).Trim() -split '\s+' | Where-Object { $_ })
        $hit = @($scopes | Where-Object { $script:TRRiskyDelegatedScopes -contains $_ })
        if ($hit.Count) {
            $u = $idx[[string]$g.principalId]
            New-TRAffected $(if ($sp) { $sp.displayName } else { $g.clientId }) ('User: {0}; scopes: {1}' -f $(if ($u) { $u.userPrincipalName } else { $g.principalId }), ($hit -join ', '))
        }
    }
    $aff = @($aff)
    if ($aff.Count) { return New-TRResult Warning ('User consents granting high-impact access to non-Microsoft apps: {0}.' -f $aff.Count) $aff }
    New-TRResult Pass 'No user consents grant high-impact access to non-Microsoft apps.'
}

Register-TRCheck -Id 'APP-04' -Area 'Applications' -Category 'Applications' -Severity Low -Effort 1 `
    -Title 'App registration credentials are current' `
    -Needs 'Applications' `
    -Recommendation 'Renew credentials expiring in the next 30 days, remove expired secrets and certificates, and prefer certificates or managed identities over client secrets.' `
    -Reference 'https://learn.microsoft.com/entra/identity-platform/how-to-add-credentials' `
    -Test {
    $now = (Get-TRNow)
    $aff = foreach ($a in (Get-TRItems 'Applications')) {
        foreach ($set in @(@{ T = 'Secret'; L = $a.passwordCredentials }, @{ T = 'Certificate'; L = $a.keyCredentials })) {
            foreach ($c in @($set.L)) {
                if (-not $c) { continue }
                $end = ConvertTo-TRDate $c.endDateTime
                if (-not $end) { continue }
                $days = [int]($end - $now).TotalDays
                if ($days -lt 0) { New-TRAffected $a.displayName ('{0} expired {1}' -f $set.T, (Format-TRDate $end)) }
                elseif ($days -le 30) { New-TRAffected $a.displayName ('{0} expires {1}' -f $set.T, (Format-TRDate $end)) }
            }
        }
    }
    $aff = @($aff)
    if ($aff.Count) { return New-TRResult Warning ('Credentials expired or expiring within 30 days: {0}.' -f $aff.Count) $aff }
    New-TRResult Pass 'No app credentials are expired or close to expiry.'
}

Register-TRCheck -Id 'APP-05' -Area 'Applications' -Category 'Applications' -Severity Low -Effort 0 `
    -Title 'Third-party application inventory' `
    -Needs 'ServicePrincipals' `
    -Recommendation 'Use the Applications inventory to confirm with the client which third-party apps are in use and remove the rest.' `
    -Reference 'https://learn.microsoft.com/entra/identity/enterprise-apps/view-applications-portal' `
    -Test {
    $all = @(Get-TRItems 'ServicePrincipals')
    $third = @($all | Where-Object { (Get-TRSpOwner $_) -eq 'Third party' })
    $internal = @($all | Where-Object { (Get-TRSpOwner $_) -eq 'Internal' })
    New-TRResult Info ('Enterprise applications: {0} ({1} third party, {2} internal, {3} Microsoft or other).' -f $all.Count, $third.Count, $internal.Count, ($all.Count - $third.Count - $internal.Count))
}

Register-TRCheck -Id 'LIC-01' -Area 'Licensing' -Category 'Licensing' -Severity Low -Effort 0.5 `
    -Title 'Unassigned paid licences' `
    -Needs 'SubscribedSkus' `
    -Recommendation 'Reduce subscription quantities at the next renewal, or assign the spare licences to users who need them.' `
    -Reference 'https://learn.microsoft.com/microsoft-365/commerce/licenses/buy-licenses' `
    -Test {
    $aff = foreach ($s in (Get-TRItems 'SubscribedSkus')) {
        $pn = [string]$s.skuPartNumber
        if ($script:TRFreeSkus -contains $pn) { continue }
        $enabled = [int]$s.prepaidUnits.enabled
        if ($enabled -ge 10000) { continue }
        $spare = $enabled - [int]$s.consumedUnits
        if ($spare -gt 0) { New-TRAffected (Get-TRSkuName $pn) ('{0} spare of {1}' -f $spare, $enabled) }
    }
    $aff = @($aff)
    if ($aff.Count) { return New-TRResult Warning ('Products with unassigned licences: {0}.' -f $aff.Count) $aff }
    New-TRResult Pass 'All paid licences are assigned.'
}

Register-TRCheck -Id 'LIC-02' -Area 'Licensing' -Category 'Licensing' -Severity Low -Effort 1 `
    -Title 'No licences assigned to disabled accounts' `
    -Needs 'Users', 'SubscribedSkus' `
    -Recommendation 'Remove licences from blocked accounts, or convert leavers to shared mailboxes where the mailbox must be kept and is under 50 GB.' `
    -Reference 'https://learn.microsoft.com/microsoft-365/admin/add-users/remove-former-employee' `
    -Test {
    $bad = @(Get-TRItems 'Users' | Where-Object { $_.accountEnabled -ne $true -and @($_.assignedLicenses).Count -gt 0 })
    if ($bad.Count) { return New-TRResult Warning ('Disabled accounts holding licences: {0}.' -f $bad.Count) @($bad | ForEach-Object { New-TRAffected $_.userPrincipalName (Get-TRUserLicenceNames $_) }) }
    New-TRResult Pass 'No disabled accounts hold licences.'
}

Register-TRCheck -Id 'LIC-03' -Area 'Licensing' -Category 'Licensing' -Severity Medium -Effort 0.5 `
    -Title 'Subscriptions are in good standing' `
    -Needs 'SubscribedSkus' `
    -Recommendation 'Renew or remove subscriptions in a warning or suspended state before services are switched off.' `
    -Reference 'https://learn.microsoft.com/microsoft-365/commerce/subscriptions/what-if-my-subscription-expires' `
    -Test {
    $bad = @(Get-TRItems 'SubscribedSkus' | Where-Object { $_.capabilityStatus -in @('Warning', 'Suspended', 'LockedOut') -or [int]$_.prepaidUnits.warning -gt 0 -or [int]$_.prepaidUnits.suspended -gt 0 })
    if ($bad.Count) { return New-TRResult Warning ('Subscriptions needing attention: {0}.' -f $bad.Count) @($bad | ForEach-Object { New-TRAffected (Get-TRSkuName $_.skuPartNumber) ('Status {0}; warning units {1}; suspended units {2}' -f $_.capabilityStatus, $_.prepaidUnits.warning, $_.prepaidUnits.suspended) }) }
    New-TRResult Pass 'All subscriptions are active.'
}

Register-TRCheck -Id 'LIC-04' -Area 'Licensing' -Category 'Licensing' -Severity Low -Effort 0.5 `
    -Title 'Shared and resource mailboxes are not licensed unnecessarily' `
    -Needs 'Users', 'ExoMailboxes' `
    -Recommendation 'Remove licences from shared and resource mailboxes unless they need more than 50 GB, an archive or a hold.' `
    -Reference 'https://learn.microsoft.com/microsoft-365/admin/email/about-shared-mailboxes' `
    -Test {
    $res = Get-TRResourceAccountIds
    $mbx = @{}
    foreach ($m in (Get-TRItems 'ExoMailboxes')) { if ($m.ExternalDirectoryObjectId) { $mbx[[string]$m.ExternalDirectoryObjectId] = $m } }
    $bad = @(Get-TRItems 'Users' | Where-Object { $res.ContainsKey([string]$_.id) -and @($_.assignedLicenses).Count -gt 0 })
    $bad = @($bad | Where-Object { $m = $mbx[[string]$_.id]; -not ($m -and ($m.LitigationHoldEnabled -eq $true -or [string]$m.ArchiveStatus -eq 'Active')) })
    if ($bad.Count) { return New-TRResult Warning ('Shared or resource mailboxes licensed without an obvious need: {0}.' -f $bad.Count) @($bad | ForEach-Object { New-TRAffected $_.userPrincipalName (Get-TRUserLicenceNames $_) }) }
    New-TRResult Pass 'No unnecessary licences on shared or resource mailboxes.'
}

Register-TRCheck -Id 'LIC-05' -Area 'Licensing' -Category 'Licensing' -Severity Info -Effort 0 `
    -Title 'Security feature licensing' `
    -Needs 'SubscribedSkus' `
    -Recommendation 'Use this to scope recommendations. Business Premium or E3 with add-ons unlocks Conditional Access, Intune and Defender for Office 365.' `
    -Reference 'https://learn.microsoft.com/office365/servicedescriptions/microsoft-365-service-descriptions/microsoft-365-business-service-description' `
    -Test {
    $parts = @(
        ('Entra ID P1: ' + $(if (Test-TRLicensed P1) { 'Yes' } else { 'No' }))
        ('Entra ID P2: ' + $(if (Test-TRLicensed P2) { 'Yes' } else { 'No' }))
        ('Intune: ' + $(if (Test-TRLicensed Intune) { 'Yes' } else { 'No' }))
        ('Defender for Office 365: ' + $(if (Test-TRLicensed DefenderO365P2) { 'Plan 2' } elseif (Test-TRLicensed DefenderO365) { 'Plan 1' } else { 'No' }))
        ('Defender for Endpoint or Business: ' + $(if (Test-TRLicensed DefenderEndpoint) { 'Yes' } else { 'No' }))
    )
    New-TRResult Info ($parts -join '; ')
}

Register-TRCheck -Id 'EXO-01' -Area 'Exchange' -Category 'Exchange Online' -Severity High -Effort 0.5 `
    -Title 'Unified audit logging is enabled' `
    -Needs 'ExoAdminAuditLogConfig' `
    -Recommendation 'Turn on audit log ingestion so user and admin activity is recorded for investigations.' `
    -Reference 'https://learn.microsoft.com/purview/audit-log-enable-disable' `
    -Test {
    $c = Get-TRRawValue 'ExoAdminAuditLogConfig'
    if ($c.UnifiedAuditLogIngestionEnabled -eq $true) { return New-TRResult Pass 'Unified audit log ingestion is enabled.' }
    New-TRResult Fail 'Unified audit log ingestion is disabled.'
}

Register-TRCheck -Id 'EXO-02' -Area 'Exchange' -Category 'Exchange Online' -Severity High -Effort 0.5 `
    -Title 'Mailbox auditing is on by default' `
    -Needs 'ExoOrganizationConfig' `
    -Recommendation 'Ensure AuditDisabled is False on the organisation configuration so mailbox actions are logged.' `
    -Reference 'https://learn.microsoft.com/purview/audit-mailboxes' `
    -Test {
    $c = Get-TRRawValue 'ExoOrganizationConfig'
    if ($c.AuditDisabled -eq $true) { return New-TRResult Fail 'Mailbox auditing is disabled for the organisation.' }
    $off = @(Get-TRItems 'ExoMailboxes' | Where-Object { $_.AuditEnabled -eq $false -and $_.RecipientTypeDetails -match 'UserMailbox|SharedMailbox' })
    if ($off.Count) { return New-TRResult Warning ('Auditing is on by default but disabled on {0} mailboxes.' -f $off.Count) @($off | ForEach-Object { New-TRAffected $_.PrimarySmtpAddress $_.RecipientTypeDetails }) }
    New-TRResult Pass 'Mailbox auditing is on by default.'
}

Register-TRCheck -Id 'EXO-03' -Area 'Exchange' -Category 'Exchange Online' -Severity Medium -Effort 0.5 `
    -Title 'Modern authentication is enabled for Exchange Online' `
    -Needs 'ExoOrganizationConfig' `
    -Recommendation 'Enable OAuth2ClientProfileEnabled so Outlook uses modern authentication and MFA can apply.' `
    -Reference 'https://learn.microsoft.com/exchange/clients-and-mobile-in-exchange-online/enable-or-disable-modern-authentication-in-exchange-online' `
    -Test {
    $c = Get-TRRawValue 'ExoOrganizationConfig'
    if ($c.OAuth2ClientProfileEnabled -eq $false) { return New-TRResult Fail 'Modern authentication is disabled.' }
    New-TRResult Pass 'Modern authentication is enabled.'
}

Register-TRCheck -Id 'EXO-04' -Area 'Exchange' -Category 'Exchange Online' -Severity Medium -Effort 2 `
    -Title 'SMTP AUTH client submission is disabled' `
    -Needs 'ExoTransportConfig' `
    -Recommendation 'Disable SMTP AUTH at organisation level and allow it only on specific mailboxes used by devices or apps that cannot use modern methods. Plan moves to high volume email or a relay connector.' `
    -Reference 'https://learn.microsoft.com/exchange/clients-and-mobile-in-exchange-online/authenticated-client-smtp-submission' `
    -Test {
    $t = Get-TRRawValue 'ExoTransportConfig'
    $ex = @(Get-TRItems 'ExoCasMailboxes' | Where-Object { $_.SmtpClientAuthenticationEnabled -eq $true })
    $aff = @($ex | ForEach-Object { New-TRAffected $_.PrimarySmtpAddress 'SMTP AUTH enabled on mailbox' })
    if ($t.SmtpClientAuthenticationDisabled -ne $true) { return New-TRResult Fail 'SMTP AUTH is enabled for the whole organisation.' $aff }
    if ($ex.Count) { return New-TRResult Info ('Disabled at organisation level, enabled on {0} mailboxes.' -f $ex.Count) $aff }
    New-TRResult Pass 'SMTP AUTH is disabled.'
}

Register-TRCheck -Id 'EXO-05' -Area 'Exchange' -Category 'Exchange Online' -Severity High -Effort 1 `
    -Title 'Automatic forwarding to external recipients is blocked' `
    -Needs 'ExoOutboundSpamPolicies' `
    -Recommendation 'Set AutoForwardingMode to Off (or Automatic) on the default outbound spam policy and allow forwarding only through scoped custom policies for named users.' `
    -Reference 'https://learn.microsoft.com/defender-office-365/outbound-spam-policies-external-email-forwarding' `
    -Test {
    $pols = @(Get-TRItems 'ExoOutboundSpamPolicies')
    $on = @($pols | Where-Object { $_.AutoForwardingMode -eq 'On' })
    $aff = @($on | ForEach-Object { New-TRAffected $_.Name $(if ($_.IsDefault) { 'Default policy' } else { 'Custom policy' }) })
    if (@($on | Where-Object { $_.IsDefault }).Count) { return New-TRResult Fail 'External automatic forwarding is allowed by the default policy.' $aff }
    if ($on.Count) { return New-TRResult Warning ('External forwarding allowed by {0} custom policies. Confirm the scoping is intended.' -f $on.Count) $aff }
    New-TRResult Pass 'External automatic forwarding is blocked.'
}

Register-TRCheck -Id 'EXO-06' -Area 'Exchange' -Category 'Exchange Online' -Severity High -Effort 1 `
    -Title 'Mailbox forwarding is reviewed' `
    -Needs 'ExoMailboxes', 'Domains' `
    -Recommendation 'Confirm every mailbox forward is authorised, particularly to external addresses. Unexpected forwarding is a common sign of a compromised account.' `
    -Reference 'https://learn.microsoft.com/defender-office-365/outbound-spam-policies-external-email-forwarding' `
    -Test {
    $domains = @(Get-TRItems 'Domains' | ForEach-Object { ([string]$_.id).ToLower() })
    $fwd = @(Get-TRItems 'ExoMailboxes' | Where-Object { $_.ForwardingSmtpAddress -or $_.ForwardingAddress })
    if (-not $fwd.Count) { return New-TRResult Pass 'No mailboxes forward mail.' }
    $external = 0
    $aff = foreach ($m in $fwd) {
        $target = if ($m.ForwardingSmtpAddress) { ([string]$m.ForwardingSmtpAddress) -replace '^smtp:', '' } else { [string]$m.ForwardingAddress }
        $isExt = $false
        if ($target -match '@(.+)$') { $isExt = -not ($domains -contains $Matches[1].ToLower()) }
        if ($isExt) { $external++ }
        New-TRAffected $m.PrimarySmtpAddress ('Forwards to {0}{1}{2}' -f $target, $(if ($isExt) { ' (external)' } else { '' }), $(if ($m.DeliverToMailboxAndForward) { '; keeps a copy' } else { '; no copy kept' }))
    }
    $cur = 'Mailboxes forwarding mail: {0} ({1} to external addresses).' -f $fwd.Count, $external
    if ($external) { return New-TRResult Fail $cur $aff }
    New-TRResult Warning $cur $aff
}

Register-TRCheck -Id 'EXO-07' -Area 'Exchange' -Category 'Exchange Online' -Severity Medium -Effort 2 `
    -Title 'Mail flow rules do not weaken security' `
    -Needs 'ExoTransportRules' `
    -Recommendation 'Review rules that bypass spam filtering (SCL -1) or copy or redirect mail. Replace sender allow rules with Tenant Allow/Block List entries or connectors scoped by IP.' `
    -Reference 'https://learn.microsoft.com/exchange/security-and-compliance/mail-flow-rules/mail-flow-rules' `
    -Test {
    $aff = foreach ($r in (Get-TRItems 'ExoTransportRules')) {
        $issues = @()
        if ([string]$r.SetSCL -eq '-1') { $issues += 'bypasses spam filtering' }
        if (@($r.RedirectMessageTo).Count -and $r.RedirectMessageTo) { $issues += ('redirects to ' + (@($r.RedirectMessageTo) -join ', ')) }
        if (@($r.BlindCopyTo).Count -and $r.BlindCopyTo) { $issues += ('BCCs ' + (@($r.BlindCopyTo) -join ', ')) }
        if (@($r.AddToRecipients).Count -and $r.AddToRecipients) { $issues += ('adds recipients ' + (@($r.AddToRecipients) -join ', ')) }
        if (@($r.CopyTo).Count -and $r.CopyTo) { $issues += ('copies to ' + (@($r.CopyTo) -join ', ')) }
        if ($issues.Count) { New-TRAffected $r.Name ('{0}: {1}' -f $r.State, ($issues -join '; ')) }
    }
    $aff = @($aff)
    $total = @(Get-TRItems 'ExoTransportRules').Count
    if ($aff.Count) { return New-TRResult Warning ('Mail flow rules that bypass filtering or copy or redirect mail: {0} of {1}.' -f $aff.Count, $total) $aff }
    New-TRResult Pass ('Mail flow rules: {0}. None bypass filtering or redirect mail.' -f $total)
}

Register-TRCheck -Id 'EXO-08' -Area 'Exchange' -Category 'Exchange Online' -Severity Medium -Effort 1 `
    -Title 'Anti-spam policies do not allow whole sender domains' `
    -Needs 'ExoContentFilterPolicies' `
    -Recommendation 'Remove allowed sender domains and addresses from anti-spam policies. Spoofed mail from these domains skips filtering. Use the Tenant Allow/Block List for genuine false positives.' `
    -Reference 'https://learn.microsoft.com/defender-office-365/create-safe-sender-lists-in-office-365' `
    -Test {
    $aff = foreach ($p in (Get-TRItems 'ExoContentFilterPolicies')) {
        $d = @($p.AllowedSenderDomains | Where-Object { $_ })
        $s = @($p.AllowedSenders | Where-Object { $_ })
        if ($d.Count -or $s.Count) { New-TRAffected $p.Name ('Allowed domains: {0}; allowed senders: {1}' -f ($d -join ', '), ($s -join ', ')) }
    }
    $aff = @($aff)
    if ($aff.Count) { return New-TRResult Warning 'Anti-spam policies contain allowed senders or domains.' $aff }
    New-TRResult Pass 'No allowed sender lists in anti-spam policies.'
}

Register-TRCheck -Id 'EXO-09' -Area 'Exchange' -Category 'Exchange Online' -Severity Medium -Effort 2 `
    -Title 'Anti-phishing protection is configured' `
    -Needs 'ExoAntiPhishPolicies', 'SubscribedSkus' `
    -Recommendation 'Enable spoof intelligence, first contact safety tips and honour DMARC policy. With Defender for Office 365, add impersonation protection for executives and the client''s domains and turn on mailbox intelligence.' `
    -Reference 'https://learn.microsoft.com/defender-office-365/anti-phishing-policies-about' `
    -Test {
    $pols = @(Get-TRItems 'ExoAntiPhishPolicies' | Where-Object { $_.Enabled -ne $false })
    if (-not $pols.Count) { return New-TRResult Fail 'No enabled anti-phishing policy.' }
    $best = $pols | Sort-Object { [int]($_.EnableTargetedUserProtection -eq $true) + [int]($_.EnableOrganizationDomainsProtection -eq $true) + [int]($_.EnableMailboxIntelligenceProtection -eq $true) } -Descending | Select-Object -First 1
    $gaps = @()
    if ($best.EnableSpoofIntelligence -ne $true) { $gaps += 'spoof intelligence off' }
    if ($best.EnableFirstContactSafetyTips -ne $true) { $gaps += 'first contact safety tips off' }
    if ($best.HonorDmarcPolicy -eq $false) { $gaps += 'DMARC policy not honoured' }
    if (Test-TRLicensed DefenderO365) {
        if ($best.EnableTargetedUserProtection -ne $true) { $gaps += 'user impersonation protection off' }
        if ($best.EnableOrganizationDomainsProtection -ne $true) { $gaps += 'domain impersonation protection off' }
        if ($best.EnableMailboxIntelligenceProtection -ne $true) { $gaps += 'mailbox intelligence protection off' }
    }
    $cur = 'Strongest policy: {0}' -f $best.Name
    if ($gaps.Count) { return New-TRResult Warning ($cur + '; gaps: ' + ($gaps -join ', ')) }
    New-TRResult Pass ($cur + '; key protections enabled.')
}

Register-TRCheck -Id 'EXO-10' -Area 'Exchange' -Category 'Exchange Online' -Severity Medium -Effort 2 `
    -Title 'Safe Links protects email, Teams and Office apps' `
    -Needs 'SubscribedSkus' `
    -Recommendation 'Apply the Standard preset security policy, or a custom Safe Links policy for all users covering email, Teams and Office apps with click tracking and no click-through.' `
    -Reference 'https://learn.microsoft.com/defender-office-365/safe-links-about' `
    -Test {
    if (-not (Test-TRLicensed DefenderO365)) { return New-TRResult Info 'Defender for Office 365 is not licensed.' }
    if (-not (Test-TRCollected @('ExoSafeLinksPolicies'))) { return New-TRResult NotAssessed (Get-TRMissingReason @('ExoSafeLinksPolicies')) }
    $preset = @(@(Get-TRItems 'ExoPresetAtp') | Where-Object { $_.State -eq 'Enabled' })
    if ($preset.Count) { return New-TRResult Pass ('Preset policy enabled: ' + ((@($preset | ForEach-Object { $_.Name })) -join ', ')) }
    $enabledRules = @(Get-TRItems 'ExoSafeLinksRules' | Where-Object { $_.State -eq 'Enabled' } | ForEach-Object { [string]$_.SafeLinksPolicy })
    $pols = @(Get-TRItems 'ExoSafeLinksPolicies' | Where-Object { $enabledRules -contains [string]$_.Name -or $enabledRules -contains [string]$_.Identity })
    if (-not $pols.Count) { return New-TRResult Warning 'Only Built-in protection applies. No custom Safe Links policy is enabled.' }
    $p = $pols[0]
    $gaps = @()
    if ($p.EnableSafeLinksForEmail -ne $true) { $gaps += 'email' }
    if ($p.EnableSafeLinksForTeams -ne $true) { $gaps += 'Teams' }
    if ($p.EnableSafeLinksForOffice -ne $true) { $gaps += 'Office apps' }
    if ($p.AllowClickThrough -eq $true) { $gaps += 'click-through allowed' }
    if ($gaps.Count) { return New-TRResult Warning ('{0}: gaps in {1}' -f $p.Name, ($gaps -join ', ')) }
    New-TRResult Pass ('{0} covers email, Teams and Office apps.' -f $p.Name)
}

Register-TRCheck -Id 'EXO-11' -Area 'Exchange' -Category 'Exchange Online' -Severity Medium -Effort 1 `
    -Title 'Safe Attachments is enabled' `
    -Needs 'SubscribedSkus' `
    -Recommendation 'Apply the Standard preset policy or a Safe Attachments policy with the Block action for all users, and enable Safe Attachments for SharePoint, OneDrive and Teams.' `
    -Reference 'https://learn.microsoft.com/defender-office-365/safe-attachments-about' `
    -Test {
    if (-not (Test-TRLicensed DefenderO365)) { return New-TRResult Info 'Defender for Office 365 is not licensed.' }
    if (-not (Test-TRCollected @('ExoSafeAttachmentPolicies'))) { return New-TRResult NotAssessed (Get-TRMissingReason @('ExoSafeAttachmentPolicies')) }
    $atp = Get-TRRawValue 'ExoAtpPolicy'
    $preset = @(@(Get-TRItems 'ExoPresetAtp') | Where-Object { $_.State -eq 'Enabled' })
    $spo = if ($atp -and $atp.EnableATPForSPOTeamsODB -eq $true) { 'on' } else { 'off' }
    if ($preset.Count) {
        if ($spo -eq 'on') { return New-TRResult Pass 'Preset policy enabled; SharePoint, OneDrive and Teams protection on.' }
        return New-TRResult Warning 'Preset policy enabled, but Safe Attachments for SharePoint, OneDrive and Teams is off.'
    }
    $enabledRules = @(Get-TRItems 'ExoSafeAttachmentRules' | Where-Object { $_.State -eq 'Enabled' } | ForEach-Object { [string]$_.SafeAttachmentPolicy })
    $pols = @(Get-TRItems 'ExoSafeAttachmentPolicies' | Where-Object { ($enabledRules -contains [string]$_.Name -or $enabledRules -contains [string]$_.Identity) -and $_.Enable -eq $true })
    if (-not $pols.Count) { return New-TRResult Warning ('No custom Safe Attachments policy is enabled. SharePoint, OneDrive and Teams protection: {0}.' -f $spo) }
    if ($spo -ne 'on') { return New-TRResult Warning ('{0} is enabled, but SharePoint, OneDrive and Teams protection is off.' -f $pols[0].Name) }
    New-TRResult Pass ('{0} enabled with action {1}; SharePoint, OneDrive and Teams protection on.' -f $pols[0].Name, $pols[0].Action)
}

Register-TRCheck -Id 'EXO-12' -Area 'Exchange' -Category 'Exchange Online' -Severity Medium -Effort 0.5 `
    -Title 'Anti-malware common attachment filter and ZAP are on' `
    -Needs 'ExoMalwarePolicies' `
    -Recommendation 'Enable the common attachments filter and zero-hour auto purge on the default anti-malware policy.' `
    -Reference 'https://learn.microsoft.com/defender-office-365/anti-malware-policies-configure' `
    -Test {
    $d = @(Get-TRItems 'ExoMalwarePolicies' | Where-Object { $_.IsDefault }) | Select-Object -First 1
    if (-not $d) { $d = @(Get-TRItems 'ExoMalwarePolicies') | Select-Object -First 1 }
    $gaps = @()
    if ($d.EnableFileFilter -ne $true) { $gaps += 'common attachment filter off' }
    if ($d.ZapEnabled -eq $false) { $gaps += 'zero-hour auto purge off' }
    if ($gaps.Count) { return New-TRResult Fail ($d.Name + ': ' + ($gaps -join ', ')) }
    New-TRResult Pass ($d.Name + ': attachment filter and ZAP on.')
}

Register-TRCheck -Id 'EXO-13' -Area 'Exchange' -Category 'Exchange Online' -Severity Low -Effort 0.5 `
    -Title 'External sender tagging is enabled in Outlook' `
    -Needs 'ExoExternalInOutlook' `
    -Recommendation 'Run Set-ExternalInOutlook -Enabled $true so Outlook marks mail from outside the organisation.' `
    -Reference 'https://learn.microsoft.com/powershell/module/exchangepowershell/set-externalinoutlook' `
    -Test {
    $e = Get-TRRawValue 'ExoExternalInOutlook'
    if ($e.Enabled -eq $true) { return New-TRResult Pass 'External sender tagging is enabled.' }
    New-TRResult Warning 'External sender tagging is disabled.'
}

Register-TRCheck -Id 'EXO-14' -Area 'Exchange' -Category 'Exchange Online' -Severity Low -Effort 0.5 `
    -Title 'Calendar details are not shared anonymously' `
    -Needs 'ExoSharingPolicies' `
    -Recommendation 'Remove the Anonymous entry from the default sharing policy, or limit it to free/busy only.' `
    -Reference 'https://learn.microsoft.com/exchange/sharing/sharing-policies/sharing-policies' `
    -Test {
    $bad = @(Get-TRItems 'ExoSharingPolicies' | Where-Object { $_.Enabled -ne $false -and (@($_.Domains) -join ' ') -match 'Anonymous' })
    if ($bad.Count) { return New-TRResult Warning 'Anonymous calendar publishing is allowed.' @($bad | ForEach-Object { New-TRAffected $_.Name ((@($_.Domains)) -join '; ') }) }
    New-TRResult Pass 'Anonymous calendar sharing is not allowed.'
}

Register-TRCheck -Id 'EXO-15' -Area 'Exchange' -Category 'Exchange Online' -Severity Low -Effort 0.5 `
    -Title 'Outlook on the web third-party storage is disabled' `
    -Needs 'ExoOwaPolicies' `
    -Recommendation 'Set AdditionalStorageProvidersAvailable to False on OWA mailbox policies so users cannot attach files from personal storage such as Dropbox.' `
    -Reference 'https://learn.microsoft.com/powershell/module/exchangepowershell/set-owamailboxpolicy' `
    -Test {
    $bad = @(Get-TRItems 'ExoOwaPolicies' | Where-Object { $_.AdditionalStorageProvidersAvailable -eq $true })
    if ($bad.Count) { return New-TRResult Warning 'Third-party storage providers are available in Outlook on the web.' @($bad | ForEach-Object { New-TRAffected $_.Name 'AdditionalStorageProvidersAvailable is True' }) }
    New-TRResult Pass 'Third-party storage providers are disabled.'
}

Register-TRCheck -Id 'EXO-16' -Area 'Exchange' -Category 'Exchange Online' -Severity Medium -Effort 1 `
    -Title 'Sign-in is blocked for shared and resource mailboxes' `
    -Needs 'ExoMailboxes', 'Users' `
    -Recommendation 'Block sign-in on shared, room and equipment mailbox accounts. Access should come through mailbox permissions, not the account password.' `
    -Reference 'https://learn.microsoft.com/microsoft-365/admin/email/about-shared-mailboxes' `
    -Test {
    $idx = Get-TRUserIndex
    $bad = @(Get-TRItems 'ExoMailboxes' | Where-Object { $_.RecipientTypeDetails -match 'SharedMailbox|RoomMailbox|EquipmentMailbox' -and $_.ExternalDirectoryObjectId -and $idx[[string]$_.ExternalDirectoryObjectId] -and $idx[[string]$_.ExternalDirectoryObjectId].accountEnabled -eq $true })
    if ($bad.Count) { return New-TRResult Warning ('Shared or resource mailbox accounts that allow sign-in: {0}.' -f $bad.Count) @($bad | ForEach-Object { New-TRAffected $_.PrimarySmtpAddress $_.RecipientTypeDetails }) }
    New-TRResult Pass 'Sign-in is blocked for all shared and resource mailboxes.'
}

Register-TRCheck -Id 'EXO-17' -Area 'Exchange' -Category 'Exchange Online' -Severity Low -Effort 1 `
    -Title 'POP and IMAP are disabled where not needed' `
    -Needs 'ExoCasMailboxes' `
    -Recommendation 'Disable POP and IMAP on mailboxes and in the CAS mailbox plans so new mailboxes do not get them. Keep only documented exceptions.' `
    -Reference 'https://learn.microsoft.com/exchange/clients-and-mobile-in-exchange-online/pop3-and-imap4/enable-or-disable-pop3-or-imap4-access' `
    -Test {
    $all = @(Get-TRItems 'ExoCasMailboxes')
    $bad = @($all | Where-Object { $_.PopEnabled -eq $true -or $_.ImapEnabled -eq $true })
    $cur = 'Mailboxes with POP or IMAP enabled: {0} of {1}.' -f $bad.Count, $all.Count
    if ($bad.Count) { return New-TRResult Warning $cur @($bad | ForEach-Object { New-TRAffected $_.PrimarySmtpAddress ('POP {0}; IMAP {1}' -f $_.PopEnabled, $_.ImapEnabled) }) }
    New-TRResult Pass $cur
}

Register-TRCheck -Id 'EXO-18' -Area 'Exchange' -Category 'Exchange Online' -Severity Low -Effort 0.5 `
    -Title 'Users can report suspicious messages' `
    -Needs 'ExoReportSubmissionPolicy' `
    -Recommendation 'Keep the built-in Report button enabled and send reports to Microsoft and, ideally, a monitored reporting mailbox.' `
    -Reference 'https://learn.microsoft.com/defender-office-365/submissions-user-reported-messages-custom-mailbox' `
    -Test {
    $p = Get-TRRawValue 'ExoReportSubmissionPolicy'
    if ($p.EnableReportToMicrosoft -eq $true -or $p.ReportPhishToCustomizedAddress -eq $true) { return New-TRResult Pass ('Report to Microsoft: {0}; to custom mailbox: {1}' -f $p.EnableReportToMicrosoft, $p.ReportPhishToCustomizedAddress) }
    New-TRResult Warning 'User reported messages are not sent to Microsoft or a reporting mailbox.'
}

Register-TRCheck -Id 'EXO-19' -Area 'Exchange' -Category 'Exchange Online' -Severity Low -Effort 1 `
    -Title 'Mailboxes approaching their quota' `
    -Needs 'MailboxUsage' `
    -Recommendation 'Enable archiving or auto-expanding archiving, or apply retention to mailboxes above 90% of their send quota.' `
    -Reference 'https://learn.microsoft.com/purview/autoexpanding-archiving' `
    -Test {
    $aff = foreach ($m in (Get-TRItems 'MailboxUsage')) {
        $used = 0.0; $quota = 0.0
        [void][double]::TryParse([string]$m.'Storage Used (Byte)', [ref]$used)
        [void][double]::TryParse([string]$m.'Prohibit Send Quota (Byte)', [ref]$quota)
        if ($quota -gt 0 -and $used / $quota -ge 0.9) { New-TRAffected $m.'User Principal Name' ('{0:N1} GB of {1:N0} GB ({2:N0}%)' -f ($used / 1GB), ($quota / 1GB), (100 * $used / $quota)) }
    }
    $aff = @($aff)
    if ($aff.Count) { return New-TRResult Warning ('Mailboxes above 90% of quota: {0}.' -f $aff.Count) $aff }
    New-TRResult Pass 'No mailboxes are above 90% of quota.'
}

Register-TRCheck -Id 'EXO-20' -Area 'Exchange' -Category 'Exchange Online' -Severity Info -Effort 0 `
    -Title 'Mail connectors' `
    -Needs 'ExoInboundConnectors' `
    -Recommendation 'Confirm each connector is still needed. If mail is filtered by a third-party gateway before Microsoft 365, enable Enhanced Filtering for Connectors and lock down direct delivery.' `
    -Reference 'https://learn.microsoft.com/exchange/mail-flow-best-practices/use-connectors-to-configure-mail-flow/enhanced-filtering-for-connectors' `
    -Test {
    $in = @(Get-TRItems 'ExoInboundConnectors')
    $out = @(Get-TRItems 'ExoOutboundConnectors')
    $aff = @(@($in | ForEach-Object { New-TRAffected $_.Name ('Inbound {0}; enabled {1}; senders {2}' -f $_.ConnectorType, $_.Enabled, ((@($_.SenderDomains)) -join ', ')) }) + @($out | ForEach-Object { New-TRAffected $_.Name ('Outbound {0}; enabled {1}; smart hosts {2}' -f $_.ConnectorType, $_.Enabled, ((@($_.SmartHosts)) -join ', ')) }))
    New-TRResult Info ('Connectors: {0} inbound, {1} outbound.' -f $in.Count, $out.Count) $aff
}

function Get-TRMailDomains {
    @(Get-TRItems 'DnsRecords')
}

function Test-TRMicrosoftMx {
    param($Row)
    (@($Row.Mx) -join ' ') -match 'mail\.protection\.outlook\.com|mx\.microsoft'
}

Register-TRCheck -Id 'DNS-01' -Area 'Dns' -Category 'Email authentication' -Severity High -Effort 1 `
    -Title 'SPF records are valid' `
    -Needs 'DnsRecords' `
    -Recommendation 'Publish exactly one SPF record per domain that includes spf.protection.outlook.com and every other legitimate sender, ending in -all or ~all.' `
    -Reference 'https://learn.microsoft.com/defender-office-365/email-authentication-spf-configure' `
    -Test {
    $rows = @(Get-TRMailDomains | Where-Object { @($_.Mx).Count -gt 0 })
    if (-not $rows.Count) { return New-TRResult Info 'No custom domains receive mail.' }
    $aff = foreach ($r in $rows) {
        $spf = @($r.Spf)
        if ($spf.Count -eq 0) { New-TRAffected $r.Domain 'No SPF record'; continue }
        if ($spf.Count -gt 1) { New-TRAffected $r.Domain ('{0} SPF records (only one is allowed)' -f $spf.Count); continue }
        $s = [string]$spf[0]
        if ($s -match '[+?]all\b') { New-TRAffected $r.Domain ('Permissive qualifier: ' + $s); continue }
        if ($s -notmatch '[-~]all\b' -and $s -notmatch 'redirect=') { New-TRAffected $r.Domain ('No all mechanism: ' + $s); continue }
        if ((Test-TRMicrosoftMx $r) -and $s -notmatch 'spf\.protection\.outlook\.com') { New-TRAffected $r.Domain ('Does not include spf.protection.outlook.com: ' + $s) }
    }
    $aff = @($aff)
    if ($aff.Count) { return New-TRResult Fail ('Mail domains with SPF problems: {0} of {1}.' -f $aff.Count, $rows.Count) $aff }
    New-TRResult Pass ('All {0} mail domains have a valid SPF record.' -f $rows.Count)
}

Register-TRCheck -Id 'DNS-02' -Area 'Dns' -Category 'Email authentication' -Severity High -Effort 1 `
    -Title 'DKIM signing is enabled for every mail domain' `
    -Needs 'DnsRecords' `
    -Recommendation 'Publish the selector1 and selector2 CNAME records and enable DKIM signing in Defender for each custom domain.' `
    -Reference 'https://learn.microsoft.com/defender-office-365/email-authentication-dkim-configure' `
    -Test {
    $rows = @(Get-TRMailDomains | Where-Object { $_.SupportsEmail -or @($_.Mx).Count -gt 0 })
    if (-not $rows.Count) { return New-TRResult Info 'No custom email domains.' }
    $dkim = @{}
    $haveExo = Test-TRCollected @('ExoDkim')
    foreach ($d in (Get-TRItems 'ExoDkim')) { $dkim[([string]$d.Domain).ToLower()] = $d }
    $aff = foreach ($r in $rows) {
        $cfg = $dkim[([string]$r.Domain).ToLower()]
        $cn = (@($r.DkimSelector1).Count -gt 0) -and (@($r.DkimSelector2).Count -gt 0)
        if ($haveExo) {
            if (-not ($cfg -and $cfg.Enabled -eq $true)) { New-TRAffected $r.Domain ('Signing disabled; CNAMEs {0}' -f $(if ($cn) { 'present' } else { 'missing' })) }
        }
        elseif (-not $cn) { New-TRAffected $r.Domain 'Selector CNAME records missing' }
    }
    $aff = @($aff)
    if ($aff.Count) { return New-TRResult Fail ('Email domains not DKIM signing: {0} of {1}.' -f $aff.Count, $rows.Count) $aff }
    if (-not $haveExo) { return New-TRResult Warning 'Selector CNAMEs exist, but signing status could not be read from Exchange.' }
    New-TRResult Pass ('DKIM signing is enabled for all {0} email domains.' -f $rows.Count)
}

Register-TRCheck -Id 'DNS-03' -Area 'Dns' -Category 'Email authentication' -Severity High -Effort 1 `
    -Title 'DMARC is published and enforced' `
    -Needs 'DnsRecords' `
    -Recommendation 'Publish DMARC for every domain, start at p=none with reporting, then move to p=quarantine and p=reject once legitimate senders pass SPF or DKIM.' `
    -Reference 'https://learn.microsoft.com/defender-office-365/email-authentication-dmarc-configure' `
    -Test {
    $rows = @(Get-TRMailDomains)
    if (-not $rows.Count) { return New-TRResult Info 'No custom domains.' }
    $missing = 0; $none = 0
    $aff = foreach ($r in $rows) {
        $d = @($r.Dmarc)
        if ($d.Count -eq 0) { $missing++; New-TRAffected $r.Domain 'No DMARC record'; continue }
        $rec = [string]$d[0]
        $policy = if ($rec -match '(?:^|;)\s*p\s*=\s*(\w+)') { $Matches[1].ToLower() } else { '' }
        $pct = if ($rec -match 'pct\s*=\s*(\d+)') { [int]$Matches[1] } else { 100 }
        if ($policy -eq 'none' -or $policy -eq '') { $none++; New-TRAffected $r.Domain ('Monitoring only: ' + $rec) }
        elseif ($pct -lt 100) { $none++; New-TRAffected $r.Domain ('Applied to {0}% of mail: {1}' -f $pct, $rec) }
    }
    $aff = @($aff)
    if ($missing) { return New-TRResult Fail ('Domains without DMARC: {0}; not enforcing: {1}.' -f $missing, $none) $aff }
    if ($none) { return New-TRResult Warning ('Domains with DMARC in monitoring mode only: {0}.' -f $none) $aff }
    New-TRResult Pass ('All {0} domains enforce DMARC (quarantine or reject).' -f $rows.Count)
}

Register-TRCheck -Id 'DNS-04' -Area 'Dns' -Category 'Email authentication' -Severity Low -Effort 1 `
    -Title 'DMARC aggregate reporting is configured' `
    -Needs 'DnsRecords' `
    -Recommendation 'Add an rua= address (or a DMARC reporting service) so you can see who sends mail as the client''s domains before tightening policy.' `
    -Reference 'https://learn.microsoft.com/defender-office-365/email-authentication-dmarc-configure' `
    -Test {
    $rows = @(Get-TRMailDomains | Where-Object { @($_.Dmarc).Count -gt 0 })
    if (-not $rows.Count) { return New-TRResult Info 'No DMARC records to check.' }
    $bad = @($rows | Where-Object { [string](@($_.Dmarc)[0]) -notmatch 'rua\s*=' })
    if ($bad.Count) { return New-TRResult Warning ('DMARC records without an aggregate report address: {0}.' -f $bad.Count) @($bad | ForEach-Object { New-TRAffected $_.Domain ([string]@($_.Dmarc)[0]) }) }
    New-TRResult Pass 'All DMARC records include aggregate reporting.'
}

Register-TRCheck -Id 'DNS-05' -Area 'Dns' -Category 'Email authentication' -Severity Low -Effort 1 `
    -Title 'Domains that do not send mail are locked down' `
    -Needs 'DnsRecords' `
    -Recommendation 'For parked or non-mail domains publish v=spf1 -all and a DMARC record with p=reject so they cannot be spoofed.' `
    -Reference 'https://learn.microsoft.com/defender-office-365/email-authentication-spf-configure' `
    -Test {
    $rows = @(Get-TRMailDomains | Where-Object { @($_.Mx).Count -eq 0 })
    if (-not $rows.Count) { return New-TRResult Pass 'All custom domains receive mail.' }
    $aff = foreach ($r in $rows) {
        $spfOk = (@($r.Spf).Count -eq 1) -and ([string]@($r.Spf)[0] -match '^\s*v=spf1\s+-all\s*$')
        $dm = [string](@($r.Dmarc) | Select-Object -First 1)
        $dmOk = $dm -match 'p\s*=\s*reject'
        if (-not ($spfOk -and $dmOk)) { New-TRAffected $r.Domain ('Null SPF {0}; DMARC reject {1}' -f $(if ($spfOk) { 'yes' } else { 'no' }), $(if ($dmOk) { 'yes' } else { 'no' })) }
    }
    $aff = @($aff)
    if ($aff.Count) { return New-TRResult Warning ('Non-mail domains that could be spoofed: {0}.' -f $aff.Count) $aff }
    New-TRResult Pass 'Non-mail domains publish null SPF and DMARC reject.'
}

Register-TRCheck -Id 'DNS-06' -Area 'Dns' -Category 'Email authentication' -Severity Info -Effort 0 `
    -Title 'Mail routing (MX) and MTA-STS' `
    -Needs 'DnsRecords' `
    -Recommendation 'Confirm MX routing matches the intended design. Consider MTA-STS to enforce TLS for inbound mail.' `
    -Reference 'https://learn.microsoft.com/purview/enhancing-mail-flow-with-mta-sts' `
    -Test {
    $rows = @(Get-TRMailDomains)
    $aff = @($rows | ForEach-Object { New-TRAffected $_.Domain ('MX: {0}; route: {1}; MTA-STS: {2}{3}' -f $(if (@($_.Mx).Count) { (@($_.Mx)) -join ', ' } else { 'none' }), $(if (Test-TRMicrosoftMx $_) { 'Microsoft 365' } elseif (@($_.Mx).Count) { 'third party or on-premises' } else { 'none' }), $(if (@($_.MtaSts).Count) { 'yes' } else { 'no' }), $(if ($_.Errors) { '; lookup errors: ' + $_.Errors } else { '' })) })
    $third = @($rows | Where-Object { @($_.Mx).Count -and -not (Test-TRMicrosoftMx $_) })
    New-TRResult Info ('Custom domains: {0}; routed through a third party or on-premises system: {1}.' -f $rows.Count, $third.Count) $aff
}

Register-TRCheck -Id 'SPO-01' -Area 'Collaboration' -Category 'SharePoint and OneDrive' -Severity Medium -Effort 2 `
    -Title 'Anonymous (Anyone) sharing links are controlled' `
    -Needs 'SharePointSettings' `
    -Recommendation 'Restrict tenant sharing to "New and existing guests" unless Anyone links are a business need. If they are, set link expiry and view-only defaults and limit them to specific sites.' `
    -Reference 'https://learn.microsoft.com/sharepoint/turn-external-sharing-on-or-off' `
    -Test {
    $s = Get-TRRawValue 'SharePointSettings'
    switch ([string]$s.sharingCapability) {
        'externalUserAndGuestSharing' { return New-TRResult Warning 'Anyone links (no sign-in) are allowed at tenant level.' }
        'externalUserSharingOnly' { return New-TRResult Pass 'Sharing with new and existing guests who sign in.' }
        'existingExternalUserSharingOnly' { return New-TRResult Pass 'Sharing with existing guests only.' }
        'disabled' { return New-TRResult Pass 'External sharing is disabled.' }
    }
    New-TRResult Info ('Sharing capability: ' + $s.sharingCapability)
}

Register-TRCheck -Id 'SPO-02' -Area 'Collaboration' -Category 'SharePoint and OneDrive' -Severity Medium -Effort 0.5 `
    -Title 'Guests cannot reshare content they do not own' `
    -Needs 'SharePointSettings' `
    -Recommendation 'Turn off "Allow guests to share items they don''t own".' `
    -Reference 'https://learn.microsoft.com/sharepoint/turn-external-sharing-on-or-off' `
    -Test {
    $s = Get-TRRawValue 'SharePointSettings'
    if ([string]$s.sharingCapability -eq 'disabled') { return New-TRResult Pass 'External sharing is disabled.' }
    if ($s.isResharingByExternalUsersEnabled -eq $true) { return New-TRResult Warning 'Guests can reshare content they do not own.' }
    New-TRResult Pass 'Guests cannot reshare content.'
}

Register-TRCheck -Id 'SPO-03' -Area 'Collaboration' -Category 'SharePoint and OneDrive' -Severity Medium -Effort 0.5 `
    -Title 'Guests must sign in with the invited account' `
    -Needs 'SharePointSettings' `
    -Recommendation 'Require guests to accept sharing invitations with the same account the invitation was sent to.' `
    -Reference 'https://learn.microsoft.com/powershell/module/sharepoint-online/set-spotenant' `
    -Test {
    $s = Get-TRRawValue 'SharePointSettings'
    if ([string]$s.sharingCapability -eq 'disabled') { return New-TRResult Pass 'External sharing is disabled.' }
    if ($s.isRequireAcceptingUserToMatchInvitedUserEnabled -eq $true) { return New-TRResult Pass 'Invitations must be accepted by the invited account.' }
    New-TRResult Warning 'Sharing invitations can be accepted by a different account.'
}

Register-TRCheck -Id 'SPO-04' -Area 'Collaboration' -Category 'SharePoint and OneDrive' -Severity Medium -Effort 0.5 `
    -Title 'Legacy authentication is blocked for SharePoint' `
    -Needs 'SharePointSettings' `
    -Recommendation 'Disable legacy authentication protocols for SharePoint and OneDrive (Set-SPOTenant -LegacyAuthProtocolsEnabled $false).' `
    -Reference 'https://learn.microsoft.com/powershell/module/sharepoint-online/set-spotenant' `
    -Test {
    $s = Get-TRRawValue 'SharePointSettings'
    if ($s.isLegacyAuthProtocolsEnabled -eq $true) { return New-TRResult Warning 'Legacy authentication protocols are allowed.' }
    New-TRResult Pass 'Legacy authentication protocols are blocked.'
}

Register-TRCheck -Id 'SPO-05' -Area 'Collaboration' -Category 'SharePoint and OneDrive' -Severity Low -Effort 1 `
    -Title 'External sharing is limited by domain where appropriate' `
    -Needs 'SharePointSettings' `
    -Recommendation 'Consider an allow list of partner domains, or a block list of personal email domains, if the client only collaborates with known organisations.' `
    -Reference 'https://learn.microsoft.com/sharepoint/restricted-domains-sharing' `
    -Test {
    $s = Get-TRRawValue 'SharePointSettings'
    if ([string]$s.sharingCapability -eq 'disabled') { return New-TRResult Pass 'External sharing is disabled.' }
    switch ([string]$s.sharingDomainRestrictionMode) {
        'allowList' { return New-TRResult Pass ('Allow list: ' + ((@($s.sharingAllowedDomainList)) -join ', ')) }
        'blockList' { return New-TRResult Pass ('Block list: ' + ((@($s.sharingBlockedDomainList)) -join ', ')) }
    }
    New-TRResult Info 'Sharing is not restricted by domain.'
}

Register-TRCheck -Id 'SPO-06' -Area 'Collaboration' -Category 'SharePoint and OneDrive' -Severity Low -Effort 1 `
    -Title 'Idle session sign-out is configured' `
    -Needs 'SharePointSettings' `
    -Recommendation 'Enable idle session sign-out for unmanaged devices so browser sessions on shared or personal computers end automatically.' `
    -Reference 'https://learn.microsoft.com/sharepoint/sign-out-inactive-users' `
    -Test {
    $s = Get-TRRawValue 'SharePointSettings'
    if ($s.idleSessionSignOut.isEnabled -eq $true) { return New-TRResult Pass ('Enabled; sign out after {0} minutes.' -f [int]([int]$s.idleSessionSignOut.signOutAfterInSeconds / 60)) }
    New-TRResult Warning 'Idle session sign-out is not enabled.'
}

Register-TRCheck -Id 'SPO-07' -Area 'Collaboration' -Category 'SharePoint and OneDrive' -Severity Low -Effort 1 `
    -Title 'OneDrive sync is limited to managed devices' `
    -Needs 'SharePointSettings' `
    -Recommendation 'Restrict the OneDrive sync app to domain-joined computers, or use Conditional Access to block downloads on unmanaged devices.' `
    -Reference 'https://learn.microsoft.com/sharepoint/allow-syncing-only-on-specific-domains' `
    -Test {
    $s = Get-TRRawValue 'SharePointSettings'
    if ($s.isUnmanagedSyncAppForTenantRestricted -eq $true) { return New-TRResult Pass 'Sync is restricted to trusted domains.' }
    New-TRResult Info 'OneDrive sync is allowed on any device. Check whether Conditional Access covers unmanaged devices.'
}

Register-TRCheck -Id 'SPO-08' -Area 'Collaboration' -Category 'SharePoint and OneDrive' -Severity Info -Effort 0.5 `
    -Title 'Usage reports show real names' `
    -Needs 'ReportSettings' `
    -Recommendation 'If names are concealed, site owners and inactive sites cannot be identified from the reports. Turn off concealment in the Microsoft 365 admin centre (Org settings, Reports) if the client agrees.' `
    -Reference 'https://learn.microsoft.com/microsoft-365/troubleshoot/miscellaneous/reports-show-anonymous-user-name' `
    -Test {
    $r = Get-TRRawValue 'ReportSettings'
    if ($r.displayConcealedNames -eq $true) { return New-TRResult Warning 'User, group and site names are concealed in usage reports.' }
    New-TRResult Pass 'Usage reports show real names.'
}

Register-TRCheck -Id 'SPO-09' -Area 'Collaboration' -Category 'SharePoint and OneDrive' -Severity Low -Effort 2 `
    -Title 'Inactive SharePoint sites' `
    -Needs 'SiteUsage' `
    -Recommendation 'Confirm with owners whether inactive sites can be archived or deleted, or apply a site lifecycle policy.' `
    -Reference 'https://learn.microsoft.com/sharepoint/site-lifecycle-management' `
    -Test {
    $days = [int](Get-TRSetting 'InactiveSiteDays' 180)
    $sites = @(Get-TRItems 'SiteUsage' | Where-Object { [string]$_.'Is Deleted' -ne 'True' })
    $stale = @($sites | Where-Object { $d = Get-TRDaysSince $_.'Last Activity Date'; ($null -eq $d) -or $d -gt $days })
    $cur = 'Sites with no activity in {2}+ days: {0} of {1}.' -f $stale.Count, $sites.Count, $days
    if ($stale.Count) { return New-TRResult Info $cur @($stale | ForEach-Object { New-TRAffected $_.'Site URL' ('Owner {0}; last activity {1}; {2:N2} GB' -f $_.'Owner Display Name', $(if ($_.'Last Activity Date') { Format-TRDate $_.'Last Activity Date' } else { 'never' }), ([double]$_.'Storage Used (Byte)' / 1GB)) }) }
    New-TRResult Pass $cur
}

Register-TRCheck -Id 'COL-01' -Area 'Collaboration' -Category 'Teams and groups' -Severity Low -Effort 1 `
    -Title 'Microsoft 365 group and Team creation is governed' `
    -Needs 'GroupSettings' `
    -Recommendation 'Decide with the client whether all users can create Teams. If not, limit creation to a security group, and consider a naming policy and expiry.' `
    -Reference 'https://learn.microsoft.com/microsoft-365/solutions/manage-creation-of-groups' `
    -Test {
    $v = Get-TRGroupSettingValue 'Group.Unified' 'EnableGroupCreation'
    if ($null -eq $v) { return New-TRResult Info 'Default settings: all users can create Microsoft 365 groups and Teams.' }
    if ($v -eq 'false') { return New-TRResult Pass 'Group creation is limited to a security group.' }
    New-TRResult Info 'All users can create Microsoft 365 groups and Teams.'
}

Register-TRCheck -Id 'COL-02' -Area 'GroupMembership' -Category 'Teams and groups' -Severity Medium -Effort 2 `
    -Title 'Every group and Team has an owner' `
    -Needs 'GroupMembers' `
    -Recommendation 'Assign at least two owners to every Team and Microsoft 365 group, and enable the ownerless group policy.' `
    -Reference 'https://learn.microsoft.com/microsoft-365/admin/create-groups/manage-groups' `
    -Test {
    $groups = @(Get-TRItems 'Groups' | Where-Object { @($_.groupTypes) -contains 'Unified' })
    $owners = @{}
    foreach ($m in (Get-TRItems 'GroupMembers')) { if ($m.Role -eq 'Owner') { $owners[[string]$m.GroupId] = 1 + [int]$owners[[string]$m.GroupId] } }
    $none = @($groups | Where-Object { -not $owners[[string]$_.id] })
    $one = @($groups | Where-Object { $owners[[string]$_.id] -eq 1 })
    $aff = @(@($none | ForEach-Object { New-TRAffected $_.displayName 'No owner' }) + @($one | ForEach-Object { New-TRAffected $_.displayName 'Single owner' }))
    $cur = 'Microsoft 365 groups: {0}; without an owner: {1}; single owner: {2}.' -f $groups.Count, $none.Count, $one.Count
    if ($none.Count) { return New-TRResult Warning $cur $aff }
    if ($one.Count) { return New-TRResult Info $cur $aff }
    New-TRResult Pass $cur
}

Register-TRCheck -Id 'COL-03' -Area 'GroupMembership' -Category 'Teams and groups' -Severity Low -Effort 1 `
    -Title 'Groups and Teams with guest members' `
    -Needs 'GroupMembers' `
    -Recommendation 'Review guest membership with each owner, or set up an Entra access review for groups with guests.' `
    -Reference 'https://learn.microsoft.com/entra/id-governance/create-access-review' `
    -Test {
    $g = @(Get-TRItems 'GroupMembers' | Where-Object { $_.UserType -eq 'Guest' } | Group-Object GroupName)
    if ($g.Count) { return New-TRResult Info ('Groups or Teams with guest members: {0}.' -f $g.Count) @($g | ForEach-Object { New-TRAffected $_.Name ('Guests ({0}): {1}' -f $_.Count, ((@($_.Group | ForEach-Object { $_.MemberUpn } | Select-Object -First 10)) -join ', ')) }) }
    New-TRResult Pass 'No groups or Teams have guest members.'
}

Register-TRCheck -Id 'COL-04' -Area 'Collaboration' -Category 'Teams and groups' -Severity Low -Effort 1 `
    -Title 'Public groups and Teams' `
    -Needs 'Groups' `
    -Recommendation 'Confirm public Teams contain nothing sensitive. Anyone in the organisation can join a public Team and read its files.' `
    -Reference 'https://learn.microsoft.com/microsoftteams/manage-teams-in-modern-portal' `
    -Test {
    $pub = @(Get-TRItems 'Groups' | Where-Object { @($_.groupTypes) -contains 'Unified' -and $_.visibility -eq 'Public' })
    if ($pub.Count) { return New-TRResult Info ('Public groups or Teams: {0}.' -f $pub.Count) @($pub | ForEach-Object { New-TRAffected $_.displayName $(if (@($_.resourceProvisioningOptions) -contains 'Team') { 'Team' } else { 'Microsoft 365 group' }) }) }
    New-TRResult Pass 'No public groups or Teams.'
}

Register-TRCheck -Id 'COL-05' -Area 'Collaboration' -Category 'Teams and groups' -Severity Medium -Effort 1 `
    -Title 'Teams external access and anonymous meeting join' `
    -Needs @() `
    -Recommendation 'In the Teams admin centre, confirm external access is limited to trusted domains (or blocked for unmanaged Teams accounts), anonymous users cannot start meetings, and lobby settings stop anonymous users joining directly.' `
    -Reference 'https://learn.microsoft.com/microsoftteams/trusted-organizations-external-meetings-chat' `
    -Test { New-TRResult Manual 'Teams policy settings are not readable through delegated Graph access. Check in the Teams admin centre.' }

Register-TRCheck -Id 'END-01' -Area 'Intune' -Category 'Intune and devices' -Severity High -Effort 4 `
    -Title 'Compliance policies cover every enrolled platform' `
    -Needs 'ManagedDevices', 'CompliancePolicies' `
    -Recommendation 'Create and assign a compliance policy for each platform in use (Windows, iOS/iPadOS, Android, macOS) covering encryption, OS version, password and Defender status.' `
    -Reference 'https://learn.microsoft.com/intune/intune-service/protect/device-compliance-get-started' `
    -Test {
    $devs = @(Get-TRItems 'ManagedDevices')
    if (-not $devs.Count) { return New-TRResult Info 'No devices are enrolled in Intune.' }
    $platformOf = {
        param($os)
        switch -Regex ([string]$os) { '^Windows' { 'Windows' } 'iOS|iPadOS' { 'iOS' } 'Android' { 'Android' } 'mac' { 'macOS' } default { [string]$os } }
    }
    $used = @($devs | ForEach-Object { & $platformOf $_.operatingSystem } | Select-Object -Unique)
    $covered = @{}
    foreach ($p in (Get-TRItems 'CompliancePolicies')) {
        if (@($p.assignments).Count -eq 0) { continue }
        $t = [string]$p.'@odata.type'
        if ($t -match 'windows') { $covered['Windows'] = $true }
        if ($t -match 'ios') { $covered['iOS'] = $true }
        if ($t -match 'android|aosp') { $covered['Android'] = $true }
        if ($t -match 'macOS') { $covered['macOS'] = $true }
    }
    $gaps = @($used | Where-Object { $_ -in @('Windows', 'iOS', 'Android', 'macOS') -and -not $covered[$_] })
    if ($gaps.Count) { return New-TRResult Fail ('No assigned compliance policy for: ' + ($gaps -join ', ')) @($gaps | ForEach-Object { $pl = $_; New-TRAffected $pl ('Enrolled devices: {0}' -f @($devs | Where-Object { (& $platformOf $_.operatingSystem) -eq $pl }).Count) }) }
    New-TRResult Pass ('Assigned compliance policies cover: ' + ($used -join ', '))
}

Register-TRCheck -Id 'END-02' -Area 'Intune' -Category 'Intune and devices' -Severity Medium -Effort 0.5 `
    -Title 'Devices without a compliance policy are marked non-compliant' `
    -Needs 'DeviceManagement' `
    -Recommendation 'Set "Mark devices with no compliance policy assigned as" to Not compliant so Conditional Access cannot be bypassed by unassigned devices.' `
    -Reference 'https://learn.microsoft.com/intune/intune-service/protect/device-compliance-get-started' `
    -Test {
    $s = (Get-TRRawValue 'DeviceManagement').settings
    if ($s.secureByDefault -eq $true) { return New-TRResult Pass 'Devices with no policy are marked not compliant.' }
    New-TRResult Warning 'Devices with no compliance policy are marked compliant.'
}

Register-TRCheck -Id 'END-03' -Area 'Intune' -Category 'Intune and devices' -Severity Medium -Effort 3 `
    -Title 'Managed devices are compliant' `
    -Needs 'ManagedDevices' `
    -Recommendation 'Work through non-compliant devices by reason in Intune and fix or retire them.' `
    -Reference 'https://learn.microsoft.com/intune/intune-service/protect/compliance-policy-monitor' `
    -Test {
    $devs = @(Get-TRItems 'ManagedDevices')
    if (-not $devs.Count) { return New-TRResult Info 'No managed devices.' }
    $bad = @($devs | Where-Object { $_.complianceState -in @('noncompliant', 'error', 'conflict', 'inGracePeriod') })
    $cur = 'Devices not compliant: {0} of {1}.' -f $bad.Count, $devs.Count
    if ($bad.Count) { return New-TRResult Warning $cur @($bad | ForEach-Object { New-TRAffected $_.deviceName ('{0} {1}; {2}; user {3}' -f $_.operatingSystem, $_.osVersion, $_.complianceState, $_.userPrincipalName) }) }
    New-TRResult Pass $cur
}

Register-TRCheck -Id 'END-04' -Area 'Intune' -Category 'Intune and devices' -Severity Low -Effort 1 `
    -Title 'Devices are checking in with Intune' `
    -Needs 'ManagedDevices' `
    -Recommendation 'Investigate devices that have not synced for 30 days. Retire lost or replaced devices.' `
    -Reference 'https://learn.microsoft.com/intune/intune-service/remote-actions/devices-wipe' `
    -Test {
    $bad = @(Get-TRItems 'ManagedDevices' | Where-Object { $d = Get-TRDaysSince $_.lastSyncDateTime; $null -ne $d -and $d -gt 30 })
    if ($bad.Count) { return New-TRResult Warning ('Devices not synced for 30+ days: {0}.' -f $bad.Count) @($bad | ForEach-Object { New-TRAffected $_.deviceName ('Last sync {0}; user {1}' -f (Format-TRDate $_.lastSyncDateTime), $_.userPrincipalName) }) }
    New-TRResult Pass 'All devices have synced in the last 30 days.'
}

Register-TRCheck -Id 'END-05' -Area 'Intune' -Category 'Intune and devices' -Severity High -Effort 4 `
    -Title 'Windows devices are encrypted' `
    -Needs 'ManagedDevices' `
    -Recommendation 'Deploy a BitLocker disk encryption policy from Endpoint security and escrow recovery keys to Entra ID.' `
    -Reference 'https://learn.microsoft.com/intune/intune-service/protect/encrypt-devices' `
    -Test {
    $win = @(Get-TRItems 'ManagedDevices' | Where-Object { [string]$_.operatingSystem -match '^Windows' })
    if (-not $win.Count) { return New-TRResult Info 'No Windows devices are managed.' }
    $bad = @($win | Where-Object { $_.isEncrypted -ne $true })
    $cur = 'Windows devices reporting as not encrypted: {0} of {1}.' -f $bad.Count, $win.Count
    if ($bad.Count) { return New-TRResult Fail $cur @($bad | ForEach-Object { New-TRAffected $_.deviceName ('{0}; user {1}' -f $_.model, $_.userPrincipalName) }) }
    New-TRResult Pass $cur
}

Register-TRCheck -Id 'END-06' -Area 'Intune' -Category 'Intune and devices' -Severity High -Effort 4 `
    -Title 'Windows devices run a supported version' `
    -Needs 'ManagedDevices' `
    -Recommendation 'Upgrade Windows 10 devices (out of support since 14 October 2025 unless covered by ESU) and Windows 11 builds below the minimum to a supported release.' `
    -Reference 'https://learn.microsoft.com/windows/release-health/windows11-release-information' `
    -Test {
    $min = [int](Get-TRSetting 'MinimumWindows11Build' 26100)
    $win = @(Get-TRItems 'ManagedDevices' | Where-Object { [string]$_.operatingSystem -match '^Windows' -and [string]$_.osVersion -match '^10\.0\.(\d+)' })
    if (-not $win.Count) { return New-TRResult Info 'No Windows devices are managed.' }
    $w10 = @(); $old = @()
    foreach ($d in $win) {
        [void]([string]$d.osVersion -match '^10\.0\.(\d+)')
        $b = [int]$Matches[1]
        if ($b -lt 22000) { $w10 += $d } elseif ($b -lt $min) { $old += $d }
    }
    $aff = @(@($w10 | ForEach-Object { New-TRAffected $_.deviceName ('Windows 10 ' + $_.osVersion) }) + @($old | ForEach-Object { New-TRAffected $_.deviceName ('Windows 11 ' + $_.osVersion) }))
    $cur = 'Windows devices: {2}; on Windows 10: {0}; on Windows 11 below the minimum build: {1}.' -f $w10.Count, $old.Count, $win.Count
    if ($w10.Count) { return New-TRResult Fail $cur $aff }
    if ($old.Count) { return New-TRResult Warning $cur $aff }
    New-TRResult Pass ('All {0} Windows devices are on build {1} or later.' -f $win.Count, $min)
}

Register-TRCheck -Id 'END-07' -Area 'Intune' -Category 'Intune and devices' -Severity Medium -Effort 6 `
    -Title 'Endpoint security policies are deployed' `
    -Needs 'ManagedDevices', 'ConfigurationPolicies' `
    -Recommendation 'Deploy and assign Endpoint security policies for antivirus, disk encryption, firewall, EDR, attack surface reduction and account protection (LAPS).' `
    -Reference 'https://learn.microsoft.com/intune/intune-service/protect/endpoint-security' `
    -Test {
    if (-not @(Get-TRItems 'ManagedDevices' | Where-Object { [string]$_.operatingSystem -match '^Windows' }).Count) { return New-TRResult Info 'No Windows devices are managed.' }
    $families = [ordered]@{
        'endpointSecurityAntivirus'                    = 'Antivirus'
        'endpointSecurityDiskEncryption'               = 'Disk encryption'
        'endpointSecurityFirewall'                     = 'Firewall'
        'endpointSecurityEndpointDetectionAndResponse' = 'Endpoint detection and response'
        'endpointSecurityAttackSurfaceReduction'       = 'Attack surface reduction'
        'endpointSecurityAccountProtection'            = 'Account protection (LAPS)'
    }
    $found = @{}
    foreach ($p in (Get-TRItems 'ConfigurationPolicies')) {
        $fam = [string]$p.templateReference.templateFamily
        if (-not $families.Contains($fam)) { continue }
        if ((Test-TRHasProperty $p 'assignments') -and @($p.assignments).Count -eq 0) { continue }
        $found[$fam] = $true
    }
    $legacy = @(Get-TRItems 'Intents' | Where-Object { $_.isAssigned -eq $true }).Count
    $legacy += @(Get-TRItems 'DeviceConfigurations' | Where-Object { [string]$_.'@odata.type' -match 'windows10EndpointProtectionConfiguration' -and @($_.assignments).Count }).Count
    $missing = @($families.Keys | Where-Object { -not $found[$_] } | ForEach-Object { $families[$_] })
    $note = if ($legacy) { (' {0} legacy endpoint protection profiles are assigned and may cover some areas.' -f $legacy) } else { '' }
    if ($missing.Count -eq 0) { return New-TRResult Pass ('All endpoint security areas have assigned policies.' + $note) }
    if ($missing.Count -ge 4) { return New-TRResult Fail ('Missing: ' + ($missing -join ', ') + '.' + $note) }
    New-TRResult Warning ('Missing: ' + ($missing -join ', ') + '.' + $note)
}

Register-TRCheck -Id 'END-08' -Area 'Intune' -Category 'Intune and devices' -Severity Low -Effort 1 `
    -Title 'Personal Windows device enrolment is blocked' `
    -Needs 'EnrollmentConfigurations' `
    -Recommendation 'Block personally owned Windows enrolment in the default platform restriction unless BYOD Windows is in scope, and use Autopilot for corporate devices.' `
    -Reference 'https://learn.microsoft.com/intune/intune-service/enrollment/enrollment-restrictions-set' `
    -Test {
    $r = @(Get-TRItems 'EnrollmentConfigurations' | Where-Object { [string]$_.'@odata.type' -match 'PlatformRestrictionsConfiguration$' -and [int]$_.priority -eq 0 }) | Select-Object -First 1
    if (-not $r) { $r = @(Get-TRItems 'EnrollmentConfigurations' | Where-Object { [string]$_.'@odata.type' -match 'PlatformRestrictions' }) | Select-Object -First 1 }
    if (-not $r) { return New-TRResult Info 'No platform restriction configuration found.' }
    $w = $r.windowsRestriction
    if ($w -and $w.personalDeviceEnrollmentBlocked -eq $true) { return New-TRResult Pass 'Personal Windows enrolment is blocked.' }
    if ($w -and $w.platformBlocked -eq $true) { return New-TRResult Pass 'Windows enrolment is blocked.' }
    New-TRResult Warning 'Personally owned Windows devices can enrol.'
}

Register-TRCheck -Id 'END-09' -Area 'Intune' -Category 'Intune and devices' -Severity Medium -Effort 3 `
    -Title 'App protection policies protect mobile data' `
    -Needs 'IosAppProtection', 'AndroidAppProtection' `
    -Recommendation 'Create and assign app protection policies for iOS and Android so corporate data in Outlook, Teams and OneDrive is protected on personal phones.' `
    -Reference 'https://learn.microsoft.com/intune/intune-service/apps/app-protection-policy' `
    -Test {
    $ios = @(Get-TRItems 'IosAppProtection' | Where-Object { @($_.assignments).Count -gt 0 })
    $and = @(Get-TRItems 'AndroidAppProtection' | Where-Object { @($_.assignments).Count -gt 0 })
    $cur = 'Assigned policies: iOS {0}, Android {1}' -f $ios.Count, $and.Count
    if ($ios.Count -and $and.Count) { return New-TRResult Pass $cur }
    if ($ios.Count -or $and.Count) { return New-TRResult Warning $cur }
    New-TRResult Fail $cur
}

Register-TRCheck -Id 'END-10' -Area 'Intune' -Category 'Intune and devices' -Severity Info -Effort 0 `
    -Title 'Windows update management' `
    -Needs 'DeviceConfigurations' `
    -Recommendation 'Confirm Windows updates are managed by exactly one tool. If updates are handled by the RMM, avoid assigning Intune update rings to the same devices.' `
    -Reference 'https://learn.microsoft.com/intune/intune-service/protect/windows-update-for-business-configure' `
    -Test {
    $rings = @(Get-TRItems 'DeviceConfigurations' | Where-Object { [string]$_.'@odata.type' -match 'windowsUpdateForBusinessConfiguration' })
    $assigned = @($rings | Where-Object { @($_.assignments).Count -gt 0 })
    $rmm = [bool](Get-TRSetting 'PatchingViaRmm' $true)
    $cur = 'Intune update rings: {0} ({1} assigned).' -f $rings.Count, $assigned.Count
    if ($rmm -and $assigned.Count) { return New-TRResult Warning ($cur + ' Patching is expected through the RMM, so check for overlap.') @($assigned | ForEach-Object { New-TRAffected $_.displayName 'Assigned update ring' }) }
    if ($rmm) { return New-TRResult Info ($cur + ' Patching is expected through the RMM.') }
    if (-not $assigned.Count) { return New-TRResult Warning ($cur + ' No assigned update ring.') }
    New-TRResult Pass $cur
}

Register-TRCheck -Id 'END-11' -Area 'Intune' -Category 'Intune and devices' -Severity High -Effort 1 `
    -Title 'No jailbroken or rooted devices' `
    -Needs 'ManagedDevices' `
    -Recommendation 'Block jailbroken and rooted devices in compliance policies and retire any that are reported.' `
    -Reference 'https://learn.microsoft.com/intune/intune-service/protect/compliance-policy-create-ios' `
    -Test {
    $bad = @(Get-TRItems 'ManagedDevices' | Where-Object { [string]$_.jailBroken -eq 'True' })
    if ($bad.Count) { return New-TRResult Fail ('Jailbroken or rooted devices: {0}.' -f $bad.Count) @($bad | ForEach-Object { New-TRAffected $_.deviceName $_.userPrincipalName }) }
    New-TRResult Pass 'No jailbroken or rooted devices.'
}

Register-TRCheck -Id 'END-12' -Area 'Intune' -Category 'Intune and devices' -Severity Info -Effort 0 `
    -Title 'Device estate summary' `
    -Needs 'ManagedDevices' `
    -Recommendation 'Use the Devices inventory to agree the device estate with the client and identify devices that should be enrolled.' `
    -Reference 'https://learn.microsoft.com/intune/intune-service/fundamentals/deployment-guide-enrollment' `
    -Test {
    $devs = @(Get-TRItems 'ManagedDevices')
    $byOs = @($devs | Group-Object operatingSystem | ForEach-Object { '{0} {1}' -f $_.Name, $_.Count })
    $entra = @(Get-TRItems 'Devices')
    $ap = @(Get-TRItems 'AutopilotDevices')
    New-TRResult Info ('Intune managed: {0} ({1}); Entra registered or joined: {2}; Autopilot registered: {3}' -f $devs.Count, ($byOs -join ', '), $entra.Count, $ap.Count)
}

Register-TRCheck -Id 'SEC-01' -Area 'SecureScore' -Category 'Microsoft Secure Score' -Severity Medium -Effort 0 `
    -Title 'Microsoft Secure Score' `
    -Needs 'SecureScore' `
    -Recommendation 'Work through the Secure Score improvement actions in the Secure Score inventory, starting with the largest gaps that have low user impact.' `
    -Reference 'https://learn.microsoft.com/defender-xdr/microsoft-secure-score' `
    -Test {
    $s = Get-TRRawValue 'SecureScore'
    $pct = Get-TRPercent ([double]$s.currentScore) ([double]$s.maxScore)
    $avg = @($s.averageComparativeScores | Where-Object { $_.basis -eq 'TotalSeats' }) | Select-Object -First 1
    if (-not $avg) { $avg = @($s.averageComparativeScores | Where-Object { $_.basis -eq 'AllTenants' }) | Select-Object -First 1 }
    $cur = 'Secure Score {0:N0} of {1:N0} ({2}%).' -f [double]$s.currentScore, [double]$s.maxScore, $pct
    if ($avg) { $cur += (' Comparable organisations ({0}) average {1:N1}.' -f $avg.basis, [double]$avg.averageScore) }
    if ($pct -ge 70) { return New-TRResult Pass $cur }
    if ($pct -ge 50) { return New-TRResult Warning $cur }
    New-TRResult Fail $cur
}

Register-TRCheck -Id 'PRM-01' -Area 'MailboxPermissions' -Category 'Permissions' -Severity Low -Effort 2 `
    -Title 'Mailbox delegation is reviewed' `
    -Needs 'MailboxPermissions' `
    -Recommendation 'Ask the client to confirm Full Access, Send As and Send on Behalf permissions on user mailboxes. Delegation to user mailboxes should be rare and documented.' `
    -Reference 'https://learn.microsoft.com/exchange/recipients-in-exchange-online/manage-permissions-for-recipients' `
    -Test {
    $rows = @(Get-TRItems 'MailboxPermissions')
    $userMb = @($rows | Where-Object { $_.MailboxType -eq 'UserMailbox' })
    $cur = 'Mailbox delegations: {0} ({1} on user mailboxes).' -f $rows.Count, $userMb.Count
    if ($userMb.Count) { return New-TRResult Info $cur @($userMb | ForEach-Object { New-TRAffected $_.Mailbox ('{0}: {1}' -f $_.Permission, $_.Delegate) }) }
    New-TRResult Pass $cur
}

Register-TRCheck -Id 'PRM-02' -Area 'MailboxPermissions' -Category 'Permissions' -Severity Low -Effort 1 `
    -Title 'Mailbox permissions do not reference deleted or disabled accounts' `
    -Needs 'MailboxPermissions', 'Users' `
    -Recommendation 'Remove permissions granted to deleted accounts (shown as SIDs) and to disabled accounts.' `
    -Reference 'https://learn.microsoft.com/exchange/recipients-in-exchange-online/manage-permissions-for-recipients' `
    -Test {
    $byUpn = @{}
    foreach ($u in (Get-TRItems 'Users')) {
        if ($u.userPrincipalName) { $byUpn[([string]$u.userPrincipalName).ToLower()] = $u }
        if ($u.mail) { $byUpn[([string]$u.mail).ToLower()] = $u }
    }
    $aff = foreach ($r in (Get-TRItems 'MailboxPermissions')) {
        $d = [string]$r.Delegate
        if ($d -match '^S-1-5-21-') { New-TRAffected $r.Mailbox ('{0} granted to a deleted account ({1})' -f $r.Permission, $d); continue }
        $u = $byUpn[$d.ToLower()]
        if ($u -and $u.accountEnabled -ne $true) { New-TRAffected $r.Mailbox ('{0} granted to disabled account {1}' -f $r.Permission, $d) }
    }
    $aff = @($aff)
    if ($aff.Count) { return New-TRResult Warning ('Permissions referencing deleted or disabled accounts: {0}.' -f $aff.Count) $aff }
    New-TRResult Pass 'No orphaned mailbox permissions found.'
}

Register-TRCheck -Id 'PRM-03' -Area 'SharingAudit' -Category 'Permissions' -Severity Medium -Effort 2 `
    -Title 'Anonymous and external sharing activity (last 30 days)' `
    -Needs 'SharingAudit' `
    -Recommendation 'Review the Sharing activity inventory with the client. Remove Anyone links on sensitive content and consider expiry and view-only defaults.' `
    -Reference 'https://learn.microsoft.com/purview/audit-log-sharing' `
    -Test {
    $rows = @(Get-TRItems 'SharingAudit')
    $anon = @($rows | Where-Object { $_.Operation -match '^AnonymousLink' })
    $ext = @($rows | Where-Object { $_.Operation -eq 'SharingInvitationCreated' -or [string]$_.TargetType -match 'Guest|External' })
    $cur = 'Sharing events: {0} ({1} Anyone links, {2} external invitations).' -f $rows.Count, $anon.Count, $ext.Count
    $aff = @($anon | Select-Object -First 500 | ForEach-Object { New-TRAffected $_.Item ('{0} by {1} on {2}' -f $_.Operation, $_.User, (Format-TRDate $_.Date)) })
    if ($anon.Count) { return New-TRResult Warning $cur $aff }
    New-TRResult Info $cur
}

function Get-TRGate {
    param([string]$Capability, [string]$Label, [string[]]$Keys, [switch]$AllowUnprovisioned)
    if ($Capability -and -not (Test-TRLicensed $Capability)) { return New-TRResult Info ($Label + ' is not licensed.') }
    if (-not $AllowUnprovisioned -and $Keys -contains 'DefenderDevices' -and (Get-TRMeta 'DefenderNotProvisioned') -eq $true) {
        return New-TRResult NotAssessed 'Defender for Endpoint has not been set up in this tenant, so there is no device data to assess. See DEF-01.'
    }
    if ($Keys -and -not (Test-TRCollected $Keys)) { return New-TRResult NotAssessed ('Data not available. ' + (Get-TRMissingReason $Keys)) }
    $null
}

function Get-TRMdeOnboarded {
    @(Get-TRItems 'DefenderDevices' | Where-Object { [string]$_.OnboardingStatus -eq 'Onboarded' })
}

function Format-TRSoftware {
    param([string]$Vendor, [string]$Name)
    $t = (Get-Culture).TextInfo
    $v = $t.ToTitleCase(($Vendor -replace '_', ' ').Trim())
    $n = $t.ToTitleCase(($Name -replace '_', ' ').Trim())
    if ($v -and $n -notlike ($v + '*')) { return ('{0} {1}' -f $v, $n).Trim() }
    $n
}

function Get-TRSecureScoreEvidence {
    param([string]$Pattern)
    $profiles = @{}
    foreach ($p in (Get-TRItems 'SecureScoreProfiles')) { $profiles[[string]$p.id] = $p }
    $ss = Get-TRRawValue 'SecureScore'
    if (-not $ss) { return }
    foreach ($c in @($ss.controlScores)) {
        if (-not $c) { continue }
        $p = $profiles[[string]$c.controlName]
        $title = if ($p) { [string]$p.title } else { [string]$c.description }
        if ($title -notmatch $Pattern) { continue }
        [pscustomobject]@{ Title = $title; Score = [double]$c.score; Max = $(if ($p) { [double]$p.maxScore } else { 0 }) }
    }
}

function Get-TRPurviewFallback {
    param([string]$Pattern, [string[]]$Keys)
    $reason = Get-TRMissingReason $Keys
    $ev = @(Get-TRSecureScoreEvidence $Pattern)
    if (-not $ev.Count) { return New-TRResult NotAssessed ('Data not available. ' + $reason) }
    $parts = @($ev | ForEach-Object { '{0} ({1:N0} of {2:N0} points)' -f $_.Title, $_.Score, $_.Max })
    $text = 'Purview policies could not be read directly. Secure Score reports: {0}.' -f ($parts -join '; ')
    $done = @($ev | Where-Object { $_.Max -gt 0 -and $_.Score -ge $_.Max })
    if ($done.Count -eq $ev.Count) { return New-TRResult Pass $text }
    New-TRResult Warning $text
}

function Get-TRPolicyWorkloads {
    param($Policy)
    $w = New-Object System.Collections.ArrayList
    $text = [string]$Policy.Workload
    if ($Policy.ExchangeLocation -or $text -match 'Exchange') { [void]$w.Add('Exchange') }
    if ($Policy.SharePointLocation -or $text -match 'SharePoint') { [void]$w.Add('SharePoint') }
    if ($Policy.OneDriveLocation -or $text -match 'OneDrive') { [void]$w.Add('OneDrive') }
    if ($Policy.TeamsLocation -or $Policy.TeamsChannelLocation -or $Policy.TeamsChatLocation -or $text -match 'Teams') { [void]$w.Add('Teams') }
    if ($Policy.EndpointDlpLocation -or $text -match 'Endpoint') { [void]$w.Add('Devices') }
    if ($Policy.ModernGroupLocation -or $text -match 'ModernGroup') { [void]$w.Add('Microsoft 365 Groups') }
    , $w.ToArray()
}

function Test-TRPolicyActive {
    param($Policy)
    ($Policy.Enabled -ne $false) -and ([string]$Policy.Mode -notmatch 'Disable|PendingDeletion')
}

function Format-TRRetention {
    param($Rule)
    $d = [string]$Rule.RetentionDuration
    $action = [string]$Rule.RetentionComplianceAction
    if (-not $d) { return $action }
    if ($d -eq 'Unlimited') { $text = 'forever' }
    else {
        $n = 0
        if ([int]::TryParse($d, [ref]$n)) {
            $hint = [string]$Rule.RetentionDurationDisplayHint
            $text = if ($hint -eq 'Years' -or ($n -ge 365 -and $n % 365 -eq 0)) { '{0} years' -f [Math]::Round($n / 365, 1) } elseif ($hint -eq 'Months') { '{0} months' -f [Math]::Round($n / 30) } else { '{0} days' -f $n }
        }
        else { $text = $d }
    }
    if ($action) { return ('{0} for {1}' -f $action, $text) }
    $text
}

Register-TRCheck -Id 'DEF-01' -Area 'Defender' -Category 'Microsoft Defender XDR' -Severity High -Effort 4 `
    -Title 'Devices are onboarded to Defender for Endpoint' `
    -Needs @() `
    -Recommendation 'Onboard every Windows and macOS device to Defender for Endpoint or Defender for Business, ideally with the Intune EDR onboarding policy, and confirm each device reports in the Defender portal.' `
    -Reference 'https://learn.microsoft.com/defender-endpoint/onboarding' `
    -Test {
    $g = Get-TRGate 'DefenderEndpoint' 'Defender for Endpoint or Defender for Business' @('DefenderDevices') -AllowUnprovisioned
    if ($g) { return $g }
    $onb = @(Get-TRMdeOnboarded)
    if ((Get-TRMeta 'DefenderNotProvisioned') -eq $true) { return New-TRResult Fail 'Defender for Endpoint or Defender for Business is licensed but has never been set up in this tenant (no device data in advanced hunting).' }
    if (-not $onb.Count) { return New-TRResult Fail 'Defender for Endpoint is licensed but no devices are onboarded.' }
    $byAad = @{}
    $byName = @{}
    foreach ($d in $onb) {
        if ($d.AadDeviceId) { $byAad[([string]$d.AadDeviceId).ToLower()] = $d }
        if ($d.DeviceName) { $byName[((([string]$d.DeviceName) -split '\.')[0]).ToLower()] = $d }
    }
    $ref = @()
    $label = ''
    if (Test-TRCollected @('ManagedDevices')) {
        $ref = @(Get-TRItems 'ManagedDevices' | Where-Object { [string]$_.operatingSystem -match '^(Windows|macOS)' } | ForEach-Object { [pscustomobject]@{ Name = [string]$_.deviceName; Aad = [string]$_.azureADDeviceId; Detail = ('{0}, {1}' -f $_.operatingSystem, $_.userPrincipalName) } })
        $label = 'Intune managed Windows and macOS devices'
    }
    elseif (Test-TRCollected @('Devices')) {
        $stale = [int](Get-TRSetting 'StaleDeviceDays' 180)
        $ref = @(Get-TRItems 'Devices' | Where-Object {
                $days = Get-TRDaysSince $_.approximateLastSignInDateTime
                [string]$_.operatingSystem -match '^(Windows|Mac)' -and $_.accountEnabled -eq $true -and $null -ne $days -and $days -le $stale
            } | ForEach-Object { [pscustomobject]@{ Name = [string]$_.displayName; Aad = [string]$_.deviceId; Detail = ('{0}, last sign-in {1}' -f $_.operatingSystem, (Format-TRDate $_.approximateLastSignInDateTime)) } })
        $label = 'Active Entra ID Windows and macOS devices'
    }
    if (-not $ref.Count) { return New-TRResult Pass ('Onboarded devices: {0}.' -f $onb.Count) }
    $missing = @($ref | Where-Object { -not (($_.Aad -and $byAad.ContainsKey($_.Aad.ToLower())) -or ($_.Name -and $byName.ContainsKey($_.Name.ToLower()))) })
    $covered = $ref.Count - $missing.Count
    $pct = Get-TRPercent $covered $ref.Count
    $cur = 'Onboarded devices: {0}. {1}: {2} of {3} onboarded ({4}%).' -f $onb.Count, $label, $covered, $ref.Count, $pct
    $aff = @($missing | ForEach-Object { New-TRAffected $_.Name $_.Detail })
    if ($pct -ge 95) { return New-TRResult Pass $cur $aff }
    if ($pct -ge 75) { return New-TRResult Warning $cur $aff }
    New-TRResult Fail $cur $aff
}

Register-TRCheck -Id 'DEF-02' -Area 'Defender' -Category 'Microsoft Defender XDR' -Severity Medium -Effort 2 `
    -Title 'Discovered devices that can be onboarded' `
    -Needs @() `
    -Recommendation 'Review devices found by device discovery that are not onboarded. Onboard company devices, and identify or isolate unknown ones.' `
    -Reference 'https://learn.microsoft.com/defender-endpoint/device-discovery' `
    -Test {
    $g = Get-TRGate 'DefenderEndpoint' 'Defender for Endpoint or Defender for Business' @('DefenderDevices')
    if ($g) { return $g }
    $devs = @(Get-TRItems 'DefenderDevices')
    $can = @($devs | Where-Object { [string]$_.OnboardingStatus -eq 'CanBeOnboarded' })
    $uns = @($devs | Where-Object { [string]$_.OnboardingStatus -eq 'Unsupported' }).Count
    $cur = 'Discovered devices that can be onboarded: {0}. Unsupported discovered devices: {1}.' -f $can.Count, $uns
    $aff = @($can | ForEach-Object { New-TRAffected $_.DeviceName ('{0} {1}, {2}, last seen {3}' -f $_.OSPlatform, $_.DeviceType, $_.JoinType, (Format-TRDate $_.LastSeen)) })
    if ($can.Count) { return New-TRResult Warning $cur $aff }
    New-TRResult Pass $cur
}

Register-TRCheck -Id 'DEF-03' -Area 'Defender' -Category 'Microsoft Defender XDR' -Severity Medium -Effort 2 `
    -Title 'Onboarded devices report a healthy sensor' `
    -Needs @() `
    -Recommendation 'Investigate devices with an inactive, misconfigured or impaired sensor. Remove retired devices, and fix connectivity or service issues on the rest so they are protected and visible.' `
    -Reference 'https://learn.microsoft.com/defender-endpoint/fix-unhealthy-sensors' `
    -Test {
    $g = Get-TRGate 'DefenderEndpoint' 'Defender for Endpoint or Defender for Business' @('DefenderDevices')
    if ($g) { return $g }
    $onb = @(Get-TRMdeOnboarded)
    $bad = @($onb | Where-Object { [string]$_.SensorHealthState -and [string]$_.SensorHealthState -ne 'Active' })
    $states = @($bad | Group-Object SensorHealthState | ForEach-Object { '{0} {1}' -f $_.Name, $_.Count })
    $cur = 'Onboarded devices with an unhealthy or inactive sensor: {0} of {1}' -f $bad.Count, $onb.Count
    if ($states.Count) { $cur += (' (' + ($states -join ', ') + ')') }
    $cur += '.'
    $aff = @($bad | ForEach-Object { New-TRAffected $_.DeviceName ('{0}, last seen {1}' -f $_.SensorHealthState, (Format-TRDate $_.LastSeen)) })
    if ($bad.Count) { return New-TRResult Warning $cur $aff }
    New-TRResult Pass $cur
}

Register-TRCheck -Id 'DEF-04' -Area 'Defender' -Category 'Microsoft Defender XDR' -Severity High -Effort 8 `
    -Title 'No critical vulnerabilities with public exploits' `
    -Needs @() `
    -Recommendation 'Patch the listed software through the RMM or Intune, starting with critical vulnerabilities that have public exploits. Remove software that is no longer needed and make sure third-party applications are in the patch policy.' `
    -Reference 'https://learn.microsoft.com/defender-vulnerability-management/tvm-weaknesses' `
    -Test {
    $g = Get-TRGate 'DefenderEndpoint' 'Defender for Endpoint or Defender for Business' @('DefenderDevices', 'DefenderVulnSoftware')
    if ($g) { return $g }
    $rows = @(Get-TRItems 'DefenderVulnSoftware')
    $crit = @($rows | Where-Object { [int]$_.CriticalCves -gt 0 })
    $critExp = @($crit | Where-Object { [int]$_.ExploitableCves -gt 0 })
    $cur = 'Software with critical vulnerabilities: {0} ({1} with public exploits). Software with high or critical vulnerabilities: {2}.' -f $crit.Count, $critExp.Count, $rows.Count
    $sorted = @($rows | Sort-Object @{ e = { [int]$_.ExploitableCves }; Descending = $true }, @{ e = { [int]$_.CriticalCves }; Descending = $true }, @{ e = { [int]$_.Devices }; Descending = $true })
    $aff = @($sorted | ForEach-Object {
            $upd = @($_.Updates | Where-Object { $_ }) -join ', '
            $d = 'Critical {0}, high {1}, with exploits {2}, devices {3}' -f [int]$_.CriticalCves, [int]$_.HighCves, [int]$_.ExploitableCves, [int]$_.Devices
            if ($upd) { $d += ('. Update: ' + $upd) }
            New-TRAffected (Format-TRSoftware $_.SoftwareVendor $_.SoftwareName) $d
        })
    if ($critExp.Count) { return New-TRResult Fail $cur $aff }
    if ($rows.Count) { return New-TRResult Warning $cur $aff }
    New-TRResult Pass 'No high or critical software vulnerabilities reported.'
}

Register-TRCheck -Id 'DEF-05' -Area 'Defender' -Category 'Microsoft Defender XDR' -Severity Medium -Effort 6 `
    -Title 'High-impact secure configuration gaps are addressed' `
    -Needs @() `
    -Recommendation 'Work through the high-impact security recommendations (impact 7 or more), usually by adjusting Intune endpoint security, attack surface reduction or baseline policies, and test with a pilot group first.' `
    -Reference 'https://learn.microsoft.com/defender-vulnerability-management/tvm-security-recommendation' `
    -Test {
    $g = Get-TRGate 'DefenderEndpoint' 'Defender for Endpoint or Defender for Business' @('DefenderDevices', 'DefenderConfigGaps')
    if ($g) { return $g }
    $rows = @(Get-TRItems 'DefenderConfigGaps')
    $high = @($rows | Where-Object { [double]$_.ConfigurationImpact -ge 7 })
    $cur = 'Secure configuration gaps: {0} ({1} high impact, rated 7 or more out of 10).' -f $rows.Count, $high.Count
    $sorted = @($rows | Sort-Object @{ e = { [double]$_.ConfigurationImpact }; Descending = $true }, @{ e = { [int]$_.Failing }; Descending = $true } | Select-Object -First 100)
    $aff = @($sorted | ForEach-Object {
            $name = if ($_.ConfigurationName) { [string]$_.ConfigurationName } else { [string]$_.ConfigurationId }
            New-TRAffected $name ('Impact {0:N1}; failing on {1} of {2} devices; {3}' -f [double]$_.ConfigurationImpact, [int]$_.Failing, [int]$_.Assessed, $_.ConfigurationSubcategory)
        })
    if ($high.Count -ge 5) { return New-TRResult Fail $cur $aff }
    if ($high.Count) { return New-TRResult Warning $cur $aff }
    New-TRResult Pass $cur $aff
}

Register-TRCheck -Id 'DEF-06' -Area 'Defender' -Category 'Microsoft Defender XDR' -Severity Medium -Effort 2 `
    -Title 'No devices with a high exposure level' `
    -Needs @() `
    -Recommendation 'Reduce the exposure of the listed devices by applying their security recommendations and patches, starting with devices used by administrators.' `
    -Reference 'https://learn.microsoft.com/defender-vulnerability-management/tvm-exposure-score' `
    -Test {
    $g = Get-TRGate 'DefenderEndpoint' 'Defender for Endpoint or Defender for Business' @('DefenderDevices')
    if ($g) { return $g }
    $onb = @(Get-TRMdeOnboarded)
    $vuln = @{}
    foreach ($v in (Get-TRItems 'DefenderDeviceVulns')) { $vuln[[string]$v.DeviceId] = $v }
    $hi = @($onb | Where-Object { [string]$_.ExposureLevel -eq 'High' })
    $med = @($onb | Where-Object { [string]$_.ExposureLevel -eq 'Medium' }).Count
    $cur = 'Devices with high exposure: {0}; medium exposure: {1}; onboarded: {2}.' -f $hi.Count, $med, $onb.Count
    $aff = @($hi | ForEach-Object {
            $v = $vuln[[string]$_.DeviceId]
            $d = '{0} {1}' -f $_.OSPlatform, $_.OSVersion
            if ($v) { $d += ('; critical CVEs {0}, high CVEs {1}' -f [int]$v.Critical, [int]$v.High) }
            New-TRAffected $_.DeviceName $d
        })
    if ($hi.Count) { return New-TRResult Warning $cur $aff }
    New-TRResult Pass $cur
}

Register-TRCheck -Id 'DEF-07' -Area 'Defender' -Category 'Microsoft Defender XDR' -Severity Medium -Effort 1 `
    -Title 'Defender for Endpoint is connected to Intune' `
    -Needs @() `
    -Recommendation 'Turn on the Microsoft Intune connection in Defender (Settings, Endpoints, Advanced features) and the Defender for Endpoint connector in Intune, then use device risk in compliance policies.' `
    -Reference 'https://learn.microsoft.com/intune/intune-service/protect/advanced-threat-protection-configure' `
    -Test {
    if (-not (Test-TRLicensed DefenderEndpoint) -or -not (Test-TRLicensed Intune)) { return New-TRResult Info 'Needs both Defender for Endpoint (or Defender for Business) and Intune.' }
    $g = Get-TRGate '' '' @('MtdConnectors')
    if ($g) { return $g }
    $c = @(Get-TRItems 'MtdConnectors' | Where-Object { [string]$_.id -eq 'fc780465-2017-40d4-a0c5-307022471b92' }) | Select-Object -First 1
    if (-not $c) { return New-TRResult Warning 'The Defender for Endpoint connector is not set up in Intune.' }
    $cur = 'Connector state: {0}; Windows devices connected: {1}; last heartbeat {2}.' -f $c.partnerState, (ConvertTo-TRYesNo $c.windowsEnabled), (Format-TRDate $c.lastHeartbeatDateTime)
    if ([string]$c.partnerState -eq 'enabled' -and $c.windowsEnabled -ne $false) { return New-TRResult Pass $cur }
    New-TRResult Warning $cur
}

Register-TRCheck -Id 'DEF-08' -Area 'Defender' -Category 'Microsoft Defender XDR' -Severity High -Effort 2 `
    -Title 'Security incidents are triaged and resolved' `
    -Needs 'DefenderIncidents' `
    -Recommendation 'Assign, investigate and resolve open incidents, starting with high severity. Make sure incident notifications reach your service desk or SOC.' `
    -Reference 'https://learn.microsoft.com/defender-xdr/manage-incidents' `
    -Test {
    $all = @(Get-TRItems 'DefenderIncidents')
    $open = @($all | Where-Object { [string]$_.status -notin @('resolved', 'redirected') })
    $oldHigh = @($open | Where-Object { [string]$_.severity -eq 'high' -and [int](Get-TRDaysSince $_.createdDateTime) -gt 7 })
    $highOpen = @($open | Where-Object { [string]$_.severity -eq 'high' }).Count
    $cur = 'Incidents in the last 90 days: {0}. Open: {1} ({2} high severity).' -f $all.Count, $open.Count, $highOpen
    $aff = @($open | Sort-Object { ConvertTo-TRDate $_.createdDateTime } | ForEach-Object {
            $who = if ($_.assignedTo) { [string]$_.assignedTo } else { 'unassigned' }
            New-TRAffected $_.displayName ('Severity {0}, {1}, created {2}, {3}' -f $_.severity, $_.status, (Format-TRDate $_.createdDateTime), $who)
        })
    if ($oldHigh.Count) { return New-TRResult Fail ($cur + (' High-severity incidents open for more than 7 days: {0}.' -f $oldHigh.Count)) $aff }
    if ($open.Count) { return New-TRResult Warning $cur $aff }
    New-TRResult Pass $cur
}

Register-TRCheck -Id 'DEF-09' -Area 'Defender' -Category 'Microsoft Defender XDR' -Severity Low -Effort 4 `
    -Title 'Attack simulation training is used' `
    -Needs @() `
    -Recommendation 'Run phishing simulations at least quarterly with automatic training for users who click, and report the trend to management.' `
    -Reference 'https://learn.microsoft.com/defender-office-365/attack-simulation-training-get-started' `
    -Test {
    $g = Get-TRGate 'DefenderO365P2' 'Defender for Office 365 Plan 2' @('AttackSimulations')
    if ($g) { return $g }
    $sims = @(Get-TRItems 'AttackSimulations')
    $recent = @($sims | Where-Object { $d = Get-TRDaysSince $(if ($_.launchDateTime) { $_.launchDateTime } else { $_.createdDateTime }); $null -ne $d -and $d -le 365 })
    $cur = 'Simulations in the last 12 months: {0} (all time: {1}).' -f $recent.Count, $sims.Count
    $aff = @($recent | ForEach-Object { New-TRAffected $_.displayName ('{0}, launched {1}' -f $_.status, (Format-TRDate $_.launchDateTime)) })
    if ($recent.Count -ge 2) { return New-TRResult Pass $cur $aff }
    New-TRResult Warning $cur $aff
}

Register-TRCheck -Id 'PUR-01' -Area 'Purview' -Category 'Microsoft Purview' -Severity Medium -Effort 6 `
    -Title 'Data loss prevention policies protect sensitive data' `
    -Needs @() `
    -Recommendation 'Create DLP policies for UK financial and personal data (for example bank details, National Insurance and passport numbers) across Exchange, SharePoint, OneDrive and Teams. Start in simulation mode with policy tips, review matches with the client, then block external sharing.' `
    -Reference 'https://learn.microsoft.com/purview/dlp-create-deploy-policy' `
    -Test {
    $g = Get-TRGate 'Dlp' 'Data loss prevention'
    if ($g) { return $g }
    if (-not (Test-TRCollected @('SccDlpPolicies'))) { return Get-TRPurviewFallback -Pattern 'DLP|[Dd]ata [Ll]oss [Pp]revention' -Keys @('SccDlpPolicies') }
    $pol = @(Get-TRItems 'SccDlpPolicies')
    $enforced = @($pol | Where-Object { $_.Enabled -ne $false -and [string]$_.Mode -eq 'Enable' })
    $test = @($pol | Where-Object { $_.Enabled -ne $false -and [string]$_.Mode -match '^Test' })
    $wl = @{}
    foreach ($p in $enforced) { foreach ($w in (Get-TRPolicyWorkloads $p)) { $wl[$w] = $true } }
    $core = @('Exchange', 'SharePoint', 'OneDrive')
    $missing = @($core | Where-Object { -not $wl.ContainsKey($_) })
    $cur = 'DLP policies: {0} ({1} enforced, {2} in simulation). Workloads with an enforced policy: {3}.' -f $pol.Count, $enforced.Count, $test.Count, $(if ($wl.Count) { (@($wl.Keys | Sort-Object) -join ', ') } else { 'none' })
    $aff = @($pol | ForEach-Object { New-TRAffected $_.Name ('{0}; {1}' -f $_.Mode, ((Get-TRPolicyWorkloads $_) -join ', ')) })
    if ($enforced.Count -and -not $missing.Count) { return New-TRResult Pass $cur $aff }
    if ($enforced.Count -or $test.Count) { return New-TRResult Warning $cur $aff }
    New-TRResult Fail ($cur + ' No DLP policy is protecting sensitive data.') $aff
}

Register-TRCheck -Id 'PUR-02' -Area 'Purview' -Category 'Microsoft Purview' -Severity Medium -Effort 3 `
    -Title 'Retention policies cover email, files and Teams' `
    -Needs @() `
    -Recommendation 'Agree retention periods with the client (for example 6 or 7 years for finance and HR records) and apply org-wide retention policies to Exchange, SharePoint, OneDrive and Teams so deleted or changed content can be recovered.' `
    -Reference 'https://learn.microsoft.com/purview/create-retention-policies' `
    -Test {
    $g = Get-TRGate 'Retention' 'Retention policies'
    if ($g) { return $g }
    if (-not (Test-TRCollected @('SccRetentionPolicies'))) { return Get-TRPurviewFallback -Pattern '[Rr]etention' -Keys @('SccRetentionPolicies') }
    $pol = @(Get-TRItems 'SccRetentionPolicies' | Where-Object { Test-TRPolicyActive $_ })
    $cover = [ordered]@{ 'Exchange' = $false; 'SharePoint' = $false; 'OneDrive' = $false; 'Teams' = $false; 'Microsoft 365 Groups' = $false }
    foreach ($p in $pol) {
        $adaptive = ($p.IsAdaptivePolicy -eq $true)
        $wl = @(Get-TRPolicyWorkloads $p)
        if ($p.ExchangeLocation -eq 'All' -or ($adaptive -and $wl -contains 'Exchange')) { $cover['Exchange'] = $true }
        if ($p.SharePointLocation -eq 'All' -or ($adaptive -and $wl -contains 'SharePoint')) { $cover['SharePoint'] = $true }
        if ($p.OneDriveLocation -eq 'All' -or ($adaptive -and $wl -contains 'OneDrive')) { $cover['OneDrive'] = $true }
        if ($p.TeamsChatLocation -eq 'All' -or $p.TeamsChannelLocation -eq 'All' -or ($adaptive -and $wl -contains 'Teams')) { $cover['Teams'] = $true }
        if ($p.ModernGroupLocation -eq 'All') { $cover['Microsoft 365 Groups'] = $true }
    }
    $rules = @(Get-TRItems 'SccRetentionRules')
    $covered = @($cover.Keys | Where-Object { $cover[$_] })
    $missing = @(@('Exchange', 'SharePoint', 'OneDrive', 'Teams') | Where-Object { -not $cover[$_] })
    $cur = 'Active retention policies: {0}. Covered org-wide: {1}. Not covered: {2}.' -f $pol.Count, $(if ($covered.Count) { $covered -join ', ' } else { 'none' }), $(if ($missing.Count) { $missing -join ', ' } else { 'none' })
    $aff = @($pol | ForEach-Object {
            $p = $_
            $r = @($rules | Where-Object { ($p.Guid -and [string]$_.Policy -eq [string]$p.Guid) -or [string]$_.ParentPolicyName -eq [string]$p.Name -or ($p.Identity -and [string]$_.Policy -eq [string]$p.Identity) }) | Select-Object -First 1
            $d = (Get-TRPolicyWorkloads $p) -join ', '
            if ($r) { $d = (Format-TRRetention $r) + '; ' + $d }
            New-TRAffected $p.Name $d
        })
    if (-not $missing.Count) { return New-TRResult Pass $cur $aff }
    if ($covered.Count) { return New-TRResult Warning $cur $aff }
    New-TRResult Fail $cur $aff
}

Register-TRCheck -Id 'PUR-03' -Area 'Purview' -Category 'Microsoft Purview' -Severity Medium -Effort 8 `
    -Title 'Sensitivity labels are defined and published' `
    -Needs @() `
    -Recommendation 'Agree a simple label taxonomy with the client (Public, Internal, Confidential, Highly confidential), add encryption and markings where needed, publish the labels with a default label and justification for downgrades, and enable labels for SharePoint and Teams sites.' `
    -Reference 'https://learn.microsoft.com/purview/get-started-with-sensitivity-labels' `
    -Test {
    $g = Get-TRGate 'InfoProtection' 'Sensitivity labelling (Information Protection)'
    if ($g) { return $g }
    if (-not (Test-TRCollected @('SccLabels', 'SccLabelPolicies'))) { return Get-TRPurviewFallback -Pattern '[Ss]ensitivity label' -Keys @('SccLabels', 'SccLabelPolicies') }
    $labels = @(Get-TRItems 'SccLabels' | Where-Object { $_.Disabled -ne $true })
    $enc = @($labels | Where-Object { $_.EncryptionEnabled -eq $true -or ((@($_.LabelActions) -join ' ') -match '"?[Tt]ype"?\s*:\s*"?encrypt') })
    $pol = @(Get-TRItems 'SccLabelPolicies' | Where-Object { Test-TRPolicyActive $_ })
    $settings = (@($pol | ForEach-Object { @($_.Settings) }) -join ' ').ToLower()
    $cur = 'Sensitivity labels: {0} ({1} with encryption). Active label policies: {2}.' -f $labels.Count, $enc.Count, $pol.Count
    if ($pol.Count) {
        $cur += (' Default label set: {0}. Mandatory labelling: {1}.' -f $(if ($settings -match 'defaultlabelid') { 'Yes' } else { 'No' }), $(if ($settings -match 'mandatory,\s*true') { 'Yes' } else { 'No' }))
    }
    $aff = @($labels | ForEach-Object { New-TRAffected $(if ($_.DisplayName) { $_.DisplayName } else { $_.Name }) ('Scope: {0}' -f $_.ContentType) })
    if (-not $labels.Count) { return New-TRResult Warning ($cur + ' No sensitivity labels are defined.') }
    if (-not $pol.Count) { return New-TRResult Warning ($cur + ' Labels exist but are not published to users.') $aff }
    New-TRResult Pass $cur $aff
}

Register-TRCheck -Id 'PUR-04' -Area 'Purview' -Category 'Microsoft Purview' -Severity Medium -Effort 1 `
    -Title 'Default alert policies are enabled and notify administrators' `
    -Needs 'SccAlertPolicies' `
    -Recommendation 'Re-enable disabled default alert policies and send high-severity alerts to a monitored support or client mailbox rather than individual administrators.' `
    -Reference 'https://learn.microsoft.com/purview/alert-policies' `
    -Test {
    $alerts = @(Get-TRItems 'SccAlertPolicies')
    $sys = @($alerts | Where-Object { $_.IsSystemRule -eq $true })
    $off = @($sys | Where-Object { $_.Disabled -eq $true })
    $silent = @($alerts | Where-Object { $_.Disabled -ne $true -and [string]$_.Severity -eq 'High' -and (@($_.NotifyUser | Where-Object { $_ }).Count -eq 0 -or $_.NotificationEnabled -eq $false) })
    $cur = 'Alert policies: {0} ({1} default). Disabled default policies: {2}. Enabled high-severity policies with no email notification: {3}.' -f $alerts.Count, $sys.Count, $off.Count, $silent.Count
    $aff = @(@($off | ForEach-Object { New-TRAffected $_.Name ('Disabled; {0} severity' -f $_.Severity) }) + @($silent | ForEach-Object { New-TRAffected $_.Name 'No email notification' }))
    if ($off.Count -or $silent.Count) { return New-TRResult Warning $cur $aff }
    New-TRResult Pass $cur
}

Register-TRCheck -Id 'PUR-05' -Area 'Purview' -Category 'Microsoft Purview' -Severity Info -Effort 0 `
    -Title 'Purview configuration summary' `
    -Needs @() `
    -Recommendation 'Use the Purview inventories to agree the client''s information protection and retention requirements.' `
    -Reference 'https://learn.microsoft.com/purview/purview' `
    -Test {
    $parts = New-Object System.Collections.ArrayList
    $notRead = New-Object System.Collections.ArrayList
    foreach ($k in @(@('SccDlpPolicies', 'DLP policies'), @('SccRetentionPolicies', 'retention policies'), @('SccLabels', 'sensitivity labels'), @('SccLabelPolicies', 'label policies'), @('SccAutoLabelPolicies', 'auto-labelling policies'), @('SccAlertPolicies', 'alert policies'), @('SccAuditRetention', 'audit retention policies'), @('SccInsiderRisk', 'insider risk policies'))) {
        $d = $script:TRDiagIndex[$k[0]]
        if (Test-TRCollected @($k[0])) { [void]$parts.Add(('{0} {1}' -f $k[1], @(Get-TRItems $k[0]).Count)) }
        elseif ($d -and $d.Status -ne 'Skipped') { [void]$notRead.Add($k[1]) }
    }
    if ($notRead.Count) { [void]$parts.Add(('not read: {0} (see Collection diagnostics)' -f (@($notRead) -join ', '))) }
    if (-not (Test-TRCollected @('SccDlpPolicies')) -and -not (Get-TRMeta 'PurviewAvailable')) { [void]$parts.Add(('Security & Compliance not reachable ({0})' -f (Get-TRMissingReason @('SccDlpPolicies')))) }
    if (Test-TRCollected @('RetentionLabels')) { [void]$parts.Add(('retention labels {0}' -f @(Get-TRItems 'RetentionLabels').Count)) }
    if (Test-TRCollected @('EdiscoveryCases')) { [void]$parts.Add(('eDiscovery cases {0}' -f @(Get-TRItems 'EdiscoveryCases').Count)) }
    $text = (@($parts) -join '; ') + '.'
    if ($text.Length -gt 1) { $text = $text.Substring(0, 1).ToUpper() + $text.Substring(1) }
    New-TRResult Info $text
}

Register-TRCheck -Id 'GOV-01' -Area 'Identity' -Category 'Governance' -Severity Medium -Effort 0 `
    -Title 'Microsoft 365 data is backed up' `
    -Needs @() `
    -Recommendation 'Confirm Exchange, OneDrive, SharePoint and Teams are protected by a third-party backup or Microsoft 365 Backup, with retention that meets the client''s requirements.' `
    -Reference 'https://learn.microsoft.com/microsoft-365/backup/backup-overview' `
    -Test { New-TRResult Manual 'Backup coverage cannot be read from the tenant. Confirm the backup product, scope and last successful run.' }

function Invoke-TRChecks {
    param([string[]]$Areas)
    $findings = New-Object System.Collections.ArrayList
    $platform = Get-TRPlatform
    foreach ($def in $script:TRCheckDefs) {
        if ($def.Platform -ne $platform -and $def.Platform -ne 'Any') { continue }
        if ($Areas -and ($Areas -notcontains $def.Area)) { continue }
        $res = $null
        if ($def.Needs.Count -and -not (Test-TRCollected $def.Needs)) {
            $res = New-TRResult NotAssessed ('Data not available. ' + (Get-TRMissingReason $def.Needs))
        }
        else {
            try {
                $res = & $def.Test
                if ($res -is [System.Array]) { $res = $res[-1] }
                if (-not $res) { $res = New-TRResult NotAssessed 'The check returned no result.' }
                if ($res.Status -eq 'Info' -and [string]$res.Current -match 'not licensed|Needs both' -and -not (Test-TRLicenceDataKnown)) { $res = New-TRResult NotAssessed ('The licences could not be read, so this could not be assessed. ' + (Get-TRMissingReason @($(if ($platform -eq 'Google') { 'GwsLicences' } else { 'SubscribedSkus' })))) }
            }
            catch {
                $res = New-TRResult NotAssessed ('The check could not be evaluated: ' + $_.Exception.Message)
            }
        }
        $priority = switch ($res.Status) {
            'Fail' { if ($def.Severity -eq 'High') { 'P1' } elseif ($def.Severity -eq 'Medium') { 'P2' } else { 'P3' } }
            'Warning' { if ($def.Severity -eq 'High') { 'P2' } else { 'P3' } }
            'Manual' { 'P3' }
            default { '' }
        }
        [void]$findings.Add([pscustomobject][ordered]@{
                Id             = $def.Id
                Area           = $def.Area
                Category       = $def.Category
                Title          = $def.Title
                Status         = $res.Status
                Severity       = $def.Severity
                Priority       = $priority
                Current        = $res.Current
                Recommendation = $def.Recommendation
                EffortHours    = $(if ($res.Status -in @('Fail', 'Warning')) { $def.Effort } else { 0 })
                Reference      = $def.Reference
                AffectedCount  = @($res.Affected).Count
                Affected       = @($res.Affected)
            })
    }
    , $findings.ToArray()
}
