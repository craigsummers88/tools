function Test-TRGwsEnforcedFrom {
    param($Value)
    $d = ConvertTo-TRDate $Value
    if ($null -eq $d) { return $false }
    ($d -gt [datetime]'1971-01-01') -and ($d -le (Get-TRNow))
}

$script:TRGwsCisAlertRules = [ordered]@{
    'User''s password changed'                  = 'MEDIUM'
    'Government-backed attacks'                 = 'HIGH'
    'User suspended due to suspicious activity' = 'HIGH'
    'User granted Admin privilege'              = 'MEDIUM'
    'Suspicious programmatic login'             = 'LOW'
    'Suspicious login'                          = 'LOW'
    'Leaked password'                           = 'MEDIUM'
    'Gmail potential employee spoofing'         = 'MEDIUM'
}

function Get-TRGwsAppAccessText {
    param([string]$Value)
    switch ($Value) {
        { $_ -in @('BLOCK_ALL', 'BLOCK_ALL_SCOPES') } { 'block all unconfigured apps' }
        { $_ -in @('ALLOW_SIGN_IN_ONLY', 'ALLOW_SIGN_IN_SCOPES_ONLY') } { 'allow Sign in with Google only' }
        default { 'allow any app' }
    }
}

function Get-TRGwsDays {
    param($Value)
    $d = ConvertTo-TRDate $Value
    if ($null -eq $d -or $d -lt [datetime]'1971-01-01') { return $null }
    [int]((Get-TRNow) - $d).TotalDays
}

function Test-TRGoogleMx {
    param($Row)
    $mx = @(Get-TRStrings $Row.Mx | ForEach-Object { (($_ -split '\s+')[-1]).TrimEnd('.').ToLower() })
    if (-not $mx.Count) { return 'None' }
    $g = @($mx | Where-Object { $_ -match '(^|\.)(google\.com|googlemail\.com)$' })
    if ($g.Count -eq $mx.Count) { return 'Google' }
    if ($g.Count) { return 'Mixed' }
    'Other'
}

function Get-TRGwsDnsRows { @(Get-TRItems 'GwsDnsRecords') }

function Get-TRGwsDkimBits {
    param($Row)
    $rec = (@(Get-TRStrings $Row.Dkim) -join '') -replace '"', '' -replace '\s', ''
    if ($rec -notmatch 'p=([A-Za-z0-9+/=]+)') { return 0 }
    $len = $Matches[1].Length
    if ($len -ge 360) { return 2048 }
    if ($len -ge 200) { return 1024 }
    512
}

function Get-TRGwsTokenRisk {
    param([string[]]$Scopes)
    $high = @($Scopes | Where-Object { $_ -match 'https://mail\.google\.com/|/auth/gmail\.(modify|compose|insert|send|settings)|/auth/drive$|/auth/drive\.readonly$|/auth/admin\.|/auth/cloud-platform$|/auth/ediscovery|/auth/apps\.groups\.settings|/auth/calendar$|/auth/contacts$|/auth/script\.' })
    $high
}

Register-TRCheck -Platform Google -Id 'GIAM-01' -Area 'Identity' -Category 'Identity and access' -Severity High -Effort 4 `
    -Title '2-Step Verification is enforced for all users' `
    -Needs 'GwsPolicies' `
    -Recommendation 'In Security, Authentication, 2-step verification, allow users to turn on 2SV and set Enforcement to On for the top-level organisational unit, with a new user enrolment period of one week. Remove any organisational unit or group that turns enforcement off.' `
    -Reference 'https://knowledge.workspace.google.com/admin/security/deploy-2-step-verification' `
    -Test {
    $en = Test-TRGwsPolicy -Type 'security.two_step_verification_enrollment' -Ok { param($s) Test-TRGwsTrue $s['allowEnrollment'] } -Good 'users can enrol in 2-Step Verification' -Bad 'users cannot enrol in 2-Step Verification'
    $ev = Test-TRGwsPolicy -Type 'security.two_step_verification_enforcement' -Ok { param($s) Test-TRGwsEnforcedFrom $s['enforcedFrom'] } -Good '2-Step Verification is enforced' -Bad '2-Step Verification is not enforced'
    if ($en.Status -eq 'Fail') { return New-TRResult Fail ($en.Text) $en.Affected }
    ConvertTo-TRGwsResult $ev
}

Register-TRCheck -Platform Google -Id 'GIAM-02' -Area 'Identity' -Category 'Identity and access' -Severity High -Effort 4 `
    -Title 'All active users are enrolled in 2-Step Verification' `
    -Needs 'GwsUsers' `
    -Recommendation 'Contact each user who has not enrolled and help them set up a passkey, security key or Google prompt. Enforcement blocks sign-in for anyone still not enrolled once the enrolment period ends.' `
    -Reference 'https://knowledge.workspace.google.com/admin/security/deploy-2-step-verification' `
    -Test {
    $users = @(Get-TRGwsEnabledUsers)
    if (-not $users.Count) { return New-TRResult NotAssessed 'No active users were returned.' }
    $bad = @($users | Where-Object { -not $_.isEnrolledIn2Sv })
    $pct = Get-TRPercent ($users.Count - $bad.Count) $users.Count
    $aff = @($bad | ForEach-Object { New-TRAffected ([string]$_.primaryEmail) $(if ($_.isAdmin) { 'Super admin, not enrolled' } else { 'Not enrolled' }) })
    if (-not $bad.Count) { return New-TRResult Pass ('All {0} active users are enrolled in 2-Step Verification.' -f $users.Count) }
    $admins = @($bad | Where-Object { $_.isAdmin })
    $text = '{0}% of active users are enrolled; {1} not enrolled{2}.' -f $pct, (Format-TRN $bad.Count 'user is' 'users are'), $(if ($admins.Count) { (', including {0}' -f (Format-TRN $admins.Count 'super admin')) } else { '' })
    if ($admins.Count -or $pct -lt 90) { return New-TRResult Fail $text $aff }
    New-TRResult Warning $text $aff
}

Register-TRCheck -Platform Google -Id 'GIAM-03' -Area 'Identity' -Category 'Identity and access' -Severity Medium -Effort 3 `
    -Title 'Text message and phone call codes are not allowed for 2-Step Verification' `
    -Needs 'GwsPolicies' `
    -Recommendation 'In 2-step verification settings, set Allowed methods to Any except verification codes via text, phone call, or to Only security key for administrators and high-risk users.' `
    -Reference 'https://knowledge.workspace.google.com/admin/security/deploy-2-step-verification' `
    -Test {
    $e = Test-TRGwsPolicy -Type 'security.two_step_verification_enforcement_factor' -Ok { param($s) [string]$s['allowedSignInFactorSet'] -ne 'ALL' } -Good 'text and voice codes are not allowed' -Bad 'any 2SV method, including text and voice codes, is allowed' -Detail { param($s) 'Allowed methods: ' + (Get-TRGwsFactorText ([string]$s['allowedSignInFactorSet'])) }
    ConvertTo-TRGwsResult $e -FailAs Warning
}

Register-TRCheck -Platform Google -Id 'GIAM-04' -Area 'Identity' -Category 'Identity and access' -Severity Medium -Effort 3 `
    -Title 'The password policy requires strong passwords of at least 12 characters' `
    -Needs 'GwsPolicies' `
    -Recommendation 'In Security, Authentication, Password management, require strong passwords with a minimum length of 12 (CISA recommends 16), enforce the policy at next sign-in, do not allow reuse and set expiry to Never.' `
    -Reference 'https://knowledge.workspace.google.com/admin/security/enforce-and-monitor-password-requirements-for-users' `
    -Test {
    $e = Test-TRGwsPolicy -Type 'security.password' -Ok { param($s) [string]$s['allowedStrength'] -eq 'STRONG' -and [int]$s['minimumLength'] -ge 12 -and (Test-TRGwsTrue $s['enforceRequirementsAtLogin']) -and -not (Test-TRGwsTrue $s['allowReuse']) -and (([double](ConvertTo-TRGwsSeconds $s['expirationDuration'])) -eq 0) } `
        -Good 'strong passwords of 12 or more characters are required, enforced at sign-in, with no reuse or expiry' -Bad 'the password policy falls short' `
        -Detail { param($s) $g = @(); if ([string]$s['allowedStrength'] -ne 'STRONG') { $g += 'strength ' + [string]$s['allowedStrength'] }; if ([int]$s['minimumLength'] -lt 12) { $g += 'minimum length ' + [string]$s['minimumLength'] }; if (-not (Test-TRGwsTrue $s['enforceRequirementsAtLogin'])) { $g += 'not enforced at next sign-in' }; if (Test-TRGwsTrue $s['allowReuse']) { $g += 'reuse allowed' }; $x = ConvertTo-TRGwsSeconds $s['expirationDuration']; if ($x -and $x -gt 0) { $g += 'expires after ' + (Format-TRGwsDuration $x) }; ($g -join '; ') }
    ConvertTo-TRGwsResult $e
}

Register-TRCheck -Platform Google -Id 'GIAM-05' -Area 'Identity' -Category 'Identity and access' -Severity Medium -Effort 2 `
    -Title 'No users have weak or short passwords' `
    -Needs 'GwsUserUsage' `
    -Recommendation 'Ask the listed users to change their password at next sign-in (Users, Reset password, Ask for a password change at the next sign-in) and turn on Enforce password policy at next sign-in.' `
    -Reference 'https://knowledge.workspace.google.com/admin/security/enforce-and-monitor-password-requirements-for-users' `
    -Test {
    $users = Get-TRGwsUserIndex
    $bad = @(Get-TRItems 'GwsUserUsage' | Where-Object {
            $u = $users[([string]$_.Email).ToLower()]
            $u -and -not $u.suspended -and (([string]$_.accounts_password_strength -eq 'WEAK') -or ([string]$_.accounts_password_length_compliance -eq 'NON_COMPLIANT'))
        })
    if (-not $bad.Count) { return New-TRResult Pass 'No active user has a password Google rates as weak or shorter than the policy.' }
    New-TRResult Warning ('{0} a weak password or one shorter than the current policy.' -f (Format-TRN $bad.Count 'user has' 'users have')) (@($bad | ForEach-Object { New-TRAffected $_.Email ((@($(if ($_.accounts_password_strength -eq 'WEAK') { 'Weak' }), $(if ($_.accounts_password_length_compliance -eq 'NON_COMPLIANT') { 'Shorter than policy' })) | Where-Object { $_ }) -join ', ') }))
}

Register-TRCheck -Platform Google -Id 'GIAM-06' -Area 'Identity' -Category 'Identity and access' -Severity Medium -Effort 1 `
    -Title 'Web sessions require sign-in again within 12 hours' `
    -Needs 'GwsPolicies' `
    -Recommendation 'In Security, Access and data control, Google session control, set Web session duration to 12 hours or less.' `
    -Reference 'https://knowledge.workspace.google.com/admin/security/set-session-length-for-google-services' `
    -Test {
    $s = Get-TRGwsSetting 'security.session_controls'
    $e = Test-TRGwsPolicy -Type 'security.session_controls' -Ok { param($x) $v = ConvertTo-TRGwsSeconds $x['webSessionDuration']; $null -ne $v -and $v -le 43200 } -Good 'sessions last 12 hours or less' -Bad 'web sessions last longer than 12 hours' -Detail { param($x) 'Session length ' + (Format-TRGwsDuration (ConvertTo-TRGwsSeconds $x['webSessionDuration'])) }
    if ($e.Status -eq 'Unknown' -and -not $s.Known) { return New-TRResult Warning 'No session length policy was returned, so the Google default of 14 days applies.' }
    ConvertTo-TRGwsResult $e -FailAs Warning
}

Register-TRCheck -Platform Google -Id 'GIAM-07' -Area 'Identity' -Category 'Identity and access' -Severity Medium -Effort 2 `
    -Title 'Licensed users have signed in recently' `
    -Needs 'GwsUsers', 'GwsLicences' `
    -Recommendation 'Suspend or delete accounts that are no longer used and remove their licences. Use Archived User licences for leavers whose data must be kept.' `
    -Reference 'https://knowledge.workspace.google.com/admin/users/suspend-a-users-account' `
    -Test {
    $days = [int](Get-TRSetting 'InactiveDays' 90)
    $lic = Get-TRGwsUserLicences
    $bad = foreach ($u in (Get-TRGwsEnabledUsers)) {
        if (-not $lic.ContainsKey(([string]$u.primaryEmail).ToLower())) { continue }
        $age = Get-TRGwsDays $u.lastLoginTime
        $created = Get-TRGwsDays $u.creationTime
        if ($null -eq $age -and $created -gt 30) { New-TRAffected ([string]$u.primaryEmail) ('Never signed in; created ' + (Format-TRDate $u.creationTime)) }
        elseif ($null -ne $age -and $age -gt $days) { New-TRAffected ([string]$u.primaryEmail) ('Last sign-in ' + (Format-TRDate $u.lastLoginTime)) }
    }
    $bad = @($bad)
    if (-not $bad.Count) { return New-TRResult Pass ('Every licensed active user has signed in within {0} days.' -f $days) }
    New-TRResult Warning ('{0} not signed in for more than {1} days or never.' -f (Format-TRN $bad.Count 'licensed user has' 'licensed users have'), $days) $bad
}

Register-TRCheck -Platform Google -Id 'GIAM-08' -Area 'Identity' -Category 'Identity and access' -Severity Medium -Effort 1 `
    -Title 'App passwords are not in use' `
    -Needs 'GwsAsps' `
    -Recommendation 'Revoke app passwords (Users, Security, App passwords) and move the devices or apps to OAuth sign-in. App passwords bypass 2-Step Verification.' `
    -Reference 'https://knowledge.workspace.google.com/admin/security/manage-app-passwords' `
    -Test {
    $a = @(Get-TRItems 'GwsAsps')
    if (-not $a.Count) { return New-TRResult Pass 'No app passwords were found.' }
    New-TRResult Warning ('{0} found across {1}.' -f (Format-TRN $a.Count 'app password'), (Format-TRN @($a | Select-Object -ExpandProperty User -Unique).Count 'user')) (@($a | ForEach-Object { New-TRAffected $_.User ('{0}; last used {1}' -f $_.Name, $(if ($_.LastUsed -and [long]$_.LastUsed -gt 0) { Format-TRDate ([datetime]::new(1970, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)).AddMilliseconds([long]$_.LastUsed) } else { 'never' })) }))
}

Register-TRCheck -Platform Google -Id 'GIAM-09' -Area 'Identity' -Category 'Identity and access' -Severity Medium -Effort 1 `
    -Title 'Less secure app access is turned off' `
    -Needs 'GwsPolicies' `
    -Recommendation 'In Security, Access and data control, Less secure apps, select Disable access to less secure apps for all users.' `
    -Reference 'https://knowledge.workspace.google.com/admin/security/control-access-to-less-secure-apps' `
    -Test {
    ConvertTo-TRGwsResult (Test-TRGwsPolicy -Type 'security.less_secure_apps' -Ok { param($s) -not (Test-TRGwsTrue $s['allowLessSecureApps']) } -Good 'less secure app access is off' -Bad 'users can allow less secure apps')
}

Register-TRCheck -Platform Google -Id 'GIAM-10' -Area 'Identity' -Category 'Identity and access' -Severity Low -Effort 1 `
    -Title 'Users cannot skip 2-Step Verification on trusted devices' `
    -Needs 'GwsPolicies' `
    -Recommendation 'In 2-step verification settings, untick Allow user to trust the device so every sign-in is challenged.' `
    -Reference 'https://knowledge.workspace.google.com/admin/security/deploy-2-step-verification' `
    -Test {
    ConvertTo-TRGwsResult (Test-TRGwsPolicy -Type 'security.two_step_verification_device_trust' -Ok { param($s) -not (Test-TRGwsTrue $s['allowTrustingDevice']) } -Good 'trusting a device is not allowed' -Bad 'users can trust a device and skip 2SV on it') -FailAs Warning
}

Register-TRCheck -Platform Google -Id 'GIAM-11' -Area 'Identity' -Category 'Identity and access' -Severity Low -Effort 1 `
    -Title 'Unmanaged accounts using company domains are taken over' `
    -Needs 'GwsPolicies' `
    -Recommendation 'In Account settings, Unmanaged accounts, choose Replace conflicting unmanaged accounts with managed ones, so personal Google accounts on the company domain are brought under management.' `
    -Reference 'https://knowledge.workspace.google.com/admin/users/find-and-manage-unmanaged-accounts' `
    -Test {
    ConvertTo-TRGwsResult (Test-TRGwsPolicy -Type 'provisioning.conflicting_accounts_management' -Ok { param($s) $v = [string]$(if ($s['conflictingAccountsManagement']) { $s['conflictingAccountsManagement'] } else { $s['option'] }); $v -eq 'REPLACE_CONFLICTING_ACCOUNT' } -Good 'conflicting unmanaged accounts are replaced' -Bad 'conflicting unmanaged accounts are not replaced automatically') -FailAs Warning
}

Register-TRCheck -Platform Google -Id 'GIAM-12' -Area 'Identity' -Category 'Identity and access' -Severity Low -Effort 1 `
    -Title 'Recovery email addresses are not personal accounts' `
    -Needs 'GwsUsers' `
    -Recommendation 'Remove personal recovery email addresses from user accounts, or use a company-controlled address. Attackers who control a personal mailbox can use it to recover the work account.' `
    -Reference 'https://knowledge.workspace.google.com/admin/users/let-users-recover-their-own-passwords' `
    -Test {
    $bad = @(Get-TRGwsEnabledUsers | Where-Object { $_.recoveryEmail -and -not (Test-TRGwsInternal ([string]$_.recoveryEmail)) })
    if (-not $bad.Count) { return New-TRResult Pass 'No active user has an external recovery email address.' }
    New-TRResult Info ('{0} a recovery email outside the organisation.' -f (Format-TRN $bad.Count 'user has' 'users have')) (@($bad | ForEach-Object { New-TRAffected ([string]$_.primaryEmail) ('Recovery: ' + [string]$_.recoveryEmail) }))
}

Register-TRCheck -Platform Google -Id 'GIAM-13' -Area 'Identity' -Category 'Identity and access' -Severity Low -Effort 4 `
    -Title 'Users are organised into organisational units' `
    -Needs 'GwsUsers', 'GwsOrgUnits' `
    -Recommendation 'Create organisational units (for example Staff, Admins, Shared accounts, Leavers) so settings such as 2SV enforcement, Drive sharing and device rules can be tuned without changing them for everyone.' `
    -Reference 'https://knowledge.workspace.google.com/admin/users/how-the-organizational-structure-works' `
    -Test {
    $users = @(Get-TRGwsEnabledUsers)
    $root = @($users | Where-Object { [string]$_.orgUnitPath -eq '/' })
    $ous = @(Get-TRItems 'GwsOrgUnits' | Where-Object { [string]$_.orgUnitPath -ne '/' })
    if ($users.Count -ge 10 -and $root.Count -eq $users.Count) { return New-TRResult Info ('All {0} active users sit in the top-level organisational unit, so every setting applies to everyone.' -f $users.Count) }
    New-TRResult Pass ('{0}; {1} in the top-level unit.' -f (Format-TRN $ous.Count 'organisational unit'), (Format-TRN $root.Count 'user'))
}

Register-TRCheck -Platform Google -Id 'GIAM-14' -Area 'Identity' -Category 'Identity and access' -Severity Low -Effort 1 `
    -Title 'Users have signed in at least once' `
    -Needs 'GwsUsers' `
    -Recommendation 'Review accounts created more than 30 days ago that have never been used. Delete them, or suspend them if they are kept for a reason.' `
    -Reference 'https://knowledge.workspace.google.com/admin/users/suspend-a-users-account' `
    -Test {
    $bad = @(Get-TRGwsEnabledUsers | Where-Object { $null -eq (Get-TRGwsDays $_.lastLoginTime) -and (Get-TRGwsDays $_.creationTime) -gt 30 })
    if (-not $bad.Count) { return New-TRResult Pass 'Every active account older than 30 days has signed in.' }
    New-TRResult Info ('{0} never signed in.' -f (Format-TRN $bad.Count 'active account has' 'active accounts have')) (@($bad | ForEach-Object { New-TRAffected ([string]$_.primaryEmail) ('Created ' + (Format-TRDate $_.creationTime)) }))
}

Register-TRCheck -Platform Google -Id 'GPRV-01' -Area 'Identity' -Category 'Privileged access' -Severity High -Effort 2 `
    -Title 'Between two and four super admins' `
    -Needs 'GwsUsers' `
    -Recommendation 'Keep two to four super admin accounts, ideally separate admin-only accounts. Use narrower admin roles (User Management, Groups, Help Desk) for day-to-day administration.' `
    -Reference 'https://knowledge.workspace.google.com/admin/security/security-best-practices-for-administrator-accounts' `
    -Test {
    $sa = @(Get-TRGwsSuperAdmins)
    $aff = @($sa | ForEach-Object { New-TRAffected ([string]$_.primaryEmail) 'Super admin' })
    if ($sa.Count -lt 2) { return New-TRResult Fail ('{0}. With one super admin there is no way back in if it is lost or locked out.' -f (Format-TRN $sa.Count 'super admin')) $aff }
    if ($sa.Count -gt 4) { return New-TRResult Warning ('{0}: {1}.' -f (Format-TRN $sa.Count 'super admin'), (Join-TRList ($sa | ForEach-Object { $_.primaryEmail }) 6)) $aff }
    New-TRResult Pass ('{0}: {1}.' -f (Format-TRN $sa.Count 'super admin'), (Join-TRList ($sa | ForEach-Object { $_.primaryEmail }) 4))
}

Register-TRCheck -Platform Google -Id 'GPRV-02' -Area 'Identity' -Category 'Privileged access' -Severity High -Effort 2 `
    -Title 'Super admins use security keys or passkeys' `
    -Needs 'GwsUsers', 'GwsUserUsage' `
    -Recommendation 'Enrol a security key or passkey for every super admin, then put admins in an organisational unit or group whose 2SV method is Only security key. Enrol them in the Advanced Protection Program.' `
    -Reference 'https://knowledge.workspace.google.com/admin/security/security-best-practices-for-administrator-accounts' `
    -Test {
    $usage = Get-TRGwsUsage
    $bad = foreach ($u in (Get-TRGwsSuperAdmins)) {
        $x = $usage[([string]$u.primaryEmail).ToLower()]
        $keys = if ($x) { [long]$x.accounts_num_security_keys + [long]$x.accounts_num_passkeys_enrolled } else { 0 }
        if (-not $u.isEnrolledIn2Sv) { New-TRAffected ([string]$u.primaryEmail) 'Not enrolled in 2SV' }
        elseif ($x -and $keys -eq 0) { New-TRAffected ([string]$u.primaryEmail) 'No security key or passkey' }
    }
    $bad = @($bad)
    if (-not $bad.Count) { return New-TRResult Pass 'Every super admin has a security key or passkey enrolled.' }
    $no2sv = @($bad | Where-Object { $_.Detail -eq 'Not enrolled in 2SV' })
    New-TRResult $(if ($no2sv.Count) { 'Fail' } else { 'Warning' }) ('{0} without a phishing-resistant sign-in method{1}.' -f (Format-TRN $bad.Count 'super admin is' 'super admins are'), $(if ($no2sv.Count) { (', {0} not enrolled in 2SV at all' -f $no2sv.Count) } else { '' })) $bad
}

Register-TRCheck -Platform Google -Id 'GPRV-03' -Area 'Identity' -Category 'Privileged access' -Severity Medium -Effort 3 `
    -Title 'Super admin accounts are not used for everyday email' `
    -Needs 'GwsUsers', 'GwsUserUsage' `
    -Recommendation 'Give each administrator a separate admin-only account without day-to-day email, and remove super admin from the accounts they use for email and browsing.' `
    -Reference 'https://knowledge.workspace.google.com/admin/security/security-best-practices-for-administrator-accounts' `
    -Test {
    $usage = Get-TRGwsUsage
    $bad = foreach ($u in (Get-TRGwsSuperAdmins)) {
        $x = $usage[([string]$u.primaryEmail).ToLower()]
        if ($x -and [long]$x.gmail_num_emails_sent -gt 0) { New-TRAffected ([string]$u.primaryEmail) ('Sent {0} on the report day' -f (Format-TRN ([int]$x.gmail_num_emails_sent) 'email')) }
    }
    $bad = @($bad)
    if (-not $bad.Count) { return New-TRResult Pass 'No super admin sent email on the most recent report day.' }
    New-TRResult Warning ('{0} for day-to-day email.' -f (Format-TRN $bad.Count 'super admin appears to be used' 'super admins appear to be used')) $bad
}

Register-TRCheck -Platform Google -Id 'GPRV-04' -Area 'Identity' -Category 'Privileged access' -Severity Medium -Effort 1 `
    -Title 'Super admins cannot recover their own accounts' `
    -Needs 'GwsPolicies' `
    -Recommendation 'In Security, Authentication, Account recovery, untick Allow super admins to recover their account. Recovery should go through another super admin.' `
    -Reference 'https://knowledge.workspace.google.com/admin/security/set-up-self-service-password-recovery-for-super-administrators' `
    -Test {
    ConvertTo-TRGwsResult (Test-TRGwsPolicy -Type 'security.super_admin_account_recovery' -Ok { param($s) -not (Test-TRGwsTrue $s['enableAccountRecovery']) } -Good 'super admin self-recovery is off' -Bad 'super admins can recover their own accounts by email or phone') -FailAs Warning
}

Register-TRCheck -Platform Google -Id 'GPRV-05' -Area 'Identity' -Category 'Privileged access' -Severity Medium -Effort 1 `
    -Title 'Admin roles are not held by suspended or inactive accounts' `
    -Needs 'GwsUsers', 'GwsRoleAssignments', 'GwsRoles' `
    -Recommendation 'Remove admin roles from suspended accounts and from accounts that have not signed in for 90 days.' `
    -Reference 'https://knowledge.workspace.google.com/admin/users/assign-specific-admin-roles' `
    -Test {
    $days = [int](Get-TRSetting 'InactiveDays' 90)
    $users = Get-TRGwsUserIndex
    $bad = foreach ($r in (Get-TRGwsRoleRows)) {
        if ($r.AssigneeType -ne 'USER') { continue }
        $u = $users['id:' + $r.AssignedTo]
        if (-not $u) { continue }
        $age = Get-TRGwsDays $u.lastLoginTime
        if ($u.suspended) { New-TRAffected $r.Email ($r.Role + '; suspended') }
        elseif ($null -eq $age -or $age -gt $days) { New-TRAffected $r.Email ($r.Role + $(if ($null -eq $age) { '; never signed in' } else { '; last sign-in ' + (Format-TRDate $u.lastLoginTime) })) }
    }
    $bad = @($bad)
    if (-not $bad.Count) { return New-TRResult Pass 'Every admin role is held by an active account that signs in.' }
    New-TRResult Warning ('{0} held by suspended or inactive accounts.' -f (Format-TRN $bad.Count 'admin role assignment is' 'admin role assignments are')) $bad
}

Register-TRCheck -Platform Google -Id 'GPRV-06' -Area 'Identity' -Category 'Privileged access' -Severity Low -Effort 1 `
    -Title 'Highly privileged roles are limited' `
    -Needs 'GwsRoleAssignments', 'GwsRoles' `
    -Recommendation 'Review who holds roles that can manage users, passwords, security settings, groups or services, and remove any that are not needed.' `
    -Reference 'https://knowledge.workspace.google.com/admin/users/pre-built-administrator-roles' `
    -Test {
    $priv = Get-TRGwsPrivilegedUsers
    $other = @($priv.Keys | Where-Object { $priv[$_] -ne 'Super Admin' })
    $aff = @($priv.Keys | Sort-Object | ForEach-Object { New-TRAffected $_ $priv[$_] })
    New-TRResult Info ('{0} with super admin or another highly privileged role ({1} super admins, {2} other).' -f (Format-TRN $priv.Count 'account'), ($priv.Count - $other.Count), $other.Count) $aff
}

Register-TRCheck -Platform Google -Id 'GAPP-01' -Area 'Applications' -Category 'Applications' -Severity High -Effort 3 `
    -Title 'Users cannot grant unreviewed third-party apps access to company data' `
    -Needs 'GwsPolicies' `
    -Recommendation 'In Security, API controls, set Unconfigured third-party apps to Don''t allow users to access any third-party apps (or allow sign-in only), then mark the apps the business uses as Trusted or Limited.' `
    -Reference 'https://knowledge.workspace.google.com/admin/apps/control-which-third-party-and-internal-apps-access-google-workspace-data' `
    -Test {
    $e = Test-TRGwsPolicy -Type 'api_controls.unconfigured_third_party_apps' -Ok { param($s) [string]$s['accessLevel'] -in @('BLOCK_ALL', 'BLOCK_ALL_SCOPES', 'ALLOW_SIGN_IN_ONLY', 'ALLOW_SIGN_IN_SCOPES_ONLY') } -Good 'unconfigured third-party apps are blocked or limited to Sign in with Google' -Bad 'users can grant any unconfigured third-party app access to their data' -Detail { param($s) 'Access level: ' + (Get-TRGwsAppAccessText ([string]$s['accessLevel'])) }
    if ($e.Status -eq 'Unknown') { return New-TRResult Warning 'No restriction on unconfigured third-party apps was returned, so users can most likely grant any app access to their data. Confirm in API controls.' }
    ConvertTo-TRGwsResult $e
}

Register-TRCheck -Platform Google -Id 'GAPP-02' -Area 'Applications' -Category 'Applications' -Severity High -Effort 3 `
    -Title 'Third-party apps with access to mail, files or admin data are reviewed' `
    -Needs 'GwsTokens' `
    -Recommendation 'Review each app below with the client. Remove the ones that are unknown or unused (Security, API controls, App access control) and mark approved ones as Trusted or Limited.' `
    -Reference 'https://knowledge.workspace.google.com/admin/apps/control-which-third-party-and-internal-apps-access-google-workspace-data' `
    -Test {
    $t = @(Get-TRItems 'GwsTokens' | Where-Object { -not $_.NativeApp -and @(Get-TRGwsTokenRisk @($_.Scopes)).Count })
    if (-not $t.Count) { return New-TRResult Pass 'No third-party app has been granted access to mail, all Drive files or admin data.' }
    $apps = @($t | Group-Object App | Sort-Object Count -Descending)
    New-TRResult Warning ('{0} with high-impact access, granted by {1}.' -f (Format-TRN $apps.Count 'third-party app'), (Format-TRN @($t | Select-Object -ExpandProperty User -Unique).Count 'user')) (@($apps | ForEach-Object { New-TRAffected $_.Name ('{0}; {1}' -f (Format-TRN $_.Count 'user'), (Join-TRList (@(Get-TRGwsTokenRisk @($_.Group[0].Scopes)) | ForEach-Object { $_ -replace '^https://www\.googleapis\.com/auth/', '' }) 3)) }))
}

Register-TRCheck -Platform Google -Id 'GAPP-03' -Area 'Applications' -Category 'Applications' -Severity Medium -Effort 2 `
    -Title 'Only approved Marketplace apps can be installed' `
    -Needs 'GwsPolicies' `
    -Recommendation 'In Apps, Google Workspace Marketplace apps, Settings, choose Allow users to install and run only allowlisted apps, and add the approved apps to the allowlist.' `
    -Reference 'https://knowledge.workspace.google.com/admin/apps/manage-google-workspace-marketplace-apps-in-your-allowlist' `
    -Test {
    ConvertTo-TRGwsResult (Test-TRGwsPolicy -Type 'workspace_marketplace.apps_access_options' -Ok { param($s) [string]$s['accessLevel'] -in @('ALLOW_LISTED_APPS', 'ALLOW_NONE') } -Good 'only allowlisted Marketplace apps can be installed' -Bad 'users can install any Marketplace app' -Detail { param($s) 'Access level: ' + [string]$s['accessLevel'] }) -FailAs Warning
}

Register-TRCheck -Platform Google -Id 'GAPP-04' -Area 'Applications' -Category 'Applications' -Severity Low -Effort 1 `
    -Title 'Internal apps are not trusted automatically' `
    -Needs 'GwsPolicies' `
    -Recommendation 'In API controls, untick Trust internal, domain-owned apps unless every internal app has been reviewed; trust specific internal apps instead.' `
    -Reference 'https://knowledge.workspace.google.com/admin/apps/control-which-third-party-and-internal-apps-access-google-workspace-data' `
    -Test {
    $e = Test-TRGwsPolicy -Type 'api_controls.internal_apps' -Ok { param($s) -not (Test-TRGwsTrue $s['trustInternalApps']) } -Good 'internal apps are not trusted automatically' -Bad 'all internal, domain-owned apps are trusted automatically'
    if ($e.Status -eq 'Unknown') { return New-TRResult Info 'The internal apps setting was not returned by the Policy API.' }
    ConvertTo-TRGwsResult $e -FailAs Warning
}

Register-TRCheck -Platform Google -Id 'GAPP-05' -Area 'Applications' -Category 'Applications' -Severity Info -Effort 0 `
    -Title 'Third-party apps in use' `
    -Needs 'GwsTokens' `
    -Recommendation 'Use this list to agree with the client which apps should be trusted, limited or blocked in API controls.' `
    -Reference 'https://knowledge.workspace.google.com/admin/apps/control-which-third-party-and-internal-apps-access-google-workspace-data' `
    -Test {
    $t = @(Get-TRItems 'GwsTokens' | Where-Object { -not $_.NativeApp })
    $apps = @($t | Group-Object App | Sort-Object Count -Descending)
    New-TRResult Info ('{0} granted access by {1}.' -f (Format-TRN $apps.Count 'third-party app'), (Format-TRN @($t | Select-Object -ExpandProperty User -Unique).Count 'user')) (@($apps | ForEach-Object { New-TRAffected $_.Name (Format-TRN $_.Count 'user') }))
}

Register-TRCheck -Platform Google -Id 'GLIC-01' -Area 'Licensing' -Category 'Licensing' -Severity Medium -Effort 1 `
    -Title 'Suspended users do not hold paid licences' `
    -Needs 'GwsUsers', 'GwsLicences' `
    -Recommendation 'Remove licences from suspended users, or switch leavers whose data must be kept to Archived User licences. On a flexible plan this reduces the bill straight away.' `
    -Reference 'https://knowledge.workspace.google.com/admin/billing/remove-licenses-from-users' `
    -Test {
    $lic = Get-TRGwsUserLicences
    $bad = @(Get-TRItems 'GwsUsers' | Where-Object { $_.suspended -and -not $_.archived -and $lic.ContainsKey(([string]$_.primaryEmail).ToLower()) })
    if (-not $bad.Count) { return New-TRResult Pass 'No suspended user holds a licence.' }
    New-TRResult Warning ('{0} still licensed.' -f (Format-TRN $bad.Count 'suspended user is' 'suspended users are')) (@($bad | ForEach-Object { New-TRAffected ([string]$_.primaryEmail) ((@($lic[([string]$_.primaryEmail).ToLower()] | ForEach-Object { Get-TRGwsSkuName $_ }) -join ', ')) }))
}

Register-TRCheck -Platform Google -Id 'GLIC-02' -Area 'Licensing' -Category 'Licensing' -Severity Medium -Effort 1 `
    -Title 'Active users have a Google Workspace licence' `
    -Needs 'GwsUsers', 'GwsLicences' `
    -Recommendation 'Assign a licence to each active user who needs Workspace services, or suspend the account. Unlicensed users lose access to Gmail, Drive and Meet.' `
    -Reference 'https://knowledge.workspace.google.com/admin/billing/assign-a-license-to-a-user' `
    -Test {
    $lic = Get-TRGwsUserLicences
    $core = @{}
    foreach ($s in $script:TRGwsCapabilities['Workspace']) { $core[$s] = $true }
    $bad = @(Get-TRGwsEnabledUsers | Where-Object { $l = $lic[([string]$_.primaryEmail).ToLower()]; -not $l -or -not @($l | Where-Object { $core.ContainsKey($_) }).Count })
    if (-not $bad.Count) { return New-TRResult Pass 'Every active user has a Google Workspace licence.' }
    New-TRResult Warning ('{0} without a Google Workspace edition licence.' -f (Format-TRN $bad.Count 'active user is' 'active users are')) (@($bad | ForEach-Object { New-TRAffected ([string]$_.primaryEmail) $(if ($_.isMailboxSetup) { 'Mailbox set up, no edition licence' } else { 'No edition licence' }) }))
}

Register-TRCheck -Platform Google -Id 'GLIC-03' -Area 'Licensing' -Category 'Licensing' -Severity Info -Effort 0 `
    -Title 'Licences assigned' `
    -Needs 'GwsLicences' `
    -Recommendation 'Compare these numbers with the subscription in Billing. Unassigned seats on an annual plan are paid for but unused.' `
    -Reference 'https://knowledge.workspace.google.com/admin/billing/see-your-subscriptions' `
    -Test {
    $c = Get-TRGwsSkuCounts
    if (-not $c.Count) { return New-TRResult Info 'No licence assignments were returned.' }
    New-TRResult Info ((@($c.Keys | Sort-Object @{ e = { -$c[$_] } }, @{ e = { Get-TRGwsSkuName $_ } } | ForEach-Object { '{0} {1}' -f $c[$_], (Get-TRGwsSkuName $_) }) -join '; ') + '.') (@($c.Keys | Sort-Object @{ e = { -$c[$_] } }, @{ e = { Get-TRGwsSkuName $_ } } | ForEach-Object { New-TRAffected (Get-TRGwsSkuName $_) (Format-TRN $c[$_] 'user') }))
}

Register-TRCheck -Platform Google -Id 'GMAIL-01' -Area 'Gmail' -Category 'Gmail' -Severity High -Effort 1 `
    -Title 'Spoofing and authentication protections are on' `
    -Needs 'GwsPolicies' `
    -Recommendation 'In Gmail, Safety, Spoofing and authentication, turn on all five protections (similar domain names, employee names, inbound domain spoofing, unauthenticated email, groups) with the action Move email to spam or Quarantine, and apply future recommended settings automatically.' `
    -Reference 'https://knowledge.workspace.google.com/admin/gmail/advanced-phishing-and-malware-protection' `
    -Test {
    $e = Test-TRGwsPolicy -Type 'gmail.spoofing_and_authentication' -Ok { param($s) (Test-TRGwsTrue $s['detectDomainNameSpoofing']) -and (Test-TRGwsTrue $s['detectEmployeeNameSpoofing']) -and (Test-TRGwsTrue $s['detectDomainSpoofingFromUnauthenticatedSenders']) -and (Test-TRGwsTrue $s['detectUnauthenticatedEmails']) -and (Test-TRGwsTrue $s['detectGroupsSpoofing']) } `
        -Good 'all spoofing and authentication protections are on' -Bad 'some spoofing protections are off' `
        -Detail { param($s) $m = [ordered]@{ detectDomainNameSpoofing = 'similar domain names'; detectEmployeeNameSpoofing = 'employee names'; detectDomainSpoofingFromUnauthenticatedSenders = 'inbound domain spoofing'; detectUnauthenticatedEmails = 'unauthenticated email'; detectGroupsSpoofing = 'groups' }; 'Off: ' + ((@($m.Keys | Where-Object { -not (Test-TRGwsTrue $s[$_]) } | ForEach-Object { $m[$_] })) -join ', ') }
    ConvertTo-TRGwsResult $e
}

Register-TRCheck -Platform Google -Id 'GMAIL-02' -Area 'Gmail' -Category 'Gmail' -Severity Medium -Effort 1 `
    -Title 'Attachment protections are on' `
    -Needs 'GwsPolicies' `
    -Recommendation 'In Gmail, Safety, Attachments, turn on protection against encrypted attachments, attachments with scripts and anomalous attachment types, with the action Move email to spam or Quarantine, and apply future recommended settings automatically.' `
    -Reference 'https://knowledge.workspace.google.com/admin/gmail/advanced-phishing-and-malware-protection' `
    -Test {
    $e = Test-TRGwsPolicy -Type 'gmail.email_attachment_safety' -Ok { param($s) (Test-TRGwsTrue $s['enableEncryptedAttachmentProtection']) -and (Test-TRGwsTrue $s['enableAttachmentWithScriptsProtection']) -and (Test-TRGwsTrue $s['enableAnomalousAttachmentProtection']) } `
        -Good 'all attachment protections are on' -Bad 'some attachment protections are off' `
        -Detail { param($s) $m = [ordered]@{ enableEncryptedAttachmentProtection = 'encrypted attachments'; enableAttachmentWithScriptsProtection = 'attachments with scripts'; enableAnomalousAttachmentProtection = 'anomalous attachment types' }; 'Off: ' + ((@($m.Keys | Where-Object { -not (Test-TRGwsTrue $s[$_]) } | ForEach-Object { $m[$_] })) -join ', ') }
    ConvertTo-TRGwsResult $e
}

Register-TRCheck -Platform Google -Id 'GMAIL-03' -Area 'Gmail' -Category 'Gmail' -Severity Medium -Effort 1 `
    -Title 'Link and image protections are on' `
    -Needs 'GwsPolicies' `
    -Recommendation 'In Gmail, Safety, Links and external images, turn on identifying links behind shortened URLs, scanning linked images and the warning prompt for links to untrusted domains.' `
    -Reference 'https://knowledge.workspace.google.com/admin/gmail/advanced-phishing-and-malware-protection' `
    -Test {
    $e = Test-TRGwsPolicy -Type 'gmail.links_and_external_images' -Ok { param($s) (Test-TRGwsTrue $s['enableShortenerScanning']) -and (Test-TRGwsTrue $s['enableExternalImageScanning']) -and (Test-TRGwsTrue $s['enableAggressiveWarningsOnUntrustedLinks']) } `
        -Good 'all link and image protections are on' -Bad 'some link and image protections are off' `
        -Detail { param($s) $m = [ordered]@{ enableShortenerScanning = 'shortened URLs'; enableExternalImageScanning = 'linked images'; enableAggressiveWarningsOnUntrustedLinks = 'untrusted link warnings' }; 'Off: ' + ((@($m.Keys | Where-Object { -not (Test-TRGwsTrue $s[$_]) } | ForEach-Object { $m[$_] })) -join ', ') }
    ConvertTo-TRGwsResult $e -FailAs Warning
}

Register-TRCheck -Platform Google -Id 'GMAIL-04' -Area 'Gmail' -Category 'Gmail' -Severity Medium -Effort 1 `
    -Title 'Enhanced pre-delivery message scanning is on' `
    -Needs 'GwsPolicies' `
    -Recommendation 'In Gmail, Spam, phishing and malware, turn on Enhanced pre-delivery message scanning.' `
    -Reference 'https://knowledge.workspace.google.com/admin/gmail/use-enhanced-pre-delivery-message-scanning-to-improve-phishing-detection' `
    -Test {
    ConvertTo-TRGwsResult (Test-TRGwsPolicy -Type 'gmail.enhanced_pre_delivery_message_scanning' -Ok { param($s) Test-TRGwsTrue $s['enableImprovedSuspiciousContentDetection'] } -Good 'enhanced pre-delivery scanning is on' -Bad 'enhanced pre-delivery scanning is off') -FailAs Warning
}

Register-TRCheck -Platform Google -Id 'GMAIL-05' -Area 'Gmail' -Category 'Gmail' -Severity High -Effort 1 `
    -Title 'Automatic forwarding is turned off' `
    -Needs 'GwsPolicies' `
    -Recommendation 'In Gmail, End user access, untick Allow users to automatically forward incoming email to another address. Allow it only for an organisational unit with an agreed business need.' `
    -Reference 'https://knowledge.workspace.google.com/admin/gmail/disable-automatic-forwarding' `
    -Test {
    ConvertTo-TRGwsResult (Test-TRGwsPolicy -Type 'gmail.auto_forwarding' -Ok { param($s) -not (Test-TRGwsTrue $s['enableAutoForwarding']) } -Good 'automatic forwarding is off' -Bad 'users can automatically forward mail to any address')
}

Register-TRCheck -Platform Google -Id 'GMAIL-06' -Area 'Gmail' -Category 'Gmail' -Severity Medium -Effort 2 `
    -Title 'POP and IMAP are turned off or limited' `
    -Needs 'GwsPolicies' `
    -Recommendation 'Turn off POP and IMAP in Gmail, End user access, or limit IMAP to approved mail clients. Check the users below first, as they used POP or IMAP recently.' `
    -Reference 'https://knowledge.workspace.google.com/admin/gmail/turn-pop-and-imap-on-and-off-for-users' `
    -Test {
    $pop = Test-TRGwsPolicy -Type 'gmail.pop_access' -Ok { param($s) -not (Test-TRGwsTrue $s['enablePopAccess']) } -Good 'POP is off' -Bad 'POP is on'
    $imap = Test-TRGwsPolicy -Type 'gmail.imap_access' -Ok { param($s) -not (Test-TRGwsTrue $s['enableImapAccess']) } -Good 'IMAP is off' -Bad 'IMAP is on'
    $used = @(Get-TRItems 'GwsUserUsage' | Where-Object { [string]$_.gmail_timestamp_last_imap -or [string]$_.gmail_timestamp_last_pop })
    $aff = @(@($pop.Affected) + @($imap.Affected)) + @($used | ForEach-Object { New-TRAffected $_.Email ('Used ' + ((@($(if ($_.gmail_timestamp_last_pop) { 'POP' }), $(if ($_.gmail_timestamp_last_imap) { 'IMAP' })) | Where-Object { $_ }) -join ' and ') + ' in the last 30 days') })
    if ($pop.Status -eq 'Pass' -and $imap.Status -eq 'Pass') { return New-TRResult Pass 'POP and IMAP are off.' }
    if ($pop.Status -eq 'Unknown' -and $imap.Status -eq 'Unknown') { return New-TRResult NotAssessed 'The POP and IMAP settings were not returned.' }
    New-TRResult Warning (((@($pop, $imap) | Where-Object { $_.Status -eq 'Fail' } | ForEach-Object { $_.Text }) -join ' ') + $(if ($used.Count) { (' {0} used POP or IMAP in the last 30 days.' -f (Format-TRN $used.Count 'user')) } else { ' No user used POP or IMAP in the last 30 days.' })) $aff
}

Register-TRCheck -Platform Google -Id 'GMAIL-07' -Area 'Gmail' -Category 'Gmail' -Severity Medium -Effort 1 `
    -Title 'Users cannot send through their own outbound mail servers' `
    -Needs 'GwsPolicies' `
    -Recommendation 'In Gmail, End user access, untick Allow per-user outbound gateways.' `
    -Reference 'https://knowledge.workspace.google.com/admin/gmail/allow-per-user-outbound-gateways' `
    -Test {
    $e = Test-TRGwsPolicy -Type 'gmail.per_user_outbound_gateway' -Ok { param($s) -not (Test-TRGwsTrue $(if ($null -ne $s['allowUsersToUseExternalSmtpServers']) { $s['allowUsersToUseExternalSmtpServers'] } else { $s['enablePerUserOutboundGateway'] })) } -Good 'per-user outbound gateways are off' -Bad 'users can send mail through external SMTP servers'
    if ($e.Status -eq 'Unknown') { return New-TRResult NotAssessed 'The per-user outbound gateway setting was not returned.' }
    ConvertTo-TRGwsResult $e -FailAs Warning
}

Register-TRCheck -Platform Google -Id 'GMAIL-08' -Area 'Gmail' -Category 'Gmail' -Severity Medium -Effort 2 `
    -Title 'Spam filtering is not bypassed for whole domains or IP ranges' `
    -Needs 'GwsPolicies' `
    -Recommendation 'Remove domains from Approved senders lists in Gmail spam settings, untick Bypass spam filters for internal senders and remove IP addresses from the email allowlist unless they are your own relays.' `
    -Reference 'https://knowledge.workspace.google.com/admin/gmail/customize-spam-filter-settings' `
    -Test {
    $aff = New-Object System.Collections.ArrayList
    foreach ($p in @((Get-TRGwsPolicyIndex)['gmail.email_spam_filter_ip_allowlist'])) {
        $ips = @(Get-TRStrings (Get-TRV $p.Value 'allowedIpAddresses'))
        if ($ips.Count) { [void]$aff.Add((New-TRAffected ($p.Scope + ': IP allowlist') (Join-TRList $ips 5))) }
    }
    foreach ($p in @((Get-TRGwsPolicyIndex)['gmail.spam_override_lists'])) {
        foreach ($o in @(Get-TRV $p.Value 'spamOverride')) {
            if (-not $o) { continue }
            $flags = @()
            if (Test-TRGwsTrue (Get-TRV $o 'bypassInternalSenders')) { $flags += 'bypasses internal senders' }
            if (Test-TRGwsTrue (Get-TRV $o 'bypassSelectedSenders')) { $flags += 'bypasses approved senders' }
            if (Test-TRGwsTrue (Get-TRV $o 'hideWarningBannerForAll')) { $flags += 'hides warnings for all senders' }
            if ($flags.Count) { [void]$aff.Add((New-TRAffected ($p.Scope + ': ' + [string](Get-TRV $o 'description')) ($flags -join '; '))) }
        }
    }
    if (-not $aff.Count) { return New-TRResult Pass 'No spam filter bypass or IP allowlist was found.' }
    New-TRResult Warning ('{0} spam filtering.' -f (Format-TRN $aff.Count 'setting bypasses' 'settings bypass')) $aff.ToArray()
}

Register-TRCheck -Platform Google -Id 'GMAIL-09' -Area 'Gmail' -Category 'Gmail' -Severity Low -Effort 1 `
    -Title 'Comprehensive mail storage is on' `
    -Needs 'GwsPolicies' `
    -Recommendation 'In Gmail, Compliance, turn on Comprehensive mail storage so mail sent by other services (for example Calendar and Docs) is also kept in Gmail for Vault and audit.' `
    -Reference 'https://knowledge.workspace.google.com/admin/gmail/set-up-comprehensive-mail-storage' `
    -Test {
    $r = @((Get-TRGwsPolicyIndex)['gmail.comprehensive_mail_storage'] | Where-Object { $_ -and $_.IsRoot })
    if ($r.Count -and (Get-TRV $r[0].Value 'ruleId')) { return New-TRResult Pass 'Comprehensive mail storage is on.' }
    New-TRResult Warning 'Comprehensive mail storage is not turned on for the organisation.'
}

Register-TRCheck -Platform Google -Id 'GMAIL-10' -Area 'Gmail' -Category 'Gmail' -Severity Low -Effort 1 `
    -Title 'Users are warned before replying to external recipients' `
    -Needs 'GwsPolicies' `
    -Recommendation 'In Gmail, End user access, turn on Warn for external recipients.' `
    -Reference 'https://knowledge.workspace.google.com/admin/gmail/warn-users-about-external-recipients' `
    -Test {
    $e = Test-TRGwsPolicy -Type 'gmail.external_recipient_warning' -Ok { param($s) Test-TRGwsTrue $s['enabled'] } -Good 'external recipient warnings are on' -Bad 'external recipient warnings are off'
    if ($e.Status -eq 'Unknown') {
        $l = Test-TRGwsLogSetting -Setting 'OutOfDomainWarningProto disable_untrusted_recipient_warning' -Ok { param($v) $v -eq 'false' } -Good 'External recipient warnings are on' -Bad 'external recipient warnings are off' -DefaultOk $true -DefaultText 'warnings on'
        return ConvertTo-TRGwsResult $l -FailAs Warning
    }
    ConvertTo-TRGwsResult $e -FailAs Warning
}

Register-TRCheck -Platform Google -Id 'GMAIL-11' -Area 'Gmail' -Category 'Gmail' -Severity Low -Effort 1 `
    -Title 'Mail delegation is controlled' `
    -Needs 'GwsPolicies' `
    -Recommendation 'Turn off Let users delegate access to their mailbox, or allow it only in an organisational unit for staff who need it. Delegates can read, send and delete mail.' `
    -Reference 'https://knowledge.workspace.google.com/admin/gmail/turn-gmail-delegation-on-or-off' `
    -Test {
    ConvertTo-TRGwsResult (Test-TRGwsPolicy -Type 'gmail.mail_delegation' -Ok { param($s) -not (Test-TRGwsTrue $s['enableMailDelegation']) } -Good 'mail delegation is off' -Bad 'users can delegate access to their mailbox') -FailAs Warning
}

Register-TRCheck -Platform Google -Id 'GMAIL-12' -Area 'Gmail' -Category 'Gmail' -Severity Low -Effort 1 `
    -Title 'Users cannot import mail from other accounts' `
    -Needs 'GwsPolicies' `
    -Recommendation 'In Gmail, Setup, untick Allow users to import their mail and contacts from Gmail, Yahoo, Outlook and other webmail or POP3 accounts.' `
    -Reference 'https://knowledge.workspace.google.com/admin/gmail/let-users-import-their-mail-and-contacts' `
    -Test {
    ConvertTo-TRGwsResult (Test-TRGwsPolicy -Type 'gmail.user_email_uploads' -Ok { param($s) -not (Test-TRGwsTrue $s['enableMailAndContactsImport']) } -Good 'mail import is off' -Bad 'users can import mail from outside accounts') -FailAs Warning
}

Register-TRCheck -Platform Google -Id 'GDNS-01' -Area 'Dns' -Category 'Email DNS' -Severity High -Effort 2 `
    -Title 'MX records deliver mail to Gmail' `
    -Needs 'GwsDnsRecords' `
    -Recommendation 'Point the MX records of every domain that receives mail at Google (smtp.google.com, or the ASPMX set), or at the mail filter in front of Gmail. Remove MX records left from a previous provider.' `
    -Reference 'https://knowledge.workspace.google.com/admin/domains/set-up-mx-records-for-google-workspace' `
    -Test {
    $rows = @(Get-TRGwsDnsRows)
    $aff = foreach ($r in $rows) {
        $k = Test-TRGoogleMx $r
        $mx = Join-TRList (Get-TRStrings $r.Mx | ForEach-Object { (($_ -split '\s+')[-1]).TrimEnd('.') }) 4
        if ($k -eq 'Mixed') { New-TRAffected $r.Domain ('Google and other servers: ' + $mx) }
        elseif ($k -eq 'Other') { New-TRAffected $r.Domain ('Not Google: ' + $mx) }
        elseif ($k -eq 'None' -and $r.IsPrimary) { New-TRAffected $r.Domain 'No MX record' }
    }
    $aff = @($aff)
    if (-not $aff.Count) { return New-TRResult Pass ('All mail domains point their MX records at Google ({0}).' -f (Format-TRN $rows.Count 'domain')) }
    $mixed = @($aff | Where-Object { $_.Detail -like 'Google and other*' -or $_.Detail -eq 'No MX record' })
    New-TRResult $(if ($mixed.Count) { 'Fail' } else { 'Warning' }) ('{0} {1} not deliver straight to Gmail. Other servers can be a mail filter (fine if it relays to Gmail) or a leftover from a previous provider.' -f (Format-TRN $aff.Count 'domain'), (Select-TRText $aff.Count 'does' 'do')) $aff
}

Register-TRCheck -Platform Google -Id 'GDNS-02' -Area 'Dns' -Category 'Email DNS' -Severity High -Effort 1 `
    -Title 'SPF authorises Google and ends with -all or ~all' `
    -Needs 'GwsDnsRecords' `
    -Recommendation 'Publish one SPF record per mail domain that includes _spf.google.com and any other services that send as the domain, ending in -all (or ~all while testing).' `
    -Reference 'https://knowledge.workspace.google.com/admin/security/set-up-spf' `
    -Test {
    $rows = @(Get-TRGwsDnsRows | Where-Object { (Test-TRGoogleMx $_) -ne 'None' -or $_.IsPrimary })
    $aff = foreach ($r in $rows) {
        $p = Test-TRSpfOk $r
        $spf = @(Get-TRStrings $r.Spf) -join ' '
        if ($p) { New-TRAffected $r.Domain $p }
        elseif ($spf -notmatch '_spf\.google\.com' -and $spf -notmatch 'redirect=') { New-TRAffected $r.Domain ('Google is not included: ' + $spf) }
    }
    $aff = @($aff)
    if (-not $aff.Count) { return New-TRResult Pass ('SPF is correct on {0}.' -f (Format-TRN $rows.Count 'mail domain')) }
    New-TRResult Fail ('{0} of {1} mail domains {2} an SPF problem.' -f $aff.Count, $rows.Count, (Select-TRText $aff.Count 'has' 'have')) $aff
}

Register-TRCheck -Platform Google -Id 'GDNS-03' -Area 'Dns' -Category 'Email DNS' -Severity High -Effort 1 `
    -Title 'DKIM signing is set up with a 2048-bit key' `
    -Needs 'GwsDnsRecords' `
    -Recommendation 'In Gmail, Authenticate email, generate a 2048-bit DKIM key for each domain, publish the TXT record at google._domainkey and select Start authentication.' `
    -Reference 'https://knowledge.workspace.google.com/admin/security/set-up-dkim' `
    -Test {
    $rows = @(Get-TRGwsDnsRows | Where-Object { (Test-TRGoogleMx $_) -in @('Google', 'Mixed', 'Other') -or $_.IsPrimary })
    $aff = foreach ($r in $rows) {
        $bits = Get-TRGwsDkimBits $r
        if ($bits -eq 0) { New-TRAffected $r.Domain 'No DKIM record found at google._domainkey' }
        elseif ($bits -lt 2048) { New-TRAffected $r.Domain ('{0}-bit key at {1}._domainkey' -f $bits, $r.DkimSelector) }
    }
    $aff = @($aff)
    if (-not $aff.Count) { return New-TRResult Pass ('DKIM is published with a 2048-bit key on {0}.' -f (Format-TRN $rows.Count 'mail domain')) }
    $missing = @($aff | Where-Object { $_.Detail -like 'No DKIM*' })
    New-TRResult $(if ($missing.Count) { 'Fail' } else { 'Warning' }) ('{0} of {1} mail domains {2} missing DKIM or {3} a short key.' -f $aff.Count, $rows.Count, (Select-TRText $aff.Count 'is' 'are'), (Select-TRText $aff.Count 'uses' 'use')) $aff
}

Register-TRCheck -Platform Google -Id 'GDNS-04' -Area 'Dns' -Category 'Email DNS' -Severity High -Effort 2 `
    -Title 'DMARC is enforced with reporting' `
    -Needs 'GwsDnsRecords' `
    -Recommendation 'Publish a DMARC record for each mail domain with a rua reporting address, monitor the reports, then move to p=quarantine and p=reject.' `
    -Reference 'https://knowledge.workspace.google.com/admin/security/set-up-dmarc' `
    -Test {
    $rows = @(Get-TRGwsDnsRows)
    $aff = foreach ($r in $rows) {
        $d = @(Get-TRStrings $r.Dmarc)
        if (-not $d.Count) { New-TRAffected $r.Domain 'No DMARC record'; continue }
        $t = ConvertFrom-TRDmarc ($d[0] -replace '"', '')
        $p = [string]$t['p']
        $issues = @()
        if ($p -notin @('quarantine', 'reject')) { $issues += ('p=' + $p) }
        if ($t.ContainsKey('pct') -and [int]$t['pct'] -lt 100) { $issues += ('pct=' + $t['pct']) }
        if (-not $t['rua']) { $issues += 'no rua reporting address' }
        if ($issues.Count) { New-TRAffected $r.Domain ($issues -join '; ') }
    }
    $aff = @($aff)
    if (-not $aff.Count) { return New-TRResult Pass ('DMARC is enforced with reporting on {0}.' -f (Format-TRN $rows.Count 'domain')) }
    $none = @($aff | Where-Object { $_.Detail -eq 'No DMARC record' })
    New-TRResult $(if ($none.Count) { 'Fail' } else { 'Warning' }) ('{0} of {1} domains {2} not enforce DMARC with reporting.' -f $aff.Count, $rows.Count, (Select-TRText $aff.Count 'does' 'do')) $aff
}

Register-TRCheck -Platform Google -Id 'GDNS-05' -Area 'Dns' -Category 'Email DNS' -Severity Medium -Effort 1 `
    -Title 'All domains in Google Workspace are verified' `
    -Needs 'GwsDomains' `
    -Recommendation 'Verify or remove unverified domains and domain aliases in Account, Domains, Manage domains. Unverified domains cannot receive mail or be used for addresses.' `
    -Reference 'https://knowledge.workspace.google.com/admin/domains/verify-your-domain-for-google-workspace' `
    -Test {
    $aff = New-Object System.Collections.ArrayList
    foreach ($d in (Get-TRItems 'GwsDomains')) {
        if (-not $d.verified) { [void]$aff.Add((New-TRAffected ([string]$d.domainName) 'Secondary domain not verified')) }
        foreach ($a in @($d.domainAliases)) { if ($a -and -not $a.verified) { [void]$aff.Add((New-TRAffected ([string]$a.domainAliasName) 'Domain alias not verified')) } }
    }
    if (-not $aff.Count) { return New-TRResult Pass ('All {0} are verified.' -f (Format-TRN @(Get-TRItems 'GwsDomains').Count 'domain')) }
    New-TRResult Warning ('{0} not verified.' -f (Format-TRN $aff.Count 'domain is' 'domains are')) $aff.ToArray()
}

Register-TRCheck -Platform Google -Id 'GDNS-06' -Area 'Dns' -Category 'Email DNS' -Severity Low -Effort 1 `
    -Title 'MTA-STS is published' `
    -Needs 'GwsDnsRecords' `
    -Recommendation 'Publish an MTA-STS policy and _mta-sts TXT record for each mail domain, so other servers only deliver over verified TLS.' `
    -Reference 'https://knowledge.workspace.google.com/admin/security/about-mta-sts-and-tls-reporting' `
    -Test {
    $rows = @(Get-TRGwsDnsRows | Where-Object { (Test-TRGoogleMx $_) -in @('Google', 'Mixed') })
    $aff = @($rows | Where-Object { -not @(Get-TRStrings $_.MtaSts).Count } | ForEach-Object { New-TRAffected $_.Domain 'No _mta-sts record' })
    if (-not $rows.Count) { return New-TRResult Info 'No domain delivers mail straight to Google.' }
    if (-not $aff.Count) { return New-TRResult Pass 'MTA-STS is published for every mail domain.' }
    New-TRResult Info ('MTA-STS is not published for {0}.' -f (Format-TRN $aff.Count 'mail domain')) $aff
}

Register-TRCheck -Platform Google -Id 'GDRV-01' -Area 'Drive' -Category 'Drive and Docs' -Severity Medium -Effort 2 `
    -Title 'External sharing is limited and users are warned' `
    -Needs 'GwsPolicies' `
    -Recommendation 'In Drive and Docs, Sharing settings, restrict sharing outside the organisation to allowlisted domains where possible, or keep it on with Warn when files owned by users are shared outside turned on. Turn off sharing to people without a Google account.' `
    -Reference 'https://knowledge.workspace.google.com/admin/drive/manage-external-sharing-for-your-organization' `
    -Test {
    $e = Test-TRGwsPolicy -Type 'drive_and_docs.external_sharing' -Ok { param($s) $m = [string]$s['externalSharingMode']; ($m -eq 'DISALLOWED') -or ($m -eq 'ALLOWLISTED_DOMAINS' -and (Test-TRGwsTrue $s['warnForSharingOutsideAllowlistedDomains'])) -or ($m -eq 'ALLOWED' -and (Test-TRGwsTrue $s['warnForExternalSharing']) -and -not (Test-TRGwsTrue $s['allowNonGoogleInvites'])) } `
        -Good 'external sharing is limited with warnings' -Bad 'external sharing is open' `
        -Detail { param($s) $d = 'Mode ' + [string]$s['externalSharingMode']; if (-not (Test-TRGwsTrue $s['warnForExternalSharing'])) { $d += '; no warning' }; if (Test-TRGwsTrue $s['allowNonGoogleInvites']) { $d += '; sharing with non-Google accounts allowed' }; $d }
    ConvertTo-TRGwsResult $e -FailAs Warning
}

Register-TRCheck -Platform Google -Id 'GDRV-02' -Area 'Drive' -Category 'Drive and Docs' -Severity Medium -Effort 1 `
    -Title 'Files cannot be published to the web' `
    -Needs 'GwsPolicies' `
    -Recommendation 'In Drive and Docs, Sharing settings, untick When sharing outside of the organisation, allow users to publish files on the web or make them visible to the world as public or unlisted.' `
    -Reference 'https://knowledge.workspace.google.com/admin/drive/manage-external-sharing-for-your-organization' `
    -Test {
    ConvertTo-TRGwsResult (Test-TRGwsPolicy -Type 'drive_and_docs.external_sharing' -Ok { param($s) -not (Test-TRGwsTrue $s['allowPublishingFiles']) -or [string]$s['externalSharingMode'] -eq 'DISALLOWED' } -Good 'publishing files to the web is off' -Bad 'users can publish files to the web') -FailAs Warning
}

Register-TRCheck -Platform Google -Id 'GDRV-03' -Area 'Drive' -Category 'Drive and Docs' -Severity Medium -Effort 1 `
    -Title 'New files are private to their owner by default' `
    -Needs 'GwsPolicies' `
    -Recommendation 'In Drive and Docs, Sharing settings, General access default, set new items to Private to the owner.' `
    -Reference 'https://knowledge.workspace.google.com/admin/drive/set-default-general-access-for-new-files' `
    -Test {
    ConvertTo-TRGwsResult (Test-TRGwsPolicy -Type 'drive_and_docs.general_access_default' -Ok { param($s) [string]$s['defaultFileAccess'] -in @('PRIVATE_TO_OWNER', 'LINK_SHARING_PRIVATE') } -Good 'new files are private to the owner' -Bad 'new files are shared with the organisation by default' -Detail { param($s) 'Default: ' + [string]$s['defaultFileAccess'] }) -FailAs Warning
}

Register-TRCheck -Platform Google -Id 'GDRV-04' -Area 'Drive' -Category 'Drive and Docs' -Severity Low -Effort 1 `
    -Title 'Access checker suggests recipients only' `
    -Needs 'GwsPolicies' `
    -Recommendation 'In Drive and Docs, Sharing settings, set Access checker to Recipients only, so Drive does not suggest making files available to anyone with the link.' `
    -Reference 'https://knowledge.workspace.google.com/admin/drive/manage-external-sharing-for-your-organization' `
    -Test {
    ConvertTo-TRGwsResult (Test-TRGwsPolicy -Type 'drive_and_docs.external_sharing' -Ok { param($s) [string]$s['accessCheckerSuggestions'] -eq 'RECIPIENTS_ONLY' } -Good 'access checker suggests recipients only' -Bad 'access checker can suggest wider sharing' -Detail { param($s) 'Access checker: ' + [string]$s['accessCheckerSuggestions'] }) -FailAs Warning
}

Register-TRCheck -Platform Google -Id 'GDRV-05' -Area 'Drive' -Category 'Drive and Docs' -Severity Low -Effort 1 `
    -Title 'Shared drives keep content inside the drive' `
    -Needs 'GwsPolicies' `
    -Recommendation 'In Drive and Docs, Sharing settings, Shared drive creation, stop managers overriding these settings, and stop sharing with people outside the organisation and with non-members unless needed.' `
    -Reference 'https://knowledge.workspace.google.com/admin/drive/manage-shared-drives-as-an-admin' `
    -Test {
    $e = Test-TRGwsPolicy -Type 'drive_and_docs.shared_drive_creation' -Ok { param($s) -not (Test-TRGwsTrue $s['allowManagersToOverrideSettings']) -and -not (Test-TRGwsTrue $s['allowNonMemberAccess']) } `
        -Good 'shared drive managers cannot override settings and non-members cannot be added to files' -Bad 'shared drive content can be opened up' `
        -Detail { param($s) $g = @(); if (Test-TRGwsTrue $s['allowManagersToOverrideSettings']) { $g += 'managers can override' }; if (Test-TRGwsTrue $s['allowNonMemberAccess']) { $g += 'non-members can be added to files' }; if (Test-TRGwsTrue $s['allowExternalUserAccess']) { $g += 'external users allowed' }; $g -join '; ' }
    ConvertTo-TRGwsResult $e -FailAs Warning
}

Register-TRCheck -Platform Google -Id 'GDRV-06' -Area 'Drive' -Category 'Drive and Docs' -Severity Low -Effort 2 `
    -Title 'Drive for desktop is limited to company devices' `
    -Needs 'GwsPolicies' `
    -Recommendation 'In Drive and Docs, Google Drive for desktop, allow it only on authorised devices (needs endpoint management).' `
    -Reference 'https://knowledge.workspace.google.com/admin/drive/deploy-google-drive-for-desktop' `
    -Test {
    ConvertTo-TRGwsResult (Test-TRGwsPolicy -Type 'drive_and_docs.drive_for_desktop' -Ok { param($s) -not (Test-TRGwsTrue $s['allowDriveForDesktop']) -or (Test-TRGwsTrue $s['restrictToAuthorizedDevices']) } -Good 'Drive for desktop is limited to authorised devices' -Bad 'Drive for desktop works on any device') -FailAs Warning
}

Register-TRCheck -Platform Google -Id 'GDRV-07' -Area 'Drive' -Category 'Drive and Docs' -Severity Low -Effort 1 `
    -Title 'The Drive link security update is applied' `
    -Needs 'GwsPolicies' `
    -Recommendation 'In Drive and Docs, Security update for files, apply the update to affected files and stop users removing it.' `
    -Reference 'https://knowledge.workspace.google.com/admin/drive/manage-the-link-sharing-security-update-for-drive' `
    -Test {
    $e = Test-TRGwsPolicy -Type 'drive_and_docs.file_security_update' -Ok { param($s) [string]$s['securityUpdate'] -eq 'APPLY_TO_IMPACTED_FILES' -and -not (Test-TRGwsTrue $s['allowUsersToManageUpdate']) } -Good 'the security update is applied and users cannot remove it' -Bad 'the link security update is not fully applied'
    if ($e.Status -eq 'Unknown') { return New-TRResult Info 'The file security update setting was not returned.' }
    ConvertTo-TRGwsResult $e -FailAs Warning
}

Register-TRCheck -Platform Google -Id 'GDRV-08' -Area 'DriveSharing' -Category 'Drive and Docs' -Severity Info -Effort 0 `
    -Title 'Files shared outside the organisation in the last 30 days' `
    -Needs 'GwsDriveSharing' `
    -Recommendation 'Review the files below with their owners, remove sharing that is no longer needed and consider Drive trust rules or DLP for sensitive folders.' `
    -Reference 'https://knowledge.workspace.google.com/admin/drive/manage-external-sharing-for-your-organization' `
    -Test {
    $e = @(Get-TRItems 'GwsDriveSharing')
    if (-not $e.Count) { return New-TRResult Pass 'No external or link sharing of files was logged in the last 30 days.' }
    $files = @($e | Group-Object doc_id)
    New-TRResult Info ('{0} logged on {1} by {2} in the last 30 days.' -f (Format-TRN $e.Count 'external or link sharing event'), (Format-TRN $files.Count 'file'), (Format-TRN @($e | Select-Object -ExpandProperty Actor -Unique).Count 'user')) (@($files | Select-Object -First 200 | ForEach-Object { $x = $_.Group[-1]; New-TRAffected ([string]$x.doc_title) ('{0}; {1}' -f $x.Actor, $(if ($x.visibility) { [string]$x.visibility } else { [string]$x.target_user })) }))
}

Register-TRCheck -Platform Google -Id 'GCOL-01' -Area 'Collaboration' -Category 'Calendar, Chat and Meet' -Severity Low -Effort 1 `
    -Title 'Calendars share only free/busy outside the organisation' `
    -Needs 'GwsPolicies' `
    -Recommendation 'In Calendar, Sharing settings, set External sharing options for primary calendars to Only free/busy information.' `
    -Reference 'https://knowledge.workspace.google.com/admin/calendar/set-calendar-sharing-options' `
    -Test {
    ConvertTo-TRGwsResult (Test-TRGwsPolicy -Type 'calendar.primary_calendar_max_allowed_external_sharing' -Ok { param($s) [string]$s['maxAllowedExternalSharing'] -eq 'EXTERNAL_FREE_BUSY_ONLY' } -Good 'primary calendars share only free/busy externally' -Bad 'users can share event details outside the organisation' -Detail { param($s) 'Maximum: ' + [string]$s['maxAllowedExternalSharing'] }) -FailAs Warning
}

Register-TRCheck -Platform Google -Id 'GCOL-02' -Area 'Collaboration' -Category 'Calendar, Chat and Meet' -Severity Low -Effort 1 `
    -Title 'Chat is limited to trusted external domains' `
    -Needs 'GwsPolicies' `
    -Recommendation 'In Google Chat, External chat settings, allow chat only with allowlisted (trusted) domains, and in Chat file sharing set external sharing to No files or Images only.' `
    -Reference 'https://knowledge.workspace.google.com/admin/chat/turn-external-chat-on-or-off' `
    -Test {
    $a = Test-TRGwsPolicy -Type 'chat.external_chat_restriction' -Ok { param($s) -not (Test-TRGwsTrue $s['allowExternalChat']) -or [string]$s['externalChatRestriction'] -eq 'TRUSTED_DOMAINS' } -Good 'external chat is off or limited to trusted domains' -Bad 'users can chat with any external account'
    $b = Test-TRGwsPolicy -Type 'chat.chat_file_sharing' -Ok { param($s) [string]$s['externalFileSharing'] -in @('NO_FILES', 'IMAGES_ONLY') } -Good 'external file sharing in Chat is limited' -Bad 'any file can be shared in external chats'
    $bad = @(@($a, $b) | Where-Object { $_.Status -eq 'Fail' })
    if (-not $bad.Count -and $a.Status -eq 'Pass') { return New-TRResult Pass ($a.Text + ' ' + $b.Text) }
    if (-not $bad.Count) { return New-TRResult NotAssessed 'The Chat settings were not returned.' }
    New-TRResult Warning (($bad | ForEach-Object { $_.Text }) -join ' ') (@($bad | ForEach-Object { $_.Affected }))
}

Register-TRCheck -Platform Google -Id 'GCOL-03' -Area 'Collaboration' -Category 'Calendar, Chat and Meet' -Severity Low -Effort 1 `
    -Title 'Meet asks external people to knock and labels them' `
    -Needs 'GwsPolicies' `
    -Recommendation 'In Google Meet, Meet safety settings, require people outside the organisation to ask to join, turn on host management and the external participant label.' `
    -Reference 'https://knowledge.workspace.google.com/admin/meet/meet-safety-settings' `
    -Test {
    $checks = @(
        (Test-TRGwsPolicy -Type 'meet.safety_host_management' -Ok { param($s) Test-TRGwsTrue $s['enableHostManagement'] } -Good 'host management is on' -Bad 'host management is off'),
        (Test-TRGwsPolicy -Type 'meet.safety_external_participants' -Ok { param($s) Test-TRGwsTrue $s['enableExternalLabel'] } -Good 'external participants are labelled' -Bad 'external participants are not labelled'),
        (Test-TRGwsPolicy -Type 'meet.meet_joining' -Ok { param($s) [string]$s['allowedAudience'] -ne 'OPEN' } -Good 'uninvited external people must ask to join' -Bad 'anyone with the link can join without knocking')
    )
    $bad = @($checks | Where-Object { $_.Status -eq 'Fail' })
    $known = @($checks | Where-Object { $_.Status -ne 'Unknown' })
    if (-not $known.Count) { return New-TRResult NotAssessed 'The Meet safety settings were not returned.' }
    if (-not $bad.Count) { return New-TRResult Pass (($known | ForEach-Object { $_.Text }) -join ' ') }
    New-TRResult Warning (($bad | ForEach-Object { $_.Text }) -join ' ') (@($bad | ForEach-Object { $_.Affected }))
}

Register-TRCheck -Platform Google -Id 'GCOL-04' -Area 'Collaboration' -Category 'Groups' -Severity Medium -Effort 1 `
    -Title 'Group creation and outside access are restricted' `
    -Needs 'GwsPolicies' `
    -Recommendation 'In Groups for Business, Sharing settings, set Accessing groups from outside this organisation to Private, limit who can create groups and stop owners allowing external members unless needed.' `
    -Reference 'https://knowledge.workspace.google.com/admin/groups/set-groups-for-business-sharing-options' `
    -Test {
    $e = Test-TRGwsPolicy -Type 'groups_for_business.groups_sharing' -Ok { param($s) [string]$s['collaborationCapability'] -eq 'DOMAIN_USERS_ONLY' -and [string]$s['createGroupsAccessLevel'] -ne 'ANYONE_CAN_CREATE' -and -not (Test-TRGwsTrue $s['ownersCanAllowExternalMembers']) } `
        -Good 'groups are private to the organisation and owners cannot add external members' -Bad 'groups can be opened up outside the organisation' `
        -Detail { param($s) $g = @(); if ([string]$s['collaborationCapability'] -ne 'DOMAIN_USERS_ONLY') { $g += 'outside access ' + [string]$s['collaborationCapability'] }; if ([string]$s['createGroupsAccessLevel'] -eq 'ANYONE_CAN_CREATE') { $g += 'anyone can create groups' }; if (Test-TRGwsTrue $s['ownersCanAllowExternalMembers']) { $g += 'owners can add external members' }; $g -join '; ' }
    ConvertTo-TRGwsResult $e -FailAs Warning
}

Register-TRCheck -Platform Google -Id 'GCOL-05' -Area 'Collaboration' -Category 'Groups' -Severity Medium -Effort 2 `
    -Title 'Groups do not accept posts or joins from anyone on the internet' `
    -Needs 'GwsGroupSettings' `
    -Recommendation 'For each group listed, set Who can post to members of the organisation (or specific external senders) and Who can join to invited users only, unless the group is a public mailbox such as info@ that is protected by spam filtering.' `
    -Reference 'https://knowledge.workspace.google.com/admin/groups/set-group-access-and-permissions' `
    -Test {
    $bad = foreach ($g in (Get-TRItems 'GwsGroupSettings')) {
        $issues = @()
        if ([string]$g.whoCanJoin -eq 'ANYONE_CAN_JOIN') { $issues += 'anyone can join' }
        if ([string]$g.whoCanViewGroup -eq 'ANYONE_CAN_VIEW') { $issues += 'anyone can view conversations' }
        if ($issues.Count) { New-TRAffected ([string]$g.email) ($issues -join '; ') }
    }
    $bad = @($bad)
    $public = @(Get-TRItems 'GwsGroupSettings' | Where-Object { [string]$_.whoCanPostMessage -eq 'ANYONE_CAN_POST' })
    if (-not $bad.Count) { return New-TRResult Pass ('No group lets anyone on the internet join or read its conversations. {0} accept email from anyone, which is normal for shared addresses.' -f (Format-TRN $public.Count 'group')) }
    New-TRResult Warning ('{0} open to anyone on the internet.' -f (Format-TRN $bad.Count 'group is' 'groups are')) $bad
}

Register-TRCheck -Platform Google -Id 'GCOL-06' -Area 'Collaboration' -Category 'Groups' -Severity Medium -Effort 1 `
    -Title 'External members of groups are reviewed' `
    -Needs 'GwsGroupMembers' `
    -Recommendation 'Confirm each external member listed still needs to receive the group''s email, and remove the rest.' `
    -Reference 'https://knowledge.workspace.google.com/admin/groups/add-users-to-groups' `
    -Test {
    $ext = @(Get-TRItems 'GwsGroupMembers' | Where-Object { $_.Type -eq 'USER' -and -not (Test-TRGwsInternal $_.Member) })
    if (-not $ext.Count) { return New-TRResult Pass 'No group has external members.' }
    $groups = @($ext | Select-Object -ExpandProperty Group -Unique)
    New-TRResult Info ('{0} {2} {1}.' -f (Format-TRN $groups.Count 'group'), (Format-TRN $ext.Count 'external member'), (Select-TRText $groups.Count 'has' 'have')) (@($ext | ForEach-Object { New-TRAffected $_.Group ($_.Member + ' (' + $_.Role.ToLower() + ')') }))
}

Register-TRCheck -Platform Google -Id 'GCOL-07' -Area 'Collaboration' -Category 'Groups' -Severity Low -Effort 1 `
    -Title 'Groups have an owner' `
    -Needs 'GwsGroupMembers', 'GwsGroups' `
    -Recommendation 'Add an owner to each group listed, so someone is responsible for its membership and settings.' `
    -Reference 'https://knowledge.workspace.google.com/admin/groups/add-users-to-groups' `
    -Test {
    $owners = @{}
    foreach ($m in (Get-TRItems 'GwsGroupMembers')) { if ($m.Role -eq 'OWNER') { $owners[([string]$m.Group).ToLower()] = $true } }
    $bad = @(Get-TRItems 'GwsGroups' | Where-Object { -not $owners.ContainsKey(([string]$_.email).ToLower()) -and [int]$_.directMembersCount -gt 0 })
    $empty = @(Get-TRItems 'GwsGroups' | Where-Object { [int]$_.directMembersCount -eq 0 })
    if (-not $bad.Count) { return New-TRResult Pass ('Every group with members has an owner. {0}.' -f (Format-TRN $empty.Count 'group has no members' 'groups have no members')) }
    New-TRResult Info ('{0} no owner. {1}.' -f (Format-TRN $bad.Count 'group has' 'groups have'), (Format-TRN $empty.Count 'group has no members' 'groups have no members')) (@($bad | ForEach-Object { New-TRAffected ([string]$_.email) ('{0} members' -f [int]$_.directMembersCount) }))
}

Register-TRCheck -Platform Google -Id 'GCOL-08' -Area 'Collaboration' -Category 'Calendar, Chat and Meet' -Severity Low -Effort 1 `
    -Title 'Google Takeout is controlled' `
    -Needs 'GwsPolicies' `
    -Recommendation 'In Account, Google Takeout, turn Takeout off for users who should not export their data, or for everyone and allow it by exception.' `
    -Reference 'https://knowledge.workspace.google.com/admin/users/allow-or-block-google-takeout' `
    -Test {
    $e = Test-TRGwsPolicy -Type 'takeout.service_status' -Ok { param($s) [string]$s['serviceState'] -eq 'DISABLED' } -Good 'Google Takeout is off' -Bad 'users can export their data with Google Takeout'
    if ($e.Status -eq 'Unknown') { return New-TRResult Info 'The Takeout setting was not returned.' }
    ConvertTo-TRGwsResult $e -FailAs Warning
}

Register-TRCheck -Platform Google -Id 'GDEV-01' -Area 'Devices' -Category 'Devices' -Severity High -Effort 2 `
    -Title 'Compromised mobile devices are blocked' `
    -Needs 'GwsPolicies', 'GwsDevices' `
    -Recommendation 'In Devices, Mobile and endpoints, Settings, Security, block compromised Android devices and jailbroken iOS devices. Wipe or remove the devices listed.' `
    -Reference 'https://knowledge.workspace.google.com/admin/mobile/apply-settings-for-android-mobile-devices' `
    -Test {
    $bad = @(Get-TRItems 'GwsDevices' | Where-Object { [string]$_.compromisedState -eq 'COMPROMISED' })
    $e = Test-TRGwsPolicy -Type 'devices.compromised_devices' -Ok { param($s) (Test-TRGwsTrue $s['compromisedAndroidDevicesBlocked']) -and (Test-TRGwsTrue $s['jailbrokenIosDevicesBlocked']) } -Good 'compromised devices are blocked' -Bad 'compromised devices are not blocked'
    $aff = @($bad | ForEach-Object { New-TRAffected ('{0} {1}' -f $_.model, $_.serialNumber).Trim() 'Compromised' })
    if ($bad.Count) { return New-TRResult Fail ('{0} reported as compromised. {1}' -f (Format-TRN $bad.Count 'device is' 'devices are'), $(if ($e.Status -ne 'Unknown') { $e.Text } else { '' })) $aff }
    if ($e.Status -eq 'Unknown') { return New-TRResult Info 'No compromised device was found. The blocking setting was not returned (it applies to advanced management only).' }
    ConvertTo-TRGwsResult $e -FailAs Warning
}

Register-TRCheck -Platform Google -Id 'GDEV-02' -Area 'Devices' -Category 'Devices' -Severity Medium -Effort 2 `
    -Title 'Devices are encrypted' `
    -Needs 'GwsDevices' `
    -Recommendation 'Require encryption in Devices, Mobile and endpoints, Settings, and follow up the devices listed.' `
    -Reference 'https://knowledge.workspace.google.com/admin/mobile/set-up-advanced-mobile-management' `
    -Test {
    $d = @(Get-TRItems 'GwsDevices' | Where-Object { [string]$_.deviceType -notin @('CHROME_OS', 'GOOGLE_SYNC') })
    if (-not $d.Count) { return New-TRResult Info 'No mobile or desktop devices are managed in Google Workspace.' }
    $bad = @($d | Where-Object { [string]$_.encryptionState -eq 'NOT_ENCRYPTED' })
    if (-not $bad.Count) { return New-TRResult Pass ('No unencrypted device among {0}.' -f (Format-TRN $d.Count 'managed device')) }
    New-TRResult Warning ('{0} of {1} devices {2} not encrypted.' -f $bad.Count, $d.Count, (Select-TRText $bad.Count 'reports it is' 'report they are')) (@($bad | ForEach-Object { New-TRAffected ('{0} {1}' -f $_.model, $_.serialNumber).Trim() ([string]$_.deviceType + ' ' + [string]$_.osVersion) }))
}

Register-TRCheck -Platform Google -Id 'GDEV-03' -Area 'Devices' -Category 'Devices' -Severity Medium -Effort 2 `
    -Title 'Windows 10 and unsupported ChromeOS devices are replaced' `
    -Needs 'GwsDevices' `
    -Recommendation 'Upgrade Windows 10 devices to Windows 11 (Windows 10 support ended in October 2025) and replace ChromeOS devices past their auto update expiry.' `
    -Reference 'https://support.google.com/chrome/a/answer/6220366' `
    -Test {
    $aff = New-Object System.Collections.ArrayList
    foreach ($d in (Get-TRItems 'GwsDevices')) {
        if ([string]$d.deviceType -eq 'WINDOWS' -and [string]$d.osVersion -match '10\.0\.(\d+)' -and [int]$Matches[1] -lt 22000) { [void]$aff.Add((New-TRAffected ('{0} {1}' -f $d.model, $d.serialNumber).Trim() ('Windows 10 build ' + $Matches[1]))) }
    }
    foreach ($c in (Get-TRItems 'GwsChromeDevices')) {
        $exp = ConvertTo-TRDate $(if ($c.autoUpdateThrough) { $c.autoUpdateThrough } elseif ($c.autoUpdateExpiration) { ([datetime]::new(1970, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)).AddMilliseconds([long]$c.autoUpdateExpiration) } else { $null })
        if ($exp -and $exp -lt (Get-TRNow) -and [string]$c.status -eq 'ACTIVE') { [void]$aff.Add((New-TRAffected ('{0} {1}' -f $c.model, $c.serialNumber).Trim() ('ChromeOS updates ended ' + (Format-TRDate $exp)))) }
    }
    if (-not $aff.Count) { return New-TRResult Pass 'No Windows 10 or out-of-support ChromeOS device was found.' }
    New-TRResult Warning ('{0} no longer receive security updates.' -f (Format-TRN $aff.Count 'device' 'devices')) $aff.ToArray()
}

Register-TRCheck -Platform Google -Id 'GDEV-04' -Area 'Devices' -Category 'Devices' -Severity Low -Effort 1 `
    -Title 'Devices that have stopped syncing are removed' `
    -Needs 'GwsDevices' `
    -Recommendation 'Review devices that have not synced for more than 180 days and remove or wipe them.' `
    -Reference 'https://knowledge.workspace.google.com/admin/mobile/view-mobile-device-details' `
    -Test {
    $days = [int](Get-TRSetting 'StaleDeviceDays' 180)
    $bad = @(Get-TRItems 'GwsDevices' | Where-Object { $a = Get-TRGwsDays $_.lastSyncTime; $null -ne $a -and $a -gt $days })
    if (-not $bad.Count) { return New-TRResult Pass ('Every device has synced within {0} days.' -f $days) }
    New-TRResult Info ('{0} not synced for more than {1} days.' -f (Format-TRN $bad.Count 'device has' 'devices have'), $days) (@($bad | ForEach-Object { New-TRAffected ('{0} {1}' -f $_.model, $_.serialNumber).Trim() ('Last sync ' + (Format-TRDate $_.lastSyncTime)) }))
}

Register-TRCheck -Platform Google -Id 'GDEV-05' -Area 'Devices' -Category 'Devices' -Severity Low -Effort 1 `
    -Title 'Android security patches are recent' `
    -Needs 'GwsDevices' `
    -Recommendation 'Ask users of the devices listed to install the latest Android update, and replace devices that no longer receive updates.' `
    -Reference 'https://knowledge.workspace.google.com/admin/mobile/view-mobile-device-details' `
    -Test {
    $bad = @(Get-TRItems 'GwsDevices' | Where-Object { [string]$_.deviceType -eq 'ANDROID' -and $_.securityPatchTime -and (Get-TRGwsDays $_.securityPatchTime) -gt 120 })
    $android = @(Get-TRItems 'GwsDevices' | Where-Object { [string]$_.deviceType -eq 'ANDROID' })
    if (-not $android.Count) { return New-TRResult Info 'No Android devices are managed.' }
    if (-not $bad.Count) { return New-TRResult Pass ('All {0} have a security patch from the last four months.' -f (Format-TRN $android.Count 'Android device')) }
    New-TRResult Warning ('{0} of {1} Android devices {2} a security patch older than four months.' -f $bad.Count, $android.Count, (Select-TRText $bad.Count 'has' 'have')) (@($bad | ForEach-Object { New-TRAffected ('{0} {1}' -f $_.model, $_.serialNumber).Trim() ('Patch ' + (Format-TRDate $_.securityPatchTime)) }))
}

Register-TRCheck -Platform Google -Id 'GSEC-01' -Area 'Security' -Category 'Security operations' -Severity Medium -Effort 1 `
    -Title 'Key system alert rules are on and notify someone' `
    -Needs 'GwsPolicies' `
    -Recommendation 'In Security, Alert center, Rules, make sure the system-defined rules for suspicious sign-ins, leaked passwords, government-backed attacks, admin privilege grants, password changes and suspicious programmatic sign-ins are on, and send email to a monitored address.' `
    -Reference 'https://knowledge.workspace.google.com/admin/security/manage-alerts-in-the-alert-center' `
    -Test {
    $rules = @(Get-TRGwsRules 'rule.system_defined_alerts')
    if (-not $rules.Count) { return New-TRResult NotAssessed 'No system-defined alert rules were returned by the Policy API.' }
    $want = @($script:TRGwsCisAlertRules.Keys)
    $aff = foreach ($w in $want) {
        $r = @($rules | Where-Object { ([string](Get-TRV $_ 'displayName')) -ieq $w })[0]
        if (-not $r) { continue }
        $state = [string](Get-TRV $r 'state')
        $cfg = Get-TRPath $r 'action.alertCenterAction.alertCenterConfig'
        $status = [string](Get-TRV $cfg 'status')
        $rec = @(@(Get-TRPath $r 'action.alertCenterAction.recipients') | Where-Object { $_ })
        if ($state -eq 'INACTIVE' -or $status -eq 'DISABLED') { New-TRAffected $w 'Off' }
        elseif (-not $rec.Count) { New-TRAffected $w 'No email notifications' }
    }
    $aff = @($aff)
    if (-not $aff.Count) { return New-TRResult Pass 'The key system alert rules are on.' }
    $off = @($aff | Where-Object { $_.Detail -eq 'Off' })
    New-TRResult $(if ($off.Count) { 'Fail' } else { 'Info' }) ('{0} {2} attention: {1}.' -f (Format-TRN $aff.Count 'alert rule'), (Join-TRList ($aff | ForEach-Object { $_.Item + ' (' + $_.Detail.ToLower() + ')' }) 4), (Select-TRText $aff.Count 'needs' 'need')) $aff
}

Register-TRCheck -Platform Google -Id 'GSEC-02' -Area 'Security' -Category 'Security operations' -Severity High -Effort 2 `
    -Title 'Recent high-severity alerts have been dealt with' `
    -Needs 'GwsAlerts' `
    -Recommendation 'Investigate and close the open alerts listed in the Alert Center, starting with suspicious sign-ins, leaked passwords and government-backed attack warnings.' `
    -Reference 'https://knowledge.workspace.google.com/admin/security/manage-alerts-in-the-alert-center' `
    -Test {
    $a = @(Get-TRItems 'GwsAlerts' | Where-Object { -not $_.deleted })
    $open = @($a | Where-Object { [string](Get-TRPath $_ 'metadata.status') -ne 'CLOSED' })
    $high = @($open | Where-Object { [string](Get-TRPath $_ 'metadata.severity') -eq 'HIGH' })
    if (-not $a.Count) { return New-TRResult Pass 'No alerts were raised in the last 90 days.' }
    $aff = @($open | Sort-Object createTime -Descending | Select-Object -First 100 | ForEach-Object { New-TRAffected ([string]$_.type) ('{0}; {1}; {2}' -f (Format-TRDate $_.createTime), $(if (Get-TRPath $_ 'metadata.severity') { [string](Get-TRPath $_ 'metadata.severity') } else { 'no severity' }), [string](Get-TRPath $_ 'metadata.status')) })
    if ($high.Count) { return New-TRResult Fail ('{0} open in the last 90 days ({1} alerts in total).' -f (Format-TRN $high.Count 'high-severity alert is' 'high-severity alerts are'), $a.Count) $aff }
    if ($open.Count) { return New-TRResult Warning ('{0} of {1} alerts from the last 90 days {2} not closed.' -f $open.Count, $a.Count, (Select-TRText $open.Count 'is' 'are')) $aff }
    New-TRResult Pass ('All {0} alerts from the last 90 days are closed.' -f $a.Count)
}

Register-TRCheck -Platform Google -Id 'GSEC-03' -Area 'Security' -Category 'Security operations' -Severity High -Effort 2 `
    -Title 'No accounts show signs of compromise' `
    -Needs 'GwsLoginEvents' `
    -Recommendation 'Check each account listed: reset the password, sign the user out, review 2SV methods, mail forwarding and app access, and look at the sign-in audit log for the source.' `
    -Reference 'https://knowledge.workspace.google.com/admin/reports/login-audit-log' `
    -Test {
    $e = @(Get-TRItems 'GwsLoginEvents')
    if (-not $e.Count) { return New-TRResult Pass 'No suspicious sign-in, leaked password or government-backed attack events in the last 30 days.' }
    $byUser = @($e | Group-Object Actor)
    $names = @{ suspicious_login = 'suspicious sign-in'; suspicious_login_less_secure_app = 'suspicious less secure app sign-in'; suspicious_programmatic_login = 'suspicious programmatic sign-in'; gov_attack_warning = 'government-backed attack warning'; account_disabled_password_leak = 'disabled for leaked password'; account_disabled_hijacked = 'disabled as hijacked' }
    New-TRResult Fail ('{0} with {1} in the last 30 days.' -f (Format-TRN $byUser.Count 'account'), (Format-TRN $e.Count 'security sign-in event')) (@($byUser | ForEach-Object { New-TRAffected $_.Name ((@($_.Group | ForEach-Object { $names[[string]$_.Event] } | Where-Object { $_ } | Sort-Object -Unique)) -join ', ') }))
}

Register-TRCheck -Platform Google -Id 'GSEC-04' -Area 'Security' -Category 'Security operations' -Severity Medium -Effort 4 `
    -Title 'Data loss prevention rules protect Drive' `
    -Needs 'GwsPolicies', 'GwsLicences' `
    -Recommendation 'Create DLP rules in Security, Access and data control, Data protection for UK personal data such as National Insurance numbers, bank details and passport numbers, starting in audit mode, then warn or block sharing outside the organisation.' `
    -Reference 'https://knowledge.workspace.google.com/admin/security/about-dlp' `
    -Test {
    if (-not (Test-TRGwsCapability 'Dlp')) { return New-TRResult Info 'Data loss prevention rules need an Enterprise, Frontline Standard or Education Standard/Plus licence, which this tenant does not have.' }
    $rules = @(Get-TRGwsRules 'rule.dlp' | Where-Object { [string](Get-TRV $_ 'state') -eq 'ACTIVE' })
    $drive = @($rules | Where-Object { @(Get-TRStrings (Get-TRV $_ 'triggers') | Where-Object { $_ -like 'google.workspace.drive.*' }).Count })
    if ($drive.Count) { return New-TRResult Pass ('{0} protect Drive: {1}.' -f (Format-TRN $drive.Count 'active DLP rule' 'active DLP rules'), (Join-TRList ($drive | ForEach-Object { Get-TRV $_ 'displayName' }) 4)) }
    if ($rules.Count) { return New-TRResult Warning ('{0}, but none applies to Drive.' -f (Format-TRN $rules.Count 'active DLP rule')) }
    New-TRResult Fail 'No active DLP rule exists, although the licence includes it.'
}

Register-TRCheck -Platform Google -Id 'GSEC-05' -Area 'Security' -Category 'Security operations' -Severity Low -Effort 0 `
    -Title 'Admin role changes in the last 180 days' `
    -Needs 'GwsAdminEvents' `
    -Recommendation 'Confirm each change below was expected. Unexpected admin grants are a common sign of account takeover.' `
    -Reference 'https://knowledge.workspace.google.com/admin/reports/admin-log-events' `
    -Test {
    $e = @(Get-TRItems 'GwsAdminEvents' | Where-Object { $_.Event -in @('ASSIGN_ROLE', 'GRANT_ADMIN_PRIVILEGE', 'UNASSIGN_ROLE', 'REVOKE_ADMIN_PRIVILEGE', 'CREATE_ROLE', 'ADD_PRIVILEGE') })
    if (-not $e.Count) { return New-TRResult Pass 'No admin role changes were logged in the last 180 days.' }
    New-TRResult Info ('{0} logged in the last 180 days.' -f (Format-TRN $e.Count 'admin role change')) (@($e | Sort-Object Time -Descending | Select-Object -First 100 | ForEach-Object { New-TRAffected $(if ($_.USER_EMAIL) { [string]$_.USER_EMAIL } else { [string]$_.ROLE_NAME }) ('{0} {1} by {2} on {3}' -f $(switch ([string]$_.Event) { 'ASSIGN_ROLE' { 'Assigned' } 'UNASSIGN_ROLE' { 'Removed' } 'CREATE_ROLE' { 'Created' } 'DELETE_ROLE' { 'Deleted' } 'ADD_PRIVILEGE' { 'Privilege added to' } 'REMOVE_PRIVILEGE' { 'Privilege removed from' } default { [string]$_ } }), (Get-TRGwsRoleName ([string]$_.ROLE_NAME)), $_.Actor, (Format-TRDate $_.Time)) }))
}
