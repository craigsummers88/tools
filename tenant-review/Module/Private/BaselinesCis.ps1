$script:TRCisAttachmentTypes = @('7z', 'a3x', 'ace', 'ade', 'adp', 'ani', 'apk', 'app', 'appinstaller', 'applescript', 'application', 'appref-ms', 'appx', 'appxbundle', 'arj', 'asd', 'asx', 'bas', 'bat', 'bgi', 'bz2', 'cab', 'chm', 'cmd', 'com', 'cpl', 'crt', 'cs', 'csh', 'daa', 'dbf', 'dcr', 'deb', 'desktopthemepackfile', 'dex', 'diagcab', 'dif', 'dir', 'dll', 'dmg', 'doc', 'docm', 'dot', 'dotm', 'elf', 'eml', 'exe', 'fxp', 'gadget', 'gz', 'hlp', 'hta', 'htc', 'htm', 'html', 'hwpx', 'ics', 'img', 'inf', 'ins', 'iqy', 'iso', 'isp', 'jar', 'jnlp', 'js', 'jse', 'kext', 'ksh', 'lha', 'lib', 'library', 'library-ms', 'lnk', 'lzh', 'macho', 'mam', 'mda', 'mdb', 'mde', 'mdt', 'mdw', 'mdz', 'mht', 'mhtml', 'mof', 'msc', 'msi', 'msix', 'msp', 'msrcincident', 'mst', 'ocx', 'odt', 'ops', 'oxps', 'pcd', 'pif', 'plg', 'pot', 'potm', 'ppa', 'ppam', 'ppkg', 'pps', 'ppsm', 'ppt', 'pptm', 'prf', 'prg', 'ps1', 'ps11', 'ps11xml', 'ps1xml', 'ps2', 'ps2xml', 'psc1', 'psc2', 'pub', 'py', 'pyc', 'pyo', 'pyw', 'pyz', 'pyzw', 'rar', 'reg', 'rev', 'rtf', 'scf', 'scpt', 'scr', 'sct', 'searchConnector-ms', 'service', 'settingcontent-ms', 'sh', 'shb', 'shs', 'shtm', 'shtml', 'sldm', 'slk', 'so', 'spl', 'stm', 'svg', 'swf', 'sys', 'tar', 'theme', 'themepack', 'timer', 'uif', 'url', 'uue', 'vb', 'vbe', 'vbs', 'vhd', 'vhdx', 'vxd', 'wbk', 'website', 'wim', 'wiz', 'ws', 'wsc', 'wsf', 'wsh', 'xla', 'xlam', 'xlc', 'xll', 'xlm', 'xls', 'xlsb', 'xlsm', 'xlt', 'xltm', 'xlw', 'xnk', 'xps', 'xsl', 'xz', 'z')

$script:TRCisDefaultAttachmentTypes = @('ace', 'ani', 'apk', 'app', 'appx', 'arj', 'bat', 'cab', 'cmd', 'com', 'deb', 'dex', 'dll', 'docm', 'elf', 'exe', 'hta', 'img', 'iso', 'jar', 'jnlp', 'kext', 'lha', 'lib', 'library', 'lnk', 'lzh', 'macho', 'msc', 'msi', 'msix', 'msp', 'mst', 'pif', 'ppa', 'ppam', 'reg', 'rev', 'scf', 'scr', 'sct', 'sys', 'uif', 'vb', 'vbe', 'vbs', 'vxd', 'wsc', 'wsf', 'wsh', 'xll', 'xz', 'z')

$script:TRProductivityNames = @{ EXCHANGE_S_STANDARD = 'Exchange'; EXCHANGE_S_ENTERPRISE = 'Exchange'; EXCHANGE_S_DESKLESS = 'Exchange'; SHAREPOINTSTANDARD = 'SharePoint'; SHAREPOINTENTERPRISE = 'SharePoint'; TEAMS1 = 'Teams'; OFFICESUBSCRIPTION = 'Office apps'; OFFICE_BUSINESS = 'Office apps'; MCOSTANDARD = 'Teams phone and meetings' }
$script:TRProductivityPlans = @('EXCHANGE_S_STANDARD', 'EXCHANGE_S_ENTERPRISE', 'EXCHANGE_S_DESKLESS', 'SHAREPOINTSTANDARD', 'SHAREPOINTENTERPRISE', 'TEAMS1', 'OFFICESUBSCRIPTION', 'OFFICE_BUSINESS', 'MCOSTANDARD')

function Get-TRUserPlanNames {
    param($User)
    $skus = Get-TRCached 'SkuPlanMap' {
        $h = @{}
        foreach ($s in (Get-TRItems 'SubscribedSkus')) {
            $h[[string]$s.skuId] = [pscustomobject]@{ Part = [string]$s.skuPartNumber; Plans = @(@($s.servicePlans) | Where-Object { $_ } | ForEach-Object { [pscustomobject]@{ Id = [string]$_.servicePlanId; Name = [string]$_.servicePlanName } }) }
        }
        $h
    }
    $names = @{}
    foreach ($l in @($User.assignedLicenses)) {
        if (-not $l -or -not $l.skuId) { continue }
        $sku = $skus[[string]$l.skuId]
        if (-not $sku) { continue }
        $off = @(Get-TRStrings $l.disabledPlans)
        foreach ($p in $sku.Plans) { if ($off -notcontains $p.Id) { $names[$p.Name] = $sku.Part } }
    }
    $names
}

function Get-TRCisAdminRows {
    @(Get-TRRoleRows | Where-Object { $_.Assignment -eq 'Active' -and $_.PrincipalType -eq 'user' -and ($_.Role -like '*Administrator*' -or $_.RoleTemplate -eq $script:TRGlobalReaderRole) })
}

function Get-TRCaExcludedEverywhere {
    $pol = @(Get-TRItems 'ConditionalAccessPolicies' | Where-Object { [string]$_.state -eq 'enabled' })
    if (-not $pol.Count) { return $null }
    $common = $null
    foreach ($p in $pol) {
        $ex = @(Get-TRStrings $p.conditions.users.excludeUsers)
        if ($null -eq $common) { $common = $ex } else { $common = @($common | Where-Object { $ex -contains $_ }) }
    }
    $users = Get-TRUserIndex
    @(@($common) | ForEach-Object { $u = $users[$_]; if ($u) { [string]$u.userPrincipalName } else { $_ } })
}

Register-TRControl -Framework CIS -Id '1.1.1' -Level L1 -Profile E3 -Title 'Administrative accounts are cloud-only' `
    -Needs 'RoleAssignments', 'Users' -Checks 'PRV-03' -Map 'MS.AAD.7.3v1' `
    -Guidance 'Use separate cloud-only accounts (onmicrosoft.com or a cloud UPN) for every administrative role, never accounts synchronised from on-premises AD.' `
    -Test {
    $users = Get-TRUserIndex
    $rows = Get-TRCisAdminRows
    $by = $rows | Group-Object PrincipalId
    $bad = foreach ($g in $by) {
        $u = $users[[string]$g.Name]
        if ($u -and (Test-TRTrue $u.onPremisesSyncEnabled)) { New-TRAffected ([string]$u.userPrincipalName) (Join-TRList ($g.Group | ForEach-Object { $_.Role } | Select-Object -Unique) 4) }
    }
    $bad = @($bad)
    if ($bad.Count) { return New-TRCtl Fail ('{0} of {1} administrators are synchronised from on-premises.' -f $bad.Count, @($by).Count) $bad }
    New-TRCtl Pass ((Select-TRText @($by).Count 'The only administrator is a cloud-only account.' 'All {0} administrators are cloud-only accounts.') -f @($by).Count)
}

Register-TRControl -Framework CIS -Id '1.1.2' -Level L1 -Profile E3 -Title 'Two emergency access accounts are in place' `
    -Needs 'ConditionalAccessPolicies' -Checks 'IAM-10' `
    -Guidance 'Keep two cloud-only Global Administrator accounts for emergencies, protected with FIDO2 keys or certificates, excluded from Conditional Access, monitored, and covered by a documented procedure.' `
    -Test {
    $ex = Get-TRCaExcludedEverywhere
    if ($null -eq $ex) { return New-TRCtl Manual 'There are no enabled Conditional Access policies to compare. Confirm the emergency access accounts and procedure by hand.' }
    if (-not @($ex).Count) { return New-TRCtl Manual 'No account is excluded from every enabled Conditional Access policy. Confirm whether emergency access accounts exist and how they are protected.' }
    New-TRCtl Manual ('Excluded from every enabled Conditional Access policy: {0}. Confirm these are the emergency access accounts, that they use phishing-resistant sign-in, and that the procedure is documented.' -f (Join-TRList $ex 5))
}

Register-TRControl -Framework CIS -Id '1.1.3' -Level L1 -Profile E3 -Title 'Between two and four Global Administrators' `
    -Needs 'RoleAssignments' -Checks 'PRV-01' -Map 'MS.AAD.7.1v1' `
    -Guidance 'Keep at least two Global Administrators for resilience and no more than four, using narrower roles for day-to-day administration.' `
    -Test {
    $ga = @(Get-TRRoleRows | Where-Object { $_.RoleTemplate -eq $script:TRGlobalAdminRole -and $_.Assignment -eq 'Active' })
    $users = @($ga | Where-Object { $_.PrincipalType -eq 'user' } | Select-Object -ExpandProperty PrincipalUpn -Unique)
    $groups = @($ga | Where-Object { $_.PrincipalType -eq 'group' } | Select-Object -ExpandProperty PrincipalName -Unique)
    $text = ('{0}: {1}.' -f (Format-TRN $users.Count 'Global Administrator account'), (Join-TRList $users 6))
    if ($groups.Count) { $text += ' Groups holding the role are not expanded: ' + (Join-TRList $groups 3) + '.' }
    if ($users.Count -ge 2 -and $users.Count -le 4) { return New-TRCtl Pass $text }
    New-TRCtl Fail $text (@($users | ForEach-Object { New-TRAffected $_ 'Global Administrator' }))
}

Register-TRControl -Framework CIS -Id '1.1.4' -Level L1 -Profile E3 -Title 'Administrators hold only identity licences' `
    -Needs 'RoleAssignments', 'Users', 'SubscribedSkus' -Checks 'PRV-04' `
    -Guidance 'Admin accounts should carry an Entra ID licence only, not Exchange, SharePoint, Teams or Office apps, so they cannot be phished through mail or collaboration.' `
    -Test {
    $users = Get-TRUserIndex
    $ids = @(Get-TRCisAdminRows | Select-Object -ExpandProperty PrincipalId -Unique)
    $bad = foreach ($id in $ids) {
        $u = $users[$id]
        if (-not $u) { continue }
        $plans = Get-TRUserPlanNames $u
        $hit = @($script:TRProductivityPlans | Where-Object { $plans.ContainsKey($_) })
        if ($hit.Count) { New-TRAffected ([string]$u.userPrincipalName) ('Has ' + (Join-TRList ($hit | ForEach-Object { $script:TRProductivityNames[$_] } | Select-Object -Unique) 4)) }
    }
    $bad = @($bad)
    if ($bad.Count) { return New-TRCtl Fail ('{0} of {1} administrators have productivity licences (Exchange, SharePoint, Teams or Office apps).' -f $bad.Count, $ids.Count) $bad }
    New-TRCtl Pass ((Select-TRText $ids.Count 'The only administrator holds no productivity licences.' 'None of the {0} administrators hold productivity licences.') -f $ids.Count)
}

Register-TRControl -Framework CIS -Id '1.2.1' -Level L2 -Profile E3 -Title 'Microsoft 365 groups are private' `
    -Needs 'Groups' -Checks 'COL-04' `
    -Guidance 'Set Microsoft 365 groups and Teams to private unless there is a business reason for them to be public, and approve public groups through governance.' `
    -Test {
    $pub = @(Get-TRItems 'Groups' | Where-Object { @($_.groupTypes) -contains 'Unified' -and [string]$_.visibility -eq 'Public' })
    if ($pub.Count) { return New-TRCtl Fail ((Format-TRN $pub.Count 'public Microsoft 365 group') + '.') (@($pub | ForEach-Object { New-TRAffected ([string]$_.displayName) 'Public' })) }
    New-TRCtl Pass 'All Microsoft 365 groups are private.'
}

Register-TRControl -Framework CIS -Id '1.2.2' -Level L1 -Profile E3 -Title 'Sign-in is blocked for shared mailboxes' `
    -Needs 'ExoMailboxes', 'Users' -Checks 'EXO-16' `
    -Guidance 'Block sign-in on the Entra accounts behind shared mailboxes; people access them through delegated permissions.' `
    -Test {
    $users = Get-TRUserIndex
    $shared = @(Get-TRItems 'ExoMailboxes' | Where-Object { [string]$_.RecipientTypeDetails -eq 'SharedMailbox' })
    $bad = foreach ($m in $shared) {
        $u = $users[[string]$m.ExternalDirectoryObjectId]
        if ($u -and (Test-TRTrue $u.accountEnabled)) { New-TRAffected ([string]$m.PrimarySmtpAddress) 'Sign-in allowed' }
    }
    $bad = @($bad)
    if ($bad.Count) { return New-TRCtl Fail ('{0} of {1} shared mailboxes allow sign-in.' -f $bad.Count, $shared.Count) $bad }
    New-TRCtl Pass ((Select-TRText $shared.Count 'Sign-in is blocked for the only shared mailbox.' 'Sign-in is blocked for all {0} shared mailboxes.') -f $shared.Count)
}

Register-TRControl -Framework CIS -Id '1.3.1' -Level L1 -Profile E3 -Title 'Passwords are set never to expire' `
    -Needs 'Domains' -Checks 'IAM-19' -Map 'MS.AAD.6.1v1' `
    -Guidance 'Set the password expiry policy to never expire, combined with MFA and banned password lists, in line with NCSC and NIST guidance.' `
    -Test {
    $doms = @(Get-TRItems 'Domains' | Where-Object { Test-TRTrue $_.isVerified })
    $bad = @($doms | Where-Object { $null -ne $_.passwordValidityPeriodInDays -and [long]$_.passwordValidityPeriodInDays -ne 2147483647 })
    if ($bad.Count) { return New-TRCtl Fail ('Passwords expire on {0}.' -f (Format-TRN $bad.Count 'domain')) (@($bad | ForEach-Object { New-TRAffected ([string]$_.id) ('Expires after {0}' -f (Format-TRN ([int]$_.passwordValidityPeriodInDays) 'day')) })) }
    New-TRCtl Pass 'Passwords are set never to expire on all verified domains.'
}

Register-TRControl -Framework CIS -Id '1.3.2' -Level L2 -Profile E3 -Title 'Idle web sessions sign out within three hours' `
    -Needs 'ActivityTimeoutPolicies', 'ConditionalAccessPolicies' -Checks 'SPO-06' `
    -Guidance 'Turn on idle session timeout in the Microsoft 365 admin centre (3 hours or less) and add a Conditional Access policy for Office 365 browser sessions using app enforced restrictions.' `
    -Test {
    $pol = @(Get-TRItems 'ActivityTimeoutPolicies')[0]
    $ok1 = $false; $desc = 'Idle session timeout is not configured.'
    if ($pol) {
        $def = @($pol.definition)[0]
        if ($def -is [string]) { try { $def = ConvertFrom-Json -InputObject $def } catch { $def = $null } }
        $t = $null
        foreach ($ap in @(Get-TRPath $def 'ActivityBasedTimeoutPolicy.ApplicationPolicies')) { if ($ap -and $ap.WebSessionIdleTimeout) { $t = [string]$ap.WebSessionIdleTimeout; break } }
        if ($t) {
            $span = [TimeSpan]::Zero
            if ([TimeSpan]::TryParse($t, [ref]$span)) {
                $ok1 = $span.TotalHours -le 3
                $desc = 'Idle session timeout is {0}.' -f $(if ($span.TotalHours -eq 1) { '1 hour' } else { '{0} hours' -f [Math]::Round($span.TotalHours, 1) })
            }
        }
    }
    $ca = @(Get-TRItems (Get-TRBlCaKey) | Where-Object {
            [string]$_.state -eq 'enabled' -and (Test-TRBlAllUsers $_) -and (@(Get-TRStrings $_.conditions.applications.includeApplications) -contains 'Office365') -and
            (@(Get-TRStrings $_.conditions.clientAppTypes) -join ',') -eq 'browser' -and (Test-TRTrue $_.sessionControls.applicationEnforcedRestrictions.isEnabled)
        })
    $desc += $(if ($ca.Count) { ' App enforced restrictions policy: ' + (Get-TRBlCaNames $ca) + '.' } else { ' No Conditional Access policy applies app enforced restrictions to Office 365 browser sessions.' })
    if ($ok1 -and $ca.Count) { return New-TRCtl Pass $desc }
    New-TRCtl Fail $desc
}

Register-TRControl -Framework CIS -Id '1.3.3' -Level L2 -Profile E3 -Title 'External calendar sharing is off' `
    -Needs 'ExoSharingPolicies' -Checks 'EXO-14' -Map 'MS.EXO.6.2v1' `
    -Guidance 'Disable the Default Sharing Policy (or remove anonymous and all-domain calendar sharing) so calendars are not published outside the organisation.' `
    -Test {
    $d = @(Get-TRItems 'ExoSharingPolicies' | Where-Object { (Test-TRTrue $_.Default) -or [string]$_.Name -eq 'Default Sharing Policy' })[0]
    if (-not $d) { return New-TRCtl NotAssessed 'The default sharing policy was not returned.' }
    if (Test-TRFalse $d.Enabled) { return New-TRCtl Pass 'The default sharing policy is disabled.' }
    New-TRCtl Fail ('The default sharing policy is enabled: {0}.' -f (Join-TRList $d.Domains 4))
}

Register-TRControl -Framework CIS -Id '1.3.4' -Level L1 -Profile E3 -Title 'Users cannot use the Office Store or start trials' `
    -Needs 'AppsAndServicesSettings' `
    -Guidance 'In Org settings, User owned apps and services, untick access to the Office Store and the option for users to start trials.' `
    -Test {
    $s = Get-TRRawValue 'AppsAndServicesSettings'
    $store = Get-TRV $s 'isOfficeStoreEnabled'
    $trial = Get-TRV $s 'isAppAndServicesTrialEnabled'
    $text = 'Office Store: {0}; user trials: {1}.' -f $(if (Test-TRTrue $store) { 'allowed' } else { 'blocked' }), $(if (Test-TRTrue $trial) { 'allowed' } else { 'blocked' })
    if ((Test-TRFalse $store) -and (Test-TRFalse $trial)) { return New-TRCtl Pass $text }
    New-TRCtl Fail $text
}

Register-TRControl -Framework CIS -Id '1.3.5' -Level L1 -Profile E3 -Title 'Forms internal phishing protection is on' `
    -Needs 'FormsSettings' `
    -Guidance 'In Org settings, Microsoft Forms, tick Add internal phishing protection.' `
    -Test {
    $v = Get-TRV (Get-TRRawValue 'FormsSettings') 'isInOrgFormsPhishingScanEnabled'
    if (Test-TRTrue $v) { return New-TRCtl Pass 'Internal phishing protection for Forms is on.' }
    New-TRCtl Fail 'Internal phishing protection for Forms is off.'
}

Register-TRControl -Framework CIS -Id '1.3.6' -Level L2 -Profile E5 -Title 'Customer Lockbox is enabled' `
    -Licence 'CustomerLockbox' -Needs 'ExoOrganizationConfig' `
    -Guidance 'Turn on Customer Lockbox so Microsoft engineers need approval before accessing tenant data.' `
    -Test {
    $o = Get-TRRawValue 'ExoOrganizationConfig'
    if (Test-TRTrue $o.CustomerLockBoxEnabled) { return New-TRCtl Pass 'Customer Lockbox is enabled.' }
    New-TRCtl Fail 'Customer Lockbox is disabled.'
}

Register-TRControl -Framework CIS -Id '1.3.7' -Level L2 -Profile E3 -Title 'Third-party storage is off in Microsoft 365 on the web' `
    -Needs 'ServicePrincipals' `
    -Guidance 'In Org settings, Microsoft 365 on the web, untick letting users open files stored in third-party storage services.' `
    -Test {
    $sp = @(Get-TRItems 'ServicePrincipals' | Where-Object { [string]$_.appId -eq 'c1f33bc0-bdb4-4248-ba9b-096807ddb43e' })[0]
    if (-not $sp) { return New-TRCtl Pass 'The third-party storage service principal is not present, so the feature is off.' }
    if (Test-TRFalse $sp.accountEnabled) { return New-TRCtl Pass 'Third-party storage is turned off.' }
    New-TRCtl Fail 'Users can open files stored in third-party storage services.'
}

Register-TRControl -Framework CIS -Id '1.3.8' -Level L2 -Profile E3 -Title 'Sway cannot be shared externally' -ManualOnly `
    -Guidance 'In Org settings, Sway, untick letting people share sways with people outside the organisation. There is no API for this setting.'

Register-TRControl -Framework CIS -Id '1.3.9' -Level L1 -Profile E3 -Title 'Shared Bookings is restricted' `
    -Needs 'ExoOwaPolicies', 'ExoOrganizationConfig' `
    -Guidance 'Turn off Bookings mailbox creation in the default OWA mailbox policy, or turn Bookings off for the organisation, and enable it only for approved users.' `
    -Test {
    $o = Get-TRRawValue 'ExoOrganizationConfig'
    if (Test-TRFalse $o.BookingsEnabled) { return New-TRCtl Pass 'Bookings is turned off for the organisation.' }
    $d = @(Get-TRItems 'ExoOwaPolicies' | Where-Object { (Test-TRTrue $_.IsDefault) -or [string]$_.Name -eq 'OwaMailboxPolicy-Default' })[0]
    if ($d -and (Test-TRFalse $d.BookingsMailboxCreationEnabled)) { return New-TRCtl Pass 'Shared Bookings creation is off in the default OWA policy.' }
    New-TRCtl Fail 'Bookings is on and users can create shared booking pages.'
}

Register-TRControl -Framework CIS -Id '2.1.1' -Level L2 -Profile E5 -Title 'Safe Links protects email, Teams and Office apps' `
    -Licence 'DefenderO365' -Needs 'ExoSafeLinksPolicies' -Checks 'EXO-10' -Map 'MS.SECURITYSUITE.7.1v1', 'MS.SECURITYSUITE.7.2v1', 'MS.SECURITYSUITE.7.3v1' `
    -Guidance 'Apply a Safe Links policy (or the Standard or Strict preset) that covers email, Teams and Office apps, scans URLs in real time, waits for scanning, tracks clicks and does not let users click through.' `
    -Test {
    $active = @(Get-TRActiveExoPolicies -PolicyKey 'ExoSafeLinksPolicies' -RuleKey 'ExoSafeLinksRules' -RuleField 'SafeLinksPolicy' -Plane ATP)
    $want = [ordered]@{ EnableSafeLinksForEmail = $true; EnableSafeLinksForTeams = $true; EnableSafeLinksForOffice = $true; TrackClicks = $true; AllowClickThrough = $false; ScanUrls = $true; EnableForInternalSenders = $true; DeliverMessageAfterScan = $true; DisableUrlRewrite = $false }
    $best = $null; $bestGap = 99
    foreach ($a in $active) {
        $gap = @($want.Keys | Where-Object { $v = Get-TRV $a.Policy $_; if ($want[$_]) { -not (Test-TRTrue $v) } else { Test-TRTrue $v } })
        if ($gap.Count -lt $bestGap) { $best = $a; $bestGap = $gap.Count; $bestList = $gap }
        if (-not $gap.Count) { return New-TRCtl Pass ('{0} meets every setting.' -f $a.Name) }
    }
    if (-not $best) { return New-TRCtl Fail 'No Safe Links policy is applied.' }
    New-TRCtl Fail ('Closest applied policy is {0}, which differs on: {1}.' -f $best.Name, ($bestList -join ', '))
}

Register-TRControl -Framework CIS -Id '2.1.2' -Level L1 -Profile E3 -Title 'The common attachment types filter is on' `
    -Needs 'ExoMalwarePolicies' -Checks 'EXO-12' -Map 'MS.SECURITYSUITE.1.1v1' `
    -Guidance 'Turn on the common attachments filter in the default anti-malware policy with at least the Microsoft default list of file types.' `
    -Test {
    $d = Get-TRExoDefault 'ExoMalwarePolicies'
    if (-not $d) { return New-TRCtl NotAssessed 'The default anti-malware policy was not returned.' }
    if (-not (Test-TRTrue $d.EnableFileFilter)) { return New-TRCtl Fail 'The common attachment types filter is off in the default anti-malware policy.' }
    $have = @(Get-TRStrings $d.FileTypes | ForEach-Object { $_.ToLower() })
    if (-not $have.Count) { return New-TRCtl Pass 'The filter is on. The file type list was not returned, so confirm it includes the default types.' }
    $missing = @($script:TRCisDefaultAttachmentTypes | Where-Object { $have -notcontains $_ })
    if ($missing.Count) { return New-TRCtl Fail ('The filter is on but these default types are missing: {0}.' -f (Join-TRList $missing 10)) }
    New-TRCtl Pass ('The filter is on and blocks {0} file types, including all defaults.' -f $have.Count)
}

Register-TRControl -Framework CIS -Id '2.1.3' -Level L1 -Profile E3 -Title 'Admins are told when internal users send malware' `
    -Needs 'ExoMalwarePolicies' `
    -Guidance 'In the anti-malware policy, turn on notifications to an administrator mailbox when internal senders send malware.' `
    -Test {
    $d = Get-TRExoDefault 'ExoMalwarePolicies'
    if (-not $d) { return New-TRCtl NotAssessed 'The default anti-malware policy was not returned.' }
    if ((Test-TRTrue $d.EnableInternalSenderAdminNotifications) -and [string]$d.InternalSenderAdminAddress) { return New-TRCtl Pass ('Notifications go to {0}.' -f $d.InternalSenderAdminAddress) }
    New-TRCtl Fail 'Internal sender malware notifications are not set up in the default anti-malware policy.'
}

Register-TRControl -Framework CIS -Id '2.1.4' -Level L2 -Profile E5 -Title 'Safe Attachments blocks malicious attachments' `
    -Licence 'DefenderO365' -Needs 'ExoSafeAttachmentPolicies' -Checks 'EXO-11' -Map 'MS.SECURITYSUITE.1.3v1' `
    -Guidance 'Apply a Safe Attachments policy to everyone with the Block action and the AdminOnlyAccessPolicy quarantine policy, or use the Standard or Strict preset.' `
    -Test {
    $top = Get-TRTopExoPolicy (Get-TRActiveExoPolicies -PolicyKey 'ExoSafeAttachmentPolicies' -RuleKey 'ExoSafeAttachmentRules' -RuleField 'SafeAttachmentPolicy' -Plane ATP)
    if (-not $top) { return New-TRCtl Fail 'No Safe Attachments policy is applied.' }
    $p = $top.Policy
    $gaps = @()
    if (-not (Test-TRTrue $p.Enable)) { $gaps += 'not enabled' }
    if ([string]$p.Action -ne 'Block') { $gaps += ('action is ' + [string]$p.Action) }
    if ($p.QuarantineTag -and [string]$p.QuarantineTag -ne 'AdminOnlyAccessPolicy') { $gaps += ('quarantine policy is ' + [string]$p.QuarantineTag) }
    if ($gaps.Count) { return New-TRCtl Fail ('Highest priority policy ({0}): {1}.' -f $top.Name, ($gaps -join ', ')) }
    New-TRCtl Pass ('Highest priority policy ({0}) blocks malware.' -f $top.Name)
}

Register-TRControl -Framework CIS -Id '2.1.5' -Level L2 -Profile E5 -Title 'Safe Attachments covers SharePoint, OneDrive and Teams' `
    -Licence 'DefenderO365' -Needs 'ExoAtpPolicy' -Map 'MS.SECURITYSUITE.1.4v1' `
    -Guidance 'In Safe Attachments global settings, turn on Defender for Office 365 for SharePoint, OneDrive and Teams and Safe Documents, and stop users clicking through Protected View.' `
    -Test {
    $a = Get-TRRawValue 'ExoAtpPolicy'
    $gaps = @()
    if (-not (Test-TRTrue $a.EnableATPForSPOTeamsODB)) { $gaps += 'SharePoint, OneDrive and Teams scanning is off' }
    if (-not (Test-TRTrue $a.EnableSafeDocs)) { $gaps += 'Safe Documents is off' }
    if (Test-TRTrue $a.AllowSafeDocsOpen) { $gaps += 'users can click through Protected View' }
    if ($gaps.Count) { return New-TRCtl Fail (($gaps -join '; ') + '.') }
    New-TRCtl Pass 'SharePoint, OneDrive and Teams scanning and Safe Documents are on.'
}

Register-TRControl -Framework CIS -Id '2.1.6' -Level L1 -Profile E3 -Title 'Outbound spam notifications are set up' `
    -Needs 'ExoOutboundSpamPolicies' `
    -Guidance 'In the default outbound anti-spam policy, copy suspicious outbound messages to and notify a monitored mailbox when a sender is blocked.' `
    -Test {
    $d = Get-TRExoDefault 'ExoOutboundSpamPolicies'
    if (-not $d) { return New-TRCtl NotAssessed 'The default outbound spam policy was not returned.' }
    $bcc = Test-TRTrue $d.BccSuspiciousOutboundMail
    $notify = Test-TRTrue $d.NotifyOutboundSpam
    $text = 'Copy suspicious messages: {0}; notify when blocked: {1}.' -f $(if ($bcc) { 'on (' + (Join-TRList $d.BccSuspiciousOutboundAdditionalRecipients 3) + ')' } else { 'off' }), $(if ($notify) { 'on (' + (Join-TRList $d.NotifyOutboundSpamRecipients 3) + ')' } else { 'off' })
    if ($bcc -and $notify) { return New-TRCtl Pass $text }
    New-TRCtl Fail $text
}

Register-TRControl -Framework CIS -Id '2.1.7' -Level L2 -Profile E5 -Title 'Anti-phishing policy is tuned for impersonation' `
    -Licence 'DefenderO365' -Needs 'ExoAntiPhishPolicies' -Checks 'EXO-09' -Map 'MS.SECURITYSUITE.2.1v1', 'MS.SECURITYSUITE.2.2v1', 'MS.SECURITYSUITE.2.4v1' `
    -Guidance 'Apply an anti-phishing policy to most of the organisation with threshold 3 or higher, user and domain impersonation protection, mailbox intelligence, quarantine actions, all safety tips and honour DMARC.' `
    -Test {
    $active = @(Get-TRActiveExoPolicies -PolicyKey 'ExoAntiPhishPolicies' -RuleKey 'ExoAntiPhishRules' -RuleField 'AntiPhishPolicy' -Plane EOP)
    $bestGap = 99; $best = $null; $bestList = @()
    foreach ($a in $active) {
        $p = $a.Policy
        $gap = @()
        if (-not (Test-TRTrue $p.Enabled) -and $a.Source -eq 'Custom') { $gap += 'disabled' }
        if ([int]$p.PhishThresholdLevel -lt 3) { $gap += ('threshold ' + [string]$p.PhishThresholdLevel) }
        foreach ($k in 'EnableTargetedUserProtection', 'EnableOrganizationDomainsProtection', 'EnableMailboxIntelligence', 'EnableMailboxIntelligenceProtection', 'EnableSpoofIntelligence', 'EnableFirstContactSafetyTips', 'EnableSimilarUsersSafetyTips', 'EnableSimilarDomainsSafetyTips', 'EnableUnusualCharactersSafetyTips', 'HonorDmarcPolicy') {
            if (-not (Test-TRTrue (Get-TRV $p $k))) { $gap += ($k -replace '^Enable', '') }
        }
        foreach ($k in 'TargetedUserProtectionAction', 'TargetedDomainProtectionAction', 'MailboxIntelligenceProtectionAction') {
            if ([string](Get-TRV $p $k) -ne 'Quarantine') { $gap += ('{0} {1}' -f ($k -replace 'ProtectionAction', ''), [string](Get-TRV $p $k)) }
        }
        if (-not @(Get-TRStrings $p.TargetedUsersToProtect).Count) { $gap += 'no users to protect' }
        if ($gap.Count -lt $bestGap) { $best = $a; $bestGap = $gap.Count; $bestList = $gap }
        if (-not $gap.Count) { return New-TRCtl Pass ('{0} meets every setting.' -f $a.Name) }
    }
    if (-not $best) { return New-TRCtl Fail 'No anti-phishing policy is applied.' }
    New-TRCtl Fail ('Closest applied policy is {0}, which differs on: {1}.' -f $best.Name, (Join-TRList $bestList 8))
}

Register-TRControl -Framework CIS -Id '2.1.8' -Level L1 -Profile E3 -Title 'SPF is published for every mail domain' `
    -Needs 'DnsRecords' -Checks 'DNS-01', 'DNS-05' -Map 'MS.EXO.2.2v3' `
    -Guidance 'Publish one SPF record per sending domain ending in -all or ~all, and v=spf1 -all on domains that do not send mail.' `
    -Test {
    $rows = @(Get-TRItems 'DnsRecords')
    if (-not $rows.Count) { return New-TRCtl NotApplicable 'There are no custom domains.' }
    $bad = foreach ($r in $rows) {
        $sends = $r.SupportsEmail -or @($r.Mx).Count -gt 0
        if ($sends) { $p = Test-TRSpfOk $r; if ($p) { New-TRAffected ([string]$r.Domain) $p } }
        else {
            $spf = @(Get-TRStrings $r.Spf)
            if (-not ($spf.Count -eq 1 -and $spf[0] -match '^\s*v=spf1\s+-all\s*$')) { New-TRAffected ([string]$r.Domain) ('Non-mail domain without v=spf1 -all' + $(if ($spf.Count) { ': ' + $spf[0] } else { '' })) }
        }
    }
    $bad = @($bad)
    if ($bad.Count) { return New-TRCtl Fail ('{0} of {1} domains do not meet the SPF requirement.' -f $bad.Count, $rows.Count) $bad }
    New-TRCtl Pass ((Select-TRText $rows.Count 'The only custom domain has a compliant SPF record.' 'All {0} custom domains have a compliant SPF record.') -f $rows.Count)
}

Register-TRControl -Framework CIS -Id '2.1.9' -Level L1 -Profile E3 -Title 'DKIM is enabled for every mail domain' `
    -Needs 'DnsRecords', 'ExoDkim' -Checks 'DNS-02' -Map 'MS.EXO.3.1v1' `
    -Guidance 'Publish the selector CNAME records and enable DKIM signing for every custom domain that sends mail.' `
    -Test {
    $rows = Get-TRMailRows
    if (-not $rows.Count) { return New-TRCtl NotApplicable 'No custom domains send mail.' }
    $dk = @{}
    foreach ($d in (Get-TRItems 'ExoDkim')) { $dk[([string]$d.Domain).ToLower()] = $d }
    $bad = @($rows | Where-Object { $c = $dk[([string]$_.Domain).ToLower()]; -not ($c -and (Test-TRTrue $c.Enabled)) } | ForEach-Object { New-TRAffected ([string]$_.Domain) 'DKIM signing off' })
    if ($bad.Count) { return New-TRCtl Fail ('{0} of {1} mail domains are not DKIM signing.' -f $bad.Count, $rows.Count) $bad }
    New-TRCtl Pass ((Select-TRText $rows.Count 'DKIM signing is on for the only mail domain.' 'DKIM signing is on for all {0} mail domains.') -f $rows.Count)
}

Register-TRControl -Framework CIS -Id '2.1.10' -Level L1 -Profile E3 -Title 'DMARC is enforced with reporting' `
    -Needs 'DnsRecords' -Checks 'DNS-03', 'DNS-04' -Map 'MS.EXO.4.1v1', 'MS.EXO.4.2v1', 'MS.EXO.4.4v1' `
    -Guidance 'Publish DMARC with p=quarantine or p=reject, pct=100, and rua and ruf reporting addresses on every custom domain and the onmicrosoft.com domain.' `
    -Test {
    $rows = @(Get-TRItems 'DnsRecords' | ForEach-Object { [pscustomobject]@{ Domain = $_.Domain; Dmarc = $_.Dmarc } })
    $m = Get-TRRawValue 'DnsMoera'
    if ($m) { $rows += [pscustomobject]@{ Domain = $m.Domain; Dmarc = $m.Dmarc } }
    $bad = foreach ($r in $rows) {
        $rec = @(Get-TRStrings $r.Dmarc)[0]
        if (-not $rec) { New-TRAffected ([string]$r.Domain) 'No DMARC record'; continue }
        $t = ConvertFrom-TRDmarc $rec
        $issues = @()
        if (@('quarantine', 'reject') -notcontains ([string]$t['p']).ToLower()) { $issues += ('p=' + $t['p']) }
        if ($t.ContainsKey('pct') -and [string]$t['pct'] -ne '100') { $issues += ('pct=' + $t['pct']) }
        if (-not $t['rua']) { $issues += 'no rua' }
        if (-not $t['ruf']) { $issues += 'no ruf' }
        if ($issues.Count) { New-TRAffected ([string]$r.Domain) ($issues -join ', ') }
    }
    $bad = @($bad)
    if ($bad.Count) { return New-TRCtl Fail ('{0} of {1} domains do not meet the DMARC requirement.' -f $bad.Count, $rows.Count) $bad }
    New-TRCtl Pass ((Select-TRText $rows.Count 'The only domain enforces DMARC with reporting.' 'All {0} domains enforce DMARC with reporting.') -f $rows.Count)
}

Register-TRControl -Framework CIS -Id '2.1.11' -Level L2 -Profile E3 -Title 'A comprehensive attachment filter is in place' `
    -Needs 'ExoMalwarePolicies' -Map 'MS.SECURITYSUITE.1.1v1' `
    -Guidance 'Apply an anti-malware policy that blocks at least 90% of the extended list of risky file types (184 types), documenting any exceptions.' `
    -Test {
    $active = @(Get-TRActiveExoPolicies -PolicyKey 'ExoMalwarePolicies' -RuleKey 'ExoMalwareRules' -RuleField 'MalwareFilterPolicy' -Plane EOP)
    $limit = [int]($script:TRCisAttachmentTypes.Count * 0.1)
    $best = $null; $bestMissing = 999
    foreach ($a in $active) {
        if (-not (Test-TRTrue $a.Policy.EnableFileFilter)) { continue }
        $have = @(Get-TRStrings $a.Policy.FileTypes | ForEach-Object { $_.ToLower() })
        if ($have.Count -le 120) { continue }
        $missing = @($script:TRCisAttachmentTypes | Where-Object { $have -notcontains $_.ToLower() })
        if ($missing.Count -lt $bestMissing) { $best = $a; $bestMissing = $missing.Count; $bestList = $missing }
    }
    if (-not $best) { return New-TRCtl Fail 'No applied anti-malware policy blocks more than 120 file types.' }
    if ($bestMissing -le $limit) { return New-TRCtl Pass ('{0} covers all but {1} of the {2} listed types.' -f $best.Name, $bestMissing, $script:TRCisAttachmentTypes.Count) }
    New-TRCtl Fail ('{0} is missing {1}: {2}.' -f $best.Name, (Format-TRN $bestMissing 'listed type'), (Join-TRList $bestList 12))
}

Register-TRControl -Framework CIS -Id '2.1.12' -Level L1 -Profile E3 -Title 'The connection filter IP allow list is empty' `
    -Needs 'ExoConnectionFilter' -Map 'MS.SECURITYSUITE.8.1v1' `
    -Guidance 'Remove entries from the IP allow list in the default connection filter policy; use mail flow rules or the Tenant Allow/Block List with care instead.' `
    -Test {
    $d = Get-TRExoDefault 'ExoConnectionFilter'
    if (-not $d) { return New-TRCtl NotAssessed 'The default connection filter policy was not returned.' }
    $ips = @(Get-TRStrings $d.IPAllowList)
    if ($ips.Count) { return New-TRCtl Fail ('The IP allow list has {0}: {1}.' -f (Format-TRN $ips.Count 'entry' 'entries'), (Join-TRList $ips 5)) }
    New-TRCtl Pass 'The IP allow list is empty.'
}

Register-TRControl -Framework CIS -Id '2.1.13' -Level L1 -Profile E3 -Title 'The connection filter safe list is off' `
    -Needs 'ExoConnectionFilter' -Map 'MS.SECURITYSUITE.8.2v1' `
    -Guidance 'Turn off the safe list in the default connection filter policy.' `
    -Test {
    $d = Get-TRExoDefault 'ExoConnectionFilter'
    if (-not $d) { return New-TRCtl NotAssessed 'The default connection filter policy was not returned.' }
    if (Test-TRTrue $d.EnableSafeList) { return New-TRCtl Fail 'The safe list is on.' }
    New-TRCtl Pass 'The safe list is off.'
}

Register-TRControl -Framework CIS -Id '2.1.14' -Level L1 -Profile E3 -Title 'Inbound anti-spam policies allow no sender domains' `
    -Needs 'ExoContentFilterPolicies' -Checks 'EXO-08' -Map 'MS.SECURITYSUITE.6.2v1' `
    -Guidance 'Remove all allowed sender domains from inbound anti-spam policies.' `
    -Test {
    $bad = @(Get-TRItems 'ExoContentFilterPolicies' | Where-Object { @(Get-TRStrings $_.AllowedSenderDomains).Count -gt 0 } | ForEach-Object { New-TRAffected ([string]$_.Name) (Join-TRList $_.AllowedSenderDomains 5) })
    if ($bad.Count) { return New-TRCtl Fail ((Select-TRText $bad.Count '1 anti-spam policy allows whole sender domains.' '{0} anti-spam policies allow whole sender domains.') -f $bad.Count) $bad }
    New-TRCtl Pass 'No inbound anti-spam policy allows whole sender domains.'
}

Register-TRControl -Framework CIS -Id '2.1.15' -Level L1 -Profile E3 -Title 'Outbound spam limits are set' `
    -Needs 'ExoOutboundSpamPolicies' `
    -Guidance 'In the default outbound anti-spam policy set limits of 500 external and 1000 internal recipients per hour and 1000 per day, restrict the user when reached and notify a monitored mailbox.' `
    -Test {
    $d = Get-TRExoDefault 'ExoOutboundSpamPolicies'
    if (-not $d) { return New-TRCtl NotAssessed 'The default outbound spam policy was not returned.' }
    $gaps = @()
    $e = [int]$d.RecipientLimitExternalPerHour; $i = [int]$d.RecipientLimitInternalPerHour; $day = [int]$d.RecipientLimitPerDay
    $fmt = { param($v) if ($v -le 0) { 'the service default' } else { [string]$v } }
    if ($e -le 0 -or $e -gt 500) { $gaps += ('the external recipient limit per hour is ' + (& $fmt $e)) }
    if ($i -le 0 -or $i -gt 1000) { $gaps += ('the internal recipient limit per hour is ' + (& $fmt $i)) }
    if ($day -le 0 -or $day -gt 1000) { $gaps += ('the daily recipient limit is ' + (& $fmt $day)) }
    if ([string]$d.ActionWhenThresholdReached -ne 'BlockUser') { $gaps += ('the action when a limit is reached is ' + [string]$d.ActionWhenThresholdReached) }
    if (-not @(Get-TRStrings $d.NotifyOutboundSpamRecipients).Count) { $gaps += 'no notification recipients are set' }
    if ($gaps.Count) { $t = $gaps -join '; '; return New-TRCtl Fail ($t.Substring(0, 1).ToUpper() + $t.Substring(1) + '.') }
    New-TRCtl Pass ('Limits {0}/{1}/{2}, users blocked when reached.' -f $e, $i, $day)
}

Register-TRControl -Framework CIS -Id '2.2.1' -Level L1 -Profile E5 -Title 'Emergency account activity is monitored' -ManualOnly `
    -Licence 'DefenderCloudApps' `
    -Guidance 'Create a Defender for Cloud Apps or Sentinel alert for sign-ins and activity by the emergency access accounts that notifies other administrators.'

Register-TRControl -Framework CIS -Id '2.4.1' -Level L1 -Profile E5 -Title 'Priority account protection is on' `
    -Licence 'DefenderO365P2' -Needs 'ExoEmailTenantSettings' `
    -Guidance 'Turn on priority account protection, tag executives and other high-risk users as priority accounts, and create high-severity alert policies for them.' `
    -Test {
    $s = Get-TRRawValue 'ExoEmailTenantSettings'
    if (-not (Test-TRTrue $s.EnablePriorityAccountProtection)) { return New-TRCtl Fail 'Priority account protection is off.' }
    $alerts = @(Get-TRItems 'SccAlertPolicies' | Where-Object { [string]$_.RecipientTags -match 'Priority' })
    New-TRCtl Manual ('Priority account protection is on. Alert policies for priority accounts: {0}. Confirm the right users are tagged.' -f $(if ($alerts.Count) { Join-TRList ($alerts | ForEach-Object { $_.Name }) 4 } else { 'none found' }))
}

Register-TRControl -Framework CIS -Id '2.4.2' -Level L1 -Profile E5 -Title 'Strict preset policies protect priority accounts' `
    -Licence 'DefenderO365' -Needs 'ExoPresetEop', 'ExoPresetAtp' `
    -Guidance 'Turn on the Strict preset security policy and add priority accounts or groups to both the Exchange Online Protection and Defender for Office 365 sections.' `
    -Test {
    $gaps = @()
    foreach ($plane in 'EOP', 'ATP') {
        $r = Get-TRPresetRule Strict $plane
        if (-not $r) { $gaps += ($plane + ' rule missing'); continue }
        if ([string]$r.State -ne 'Enabled') { $gaps += ($plane + ' rule off') }
        if (-not (@(Get-TRStrings $r.SentTo) + @(Get-TRStrings $r.SentToMemberOf) + @(Get-TRStrings $r.RecipientDomainIs)).Count) { $gaps += ($plane + ' rule has no recipients') }
    }
    if ($gaps.Count) { return New-TRCtl Fail ('Strict preset: ' + ($gaps -join '; ') + '.') }
    New-TRCtl Pass 'The Strict preset is on for named recipients in both sections.'
}

Register-TRControl -Framework CIS -Id '2.4.3' -Level L2 -Profile E5 -Title 'Defender for Cloud Apps is connected' -ManualOnly `
    -Licence 'DefenderCloudApps' `
    -Guidance 'In Defender for Cloud Apps, App connectors, confirm Microsoft 365 and Microsoft Azure show as Connected.'

Register-TRControl -Framework CIS -Id '2.4.4' -Level L1 -Profile E5 -Title 'Zero-hour auto purge is on for Teams' `
    -Licence 'DefenderO365P2' -Needs 'ExoTeamsProtection' `
    -Guidance 'In Defender, Microsoft Teams protection, keep zero-hour auto purge on and review any excluded participants.' `
    -Test {
    $p = Get-TRRawValue 'ExoTeamsProtection'
    if (-not (Test-TRTrue $p.ZapEnabled)) { return New-TRCtl Fail 'Zero-hour auto purge for Teams is off.' }
    $ex = @()
    foreach ($r in (Get-TRItems 'ExoTeamsProtectionRules')) { $ex += @(Get-TRStrings $r.ExceptIfSentTo) + @(Get-TRStrings $r.ExceptIfSentToMemberOf) + @(Get-TRStrings $r.ExceptIfRecipientDomainIs) }
    New-TRCtl Pass ('Zero-hour auto purge for Teams is on.' + $(if ($ex.Count) { ' Review exclusions: ' + (Join-TRList $ex 5) + '.' } else { ' No exclusions.' }))
}

Register-TRControl -Framework CIS -Id '2.4.5' -Level L1 -Profile E5 -Title 'Automated investigation groups similar messages' -ManualOnly `
    -Licence 'DefenderO365P2' `
    -Guidance 'In Defender settings for automated investigation and response, tick similar files, similar URLs and multiple similar attributes under message clusters.'

Register-TRControl -Framework CIS -Id '3.1.1' -Level L1 -Profile E3 -Title 'Audit log search is on' `
    -Needs 'ExoAdminAuditLogConfig' -Checks 'EXO-01' -Map 'MS.SECURITYSUITE.5.1v1' `
    -Guidance 'Turn on audit log ingestion in Microsoft Purview, Audit.' `
    -Test {
    $a = Get-TRRawValue 'ExoAdminAuditLogConfig'
    if (Test-TRTrue $a.UnifiedAuditLogIngestionEnabled) { return New-TRCtl Pass 'Unified audit log ingestion is on.' }
    New-TRCtl Fail 'Unified audit log ingestion is off.'
}

Register-TRControl -Framework CIS -Id '3.2.1' -Level L1 -Profile E3 -Title 'DLP policies are turned on' `
    -Licence 'Dlp' -Needs 'SccDlpPolicies' -Checks 'PUR-01' -Map 'MS.SECURITYSUITE.3.1v1', 'MS.SECURITYSUITE.3.2v1' `
    -Guidance 'Create and enforce DLP policies for Exchange, SharePoint and OneDrive covering the sensitive information the organisation handles.' `
    -Test {
    $on = Get-TRDlpActive
    if ($on.Count) { return New-TRCtl Pass ('Enforced DLP policies: {0}.' -f (Join-TRList ($on | ForEach-Object { $_.Name }) 5)) }
    $any = @(Get-TRItems 'SccDlpPolicies')
    New-TRCtl Fail $(if ($any.Count) { 'DLP policies exist but none are enforced (test or off): ' + (Join-TRList ($any | ForEach-Object { $_.Name }) 5) + '.' } else { 'No DLP policies exist.' })
}

Register-TRControl -Framework CIS -Id '3.2.2' -Level L1 -Profile E5 -Title 'DLP covers Teams chats and channels' `
    -Licence 'ComplianceE5' -Needs 'SccDlpPolicies' -Map 'MS.SECURITYSUITE.3.2v1' `
    -Guidance 'Enforce a DLP policy for all Teams chat and channel messages, with only documented exceptions.' `
    -Test {
    $t = @(Get-TRDlpActive | Where-Object { [string]$_.TeamsLocation -eq 'All' -or [string]$_.TeamsChatLocation -eq 'All' -or [string]$_.TeamsChannelLocation -eq 'All' })
    if ($t.Count) { return New-TRCtl Pass ('Teams is covered by: {0}.' -f (Join-TRList ($t | ForEach-Object { $_.Name }) 4)) }
    New-TRCtl Fail 'No enforced DLP policy covers all Teams chats and channels.'
}

Register-TRControl -Framework CIS -Id '3.2.3' -Level L1 -Profile E5 -Title 'DLP covers Microsoft 365 Copilot' `
    -Licence 'Copilot' -Needs 'SccDlpPolicies' `
    -Guidance 'Enforce a DLP policy for Microsoft 365 Copilot and Copilot Chat so labelled or sensitive content is not processed or surfaced.' `
    -Test {
    $c = @(Get-TRDlpActive | Where-Object { (Join-TRList $_.EnforcementPlanes 20) -match 'Copilot' })
    if ($c.Count) { return New-TRCtl Pass ('Copilot is covered by: {0}.' -f (Join-TRList ($c | ForEach-Object { $_.Name }) 4)) }
    New-TRCtl Fail 'No enforced DLP policy targets Microsoft 365 Copilot.'
}

Register-TRControl -Framework CIS -Id '3.3.1' -Level L1 -Profile E3 -Title 'Sensitivity label policies are published' `
    -Needs 'SccLabelPolicies' -Checks 'PUR-03' `
    -Guidance 'Create sensitivity labels and publish them with a label policy so users can classify content.' `
    -Test {
    $p = @(Get-TRItems 'SccLabelPolicies' | Where-Object { -not (Test-TRFalse $_.Enabled) })
    if ($p.Count) { return New-TRCtl Pass ('Published label policies: {0}.' -f (Join-TRList ($p | ForEach-Object { $_.Name }) 4)) }
    New-TRCtl Fail 'No sensitivity label policy is published.'
}

Register-TRControl -Framework CIS -Id '4.1' -Level L1 -Profile E3 -Title 'Devices without a compliance policy are non-compliant' `
    -Licence 'Intune' -Needs 'DeviceManagement' -Checks 'END-02' `
    -Guidance 'In Intune compliance policy settings, mark devices with no compliance policy assigned as Not compliant.' `
    -Test {
    $v = Get-TRPath (Get-TRRawValue 'DeviceManagement') 'settings.secureByDefault'
    if (Test-TRTrue $v) { return New-TRCtl Pass 'Devices with no compliance policy are marked not compliant.' }
    New-TRCtl Fail 'Devices with no compliance policy are treated as compliant.'
}

Register-TRControl -Framework CIS -Id '4.2' -Level L1 -Profile E3 -Title 'Personal devices cannot enrol in Intune' `
    -Licence 'Intune' -Needs 'EnrollmentConfigurations' -Checks 'END-08' `
    -Guidance 'In the default device platform restriction, block personally owned devices for every platform, or block platforms that are not used.' `
    -Test {
    $d = @(Get-TRItems 'EnrollmentConfigurations' | Where-Object { [string]$_.id -match 'DefaultPlatformRestrictions' -and ([int]$_.priority -eq 0) -and ([string]$_.'@odata.type' -match 'PlatformRestrictionsConfiguration$') })[0]
    if (-not $d) { $d = @(Get-TRItems 'EnrollmentConfigurations' | Where-Object { [string]$_.'@odata.type' -match 'deviceEnrollmentPlatformRestrictionsConfiguration' })[0] }
    if (-not $d) { return New-TRCtl NotAssessed 'The default platform restriction was not returned.' }
    $open = @()
    foreach ($k in 'windowsRestriction', 'iosRestriction', 'androidRestriction', 'androidForWorkRestriction', 'macOSRestriction') {
        $r = Get-TRV $d $k
        if ($null -eq $r) { continue }
        if ((Test-TRTrue $r.platformBlocked) -or (Test-TRTrue $r.personalDeviceEnrollmentBlocked)) { continue }
        $open += ($k -replace 'Restriction$', '')
    }
    if ($open.Count) { return New-TRCtl Fail ('Personal devices can enrol on: {0}.' -f ($open -join ', ')) }
    New-TRCtl Pass 'Personal device enrolment is blocked on every platform.'
}

Register-TRControl -Framework CIS -Id '5.1.2.1' -Level L1 -Profile E3 -Title 'Per-user MFA is turned off' -ManualOnly `
    -Guidance 'In Entra ID, Per-user MFA, confirm every account shows Disabled, and enforce MFA with Conditional Access instead.'

Register-TRControl -Framework CIS -Id '5.1.2.2' -Level L1 -Profile E3 -Title 'Users cannot register applications' `
    -Needs 'AuthorizationPolicy' -Checks 'IAM-15' -Map 'MS.AAD.5.1v1' `
    -Guidance 'Set Users can register applications to No.' `
    -Test {
    if (Test-TRFalse (Get-TRPath (Get-TRRawValue 'AuthorizationPolicy') 'defaultUserRolePermissions.allowedToCreateApps')) { return New-TRCtl Pass 'Users cannot register applications.' }
    New-TRCtl Fail 'Users can register applications.'
}

Register-TRControl -Framework CIS -Id '5.1.2.3' -Level L1 -Profile E3 -Title 'Users cannot create tenants' `
    -Needs 'AuthorizationPolicy' -Checks 'IAM-15' `
    -Guidance 'Set Restrict non-admin users from creating tenants to Yes.' `
    -Test {
    if (Test-TRFalse (Get-TRPath (Get-TRRawValue 'AuthorizationPolicy') 'defaultUserRolePermissions.allowedToCreateTenants')) { return New-TRCtl Pass 'Users cannot create tenants.' }
    New-TRCtl Fail 'Users can create tenants.'
}

Register-TRControl -Framework CIS -Id '5.1.2.4' -Level L1 -Profile E3 -Title 'Entra admin centre access is restricted' -ManualOnly `
    -Guidance 'In Entra ID, User settings, set Restrict access to Microsoft Entra admin center to Yes.'

Register-TRControl -Framework CIS -Id '5.1.2.5' -Level L2 -Profile E3 -Title 'The stay signed in prompt is hidden' -ManualOnly `
    -Guidance 'In Company branding, set Show option to remain signed in to No.'

Register-TRControl -Framework CIS -Id '5.1.2.6' -Level L2 -Profile E3 -Title 'LinkedIn account connections are off' -ManualOnly `
    -Guidance 'In Entra ID, User settings, set LinkedIn account connections to No.'

Register-TRControl -Framework CIS -Id '5.1.3.1' -Level L1 -Profile E3 -Title 'Users cannot create security groups' `
    -Needs 'AuthorizationPolicy' `
    -Guidance 'Set Users can create security groups to No.' `
    -Test {
    if (Test-TRFalse (Get-TRPath (Get-TRRawValue 'AuthorizationPolicy') 'defaultUserRolePermissions.allowedToCreateSecurityGroups')) { return New-TRCtl Pass 'Users cannot create security groups.' }
    New-TRCtl Fail 'Users can create security groups.'
}

Register-TRControl -Framework CIS -Id '5.1.3.2' -Level L2 -Profile E3 -Title 'My Groups web access is restricted' -ManualOnly `
    -Guidance 'In Entra ID, Groups, General, set Restrict user ability to access groups features in My Groups to Yes.'

Register-TRControl -Framework CIS -Id '5.1.3.3' -Level L1 -Profile E3 -Title 'Self-service group management is restricted' -ManualOnly `
    -Guidance 'In Entra ID, Groups, General, set Owners can manage group membership requests in My Groups to No.'

Register-TRControl -Framework CIS -Id '5.1.3.4' -Level L2 -Profile E3 -Title 'Microsoft 365 group creation is restricted' `
    -Needs 'GroupSettings' -Checks 'COL-01' `
    -Guidance 'Set EnableGroupCreation to false in the Group.Unified directory setting and allow a named security group to create groups.' `
    -Test {
    $v = Get-TRGroupSettingValue 'Group.Unified' 'EnableGroupCreation'
    if ([string]$v -eq 'false' -or [string]$v -eq 'False') { return New-TRCtl Pass 'Only approved users can create Microsoft 365 groups.' }
    New-TRCtl Fail 'All users can create Microsoft 365 groups.'
}

Register-TRControl -Framework CIS -Id '5.1.4.1' -Level L2 -Profile E3 -Title 'Entra join is limited to selected users' `
    -Needs 'DeviceRegistrationPolicy' `
    -Guidance 'Set Users may join devices to Microsoft Entra to Selected or None.' `
    -Test {
    $t = [string](Get-TRPath (Get-TRRawValue 'DeviceRegistrationPolicy') 'azureADJoin.allowedToJoin.@odata.type')
    if ($t -match 'enumerated|noDeviceRegistration') { return New-TRCtl Pass 'Only selected users can join devices.' }
    New-TRCtl Fail 'All users can join devices to Entra ID.'
}

Register-TRControl -Framework CIS -Id '5.1.4.2' -Level L1 -Profile E3 -Title 'Each user can register ten devices or fewer' `
    -Needs 'DeviceRegistrationPolicy' `
    -Guidance 'Set Maximum number of devices per user to 10 or less.' `
    -Test {
    $q = Get-TRV (Get-TRRawValue 'DeviceRegistrationPolicy') 'userDeviceQuota'
    if ($null -ne $q -and [int]$q -le 10) { return New-TRCtl Pass ('The device limit is {0}.' -f $q) }
    New-TRCtl Fail ('The device limit is {0}.' -f $(if ($null -eq $q) { 'not set' } else { $q }))
}

Register-TRControl -Framework CIS -Id '5.1.4.3' -Level L1 -Profile E3 -Title 'Global Administrators are not added as local admins' `
    -Needs 'DeviceRegistrationPolicy' `
    -Guidance 'Set Global administrator role is added as local administrator on the device during Microsoft Entra join to No, and use Windows LAPS instead.' `
    -Test {
    $v = Get-TRPath (Get-TRRawValue 'DeviceRegistrationPolicy') 'azureADJoin.localAdmins.enableGlobalAdmins'
    if (Test-TRFalse $v) { return New-TRCtl Pass 'Global Administrators are not made local administrators.' }
    New-TRCtl Fail 'Global Administrators become local administrators on every joined device.'
}

Register-TRControl -Framework CIS -Id '5.1.4.4' -Level L1 -Profile E3 -Title 'The registering user is not made local admin' `
    -Needs 'DeviceRegistrationPolicy' `
    -Guidance 'Set Registering user is added as local administrator on the device during Microsoft Entra join to Selected or None.' `
    -Test {
    $t = [string](Get-TRPath (Get-TRRawValue 'DeviceRegistrationPolicy') 'azureADJoin.localAdmins.registeringUsers.@odata.type')
    if ($t -match 'enumerated|noDeviceRegistration') { return New-TRCtl Pass 'Registering users are not made local administrators.' }
    New-TRCtl Fail 'Every user who joins a device becomes its local administrator.'
}

Register-TRControl -Framework CIS -Id '5.1.4.5' -Level L1 -Profile E3 -Title 'Entra LAPS is turned on' `
    -Needs 'DeviceRegistrationPolicy' -Checks 'IAM-25' `
    -Guidance 'Set Enable Microsoft Entra Local Administrator Password Solution (LAPS) to Yes and deploy a Windows LAPS policy.' `
    -Test {
    if (Test-TRTrue (Get-TRPath (Get-TRRawValue 'DeviceRegistrationPolicy') 'localAdminPassword.isEnabled')) { return New-TRCtl Pass 'Entra LAPS is turned on.' }
    New-TRCtl Fail 'Entra LAPS is turned off.'
}

Register-TRControl -Framework CIS -Id '5.1.4.6' -Level L2 -Profile E3 -Title 'Users cannot read their own BitLocker keys' `
    -Needs 'AuthorizationPolicy' `
    -Guidance 'Set Restrict users from recovering the BitLocker key(s) for their owned devices to Yes.' `
    -Test {
    if (Test-TRFalse (Get-TRPath (Get-TRRawValue 'AuthorizationPolicy') 'defaultUserRolePermissions.allowedToReadBitlockerKeysForOwnedDevice')) { return New-TRCtl Pass 'Users cannot read BitLocker keys.' }
    New-TRCtl Fail 'Users can read the BitLocker keys of their own devices.'
}

Register-TRControl -Framework CIS -Id '5.1.5.1' -Level L2 -Profile E3 -Title 'Users cannot consent to applications' `
    -Needs 'AuthorizationPolicy' -Checks 'IAM-13' -Map 'MS.AAD.5.2v1' `
    -Guidance 'Set user consent for applications to Do not allow user consent and use the admin consent workflow.' `
    -Test {
    $p = @(Get-TRStrings (Get-TRPath (Get-TRRawValue 'AuthorizationPolicy') 'defaultUserRolePermissions.permissionGrantPoliciesAssigned') | Where-Object { $_ -like 'ManagePermissionGrantsForSelf.*' })
    if ($p.Count) { return New-TRCtl Fail ('User consent is allowed: {0}.' -f (($p | ForEach-Object { Format-TRConsentPolicy $_ }) -join '; ')) }
    New-TRCtl Pass 'Users cannot consent to applications.'
}

Register-TRControl -Framework CIS -Id '5.1.5.2' -Level L1 -Profile E3 -Title 'The admin consent workflow is on' `
    -Needs 'AdminConsentPolicy' -Checks 'IAM-14' -Map 'MS.AAD.5.3v1' `
    -Guidance 'Turn on the admin consent request workflow with named reviewers.' `
    -Test {
    if (Test-TRTrue (Get-TRRawValue 'AdminConsentPolicy').isEnabled) { return New-TRCtl Pass 'The admin consent workflow is on.' }
    New-TRCtl Fail 'The admin consent workflow is off.'
}

Register-TRControl -Framework CIS -Id '5.1.5.3' -Level L2 -Profile E3 -Title 'Apps cannot add password credentials' `
    -Needs 'DefaultAppMgmtPolicy' -Map 'MS.AAD.5.5v1' `
    -Guidance 'Enable the tenant app management policy restriction that blocks new password credentials for applications and service principals.' `
    -Test { Test-TRAppRestriction -Type 'passwordAddition' -Label 'New client secrets blocked' }

Register-TRControl -Framework CIS -Id '5.1.5.4' -Level L1 -Profile E3 -Title 'App secrets last 180 days or less' `
    -Needs 'DefaultAppMgmtPolicy' -Map 'MS.AAD.5.6v1' `
    -Guidance 'Enable the app management policy restriction that limits client secret lifetime to 180 days or less.' `
    -Test { Test-TRAppRestriction -Type 'passwordLifetime' -MaxDays 180 -Label 'Client secret lifetime limit' }

Register-TRControl -Framework CIS -Id '5.1.5.5' -Level L1 -Profile E3 -Title 'Custom app passwords are blocked' `
    -Needs 'DefaultAppMgmtPolicy' `
    -Guidance 'Enable the app management policy restriction that blocks custom (caller supplied) password credentials.' `
    -Test { Test-TRAppRestriction -Type 'customPasswordAddition' -Label 'Custom passwords blocked' }

Register-TRControl -Framework CIS -Id '5.1.5.6' -Level L1 -Profile E3 -Title 'App certificates last 180 days or less' `
    -Needs 'DefaultAppMgmtPolicy' -Map 'MS.AAD.5.7v1' `
    -Guidance 'Enable the app management policy restriction that limits certificate credential lifetime.' `
    -Test { Test-TRAppRestriction -Type 'asymmetricKeyLifetime' -Kind keyCredentials -MaxDays 180 -Label 'Certificate lifetime limit' }

Register-TRControl -Framework CIS -Id '5.1.6.1' -Level L2 -Profile E3 -Title 'Guest invitations are limited to approved domains' `
    -Needs 'B2BManagementPolicy' -Map 'MS.AAD.8.3v1' `
    -Guidance 'In External collaboration settings, allow invitations only to the specified domains and list the approved partner domains.' `
    -Test {
    $b = Get-TRRawValue 'B2BManagementPolicy'
    if ($b -and (Test-TRTrue $b.Present) -and $null -ne $b.AllowedDomains -and $null -eq $b.BlockedDomains) { return New-TRCtl Pass ('Invitations are limited to: {0}.' -f $(if (@($b.AllowedDomains).Count) { Join-TRList $b.AllowedDomains 6 } else { 'no domains' })) }
    if ($b -and $null -ne $b.BlockedDomains) { return New-TRCtl Fail ('A block list is used instead of an allow list: {0}.' -f (Join-TRList $b.BlockedDomains 6)) }
    New-TRCtl Fail 'Invitations can be sent to any domain.'
}

Register-TRControl -Framework CIS -Id '5.1.6.2' -Level L1 -Profile E3 -Title 'Guest access to directory objects is restricted' `
    -Needs 'AuthorizationPolicy' -Checks 'IAM-17' -Map 'MS.AAD.8.1v1' `
    -Guidance 'Set guest user access to limited or restricted.' `
    -Test {
    $g = [string](Get-TRRawValue 'AuthorizationPolicy').guestUserRoleId
    if ($g -eq '10dae51f-b6af-4016-8d66-8c2a99b929b3') { return New-TRCtl Pass 'Guests have limited access.' }
    if ($g -eq '2af84b1e-32c8-42b7-82bc-daa82404023b') { return New-TRCtl Pass 'Guests have the most restricted access.' }
    New-TRCtl Fail 'Guests have the same access as members.'
}

Register-TRControl -Framework CIS -Id '5.1.6.3' -Level L2 -Profile E3 -Title 'Only admins and Guest Inviters can invite guests' `
    -Needs 'AuthorizationPolicy' -Checks 'IAM-16' -Map 'MS.AAD.8.2v1' `
    -Guidance 'Set guest invite restrictions to Only users assigned to specific admin roles can invite guest users, or No one.' `
    -Test {
    $v = [string](Get-TRRawValue 'AuthorizationPolicy').allowInvitesFrom
    if ($v -in @('adminsAndGuestInviters', 'none')) { return New-TRCtl Pass ('Invitations: {0}.' -f $v) }
    New-TRCtl Fail ('Invitations: {0}.' -f $v)
}

Register-TRControl -Framework CIS -Id '5.1.8.1' -Level L1 -Profile E3 -Title 'Password hash sync is on for hybrid tenants' `
    -Needs 'Organization' -Checks 'IAM-22' `
    -Guidance 'Turn on password hash synchronisation in Entra Connect so leaked credential detection and cloud sign-in fallback work.' `
    -Test {
    $o = Get-TRRawValue 'Organization'
    if (-not (Test-TRTrue $o.onPremisesSyncEnabled)) { return New-TRCtl NotApplicable 'The tenant is cloud-only.' }
    $s = Get-TRRawValue 'OnPremSync'
    if (-not $s) { return New-TRCtl NotAssessed 'Directory synchronisation settings could not be read.' }
    if (Test-TRTrue (Get-TRPath $s 'features.passwordSyncEnabled')) { return New-TRCtl Pass 'Password hash synchronisation is on.' }
    New-TRCtl Fail 'Password hash synchronisation is off.'
}

Register-TRControl -Framework CIS -Id '5.2.2.1' -Level L1 -Profile E3 -Title 'MFA is required for administrator roles' `
    -Needs 'ConditionalAccessPolicies' -Checks 'IAM-03' -Map 'MS.AAD.3.6v1' `
    -Guidance 'Create a Conditional Access policy for the administrator roles, all resources, requiring MFA or an authentication strength.' `
    -Test {
    Test-TRBlCaRule -Requirement 'requires MFA for the administrator roles on all resources' -Filter { (Test-TRBlAllApps $_) -and (Test-TRBlMfa $_) -and ((Test-TRBlAllUsers $_) -or @(Get-TRStrings $_.conditions.users.includeRoles) -contains $script:TRGlobalAdminRole) }
}

Register-TRControl -Framework CIS -Id '5.2.2.2' -Level L1 -Profile E3 -Title 'MFA is required for all users' `
    -Needs 'ConditionalAccessPolicies' -Checks 'IAM-01' -Map 'MS.AAD.3.2v2', 'MS.AAD.3.1v1' `
    -Guidance 'Create a Conditional Access policy for all users and all resources requiring MFA, excluding only the emergency access accounts.' `
    -Test { Test-TRBlCaRule -Requirement 'requires MFA for all users on all resources' -Filter { (Test-TRBlAllUsers $_) -and (Test-TRBlAllApps $_) -and (Test-TRBlMfa $_) } }

Register-TRControl -Framework CIS -Id '5.2.2.3' -Level L1 -Profile E3 -Title 'Legacy authentication is blocked' `
    -Needs 'ConditionalAccessPolicies' -Checks 'IAM-02' -Map 'MS.AAD.1.1v1' `
    -Guidance 'Create a Conditional Access policy for all users and all resources that blocks Exchange ActiveSync and other legacy clients.' `
    -Test { Test-TRBlCaRule -Requirement 'blocks legacy authentication for all users' -Filter { (Test-TRBlAllUsers $_) -and (Test-TRBlAllApps $_) -and (Test-TRCaLegacy $_) -and (Test-TRBlBlock $_) } }

Register-TRControl -Framework CIS -Id '5.2.2.4' -Level L1 -Profile E3 -Title 'Admin sessions re-authenticate and do not persist' `
    -Needs 'ConditionalAccessPolicies' `
    -Guidance 'For administrator roles, set sign-in frequency to 4 hours or less and persistent browser session to never.' `
    -Test {
    Test-TRBlCaRule -Requirement 'limits administrator sessions to 4 hours with no persistent browser' -Filter {
        $f = $_.sessionControls.signInFrequency
        $hours = $null
        if ($f -and (Test-TRTrue $f.isEnabled) -and [string]$f.frequencyInterval -ne 'everyTime') { $hours = if ([string]$f.type -eq 'days') { [int]$f.value * 24 } else { [int]$f.value } }
        $pb = $_.sessionControls.persistentBrowser
        (Test-TRBlAllApps $_) -and ((Test-TRBlAllUsers $_) -or @(Get-TRStrings $_.conditions.users.includeRoles) -contains $script:TRGlobalAdminRole) -and
        (((Test-TRBlSignInEveryTime $_)) -or ($null -ne $hours -and $hours -le 4)) -and $pb -and (Test-TRTrue $pb.isEnabled) -and [string]$pb.mode -eq 'never'
    }
}

Register-TRControl -Framework CIS -Id '5.2.2.5' -Level L2 -Profile E3 -Title 'Administrators use phishing-resistant MFA' `
    -Needs 'ConditionalAccessPolicies' -Checks 'IAM-04' -Map 'MS.AAD.3.6v1' `
    -Guidance 'Require the phishing-resistant MFA authentication strength for the administrator roles on all resources.' `
    -Test { Test-TRBlCaRule -Requirement 'requires phishing-resistant MFA for the administrator roles' -Filter { (Test-TRBlAllApps $_) -and (Test-TRCaPhishResistant $_) -and ((Test-TRBlAllUsers $_) -or @(Get-TRStrings $_.conditions.users.includeRoles) -contains $script:TRGlobalAdminRole) } }

Register-TRControl -Framework CIS -Id '5.2.2.6' -Level L1 -Profile E5 -Title 'High user risk forces a secure password change' `
    -Licence 'P2' -Needs 'ConditionalAccessPolicies' -Checks 'IAM-09' -Map 'MS.AAD.2.1v1' `
    -Guidance 'Create a user risk Conditional Access policy for all users: high risk requires MFA and a password change, with sign-in frequency every time.' `
    -Test {
    Test-TRBlCaRule -Requirement 'requires MFA and a password change for high user risk' -Filter {
        (Test-TRBlAllUsers $_) -and (Test-TRBlAllApps $_) -and @(Get-TRStrings $_.conditions.userRiskLevels) -contains 'high' -and
        @(Get-TRBlGrant $_) -contains 'passwordChange' -and (Test-TRBlMfa $_) -and (Test-TRBlSignInEveryTime $_)
    }
}

Register-TRControl -Framework CIS -Id '5.2.2.7' -Level L1 -Profile E5 -Title 'Medium and high sign-in risk requires MFA' `
    -Licence 'P2' -Needs 'ConditionalAccessPolicies' -Checks 'IAM-09' -Map 'MS.AAD.2.3v1' `
    -Guidance 'Create a sign-in risk Conditional Access policy for all users: medium and high risk require MFA, with sign-in frequency every time.' `
    -Test {
    Test-TRBlCaRule -Requirement 'requires MFA for medium and high sign-in risk' -Filter {
        $lv = @(Get-TRStrings $_.conditions.signInRiskLevels)
        (Test-TRBlAllUsers $_) -and (Test-TRBlAllApps $_) -and $lv -contains 'high' -and $lv -contains 'medium' -and (Test-TRBlMfa $_) -and (Test-TRBlSignInEveryTime $_)
    }
}

Register-TRControl -Framework CIS -Id '5.2.2.8' -Level L2 -Profile E5 -Title 'Medium and high sign-in risk is blocked' `
    -Licence 'P2' -Needs 'ConditionalAccessPolicies' -Map 'MS.AAD.2.3v1' `
    -Guidance 'Create a Conditional Access policy for all users and all resources that blocks medium and high sign-in risk.' `
    -Test {
    Test-TRBlCaRule -Requirement 'blocks medium and high sign-in risk' -Filter {
        $lv = @(Get-TRStrings $_.conditions.signInRiskLevels)
        (Test-TRBlAllUsers $_) -and (Test-TRBlAllApps $_) -and -not @(Get-TRStrings $_.conditions.applications.excludeApplications).Count -and $lv -contains 'high' -and $lv -contains 'medium' -and (Test-TRBlBlock $_)
    }
}

Register-TRControl -Framework CIS -Id '5.2.2.9' -Level L1 -Profile E3 -Title 'A managed device is required for access' `
    -Needs 'ConditionalAccessPolicies' -Checks 'IAM-11' -Map 'MS.AAD.3.7v1' `
    -Guidance 'Require a compliant or hybrid joined device for all users and all resources with Conditional Access.' `
    -Test {
    Test-TRBlCaRule -Requirement 'requires a compliant device for all users on all resources' -Filter {
        $g = @(Get-TRBlGrant $_)
        (Test-TRBlAllUsers $_) -and (Test-TRBlAllApps $_) -and $g -contains 'compliantDevice' -and -not @($g | Where-Object { $_ -notin @('compliantDevice', 'domainJoinedDevice') }).Count -and ([string]$_.grantControls.operator -eq 'OR' -or $g.Count -eq 1)
    }
}

Register-TRControl -Framework CIS -Id '5.2.2.10' -Level L1 -Profile E3 -Title 'A managed device is required to register security info' `
    -Needs 'ConditionalAccessPolicies' -Map 'MS.AAD.3.8v1' `
    -Guidance 'Create a Conditional Access policy for the Register security information user action that requires a compliant or hybrid joined device.' `
    -Test {
    Test-TRBlCaRule -Requirement 'requires a compliant device to register security information' -Filter {
        $g = @(Get-TRBlGrant $_)
        (Test-TRBlAllUsers $_) -and @(Get-TRStrings $_.conditions.applications.includeUserActions) -contains 'urn:user:registersecurityinfo' -and $g -contains 'compliantDevice' -and -not @($g | Where-Object { $_ -notin @('compliantDevice', 'domainJoinedDevice') }).Count
    }
}

Register-TRControl -Framework CIS -Id '5.2.2.11' -Level L1 -Profile E3 -Title 'Intune enrolment requires sign-in every time' `
    -Needs 'ConditionalAccessPolicies' `
    -Guidance 'Create a Conditional Access policy for the Microsoft Intune Enrollment app requiring MFA with sign-in frequency every time.' `
    -Test {
    Test-TRBlCaRule -Requirement 'requires MFA every time for Intune enrolment' -Filter {
        (Test-TRBlAllUsers $_) -and @(Get-TRStrings $_.conditions.applications.includeApplications) -contains 'd4ebce55-015a-49b5-a083-c84d1797ae8c' -and (Test-TRBlMfa $_) -and (Test-TRBlSignInEveryTime $_)
    }
}

Register-TRControl -Framework CIS -Id '5.2.2.12' -Level L1 -Profile E3 -Title 'Device code sign-in is blocked' `
    -Needs 'ConditionalAccessPolicies' -Map 'MS.AAD.3.9v1' `
    -Guidance 'Create a Conditional Access policy for all users and all resources that blocks the device code flow, with documented exceptions only.' `
    -Test {
    Test-TRBlCaRule -Requirement 'blocks the device code flow for all users' -Filter {
        (Test-TRBlAllUsers $_) -and (Test-TRBlAllApps $_) -and ([string](Get-TRPath $_ 'conditions.authenticationFlows.transferMethods')) -match 'deviceCodeFlow' -and (Test-TRBlBlock $_)
    }
}

Register-TRControl -Framework CIS -Id '5.2.2.13' -Level L1 -Profile E3 -Title 'Users sign in again at least every seven days' `
    -Needs 'ConditionalAccessPolicies' `
    -Guidance 'Create a Conditional Access policy for all users and all resources with periodic re-authentication of 7 days or less.' `
    -Test {
    Test-TRBlCaRule -Requirement 'sets sign-in frequency of 7 days or less for all users' -Filter {
        $f = $_.sessionControls.signInFrequency
        $risk = @(Get-TRStrings $_.conditions.signInRiskLevels).Count + @(Get-TRStrings $_.conditions.userRiskLevels).Count
        $days = $null
        if ($f -and (Test-TRTrue $f.isEnabled) -and [string]$f.frequencyInterval -ne 'everyTime') { $days = if ([string]$f.type -eq 'hours') { [double]$f.value / 24 } else { [double]$f.value } }
        (-not $risk) -and (Test-TRBlAllUsers $_) -and (Test-TRBlAllApps $_) -and $null -ne $days -and $days -le 7
    }
}

Register-TRControl -Framework CIS -Id '5.2.2.14' -Level L2 -Profile E3 -Title 'A trusted IP named location is defined' `
    -Needs 'NamedLocations' `
    -Guidance 'Create an IP ranges named location for the organisation''s egress addresses and mark it trusted.' `
    -Test {
    $t = @(Get-TRItems 'NamedLocations' | Where-Object { [string]$_.'@odata.type' -match 'ipNamedLocation' -and (Test-TRTrue $_.isTrusted) -and @($_.ipRanges).Count -gt 0 })
    if ($t.Count) { return New-TRCtl Pass ('Trusted IP locations: {0}.' -f (Join-TRList ($t | ForEach-Object { $_.displayName }) 4)) }
    New-TRCtl Fail 'No trusted IP named location is defined.'
}

Register-TRControl -Framework CIS -Id '5.2.2.15' -Level L2 -Profile E3 -Title 'Sign-ins from untrusted locations are blocked' `
    -Needs 'ConditionalAccessPolicies', 'NamedLocations' `
    -Guidance 'Block access for all users from untrusted or out-of-scope countries and locations, excluding trusted locations.' `
    -Test {
    $locs = @(Get-TRItems 'NamedLocations')
    $untrusted = @($locs | Where-Object { -not (Test-TRTrue $_.isTrusted) } | ForEach-Object { [string]$_.id })
    $trusted = @($locs | Where-Object { Test-TRTrue $_.isTrusted } | ForEach-Object { [string]$_.id })
    Test-TRBlCaRule -Requirement 'blocks sign-ins from untrusted locations' -Filter {
        $inc = @(Get-TRStrings $_.conditions.locations.includeLocations)
        $exc = @(Get-TRStrings $_.conditions.locations.excludeLocations)
        (Test-TRBlAllUsers $_) -and (Test-TRBlAllApps $_) -and (Test-TRBlBlock $_) -and @($inc | Where-Object { $untrusted -contains $_ }).Count -gt 0 -and ($exc -contains 'AllTrusted' -or @($exc | Where-Object { $trusted -contains $_ }).Count -gt 0)
    }
}

Register-TRControl -Framework CIS -Id '5.2.2.16' -Level L2 -Profile E3 -Title 'Token protection is required for desktop apps' `
    -Needs 'ConditionalAccessBeta' `
    -Guidance 'Require token protection for sign-in sessions on Windows desktop clients for Exchange Online, SharePoint Online and Teams.' `
    -Test {
    $apps = @('00000002-0000-0ff1-ce00-000000000000', '00000003-0000-0ff1-ce00-000000000000', 'cc15fd57-2c6c-4117-a88c-83b1d56b4bbe')
    Test-TRBlCaRule -Requirement 'requires token protection for Exchange, SharePoint and Teams on Windows' -Filter {
        $inc = @(Get-TRStrings $_.conditions.applications.includeApplications)
        (Test-TRTrue (Get-TRPath $_ 'sessionControls.secureSignInSession.isEnabled')) -and @(Get-TRStrings $_.conditions.users.includeUsers) -notcontains 'None' -and
        ($inc -contains 'All' -or @($apps | Where-Object { $inc -notcontains $_ }).Count -eq 0) -and @(Get-TRStrings $_.conditions.platforms.includePlatforms) -contains 'windows'
    }
}

Register-TRControl -Framework CIS -Id '5.2.2.17' -Level L1 -Profile E3 -Title 'Authentication transfer is blocked' `
    -Needs 'ConditionalAccessPolicies' `
    -Guidance 'Create a Conditional Access policy for all users and all resources that blocks the authentication transfer flow.' `
    -Test {
    Test-TRBlCaRule -Requirement 'blocks authentication transfer for all users' -Filter {
        (Test-TRBlAllUsers $_) -and (Test-TRBlAllApps $_) -and ([string](Get-TRPath $_ 'conditions.authenticationFlows.transferMethods')) -match 'authenticationTransfer' -and (Test-TRBlBlock $_)
    }
}

Register-TRControl -Framework CIS -Id '5.2.3.1' -Level L1 -Profile E3 -Title 'Authenticator shows app name and location' `
    -Needs 'AuthMethodsPolicy' -Map 'MS.AAD.3.3v2' `
    -Guidance 'Enable Microsoft Authenticator for all users and turn on showing the application name and geographic location in push notifications.' `
    -Test {
    $m = Get-TRAuthMethod 'MicrosoftAuthenticator'
    if (-not $m) { return New-TRCtl NotAssessed 'The Microsoft Authenticator configuration was not returned.' }
    $gaps = @()
    if ([string]$m.state -ne 'enabled') { $gaps += 'Authenticator is disabled' }
    if (@(@($m.includeTargets) | Where-Object { [string]$_.id -eq 'all_users' }).Count -eq 0) { $gaps += 'not targeted at all users' }
    foreach ($k in 'displayAppInformationRequiredState', 'displayLocationInformationRequiredState') {
        $s = Get-TRV $m.featureSettings $k
        if (-not $s -or [string]$s.state -ne 'enabled' -or [string]$s.includeTarget.id -ne 'all_users') { $gaps += $(if ($k -like '*App*') { 'the app name is not shown to all users' } else { 'the location is not shown to all users' }) }
    }
    if ($gaps.Count) { $t = $gaps -join '; '; return New-TRCtl Fail ($t.Substring(0, 1).ToUpper() + $t.Substring(1) + '.') }
    New-TRCtl Pass 'Authenticator is on for all users and shows app name and location.'
}

Register-TRControl -Framework CIS -Id '5.2.3.2' -Level L1 -Profile E3 -Title 'A custom banned password list is enforced' `
    -Needs 'GroupSettings' `
    -Guidance 'In Password protection, set Enforce custom list to Yes and add organisation-specific words.' `
    -Test {
    $on = Get-TRPasswordRule 'EnableBannedPasswordCheck'
    $list = [string](Get-TRPasswordRule 'BannedPasswordList')
    if ([string]$on -eq 'True' -and $list.Trim()) { return New-TRCtl Pass ('A custom banned password list is enforced ({0}).' -f (Format-TRN @($list -split '\t|,|;' | Where-Object { $_ }).Count 'entry' 'entries')) }
    New-TRCtl Fail 'No custom banned password list is enforced.'
}

Register-TRControl -Framework CIS -Id '5.2.3.3' -Level L1 -Profile E3 -Title 'Password protection is enforced on-premises' `
    -Needs 'GroupSettings', 'Organization' `
    -Guidance 'Deploy the Entra password protection agents to domain controllers and set the mode to Enforced.' `
    -Test {
    if (-not (Test-TRTrue (Get-TRRawValue 'Organization').onPremisesSyncEnabled)) { return New-TRCtl NotApplicable 'The tenant is cloud-only.' }
    $on = [string](Get-TRPasswordRule 'EnableBannedPasswordCheckOnPremises')
    $mode = [string](Get-TRPasswordRule 'BannedPasswordCheckOnPremisesMode')
    if ($on -eq 'True' -and $mode -eq 'Enforce') { return New-TRCtl Pass 'On-premises password protection is enforced.' }
    if ($on -eq 'False') { return New-TRCtl Fail 'On-premises password protection is turned off.' }
    New-TRCtl Fail ('On-premises password protection is in {0} mode{1}, so weak passwords are logged but not blocked.' -f $(if ($mode) { $mode } else { 'Audit' }), $(if ($mode) { '' } else { ' (the default)' }))
}

Register-TRControl -Framework CIS -Id '5.2.3.4' -Level L1 -Profile E3 -Title 'All members are MFA capable' `
    -Needs 'RegistrationDetails' -Checks 'IAM-05' `
    -Guidance 'Make sure every member account has registered a strong method that the authentication methods policy allows.' `
    -Test {
    $users = Get-TRUserIndex
    $bad = @(Get-TRItems 'RegistrationDetails' | Where-Object { [string]$_.userType -eq 'member' -and -not (Test-TRTrue $_.isMfaCapable) } | Where-Object { $u = $users[[string]$_.id]; -not $u -or (Test-TRTrue $u.accountEnabled) })
    $all = @(Get-TRItems 'RegistrationDetails' | Where-Object { [string]$_.userType -eq 'member' })
    if ($bad.Count) { return New-TRCtl Fail ('{0} of {1} members are not MFA capable.' -f $bad.Count, $all.Count) (@($bad | ForEach-Object { New-TRAffected ([string]$_.userPrincipalName) 'Not MFA capable' })) }
    New-TRCtl Pass ((Select-TRText $all.Count 'The only member is MFA capable.' 'All {0} members are MFA capable.') -f $all.Count)
}

Register-TRControl -Framework CIS -Id '5.2.3.5' -Level L1 -Profile E3 -Title 'SMS and voice sign-in methods are off' `
    -Needs 'AuthMethodsPolicy' -Checks 'IAM-07' -Map 'MS.AAD.3.5v2' `
    -Guidance 'Disable SMS and voice call in the authentication methods policy once users have moved to Authenticator or passkeys.' `
    -Test {
    $on = @('Sms', 'Voice' | Where-Object { $m = Get-TRAuthMethod $_; $m -and [string]$m.state -eq 'enabled' })
    if ($on.Count) { return New-TRCtl Fail ('Still enabled: {0}.' -f ($on -join ', ')) }
    New-TRCtl Pass 'SMS and voice are disabled.'
}

Register-TRControl -Framework CIS -Id '5.2.3.6' -Level L1 -Profile E3 -Title 'System-preferred MFA is on' `
    -Needs 'AuthMethodsPolicyBeta' `
    -Guidance 'Turn on system-preferred multifactor authentication for all users.' `
    -Test {
    $s = Get-TRV (Get-TRRawValue 'AuthMethodsPolicyBeta') 'systemCredentialPreferences'
    if (-not $s) { return New-TRCtl NotAssessed 'System-preferred MFA settings were not returned.' }
    $all = @(@($s.includeTargets) | Where-Object { [string]$_.id -eq 'all_users' }).Count -gt 0
    if ([string]$s.state -eq 'enabled' -and $all) { return New-TRCtl Pass 'System-preferred MFA is on for all users.' }
    New-TRCtl Fail ('System-preferred MFA is {0}.' -f $(if ([string]$s.state -eq 'enabled') { 'not targeted at all users' } elseif ([string]$s.state -eq 'default') { 'Microsoft managed, not explicitly enabled' } else { [string]$s.state }))
}

Register-TRControl -Framework CIS -Id '5.2.3.7' -Level L2 -Profile E3 -Title 'Email one-time passcode is off' `
    -Needs 'AuthMethodsPolicy' -Map 'MS.AAD.3.5v2' `
    -Guidance 'Disable email OTP in the authentication methods policy.' `
    -Test {
    $m = Get-TRAuthMethod 'Email'
    if ($m -and [string]$m.state -eq 'enabled') { return New-TRCtl Fail 'Email one-time passcode is enabled.' }
    New-TRCtl Pass 'Email one-time passcode is disabled.'
}

Register-TRControl -Framework CIS -Id '5.2.3.8' -Level L1 -Profile E3 -Title 'Smart lockout locks after ten failures or fewer' `
    -Needs 'GroupSettings' `
    -Guidance 'Keep the smart lockout threshold at 10 or lower.' `
    -Test {
    $v = Get-TRPasswordRule 'LockoutThreshold'
    if (-not $v) { return New-TRCtl Pass 'The default lockout threshold of 10 applies.' }
    if ([int]$v -le 10) { return New-TRCtl Pass ('The lockout threshold is {0}.' -f $v) }
    New-TRCtl Fail ('The lockout threshold is {0}.' -f $v)
}

Register-TRControl -Framework CIS -Id '5.2.3.9' -Level L1 -Profile E3 -Title 'Smart lockout lasts at least 60 seconds' `
    -Needs 'GroupSettings' `
    -Guidance 'Keep the smart lockout duration at 60 seconds or more.' `
    -Test {
    $v = Get-TRPasswordRule 'LockoutDurationInSeconds'
    if (-not $v) { return New-TRCtl Pass 'The default lockout duration of 60 seconds applies.' }
    if ([int]$v -ge 60) { return New-TRCtl Pass ('The lockout duration is {0} seconds.' -f $v) }
    New-TRCtl Fail ('The lockout duration is {0} seconds.' -f $v)
}

Register-TRControl -Framework CIS -Id '5.2.3.10' -Level L1 -Profile E3 -Title 'Authenticator Lite in companion apps is off' `
    -Needs 'AuthMethodsPolicyBeta' `
    -Guidance 'In the Microsoft Authenticator method settings, disable Microsoft Authenticator on companion applications.' `
    -Test {
    $m = Get-TRAuthMethod 'MicrosoftAuthenticator' -Beta
    $s = [string](Get-TRPath $m 'featureSettings.companionAppAllowedState.state')
    if ($s -eq 'disabled') { return New-TRCtl Pass 'Authenticator Lite is disabled.' }
    New-TRCtl Fail ('Authenticator Lite is {0}.' -f $(if (-not $s -or $s -eq 'default') { 'Microsoft managed (enabled)' } else { $s }))
}

Register-TRControl -Framework CIS -Id '5.2.4.1' -Level L1 -Profile E3 -Title 'Self-service password reset is on for all users' -ManualOnly `
    -Guidance 'In Password reset, Properties, set Self service password reset enabled to All.'

Register-TRControl -Framework CIS -Id '5.2.4.2' -Level L2 -Profile E3 -Title 'Password reset needs two methods' -ManualOnly `
    -Guidance 'In Password reset, Authentication methods, set Number of methods required to reset to 2.'

Register-TRControl -Framework CIS -Id '5.2.4.3' -Level L1 -Profile E3 -Title 'Users must register for password reset at sign-in' -ManualOnly `
    -Guidance 'In Password reset, Registration, require users to register when signing in and set a non-zero re-confirmation period.'

Register-TRControl -Framework CIS -Id '5.2.4.4' -Level L1 -Profile E3 -Title 'Users are notified of password resets' -ManualOnly `
    -Guidance 'In Password reset, Notifications, set Notify users on password resets to Yes.'

Register-TRControl -Framework CIS -Id '5.2.4.5' -Level L1 -Profile E3 -Title 'Admins are notified when other admins reset passwords' -ManualOnly `
    -Guidance 'In Password reset, Notifications, set Notify all admins when other admins reset their password to Yes.'

Register-TRControl -Framework CIS -Id '5.3.1' -Level L2 -Profile E5 -Title 'Privileged roles use just-in-time activation' `
    -Licence 'P2' -Needs 'RoleAssignmentInstances', 'RoleDefinitions' -Checks 'PRV-05' -Map 'MS.AAD.7.4v1', 'MS.AAD.7.5v1' `
    -Guidance 'Make privileged role assignments eligible in PIM rather than permanently active. Only two break-glass Global Administrators may stay permanent, and service principals need an end date.' `
    -Test {
    $priv = @{}
    foreach ($d in (Get-TRItems 'RoleDefinitions')) { if ((Test-TRTrue $d.isPrivileged) -or $script:TRPrivilegedTemplates.ContainsKey([string]$d.templateId)) { $priv[[string]$d.id] = [string]$d.displayName; $priv[[string]$d.templateId] = [string]$d.displayName } }
    $inst = @(Get-TRItems 'RoleAssignmentInstances' | Where-Object { $priv.ContainsKey([string]$_.RoleDefinitionId) })
    $permGa = @($inst | Where-Object { [string]$_.AssignmentType -eq 'Assigned' -and $_.PrincipalType -in @('user', 'group') -and [string]$_.RoleDefinitionId -eq $script:TRGlobalAdminRole })
    $permOther = @($inst | Where-Object { [string]$_.AssignmentType -eq 'Assigned' -and $_.PrincipalType -in @('user', 'group') -and [string]$_.RoleDefinitionId -ne $script:TRGlobalAdminRole })
    $spNoEnd = @($inst | Where-Object { $_.PrincipalType -eq 'servicePrincipal' -and -not $_.EndDateTime })
    $aff = @()
    $aff += @($permOther | ForEach-Object { New-TRAffected $_.PrincipalUpn ($priv[[string]$_.RoleDefinitionId] + ', permanent') })
    $aff += @($spNoEnd | ForEach-Object { New-TRAffected $_.PrincipalName ($priv[[string]$_.RoleDefinitionId] + ', no end date') })
    if ($permGa.Count -gt 2) { $aff += @($permGa | ForEach-Object { New-TRAffected $_.PrincipalUpn 'Global Administrator, permanent' }) }
    if ($aff.Count) { return New-TRCtl Fail ('Permanent privileged assignments: {0}.' -f ((@($(if ($permGa.Count) { Format-TRN $permGa.Count 'Global Administrator' }), $(if ($permOther.Count) { Format-TRN $permOther.Count 'in another role' 'in other roles' }), $(if ($spNoEnd.Count) { (Format-TRN $spNoEnd.Count 'service principal') + ' with no end date' })) | Where-Object { $_ }) -join ', ')) $aff }
    New-TRCtl Pass ('Privileged roles are activated just in time ({0} kept for emergencies).' -f (Format-TRN $permGa.Count 'permanent Global Administrator'))
}

Register-TRControl -Framework CIS -Id '5.3.2' -Level L1 -Profile E5 -Title 'Guest access is reviewed monthly' `
    -Licence 'P2' -Needs 'AccessReviewDefinitions' `
    -Guidance 'Create a recurring monthly access review of guest users with reviewers, notifications, justification, auto-apply and deny by default.' `
    -Test {
    $ok = @(Get-TRItems 'AccessReviewDefinitions' | Where-Object {
            $scope = ($_.scope | ConvertTo-Json -Depth 8 -Compress)
            $st = $_.settings
            $scope -match "userType eq 'Guest'" -and [string]$st.recurrence.pattern.type -in @('absoluteMonthly', 'weekly') -and @($_.reviewers).Count -gt 0 -and (Test-TRTrue $st.mailNotificationsEnabled) -and (Test-TRTrue $st.reminderNotificationsEnabled) -and (Test-TRTrue $st.justificationRequiredOnApproval) -and (Test-TRTrue $st.autoApplyDecisionsEnabled) -and [string]$st.defaultDecision -eq 'Deny' -and [int]$st.instanceDurationInDays -le 14
        })
    if ($ok.Count) { return New-TRCtl Pass ('Guest reviews: {0}.' -f (Join-TRList ($ok | ForEach-Object { $_.displayName }) 3)) }
    New-TRCtl Fail 'No monthly guest access review meets the requirements.'
}

Register-TRControl -Framework CIS -Id '5.3.3' -Level L1 -Profile E5 -Title 'Privileged role access is reviewed' `
    -Licence 'P2' -Needs 'AccessReviewDefinitions' `
    -Guidance 'Create recurring access reviews of eligible and active assignments to the privileged roles with named reviewers.' `
    -Test {
    $ok = @(Get-TRItems 'AccessReviewDefinitions' | Where-Object {
            $scope = ($_.scope | ConvertTo-Json -Depth 8 -Compress)
            $scope -match 'roleDefinitions' -and [string]$_.settings.recurrence.pattern.type -in @('absoluteMonthly', 'weekly') -and @($_.reviewers).Count -gt 0
        })
    if ($ok.Count) { return New-TRCtl Pass ('Role reviews: {0}.' -f (Join-TRList ($ok | ForEach-Object { $_.displayName }) 3)) }
    New-TRCtl Fail 'No recurring access review covers the privileged roles.'
}

Register-TRControl -Framework CIS -Id '5.3.4' -Level L1 -Profile E5 -Title 'Global Administrator activation needs approval' `
    -Licence 'P2' -Needs 'RoleManagementPolicies' -Map 'MS.AAD.7.6v1' `
    -Guidance 'In PIM role settings for Global Administrator, require approval to activate and name at least one approver.' `
    -Test {
    $r = Get-TRPimRule $script:TRGlobalAdminRole 'Approval_EndUser_Assignment'
    if (-not $r) { return New-TRCtl NotAssessed 'The PIM settings for Global Administrator were not returned.' }
    $req = Test-TRTrue $r.setting.isApprovalRequired
    $appr = @(@($r.setting.approvalStages) | ForEach-Object { @($_.primaryApprovers) } | Where-Object { $_ }).Count
    if ($req -and $appr) { return New-TRCtl Pass ('Approval is required ({0}).' -f (Format-TRN $appr 'approver')) }
    New-TRCtl Fail $(if ($req) { 'Approval is required but no approvers are set.' } else { 'Activation does not need approval.' })
}

Register-TRControl -Framework CIS -Id '5.3.5' -Level L1 -Profile E5 -Title 'Privileged Role Administrator activation needs approval' `
    -Licence 'P2' -Needs 'RoleManagementPolicies' `
    -Guidance 'In PIM role settings for Privileged Role Administrator, require approval to activate and name at least one approver.' `
    -Test {
    $r = Get-TRPimRule $script:TRPrivRoleAdminRole 'Approval_EndUser_Assignment'
    if (-not $r) { return New-TRCtl NotAssessed 'The PIM settings for Privileged Role Administrator were not returned.' }
    $req = Test-TRTrue $r.setting.isApprovalRequired
    $appr = @(@($r.setting.approvalStages) | ForEach-Object { @($_.primaryApprovers) } | Where-Object { $_ }).Count
    if ($req -and $appr) { return New-TRCtl Pass ('Approval is required ({0}).' -f (Format-TRN $appr 'approver')) }
    New-TRCtl Fail $(if ($req) { 'Approval is required but no approvers are set.' } else { 'Activation does not need approval.' })
}

Register-TRControl -Framework CIS -Id '6.1.1' -Level L1 -Profile E3 -Title 'Mailbox auditing is on for the organisation' `
    -Needs 'ExoOrganizationConfig' -Checks 'EXO-02' -Map 'MS.EXO.13.1v1' `
    -Guidance 'Run Set-OrganizationConfig -AuditDisabled $false.' `
    -Test {
    if (Test-TRFalse (Get-TRRawValue 'ExoOrganizationConfig').AuditDisabled) { return New-TRCtl Pass 'Mailbox auditing is on by default.' }
    New-TRCtl Fail 'Mailbox auditing is disabled for the organisation.'
}

Register-TRControl -Framework CIS -Id '6.1.2' -Level L1 -Profile E3 -Title 'User mailboxes audit the full set of actions' `
    -Needs 'ExoMailboxes' -Map 'MS.EXO.13.1v1' `
    -Guidance 'Make sure every user mailbox has auditing enabled with the full admin, delegate and owner action sets.' `
    -Test {
    $mb = @(Get-TRItems 'ExoMailboxes' | Where-Object { [string]$_.RecipientTypeDetails -eq 'UserMailbox' })
    if (-not $mb.Count) { return New-TRCtl NotApplicable 'There are no user mailboxes.' }
    if (@($mb | Where-Object { Test-TRHasProperty $_ 'AuditGaps' }).Count -eq 0) { return New-TRCtl NotAssessed 'Audit actions were not collected by this version.' }
    $bad = @($mb | Where-Object { -not (Test-TRTrue $_.AuditEnabled) -or [string]$_.AuditGaps } | ForEach-Object { New-TRAffected ([string]$_.PrimarySmtpAddress) $(if (-not (Test-TRTrue $_.AuditEnabled)) { 'Auditing off' } else { 'Missing ' + [string]$_.AuditGaps }) })
    if ($bad.Count) { return New-TRCtl Fail ('{0} of {1} user mailboxes are missing audit actions.' -f $bad.Count, $mb.Count) $bad }
    New-TRCtl Pass ((Select-TRText $mb.Count 'The only user mailbox audits the full action sets.' 'All {0} user mailboxes audit the full action sets.') -f $mb.Count)
}

Register-TRControl -Framework CIS -Id '6.1.3' -Level L1 -Profile E3 -Title 'No accounts bypass mailbox auditing' `
    -Needs 'ExoAuditBypass' `
    -Guidance 'Remove audit bypass from every account with Set-MailboxAuditBypassAssociation -AuditBypassEnabled $false.' `
    -Test {
    $b = @(Get-TRItems 'ExoAuditBypass')
    if ($b.Count) { return New-TRCtl Fail ((Select-TRText $b.Count '1 account bypasses mailbox auditing.' '{0} accounts bypass mailbox auditing.') -f $b.Count) (@($b | ForEach-Object { New-TRAffected ([string]$_.Name) 'Audit bypass enabled' })) }
    New-TRCtl Pass 'No account bypasses mailbox auditing.'
}

Register-TRControl -Framework CIS -Id '6.2.1' -Level L1 -Profile E3 -Title 'Mail forwarding to external domains is blocked' `
    -Needs 'ExoOutboundSpamPolicies', 'ExoTransportRules' -Checks 'EXO-05', 'EXO-07' -Map 'MS.EXO.1.1v2' `
    -Guidance 'Set automatic forwarding to Off in every outbound anti-spam policy and remove mail flow rules that redirect mail to external addresses.' `
    -Test {
    $accepted = @(Get-TRItems 'ExoAcceptedDomains' | ForEach-Object { ([string]$_.DomainName).ToLower() })
    if (-not $accepted.Count) { $accepted = @(Get-TRItems 'Domains' | ForEach-Object { ([string]$_.id).ToLower() }) }
    $aff = @()
    foreach ($p in (Get-TRItems 'ExoOutboundSpamPolicies')) { if ([string]$p.AutoForwardingMode -ne 'Off') { $aff += New-TRAffected ([string]$p.Name) ('Automatic forwarding: ' + [string]$p.AutoForwardingMode) } }
    foreach ($r in (Get-TRItems 'ExoTransportRules')) {
        if ([string]$r.State -ne 'Enabled') { continue }
        foreach ($addr in @(Get-TRStrings $r.RedirectMessageTo)) {
            $dom = ($addr -split '@')[-1].ToLower().Trim()
            if ($dom -and $accepted -notcontains $dom) { $aff += New-TRAffected ([string]$r.Name) ('Redirects to ' + $addr) }
        }
    }
    if ($aff.Count) { return New-TRCtl Fail ((Select-TRText $aff.Count '1 setting allows mail to be forwarded outside the organisation.' '{0} settings allow mail to be forwarded outside the organisation.') -f $aff.Count) $aff }
    New-TRCtl Pass 'Automatic forwarding is off and no mail flow rule redirects externally.'
}

Register-TRControl -Framework CIS -Id '6.2.2' -Level L1 -Profile E3 -Title 'No mail flow rules whitelist sender domains' `
    -Needs 'ExoTransportRules' -Checks 'EXO-07' `
    -Guidance 'Remove mail flow rules that set the spam confidence level to -1 for sender domains.' `
    -Test {
    $bad = @(Get-TRItems 'ExoTransportRules' | Where-Object { [string]$_.SetSCL -eq '-1' -and @(Get-TRStrings $_.SenderDomainIs).Count -gt 0 } | ForEach-Object { New-TRAffected ([string]$_.Name) ('Bypasses filtering for ' + (Join-TRList $_.SenderDomainIs 4)) })
    if ($bad.Count) { return New-TRCtl Fail ((Select-TRText $bad.Count '1 mail flow rule bypasses spam filtering for whole domains.' '{0} mail flow rules bypass spam filtering for whole domains.') -f $bad.Count) $bad }
    New-TRCtl Pass 'No mail flow rule bypasses spam filtering for sender domains.'
}

Register-TRControl -Framework CIS -Id '6.2.3' -Level L1 -Profile E3 -Title 'External email is tagged in Outlook' `
    -Needs 'ExoExternalInOutlook' -Checks 'EXO-13' -Map 'MS.EXO.7.1v1' `
    -Guidance 'Run Set-ExternalInOutlook -Enabled $true and keep the allow list to approved addresses.' `
    -Test {
    $e = Get-TRRawValue 'ExoExternalInOutlook'
    if (Test-TRTrue $e.Enabled) { return New-TRCtl Pass ('External tagging is on.' + $(if (@(Get-TRStrings $e.AllowList).Count) { ' Allow list: ' + (Join-TRList $e.AllowList 5) + '.' } else { '' })) }
    New-TRCtl Fail 'External tagging is off.'
}

Register-TRControl -Framework CIS -Id '6.3.1' -Level L2 -Profile E3 -Title 'Users cannot install Outlook add-ins' `
    -Needs 'ExoRoleAssignmentPolicies' `
    -Guidance 'Remove My Custom Apps, My Marketplace Apps and My ReadWriteMailbox Apps from the default role assignment policy.' `
    -Test {
    $d = @(Get-TRItems 'ExoRoleAssignmentPolicies' | Where-Object { Test-TRTrue $_.IsDefault })[0]
    if (-not $d) { return New-TRCtl NotAssessed 'The default role assignment policy was not returned.' }
    $roles = @(Get-TRStrings $d.AssignedRoles)
    $hit = @('My Custom Apps', 'My Marketplace Apps', 'My ReadWriteMailbox Apps' | Where-Object { $roles -contains $_ })
    if ($hit.Count) { return New-TRCtl Fail ('The default policy ({0}) still grants: {1}.' -f $d.Name, ($hit -join ', ')) }
    New-TRCtl Pass ('The default policy ({0}) does not let users install add-ins.' -f $d.Name)
}

Register-TRControl -Framework CIS -Id '6.3.2' -Level L1 -Profile E3 -Title 'Personal accounts are blocked in Outlook' `
    -Needs 'ExoOwaPolicies' `
    -Guidance 'Set PersonalAccountsEnabled and PersonalAccountCalendarsEnabled to $false on the default OWA mailbox policy.' `
    -Test {
    $d = @(Get-TRItems 'ExoOwaPolicies' | Where-Object { Test-TRTrue $_.IsDefault })[0]
    if (-not $d) { return New-TRCtl NotAssessed 'The default OWA mailbox policy was not returned.' }
    $gaps = @('PersonalAccountsEnabled', 'PersonalAccountCalendarsEnabled' | Where-Object { -not (Test-TRFalse (Get-TRV $d $_)) })
    if ($gaps.Count) { return New-TRCtl Fail ('Not blocked: {0}.' -f ($gaps -join ', ')) }
    New-TRCtl Pass 'Personal accounts and calendars are blocked.'
}

Register-TRControl -Framework CIS -Id '6.5.1' -Level L1 -Profile E3 -Title 'Modern authentication is on for Exchange' `
    -Needs 'ExoOrganizationConfig' -Checks 'EXO-03' `
    -Guidance 'Run Set-OrganizationConfig -OAuth2ClientProfileEnabled $true.' `
    -Test {
    if (Test-TRTrue (Get-TRRawValue 'ExoOrganizationConfig').OAuth2ClientProfileEnabled) { return New-TRCtl Pass 'Modern authentication is on.' }
    New-TRCtl Fail 'Modern authentication is off.'
}

Register-TRControl -Framework CIS -Id '6.5.2' -Level L1 -Profile E3 -Title 'MailTips are on' `
    -Needs 'ExoOrganizationConfig' `
    -Guidance 'Turn on all MailTips, external recipient tips and group metrics, and set a large audience threshold (25 by default).' `
    -Test {
    $o = Get-TRRawValue 'ExoOrganizationConfig'
    $gaps = @('MailTipsAllTipsEnabled', 'MailTipsExternalRecipientsTipsEnabled', 'MailTipsGroupMetricsEnabled' | Where-Object { -not (Test-TRTrue (Get-TRV $o $_)) })
    if ([int]$o.MailTipsLargeAudienceThreshold -le 0) { $gaps += 'large audience threshold' }
    if ($gaps.Count) { return New-TRCtl Fail ('Not set: {0}.' -f ($gaps -join ', ')) }
    New-TRCtl Pass ('MailTips are on (large audience threshold {0}).' -f $o.MailTipsLargeAudienceThreshold)
}

Register-TRControl -Framework CIS -Id '6.5.3' -Level L2 -Profile E3 -Title 'Outlook on the web third-party storage is off' `
    -Needs 'ExoOwaPolicies' -Checks 'EXO-15' `
    -Guidance 'Set AdditionalStorageProvidersAvailable to $false on the default OWA mailbox policy.' `
    -Test {
    $d = @(Get-TRItems 'ExoOwaPolicies' | Where-Object { Test-TRTrue $_.IsDefault })[0]
    if (-not $d) { return New-TRCtl NotAssessed 'The default OWA mailbox policy was not returned.' }
    if (Test-TRFalse $d.AdditionalStorageProvidersAvailable) { return New-TRCtl Pass 'Additional storage providers are off.' }
    New-TRCtl Fail 'Users can open files from third-party storage in Outlook on the web.'
}

Register-TRControl -Framework CIS -Id '6.5.4' -Level L1 -Profile E3 -Title 'SMTP AUTH is off for the organisation' `
    -Needs 'ExoTransportConfig' -Checks 'EXO-04' -Map 'MS.EXO.5.1v1' `
    -Guidance 'Turn off SMTP AUTH for the organisation and enable it only on the mailboxes that need it.' `
    -Test {
    if (Test-TRTrue (Get-TRRawValue 'ExoTransportConfig').SmtpClientAuthenticationDisabled) { return New-TRCtl Pass 'SMTP AUTH is off.' }
    New-TRCtl Fail 'SMTP AUTH is on for the organisation.'
}

Register-TRControl -Framework CIS -Id '6.5.5' -Level L2 -Profile E3 -Title 'Direct Send is rejected' `
    -Needs 'ExoOrganizationConfig' `
    -Guidance 'Run Set-OrganizationConfig -RejectDirectSend $true once devices and services that send as the organisation use a connector or SMTP relay.' `
    -Test {
    if (Test-TRTrue (Get-TRRawValue 'ExoOrganizationConfig').RejectDirectSend) { return New-TRCtl Pass 'Direct Send is rejected.' }
    New-TRCtl Fail 'Direct Send is allowed.'
}

Register-TRControl -Framework CIS -Id '7.2.1' -Level L1 -Profile E3 -Title 'SharePoint requires modern authentication' `
    -Needs 'SharePointSettings' -Checks 'SPO-04' `
    -Guidance 'Turn off apps that do not use modern authentication in SharePoint access control.' `
    -Test {
    $v = Get-TRV (Get-TRSpo) 'LegacyAuthProtocolsEnabled'
    if ($null -eq $v) { $v = (Get-TRRawValue 'SharePointSettings').isLegacyAuthProtocolsEnabled }
    if (Test-TRFalse $v) { return New-TRCtl Pass 'Legacy authentication is blocked for SharePoint.' }
    New-TRCtl Fail 'Apps that do not use modern authentication can access SharePoint.'
}

Register-TRControl -Framework CIS -Id '7.2.2' -Level L1 -Profile E3 -Title 'SharePoint and OneDrive use Entra B2B' `
    -Needs 'SpoTenant' `
    -Guidance 'Run Set-SPOTenant -EnableAzureADB2BIntegration $true so guests are managed in Entra ID.' `
    -Test {
    if (Test-TRTrue (Get-TRV (Get-TRSpo) 'EnableAzureADB2BIntegration')) { return New-TRCtl Pass 'Entra B2B integration is on.' }
    New-TRCtl Fail 'Entra B2B integration is off.'
}

Register-TRControl -Framework CIS -Id '7.2.3' -Level L1 -Profile E3 -Title 'SharePoint external sharing is restricted' `
    -Needs 'SharePointSettings' -Checks 'SPO-01' -Map 'MS.SHAREPOINT.1.1v1' `
    -Guidance 'Set SharePoint external sharing to New and existing guests or more restrictive, not Anyone.' `
    -Test {
    $c = Get-TRSpoSharing
    if ($null -eq $c) { return New-TRCtl NotAssessed 'The sharing level was not returned.' }
    if ($c -in @(0, 1, 3)) { return New-TRCtl Pass ('SharePoint sharing: {0}.' -f $script:TRSharingCapNames[$c]) }
    New-TRCtl Fail ('SharePoint sharing: {0}.' -f $script:TRSharingCapNames[$c])
}

Register-TRControl -Framework CIS -Id '7.2.4' -Level L2 -Profile E3 -Title 'OneDrive content is not shared externally' `
    -Needs 'SpoTenant' -Map 'MS.SHAREPOINT.1.2v1' `
    -Guidance 'Set OneDrive external sharing to Only people in your organisation.' `
    -Test {
    $c = Get-TRSpoSharing -OneDrive
    if ($null -eq $c) { return New-TRCtl NotAssessed 'The OneDrive sharing level was not returned.' }
    if ($c -eq 0) { return New-TRCtl Pass 'OneDrive sharing is limited to the organisation.' }
    New-TRCtl Fail ('OneDrive sharing: {0}.' -f $script:TRSharingCapNames[$c])
}

Register-TRControl -Framework CIS -Id '7.2.5' -Level L2 -Profile E3 -Title 'Guests cannot reshare content' `
    -Needs 'SharePointSettings' -Checks 'SPO-02' `
    -Guidance 'Untick Allow guests to share items they don''t own.' `
    -Test {
    $v = Get-TRV (Get-TRSpo) 'PreventExternalUsersFromResharing'
    if ($null -eq $v) { $g = (Get-TRRawValue 'SharePointSettings').isResharingByExternalUsersEnabled; if ($null -ne $g) { $v = -not (Test-TRTrue $g) } }
    if (Test-TRTrue $v) { return New-TRCtl Pass 'Guests cannot reshare content.' }
    New-TRCtl Fail 'Guests can reshare content they do not own.'
}

Register-TRControl -Framework CIS -Id '7.2.6' -Level L2 -Profile E3 -Title 'External sharing is limited to allowed domains' `
    -Needs 'SharePointSettings' -Checks 'SPO-05' -Map 'MS.SHAREPOINT.1.3v1' `
    -Guidance 'Limit external sharing by domain with an allow list of trusted partner domains, or turn external sharing off.' `
    -Test {
    if ((Get-TRSpoSharing) -eq 0) { return New-TRCtl Pass 'External sharing is off.' }
    $mode = Get-TRSpoEnum 'SharingDomainRestrictionMode' @('None', 'AllowList', 'BlockList')
    $list = Get-TRV (Get-TRSpo) 'SharingAllowedDomainList'
    if ($null -eq $mode) {
        $g = Get-TRRawValue 'SharePointSettings'
        $mode = @{ 'none' = 0; 'allowList' = 1; 'blockList' = 2 }[[string]$g.sharingDomainRestrictionMode]
        $list = $g.sharingAllowedDomainList
    }
    if ($mode -eq 1 -and @(Get-TRStrings $list).Count) { return New-TRCtl Pass ('Sharing is limited to: {0}.' -f (Join-TRList (([string]($list -join ' ')) -split '\s+') 6)) }
    New-TRCtl Fail $(if ($mode -eq 2) { 'A domain block list is used instead of an allow list.' } else { 'External sharing is not limited by domain.' })
}

Register-TRControl -Framework CIS -Id '7.2.7' -Level L1 -Profile E3 -Title 'The default sharing link is restricted' `
    -Needs 'SpoTenant' -Map 'MS.SHAREPOINT.2.1v1' `
    -Guidance 'Set the default link type to Specific people or Only people in your organisation.' `
    -Test {
    $v = Get-TRSpoEnum 'DefaultSharingLinkType' @('None', 'Direct', 'Internal', 'AnonymousAccess')
    $names = @{ 0 = 'None'; 1 = 'Specific people'; 2 = 'People in the organisation'; 3 = 'Anyone' }
    if ($v -in @(1, 2)) { return New-TRCtl Pass ('Default link: {0}.' -f $names[$v]) }
    New-TRCtl Fail ('Default link: {0}.' -f $(if ($null -eq $v) { 'unknown' } else { $names[$v] }))
}

Register-TRControl -Framework CIS -Id '7.2.8' -Level L2 -Profile E3 -Title 'External sharing is limited to security groups' `
    -Needs 'SpoTenant' `
    -Guidance 'Allow only members of named security groups to share externally (More external sharing settings).' `
    -Test {
    if ((Get-TRSpoSharing) -eq 0) { return New-TRCtl Pass 'External sharing is off.' }
    $spo = Get-TRSpo
    $v = $null
    foreach ($n in 'WhoCanShareAuthenticatedGuestAllowList', 'WhoCanShareAllowListInTenant', 'GuestSharingGroupAllowListInTenant') { $x = Get-TRV $spo $n; if ($null -ne $x -and [string]$x -ne '') { $v = $x; break } }
    if ($null -eq $v) { return New-TRCtl Manual 'The security group allow list is not exposed in the tenant settings that were read. Check More external sharing settings in the SharePoint admin centre.' }
    New-TRCtl Pass ('External sharing is limited to: {0}.' -f (Join-TRList $v 4))
}

Register-TRControl -Framework CIS -Id '7.2.9' -Level L1 -Profile E3 -Title 'Guest access expires after 30 days' `
    -Needs 'SpoTenant' `
    -Guidance 'Tick Guest access to a site or OneDrive will expire automatically and set it to 30 days.' `
    -Test {
    $spo = Get-TRSpo
    $req = Test-TRTrue (Get-TRV $spo 'ExternalUserExpirationRequired')
    $days = [int](Get-TRV $spo 'ExternalUserExpireInDays')
    if ($req -and $days -gt 0 -and $days -le 30) { return New-TRCtl Pass ('Guest access expires after {0}.' -f (Format-TRN $days 'day')) }
    New-TRCtl Fail $(if ($req) { "Guest access expires after $days days." } else { 'Guest access does not expire.' })
}

Register-TRControl -Framework CIS -Id '7.2.10' -Level L1 -Profile E3 -Title 'Verification code users re-authenticate within 15 days' `
    -Needs 'SpoTenant' -Map 'MS.SHAREPOINT.3.3v2' `
    -Guidance 'Tick People who use a verification code must reauthenticate after this many days and set 15 or less.' `
    -Test {
    $spo = Get-TRSpo
    $req = Test-TRTrue (Get-TRV $spo 'EmailAttestationRequired')
    $days = [int](Get-TRV $spo 'EmailAttestationReAuthDays')
    if ($req -and $days -gt 0 -and $days -le 15) { return New-TRCtl Pass ('Re-authentication every {0}.' -f (Format-TRN $days 'day')) }
    New-TRCtl Fail $(if ($req) { "Re-authentication every $days days." } else { 'Re-authentication is not required.' })
}

Register-TRControl -Framework CIS -Id '7.2.11' -Level L1 -Profile E3 -Title 'The default link permission is view' `
    -Needs 'SpoTenant' -Map 'MS.SHAREPOINT.2.2v1' `
    -Guidance 'Set the default permission for sharing links to View.' `
    -Test {
    $v = Get-TRSpoEnum 'DefaultLinkPermission' @('None', 'View', 'Edit')
    if ($v -eq 1) { return New-TRCtl Pass 'Default link permission: View.' }
    New-TRCtl Fail ('Default link permission: {0}.' -f $(if ($v -eq 2) { 'Edit' } else { 'not set' }))
}

Register-TRControl -Framework CIS -Id '7.3.1' -Level L2 -Profile E5 -Title 'Infected files cannot be downloaded' `
    -Licence 'DefenderO365' -Needs 'SpoTenant' `
    -Guidance 'Run Set-SPOTenant -DisallowInfectedFileDownload $true.' `
    -Test {
    if (Test-TRTrue (Get-TRV (Get-TRSpo) 'DisallowInfectedFileDownload')) { return New-TRCtl Pass 'Infected files cannot be downloaded.' }
    New-TRCtl Fail 'Users can download files flagged as malicious.'
}

Register-TRControl -Framework CIS -Id '8.1.1' -Level L2 -Profile E3 -Title 'Only approved cloud storage is used in Teams' `
    -Needs 'TeamsClientConfig' `
    -Guidance 'Turn off third-party cloud storage providers in Teams files settings unless approved.' `
    -Test {
    $c = Get-TRTeamsPolicy 'TeamsClientConfig'
    if (-not $c) { return New-TRCtl NotAssessed 'The Teams client configuration was not returned.' }
    $on = @('AllowDropbox', 'AllowBox', 'AllowGoogleDrive', 'AllowShareFile', 'AllowEgnyte' | Where-Object { Test-TRTrue (Get-TRV $c $_) } | ForEach-Object { $_ -replace '^Allow', '' })
    if ($on.Count) { return New-TRCtl Fail ('Enabled providers: {0}. Accept only if approved.' -f ($on -join ', ')) }
    New-TRCtl Pass 'All third-party storage providers are off.'
}

Register-TRControl -Framework CIS -Id '8.1.2' -Level L1 -Profile E3 -Title 'Email into Teams channels is off' `
    -Needs 'TeamsClientConfig' -Map 'MS.TEAMS.4.1v1' `
    -Guidance 'Turn off Users can send emails to a channel email address.' `
    -Test {
    $c = Get-TRTeamsPolicy 'TeamsClientConfig'
    if (Test-TRFalse (Get-TRV $c 'AllowEmailIntoChannel')) { return New-TRCtl Pass 'Channel email addresses are off.' }
    New-TRCtl Fail 'Users can send email to channel addresses.'
}

Register-TRControl -Framework CIS -Id '8.2.1' -Level L2 -Profile E3 -Title 'Teams external access is limited to allowed domains' `
    -Needs 'TeamsFederation' -Checks 'COL-05' -Map 'MS.TEAMS.2.1v2' `
    -Guidance 'Set external access to allow only specific external domains, or turn it off.' `
    -Test {
    $f = Get-TRTeamsPolicy 'TeamsFederation'
    if (-not $f) { return New-TRCtl NotAssessed 'The Teams federation settings were not returned.' }
    if (Test-TRFalse (Get-TRV $f 'AllowFederatedUsers')) { return New-TRCtl Pass 'External access is off.' }
    $d = Get-TRTeamsAllowedDomains $f
    if ($d.Mode -eq 'List') { return New-TRCtl Pass ('External access is limited to: {0}.' -f $(if ($d.Domains.Count) { Join-TRList $d.Domains 6 } else { 'no domains' })) }
    New-TRCtl Fail 'External access is open to all external domains.'
}

Register-TRControl -Framework CIS -Id '8.2.2' -Level L1 -Profile E3 -Title 'Chat with unmanaged Teams users is off' `
    -Needs 'TeamsFederation' -Map 'MS.TEAMS.2.3v2' `
    -Guidance 'Turn off People in my organisation can communicate with unmanaged Teams accounts.' `
    -Test {
    $f = Get-TRTeamsPolicy 'TeamsFederation'
    if (Test-TRFalse (Get-TRV $f 'AllowTeamsConsumer')) { return New-TRCtl Pass 'Communication with unmanaged Teams accounts is off.' }
    New-TRCtl Fail 'Users can communicate with unmanaged Teams accounts.'
}

Register-TRControl -Framework CIS -Id '8.2.3' -Level L1 -Profile E3 -Title 'Unmanaged Teams users cannot start contact' `
    -Needs 'TeamsFederation' -Map 'MS.TEAMS.2.2v2' `
    -Guidance 'Untick External users with Teams accounts not managed by an organisation can contact users in my organisation.' `
    -Test {
    $f = Get-TRTeamsPolicy 'TeamsFederation'
    if ((Test-TRFalse (Get-TRV $f 'AllowTeamsConsumer')) -or (Test-TRFalse (Get-TRV $f 'AllowTeamsConsumerInbound'))) { return New-TRCtl Pass 'Unmanaged Teams users cannot start conversations.' }
    New-TRCtl Fail 'Unmanaged Teams users can start conversations with staff.'
}

Register-TRControl -Framework CIS -Id '8.2.4' -Level L1 -Profile E3 -Title 'Trial-only Teams tenants are blocked' `
    -Needs 'TeamsFederation' `
    -Guidance 'Set external access with trial-only tenants to Blocked.' `
    -Test {
    $v = [string](Get-TRV (Get-TRTeamsPolicy 'TeamsFederation') 'ExternalAccessWithTrialTenants')
    if ($v -eq 'Blocked') { return New-TRCtl Pass 'Trial-only tenants are blocked.' }
    New-TRCtl Fail ('Trial-only tenants: {0}.' -f $(if ($v) { $v } else { 'allowed' }))
}

Register-TRControl -Framework CIS -Id '8.4.1' -Level L1 -Profile E3 -Title 'Teams app installation is controlled' `
    -Map 'MS.TEAMS.5.1v2', 'MS.TEAMS.5.2v2', 'MS.TEAMS.5.3v2' `
    -Guidance 'In Teams apps, Manage apps, Org-wide app settings and permission policies, allow only approved Microsoft, third-party and custom apps.' `
    -Test {
    $p = Get-TRTeamsPolicy 'TeamsAppPolicies'
    if (-not $p) { return New-TRCtl Manual 'Review Teams org-wide app settings and permission policies by hand.' }
    New-TRCtl Manual ('Global app permission policy: Microsoft apps {0}, third-party apps {1}, custom apps {2}. Confirm only approved apps are allowed.' -f [string](Get-TRV $p 'DefaultCatalogAppsType'), [string](Get-TRV $p 'GlobalCatalogAppsType'), [string](Get-TRV $p 'PrivateCatalogAppsType'))
}

Register-TRControl -Framework CIS -Id '8.5.1' -Level L2 -Profile E3 -Title 'Anonymous users cannot join meetings' `
    -Needs 'TeamsMeetingPolicies' -Checks 'COL-05' `
    -Guidance 'Turn off Anonymous users can join a meeting in the Global meeting policy.' `
    -Test { Test-TRTeamsAll -Key 'TeamsMeetingPolicies' -Setting 'AllowAnonymousUsersToJoinMeeting' -GlobalOnly -Ok { param($v) Test-TRFalse $v } }

Register-TRControl -Framework CIS -Id '8.5.2' -Level L1 -Profile E3 -Title 'Anonymous users cannot start meetings' `
    -Needs 'TeamsMeetingPolicies' -Map 'MS.TEAMS.1.2v2' `
    -Guidance 'Turn off Anonymous users and dial-in callers can start a meeting.' `
    -Test { Test-TRTeamsAll -Key 'TeamsMeetingPolicies' -Setting 'AllowAnonymousUsersToStartMeeting' -GlobalOnly -Ok { param($v) Test-TRFalse $v } }

Register-TRControl -Framework CIS -Id '8.5.3' -Level L1 -Profile E3 -Title 'Only invited people bypass the lobby' `
    -Needs 'TeamsMeetingPolicies' -Map 'MS.TEAMS.1.3v1' `
    -Guidance 'Set Who can bypass the lobby to People who were invited, People in my org, or Only organisers and co-organisers.' `
    -Test { Test-TRTeamsAll -Key 'TeamsMeetingPolicies' -Setting 'AutoAdmittedUsers' -GlobalOnly -Ok { param($v) [string]$v -in @('InvitedUsers', 'EveryoneInCompanyExcludingGuests', 'OrganizerOnly') } }

Register-TRControl -Framework CIS -Id '8.5.4' -Level L1 -Profile E3 -Title 'Dial-in users cannot bypass the lobby' `
    -Needs 'TeamsMeetingPolicies' -Map 'MS.TEAMS.1.5v1', 'MS.TEAMS.1.3v1' `
    -Guidance 'Turn off People dialling in can bypass the lobby.' `
    -Test { Test-TRTeamsAll -Key 'TeamsMeetingPolicies' -Setting 'AllowPSTNUsersToBypassLobby' -GlobalOnly -Ok { param($v) Test-TRFalse $v } }

Register-TRControl -Framework CIS -Id '8.5.5' -Level L2 -Profile E3 -Title 'Anonymous users cannot use meeting chat' `
    -Needs 'TeamsMeetingPolicies' `
    -Guidance 'Set meeting chat to On for everyone but anonymous users, or more restrictive.' `
    -Test { Test-TRTeamsAll -Key 'TeamsMeetingPolicies' -Setting 'MeetingChatEnabledType' -GlobalOnly -Ok { param($v) [string]$v -in @('EnabledExceptAnonymous', 'EnabledInMeetingOnlyForAllExceptAnonymous', 'Disabled') } }

Register-TRControl -Framework CIS -Id '8.5.6' -Level L2 -Profile E3 -Title 'Only organisers and co-organisers present' `
    -Needs 'TeamsMeetingPolicies' `
    -Guidance 'Set Who can present to Only organisers and co-organisers.' `
    -Test { Test-TRTeamsAll -Key 'TeamsMeetingPolicies' -Setting 'DesignatedPresenterRoleMode' -GlobalOnly -Ok { param($v) [string]$v -eq 'OrganizerOnlyUserOverride' } }

Register-TRControl -Framework CIS -Id '8.5.7' -Level L1 -Profile E3 -Title 'External participants cannot take control' `
    -Needs 'TeamsMeetingPolicies' -Map 'MS.TEAMS.1.1v1' `
    -Guidance 'Turn off External participants can give or request control.' `
    -Test { Test-TRTeamsAll -Key 'TeamsMeetingPolicies' -Setting 'AllowExternalParticipantGiveRequestControl' -GlobalOnly -Ok { param($v) Test-TRFalse $v } }

Register-TRControl -Framework CIS -Id '8.5.8' -Level L2 -Profile E3 -Title 'Meeting chat with untrusted organisations is off' `
    -Needs 'TeamsMeetingPolicies' `
    -Guidance 'Turn off External meeting chat with untrusted organisations.' `
    -Test { Test-TRTeamsAll -Key 'TeamsMeetingPolicies' -Setting 'AllowExternalNonTrustedMeetingChat' -GlobalOnly -Ok { param($v) Test-TRFalse $v } }

Register-TRControl -Framework CIS -Id '8.5.9' -Level L2 -Profile E3 -Title 'Meeting recording is off by default' `
    -Needs 'TeamsMeetingPolicies' -Map 'MS.TEAMS.1.6v1' `
    -Guidance 'Turn off meeting recording in the Global policy and allow it through a separate policy for users who need it.' `
    -Test { Test-TRTeamsAll -Key 'TeamsMeetingPolicies' -Setting 'AllowCloudRecording' -GlobalOnly -Ok { param($v) Test-TRFalse $v } }

Register-TRControl -Framework CIS -Id '8.6.1' -Level L1 -Profile E5 -Title 'Users can report security concerns in Teams' `
    -Licence 'DefenderO365' -Needs 'TeamsMessagingPolicies', 'ExoReportSubmissionPolicy' -Checks 'EXO-18' `
    -Guidance 'Turn on security reporting in the Teams messaging policy and send user reported messages to a monitored mailbox in Defender.' `
    -Test {
    $m = Get-TRTeamsPolicy 'TeamsMessagingPolicies'
    $r = Get-TRRawValue 'ExoReportSubmissionPolicy'
    $gaps = @()
    if (-not (Test-TRTrue (Get-TRV $m 'AllowSecurityEndUserReporting'))) { $gaps += 'Teams security reporting is off' }
    foreach ($k in 'ReportJunkToCustomizedAddress', 'ReportNotJunkToCustomizedAddress', 'ReportPhishToCustomizedAddress') { if (-not (Test-TRTrue (Get-TRV $r $k))) { $gaps += ($k -replace 'ToCustomizedAddress', '') + ' not sent to a mailbox' } }
    if (-not @(Get-TRStrings $r.ReportPhishAddresses).Count) { $gaps += 'no reporting mailbox' }
    if ($gaps.Count) { return New-TRCtl Fail (($gaps -join '; ') + '.') }
    New-TRCtl Pass ('Reports go to {0}.' -f (Join-TRList $r.ReportPhishAddresses 3))
}

Register-TRControl -Framework CIS -Id '9.1.1' -Level L1 -Profile E3 -Title 'Guest access to Fabric is restricted' `
    -Needs 'PowerBISettings' -Map 'MS.POWERBI.2.1v1' `
    -Guidance 'Turn off Guest users can access Microsoft Fabric, or limit it to specific security groups.' `
    -Test { Test-TRFabricRestricted 'AllowGuestUserToAccessSharedContent' }

Register-TRControl -Framework CIS -Id '9.1.2' -Level L1 -Profile E3 -Title 'External user invitations are restricted' `
    -Needs 'PowerBISettings' -Map 'MS.POWERBI.3.1v1' `
    -Guidance 'Turn off Users can invite guest users to collaborate through item sharing and permissions, or limit it to security groups.' `
    -Test { Test-TRFabricRestricted 'ExternalSharingV2' }

Register-TRControl -Framework CIS -Id '9.1.3' -Level L1 -Profile E3 -Title 'Guest browsing of Fabric content is restricted' `
    -Needs 'PowerBISettings' `
    -Guidance 'Turn off Guest users can browse and access Fabric content, or limit it to security groups.' `
    -Test { Test-TRFabricRestricted 'ElevatedGuestsTenant' }

Register-TRControl -Framework CIS -Id '9.1.4' -Level L1 -Profile E3 -Title 'Publish to web is restricted' `
    -Needs 'PowerBISettings' -Map 'MS.POWERBI.1.1v1' `
    -Guidance 'Turn off Publish to web, or allow only existing embed codes for specific security groups.' `
    -Test {
    $s = Get-TRFabric 'PublishToWeb'
    if (-not $s) { return New-TRCtl NotAssessed 'The Publish to web setting was not returned.' }
    if (Test-TRFalse (Get-TRV $s 'Enabled')) { return New-TRCtl Pass 'Publish to web is turned off.' }
    $create = @(@(Get-TRV $s 'Properties') | Where-Object { [string]$_.Name -eq 'createP2w' })[0]
    $groups = @(Get-TRStrings (Get-TRV $s 'EnabledSecurityGroups'))
    if ($create -and [string]$create.Value -eq 'false' -and $groups.Count) { return New-TRCtl Pass ('Publish to web is limited to existing codes for: {0}.' -f (Join-TRList $groups 4)) }
    New-TRCtl Fail 'Users can create new Publish to web embed codes.'
}

Register-TRControl -Framework CIS -Id '9.1.5' -Level L2 -Profile E3 -Title 'R and Python visuals are off' `
    -Needs 'PowerBISettings' -Map 'MS.POWERBI.6.1v1' `
    -Guidance 'Turn off Interact with and share R and Python visuals.' `
    -Test { Test-TRFabricRestricted 'RScriptVisual' -MustBeOff }

Register-TRControl -Framework CIS -Id '9.1.6' -Level L1 -Profile E3 -Title 'Users can apply sensitivity labels in Fabric' `
    -Needs 'PowerBISettings' -Map 'MS.POWERBI.7.1v1' `
    -Guidance 'Turn on Allow users to apply sensitivity labels for content.' `
    -Test { Test-TRFabricOn 'EimInformationProtectionEdit' }

Register-TRControl -Framework CIS -Id '9.1.7' -Level L1 -Profile E3 -Title 'Organisation-wide shareable links are restricted' `
    -Needs 'PowerBISettings' `
    -Guidance 'Turn off Allow shareable links to grant access to everyone in your organisation, or limit it to security groups.' `
    -Test { Test-TRFabricRestricted 'ShareLinkToEntireOrg' }

Register-TRControl -Framework CIS -Id '9.1.8' -Level L1 -Profile E3 -Title 'External data sharing is restricted' `
    -Needs 'PowerBISettings' `
    -Guidance 'Turn off External data sharing, or limit it to security groups.' `
    -Test { Test-TRFabricRestricted 'EnableDatasetInPlaceSharing' }

Register-TRControl -Framework CIS -Id '9.1.9' -Level L1 -Profile E3 -Title 'ResourceKey authentication is blocked' `
    -Needs 'PowerBISettings' -Map 'MS.POWERBI.5.1v1' `
    -Guidance 'Turn on Block ResourceKey Authentication.' `
    -Test { Test-TRFabricOn 'BlockResourceKeyAuthentication' }

Register-TRControl -Framework CIS -Id '9.1.10' -Level L1 -Profile E3 -Title 'Service principal access to Fabric APIs is restricted' `
    -Needs 'PowerBISettings' -Map 'MS.POWERBI.4.1v1' `
    -Guidance 'Limit Service principals can call Fabric public APIs to specific security groups, or turn it off.' `
    -Test { Test-TRFabricRestricted 'ServicePrincipalAccessPermissionAPIs' }

Register-TRControl -Framework CIS -Id '9.1.11' -Level L1 -Profile E3 -Title 'Service principal profiles are restricted' `
    -Needs 'PowerBISettings' -Map 'MS.POWERBI.4.2v1' `
    -Guidance 'Limit Allow service principals to create and use profiles to security groups, or turn it off.' `
    -Test { Test-TRFabricRestricted 'AllowServicePrincipalsCreateAndUseProfiles' }

Register-TRControl -Framework CIS -Id '9.1.12' -Level L1 -Profile E3 -Title 'Service principals cannot create workspaces freely' `
    -Needs 'PowerBISettings' `
    -Guidance 'Limit Service principals can create workspaces, connections and deployment pipelines to security groups, or turn it off.' `
    -Test { Test-TRFabricRestricted 'ServicePrincipalAccessGlobalAPIs' }
