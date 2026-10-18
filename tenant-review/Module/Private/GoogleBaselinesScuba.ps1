function Test-TRGsCtl {
    param([string]$Type, [scriptblock]$Ok, [string]$Good, [string]$Bad, [scriptblock]$Detail)
    ConvertTo-TRGwsCtl (Test-TRGwsPolicy -Type $Type -Ok $Ok -Good $Good -Bad $Bad -Detail $Detail)
}

function Join-TRGsEvals {
    param($Evals)
    $e = @($Evals | Where-Object { $_ })
    $bad = @($e | Where-Object { $_.Status -eq 'Fail' })
    if ($bad.Count) { return New-TRCtl Fail (($bad | ForEach-Object { $_.Text }) -join ' ') (@($bad | ForEach-Object { $_.Affected })) }
    $unk = @($e | Where-Object { $_.Status -eq 'Unknown' })
    if ($unk.Count) { return New-TRCtl NotAssessed (($unk | ForEach-Object { $_.Text }) -join ' ') }
    New-TRCtl Pass (($e | ForEach-Object { $_.Text }) -join ' ')
}

function Test-TRGsService {
    param([string]$Service, [string]$Want, [string]$Name)
    $w = $Want
    $ok = { param($s) [string]$s['serviceState'] -eq $w }.GetNewClosure()
    $on = if ($Want -eq 'DISABLED') { $Name + ' is off' } else { $Name + ' is on' }
    $lc = if ($Name -match '^Google ') { $Name } else { $Name.Substring(0, 1).ToLower() + $Name.Substring(1) }
    $off = if ($Want -eq 'DISABLED') { $lc + ' is on' } else { $lc + ' is off' }
    Test-TRGsCtl -Type ($Service + '.service_status') -Ok $ok -Good $on -Bad $off
}

function Get-TRGs2svEvals {
    param([switch]$Factor, [string]$FactorMode)
    $evals = @(
        (Test-TRGwsPolicy -Type 'security.two_step_verification_enrollment' -Ok { param($s) Test-TRGwsTrue $s['allowEnrollment'] } -Good 'users can enrol in 2SV' -Bad 'users cannot enrol in 2SV'),
        (Test-TRGwsPolicy -Type 'security.two_step_verification_enforcement' -Ok { param($s) Test-TRGwsEnforcedFrom $s['enforcedFrom'] } -Good '2SV is enforced' -Bad '2SV is not enforced')
    )
    if ($FactorMode -eq 'PasskeyOnly') { $evals += (Test-TRGwsPolicy -Type 'security.two_step_verification_enforcement_factor' -Ok { param($s) [string]$s['allowedSignInFactorSet'] -eq 'PASSKEY_ONLY' } -Good 'only passkeys and security keys are allowed' -Bad 'methods other than passkeys and security keys are allowed' -Detail { param($s) 'Allowed methods: ' + (Get-TRGwsFactorText ([string]$s['allowedSignInFactorSet'])) }) }
    if ($FactorMode -eq 'NoTelephony') { $evals += (Test-TRGwsPolicy -Type 'security.two_step_verification_enforcement_factor' -Ok { param($s) [string]$s['allowedSignInFactorSet'] -ne 'ALL' } -Good 'text and voice codes are not allowed' -Bad 'text and voice codes are allowed' -Detail { param($s) 'Allowed methods: ' + (Get-TRGwsFactorText ([string]$s['allowedSignInFactorSet'])) }) }
    $evals
}

function Get-TRGsDmarc {
    param([string]$Domain)
    $rows = @(Get-TRItems 'GwsDnsRecords')
    $r = @($rows | Where-Object { $_.Domain -eq $Domain })[0]
    $d = if ($r) { @(Get-TRStrings $r.Dmarc) } else { @() }
    if ($d.Count) { return ($d[0] -replace '"', '') }
    $parts = $Domain.Split('.')
    if ($parts.Count -gt 2) {
        $parent = ($parts[($parts.Count - 2)..($parts.Count - 1)]) -join '.'
        $p = @($rows | Where-Object { $_.Domain -eq $parent })[0]
        if ($p -and @(Get-TRStrings $p.Dmarc).Count) { return ((@(Get-TRStrings $p.Dmarc))[0] -replace '"', '') }
    }
    $null
}

function Test-TRGsDmarc {
    param([scriptblock]$Ok, [string]$What)
    $rows = @(Get-TRItems 'GwsDnsRecords')
    if (-not $rows.Count) { return New-TRCtl NotAssessed 'No domains were checked.' }
    $bad = foreach ($r in $rows) {
        $rec = Get-TRGsDmarc $r.Domain
        if (-not $rec) { New-TRAffected $r.Domain 'No DMARC record'; continue }
        $t = ConvertFrom-TRDmarc $rec
        if (-not (& $Ok $t)) { New-TRAffected $r.Domain $rec }
    }
    $bad = @($bad)
    if ($bad.Count) { return New-TRCtl Fail ('{0} of {1} domains {3} not meet this: {2}.' -f $bad.Count, $rows.Count, (Join-TRList ($bad | ForEach-Object { $_.Item }) 5), (Select-TRText $bad.Count 'does' 'do')) $bad }
    New-TRCtl Pass ('{0} on all {1}.' -f $What, (Format-TRN $rows.Count 'domain'))
}

function Get-TRGwsSsoAssignments {
    @(Get-TRItems 'GwsSsoAssignments' | Where-Object { [string]$_.ssoMode -and [string]$_.ssoMode -notin @('SSO_OFF', 'SSO_MODE_UNSPECIFIED') })
}

function Get-TRGwsSsoUsers {
    $assign = @(Get-TRGwsSsoAssignments)
    if (-not $assign.Count) { return @() }
    $ous = Get-TRGwsOuIndex
    $paths = @($assign | Where-Object { $_.targetOrgUnit } | ForEach-Object { $id = ([string]$_.targetOrgUnit) -replace '^orgUnits/', ''; if ($ous[$id]) { $ous[$id] } else { '/' } })
    $groupIds = @($assign | Where-Object { $_.targetGroup } | ForEach-Object { ([string]$_.targetGroup) -replace '^groups/', '' })
    $groupEmails = Get-TRGwsGroupEmails
    $members = @{}
    foreach ($m in (Get-TRItems 'GwsGroupMembers')) { foreach ($g in $groupIds) { if ($groupEmails[$g] -and ([string]$m.Group) -ieq $groupEmails[$g]) { $members[([string]$m.Member).ToLower()] = $true } } }
    @(Get-TRGwsEnabledUsers | Where-Object {
            $p = [string]$_.orgUnitPath
            $byOu = @($paths | Where-Object { $_ -eq '/' -or $p -eq $_ -or $p.StartsWith($_ + '/') }).Count -gt 0
            $byOu -or $members.ContainsKey(([string]$_.primaryEmail).ToLower())
        })
}

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.ASSUREDCONTROLS.1.1v1' -Level Should -Title 'Access Approvals are on' `
    -Licence 'AssuredControls' -Needs 'GwsPolicies' `
    -Guidance 'In Security, Access and data control, Access Approvals, require your approval before Google staff can access data.' `
    -Test { Test-TRGsCtl -Type 'access_approval.axa_user_scoping' -Ok { param($s) Test-TRGwsTrue $s['requiresCustomerApproval'] } -Good 'Access Approvals are required' -Bad 'Access Approvals are not required' }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.ASSUREDCONTROLS.1.2v1' -Level Should -Title 'Support access limited to US-based Google staff' `
    -Guidance 'Applies to US federal agencies. UK organisations may instead limit access to EU-based staff if Assured Controls is licensed.' `
    -Test {
    $v = Get-TRGwsRootValue 'access_management.user_scoping' 'accessManagementRegime'
    New-TRCtl NotApplicable ('Applies to US federal agencies only. Current setting: {0}.' -f $(if ($v) { $v } else { 'not set' }))
}

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.ASSUREDCONTROLS.2.1v1' -Level Should -Title 'Processing outside the data region is off' `
    -Licence 'DataRegionsEnterprise' -Needs 'GwsAdminEvents' `
    -Guidance 'In Data regions, turn off processing of data outside the selected region for Calendar, Docs, Gmail, Chat, Meet and Gemini.' `
    -Test {
    $evals = foreach ($p in 'Calendar', 'Docs', 'Gmail', 'Chat', 'Meet', 'Gemini') {
        Test-TRGwsLogSetting -Setting ($p + 'NonRegionalizedFunctionalityStateSettingsProto state') -Ok { param($v) $v -ne 'ENABLED' } -Good ($p + ' processing stays in region') -Bad ($p + ' processing outside the region is on') -DefaultOk $false -DefaultText 'processing outside the region may be on'
    }
    Join-TRGsEvals $evals
}

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.CALENDAR.1.1v1' -Level Shall -Title 'Primary calendars share only free/busy externally' `
    -Needs 'GwsPolicies' -Checks 'GCOL-01' -Map '3.1.1.1.1' `
    -Guidance 'In Calendar, Sharing settings, set External sharing options for primary calendars to Only free/busy information.' `
    -Test { Test-TRGsCtl -Type 'calendar.primary_calendar_max_allowed_external_sharing' -Ok { param($s) [string]$s['maxAllowedExternalSharing'] -eq 'EXTERNAL_FREE_BUSY_ONLY' } -Good 'primary calendars share only free/busy externally' -Bad 'primary calendars can share event details externally' -Detail { param($s) [string]$s['maxAllowedExternalSharing'] } }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.CALENDAR.1.2v1' -Level Shall -Title 'Secondary calendars share only free/busy externally' `
    -Needs 'GwsPolicies' -Map '3.1.1.2.1' `
    -Guidance 'In Calendar, Sharing settings, set External sharing options for secondary calendars to Only free/busy information.' `
    -Test { Test-TRGsCtl -Type 'calendar.secondary_calendar_max_allowed_external_sharing' -Ok { param($s) [string]$s['maxAllowedExternalSharing'] -eq 'EXTERNAL_FREE_BUSY_ONLY' } -Good 'secondary calendars share only free/busy externally' -Bad 'secondary calendars can share event details externally' -Detail { param($s) [string]$s['maxAllowedExternalSharing'] } }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.CALENDAR.2.1v1' -Level Shall -Title 'Users are warned when inviting external guests' `
    -Needs 'GwsPolicies' -Map '3.1.1.1.3' `
    -Guidance 'In Calendar, Sharing settings, turn on External invitations warning.' `
    -Test { Test-TRGsCtl -Type 'calendar.external_invitations' -Ok { param($s) Test-TRGwsTrue $s['warnOnInvite'] } -Good 'external invitation warnings are on' -Bad 'external invitation warnings are off' }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.CALENDAR.3.1v1' -Level Should -Title 'Calendar interop with Exchange is off' `
    -Needs 'GwsPolicies' `
    -Guidance 'Turn off Calendar Interop unless the organisation shares calendars with Microsoft Exchange.' `
    -Test { Test-TRGsCtl -Type 'calendar.interoperability' -Ok { param($s) -not (Test-TRGwsTrue $s['enableInteroperability']) } -Good 'Calendar Interop is off' -Bad 'Calendar Interop is on' }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.CALENDAR.3.2v1' -Level Shall -Title 'Calendar interop uses Microsoft Graph, not basic auth' -ManualOnly `
    -Guidance 'If Calendar Interop is needed, connect with Microsoft 365 (Graph API) rather than an Exchange account with basic authentication.'

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.CALENDAR.4.1v1' -Level Should -Title 'Paid appointment schedules are off' `
    -Licence 'AppointmentPayments' -Needs 'GwsPolicies' `
    -Guidance 'In Calendar, Appointment schedules, turn off payments.' `
    -Test { Test-TRGsCtl -Type 'calendar.appointment_schedules' -Ok { param($s) -not (Test-TRGwsTrue $s['enablePayments']) } -Good 'appointment payments are off' -Bad 'appointment payments are on' }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.CHAT.1.1v1' -Level Shall -Title 'Chat history is on' `
    -Needs 'GwsPolicies' `
    -Guidance 'In Google Chat, History for chats, set History is ON by default.' `
    -Test { Test-TRGsCtl -Type 'chat.chat_history' -Ok { param($s) Test-TRGwsTrue $s['historyOnByDefault'] } -Good 'chat history is on by default' -Bad 'chat history is off by default' }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.CHAT.1.2v1' -Level Shall -Title 'Users cannot change chat history' `
    -Needs 'GwsPolicies' `
    -Guidance 'In Google Chat, History for chats, untick Allow users to change their history setting.' `
    -Test { Test-TRGsCtl -Type 'chat.chat_history' -Ok { param($s) -not (Test-TRGwsTrue $s['allowUserModification']) } -Good 'users cannot change their history setting' -Bad 'users can turn chat history off' }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.CHAT.2.1v1' -Level Shall -Title 'External file sharing in Chat is off' `
    -Needs 'GwsPolicies' -Checks 'GCOL-02' -Map '3.1.4.1.1' `
    -Guidance 'In Google Chat, Chat file sharing, set External filesharing to No files.' `
    -Test { Test-TRGsCtl -Type 'chat.chat_file_sharing' -Ok { param($s) [string]$s['externalFileSharing'] -eq 'NO_FILES' } -Good 'external file sharing in Chat is off' -Bad 'files can be shared in external chats' -Detail { param($s) [string]$s['externalFileSharing'] } }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.CHAT.3.1v1' -Level Should -Title 'Space history is always on' `
    -Needs 'GwsPolicies' `
    -Guidance 'In Google Chat, Space history, set it to Always on.' `
    -Test { Test-TRGsCtl -Type 'chat.space_history' -Ok { param($s) [string]$s['historyState'] -eq 'HISTORY_ALWAYS_ON' } -Good 'space history is always on' -Bad 'space history can be off' -Detail { param($s) [string]$s['historyState'] } }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.CHAT.4.1v1' -Level Shall -Title 'External chat is limited to allowlisted domains' `
    -Needs 'GwsPolicies' -Checks 'GCOL-02' -Map '3.1.4.2.1' `
    -Guidance 'In Google Chat, External chat settings, allow external chat only with allowlisted domains.' `
    -Test { Test-TRGsCtl -Type 'chat.external_chat_restriction' -Ok { param($s) -not (Test-TRGwsTrue $s['allowExternalChat']) -or [string]$s['externalChatRestriction'] -eq 'TRUSTED_DOMAINS' } -Good 'external chat is off or limited to allowlisted domains' -Bad 'users can chat with any external account' }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.CHAT.5.1v1' -Level Shall -Title 'Chat content reporting is on for every conversation type' `
    -Needs 'GwsPolicies', 'GwsAdminEvents' `
    -Guidance 'In Google Chat, Content reporting, allow users to report messages in direct messages, group chats and all spaces.' `
    -Test {
    $s = Get-TRGwsSetting 'chat.content_reporting'
    if ($s.Known) {
        return Test-TRGsCtl -Type 'chat.content_reporting' -Ok { param($x) ([string]$x['oneOnOneDirectMessagesReporting'] -ne 'DISABLED') -and ([string]$x['groupDirectMessagesReporting'] -ne 'DISABLED') -and ([string]$x['spacesReporting'] -ne 'DISABLED') -and ([string]$x['spacesReportingType'] -ne 'DISCOVERABLE_SPACES_ONLY') } -Good 'content reporting is on for all conversation types' -Bad 'content reporting is off for some conversations'
    }
    $evals = foreach ($n in 'one_on_one_reporting', 'group_chat_reporting', 'room_reporting') { Test-TRGwsLogSetting -Setting ('ContentReportingProto ' + $n) -Ok { param($v) $v -ne 'CONTENT_REPORTING_STATE_DISABLED' } -Good ('Reporting (' + $n + ') is on') -Bad ('reporting (' + $n + ') is off') -DefaultOk $true -DefaultText 'reporting on' }
    Join-TRGsEvals $evals
}

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.CHAT.5.2v1' -Level Should -Title 'All reporting categories are selected' `
    -Needs 'GwsPolicies', 'GwsAdminEvents' `
    -Guidance 'In Google Chat, Content reporting, select every report category.' `
    -Test {
    $s = Get-TRGwsSetting 'chat.content_reporting'
    if ($s.Known) {
        $cats = @(@($s.Root['reportingCategories']) | ForEach-Object { if ($_ -is [string]) { $_ } else { [string](Get-TRV $_ 'category') } } | Where-Object { $_ })
        $want = @('HARASSMENT', 'DISCRIMINATION', 'EXPLICIT_CONTENT', 'SPAM', 'CONFIDENTIAL_INFO', 'SENSITIVE_INFO', 'OTHER')
        $miss = @($want | Where-Object { $cats -notcontains $_ })
        if ($miss.Count) { return New-TRCtl Fail ('Report categories not selected: {0}.' -f ($miss -join ', ').ToLower().Replace('_', ' ')) }
        return New-TRCtl Pass 'All report categories are selected.'
    }
    $vals = Get-TRGwsLogSetting 'ContentReportingProto report_types'
    if ($null -eq $vals -or -not @($vals).Count) { return New-TRCtl Pass 'No change was logged in the last 180 days, so the Google default (all categories) applies.' }
    $bad = @($vals | Where-Object { $_.Deleted -or (@(([string]$_.Value) -split ',').Count -lt 7) })
    if ($bad.Count) { return New-TRCtl Fail ('Some report categories are not selected in {0}.' -f (Join-TRList ($bad | ForEach-Object { $_.Scope }) 4)) }
    New-TRCtl Pass 'All report categories are selected (from the admin audit log).'
}

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.CLASSROOM.1.1v1' -Level Should -Title 'Only users in the domain can join classes' `
    -Licence 'Classroom' -Needs 'GwsPolicies' `
    -Guidance 'In Classroom, Class settings, set Who can join classes in your domain to Users in your domain only.' `
    -Test { Test-TRGsCtl -Type 'classroom.class_membership' -Ok { param($s) [string]$s['whoCanJoinClasses'] -in @('ANYONE_IN_DOMAIN', 'ANYONE_IN_ALLOWLISTED_DOMAINS') } -Good 'only domain users can join classes' -Bad 'users outside the domain can join classes' }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.CLASSROOM.1.2v1' -Level Should -Title 'Users can join only domain classes' `
    -Licence 'Classroom' -Needs 'GwsPolicies' `
    -Guidance 'In Classroom, Class settings, set Which classes can users in your domain join to Classes in your domain only.' `
    -Test { Test-TRGsCtl -Type 'classroom.class_membership' -Ok { param($s) [string]$s['whichClassesCanUsersJoin'] -in @('CLASSES_IN_DOMAIN', 'CLASSES_IN_ALLOWLISTED_DOMAINS') } -Good 'users can join only domain classes' -Bad 'users can join classes outside the domain' }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.CLASSROOM.2.1v1' -Level Should -Title 'Apps cannot access Classroom data' `
    -Licence 'Classroom' -Needs 'GwsPolicies' `
    -Guidance 'In Classroom, Data access, untick Users can authorise apps to access their Google Classroom data.' `
    -Test { Test-TRGsCtl -Type 'classroom.api_data_access' -Ok { param($s) -not (Test-TRGwsTrue $s['enableApiAccess']) } -Good 'Classroom API access is off' -Bad 'users can authorise apps to access Classroom data' }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.CLASSROOM.3.1v1' -Level Should -Title 'Clever roster import is off' `
    -Licence 'Classroom' -Needs 'GwsPolicies' `
    -Guidance 'In Classroom, Roster import, turn Clever off.' `
    -Test { Test-TRGsCtl -Type 'classroom.roster_import' -Ok { param($s) [string]$s['rosterImportOption'] -eq 'OFF' } -Good 'roster import is off' -Bad 'roster import with Clever is on' }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.CLASSROOM.4.1v1' -Level Should -Title 'Only teachers can unenrol students' `
    -Licence 'Classroom' -Needs 'GwsPolicies' `
    -Guidance 'In Classroom, Student unenrolment, choose Teachers only.' `
    -Test { Test-TRGsCtl -Type 'classroom.student_unenrollment' -Ok { param($s) [string]$s['whoCanUnenrollStudents'] -eq 'TEACHERS_ONLY' } -Good 'only teachers can unenrol students' -Bad 'students can unenrol themselves' }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.CLASSROOM.5.1v1' -Level Should -Title 'Only verified teachers can create classes' `
    -Licence 'Classroom' -Needs 'GwsPolicies' `
    -Guidance 'In Classroom, Teacher permissions, set Who can create classes to Verified teachers only.' `
    -Test { Test-TRGsCtl -Type 'classroom.teacher_permissions' -Ok { param($s) [string]$s['whoCanCreateClasses'] -eq 'VERIFIED_TEACHERS_ONLY' } -Good 'only verified teachers can create classes' -Bad 'unverified users can create classes' }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.COMMONCONTROLS.1.1v1' -Level Shall -Title 'Phishing-resistant 2SV is required for everyone' `
    -Needs 'GwsPolicies' -Checks 'GIAM-01', 'GPRV-02' -Map '4.1.1.2' `
    -Guidance 'Enforce 2-Step Verification with Allowed methods set to Only security key (passkeys and security keys) for every organisational unit.' `
    -Test { Join-TRGsEvals (Get-TRGs2svEvals -FactorMode PasskeyOnly) }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.COMMONCONTROLS.1.2v1' -Level Shall -Title '2SV is enforced for everyone' `
    -Needs 'GwsPolicies' -Checks 'GIAM-01', 'GIAM-02' -Map '4.1.1.1', '4.1.1.3' `
    -Guidance 'Allow users to turn on 2-Step Verification and set Enforcement to On for every organisational unit.' `
    -Test { Join-TRGsEvals (Get-TRGs2svEvals) }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.COMMONCONTROLS.1.3v1' -Level Shall -Title 'Text and voice codes are not used for 2SV' `
    -Needs 'GwsPolicies' -Checks 'GIAM-03' `
    -Guidance 'Set Allowed methods to Any except verification codes via text, phone call, or stronger.' `
    -Test { Join-TRGsEvals (Get-TRGs2svEvals -FactorMode NoTelephony) }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.COMMONCONTROLS.1.4v1' -Level Shall -Title '2SV enrolment period is between one day and one week' `
    -Needs 'GwsPolicies' `
    -Guidance 'Set the New user enrolment period to between one day and one week.' `
    -Test { Test-TRGsCtl -Type 'security.two_step_verification_grace_period' -Ok { param($s) $v = ConvertTo-TRGwsSeconds $s['enrollmentGracePeriod']; $null -ne $v -and $v -ge 86400 -and $v -le 604800 } -Good 'the enrolment period is between one day and one week' -Bad 'the enrolment period is outside one day to one week' -Detail { param($s) 'Enrolment period ' + (Format-TRGwsDuration (ConvertTo-TRGwsSeconds $s['enrollmentGracePeriod'])) } }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.COMMONCONTROLS.1.5v1' -Level Shall -Title 'Users cannot trust a device to skip 2SV' `
    -Needs 'GwsPolicies' -Checks 'GIAM-10' `
    -Guidance 'Untick Allow user to trust the device.' `
    -Test { Test-TRGsCtl -Type 'security.two_step_verification_device_trust' -Ok { param($s) -not (Test-TRGwsTrue $s['allowTrustingDevice']) } -Good 'trusting a device is off' -Bad 'users can trust a device' }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.COMMONCONTROLS.2.1v1' -Level Should -Title 'Context-aware access is used' `
    -Licence 'ContextAware' -Needs 'GwsAdminEvents' -Map '4.2.2.1' `
    -Guidance 'Turn on context-aware access and create access levels based on device and location for Workspace apps.' `
    -Test {
    $e = @(Get-TRItems 'GwsAdminEvents' | Where-Object { $_.Event -eq 'TOGGLE_CAA_ENABLEMENT' } | Sort-Object Time)
    if (-not $e.Count) { return New-TRCtl Manual 'No change to context-aware access was logged in the last 180 days, and it is off by default. Confirm in Security, Access and data control, Context-aware access.' }
    $last = $e[-1]
    if ([string]$last.NEW_VALUE -eq 'ENABLED') { return New-TRCtl Pass ('Context-aware access was turned on {0}.' -f (Format-TRDate $last.Time)) }
    New-TRCtl Fail ('Context-aware access was turned off {0}.' -f (Format-TRDate $last.Time))
}

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.COMMONCONTROLS.3.1v1' -Level Should -Title 'Post-SSO verification for the organisation SSO profile' -Needs 'GwsAdminEvents' `
    -Guidance 'In Security, Authentication, SSO with third-party IdP, turn on Ask users for additional verification from Google if a sign-in attempt is suspicious.' `
    -Test {
    if (-not @(Get-TRItems 'GwsSsoProfiles').Count -and -not @(Get-TRGwsSsoAssignments).Count) { return New-TRCtl NotApplicable 'No third-party SSO profile is configured.' }
    ConvertTo-TRGwsCtl (Test-TRGwsLogSetting -Setting 'SsoPolicyProto challenge_selection_behavior' -Ok { param($v) $v -eq 'PERFORM_CHALLENGE_SELECTION' } -Good 'Post-SSO verification is on' -Bad 'post-SSO verification is off' -DefaultOk $true -DefaultText 'verification on')
}

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.COMMONCONTROLS.3.2v1' -Level Should -Title 'Post-SSO verification for other SSO profiles' -Needs 'GwsAdminEvents' `
    -Guidance 'In Security, Authentication, SSO with third-party IdP, turn on Ask users for additional verification from Google if a sign-in attempt is suspicious.' `
    -Test {
    if (-not @(Get-TRItems 'GwsSsoProfiles').Count -and -not @(Get-TRGwsSsoAssignments).Count) { return New-TRCtl NotApplicable 'No third-party SSO profile is configured.' }
    ConvertTo-TRGwsCtl (Test-TRGwsLogSetting -Setting 'SsoPolicyProto sso_profile_challenge_selection_behavior' -Ok { param($v) $v -eq 'SSO_PROFILES_PERFORM_CHALLENGE_SELECTION' } -Good 'Post-SSO verification is on' -Bad 'post-SSO verification is off' -DefaultOk $true -DefaultText 'verification on')
}

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.COMMONCONTROLS.4.1v1' -Level Shall -Title 'Web sessions expire after 12 hours' `
    -Needs 'GwsPolicies' -Checks 'GIAM-06' -Map '4.2.4.1' `
    -Guidance 'In Google session control, set Web session duration to 12 hours or less.' `
    -Test { Test-TRGsCtl -Type 'security.session_controls' -Ok { param($s) $v = ConvertTo-TRGwsSeconds $s['webSessionDuration']; $null -ne $v -and $v -le 43200 } -Good 'sessions last 12 hours or less' -Bad 'sessions last longer than 12 hours' -Detail { param($s) 'Session length ' + (Format-TRGwsDuration (ConvertTo-TRGwsSeconds $s['webSessionDuration'])) } }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.COMMONCONTROLS.5.1v1' -Level Shall -Title 'Strong passwords are enforced' `
    -Needs 'GwsPolicies' -Checks 'GIAM-04' -Map '4.1.5.1' `
    -Guidance 'In Password management, tick Enforce strong password.' `
    -Test { Test-TRGsCtl -Type 'security.password' -Ok { param($s) [string]$s['allowedStrength'] -eq 'STRONG' } -Good 'strong passwords are enforced' -Bad 'weak passwords are allowed' }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.COMMONCONTROLS.5.2v1' -Level Shall -Title 'Passwords are at least 12 characters' `
    -Needs 'GwsPolicies' -Checks 'GIAM-04' -Map '4.1.5.1' `
    -Guidance 'Set the minimum password length to 12 or more.' `
    -Test { Test-TRGsCtl -Type 'security.password' -Ok { param($s) [int]$s['minimumLength'] -ge 12 } -Good 'the minimum length is 12 or more' -Bad 'the minimum password length is below 12' -Detail { param($s) 'Minimum length ' + [string]$s['minimumLength'] } }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.COMMONCONTROLS.5.3v1' -Level Should -Title 'Passwords are at least 16 characters' `
    -Needs 'GwsPolicies' -Checks 'GIAM-04' `
    -Guidance 'Set the minimum password length to 16 or more.' `
    -Test { Test-TRGsCtl -Type 'security.password' -Ok { param($s) [int]$s['minimumLength'] -ge 16 } -Good 'the minimum length is 16 or more' -Bad 'the minimum password length is below 16' -Detail { param($s) 'Minimum length ' + [string]$s['minimumLength'] } }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.COMMONCONTROLS.5.4v1' -Level Shall -Title 'Password policy is enforced at next sign-in' `
    -Needs 'GwsPolicies' -Checks 'GIAM-04' `
    -Guidance 'Tick Enforce password policy at next sign-in.' `
    -Test { Test-TRGsCtl -Type 'security.password' -Ok { param($s) Test-TRGwsTrue $s['enforceRequirementsAtLogin'] } -Good 'the policy is enforced at next sign-in' -Bad 'the password policy is not enforced at next sign-in' }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.COMMONCONTROLS.5.5v1' -Level Shall -Title 'Passwords cannot be reused' `
    -Needs 'GwsPolicies' -Checks 'GIAM-04' `
    -Guidance 'Untick Allow password reuse.' `
    -Test { Test-TRGsCtl -Type 'security.password' -Ok { param($s) -not (Test-TRGwsTrue $s['allowReuse']) } -Good 'password reuse is not allowed' -Bad 'password reuse is allowed' }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.COMMONCONTROLS.5.6v1' -Level Shall -Title 'Passwords do not expire' `
    -Needs 'GwsPolicies' -Checks 'GIAM-04' `
    -Guidance 'Set password expiration to Never expires.' `
    -Test { Test-TRGsCtl -Type 'security.password' -Ok { param($s) $v = ConvertTo-TRGwsSeconds $s['expirationDuration']; ($null -eq $v) -or ($v -eq 0) } -Good 'passwords never expire' -Bad 'passwords expire' -Detail { param($s) 'Expires after ' + (Format-TRGwsDuration (ConvertTo-TRGwsSeconds $s['expirationDuration'])) } }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.COMMONCONTROLS.6.1v1' -Level Shall -Title 'Admin accounts are cloud-only' `
    -Needs 'GwsUsers', 'GwsRoleAssignments' -Checks 'GPRV-06' `
    -Guidance 'Make sure administrators sign in directly with Google rather than through a third-party identity provider: exclude their organisational unit or group from SSO.' `
    -Test {
    if (-not (Test-TRCollected @('GwsSsoAssignments'))) { return New-TRCtl NotAssessed 'SSO assignments could not be read.' }
    $sso = @{}
    foreach ($u in (Get-TRGwsSsoUsers)) { $sso[([string]$u.primaryEmail).ToLower()] = $true }
    if (-not $sso.Count) { return New-TRCtl Pass 'No third-party SSO applies to any user, so all admins sign in with Google.' }
    $priv = Get-TRGwsPrivilegedUsers
    $bad = @($priv.Keys | Where-Object { $sso.ContainsKey($_) })
    if ($bad.Count) { return New-TRCtl Fail ('{0} through third-party SSO.' -f (Format-TRN $bad.Count 'privileged account signs in' 'privileged accounts sign in')) (@($bad | ForEach-Object { New-TRAffected $_ $priv[$_] })) }
    New-TRCtl Pass 'Third-party SSO is used, but no privileged account is covered by it.'
}

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.COMMONCONTROLS.6.2v1' -Level Shall -Title 'Two to eight super admins' `
    -Needs 'GwsUsers' -Checks 'GPRV-01' -Map '1.1.1' `
    -Guidance 'Keep between two and eight separate super admin accounts.' `
    -Test {
    $sa = @(Get-TRGwsSuperAdmins)
    $t = '{0}: {1}.' -f (Format-TRN $sa.Count 'super admin'), (Join-TRList ($sa | ForEach-Object { $_.primaryEmail }) 8)
    if ($sa.Count -ge 2 -and $sa.Count -le 8) { return New-TRCtl Pass $t }
    New-TRCtl Fail $t (@($sa | ForEach-Object { New-TRAffected ([string]$_.primaryEmail) 'Super admin' }))
}

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.COMMONCONTROLS.7.1v1' -Level Should -Title 'Conflicting unmanaged accounts are replaced' `
    -Needs 'GwsPolicies' -Checks 'GIAM-11' `
    -Guidance 'In Account settings, Unmanaged accounts, choose Replace conflicting unmanaged accounts with managed ones.' `
    -Test { Test-TRGsCtl -Type 'provisioning.conflicting_accounts_management' -Ok { param($s) $v = [string]$(if ($s['conflictingAccountsManagement']) { $s['conflictingAccountsManagement'] } else { $s['option'] }); $v -eq 'REPLACE_CONFLICTING_ACCOUNT' } -Good 'conflicting accounts are replaced' -Bad 'conflicting accounts are not replaced' }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.COMMONCONTROLS.8.1v1' -Level Shall -Title 'Super admin self-recovery is off' `
    -Needs 'GwsPolicies' -Checks 'GPRV-04' -Map '4.1.2.1' `
    -Guidance 'Untick Allow super admins to recover their account.' `
    -Test { Test-TRGsCtl -Type 'security.super_admin_account_recovery' -Ok { param($s) -not (Test-TRGwsTrue $s['enableAccountRecovery']) } -Good 'super admin self-recovery is off' -Bad 'super admins can recover their own accounts' }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.COMMONCONTROLS.8.2v1' -Level Shall -Title 'User and admin self-recovery is off' `
    -Needs 'GwsPolicies' `
    -Guidance 'Untick Allow users and non-super admins to recover their account. Note that CIS recommends the opposite (4.1.2.2); agree the approach with the client.' `
    -Test { Test-TRGsCtl -Type 'security.user_account_recovery' -Ok { param($s) -not (Test-TRGwsTrue $s['enableAccountRecovery']) } -Good 'user self-recovery is off' -Bad 'users and non-super admins can recover their own accounts' }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.COMMONCONTROLS.8.3v1' -Level Should -Title 'Users cannot add recovery information' -ManualOnly `
    -Guidance 'In Account settings, untick Allow users to add recovery information (recovery phone and email).'

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.COMMONCONTROLS.9.1v1' -Level Shall -Title 'Privileged accounts use the Advanced Protection Program' -ManualOnly -Map '4.1.3.1' `
    -Guidance 'Allow enrolment in the Advanced Protection Program and enrol every super admin; check enrolment in the user list (Advanced Protection column).'

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.COMMONCONTROLS.9.2v1' -Level Should -Title 'Sensitive accounts use the Advanced Protection Program' -ManualOnly `
    -Guidance 'Enrol directors, finance staff and other high-value accounts in the Advanced Protection Program.'

$script:TRGwsScopeMap = [ordered]@{
    'Drive' = @('DRIVE_ALL', 'DRIVE_HIGH_RISK'); 'Gmail' = @('GMAIL_ALL', 'GMAIL_HIGH_RISK'); 'Calendar' = @('CALENDAR_ALL'); 'Contacts' = @('CONTACTS_ALL')
    'Google Workspace Admin' = @('GSUITE_ADMIN_ALL'); 'Vault' = @('VAULT_ALL'); 'Cloud Platform' = @('CLOUD_PLATFORM'); 'Cloud Billing' = @('CLOUD_BILLING')
    'Cloud Machine Learning' = @('CLOUD_ML'); 'Apps Script API' = @('APPS_SCRIPT_API'); 'Apps Script Runtime' = @('APPS_SCRIPT_RUNTIME'); 'Classroom' = @('CLASSROOM_ALL', 'CLASSROOM_HIGH_RISK')
    'Tasks' = @('TASKS'); 'Groups' = @('GROUPS'); 'Chat' = @('CHAT', 'CHAT_HIGH_RISK'); 'Google Sign-in' = @('SIGN_IN'); 'Meet' = @('MEET'); 'Cloud Search' = @('CLOUD_SEARCH')
}

function Get-TRGwsRestrictedScopes {
    $out = New-Object System.Collections.ArrayList
    foreach ($p in @((Get-TRGwsPolicyIndex)['api_controls.google_services'])) {
        foreach ($svc in @(Get-TRV $p.Value 'services')) {
            if (-not $svc) { continue }
            $g = [string](Get-TRV $svc 'scopesGroup')
            $en = Get-TRV $svc 'isEnabled'
            if ($g -and ($null -eq $en -or -not (Test-TRGwsTrue $en))) { [void]$out.Add($g) }
        }
    }
    , @($out | Select-Object -Unique)
}

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.COMMONCONTROLS.10.1v1' -Level Shall -Title 'Third-party access to every Google service is restricted' `
    -Needs 'GwsPolicies' -Checks 'GAPP-01' -Map '4.2.1.1' `
    -Guidance 'In API controls, Manage Google services, restrict access for every service so only trusted apps can use it.' `
    -Test {
    $r = @(Get-TRGwsRestrictedScopes)
    $open = @($script:TRGwsScopeMap.Keys | Where-Object { $k = $_; -not @($script:TRGwsScopeMap[$k] | Where-Object { $r -contains $_ }).Count })
    if (-not $open.Count) { return New-TRCtl Pass 'Access to every Google service is restricted to trusted apps.' }
    New-TRCtl Fail ('{0} unrestricted: {1}.' -f (Format-TRN $open.Count 'service is' 'services are'), (Join-TRList $open 8)) (@($open | ForEach-Object { New-TRAffected $_ 'Unrestricted' }))
}

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.COMMONCONTROLS.10.2v1' -Level Shall -Title 'Users cannot consent to low-risk scopes for restricted services' `
    -Needs 'GwsPolicies' `
    -Guidance 'For Drive, Gmail, Classroom and Chat, restrict access fully rather than allowing users to grant access to non-high-risk scopes.' `
    -Test {
    $r = @(Get-TRGwsRestrictedScopes)
    $part = @($r | Where-Object { $_ -in @('DRIVE_HIGH_RISK', 'GMAIL_HIGH_RISK', 'CLASSROOM_HIGH_RISK', 'CHAT_HIGH_RISK') } | ForEach-Object { ($_ -split '_')[0] })
    if ($part.Count) { return New-TRCtl Fail ('Only high-risk scopes are restricted for: {0}.' -f (($part | ForEach-Object { $_.Substring(0, 1) + $_.Substring(1).ToLower() }) -join ', ')) }
    New-TRCtl Pass 'No service is limited to restricting only high-risk scopes.'
}

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.COMMONCONTROLS.10.3v1' -Level Shall -Title 'Unconfigured internal apps are not trusted' `
    -Needs 'GwsPolicies' -Checks 'GAPP-04' `
    -Guidance 'Untick Trust internal, domain-owned apps.' `
    -Test { Test-TRGsCtl -Type 'api_controls.internal_apps' -Ok { param($s) -not (Test-TRGwsTrue $s['trustInternalApps']) } -Good 'internal apps are not trusted automatically' -Bad 'internal apps are trusted automatically' }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.COMMONCONTROLS.10.4v1' -Level Shall -Title 'Unconfigured third-party apps are blocked' `
    -Needs 'GwsPolicies' -Checks 'GAPP-01' `
    -Guidance 'Set Unconfigured third-party apps to Don''t allow users to access any third-party apps.' `
    -Test {
    $s = Get-TRGwsSetting 'api_controls.unconfigured_third_party_apps'
    if (-not $s.Known -and -not $s.Overrides.Count) { return New-TRCtl Fail 'No restriction was returned, so users can access any unconfigured third-party app.' }
    Test-TRGsCtl -Type 'api_controls.unconfigured_third_party_apps' -Ok { param($x) [string]$x['accessLevel'] -in @('BLOCK_ALL', 'BLOCK_ALL_SCOPES') } -Good 'unconfigured third-party apps are blocked' -Bad 'unconfigured third-party apps are not fully blocked' -Detail { param($x) Get-TRGwsAppAccessText ([string]$x['accessLevel']) }
}

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.COMMONCONTROLS.10.5v1' -Level Shall -Title 'Less secure apps are blocked' `
    -Needs 'GwsPolicies' -Checks 'GIAM-09' `
    -Guidance 'Disable access to less secure apps for all users.' `
    -Test { Test-TRGsCtl -Type 'security.less_secure_apps' -Ok { param($s) -not (Test-TRGwsTrue $s['allowLessSecureApps']) } -Good 'less secure apps are blocked' -Bad 'less secure apps can be allowed' }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.COMMONCONTROLS.11.1v1' -Level Shall -Title 'Only approved Marketplace apps can be installed' `
    -Needs 'GwsPolicies' -Checks 'GAPP-03' -Map '3.1.9.1.1' `
    -Guidance 'Allow users to install only allowlisted Marketplace apps, and untick allowing all internal apps.' `
    -Test { Test-TRGsCtl -Type 'workspace_marketplace.apps_access_options' -Ok { param($s) [string]$s['accessLevel'] -in @('ALLOW_LISTED_APPS', 'ALLOW_NONE') -and -not (Test-TRGwsTrue $s['allowAllInternalApps']) } -Good 'only allowlisted Marketplace apps can be installed' -Bad 'users can install unapproved Marketplace apps' -Detail { param($s) 'Access level ' + [string]$s['accessLevel'] + $(if (Test-TRGwsTrue $s['allowAllInternalApps']) { '; all internal apps allowed' } else { '' }) } }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.COMMONCONTROLS.12.1v1' -Level Shall -Title 'Google Takeout is off' `
    -Needs 'GwsPolicies' -Checks 'GCOL-08' `
    -Guidance 'In Google Takeout, turn it off for services without an individual control and for each listed service.' `
    -Test {
    $evals = @(Test-TRGwsPolicy -Type 'takeout.service_status' -Ok { param($s) [string]$s['serviceState'] -eq 'DISABLED' } -Good 'Takeout is off' -Bad 'Takeout is on')
    $names = @{ blogger = 'Blogger'; books = 'Google Books'; location_history = 'Location History'; maps = 'Google Maps'; pay = 'Google Pay'; photos = 'Google Photos'; play = 'Google Play'; play_console = 'Play Console'; youtube = 'YouTube' }
    foreach ($a in 'blogger', 'books', 'location_history', 'maps', 'pay', 'photos', 'play', 'play_console', 'youtube') {
        $t = $a + '.user_takeout'
        if (-not (Get-TRGwsSetting $t).Known -and -not (Get-TRGwsSetting $t).Overrides.Count) { continue }
        $evals += (Test-TRGwsPolicy -Type $t -Ok { param($s) [string]$s['takeoutStatus'] -eq 'DISABLED' } -Good ('Takeout for ' + $names[$a] + ' is off') -Bad ('Takeout for ' + $names[$a] + ' is on'))
    }
    Join-TRGsEvals $evals
}

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.COMMONCONTROLS.13.1v1' -Level Shall -Title 'All system-defined alert rules are on' `
    -Needs 'GwsPolicies' -Checks 'GSEC-01' -Map '6.1', '6.2', '6.3', '6.4', '6.5', '6.6', '6.7', '6.8' `
    -Guidance 'In Security, Alert center, Rules, turn on every system-defined rule.' `
    -Test {
    $r = @(Get-TRGwsRules 'rule.system_defined_alerts')
    if (-not $r.Count) { return New-TRCtl NotAssessed 'No system-defined alert rules were returned.' }
    $off = @($r | Where-Object { [string](Get-TRV $_ 'state') -ne 'ACTIVE' })
    if ($off.Count) { return New-TRCtl Fail ('{0} of {1} system rules {3} off: {2}.' -f $off.Count, $r.Count, (Join-TRList ($off | ForEach-Object { Get-TRV $_ 'displayName' }) 6), (Select-TRText $off.Count 'is' 'are')) (@($off | ForEach-Object { New-TRAffected ([string](Get-TRV $_ 'displayName')) 'Off' })) }
    New-TRCtl Pass ('All {0} system-defined alert rules are on.' -f $r.Count)
}

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.COMMONCONTROLS.14.1v1' -Level Shall -Title 'Critical logs go to a SIEM' -ManualOnly `
    -Guidance 'Send Workspace audit logs to the SOC or SIEM (for example with the BigQuery export on Enterprise, or a SIEM connector using the Reports API).'

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.COMMONCONTROLS.14.2v1' -Level Shall -Title 'Audit logs are kept for 12 months' -ManualOnly `
    -Guidance 'Workspace keeps most audit logs for six months. Export them to a SIEM or BigQuery to keep them searchable for 3 months and retrievable for 12.'

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.COMMONCONTROLS.15.1v1' -Level Shall -Title 'Data is stored in the United States' `
    -Guidance 'Applies to US federal agencies. UK organisations can choose Europe as the data region where data regions are licensed.' `
    -Test {
    $v = Get-TRGwsRootValue 'data_regions.data_at_rest_region' 'region'
    New-TRCtl NotApplicable ('Applies to US federal agencies only. Data at rest region: {0}.' -f $(if ($v) { $v } else { 'not set (any region)' }))
}

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.COMMONCONTROLS.15.2v1' -Level Shall -Title 'Data is processed in the storage region' `
    -Licence 'DataRegionsEnterprise' -Needs 'GwsPolicies' `
    -Guidance 'In Data regions, set processing to the same region as data at rest.' `
    -Test { Test-TRGsCtl -Type 'data_regions.data_processing_region' -Ok { param($s) Test-TRGwsTrue $s['limitToStorageRegion'] } -Good 'processing is limited to the storage region' -Bad 'data can be processed outside the storage region' }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.COMMONCONTROLS.16.1v1' -Level Should -Title 'Services without an individual control are off' `
    -Needs 'GwsPolicies' -Map '3.1.8.1' `
    -Guidance 'In Additional Google services, turn off access to services without individual control for everyone.' `
    -Test { Test-TRGsCtl -Type 'enterprise_service_restrictions.service_status' -Ok { param($s) [string]$s['serviceState'] -eq 'ENABLED' } -Good 'services without an individual control are restricted' -Bad 'users can use Google services that have no individual control' }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.COMMONCONTROLS.16.2v1' -Level Should -Title 'Early access apps are off' `
    -Needs 'GwsPolicies' `
    -Guidance 'In Additional Google services, turn Early Access Apps off.' `
    -Test {
    $s = Get-TRGwsSetting 'early_access_apps.service_status'
    if (-not $s.Known -and -not $s.Overrides.Count) { return New-TRCtl Pass 'Early access apps are not turned on.' }
    Test-TRGsCtl -Type 'early_access_apps.service_status' -Ok { param($x) [string]$x['serviceState'] -ne 'ENABLED' } -Good 'early access apps are off' -Bad 'early access apps are on'
}

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.COMMONCONTROLS.16.3v1' -Level Should -Title 'Looker Studio sharing outside the organisation is off' -ManualOnly `
    -Guidance 'In Additional Google services, Looker Studio, turn off sharing outside the organisation.'

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.COMMONCONTROLS.16.4v1' -Level Should -Title 'Pinpoint access to Drive is off' -ManualOnly `
    -Guidance 'In Additional Google services, Pinpoint, turn off access to Drive.'

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.COMMONCONTROLS.17.1v1' -Level Should -Title 'Multi-party approval is on for sensitive admin actions' `
    -Needs 'GwsPolicies' `
    -Guidance 'In Security, Authentication, Multi-party approval settings, require approval for sensitive admin actions.' `
    -Test {
    $s = Get-TRGwsSetting 'multi_party_approval.require_approvals'
    if (-not $s.Known -and -not $s.Overrides.Count) { return New-TRCtl Fail 'Multi-party approval is not turned on (no setting was returned).' }
    Test-TRGsCtl -Type 'multi_party_approval.require_approvals' -Ok { param($x) [string]$x['multiPartyApprovalState'] -eq 'ENABLED' } -Good 'multi-party approval is on' -Bad 'multi-party approval is off'
}

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.COMMONCONTROLS.18.1v1' -Level Shall -Title 'DLP protects sensitive data in Drive, Calendar, Chat and Gmail' `
    -Licence 'Dlp' -Needs 'GwsPolicies' -Checks 'GSEC-04' -Map '4.2.3.1' `
    -Guidance 'Create DLP rules for personal and financial data (for the UK: National Insurance numbers, bank account and sort codes, passport and driving licence numbers, card numbers) covering Drive, Calendar, Chat and Gmail.' `
    -Test {
    $rules = @(Get-TRGwsRules 'rule.dlp' | Where-Object { [string](Get-TRV $_ 'state') -eq 'ACTIVE' })
    if (-not $rules.Count) { return New-TRCtl Fail 'No active DLP rule exists.' }
    $apps = @($rules | ForEach-Object { Get-TRStrings (Get-TRV $_ 'triggers') } | ForEach-Object { ($_ -split '\.')[2] } | Select-Object -Unique)
    New-TRCtl Manual ('{0} cover: {1}. Confirm they detect the sensitive data types the client holds.' -f (Format-TRN $rules.Count 'active DLP rule'), (Join-TRList $apps 6))
}

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.COMMONCONTROLS.18.2v1' -Level Should -Title 'DLP rules block rather than warn' `
    -Licence 'Dlp' -Needs 'GwsPolicies' `
    -Guidance 'Once tested, set the DLP rule actions to block.' `
    -Test {
    $rules = @(Get-TRGwsRules 'rule.dlp' | Where-Object { [string](Get-TRV $_ 'state') -eq 'ACTIVE' })
    if (-not $rules.Count) { return New-TRCtl Fail 'No active DLP rule exists.' }
    $warn = @($rules | Where-Object { (ConvertTo-Json -InputObject (Get-TRV $_ 'action') -Depth 10 -Compress) -notmatch '(?i)block' })
    if ($warn.Count) { return New-TRCtl Fail ('{0} {2} not block: {1}.' -f (Format-TRN $warn.Count 'DLP rule'), (Join-TRList ($warn | ForEach-Object { Get-TRV $_ 'displayName' }) 5), (Select-TRText $warn.Count 'does' 'do')) }
    New-TRCtl Pass ('All {0} block.' -f (Format-TRN $rules.Count 'active DLP rule'))
}

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.DRIVEDOCS.1.1v1' -Level Shall -Title 'External sharing is limited to allowlisted domains' `
    -Needs 'GwsPolicies' -Checks 'GDRV-01' -Map '3.1.2.1.1.3' `
    -Guidance 'In Drive and Docs, Sharing settings, set Sharing outside of the organisation to Allowlisted domains (or Off).' `
    -Test { Test-TRGsCtl -Type 'drive_and_docs.external_sharing' -Ok { param($s) [string]$s['externalSharingMode'] -ne 'ALLOWED' } -Good 'external sharing is limited to allowlisted domains or off' -Bad 'files can be shared with anyone outside the organisation' -Detail { param($s) 'Mode ' + [string]$s['externalSharingMode'] } }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.DRIVEDOCS.1.2v1' -Level Should -Title 'Files from outside allowlisted domains cannot be received' `
    -Needs 'GwsPolicies' `
    -Guidance 'Untick allowing users to receive files from users or shared drives outside the allowlisted domains.' `
    -Test { Test-TRGsCtl -Type 'drive_and_docs.external_sharing' -Ok { param($s) if ([string]$s['externalSharingMode'] -eq 'ALLOWLISTED_DOMAINS') { -not (Test-TRGwsTrue $s['allowReceivingFilesOutsideAllowlistedDomains']) } else { -not (Test-TRGwsTrue $s['allowReceivingExternalFiles']) } } -Good 'files from outside are not received' -Bad 'users can receive files from outside the allowlisted domains' }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.DRIVEDOCS.1.3v1' -Level Shall -Title 'Users are warned when sharing outside' `
    -Needs 'GwsPolicies' -Checks 'GDRV-01' -Map '3.1.2.1.1.1', '3.1.2.1.1.4' `
    -Guidance 'Turn on the warning when files are shared outside the organisation or allowlisted domains.' `
    -Test { Test-TRGsCtl -Type 'drive_and_docs.external_sharing' -Ok { param($s) switch ([string]$s['externalSharingMode']) { 'ALLOWLISTED_DOMAINS' { Test-TRGwsTrue $s['warnForSharingOutsideAllowlistedDomains'] } 'ALLOWED' { Test-TRGwsTrue $s['warnForExternalSharing'] } default { $true } } } -Good 'users are warned when sharing outside' -Bad 'users are not warned when sharing outside' }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.DRIVEDOCS.1.4v1' -Level Should -Title 'Files cannot be shared with people without a Google account' `
    -Needs 'GwsPolicies' -Checks 'GDRV-01' `
    -Guidance 'Untick allowing users to share with people who are not using a Google account (visitor sharing).' `
    -Test { Test-TRGsCtl -Type 'drive_and_docs.external_sharing' -Ok { param($s) switch ([string]$s['externalSharingMode']) { 'ALLOWLISTED_DOMAINS' { -not (Test-TRGwsTrue $s['allowNonGoogleInvitesInAllowlistedDomains']) } 'ALLOWED' { -not (Test-TRGwsTrue $s['allowNonGoogleInvites']) } default { $true } } } -Good 'sharing with non-Google accounts is off' -Bad 'files can be shared with people without a Google account' }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.DRIVEDOCS.1.5v1' -Level Should -Title 'Content cannot be made available to anyone with the link' `
    -Needs 'GwsPolicies' -Checks 'GDRV-02' -Map '3.1.2.1.1.2' `
    -Guidance 'Untick allowing users to publish files on the web or make them visible to the world as public or unlisted.' `
    -Test { Test-TRGsCtl -Type 'drive_and_docs.external_sharing' -Ok { param($s) [string]$s['externalSharingMode'] -eq 'DISALLOWED' -or -not (Test-TRGwsTrue $s['allowPublishingFiles']) } -Good 'publishing to anyone with the link is off' -Bad 'files can be made public or available to anyone with the link' }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.DRIVEDOCS.1.6v1' -Level Shall -Title 'Access checker suggests recipients only' `
    -Needs 'GwsPolicies' -Checks 'GDRV-04' -Map '3.1.2.1.1.5' `
    -Guidance 'Set Access checker to Recipients only.' `
    -Test { Test-TRGsCtl -Type 'drive_and_docs.external_sharing' -Ok { param($s) [string]$s['accessCheckerSuggestions'] -eq 'RECIPIENTS_ONLY' } -Good 'access checker suggests recipients only' -Bad 'access checker can suggest wider sharing' -Detail { param($s) [string]$s['accessCheckerSuggestions'] } }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.DRIVEDOCS.1.7v1' -Level Should -Title 'Content cannot be moved to other organisations'' shared drives' `
    -Needs 'GwsPolicies' -Map '3.1.2.1.1.6' `
    -Guidance 'Set Distributing content outside of the organisation to No one.' `
    -Test { Test-TRGsCtl -Type 'drive_and_docs.external_sharing' -Ok { param($s) [string]$s['externalSharingMode'] -eq 'DISALLOWED' -or [string]$s['allowedPartiesForDistributingContent'] -eq 'NONE' } -Good 'nobody can move content to external shared drives' -Bad 'users can move content to shared drives owned by other organisations' -Detail { param($s) [string]$s['allowedPartiesForDistributingContent'] } }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.DRIVEDOCS.1.8v1' -Level Shall -Title 'New items are private to the owner' `
    -Needs 'GwsPolicies' -Checks 'GDRV-03' `
    -Guidance 'Set General access default to Private to the owner.' `
    -Test { Test-TRGsCtl -Type 'drive_and_docs.general_access_default' -Ok { param($s) [string]$s['defaultFileAccess'] -in @('PRIVATE_TO_OWNER', 'LINK_SHARING_PRIVATE') } -Good 'new items are private to the owner' -Bad 'new items are shared by default' -Detail { param($s) [string]$s['defaultFileAccess'] } }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.DRIVEDOCS.1.9v1' -Level Shall -Title 'Out-of-domain file warnings are on' `
    -Needs 'GwsPolicies' `
    -Guidance 'In Drive and Docs, turn on highlighting of files owned outside the organisation.' `
    -Test {
    $s = Get-TRGwsSetting 'drive_and_docs.external_file_warning'
    if (-not $s.Known -and -not $s.Overrides.Count) { return New-TRCtl NotAssessed 'The out-of-domain file warning setting was not returned.' }
    Test-TRGsCtl -Type 'drive_and_docs.external_file_warning' -Ok { param($x) Test-TRGwsTrue $x['highlightingEnabled'] } -Good 'external files are highlighted' -Bad 'external files are not highlighted'
}

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.DRIVEDOCS.1.10v1' -Level Should -Title 'Forms do not accept responses from outside when sharing is off' -ManualOnly `
    -Guidance 'If external sharing is off, stop forms owned in the organisation accepting responses from anyone with the link.'

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.DRIVEDOCS.1.11v1' -Level Should -Title 'Users cannot answer external forms when receiving is off' -ManualOnly `
    -Guidance 'If receiving external files is off, stop users submitting responses to forms outside the organisation.'

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.DRIVEDOCS.2.1v1' -Level Should -Title 'Shared drive managers cannot override settings' `
    -Needs 'GwsPolicies' -Checks 'GDRV-05' -Map '3.1.2.1.2.2' `
    -Guidance 'Untick Allow members with manager access to override the settings below.' `
    -Test { Test-TRGsCtl -Type 'drive_and_docs.shared_drive_creation' -Ok { param($s) -not (Test-TRGwsTrue $s['allowManagersToOverrideSettings']) } -Good 'managers cannot override shared drive settings' -Bad 'shared drive managers can override the settings' }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.DRIVEDOCS.2.2v1' -Level Shall -Title 'Non-members can be added to shared drive files' `
    -Needs 'GwsPolicies' `
    -Guidance 'Tick Allow people who aren''t shared drive members to be added to files. Note that CIS recommends the opposite (3.1.2.1.2.3); agree the approach with the client.' `
    -Test { Test-TRGsCtl -Type 'drive_and_docs.shared_drive_creation' -Ok { param($s) Test-TRGwsTrue $s['allowNonMemberAccess'] } -Good 'non-members can be added to files' -Bad 'non-members cannot be added to shared drive files' }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.DRIVEDOCS.3.1v1' -Level Shall -Title 'The Drive security update is applied' `
    -Needs 'GwsPolicies' -Checks 'GDRV-07' `
    -Guidance 'Apply the security update to all affected files and stop users removing it.' `
    -Test { Test-TRGsCtl -Type 'drive_and_docs.file_security_update' -Ok { param($s) [string]$s['securityUpdate'] -eq 'APPLY_TO_IMPACTED_FILES' -and -not (Test-TRGwsTrue $s['allowUsersToManageUpdate']) } -Good 'the security update is applied' -Bad 'the security update is not fully applied' }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.DRIVEDOCS.4.1v1' -Level Should -Title 'Drive SDK access is off' `
    -Needs 'GwsPolicies' `
    -Guidance 'Untick Allow users to access Google Drive with the Drive SDK API.' `
    -Test { Test-TRGsCtl -Type 'drive_and_docs.drive_sdk' -Ok { param($s) -not (Test-TRGwsTrue $s['enableDriveSdkApiAccess']) } -Good 'Drive SDK access is off' -Bad 'Drive SDK access is on' }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.DRIVEDOCS.5.1v1' -Level Shall -Title 'Drive for desktop only on authorised devices' `
    -Needs 'GwsPolicies' -Checks 'GDRV-06' -Map '3.1.2.3.1' `
    -Guidance 'Allow Drive for desktop only on authorised devices.' `
    -Test { Test-TRGsCtl -Type 'drive_and_docs.drive_for_desktop' -Ok { param($s) -not (Test-TRGwsTrue $s['allowDriveForDesktop']) -or (Test-TRGwsTrue $s['restrictToAuthorizedDevices']) } -Good 'Drive for desktop is limited to authorised devices' -Bad 'Drive for desktop works on any device' }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.DRIVEDOCS.5.2v1' -Level Shall -Title 'Ransomware detection for Drive for desktop is on' -ManualOnly `
    -Guidance 'Turn on monitoring for potential ransomware corruption in Drive for desktop.'

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.GEMINI.1.1v1' -Level Shall -Title 'Gemini app is off for unlicensed users' `
    -Needs 'GwsPolicies' `
    -Guidance 'In Generative AI, Gemini app, turn off access for users without a Gemini licence.' `
    -Test {
    $s = Get-TRGwsSetting 'gemini_app.unlicensed_user_access'
    if ($s.Known -or $s.Overrides.Count) { return Test-TRGsCtl -Type 'gemini_app.unlicensed_user_access' -Ok { param($x) -not (Test-TRGwsTrue $x['enabled']) } -Good 'unlicensed users cannot use the Gemini app' -Bad 'unlicensed users can use the Gemini app' }
    ConvertTo-TRGwsCtl (Test-TRGwsLogSetting -Setting 'BardNonDuetEnablementProto enable_bard_non_duet_access' -Ok { param($v) $v -ne 'true' } -Good 'Unlicensed users cannot use the Gemini app' -Bad 'unlicensed users can use the Gemini app' -DefaultOk $true -DefaultText 'off')
}

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.GEMINI.2.1v1' -Level Shall -Title 'Gemini beta features are off' `
    -Needs 'GwsPolicies' `
    -Guidance 'In Generative AI, turn off Alpha and beta Gemini features.' `
    -Test {
    $s = Get-TRGwsSetting 'gemini_for_workspace.beta_features'
    if ($s.Known -or $s.Overrides.Count) { return Test-TRGsCtl -Type 'gemini_for_workspace.beta_features' -Ok { param($x) -not (Test-TRGwsTrue $x['enabled']) } -Good 'Gemini beta features are off' -Bad 'Gemini beta features are on' }
    ConvertTo-TRGwsCtl (Test-TRGwsLogSetting -Setting 'GenAiAlphaSettingsProto alpha_enabled' -Ok { param($v) $v -ne 'true' } -Good 'Gemini beta features are off' -Bad 'Gemini beta features are on' -DefaultOk $true -DefaultText 'off')
}

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.GEMINI.3.1v1' -Level Shall -Title 'Gemini conversation history is on' -ManualOnly `
    -Guidance 'In the Gemini app settings, turn conversation history on.'

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.GEMINI.3.2v1' -Level Shall -Title 'Gemini conversations are kept for 18 months' -ManualOnly `
    -Guidance 'Set Gemini conversation retention to at least 18 months.'

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.GEMINI.4.1v1' -Level Shall -Title 'Gemini conversation sharing is off' -ManualOnly `
    -Guidance 'Turn off sharing of Gemini conversations.'

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.GMAIL.1.1v1' -Level Should -Title 'Mail delegation is off' `
    -Needs 'GwsPolicies' -Checks 'GMAIL-11' -Map '3.1.3.1.1' `
    -Guidance 'Untick Let users delegate access to their mailbox.' `
    -Test { Test-TRGsCtl -Type 'gmail.mail_delegation' -Ok { param($s) -not (Test-TRGwsTrue $s['enableMailDelegation']) } -Good 'mail delegation is off' -Bad 'mail delegation is on' }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.GMAIL.2.1v1' -Level Should -Title 'DKIM is on for all domains' `
    -Needs 'GwsDnsRecords' -Checks 'GDNS-03' -Map '3.1.3.2.1' `
    -Guidance 'Generate a DKIM key for every domain, publish it and start authentication.' `
    -Test {
    $rows = @(Get-TRItems 'GwsDnsRecords')
    $bad = @($rows | Where-Object { (Get-TRGwsDkimBits $_) -eq 0 })
    if ($bad.Count) { return New-TRCtl Fail ('No DKIM record for {0}: {1}.' -f (Format-TRN $bad.Count 'domain'), (Join-TRList ($bad | ForEach-Object { $_.Domain }) 5)) (@($bad | ForEach-Object { New-TRAffected $_.Domain 'No DKIM record' })) }
    New-TRCtl Pass ('DKIM is published for all {0}.' -f (Format-TRN $rows.Count 'domain'))
}

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.GMAIL.3.1v1' -Level Shall -Title 'SPF fails all unapproved senders' `
    -Needs 'GwsDnsRecords' -Checks 'GDNS-02' -Map '3.1.3.2.2' `
    -Guidance 'Publish an SPF record ending in -all for every domain.' `
    -Test {
    $rows = @(Get-TRItems 'GwsDnsRecords')
    $bad = @($rows | Where-Object { $spf = @(Get-TRStrings $_.Spf); $spf.Count -ne 1 -or ($spf[0] -notmatch '\s-all\b' -and $spf[0] -notmatch 'redirect=') })
    if ($bad.Count) { return New-TRCtl Fail ('{0} without an SPF record ending in -all: {1}.' -f (Format-TRN $bad.Count 'domain'), (Join-TRList ($bad | ForEach-Object { $_.Domain }) 5)) (@($bad | ForEach-Object { New-TRAffected $_.Domain ((@(Get-TRStrings $_.Spf)) -join ' | ') })) }
    New-TRCtl Pass ('Every one of the {0} publishes SPF with -all.' -f (Format-TRN $rows.Count 'domain'))
}

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.GMAIL.4.1v1' -Level Shall -Title 'DMARC is published for every domain' `
    -Needs 'GwsDnsRecords' -Checks 'GDNS-04' -Map '3.1.3.2.3' `
    -Guidance 'Publish a DMARC record at each domain or its parent.' `
    -Test { Test-TRGsDmarc -Ok { param($t) $true } -What 'DMARC is published' }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.GMAIL.4.2v1' -Level Shall -Title 'DMARC rejects failing mail' `
    -Needs 'GwsDnsRecords' -Checks 'GDNS-04' `
    -Guidance 'Set p=reject in each DMARC record once reports show legitimate mail passes.' `
    -Test { Test-TRGsDmarc -Ok { param($t) [string]$t['p'] -eq 'reject' } -What 'DMARC is set to reject' }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.GMAIL.4.3v1' -Level Shall -Title 'DMARC reports go to CISA' `
    -Guidance 'Applies to US federal agencies only.' `
    -Test { New-TRCtl NotApplicable 'Applies to US federal agencies only (aggregate reports to reports@dmarc.cyber.dhs.gov).' }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.GMAIL.4.4v1' -Level Should -Title 'DMARC reports go to a company contact' `
    -Needs 'GwsDnsRecords' -Checks 'GDNS-04' `
    -Guidance 'Include rua (aggregate) and ruf (failure) reporting addresses that someone monitors.' `
    -Test { Test-TRGsDmarc -Ok { param($t) [string]$t['rua'] -and [string]$t['ruf'] } -What 'DMARC aggregate and failure reports are sent' }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.GMAIL.5.1v1' -Level Shall -Title 'Encrypted attachments from untrusted senders are checked' `
    -Needs 'GwsPolicies' -Checks 'GMAIL-02' -Map '3.1.3.4.1.1' `
    -Guidance 'Turn on Protect against encrypted attachments from untrusted senders.' `
    -Test { Test-TRGsCtl -Type 'gmail.email_attachment_safety' -Ok { param($s) Test-TRGwsTrue $s['enableEncryptedAttachmentProtection'] } -Good 'encrypted attachment protection is on' -Bad 'encrypted attachment protection is off' }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.GMAIL.5.2v1' -Level Shall -Title 'Attachments with scripts from untrusted senders are checked' `
    -Needs 'GwsPolicies' -Checks 'GMAIL-02' -Map '3.1.3.4.1.2' `
    -Guidance 'Turn on Protect against attachments with scripts from untrusted senders.' `
    -Test { Test-TRGsCtl -Type 'gmail.email_attachment_safety' -Ok { param($s) Test-TRGwsTrue $s['enableAttachmentWithScriptsProtection'] } -Good 'script attachment protection is on' -Bad 'script attachment protection is off' }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.GMAIL.5.3v1' -Level Shall -Title 'Anomalous attachment types are checked' `
    -Needs 'GwsPolicies' -Checks 'GMAIL-02' -Map '3.1.3.4.1.3' `
    -Guidance 'Turn on Protect against anomalous attachment types in emails.' `
    -Test { Test-TRGsCtl -Type 'gmail.email_attachment_safety' -Ok { param($s) Test-TRGwsTrue $s['enableAnomalousAttachmentProtection'] } -Good 'anomalous attachment protection is on' -Bad 'anomalous attachment protection is off' }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.GMAIL.5.4v1' -Level Should -Title 'Future attachment protections apply automatically' `
    -Needs 'GwsPolicies' `
    -Guidance 'Tick Apply future recommended settings automatically in attachment safety.' `
    -Test { Test-TRGsCtl -Type 'gmail.email_attachment_safety' -Ok { param($s) Test-TRGwsTrue $s['applyFutureRecommendedSettingsAutomatically'] } -Good 'future recommended settings apply automatically' -Bad 'future recommended attachment settings are not applied automatically' }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.GMAIL.5.5v1' -Level Shall -Title 'Flagged attachments are not kept in the inbox' `
    -Needs 'GwsPolicies' `
    -Guidance 'Set the action for each attachment protection to Move email to spam or Quarantine.' `
    -Test { Test-TRGsCtl -Type 'gmail.email_attachment_safety' -Ok { param($s) @('encryptedAttachmentProtectionConsequence', 'attachmentWithScriptsProtectionConsequence', 'anomalousAttachmentProtectionConsequence' | Where-Object { [string]$s[$_] -notin @('SPAM_FOLDER', 'QUARANTINE') }).Count -eq 0 } -Good 'flagged attachments go to spam or quarantine' -Bad 'some flagged attachments are only warned about and stay in the inbox' }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.GMAIL.6.1v1' -Level Shall -Title 'Links behind shortened URLs are identified' `
    -Needs 'GwsPolicies' -Checks 'GMAIL-03' -Map '3.1.3.4.2.1' `
    -Guidance 'Turn on Identify links behind shortened URLs.' `
    -Test { Test-TRGsCtl -Type 'gmail.links_and_external_images' -Ok { param($s) Test-TRGwsTrue $s['enableShortenerScanning'] } -Good 'shortened URLs are scanned' -Bad 'shortened URLs are not scanned' }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.GMAIL.6.2v1' -Level Shall -Title 'Linked images are scanned' `
    -Needs 'GwsPolicies' -Checks 'GMAIL-03' -Map '3.1.3.4.2.2' `
    -Guidance 'Turn on Scan linked images.' `
    -Test { Test-TRGsCtl -Type 'gmail.links_and_external_images' -Ok { param($s) Test-TRGwsTrue $s['enableExternalImageScanning'] } -Good 'linked images are scanned' -Bad 'linked images are not scanned' }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.GMAIL.6.3v1' -Level Shall -Title 'Clicks on untrusted links show a warning' `
    -Needs 'GwsPolicies' -Checks 'GMAIL-03' -Map '3.1.3.4.2.3' `
    -Guidance 'Turn on Show warning prompt for any click on links to untrusted domains.' `
    -Test { Test-TRGsCtl -Type 'gmail.links_and_external_images' -Ok { param($s) Test-TRGwsTrue $s['enableAggressiveWarningsOnUntrustedLinks'] } -Good 'untrusted link warnings are on' -Bad 'untrusted link warnings are off' }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.GMAIL.6.4v1' -Level Shall -Title 'Future link protections apply automatically' `
    -Needs 'GwsPolicies' `
    -Guidance 'Tick Apply future recommended settings automatically for links and external images.' `
    -Test { Test-TRGsCtl -Type 'gmail.links_and_external_images' -Ok { param($s) Test-TRGwsTrue $s['applyFutureSettingsAutomatically'] } -Good 'future link settings apply automatically' -Bad 'future link settings are not applied automatically' }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.GMAIL.7.1v1' -Level Shall -Title 'Similar domain name spoofing is detected' `
    -Needs 'GwsPolicies' -Checks 'GMAIL-01' -Map '3.1.3.4.3.1' `
    -Guidance 'In Gmail, Safety, Spoofing and authentication, turn this protection on.' `
    -Test { Test-TRGsCtl -Type 'gmail.spoofing_and_authentication' -Ok { param($s) Test-TRGwsTrue $s['detectDomainNameSpoofing'] } -Good 'similar domain name spoofing is detected' -Bad 'similar domain name spoofing is not detected' }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.GMAIL.7.2v1' -Level Shall -Title 'Employee name spoofing is detected' `
    -Needs 'GwsPolicies' -Checks 'GMAIL-01' -Map '3.1.3.4.3.2' `
    -Guidance 'In Gmail, Safety, Spoofing and authentication, turn this protection on.' `
    -Test { Test-TRGsCtl -Type 'gmail.spoofing_and_authentication' -Ok { param($s) Test-TRGwsTrue $s['detectEmployeeNameSpoofing'] } -Good 'employee name spoofing is detected' -Bad 'employee name spoofing is not detected' }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.GMAIL.7.3v1' -Level Shall -Title 'Inbound spoofing of your domain is detected' `
    -Needs 'GwsPolicies' -Checks 'GMAIL-01' -Map '3.1.3.4.3.3' `
    -Guidance 'In Gmail, Safety, Spoofing and authentication, turn this protection on.' `
    -Test { Test-TRGsCtl -Type 'gmail.spoofing_and_authentication' -Ok { param($s) Test-TRGwsTrue $s['detectDomainSpoofingFromUnauthenticatedSenders'] } -Good 'inbound spoofing of your domain is detected' -Bad 'inbound spoofing of your domain is not detected' }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.GMAIL.7.4v1' -Level Shall -Title 'Unauthenticated email is detected' `
    -Needs 'GwsPolicies' -Checks 'GMAIL-01' -Map '3.1.3.4.3.4' `
    -Guidance 'In Gmail, Safety, Spoofing and authentication, turn this protection on.' `
    -Test { Test-TRGsCtl -Type 'gmail.spoofing_and_authentication' -Ok { param($s) Test-TRGwsTrue $s['detectUnauthenticatedEmails'] } -Good 'unauthenticated email is detected' -Bad 'unauthenticated email is not detected' }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.GMAIL.7.5v1' -Level Shall -Title 'Groups are protected from domain spoofing' `
    -Needs 'GwsPolicies' -Checks 'GMAIL-01' -Map '3.1.3.4.3.5' `
    -Guidance 'In Gmail, Safety, Spoofing and authentication, turn this protection on.' `
    -Test { Test-TRGsCtl -Type 'gmail.spoofing_and_authentication' -Ok { param($s) Test-TRGwsTrue $s['detectGroupsSpoofing'] } -Good 'groups are protected from domain spoofing' -Bad 'groups are not protected from domain spoofing' }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.GMAIL.7.6v1' -Level Shall -Title 'Spoofed mail is not kept in the inbox' `
    -Needs 'GwsPolicies' `
    -Guidance 'Set the action for each spoofing protection to Move email to spam or Quarantine.' `
    -Test { Test-TRGsCtl -Type 'gmail.spoofing_and_authentication' -Ok { param($s) @('domainNameSpoofingConsequence', 'employeeNameSpoofingConsequence', 'domainSpoofingConsequence', 'unauthenticatedEmailConsequence', 'groupsSpoofingConsequence' | Where-Object { [string]$s[$_] -notin @('SPAM_FOLDER', 'QUARANTINE') }).Count -eq 0 } -Good 'spoofed mail goes to spam or quarantine' -Bad 'some spoofed mail is only warned about or left in the inbox' }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.GMAIL.7.7v1' -Level Shall -Title 'Future spoofing protections apply automatically' `
    -Needs 'GwsPolicies' `
    -Guidance 'Tick Apply future recommended settings automatically for spoofing and authentication.' `
    -Test { Test-TRGsCtl -Type 'gmail.spoofing_and_authentication' -Ok { param($s) Test-TRGwsTrue $s['applyFutureSettingsAutomatically'] } -Good 'future spoofing settings apply automatically' -Bad 'future spoofing settings are not applied automatically' }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.GMAIL.8.1v1' -Level Shall -Title 'User mail import is off' `
    -Needs 'GwsPolicies' -Checks 'GMAIL-12' `
    -Guidance 'Untick Allow users to import their mail and contacts.' `
    -Test { Test-TRGsCtl -Type 'gmail.user_email_uploads' -Ok { param($s) -not (Test-TRGwsTrue $s['enableMailAndContactsImport']) } -Good 'mail import is off' -Bad 'users can import mail' }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.GMAIL.9.1v1' -Level Shall -Title 'POP and IMAP are off' `
    -Needs 'GwsPolicies' -Checks 'GMAIL-06' -Map '3.1.3.5.1' `
    -Guidance 'Turn off POP and IMAP access for all users.' `
    -Test {
    Join-TRGsEvals @(
        (Test-TRGwsPolicy -Type 'gmail.pop_access' -Ok { param($s) -not (Test-TRGwsTrue $s['enablePopAccess']) } -Good 'POP is off.' -Bad 'POP is on'),
        (Test-TRGwsPolicy -Type 'gmail.imap_access' -Ok { param($s) -not (Test-TRGwsTrue $s['enableImapAccess']) } -Good 'IMAP is off.' -Bad 'IMAP is on')
    )
}

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.GMAIL.10.1v1' -Level Should -Title 'Workspace Sync for Outlook is off' `
    -Needs 'GwsPolicies' `
    -Guidance 'Untick Enable Google Workspace Sync for Microsoft Outlook unless it is used.' `
    -Test { Test-TRGsCtl -Type 'gmail.workspace_sync_for_outlook' -Ok { param($s) -not (Test-TRGwsTrue $s['enableGoogleWorkspaceSyncForMicrosoftOutlook']) } -Good 'Workspace Sync for Outlook is off' -Bad 'Workspace Sync for Outlook is on' }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.GMAIL.11.1v1' -Level Should -Title 'Automatic forwarding is off' `
    -Needs 'GwsPolicies' -Checks 'GMAIL-05' -Map '3.1.3.5.2' `
    -Guidance 'Untick Allow users to automatically forward incoming email.' `
    -Test { Test-TRGsCtl -Type 'gmail.auto_forwarding' -Ok { param($s) -not (Test-TRGwsTrue $s['enableAutoForwarding']) } -Good 'automatic forwarding is off' -Bad 'automatic forwarding is on' }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.GMAIL.12.1v1' -Level Shall -Title 'Per-user outbound gateways are off' `
    -Needs 'GwsPolicies' -Checks 'GMAIL-07' -Map '3.1.3.5.3' `
    -Guidance 'Untick Allow per-user outbound gateways.' `
    -Test { Test-TRGsCtl -Type 'gmail.per_user_outbound_gateway' -Ok { param($s) -not (Test-TRGwsTrue $(if ($null -ne $s['allowUsersToUseExternalSmtpServers']) { $s['allowUsersToUseExternalSmtpServers'] } else { $s['enablePerUserOutboundGateway'] })) } -Good 'per-user outbound gateways are off' -Bad 'users can send through external SMTP servers' }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.GMAIL.13.1v1' -Level Shall -Title 'External reply warnings are on' `
    -Needs 'GwsPolicies' -Checks 'GMAIL-10' -Map '3.1.3.5.4' `
    -Guidance 'Turn on Warn for external recipients.' `
    -Test {
    $s = Get-TRGwsSetting 'gmail.external_recipient_warning'
    if ($s.Known -or $s.Overrides.Count) { return Test-TRGsCtl -Type 'gmail.external_recipient_warning' -Ok { param($x) Test-TRGwsTrue $x['enabled'] } -Good 'external recipient warnings are on' -Bad 'external recipient warnings are off' }
    ConvertTo-TRGwsCtl (Test-TRGwsLogSetting -Setting 'OutOfDomainWarningProto disable_untrusted_recipient_warning' -Ok { param($v) $v -eq 'false' } -Good 'External recipient warnings are on' -Bad 'external recipient warnings are off' -DefaultOk $true -DefaultText 'warnings on')
}

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.GMAIL.14.1v1' -Level Should -Title 'No email IP allowlist' `
    -Needs 'GwsPolicies' -Checks 'GMAIL-08' `
    -Guidance 'Remove IP addresses from the Gmail email allowlist.' `
    -Test { Test-TRGsCtl -Type 'gmail.email_spam_filter_ip_allowlist' -Ok { param($s) -not @(Get-TRStrings $s['allowedIpAddresses']).Count } -Good 'the email allowlist is empty' -Bad 'the email allowlist contains IP addresses' -Detail { param($s) Join-TRList (Get-TRStrings $s['allowedIpAddresses']) 5 } }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.GMAIL.15.1v1' -Level Shall -Title 'Enhanced pre-delivery scanning is on' `
    -Needs 'GwsPolicies' -Checks 'GMAIL-04' -Map '3.1.3.6.1' `
    -Guidance 'Turn on Enhanced pre-delivery message scanning.' `
    -Test { Test-TRGsCtl -Type 'gmail.enhanced_pre_delivery_message_scanning' -Ok { param($s) Test-TRGwsTrue $s['enableImprovedSuspiciousContentDetection'] } -Good 'enhanced pre-delivery scanning is on' -Bad 'enhanced pre-delivery scanning is off' }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.GMAIL.16.1v1' -Level Should -Title 'Security sandbox is on' `
    -Licence 'SecuritySandbox' -Needs 'GwsAdminEvents' `
    -Guidance 'In Gmail, Spam, phishing and malware, turn on Security sandbox.' `
    -Test { ConvertTo-TRGwsCtl (Test-TRGwsLogSetting -Setting 'AttachmentDeepScanningSettingsProto deep_scanning_enabled' -Ok { param($v) $v -eq 'true' } -Good 'Security sandbox is on' -Bad 'security sandbox is off' -DefaultOk $false -DefaultText 'off') }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.GMAIL.17.1v1' -Level Should -Title 'Comprehensive mail storage is on' `
    -Needs 'GwsPolicies' -Checks 'GMAIL-09' -Map '3.1.3.7.1' `
    -Guidance 'Turn on Comprehensive mail storage.' `
    -Test {
    $r = @((Get-TRGwsPolicyIndex)['gmail.comprehensive_mail_storage'] | Where-Object { $_ -and $_.IsRoot })
    if ($r.Count -and (Get-TRV $r[0].Value 'ruleId')) { return New-TRCtl Pass 'Comprehensive mail storage is on.' }
    New-TRCtl Fail 'Comprehensive mail storage is not on for the organisation.'
}

function Get-TRGwsSpamOverrides {
    foreach ($p in @((Get-TRGwsPolicyIndex)['gmail.spam_override_lists'])) {
        foreach ($o in @(Get-TRV $p.Value 'spamOverride')) { if ($o) { [pscustomobject]@{ Scope = $p.Scope; Rule = $o } } }
    }
}

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.GMAIL.18.1v1' -Level Shall -Title 'No domains bypass spam filters' `
    -Needs 'GwsPolicies' -Checks 'GMAIL-08' `
    -Guidance 'Remove domains from approved sender lists that bypass spam filters.' `
    -Test {
    $bad = @(Get-TRGwsSpamOverrides | Where-Object { (Test-TRGwsTrue (Get-TRV $_.Rule 'bypassSelectedSenders')) -and @(Get-TRStrings (Get-TRV $_.Rule 'bypassSenderAllowlist')).Count })
    if ($bad.Count) { return New-TRCtl Fail ('{0} spam filters for approved sender lists.' -f (Format-TRN $bad.Count 'rule bypasses' 'rules bypass')) (@($bad | ForEach-Object { New-TRAffected ($_.Scope + ': ' + [string](Get-TRV $_.Rule 'description')) 'Bypasses spam filters for approved senders' })) }
    New-TRCtl Pass 'No spam setting bypasses filters for approved sender lists.'
}

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.GMAIL.18.2v1' -Level Shall -Title 'No domains bypass spam filters and hide warnings' `
    -Needs 'GwsPolicies' -Checks 'GMAIL-08' `
    -Guidance 'Remove domains from lists that also hide spam warnings.' `
    -Test {
    $bad = @(Get-TRGwsSpamOverrides | Where-Object { (Test-TRGwsTrue (Get-TRV $_.Rule 'hideWarningBannerFromSelectedSenders')) -and @(Get-TRStrings (Get-TRV $_.Rule 'hideWarningBannerSenderAllowlist')).Count })
    if ($bad.Count) { return New-TRCtl Fail ('{0} warnings for selected senders.' -f (Format-TRN $bad.Count 'rule hides' 'rules hide')) (@($bad | ForEach-Object { New-TRAffected ($_.Scope + ': ' + [string](Get-TRV $_.Rule 'description')) 'Hides warnings' })) }
    New-TRCtl Pass 'No spam setting hides warnings for selected senders.'
}

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.GMAIL.18.3v1' -Level Shall -Title 'Spam filters are not bypassed for all senders' `
    -Needs 'GwsPolicies' -Checks 'GMAIL-08' -Map '3.1.3.6.2' `
    -Guidance 'Untick Bypass spam filters and hide warnings for all messages from internal and external senders.' `
    -Test {
    $bad = @(Get-TRGwsSpamOverrides | Where-Object { (Test-TRGwsTrue (Get-TRV $_.Rule 'hideWarningBannerForAll')) -or (Test-TRGwsTrue (Get-TRV $_.Rule 'bypassInternalSenders')) })
    if ($bad.Count) { return New-TRCtl Fail ('{0} spam filtering for internal senders or all senders.' -f (Format-TRN $bad.Count 'rule bypasses' 'rules bypass')) (@($bad | ForEach-Object { New-TRAffected ($_.Scope + ': ' + [string](Get-TRV $_.Rule 'description')) $(if (Test-TRGwsTrue (Get-TRV $_.Rule 'hideWarningBannerForAll')) { 'Hides warnings for all senders' } else { 'Bypasses internal senders' }) })) }
    New-TRCtl Pass 'Spam filters are not bypassed for internal or all senders.'
}

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.GROUPS.1.1v1' -Level Shall -Title 'Groups are private to the organisation' `
    -Needs 'GwsPolicies' -Checks 'GCOL-04' -Map '3.1.6.1' `
    -Guidance 'Set Accessing groups from outside this organisation to Private.' `
    -Test { Test-TRGsCtl -Type 'groups_for_business.groups_sharing' -Ok { param($s) [string]$s['collaborationCapability'] -eq 'DOMAIN_USERS_ONLY' } -Good 'groups are private to the organisation' -Bad 'groups can be accessed from outside' }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.GROUPS.1.2v1' -Level Should -Title 'Owners cannot add external members' `
    -Needs 'GwsPolicies' -Checks 'GCOL-04', 'GCOL-06' `
    -Guidance 'Untick Group owners can allow external members.' `
    -Test { Test-TRGsCtl -Type 'groups_for_business.groups_sharing' -Ok { param($s) -not (Test-TRGwsTrue $s['ownersCanAllowExternalMembers']) } -Good 'owners cannot add external members' -Bad 'group owners can add external members' }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.GROUPS.1.3v1' -Level Should -Title 'Owners cannot let outsiders post' `
    -Needs 'GwsPolicies' -Checks 'GCOL-05' `
    -Guidance 'Untick Group owners can allow incoming email from outside the organisation.' `
    -Test { Test-TRGsCtl -Type 'groups_for_business.groups_sharing' -Ok { param($s) -not (Test-TRGwsTrue $s['ownersCanAllowIncomingMailFromPublic']) } -Good 'owners cannot accept mail from outside' -Bad 'group owners can accept email from outside the organisation' }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.GROUPS.2.1v1' -Level Should -Title 'Only admins create groups' `
    -Needs 'GwsPolicies' -Checks 'GCOL-04' -Map '3.1.6.2' `
    -Guidance 'Set Creating groups to Only organisation admins can create groups.' `
    -Test { Test-TRGsCtl -Type 'groups_for_business.groups_sharing' -Ok { param($s) [string]$s['createGroupsAccessLevel'] -eq 'ADMIN_ONLY' } -Good 'only admins can create groups' -Bad 'users can create groups' -Detail { param($s) [string]$s['createGroupsAccessLevel'] } }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.GROUPS.3.1v1' -Level Should -Title 'Conversations are visible to group members by default' `
    -Needs 'GwsPolicies' -Map '3.1.6.3' `
    -Guidance 'Set Default for permission to view conversations to All group members.' `
    -Test { Test-TRGsCtl -Type 'groups_for_business.groups_sharing' -Ok { param($s) [string]$s['viewTopicsDefaultAccessLevel'] -eq 'GROUP_MEMBERS' } -Good 'conversations are visible to members by default' -Bad 'conversations are visible more widely by default' -Detail { param($s) [string]$s['viewTopicsDefaultAccessLevel'] } }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.GROUPS.4.1v1' -Level Shall -Title 'Groups cannot be hidden from the directory' `
    -Needs 'GwsPolicies' `
    -Guidance 'Untick Group owners can hide groups from the directory and make sure new groups are not hidden.' `
    -Test { Test-TRGsCtl -Type 'groups_for_business.groups_sharing' -Ok { param($s) -not (Test-TRGwsTrue $s['ownersCanHideGroups']) -and -not (Test-TRGwsTrue $s['newGroupsAreHidden']) } -Good 'groups cannot be hidden' -Bad 'groups can be hidden from the directory' }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.MEET.1.1v1' -Level Shall -Title 'Uninvited external people must ask to join' `
    -Needs 'GwsPolicies' -Checks 'GCOL-03' `
    -Guidance 'In Meet safety settings, set who can join to require people outside the organisation to ask.' `
    -Test { Test-TRGsCtl -Type 'meet.meet_joining' -Ok { param($s) [string]$s['allowedAudience'] -in @('TRUSTED', 'RESTRICTED') } -Good 'external people must ask to join' -Bad 'people can join without knocking' -Detail { param($s) [string]$s['allowedAudience'] } }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.MEET.2.1v1' -Level Shall -Title 'Users cannot join meetings from personal accounts' `
    -Needs 'GwsPolicies' `
    -Guidance 'Set Meetings users can join to Meetings created by Google Workspace users.' `
    -Test { Test-TRGsCtl -Type 'meet.safety_access' -Ok { param($s) [string]$s['meetingsAllowedToJoin'] -ne 'ALL' } -Good 'users join only Workspace meetings' -Bad 'users can join meetings created by personal accounts' -Detail { param($s) [string]$s['meetingsAllowedToJoin'] } }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.MEET.3.1v1' -Level Shall -Title 'Host management is on' `
    -Needs 'GwsPolicies' -Checks 'GCOL-03' `
    -Guidance 'Turn on Host management.' `
    -Test { Test-TRGsCtl -Type 'meet.safety_host_management' -Ok { param($s) Test-TRGwsTrue $s['enableHostManagement'] } -Good 'host management is on' -Bad 'host management is off' }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.MEET.4.1v1' -Level Shall -Title 'External participants are labelled' `
    -Needs 'GwsPolicies' -Checks 'GCOL-03' `
    -Guidance 'Turn on Warn for external participants.' `
    -Test { Test-TRGsCtl -Type 'meet.safety_external_participants' -Ok { param($s) Test-TRGwsTrue $s['enableExternalLabel'] } -Good 'external participants are labelled' -Bad 'external participants are not labelled' }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.MEET.5.1v1' -Level Shall -Title 'Automatic recording is off' `
    -Needs 'GwsPolicies' `
    -Guidance 'Turn off automatic recording.' `
    -Test {
    $s = Get-TRGwsSetting 'meet.automatic_recording'
    if (-not $s.Known -and -not $s.Overrides.Count) { return New-TRCtl Pass 'Automatic recording is not turned on.' }
    Test-TRGsCtl -Type 'meet.automatic_recording' -Ok { param($x) -not (Test-TRGwsTrue $x['enabled']) } -Good 'automatic recording is off' -Bad 'automatic recording is on'
}

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.MEET.5.2v1' -Level Shall -Title 'Automatic transcripts are off' `
    -Needs 'GwsPolicies' `
    -Guidance 'Turn off automatic transcription.' `
    -Test {
    $s = Get-TRGwsSetting 'meet.automatic_transcription'
    if (-not $s.Known -and -not $s.Overrides.Count) { return New-TRCtl Pass 'Automatic transcription is not turned on.' }
    Test-TRGsCtl -Type 'meet.automatic_transcription' -Ok { param($x) -not (Test-TRGwsTrue $x['enabled']) } -Good 'automatic transcription is off' -Bad 'automatic transcription is on'
}

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.MEET.6.1v1' -Level Should -Title 'Hosts cannot change AI notes sharing' `
    -Needs 'GwsAdminEvents' `
    -Guidance 'In Meet, Gemini note taking, stop hosts changing who notes are shared with.' `
    -Test { ConvertTo-TRGwsCtl (Test-TRGwsLogSetting -Setting 'MeetGenAiSmartNotesDocAccessProto manage_smart_notes_doc_access' -Ok { param($v) $v -ne 'true' } -Good 'Hosts cannot change AI notes sharing' -Bad 'hosts can change who AI notes are shared with' -DefaultOk $true -DefaultText 'hosts cannot change it') }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.MEET.6.2v1' -Level Shall -Title 'AI notes are shared only inside the organisation' `
    -Needs 'GwsAdminEvents' `
    -Guidance 'Set the default sharing for Google AI notes to Guests in your organisation.' `
    -Test { ConvertTo-TRGwsCtl (Test-TRGwsLogSetting -Setting 'MeetGenAiSmartNotesDocAccessProto default_smart_notes_doc_access' -Ok { param($v) $v -ne 'EVERYONE' } -Good 'AI notes are shared inside the organisation by default' -Bad 'AI notes are shared with all invited guests by default' -DefaultOk $true -DefaultText 'organisation only') }

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.MEET.6.3v1' -Level Shall -Title 'Screenshots go into notes only when recording' -ManualOnly `
    -Guidance 'In Meet, Gemini note taking, capture presented content in notes only when the meeting is recorded.'

Register-TRControl -Platform Google -Framework SCuBA -Id 'GWS.SITES.1.1v1' -Level Should -Title 'Google Sites is off' `
    -Needs 'GwsPolicies' -Checks 'GCOL-08' -Map '3.1.7.1' `
    -Guidance 'Turn Sites off for everyone unless it is used; if it is, allow it only for the teams that need it.' `
    -Test { Test-TRGsService -Service 'sites' -Want 'DISABLED' -Name 'Google Sites' }
