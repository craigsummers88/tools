function Test-TRGwsAlertRuleCtl {
    param([string]$Name)
    $min = $script:TRGwsCisAlertRules[$Name]
    $rank = @{ LOW = 1; MEDIUM = 2; HIGH = 3 }
    $r = @(Get-TRGwsRules 'rule.system_defined_alerts' | Where-Object { ([string](Get-TRV $_ 'displayName')) -ieq $Name })[0]
    if (-not $r) { return New-TRCtl Manual ('The "{0}" rule was not returned by the Policy API. Check it is on, emails all super admins and has {1} severity or higher.' -f $Name, $min.ToLower()) }
    $issues = @()
    if ([string](Get-TRV $r 'state') -ne 'ACTIVE') { $issues += 'the rule is off' }
    $cfg = Get-TRPath $r 'action.alertCenterAction.alertCenterConfig'
    if ([string](Get-TRV $cfg 'status') -eq 'DISABLED') { $issues += 'alerts are not sent to the Alert Center' }
    $rec = @(@(Get-TRPath $r 'action.alertCenterAction.recipients') | Where-Object { $_ })
    if (-not $rec.Count) { $issues += 'no email notifications' }
    elseif (-not @($rec | Where-Object { Test-TRGwsTrue (Get-TRV $_ 'allSuperAdmins') }).Count) { $issues += 'emails do not go to all super admins' }
    $sev = [string](Get-TRV $cfg 'severity')
    if ($sev -and $rank[$sev] -and $rank[$sev] -lt $rank[$min]) { $issues += ('severity {0} (should be {1} or higher)' -f $sev.ToLower(), $min.ToLower()) }
    if ($issues.Count) { return New-TRCtl Fail ('"{0}": {1}.' -f $Name, ($issues -join '; ')) }
    New-TRCtl Pass ('"{0}" is on and emails all super admins.' -f $Name)
}

function Test-TRGwsCisPassword {
    $e = Test-TRGwsPolicy -Type 'security.password' -Ok { param($s) $x = ConvertTo-TRGwsSeconds $s['expirationDuration']; [int]$s['minimumLength'] -ge 14 -and ([string]$s['allowedStrength'] -in @('STRONG', '')) -and -not (Test-TRGwsTrue $s['allowReuse']) -and (Test-TRGwsTrue $s['enforceRequirementsAtLogin']) -and $x -and $x -gt 0 -and $x -le 31536000 } `
        -Good 'the password policy meets the benchmark' -Bad 'the password policy does not meet the benchmark' `
        -Detail { param($s) $g = @(); if ([int]$s['minimumLength'] -lt 14) { $g += 'minimum length ' + [string]$s['minimumLength'] + ' (needs 14)' }; if ([string]$s['allowedStrength'] -and [string]$s['allowedStrength'] -ne 'STRONG') { $g += 'weak passwords allowed' }; if (Test-TRGwsTrue $s['allowReuse']) { $g += 'reuse allowed' }; if (-not (Test-TRGwsTrue $s['enforceRequirementsAtLogin'])) { $g += 'not enforced at next sign-in' }; $x = ConvertTo-TRGwsSeconds $s['expirationDuration']; if (-not $x) { $g += 'passwords never expire (CIS asks for 365 days or less)' } elseif ($x -gt 31536000) { $g += 'expiry longer than 365 days' }; $g -join '; ' }
    ConvertTo-TRGwsCtl $e
}

Register-TRControl -Platform Google -Framework CIS -Id '1.1.1' -Level L1 -Title 'Two to four super admins' `
    -Needs 'GwsUsers' -Checks 'GPRV-01' -Map 'GWS.COMMONCONTROLS.6.2v1' `
    -Guidance 'Keep at least two and no more than four super admin accounts, and use narrower admin roles for everyday tasks.' `
    -Test {
    $sa = @(Get-TRGwsSuperAdmins)
    $t = '{0}: {1}.' -f (Format-TRN $sa.Count 'super admin'), (Join-TRList ($sa | ForEach-Object { $_.primaryEmail }) 6)
    if ($sa.Count -ge 2 -and $sa.Count -le 4) { return New-TRCtl Pass $t }
    New-TRCtl Fail $t (@($sa | ForEach-Object { New-TRAffected ([string]$_.primaryEmail) 'Super admin' }))
}

Register-TRControl -Platform Google -Framework CIS -Id '1.1.2' -Level L1 -Title 'Super admin accounts are used only for administration' `
    -Needs 'GwsUsers', 'GwsUserUsage' -Checks 'GPRV-03' `
    -Guidance 'Give administrators a separate admin-only account and do not use super admin accounts for email or browsing.' `
    -Test {
    $usage = Get-TRGwsUsage
    $bad = @(Get-TRGwsSuperAdmins | Where-Object { $x = $usage[([string]$_.primaryEmail).ToLower()]; $x -and [long]$x.gmail_num_emails_sent -gt 0 })
    if ($bad.Count) { return New-TRCtl Fail ('{0} sent email on the report day, so {1} to be used day to day.' -f (Format-TRN $bad.Count 'super admin'), (Select-TRText $bad.Count 'appears' 'appear')) (@($bad | ForEach-Object { New-TRAffected ([string]$_.primaryEmail) 'Sent email' })) }
    New-TRCtl Manual 'No super admin sent email on the report day. Confirm with the client that these accounts are used only for administration.'
}

Register-TRControl -Platform Google -Framework CIS -Id '1.2.1.1' -Level L1 -Title 'Directory data is not shared externally' `
    -Needs 'GwsPolicies' `
    -Guidance 'In Directory, Directory settings, External directory sharing, do not share domain profile data with external users.' `
    -Test {
    $s = Get-TRGwsSetting 'directory.external_directory_sharing'
    if (-not $s.Known -and -not $s.Overrides.Count) { return New-TRCtl Manual 'The external directory sharing setting was not returned. Check it in Directory settings.' }
    Test-TRGsCtl -Type 'directory.external_directory_sharing' -Ok { param($x) [string]$x['sharingOption'] -ne 'ORGANIZATION_DIRECTORY_DATA' } -Good 'domain directory data is not shared externally' -Bad 'domain directory data is shared with external users'
}

Register-TRControl -Platform Google -Framework CIS -Id '3.1.1.1.1' -Level L1 -Title 'Primary calendars share only free/busy externally' `
    -Needs 'GwsPolicies' -Checks 'GCOL-01' -Map 'GWS.CALENDAR.1.1v1' `
    -Guidance 'Set External sharing options for primary calendars to Only free/busy information (hide event details).' `
    -Test { Test-TRGsCtl -Type 'calendar.primary_calendar_max_allowed_external_sharing' -Ok { param($s) [string]$s['maxAllowedExternalSharing'] -eq 'EXTERNAL_FREE_BUSY_ONLY' } -Good 'primary calendars share only free/busy externally' -Bad 'primary calendars can share event details externally' }

Register-TRControl -Platform Google -Framework CIS -Id '3.1.1.1.2' -Level L2 -Title 'Internal sharing of primary calendars is limited' -ManualOnly `
    -Guidance 'Set Internal sharing options for primary calendars to Only free/busy information unless staff need to see each other''s event details.'

Register-TRControl -Platform Google -Framework CIS -Id '3.1.1.1.3' -Level L1 -Title 'Users are warned when inviting external guests' `
    -Needs 'GwsPolicies' -Map 'GWS.CALENDAR.2.1v1' `
    -Guidance 'Turn on External invitations warning in Calendar sharing settings.' `
    -Test { Test-TRGsCtl -Type 'calendar.external_invitations' -Ok { param($s) Test-TRGwsTrue $s['warnOnInvite'] } -Good 'external invitation warnings are on' -Bad 'external invitation warnings are off' }

Register-TRControl -Platform Google -Framework CIS -Id '3.1.1.2.1' -Level L1 -Title 'Secondary calendars share only free/busy externally' `
    -Needs 'GwsPolicies' -Map 'GWS.CALENDAR.1.2v1' `
    -Guidance 'Set External sharing options for secondary calendars to Only free/busy information (hide event details).' `
    -Test { Test-TRGsCtl -Type 'calendar.secondary_calendar_max_allowed_external_sharing' -Ok { param($s) [string]$s['maxAllowedExternalSharing'] -eq 'EXTERNAL_FREE_BUSY_ONLY' } -Good 'secondary calendars share only free/busy externally' -Bad 'secondary calendars can share event details externally' }

Register-TRControl -Platform Google -Framework CIS -Id '3.1.1.2.2' -Level L2 -Title 'Internal sharing of secondary calendars is limited' -ManualOnly `
    -Guidance 'Set Internal sharing options for secondary calendars to Only free/busy information where appropriate.'

Register-TRControl -Platform Google -Framework CIS -Id '3.1.1.3.1' -Level L2 -Title 'Calendar offline access is off' -ManualOnly `
    -Guidance 'In Calendar, Advanced settings, turn off Calendar web offline.'

Register-TRControl -Platform Google -Framework CIS -Id '3.1.2.1.1.1' -Level L1 -Title 'Users are warned when sharing files outside' `
    -Needs 'GwsPolicies' -Checks 'GDRV-01' -Map 'GWS.DRIVEDOCS.1.3v1' `
    -Guidance 'Tick Warn when files owned by users or shared drives are shared outside the organisation.' `
    -Test { Test-TRGsCtl -Type 'drive_and_docs.external_sharing' -Ok { param($s) switch ([string]$s['externalSharingMode']) { 'ALLOWLISTED_DOMAINS' { Test-TRGwsTrue $s['warnForSharingOutsideAllowlistedDomains'] } 'ALLOWED' { Test-TRGwsTrue $s['warnForExternalSharing'] } default { $true } } } -Good 'users are warned when sharing outside' -Bad 'users are not warned when sharing outside' }

Register-TRControl -Platform Google -Framework CIS -Id '3.1.2.1.1.2' -Level L1 -Title 'Files cannot be published to the web' `
    -Needs 'GwsPolicies' -Checks 'GDRV-02' -Map 'GWS.DRIVEDOCS.1.5v1' `
    -Guidance 'Untick allowing users to publish files on the web or make them visible to the world as public or unlisted.' `
    -Test { Test-TRGsCtl -Type 'drive_and_docs.external_sharing' -Ok { param($s) [string]$s['externalSharingMode'] -eq 'DISALLOWED' -or -not (Test-TRGwsTrue $s['allowPublishingFiles']) } -Good 'publishing to the web is off' -Bad 'files can be published to the web' }

Register-TRControl -Platform Google -Framework CIS -Id '3.1.2.1.1.3' -Level L2 -Title 'Sharing is limited to allowlisted domains' `
    -Needs 'GwsPolicies' -Checks 'GDRV-01' -Map 'GWS.DRIVEDOCS.1.1v1' `
    -Guidance 'Set Sharing outside of the organisation to Allowlisted domains.' `
    -Test { Test-TRGsCtl -Type 'drive_and_docs.external_sharing' -Ok { param($s) [string]$s['externalSharingMode'] -in @('ALLOWLISTED_DOMAINS', 'DISALLOWED') } -Good 'sharing is limited to allowlisted domains' -Bad 'files can be shared with any domain' -Detail { param($s) 'Mode ' + [string]$s['externalSharingMode'] } }

Register-TRControl -Platform Google -Framework CIS -Id '3.1.2.1.1.4' -Level L2 -Title 'Users are warned when sharing with allowlisted domains' `
    -Needs 'GwsPolicies' -Map 'GWS.DRIVEDOCS.1.3v1' `
    -Guidance 'With sharing limited to allowlisted domains, tick the warning when files are shared with users in allowlisted domains.' `
    -Test { Test-TRGsCtl -Type 'drive_and_docs.external_sharing' -Ok { param($s) [string]$s['externalSharingMode'] -eq 'ALLOWLISTED_DOMAINS' -and (Test-TRGwsTrue $s['warnForSharingOutsideAllowlistedDomains']) } -Good 'users are warned when sharing with allowlisted domains' -Bad 'sharing is not limited to allowlisted domains with a warning' }

Register-TRControl -Platform Google -Framework CIS -Id '3.1.2.1.1.5' -Level L1 -Title 'Access checker suggests recipients only' `
    -Needs 'GwsPolicies' -Checks 'GDRV-04' -Map 'GWS.DRIVEDOCS.1.6v1' `
    -Guidance 'Set Access checker to Recipients only.' `
    -Test { Test-TRGsCtl -Type 'drive_and_docs.external_sharing' -Ok { param($s) [string]$s['accessCheckerSuggestions'] -eq 'RECIPIENTS_ONLY' } -Good 'access checker suggests recipients only' -Bad 'access checker can suggest wider sharing' }

Register-TRControl -Platform Google -Framework CIS -Id '3.1.2.1.1.6' -Level L1 -Title 'Only internal users can move content outside' `
    -Needs 'GwsPolicies' -Map 'GWS.DRIVEDOCS.1.7v1' `
    -Guidance 'Set Distributing content outside of the organisation to Only users in the organisation (or No one).' `
    -Test { Test-TRGsCtl -Type 'drive_and_docs.external_sharing' -Ok { param($s) [string]$s['allowedPartiesForDistributingContent'] -in @('ELIGIBLE_INTERNAL_USERS', 'NONE') } -Good 'only internal users can move content to external shared drives' -Bad 'anyone, including external users, can move content outside' }

Register-TRControl -Platform Google -Framework CIS -Id '3.1.2.1.2.1' -Level L1 -Title 'Shared drive creation has been reviewed' `
    -Needs 'GwsPolicies' `
    -Guidance 'Decide with the client whether users may create shared drives, and set Shared drive creation to match.' `
    -Test {
    $s = Get-TRGwsSetting 'drive_and_docs.shared_drive_creation'
    if (-not $s.Known) { return New-TRCtl Manual 'The shared drive creation setting was not returned. Review it in Drive and Docs, Sharing settings.' }
    New-TRCtl Manual ('Shared drive settings: managers can override {0}; non-members can be added {1}; external users allowed {2}. Confirm who should be able to create shared drives.' -f $(if (Test-TRGwsTrue $s.Root['allowManagersToOverrideSettings']) { 'yes' } else { 'no' }), $(if (Test-TRGwsTrue $s.Root['allowNonMemberAccess']) { 'yes' } else { 'no' }), $(if (Test-TRGwsTrue $s.Root['allowExternalUserAccess']) { 'yes' } else { 'no' }))
}

Register-TRControl -Platform Google -Framework CIS -Id '3.1.2.1.2.2' -Level L1 -Title 'Shared drive managers cannot change the settings' `
    -Needs 'GwsPolicies' -Checks 'GDRV-05' -Map 'GWS.DRIVEDOCS.2.1v1' `
    -Guidance 'Untick Allow members with manager access to override the settings below.' `
    -Test { Test-TRGsCtl -Type 'drive_and_docs.shared_drive_creation' -Ok { param($s) -not (Test-TRGwsTrue $s['allowManagersToOverrideSettings']) } -Good 'managers cannot override shared drive settings' -Bad 'shared drive managers can override the settings' }

Register-TRControl -Platform Google -Framework CIS -Id '3.1.2.1.2.3' -Level L1 -Title 'Shared drive files are available to members only' `
    -Needs 'GwsPolicies' -Checks 'GDRV-05' `
    -Guidance 'Untick Allow people who aren''t shared drive members to be added to files. Note that CISA SCuBA recommends the opposite (GWS.DRIVEDOCS.2.2).' `
    -Test { Test-TRGsCtl -Type 'drive_and_docs.shared_drive_creation' -Ok { param($s) -not (Test-TRGwsTrue $s['allowNonMemberAccess']) } -Good 'only members can access shared drive files' -Bad 'non-members can be added to shared drive files' }

Register-TRControl -Platform Google -Framework CIS -Id '3.1.2.1.2.4' -Level L2 -Title 'Viewers and commenters cannot download, print or copy' `
    -Needs 'GwsPolicies' `
    -Guidance 'Set Download, print and copy to Editors only or Managers only for shared drives.' `
    -Test { Test-TRGsCtl -Type 'drive_and_docs.shared_drive_creation' -Ok { param($s) [string]$s['allowedPartiesForDownloadPrintCopy'] -in @('EDITORS_ONLY', 'MANAGERS_ONLY') } -Good 'download, print and copy is limited' -Bad 'everyone, including viewers, can download, print and copy' }

Register-TRControl -Platform Google -Framework CIS -Id '3.1.2.2.1' -Level L1 -Title 'Offline access to documents is off' -ManualOnly `
    -Guidance 'In Drive and Docs, Features and applications, Offline, untick Allow users to enable offline access, or control it through device management.'

Register-TRControl -Platform Google -Framework CIS -Id '3.1.2.3.1' -Level L1 -Title 'Drive for desktop is off' `
    -Needs 'GwsPolicies' -Checks 'GDRV-06' -Map 'GWS.DRIVEDOCS.5.1v1' `
    -Guidance 'Untick Allow Google Drive for desktop in your organisation, or limit it to authorised devices if it is needed.' `
    -Test { Test-TRGsCtl -Type 'drive_and_docs.drive_for_desktop' -Ok { param($s) -not (Test-TRGwsTrue $s['allowDriveForDesktop']) } -Good 'Drive for desktop is off' -Bad 'Drive for desktop is allowed' -Detail { param($s) if (Test-TRGwsTrue $s['restrictToAuthorizedDevices']) { 'Allowed on authorised devices only' } else { 'Allowed on any device' } } }

Register-TRControl -Platform Google -Framework CIS -Id '3.1.3.1.1' -Level L1 -Title 'Users cannot delegate their mailbox' `
    -Needs 'GwsPolicies' -Checks 'GMAIL-11' -Map 'GWS.GMAIL.1.1v1' `
    -Guidance 'Untick Let users delegate access to their mailbox to other users in the domain.' `
    -Test { Test-TRGsCtl -Type 'gmail.mail_delegation' -Ok { param($s) -not (Test-TRGwsTrue $s['enableMailDelegation']) } -Good 'mail delegation is off' -Bad 'mail delegation is on' }

Register-TRControl -Platform Google -Framework CIS -Id '3.1.3.1.2' -Level L1 -Title 'Gmail offline access is off' `
    -Needs 'GwsPolicies' `
    -Guidance 'Untick Enable Gmail web offline.' `
    -Test {
    $s = Get-TRGwsSetting 'gmail.web_offline'
    if (-not $s.Known -and -not $s.Overrides.Count) { return New-TRCtl Manual 'The Gmail offline setting was not returned. Check Gmail, User settings, Gmail web offline.' }
    Test-TRGsCtl -Type 'gmail.web_offline' -Ok { param($x) -not (Test-TRGwsTrue $x['enabled']) } -Good 'Gmail offline is off' -Bad 'Gmail offline is on'
}

Register-TRControl -Platform Google -Framework CIS -Id '3.1.3.2.1' -Level L1 -Title 'DKIM is on for all mail domains' `
    -Needs 'GwsDnsRecords' -Checks 'GDNS-03' -Map 'GWS.GMAIL.2.1v1' `
    -Guidance 'Generate a DKIM key for each mail domain, publish it and start authentication.' `
    -Test {
    $rows = @(Get-TRItems 'GwsDnsRecords' | Where-Object { (Test-TRGoogleMx $_) -ne 'None' -or $_.IsPrimary })
    $bad = @($rows | Where-Object { (Get-TRGwsDkimBits $_) -eq 0 })
    if ($bad.Count) { return New-TRCtl Fail ('No DKIM record for {0}.' -f (Join-TRList ($bad | ForEach-Object { $_.Domain }) 5)) (@($bad | ForEach-Object { New-TRAffected $_.Domain 'No DKIM record' })) }
    New-TRCtl Pass ('DKIM is published for all {0}.' -f (Format-TRN $rows.Count 'mail domain'))
}

Register-TRControl -Platform Google -Framework CIS -Id '3.1.3.2.2' -Level L1 -Title 'SPF is published for all mail domains' `
    -Needs 'GwsDnsRecords' -Checks 'GDNS-02' -Map 'GWS.GMAIL.3.1v1' `
    -Guidance 'Publish an SPF record that includes Google for each mail domain.' `
    -Test {
    $rows = @(Get-TRItems 'GwsDnsRecords' | Where-Object { (Test-TRGoogleMx $_) -ne 'None' -or $_.IsPrimary })
    $bad = @($rows | Where-Object { Test-TRSpfOk $_ })
    if ($bad.Count) { return New-TRCtl Fail ('SPF problems on {0}.' -f (Join-TRList ($bad | ForEach-Object { $_.Domain }) 5)) (@($bad | ForEach-Object { New-TRAffected $_.Domain (Test-TRSpfOk $_) })) }
    New-TRCtl Pass ('SPF is published for {0}.' -f $(if ($rows.Count -eq 1) { 'the mail domain' } elseif ($rows.Count -eq 2) { 'both mail domains' } else { 'all {0} mail domains' -f $rows.Count }))
}

Register-TRControl -Platform Google -Framework CIS -Id '3.1.3.2.3' -Level L1 -Title 'DMARC is published for all mail domains' `
    -Needs 'GwsDnsRecords' -Checks 'GDNS-04' -Map 'GWS.GMAIL.4.1v1' `
    -Guidance 'Publish a DMARC record with a reporting address for each mail domain and move towards quarantine or reject.' `
    -Test { Test-TRGsDmarc -Ok { param($t) [string]$t['p'] -in @('quarantine', 'reject') -and [string]$t['rua'] } -What 'DMARC is published with quarantine or reject and reporting' }

Register-TRControl -Platform Google -Framework CIS -Id '3.1.3.3.1' -Level L1 -Title 'Admins are notified of quarantined mail' -ManualOnly `
    -Guidance 'In Gmail, Manage quarantines, turn on Notify periodically when messages are quarantined for each quarantine.'

Register-TRControl -Platform Google -Framework CIS -Id '3.1.3.4.1.1' -Level L1 -Title 'Encrypted attachments from untrusted senders are checked' `
    -Needs 'GwsPolicies' -Checks 'GMAIL-02' -Map 'GWS.GMAIL.5.1v1' `
    -Guidance 'Turn on Protect against encrypted attachments from untrusted senders.' `
    -Test { Test-TRGsCtl -Type 'gmail.email_attachment_safety' -Ok { param($s) Test-TRGwsTrue $s['enableEncryptedAttachmentProtection'] } -Good 'encrypted attachment protection is on' -Bad 'encrypted attachment protection is off' }

Register-TRControl -Platform Google -Framework CIS -Id '3.1.3.4.1.2' -Level L1 -Title 'Attachments with scripts are checked' `
    -Needs 'GwsPolicies' -Checks 'GMAIL-02' -Map 'GWS.GMAIL.5.2v1' `
    -Guidance 'Turn on Protect against attachments with scripts from untrusted senders.' `
    -Test { Test-TRGsCtl -Type 'gmail.email_attachment_safety' -Ok { param($s) Test-TRGwsTrue $s['enableAttachmentWithScriptsProtection'] } -Good 'script attachment protection is on' -Bad 'script attachment protection is off' }

Register-TRControl -Platform Google -Framework CIS -Id '3.1.3.4.1.3' -Level L1 -Title 'Anomalous attachment types are checked' `
    -Needs 'GwsPolicies' -Checks 'GMAIL-02' -Map 'GWS.GMAIL.5.3v1' `
    -Guidance 'Turn on Protect against anomalous attachment types in emails.' `
    -Test { Test-TRGsCtl -Type 'gmail.email_attachment_safety' -Ok { param($s) Test-TRGwsTrue $s['enableAnomalousAttachmentProtection'] } -Good 'anomalous attachment protection is on' -Bad 'anomalous attachment protection is off' }

Register-TRControl -Platform Google -Framework CIS -Id '3.1.3.4.2.1' -Level L1 -Title 'Links behind shortened URLs are identified' `
    -Needs 'GwsPolicies' -Checks 'GMAIL-03' -Map 'GWS.GMAIL.6.1v1' `
    -Guidance 'Turn on Identify links behind shortened URLs.' `
    -Test { Test-TRGsCtl -Type 'gmail.links_and_external_images' -Ok { param($s) Test-TRGwsTrue $s['enableShortenerScanning'] } -Good 'shortened URLs are scanned' -Bad 'shortened URLs are not scanned' }

Register-TRControl -Platform Google -Framework CIS -Id '3.1.3.4.2.2' -Level L1 -Title 'Linked images are scanned' `
    -Needs 'GwsPolicies' -Checks 'GMAIL-03' -Map 'GWS.GMAIL.6.2v1' `
    -Guidance 'Turn on Scan linked images.' `
    -Test { Test-TRGsCtl -Type 'gmail.links_and_external_images' -Ok { param($s) Test-TRGwsTrue $s['enableExternalImageScanning'] } -Good 'linked images are scanned' -Bad 'linked images are not scanned' }

Register-TRControl -Platform Google -Framework CIS -Id '3.1.3.4.2.3' -Level L1 -Title 'Clicks on untrusted links show a warning' `
    -Needs 'GwsPolicies' -Checks 'GMAIL-03' -Map 'GWS.GMAIL.6.3v1' `
    -Guidance 'Turn on Show warning prompt for any click on links to untrusted domains.' `
    -Test { Test-TRGsCtl -Type 'gmail.links_and_external_images' -Ok { param($s) Test-TRGwsTrue $s['enableAggressiveWarningsOnUntrustedLinks'] } -Good 'untrusted link warnings are on' -Bad 'untrusted link warnings are off' }

Register-TRControl -Platform Google -Framework CIS -Id '3.1.3.4.3.1' -Level L1 -Title 'Similar domain name spoofing is detected' `
    -Needs 'GwsPolicies' -Checks 'GMAIL-01' -Map 'GWS.GMAIL.7.1v1' `
    -Guidance 'Turn on Protect against domain spoofing based on similar domain names.' `
    -Test { Test-TRGsCtl -Type 'gmail.spoofing_and_authentication' -Ok { param($s) Test-TRGwsTrue $s['detectDomainNameSpoofing'] } -Good 'similar domain spoofing protection is on' -Bad 'similar domain spoofing protection is off' }

Register-TRControl -Platform Google -Framework CIS -Id '3.1.3.4.3.2' -Level L1 -Title 'Employee name spoofing is detected' `
    -Needs 'GwsPolicies' -Checks 'GMAIL-01' -Map 'GWS.GMAIL.7.2v1' `
    -Guidance 'Turn on Protect against spoofing of employee names.' `
    -Test { Test-TRGsCtl -Type 'gmail.spoofing_and_authentication' -Ok { param($s) Test-TRGwsTrue $s['detectEmployeeNameSpoofing'] } -Good 'employee name spoofing protection is on' -Bad 'employee name spoofing protection is off' }

Register-TRControl -Platform Google -Framework CIS -Id '3.1.3.4.3.3' -Level L1 -Title 'Inbound spoofing of your domain is detected' `
    -Needs 'GwsPolicies' -Checks 'GMAIL-01' -Map 'GWS.GMAIL.7.3v1' `
    -Guidance 'Turn on Protect against inbound emails spoofing your domain.' `
    -Test { Test-TRGsCtl -Type 'gmail.spoofing_and_authentication' -Ok { param($s) Test-TRGwsTrue $s['detectDomainSpoofingFromUnauthenticatedSenders'] } -Good 'inbound domain spoofing protection is on' -Bad 'inbound domain spoofing protection is off' }

Register-TRControl -Platform Google -Framework CIS -Id '3.1.3.4.3.4' -Level L1 -Title 'Unauthenticated email is detected' `
    -Needs 'GwsPolicies' -Checks 'GMAIL-01' -Map 'GWS.GMAIL.7.4v1' `
    -Guidance 'Turn on Protect against any unauthenticated emails.' `
    -Test { Test-TRGsCtl -Type 'gmail.spoofing_and_authentication' -Ok { param($s) Test-TRGwsTrue $s['detectUnauthenticatedEmails'] } -Good 'unauthenticated email protection is on' -Bad 'unauthenticated email protection is off' }

Register-TRControl -Platform Google -Framework CIS -Id '3.1.3.4.3.5' -Level L1 -Title 'Groups are protected from domain spoofing' `
    -Needs 'GwsPolicies' -Checks 'GMAIL-01' -Map 'GWS.GMAIL.7.5v1' `
    -Guidance 'Turn on Protect your Groups from inbound emails spoofing your domain.' `
    -Test { Test-TRGsCtl -Type 'gmail.spoofing_and_authentication' -Ok { param($s) Test-TRGwsTrue $s['detectGroupsSpoofing'] } -Good 'group spoofing protection is on' -Bad 'group spoofing protection is off' }

Register-TRControl -Platform Google -Framework CIS -Id '3.1.3.5.1' -Level L2 -Title 'POP and IMAP are off for all users' `
    -Needs 'GwsPolicies' -Checks 'GMAIL-06' -Map 'GWS.GMAIL.9.1v1' `
    -Guidance 'Turn off POP and IMAP access for all users.' `
    -Test {
    Join-TRGsEvals @(
        (Test-TRGwsPolicy -Type 'gmail.pop_access' -Ok { param($s) -not (Test-TRGwsTrue $s['enablePopAccess']) } -Good 'POP is off.' -Bad 'POP is on'),
        (Test-TRGwsPolicy -Type 'gmail.imap_access' -Ok { param($s) -not (Test-TRGwsTrue $s['enableImapAccess']) } -Good 'IMAP is off.' -Bad 'IMAP is on')
    )
}

Register-TRControl -Platform Google -Framework CIS -Id '3.1.3.5.2' -Level L1 -Title 'Automatic forwarding is off' `
    -Needs 'GwsPolicies' -Checks 'GMAIL-05' -Map 'GWS.GMAIL.11.1v1' `
    -Guidance 'Untick Allow users to automatically forward incoming email to another address.' `
    -Test { Test-TRGsCtl -Type 'gmail.auto_forwarding' -Ok { param($s) -not (Test-TRGwsTrue $s['enableAutoForwarding']) } -Good 'automatic forwarding is off' -Bad 'automatic forwarding is on' }

Register-TRControl -Platform Google -Framework CIS -Id '3.1.3.5.3' -Level L1 -Title 'Per-user outbound gateways are off' `
    -Needs 'GwsPolicies' -Checks 'GMAIL-07' -Map 'GWS.GMAIL.12.1v1' `
    -Guidance 'Untick Allow per-user outbound gateways.' `
    -Test { Test-TRGsCtl -Type 'gmail.per_user_outbound_gateway' -Ok { param($s) -not (Test-TRGwsTrue $(if ($null -ne $s['allowUsersToUseExternalSmtpServers']) { $s['allowUsersToUseExternalSmtpServers'] } else { $s['enablePerUserOutboundGateway'] })) } -Good 'per-user outbound gateways are off' -Bad 'users can send through external SMTP servers' }

Register-TRControl -Platform Google -Framework CIS -Id '3.1.3.5.4' -Level L1 -Title 'External recipient warnings are on' `
    -Needs 'GwsPolicies' -Checks 'GMAIL-10' -Map 'GWS.GMAIL.13.1v1' `
    -Guidance 'Turn on Warn for external recipients.' `
    -Test {
    $s = Get-TRGwsSetting 'gmail.external_recipient_warning'
    if ($s.Known -or $s.Overrides.Count) { return Test-TRGsCtl -Type 'gmail.external_recipient_warning' -Ok { param($x) Test-TRGwsTrue $x['enabled'] } -Good 'external recipient warnings are on' -Bad 'external recipient warnings are off' }
    ConvertTo-TRGwsCtl (Test-TRGwsLogSetting -Setting 'OutOfDomainWarningProto disable_untrusted_recipient_warning' -Ok { param($v) $v -eq 'false' } -Good 'External recipient warnings are on' -Bad 'external recipient warnings are off' -DefaultOk $true -DefaultText 'warnings on')
}

Register-TRControl -Platform Google -Framework CIS -Id '3.1.3.6.1' -Level L1 -Title 'Enhanced pre-delivery scanning is on' `
    -Needs 'GwsPolicies' -Checks 'GMAIL-04' -Map 'GWS.GMAIL.15.1v1' `
    -Guidance 'Turn on Enhanced pre-delivery message scanning.' `
    -Test { Test-TRGsCtl -Type 'gmail.enhanced_pre_delivery_message_scanning' -Ok { param($s) Test-TRGwsTrue $s['enableImprovedSuspiciousContentDetection'] } -Good 'enhanced pre-delivery scanning is on' -Bad 'enhanced pre-delivery scanning is off' }

Register-TRControl -Platform Google -Framework CIS -Id '3.1.3.6.2' -Level L1 -Title 'Spam filters are not bypassed for internal senders' `
    -Needs 'GwsPolicies' -Checks 'GMAIL-08' -Map 'GWS.GMAIL.18.3v1' `
    -Guidance 'Untick Bypass spam filters for messages received from internal senders.' `
    -Test {
    $bad = @(Get-TRGwsSpamOverrides | Where-Object { Test-TRGwsTrue (Get-TRV $_.Rule 'bypassInternalSenders') })
    if ($bad.Count) { return New-TRCtl Fail ('{0} spam filters for internal senders.' -f (Format-TRN $bad.Count 'spam setting bypasses' 'spam settings bypass')) (@($bad | ForEach-Object { New-TRAffected $_.Scope ([string](Get-TRV $_.Rule 'description')) })) }
    New-TRCtl Pass 'Spam filters are not bypassed for internal senders.'
}

Register-TRControl -Platform Google -Framework CIS -Id '3.1.3.7.1' -Level L1 -Title 'Comprehensive mail storage is on' `
    -Needs 'GwsPolicies' -Checks 'GMAIL-09' -Map 'GWS.GMAIL.17.1v1' `
    -Guidance 'Turn on Comprehensive mail storage.' `
    -Test {
    $r = @((Get-TRGwsPolicyIndex)['gmail.comprehensive_mail_storage'] | Where-Object { $_ -and $_.IsRoot })
    if ($r.Count -and (Get-TRV $r[0].Value 'ruleId')) { return New-TRCtl Pass 'Comprehensive mail storage is on.' }
    New-TRCtl Fail 'Comprehensive mail storage is not on for the organisation.'
}

Register-TRControl -Platform Google -Framework CIS -Id '3.1.3.7.2' -Level L1 -Title 'Mail to key partners requires TLS' -ManualOnly `
    -Guidance 'In Gmail, Compliance, Secure transport (TLS) compliance, require TLS for mail to and from domains that handle sensitive data.'

Register-TRControl -Platform Google -Framework CIS -Id '3.1.4.1.1' -Level L1 -Title 'External file sharing in Chat is off' `
    -Needs 'GwsPolicies' -Checks 'GCOL-02' -Map 'GWS.CHAT.2.1v1' `
    -Guidance 'Set External filesharing to No files.' `
    -Test { Test-TRGsCtl -Type 'chat.chat_file_sharing' -Ok { param($s) [string]$s['externalFileSharing'] -eq 'NO_FILES' } -Good 'external file sharing in Chat is off' -Bad 'files can be shared in external chats' }

Register-TRControl -Platform Google -Framework CIS -Id '3.1.4.1.2' -Level L2 -Title 'Internal file sharing in Chat is off' `
    -Needs 'GwsPolicies' `
    -Guidance 'Set Internal filesharing to No files where the business does not need it.' `
    -Test { Test-TRGsCtl -Type 'chat.chat_file_sharing' -Ok { param($s) [string]$s['internalFileSharing'] -eq 'NO_FILES' } -Good 'internal file sharing in Chat is off' -Bad 'files can be shared in internal chats' }

Register-TRControl -Platform Google -Framework CIS -Id '3.1.4.2.1' -Level L1 -Title 'External chat is limited to allowed domains' `
    -Needs 'GwsPolicies' -Checks 'GCOL-02' -Map 'GWS.CHAT.4.1v1' `
    -Guidance 'Allow external chat only with allowlisted domains.' `
    -Test { Test-TRGsCtl -Type 'chat.external_chat_restriction' -Ok { param($s) -not (Test-TRGwsTrue $s['allowExternalChat']) -or [string]$s['externalChatRestriction'] -eq 'TRUSTED_DOMAINS' } -Good 'external chat is off or limited to allowed domains' -Bad 'users can chat with any external account' }

Register-TRControl -Platform Google -Framework CIS -Id '3.1.4.3.1' -Level L1 -Title 'External spaces are restricted' `
    -Needs 'GwsPolicies' `
    -Guidance 'Turn off external spaces, or allow them only with allowlisted domains.' `
    -Test {
    $t = if ((Get-TRGwsSetting 'chat.external_spaces').Known) { 'chat.external_spaces' } else { 'chat.chat_external_spaces' }
    $s = Get-TRGwsSetting $t
    if (-not $s.Known -and -not $s.Overrides.Count) { return New-TRCtl Fail 'No restriction on external spaces was returned.' }
    Test-TRGsCtl -Type $t -Ok { param($x) -not (Test-TRGwsTrue $x['enabled']) -or [string]$x['domainAllowlistMode'] -eq 'TRUSTED_DOMAINS' } -Good 'external spaces are off or limited to allowed domains' -Bad 'external spaces are open to any domain'
}

Register-TRControl -Platform Google -Framework CIS -Id '3.1.4.4.1' -Level L1 -Title 'Users cannot install Chat apps' `
    -Needs 'GwsPolicies' `
    -Guidance 'In Google Chat, Chat apps, untick Allow users to install Chat apps.' `
    -Test {
    $s = Get-TRGwsSetting 'chat.chat_apps_access'
    if (-not $s.Known -and -not $s.Overrides.Count) { return New-TRCtl Manual 'The Chat apps setting was not returned. Check Google Chat, Chat apps.' }
    Test-TRGsCtl -Type 'chat.chat_apps_access' -Ok { param($x) -not (Test-TRGwsTrue $x['enableApps']) } -Good 'users cannot install Chat apps' -Bad 'users can install Chat apps'
}

Register-TRControl -Platform Google -Framework CIS -Id '3.1.4.4.2' -Level L1 -Title 'Incoming webhooks are off' `
    -Needs 'GwsPolicies' `
    -Guidance 'In Google Chat, Chat apps, untick Allow users to add and use incoming webhooks.' `
    -Test {
    $s = Get-TRGwsSetting 'chat.chat_apps_access'
    if (-not $s.Known -and -not $s.Overrides.Count) { return New-TRCtl Manual 'The Chat apps setting was not returned. Check Google Chat, Chat apps.' }
    Test-TRGsCtl -Type 'chat.chat_apps_access' -Ok { param($x) -not (Test-TRGwsTrue $x['enableWebhooks']) } -Good 'incoming webhooks are off' -Bad 'users can add incoming webhooks'
}

Register-TRControl -Platform Google -Framework CIS -Id '3.1.6.1' -Level L1 -Title 'Groups are private to the organisation' `
    -Needs 'GwsPolicies' -Checks 'GCOL-04' -Map 'GWS.GROUPS.1.1v1' `
    -Guidance 'Set Accessing groups from outside this organisation to Private.' `
    -Test { Test-TRGsCtl -Type 'groups_for_business.groups_sharing' -Ok { param($s) [string]$s['collaborationCapability'] -eq 'DOMAIN_USERS_ONLY' } -Good 'groups are private' -Bad 'groups can be accessed from outside' }

Register-TRControl -Platform Google -Framework CIS -Id '3.1.6.2' -Level L1 -Title 'Group creation is restricted' `
    -Needs 'GwsPolicies' -Checks 'GCOL-04' -Map 'GWS.GROUPS.2.1v1' `
    -Guidance 'Set Creating groups to Only organisation admins can create groups.' `
    -Test { Test-TRGsCtl -Type 'groups_for_business.groups_sharing' -Ok { param($s) [string]$s['createGroupsAccessLevel'] -eq 'ADMIN_ONLY' } -Good 'only admins can create groups' -Bad 'users can create groups' }

Register-TRControl -Platform Google -Framework CIS -Id '3.1.6.3' -Level L1 -Title 'Viewing conversations is restricted by default' `
    -Needs 'GwsPolicies' -Map 'GWS.GROUPS.3.1v1' `
    -Guidance 'Set Default for permission to view conversations to All group members.' `
    -Test { Test-TRGsCtl -Type 'groups_for_business.groups_sharing' -Ok { param($s) [string]$s['viewTopicsDefaultAccessLevel'] -in @('GROUP_MEMBERS', 'MANAGERS', 'OWNERS') } -Good 'conversations are visible to members by default' -Bad 'conversations are visible more widely by default' }

Register-TRControl -Platform Google -Framework CIS -Id '3.1.7.1' -Level L1 -Title 'Google Sites is off' `
    -Needs 'GwsPolicies' -Checks 'GCOL-08' -Map 'GWS.SITES.1.1v1' `
    -Guidance 'Set the service status for Sites to Off for everyone unless it is used.' `
    -Test { Test-TRGsService -Service 'sites' -Want 'DISABLED' -Name 'Google Sites' }

Register-TRControl -Platform Google -Framework CIS -Id '3.1.8.1' -Level L1 -Title 'Access to external Google Groups is off' `
    -Needs 'GwsPolicies' `
    -Guidance 'In Additional Google services, set Google Groups to Off for everyone.' `
    -Test { Test-TRGsService -Service 'groups' -Want 'DISABLED' -Name 'Access to external Google Groups' }

Register-TRControl -Platform Google -Framework CIS -Id '3.1.9.1.1' -Level L1 -Title 'Marketplace app installation is restricted' `
    -Needs 'GwsPolicies' -Checks 'GAPP-03' -Map 'GWS.COMMONCONTROLS.11.1v1' `
    -Guidance 'Allow users to install and run only allowlisted Marketplace apps.' `
    -Test { Test-TRGsCtl -Type 'workspace_marketplace.apps_access_options' -Ok { param($s) [string]$s['accessLevel'] -in @('ALLOW_LISTED_APPS', 'ALLOW_NONE') } -Good 'only allowlisted Marketplace apps can be installed' -Bad 'users can install any Marketplace app' }

Register-TRControl -Platform Google -Framework CIS -Id '4.1.1.1' -Level L1 -Title '2SV is enforced for administrators' `
    -Needs 'GwsUsers', 'GwsRoleAssignments' -Checks 'GIAM-01', 'GPRV-02' -Map 'GWS.COMMONCONTROLS.1.2v1' `
    -Guidance 'Put administrators in an organisational unit or group with 2-Step Verification enforced.' `
    -Test {
    $priv = Get-TRGwsPrivilegedUsers
    $users = Get-TRGwsUserIndex
    $bad = @($priv.Keys | Where-Object { $u = $users[$_]; $u -and -not $u.isEnforcedIn2Sv })
    if ($bad.Count) { return New-TRCtl Fail ('2SV is not enforced for {0}.' -f (Format-TRN $bad.Count 'administrator')) (@($bad | ForEach-Object { New-TRAffected $_ $priv[$_] })) }
    New-TRCtl Pass ('2SV is enforced for all {0}.' -f (Format-TRN $priv.Count 'administrator'))
}

Register-TRControl -Platform Google -Framework CIS -Id '4.1.1.2' -Level L2 -Title 'Administrators use security keys' `
    -Needs 'GwsUsers', 'GwsUserUsage' -Checks 'GPRV-02' -Map 'GWS.COMMONCONTROLS.1.1v1' `
    -Guidance 'Enrol security keys or passkeys for every administrator and set their allowed method to Only security key.' `
    -Test {
    $priv = Get-TRGwsPrivilegedUsers
    $usage = Get-TRGwsUsage
    $bad = @($priv.Keys | Where-Object { $x = $usage[$_]; -not $x -or ([long]$x.accounts_num_security_keys + [long]$x.accounts_num_passkeys_enrolled) -eq 0 })
    if ($bad.Count) { return New-TRCtl Fail ('{0} without a security key or passkey.' -f (Format-TRN $bad.Count 'administrator')) (@($bad | ForEach-Object { New-TRAffected $_ $priv[$_] })) }
    New-TRCtl Pass ('All {0} have a security key or passkey.' -f (Format-TRN $priv.Count 'administrator'))
}

Register-TRControl -Platform Google -Framework CIS -Id '4.1.1.3' -Level L1 -Title '2SV is enforced for all users' `
    -Needs 'GwsUsers' -Checks 'GIAM-01', 'GIAM-02' -Map 'GWS.COMMONCONTROLS.1.2v1' `
    -Guidance 'Allow users to turn on 2-Step Verification and set Enforcement to On for every organisational unit.' `
    -Test {
    $users = @(Get-TRGwsEnabledUsers)
    $bad = @($users | Where-Object { -not $_.isEnforcedIn2Sv })
    if ($bad.Count) { return New-TRCtl Fail ('2SV is not enforced for {0} of {1} active users.' -f $bad.Count, $users.Count) (@($bad | Select-Object -First 500 | ForEach-Object { New-TRAffected ([string]$_.primaryEmail) $(if ($_.isEnrolledIn2Sv) { 'Enrolled, not enforced' } else { 'Not enrolled or enforced' }) })) }
    New-TRCtl Pass ('2SV is enforced for all {0}.' -f (Format-TRN $users.Count 'active user'))
}

Register-TRControl -Platform Google -Framework CIS -Id '4.1.2.1' -Level L2 -Title 'Super admin account recovery is off' `
    -Needs 'GwsPolicies' -Checks 'GPRV-04' -Map 'GWS.COMMONCONTROLS.8.1v1' `
    -Guidance 'Untick Allow super admins to recover their account.' `
    -Test { Test-TRGsCtl -Type 'security.super_admin_account_recovery' -Ok { param($s) -not (Test-TRGwsTrue $s['enableAccountRecovery']) } -Good 'super admin self-recovery is off' -Bad 'super admins can recover their own accounts' }

Register-TRControl -Platform Google -Framework CIS -Id '4.1.2.2' -Level L1 -Title 'User account recovery is on' `
    -Needs 'GwsPolicies' `
    -Guidance 'Tick Allow users and non-super admins to recover their account. Note that CISA SCuBA recommends the opposite (GWS.COMMONCONTROLS.8.2).' `
    -Test { Test-TRGsCtl -Type 'security.user_account_recovery' -Ok { param($s) Test-TRGwsTrue $s['enableAccountRecovery'] } -Good 'user self-recovery is on' -Bad 'users cannot recover their own accounts' }

Register-TRControl -Platform Google -Framework CIS -Id '4.1.3.1' -Level L2 -Title 'The Advanced Protection Program is available' `
    -Needs 'GwsPolicies' -Map 'GWS.COMMONCONTROLS.9.1v1' `
    -Guidance 'In Advanced Protection Program, allow users to enrol, and enrol administrators and other high-risk users.' `
    -Test {
    $s = Get-TRGwsSetting 'security.advanced_protection_program'
    if (-not $s.Known -and -not $s.Overrides.Count) { return New-TRCtl Manual 'The Advanced Protection Program setting was not returned. Check Security, Authentication, Advanced Protection Program.' }
    Test-TRGsCtl -Type 'security.advanced_protection_program' -Ok { param($x) Test-TRGwsTrue $x['enableAdvancedProtectionSelfEnrollment'] } -Good 'users can enrol in Advanced Protection' -Bad 'users cannot enrol in Advanced Protection'
}

Register-TRControl -Platform Google -Framework CIS -Id '4.1.4.1' -Level L2 -Title 'Login challenges use the employee ID' `
    -Needs 'GwsPolicies' `
    -Guidance 'In Login challenges, turn on Use employee ID to keep my users more secure, and populate employee IDs.' `
    -Test {
    $s = Get-TRGwsSetting 'security.login_challenges'
    if (-not $s.Known -and -not $s.Overrides.Count) { return New-TRCtl Manual 'The login challenge setting was not returned. Check Security, Authentication, Login challenges.' }
    Test-TRGsCtl -Type 'security.login_challenges' -Ok { param($x) Test-TRGwsTrue $x['enableEmployeeIdChallenge'] } -Good 'the employee ID login challenge is on' -Bad 'the employee ID login challenge is off'
}

Register-TRControl -Platform Google -Framework CIS -Id '4.1.5.1' -Level L1 -Title 'Password policy meets the benchmark' `
    -Needs 'GwsPolicies' -Checks 'GIAM-04' -Map 'GWS.COMMONCONTROLS.5.1v1', 'GWS.COMMONCONTROLS.5.2v1' `
    -Guidance 'Require strong passwords of 14 or more characters, enforce at next sign-in, no reuse, and a reset period of 365 days or less. Note that CISA SCuBA says passwords should not expire (GWS.COMMONCONTROLS.5.6).' `
    -Test { Test-TRGwsCisPassword }

Register-TRControl -Platform Google -Framework CIS -Id '4.2.1.1' -Level L2 -Title 'App access to Google services is restricted' `
    -Needs 'GwsPolicies' -Checks 'GAPP-01' -Map 'GWS.COMMONCONTROLS.10.1v1' `
    -Guidance 'In API controls, Manage Google services, restrict access to Gmail, Drive and other services so only trusted apps can use them.' `
    -Test {
    $r = @(Get-TRGwsRestrictedScopes)
    if (-not $r.Count) { return New-TRCtl Fail 'No Google service has restricted app access.' }
    $core = @('Gmail', 'Drive') | Where-Object { $k = $_; -not @($script:TRGwsScopeMap[$k] | Where-Object { $r -contains $_ }).Count }
    if (@($core).Count) { return New-TRCtl Fail ('App access is not restricted for: {0}.' -f (@($core) -join ', ')) }
    New-TRCtl Pass ('App access is restricted for {0}.' -f (Format-TRN @($r).Count 'scope group'))
}

Register-TRControl -Platform Google -Framework CIS -Id '4.2.1.2' -Level L2 -Title 'Third-party apps are reviewed regularly' `
    -Needs 'GwsTokens' -Checks 'GAPP-02', 'GAPP-05' `
    -Guidance 'Review App access control with the client at least every quarter and remove apps that are no longer needed.' `
    -Test {
    $apps = @(Get-TRItems 'GwsTokens' | Where-Object { -not $_.NativeApp } | Select-Object -ExpandProperty App -Unique)
    New-TRCtl Manual ('{0} {1} user grants (see the Third-party apps inventory). Confirm they are reviewed regularly.' -f (Format-TRN $apps.Count 'third-party app'), (Select-TRText $apps.Count 'holds' 'hold'))
}

Register-TRControl -Platform Google -Framework CIS -Id '4.2.1.3' -Level L1 -Title 'Internal apps can access Workspace APIs' `
    -Needs 'GwsPolicies' -Checks 'GAPP-04' `
    -Guidance 'Tick Trust internal, domain-owned apps. Note that CISA SCuBA recommends the opposite (GWS.COMMONCONTROLS.10.3).' `
    -Test {
    $s = Get-TRGwsSetting 'api_controls.internal_apps'
    if (-not $s.Known -and -not $s.Overrides.Count) { return New-TRCtl Manual 'The internal apps setting was not returned. Check Security, API controls.' }
    Test-TRGsCtl -Type 'api_controls.internal_apps' -Ok { param($x) Test-TRGwsTrue $x['trustInternalApps'] } -Good 'internal apps are trusted' -Bad 'internal apps are not trusted'
}

Register-TRControl -Platform Google -Framework CIS -Id '4.2.1.4' -Level L2 -Title 'Domain-wide delegation is reviewed regularly' -ManualOnly `
    -Guidance 'Review Security, API controls, Domain-wide delegation with the client and remove clients that are not needed. The list is not available through the APIs.'

Register-TRControl -Platform Google -Framework CIS -Id '4.2.2.1' -Level L1 -Title 'Access from unapproved countries is blocked' `
    -Licence 'ContextAware' -Needs 'GwsAdminEvents' -Map 'GWS.COMMONCONTROLS.2.1v1' `
    -Guidance 'Create a context-aware access level that allows only approved countries and assign it to Workspace apps.' `
    -Test {
    $e = @(Get-TRItems 'GwsAdminEvents' | Where-Object { $_.Event -eq 'TOGGLE_CAA_ENABLEMENT' } | Sort-Object Time)
    if ($e.Count -and [string]$e[-1].NEW_VALUE -ne 'ENABLED') { return New-TRCtl Fail ('Context-aware access was turned off {0}.' -f (Format-TRDate $e[-1].Time)) }
    New-TRCtl Manual 'Confirm in Context-aware access that an access level limiting countries is assigned to the Workspace apps.'
}

Register-TRControl -Platform Google -Framework CIS -Id '4.2.3.1' -Level L1 -Title 'DLP rules protect Drive' `
    -Licence 'Dlp' -Needs 'GwsPolicies' -Checks 'GSEC-04' -Map 'GWS.COMMONCONTROLS.18.1v1' `
    -Guidance 'Create DLP rules for Drive that detect sensitive data and warn or block external sharing.' `
    -Test {
    $drive = @(Get-TRGwsRules 'rule.dlp' | Where-Object { [string](Get-TRV $_ 'state') -eq 'ACTIVE' -and @(Get-TRStrings (Get-TRV $_ 'triggers') | Where-Object { $_ -like 'google.workspace.drive.*' }).Count })
    if ($drive.Count) { return New-TRCtl Pass ('{0} protect Drive.' -f (Format-TRN $drive.Count 'active DLP rule')) }
    New-TRCtl Fail 'No active DLP rule applies to Drive.'
}

Register-TRControl -Platform Google -Framework CIS -Id '4.2.4.1' -Level L1 -Title 'Google session length is limited' `
    -Needs 'GwsPolicies' -Checks 'GIAM-06' -Map 'GWS.COMMONCONTROLS.4.1v1' `
    -Guidance 'Set Web session duration to 12 hours or less.' `
    -Test {
    $s = Get-TRGwsSetting 'security.session_controls'
    if (-not $s.Known -and -not $s.Overrides.Count) { return New-TRCtl Fail 'No session length is set, so the Google default of 14 days applies.' }
    Test-TRGsCtl -Type 'security.session_controls' -Ok { param($x) $v = ConvertTo-TRGwsSeconds $x['webSessionDuration']; $null -ne $v -and $v -le 43200 } -Good 'sessions last 12 hours or less' -Bad 'sessions last longer than 12 hours' -Detail { param($x) 'Session length ' + (Format-TRGwsDuration (ConvertTo-TRGwsSeconds $x['webSessionDuration'])) }
}

Register-TRControl -Platform Google -Framework CIS -Id '4.2.5.1' -Level L2 -Title 'Google Cloud session length is limited' -ManualOnly `
    -Guidance 'In Google Cloud session control, require reauthentication (for example every 16 hours) for users with Google Cloud access.'

Register-TRControl -Platform Google -Framework CIS -Id '4.3.1' -Level L1 -Title 'The security dashboard is reviewed regularly' -ManualOnly -Licence 'SecurityCenter' `
    -Guidance 'Agree a monthly review of the security dashboard with the client.'

Register-TRControl -Platform Google -Framework CIS -Id '4.3.2' -Level L1 -Title 'Security health is reviewed regularly' -ManualOnly -Licence 'SecurityCenter' `
    -Guidance 'Agree a monthly review of the security health page with the client.'

Register-TRControl -Platform Google -Framework CIS -Id '5.1.1.1' -Level L1 -Title 'The app usage report is reviewed regularly' -ManualOnly `
    -Guidance 'Review Reporting, Apps reports for unusual use as part of a monthly service review.'

Register-TRControl -Platform Google -Framework CIS -Id '5.1.1.2' -Level L1 -Title 'The security report is reviewed regularly' -ManualOnly `
    -Guidance 'Review Reporting, User reports, Security for accounts without 2SV, with less secure apps or external sharing.'

Register-TRControl -Platform Google -Framework CIS -Id '6.1' -Level L1 -Title 'Password change alerts are set up' `
    -Needs 'GwsPolicies' -Checks 'GSEC-01' -Map 'GWS.COMMONCONTROLS.13.1v1' `
    -Guidance 'Turn on the User''s password changed rule with email to all super admins and medium severity or higher.' `
    -Test { Test-TRGwsAlertRuleCtl -Name 'User''s password changed' }

Register-TRControl -Platform Google -Framework CIS -Id '6.2' -Level L1 -Title 'Government-backed attack alerts are set up' `
    -Needs 'GwsPolicies' -Checks 'GSEC-01' -Map 'GWS.COMMONCONTROLS.13.1v1' `
    -Guidance 'Turn on the Government-backed attacks rule with email to all super admins and high severity.' `
    -Test { Test-TRGwsAlertRuleCtl -Name 'Government-backed attacks' }

Register-TRControl -Platform Google -Framework CIS -Id '6.3' -Level L1 -Title 'Suspicious activity suspension alerts are set up' `
    -Needs 'GwsPolicies' -Checks 'GSEC-01' -Map 'GWS.COMMONCONTROLS.13.1v1' `
    -Guidance 'Turn on the User suspended due to suspicious activity rule with email to all super admins and high severity.' `
    -Test { Test-TRGwsAlertRuleCtl -Name 'User suspended due to suspicious activity' }

Register-TRControl -Platform Google -Framework CIS -Id '6.4' -Level L1 -Title 'Admin privilege alerts are set up' `
    -Needs 'GwsPolicies' -Checks 'GSEC-01' -Map 'GWS.COMMONCONTROLS.13.1v1' `
    -Guidance 'Turn on the User granted Admin privilege rule with email to all super admins and medium severity or higher.' `
    -Test { Test-TRGwsAlertRuleCtl -Name 'User granted Admin privilege' }

Register-TRControl -Platform Google -Framework CIS -Id '6.5' -Level L1 -Title 'Suspicious programmatic login alerts are set up' `
    -Needs 'GwsPolicies' -Checks 'GSEC-01' -Map 'GWS.COMMONCONTROLS.13.1v1' `
    -Guidance 'Turn on the Suspicious programmatic login rule with email to all super admins.' `
    -Test { Test-TRGwsAlertRuleCtl -Name 'Suspicious programmatic login' }

Register-TRControl -Platform Google -Framework CIS -Id '6.6' -Level L1 -Title 'Suspicious login alerts are set up' `
    -Needs 'GwsPolicies' -Checks 'GSEC-01' -Map 'GWS.COMMONCONTROLS.13.1v1' `
    -Guidance 'Turn on the Suspicious login rule with email to all super admins.' `
    -Test { Test-TRGwsAlertRuleCtl -Name 'Suspicious login' }

Register-TRControl -Platform Google -Framework CIS -Id '6.7' -Level L1 -Title 'Leaked password alerts are set up' `
    -Needs 'GwsPolicies' -Checks 'GSEC-01' -Map 'GWS.COMMONCONTROLS.13.1v1' `
    -Guidance 'Turn on the Leaked password rule with email to all super admins and medium severity or higher.' `
    -Test { Test-TRGwsAlertRuleCtl -Name 'Leaked password' }

Register-TRControl -Platform Google -Framework CIS -Id '6.8' -Level L1 -Title 'Employee spoofing alerts are set up' `
    -Needs 'GwsPolicies' -Checks 'GSEC-01' -Map 'GWS.COMMONCONTROLS.13.1v1' `
    -Guidance 'Turn on the Gmail potential employee spoofing rule with email to all super admins and medium severity or higher.' `
    -Test { Test-TRGwsAlertRuleCtl -Name 'Gmail potential employee spoofing' }
