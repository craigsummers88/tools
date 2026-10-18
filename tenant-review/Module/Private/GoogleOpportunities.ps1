function Get-TRGwsServiceState {
    param([string]$Service)
    $v = Get-TRGwsRootValue ($Service + '.service_status') 'serviceState'
    if ($v) { return [string]$v }
    $null
}

Register-TROpportunity -Platform Google -Id 'GOPP-01' -Category 'Data protection' -Feature 'Data loss prevention (DLP)' `
    -Plans 'Dlp' -Needs 'GwsPolicies' -EffortDays 3 `
    -Opportunity 'Create DLP rules for UK personal and financial data (National Insurance numbers, bank details, passport numbers, card numbers) in Drive, Gmail and Chat, starting in audit mode and moving to warn or block.' `
    -Benefit 'Stops sensitive files and emails leaving the organisation by mistake and gives evidence for UK GDPR.' `
    -Reference 'https://knowledge.workspace.google.com/admin/security/about-dlp' `
    -Evidence {
    param($Users)
    $rules = @(Get-TRGwsRules 'rule.dlp')
    $active = @($rules | Where-Object { [string](Get-TRV $_ 'state') -eq 'ACTIVE' })
    $t = '{0} DLP rules, {1} active.' -f $rules.Count, $active.Count
    if (-not $active.Count) { return New-TROppResult NotUsed $t }
    $apps = @($active | ForEach-Object { Get-TRStrings (Get-TRV $_ 'triggers') } | ForEach-Object { ($_ -split '\.')[2] } | Select-Object -Unique)
    if ($apps.Count -lt 2) { return New-TROppResult Partial ($t + ' Covers: ' + ($apps -join ', ') + '.') }
    New-TROppResult InUse ($t + ' Covers: ' + ($apps -join ', ') + '.')
}

Register-TROpportunity -Platform Google -Id 'GOPP-02' -Category 'Data protection' -Feature 'Google Vault retention and eDiscovery' `
    -Plans 'Vault' -Needs 'GwsVaultEvents' -EffortDays 2 `
    -Opportunity 'Set default retention rules for Gmail, Drive and Chat that match the client''s retention policy, add holds for leavers and disputes, and train an administrator on searches and exports.' `
    -Benefit 'Keeps mail and files for as long as the business must, even if users delete them, and supports subject access requests and disputes.' `
    -Reference 'https://knowledge.workspace.google.com/admin/vault/get-started-with-vault' `
    -Evidence {
    param($Users)
    $e = @(Get-TRItems 'GwsVaultEvents')
    if (-not $e.Count) { return New-TROppResult NotUsed 'No Vault activity was logged in the last 180 days. Retention rules cannot be read through the API, so confirm in Vault whether default retention is set.' }
    $ret = @($e | Where-Object { [string]$_.Event -match 'RETENTION' })
    if ($ret.Count) { return New-TROppResult InUse ('{0} Vault events in 180 days, including retention changes.' -f $e.Count) }
    New-TROppResult Verify ('{0} Vault events in 180 days, but no retention rule changes. Confirm in Vault that default retention rules exist.' -f $e.Count)
}

Register-TROpportunity -Platform Google -Id 'GOPP-03' -Category 'Devices and endpoints' -Feature 'Advanced endpoint management' `
    -Plans 'AdvancedEndpoint' -Needs 'GwsDevices' -EffortDays 3 `
    -Opportunity 'Turn on advanced mobile management, require screen lock and encryption, block compromised devices, use work profiles on Android and set up device approvals.' `
    -Benefit 'Company data on phones and tablets is protected and can be wiped when a device is lost or someone leaves.' `
    -Reference 'https://knowledge.workspace.google.com/admin/mobile/set-up-advanced-mobile-management' `
    -Evidence {
    param($Users)
    $d = @(Get-TRItems 'GwsDevices' | Where-Object { [string]$_.deviceType -in @('ANDROID', 'IOS') })
    $dev = @((Get-TRGwsPolicyIndex).Keys | Where-Object { $_ -like 'devices.*' })
    $t = '{0} mobile devices registered; {1} device policy settings found.' -f $d.Count, $dev.Count
    if (-not $d.Count) { return New-TROppResult NotUsed $t }
    if (-not $dev.Count) { return New-TROppResult Partial $t }
    New-TROppResult InUse $t
}

Register-TROpportunity -Platform Google -Id 'GOPP-04' -Category 'Devices and endpoints' -Feature 'Windows device management' `
    -Plans 'WindowsManagement' -Needs 'GwsDevices' -EffortDays 3 `
    -Opportunity 'Enrol Windows laptops with Google Credential Provider for Windows, manage Windows settings and BitLocker from the Admin console and wipe lost devices.' `
    -Benefit 'Windows devices are managed alongside phones without a separate MDM licence.' `
    -Reference 'https://knowledge.workspace.google.com/admin/mobile/about-windows-device-management' `
    -Evidence {
    param($Users)
    $w = @(Get-TRItems 'GwsDevices' | Where-Object { [string]$_.deviceType -eq 'WINDOWS' })
    if (-not $w.Count) { return New-TROppResult NotUsed 'No Windows devices are registered in Google endpoint management. If Windows is managed by another tool (for example Intune or the RMM), this can be ignored.' }
    New-TROppResult InUse ('{0} registered.' -f (Format-TRN $w.Count 'Windows device is' 'Windows devices are'))
}

Register-TROpportunity -Platform Google -Id 'GOPP-05' -Category 'Identity and access' -Feature 'Context-aware access' `
    -Plans 'ContextAware' -Needs 'GwsAdminEvents' -EffortDays 2 `
    -Opportunity 'Create access levels that allow Workspace only from company devices and approved countries, starting in monitor mode.' `
    -Benefit 'Stolen passwords and session cookies are much less useful to an attacker outside the approved devices and locations.' `
    -Reference 'https://knowledge.workspace.google.com/admin/security/protect-your-business-with-context-aware-access' `
    -Evidence {
    param($Users)
    $e = @(Get-TRItems 'GwsAdminEvents' | Where-Object { $_.Event -eq 'TOGGLE_CAA_ENABLEMENT' } | Sort-Object Time)
    if ($e.Count -and [string]$e[-1].NEW_VALUE -eq 'ENABLED') { return New-TROppResult InUse ('Context-aware access was turned on {0}.' -f (Format-TRDate $e[-1].Time)) }
    if ($e.Count) { return New-TROppResult NotUsed ('Context-aware access was turned off {0}.' -f (Format-TRDate $e[-1].Time)) }
    New-TROppResult Verify 'No change was logged in the last 180 days. Context-aware access is off by default; confirm in the Admin console.'
}

Register-TROpportunity -Platform Google -Id 'GOPP-06' -Category 'Security operations' -Feature 'Security centre and investigation tool' `
    -Plans 'SecurityCenter' -EffortDays 1 `
    -Opportunity 'Set up a monthly review of the security dashboard and security health page, and use the investigation tool to look into alerts and remove malicious mail.' `
    -Benefit 'Problems are spotted and cleaned up quickly, from phishing campaigns to risky sharing.' `
    -Reference 'https://knowledge.workspace.google.com/admin/security/about-the-security-center' `
    -Evidence {
    param($Users)
    $inv = @(Get-TRItems 'GwsAdminEvents' | Where-Object { [string]$_.Event -match 'INVESTIGATION|SECURITY_CENTER' })
    if ($inv.Count) { return New-TROppResult InUse ('{0} security centre actions in the last 180 days.' -f $inv.Count) }
    New-TROppResult Verify 'Use of the security centre cannot be read through the API. Ask whether anyone reviews it.'
}

Register-TROpportunity -Platform Google -Id 'GOPP-07' -Category 'Security operations' -Feature 'Gmail security sandbox' `
    -Plans 'SecuritySandbox' -Needs 'GwsAdminEvents' -EffortDays 0.5 `
    -Opportunity 'Turn on the security sandbox so attachments are opened in a virtual environment before delivery.' `
    -Benefit 'Catches new malware that signature scanning misses.' `
    -Reference 'https://knowledge.workspace.google.com/admin/gmail/set-up-rules-for-security-sandbox' `
    -Evidence {
    param($Users)
    $v = Get-TRGwsLogSetting 'AttachmentDeepScanningSettingsProto deep_scanning_enabled'
    if ($v -and @($v | Where-Object { $_.Value -eq 'true' }).Count) { return New-TROppResult InUse 'Security sandbox is on.' }
    New-TROppResult NotUsed 'Security sandbox is not on (no change logged, so the default of off applies).'
}

Register-TROpportunity -Platform Google -Id 'GOPP-08' -Category 'Data protection' -Feature 'Data regions' `
    -Plans 'DataRegions' -Needs 'GwsPolicies' -EffortDays 0.5 `
    -Opportunity 'Set the data region for data at rest to Europe for the organisation (or the units that need it).' `
    -Benefit 'Supports data residency commitments in contracts and tenders.' `
    -Reference 'https://knowledge.workspace.google.com/admin/security/choose-a-geographic-location-for-your-data' `
    -Evidence {
    param($Users)
    $v = Get-TRGwsRootValue 'data_regions.data_at_rest_region' 'region'
    if ($v -and [string]$v -notin @('ANY_REGION', 'REGION_UNSPECIFIED')) { return New-TROppResult InUse ('Data at rest region: {0}.' -f $v) }
    New-TROppResult NotUsed 'No data region is set, so data can be stored in any Google region.'
}

Register-TROpportunity -Platform Google -Id 'GOPP-09' -Category 'Productivity and AI' -Feature 'Gemini in Gmail, Docs and Drive' `
    -Plans 'GeminiDocs' -Needs 'GwsPolicies' -EffortDays 1 `
    -Opportunity 'Agree an AI use policy, turn on Gemini for the teams that will use it, and run short training on drafting, summarising and Meet notes.' `
    -Benefit 'Staff save time on email, documents and meetings with AI that keeps data inside Workspace.' `
    -Reference 'https://knowledge.workspace.google.com/admin/gemini/turn-gemini-features-on-or-off' `
    -Evidence {
    param($Users)
    $s = Get-TRGwsServiceState 'gemini_app'
    if ($s -eq 'DISABLED') { return New-TROppResult NotUsed 'The Gemini app is turned off for the organisation.' }
    New-TROppResult Verify ('Gemini is {0}. Usage by user cannot be read through the API; check the Gemini usage report.' -f $(if ($s) { $s.ToLower() } else { 'at its default' }))
}

Register-TROpportunity -Platform Google -Id 'GOPP-10' -Category 'Collaboration' -Feature 'Google Meet' `
    -Plans 'Workspace' -Needs 'GwsMeetEvents' -EffortDays 0.5 `
    -Opportunity 'Encourage Meet for internal and client calls, with room hardware or Meet on companion devices where useful.' `
    -Benefit 'Calls are included in the subscription, so no separate conferencing tool is needed.' `
    -Reference 'https://knowledge.workspace.google.com/admin/meet/get-started-with-google-meet' `
    -Evidence {
    param($Users)
    $e = @(Get-TRItems 'GwsMeetEvents')
    $org = @($e | Where-Object { $_.organizer_email } | Select-Object -ExpandProperty organizer_email -Unique)
    $t = '{0} Meet call participations in 30 days; {1} distinct organisers out of {2} licensed users.' -f $e.Count, $org.Count, $Users
    if (-not $e.Count) { return New-TROppResult NotUsed $t }
    if ($org.Count -lt ($Users * 0.2)) { return New-TROppResult Partial $t }
    New-TROppResult InUse $t
}

Register-TROpportunity -Platform Google -Id 'GOPP-11' -Category 'Collaboration' -Feature 'Google Drive' `
    -Plans 'Workspace' -Needs 'GwsUserUsage' -EffortDays 2 `
    -Opportunity 'Move file shares and personal storage into shared drives with a clear structure, and train staff on sharing.' `
    -Benefit 'Files are backed by Google''s storage, shareable safely and searchable, and old file servers can be retired.' `
    -Reference 'https://knowledge.workspace.google.com/admin/drive/set-up-shared-drives-for-your-organization' `
    -Evidence {
    param($Users)
    $u = @(Get-TRItems 'GwsUserUsage')
    $active = @($u | Where-Object { $d = Get-TRGwsDays $_.drive_timestamp_last_active_usage; $null -ne $d -and $d -le 30 }).Count
    $pct = Get-TRPercent $active $Users
    $t = '{0} of {1} licensed users used Drive in the last 30 days ({2}%).' -f $active, $Users, $pct
    if ($active -eq 0) { return New-TROppResult NotUsed $t }
    if ($pct -lt 60) { return New-TROppResult Partial $t }
    New-TROppResult InUse $t
}

Register-TROpportunity -Platform Google -Id 'GOPP-12' -Category 'Productivity and AI' -Feature 'AppSheet' `
    -Plans 'AppSheet' -Needs 'GwsPolicies' -EffortDays 3 `
    -Opportunity 'Replace spreadsheet-based processes (timesheets, inspections, stock checks) with simple AppSheet apps.' `
    -Benefit 'Faster, more reliable processes without buying separate software.' `
    -Reference 'https://knowledge.workspace.google.com/admin/apps/appsheet' `
    -Evidence {
    param($Users)
    $s = Get-TRGwsServiceState 'appsheet'
    if ($s -eq 'DISABLED') { return New-TROppResult NotUsed 'AppSheet is turned off for the organisation.' }
    New-TROppResult Verify 'AppSheet is available. Usage cannot be read through the Workspace APIs.'
}

Register-TROpportunity -Platform Google -Id 'GOPP-13' -Category 'Identity and access' -Feature 'Passkeys and security keys' `
    -Plans 'Workspace' -Needs 'GwsUserUsage' -EffortDays 2 `
    -Opportunity 'Roll out passkeys to staff (phones and laptops act as the key) and hardware security keys to administrators, then restrict 2SV methods.' `
    -Benefit 'Phishing-resistant sign-in at no extra licence cost.' `
    -Reference 'https://knowledge.workspace.google.com/admin/security/use-passkeys-to-sign-in' `
    -Evidence {
    param($Users)
    $u = @(Get-TRItems 'GwsUserUsage')
    $with = @($u | Where-Object { [long]$_.accounts_num_passkeys_enrolled + [long]$_.accounts_num_security_keys -gt 0 }).Count
    $pct = Get-TRPercent $with $Users
    $t = '{0} of {1} users {3} a passkey or security key ({2}%).' -f $with, $Users, $pct, (Select-TRText $with 'has' 'have')
    if ($with -eq 0) { return New-TROppResult NotUsed $t }
    if ($pct -lt 80) { return New-TROppResult Partial $t }
    New-TROppResult InUse $t
}
