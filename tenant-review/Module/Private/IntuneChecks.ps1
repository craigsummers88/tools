$script:TRAsrRuleNames = @{
    'blockabuseofexploitedvulnerablesigneddrivers'                                = 'Block abuse of exploited vulnerable signed drivers'
    'blockadobereaderfromcreatingchildprocesses'                                  = 'Block Adobe Reader from creating child processes'
    'blockallofficeapplicationsfromcreatingchildprocesses'                        = 'Block all Office applications from creating child processes'
    'blockcredentialstealingfromwindowslocalsecurityauthoritysubsystem'           = 'Block credential stealing from LSASS'
    'blockexecutablecontentfromemailclientandwebmail'                             = 'Block executable content from email client and webmail'
    'blockexecutablefilesrunningunlesstheymeetprevalenceagetrustedlistcriterion'  = 'Block executables unless they meet prevalence, age or trusted list criteria'
    'blockexecutionofpotentiallyobfuscatedscripts'                                = 'Block execution of potentially obfuscated scripts'
    'blockjavascriptorvbscriptfromlaunchingdownloadedexecutablecontent'           = 'Block JavaScript or VBScript from launching downloaded executables'
    'blockofficeapplicationsfromcreatingexecutablecontent'                        = 'Block Office applications from creating executable content'
    'blockofficeapplicationsfrominjectingcodeintootherprocesses'                  = 'Block Office applications from injecting code into other processes'
    'blockofficecommunicationappfromcreatingchildprocesses'                       = 'Block Office communication apps from creating child processes'
    'blockpersistencethroughwmieventsubscription'                                 = 'Block persistence through WMI event subscription'
    'blockprocesscreationsfrompsexecandwmicommands'                               = 'Block process creations from PSExec and WMI commands'
    'blockrebootingmachineinsafemode'                                             = 'Block rebooting the machine in Safe Mode'
    'blockuntrustedunsignedprocessesthatrunfromusb'                               = 'Block untrusted and unsigned processes that run from USB'
    'blockuseofcopiedorimpersonatedsystemtools'                                   = 'Block use of copied or impersonated system tools'
    'blockwebshellcreationforservers'                                             = 'Block web shell creation for servers'
    'blockwin32apicallsfromofficemacros'                                          = 'Block Win32 API calls from Office macros'
    'useadvancedprotectionagainstransomware'                                      = 'Use advanced protection against ransomware'
}

$script:TRAsrStandardRules = @('blockabuseofexploitedvulnerablesigneddrivers', 'blockcredentialstealingfromwindowslocalsecurityauthoritysubsystem', 'blockpersistencethroughwmieventsubscription')

$script:TRAsrPrefix = 'device_vendor_msft_policy_config_defender_attacksurfacereductionrules_'

function Get-TRDaysUntil {
    param($Date)
    $d = Get-TRDaysSince $Date
    if ($null -eq $d) { return $null }
    -$d
}

function Test-TRPersonalMailbox {
    param([string]$Address)
    $Address -match '@(gmail|googlemail|outlook|hotmail|live|icloud|me|mac|yahoo|aol|btinternet|sky)\.'
}

function Get-TRIntuneGroupIndex {
    Get-TRCached 'IntuneGroupIndex' {
        $h = @{}
        foreach ($g in (Get-TRItems 'Groups')) { $h[[string]$g.id] = [string]$g.displayName }
        $h
    }
}

function Format-TRIntuneTargets {
    param($Assignments)
    $groups = Get-TRIntuneGroupIndex
    $parts = foreach ($a in @($Assignments | Where-Object { $_ })) {
        $t = $a.target
        $type = [string]$t.'@odata.type'
        $gid = [string]$t.groupId
        $gname = if ($gid -and $groups[$gid]) { $groups[$gid] } elseif ($gid) { 'group ' + $gid } else { '' }
        switch -Regex ($type) {
            'allDevices' { 'All devices' }
            'allLicensedUsers' { 'All users' }
            'exclusionGroup' { 'Exclude ' + $gname }
            'groupAssignment' { $gname }
            default { if ($gname) { $gname } else { 'Assigned' } }
        }
    }
    (@($parts | Where-Object { $_ }) -join '; ')
}

function Get-TRIntuneTypeName {
    param([string]$ODataType)
    $t = $ODataType -replace '^#microsoft\.graph\.', ''
    $map = @{
        'windows10GeneralConfiguration'            = 'Device restrictions (Windows)'
        'windows10EndpointProtectionConfiguration' = 'Endpoint protection (Windows, legacy)'
        'windowsUpdateForBusinessConfiguration'    = 'Update ring (Windows)'
        'windows10CustomConfiguration'             = 'Custom OMA-URI (Windows)'
        'windowsHealthMonitoringConfiguration'     = 'Windows health monitoring'
        'windowsIdentityProtectionConfiguration'   = 'Identity protection (Windows)'
        'windows10CompliancePolicy'                = 'Compliance (Windows)'
        'iosCompliancePolicy'                      = 'Compliance (iOS/iPadOS)'
        'macOSCompliancePolicy'                    = 'Compliance (macOS)'
        'androidWorkProfileCompliancePolicy'       = 'Compliance (Android work profile)'
        'androidDeviceOwnerCompliancePolicy'       = 'Compliance (Android Enterprise fully managed)'
        'androidCompliancePolicy'                  = 'Compliance (Android device administrator)'
        'aospDeviceOwnerCompliancePolicy'          = 'Compliance (Android AOSP)'
        'iosGeneralDeviceConfiguration'            = 'Device restrictions (iOS/iPadOS)'
        'macOSGeneralDeviceConfiguration'          = 'Device restrictions (macOS)'
        'iosCustomConfiguration'                   = 'Custom (iOS/iPadOS)'
        'macOSCustomConfiguration'                 = 'Custom (macOS)'
    }
    if ($map[$t]) { return $map[$t] }
    $t
}

function Get-TRIntunePlatform {
    param([string]$Text)
    switch -Regex ($Text) {
        'windows|win32|windows10' { 'Windows'; break }
        'ios|iPad' { 'iOS/iPadOS'; break }
        'macOS' { 'macOS'; break }
        'android|aosp' { 'Android'; break }
        default { '' }
    }
}

function Get-TRIntunePolicyList {
    Get-TRCached 'IntunePolicyList' {
        $rows = New-Object System.Collections.ArrayList
        $add = {
            param($Id, $Name, $Kind, $Type, $Platform, $Known, $Assignments, $Assigned, $Modified)
            [void]$rows.Add([pscustomobject]@{ Id = [string]$Id; Name = [string]$Name; Kind = $Kind; Type = $Type; Platform = $Platform; Known = [bool]$Known; Assigned = [bool]$Assigned; Targets = $(if ($Assignments) { Format-TRIntuneTargets $Assignments } else { '' }); Modified = $Modified })
        }
        foreach ($p in (Get-TRItems 'DeviceConfigurations')) {
            $k = Test-TRHasProperty $p 'assignments'
            & $add $p.id $p.displayName 'Configuration profile' (Get-TRIntuneTypeName ([string]$p.'@odata.type')) (Get-TRIntunePlatform ([string]$p.'@odata.type')) $k $p.assignments (@($p.assignments).Count -gt 0) $p.lastModifiedDateTime
        }
        foreach ($p in (Get-TRItems 'ConfigurationPolicies')) {
            $fam = [string]$p.templateReference.templateFamily
            $kind = if ($fam -like 'endpointSecurity*') { 'Endpoint security' } elseif ($fam -eq 'baseline') { 'Security baseline' } else { 'Settings catalog' }
            $type = if ([string]$p.templateReference.templateDisplayName) { [string]$p.templateReference.templateDisplayName } else { 'Settings catalog' }
            $k = Test-TRHasProperty $p 'assignments'
            & $add $p.id $p.name $kind $type (Get-TRIntunePlatform ([string]$p.platforms)) $k $p.assignments (@($p.assignments).Count -gt 0) $p.lastModifiedDateTime
        }
        foreach ($p in (Get-TRItems 'CompliancePolicies')) {
            $k = Test-TRHasProperty $p 'assignments'
            & $add $p.id $p.displayName 'Compliance policy' (Get-TRIntuneTypeName ([string]$p.'@odata.type')) (Get-TRIntunePlatform ([string]$p.'@odata.type')) $k $p.assignments (@($p.assignments).Count -gt 0) $p.lastModifiedDateTime
        }
        foreach ($p in (Get-TRItems 'Intents')) {
            & $add $p.id $p.displayName 'Endpoint security or baseline (old format)' 'Intent' 'Windows' $true $null ($p.isAssigned -eq $true) $p.lastModifiedDateTime
        }
        foreach ($src in 'IosAppProtection', 'AndroidAppProtection') {
            foreach ($p in (Get-TRItems $src)) {
                $k = Test-TRHasProperty $p 'assignments'
                & $add $p.id $p.displayName 'App protection' 'App protection' $(if ($src -like 'Ios*') { 'iOS/iPadOS' } else { 'Android' }) $k $p.assignments (@($p.assignments).Count -gt 0) $p.lastModifiedDateTime
            }
        }
        foreach ($p in (Get-TRItems 'AutopilotProfiles')) {
            $k = Test-TRHasProperty $p 'assignments'
            & $add $p.id $p.displayName 'Autopilot profile' $(if ([string]$p.'@odata.type' -match 'activeDirectory') { 'Hybrid Entra join' } else { 'Entra join' }) 'Windows' $k $p.assignments (@($p.assignments).Count -gt 0) $p.lastModifiedDateTime
        }
        $rows.ToArray()
    }
}

function Get-TRIntuneSettings {
    param([string]$Like, [switch]$AssignedOnly)
    @(Get-TRItems 'IntunePolicySettings' | Where-Object { ([string]$_.Setting -like $Like) -and (-not $AssignedOnly -or $_.Assigned -eq $true) })
}

function Get-TRIntuneChoice {
    param([string]$Value)
    if ($Value -match '_([^_]+)$') { return $Matches[1] }
    $Value
}

function Get-TRWindowsDeviceCount {
    @(Get-TRItems 'ManagedDevices' | Where-Object { [string]$_.operatingSystem -match '^Windows' }).Count
}

function Get-TRAsrRules {
    Get-TRCached 'AsrRules' {
        $rows = foreach ($s in (Get-TRIntuneSettings -Like ($script:TRAsrPrefix + '*') -AssignedOnly)) {
            $slug = ([string]$s.Setting).Substring($script:TRAsrPrefix.Length)
            if ($slug -match 'exclusion') { continue }
            $mode = (Get-TRIntuneChoice ([string]$s.Value)).ToLower()
            if ($mode -notin @('block', 'audit', 'warn', 'off')) { continue }
            $name = if ($script:TRAsrRuleNames[$slug]) { $script:TRAsrRuleNames[$slug] } else { $slug }
            [pscustomobject]@{ Rule = $slug; Name = $name; Mode = $mode; Policy = [string]$s.Policy }
        }
        @($rows)
    }
}

Register-TRCheck -Id 'END-13' -Area 'Intune' -Category 'Intune connections' -Severity High -Effort 1 `
    -Title 'Apple MDM push certificate is valid' `
    -Needs 'IntuneApplePush', 'ManagedDevices' `
    -Recommendation 'Renew the Apple MDM push certificate in Intune (Devices, Enrolment, Apple) before it expires, using the same Apple ID that created it. Use a shared company Apple ID, not a personal one. If it expires, Apple devices stop receiving policy, and creating a new certificate with a different Apple ID means re-enrolling every Apple device.' `
    -Reference 'https://learn.microsoft.com/intune/intune-service/enrollment/apple-mdm-push-certificate-get' `
    -Test {
    $c = @(Get-TRItems 'IntuneApplePush')[0]
    $apple = @(Get-TRItems 'ManagedDevices' | Where-Object { [string]$_.operatingSystem -match 'iOS|iPadOS|mac' })
    if (-not $c -or -not $c.expirationDateTime) {
        if ($apple.Count) { return New-TRResult Warning ('{0} enrolled, but no Apple MDM push certificate was returned.' -f (Format-TRN $apple.Count 'Apple device is' 'Apple devices are')) }
        return New-TRResult Info 'Apple device management is not set up (no MDM push certificate).'
    }
    $days = Get-TRDaysUntil $c.expirationDateTime
    $who = [string]$c.appleIdentifier
    $aff = @(New-TRAffected 'Apple MDM push certificate' ('Expires {0}; Apple ID {1}' -f (Format-TRDate $c.expirationDateTime), $who))
    $personal = if (Test-TRPersonalMailbox $who) { ' It was created with a personal Apple ID, so renewal depends on that person.' } else { '' }
    if ($days -lt 0) { return New-TRResult Fail ('The Apple MDM push certificate expired on {0}. Apple devices can no longer be managed until it is renewed with Apple ID {1}.{2}' -f (Format-TRDate $c.expirationDateTime), $who, $personal) $aff }
    if ($days -le 30) { return New-TRResult Fail ('The Apple MDM push certificate expires in {0} ({1}). Renew it with Apple ID {2}.{3}' -f (Format-TRN $days 'day'), (Format-TRDate $c.expirationDateTime), $who, $personal) $aff }
    if ($days -le 60) { return New-TRResult Warning ('The Apple MDM push certificate expires in {0} ({1}).{2}' -f (Format-TRN $days 'day'), (Format-TRDate $c.expirationDateTime), $personal) $aff }
    if (Test-TRPersonalMailbox $who) { return New-TRResult Warning ('Valid until {0}, but it was created with a personal Apple ID ({1}), so renewal depends on that person.' -f (Format-TRDate $c.expirationDateTime), $who) $aff }
    New-TRResult Pass ('Valid until {0}; Apple ID {1}.' -f (Format-TRDate $c.expirationDateTime), $who)
}

Register-TRCheck -Id 'END-14' -Area 'Intune' -Category 'Intune connections' -Severity Medium -Effort 1 `
    -Title 'Apple Business Manager enrolment tokens are valid and syncing' `
    -Needs 'IntuneDepTokens' `
    -Recommendation 'Renew the automated device enrolment token in Apple Business Manager and upload it to Intune (Devices, Enrolment, Apple, Enrolment program tokens) before it expires, and fix any sync errors so new devices appear in Intune.' `
    -Reference 'https://learn.microsoft.com/intune/intune-service/enrollment/device-enrollment-program-enroll-ios' `
    -Test {
    $tokens = @(Get-TRItems 'IntuneDepTokens')
    if (-not $tokens.Count) { return New-TRResult Info 'No Apple Business Manager (automated device enrolment) token is connected.' }
    $fail = @(); $warn = @()
    foreach ($t in $tokens) {
        $name = if ([string]$t.tokenName) { [string]$t.tokenName } else { [string]$t.appleIdentifier }
        $days = Get-TRDaysUntil $t.tokenExpirationDateTime
        $sync = Get-TRDaysSince $t.lastSuccessfulSyncDateTime
        $detail = 'Expires {0}; last successful sync {1}; {2}' -f (Format-TRDate $t.tokenExpirationDateTime), (Format-TRDate $t.lastSuccessfulSyncDateTime), (Format-TRN ([int]$t.syncedDeviceCount) 'device')
        if ($null -ne $days -and $days -le 30) { $fail += (New-TRAffected $name $detail); continue }
        if (($null -ne $days -and $days -le 60) -or ([int]$t.lastSyncErrorCode -ne 0) -or ($null -ne $sync -and $sync -gt 7)) { $warn += (New-TRAffected $name ($detail + $(if ([int]$t.lastSyncErrorCode -ne 0) { '; sync error ' + $t.lastSyncErrorCode } else { '' }))) }
    }
    if ($fail.Count) { return New-TRResult Fail ('{0} expired or {1} within 30 days.' -f (Format-TRN $fail.Count 'enrolment token has' 'enrolment tokens have'), (Select-TRText $fail.Count 'expires' 'expire')) @($fail + $warn) }
    if ($warn.Count) { return New-TRResult Warning ('{0} expiring soon or not syncing.' -f (Format-TRN $warn.Count 'enrolment token is' 'enrolment tokens are')) $warn }
    New-TRResult Pass ('{0} valid and syncing.' -f (Format-TRN $tokens.Count 'enrolment token is' 'enrolment tokens are'))
}

Register-TRCheck -Id 'END-15' -Area 'Intune' -Category 'Intune connections' -Severity Medium -Effort 1 `
    -Title 'Apple Apps and Books (VPP) tokens are valid' `
    -Needs 'IntuneVppTokens' `
    -Recommendation 'Renew Apps and Books location tokens in Apple Business Manager and upload them to Intune before they expire, so purchased apps keep installing and updating.' `
    -Reference 'https://learn.microsoft.com/intune/intune-service/apps/vpp-apps-ios' `
    -Test {
    $tokens = @(Get-TRItems 'IntuneVppTokens')
    if (-not $tokens.Count) { return New-TRResult Info 'No Apple Apps and Books (VPP) token is connected.' }
    $fail = @(); $warn = @()
    foreach ($t in $tokens) {
        $name = if ([string]$t.organizationName) { [string]$t.organizationName } else { [string]$t.appleId }
        $days = Get-TRDaysUntil $t.expirationDateTime
        $detail = 'State {0}; expires {1}; last sync {2} ({3})' -f $t.state, (Format-TRDate $t.expirationDateTime), (Format-TRDate $t.lastSyncDateTime), $t.lastSyncStatus
        if ([string]$t.state -ne 'valid' -or ($null -ne $days -and $days -le 30)) { $fail += (New-TRAffected $name $detail); continue }
        if (($null -ne $days -and $days -le 60) -or [string]$t.lastSyncStatus -eq 'failed') { $warn += (New-TRAffected $name $detail) }
    }
    if ($fail.Count) { return New-TRResult Fail ('{0} not valid or {1} within 30 days.' -f (Format-TRN $fail.Count 'Apps and Books token is' 'Apps and Books tokens are'), (Select-TRText $fail.Count 'expires' 'expire')) @($fail + $warn) }
    if ($warn.Count) { return New-TRResult Warning ('{0} expiring soon or failing to sync.' -f (Format-TRN $warn.Count 'Apps and Books token is' 'Apps and Books tokens are')) $warn }
    New-TRResult Pass ('{0} valid.' -f (Format-TRN $tokens.Count 'Apps and Books token is' 'Apps and Books tokens are'))
}

Register-TRCheck -Id 'END-16' -Area 'Intune' -Category 'Intune connections' -Severity Medium -Effort 2 `
    -Title 'Android Enterprise is connected' `
    -Needs 'IntuneAndroidEnterprise', 'ManagedDevices' `
    -Recommendation 'Connect Intune to Managed Google Play (Devices, Enrolment, Android) with a shared company Google account, and move any Android devices still on device administrator management to an Android Enterprise work profile or fully managed enrolment.' `
    -Reference 'https://learn.microsoft.com/intune/intune-service/enrollment/connect-intune-android-enterprise' `
    -Test {
    $ae = @(Get-TRItems 'IntuneAndroidEnterprise')[0]
    $android = @(Get-TRItems 'ManagedDevices' | Where-Object { [string]$_.operatingSystem -match 'Android' })
    $bound = $ae -and [string]$ae.bindStatus -match '^bound'
    if (-not $bound) {
        if ($android.Count) { return New-TRResult Warning ('{0} enrolled, but Managed Google Play is not connected. These devices are likely on device administrator management, which Microsoft no longer supports on devices with Google Mobile Services.' -f (Format-TRN $android.Count 'Android device is' 'Android devices are')) }
        return New-TRResult Info 'Android Enterprise is not connected and no Android devices are enrolled.'
    }
    $owner = [string]$ae.ownerUserPrincipalName
    $sync = [string]$ae.lastAppSyncStatus
    if ($sync -and $sync -notin @('success', 'none')) { return New-TRResult Warning ('Managed Google Play is connected (owner {0}), but the last app sync reported {1} on {2}.' -f $owner, $sync, (Format-TRDate $ae.lastAppSyncDateTime)) }
    if (Test-TRPersonalMailbox $owner) { return New-TRResult Warning ('Managed Google Play is connected with a personal Google account ({0}). Move it to a shared company account.' -f $owner) }
    New-TRResult Pass ('Managed Google Play is connected (owner {0}).' -f $owner)
}

Register-TRCheck -Id 'END-17' -Area 'Intune' -Category 'Intune configuration health' -Severity Low -Effort 1 `
    -Title 'Intune policies are assigned' `
    -Needs 'DeviceConfigurations', 'CompliancePolicies', 'ConfigurationPolicies' `
    -Recommendation 'Assign or delete policies that are not assigned to anyone. Unassigned policies are often drafts or leftovers that make it hard to see what is really applied, and they can be assigned by mistake later.' `
    -Reference 'https://learn.microsoft.com/intune/intune-service/configuration/device-profile-assign' `
    -Test {
    $all = @(Get-TRIntunePolicyList | Where-Object { $_.Known -and $_.Kind -ne 'Autopilot profile' })
    if (-not $all.Count) { return New-TRResult Info 'No Intune policies were found.' }
    $un = @($all | Where-Object { -not $_.Assigned })
    if ($un.Count) { return New-TRResult Warning ('{0} of {1} policies {2} not assigned.' -f $un.Count, $all.Count, (Select-TRText $un.Count 'is' 'are')) @($un | Sort-Object Kind, Name | ForEach-Object { New-TRAffected $_.Name ('{0}; {1}' -f $_.Kind, $_.Type) }) }
    New-TRResult Pass ('All {0} are assigned.' -f (Format-TRN $all.Count 'policy' 'policies'))
}

Register-TRCheck -Id 'END-18' -Area 'Intune' -Category 'Intune configuration health' -Severity Medium -Effort 3 `
    -Title 'Policies apply without errors or conflicts' `
    -Needs 'IntunePolicyStatus' `
    -Recommendation 'Open each listed policy in Intune, select the devices in error or conflict, and fix the failing settings. Conflicts mean two policies set the same setting to different values; keep one source for each setting.' `
    -Reference 'https://learn.microsoft.com/intune/intune-service/configuration/device-profile-monitor' `
    -Test {
    $rows = @(Get-TRItems 'IntunePolicyStatus')
    if (-not $rows.Count) { return New-TRResult Info 'No policy status was returned.' }
    $names = @{}
    foreach ($p in (Get-TRIntunePolicyList)) { $names[$p.Id] = $p.Name }
    $bad = @($rows | Where-Object { [int]$_.Errors -gt 0 -or [int]$_.Conflicts -gt 0 } | Sort-Object { -([int]$_.Errors + [int]$_.Conflicts) })
    if (-not $bad.Count) { return New-TRResult Pass ('No errors or conflicts reported across {0}.' -f (Format-TRN $rows.Count 'policy' 'policies')) }
    $err = ($bad | Measure-Object -Property Errors -Sum).Sum
    $con = ($bad | Measure-Object -Property Conflicts -Sum).Sum
    $aff = @($bad | ForEach-Object { $n = if ($_.Policy) { $_.Policy } elseif ($names[$_.PolicyId]) { $names[$_.PolicyId] } else { $_.PolicyId }; New-TRAffected $n ('{0}, {1}' -f (Format-TRN ([int]$_.Errors) 'device in error' 'devices in error'), (Format-TRN ([int]$_.Conflicts) 'device in conflict' 'devices in conflict')) })
    New-TRResult Warning ('{0} {1} errors or conflicts on devices ({2} in error, {3} in conflict).' -f (Format-TRN $bad.Count 'policy' 'policies'), (Select-TRText $bad.Count 'reports' 'report'), (Format-TRN $err 'device result' 'device results'), $con) $aff
}

Register-TRCheck -Id 'END-19' -Area 'Intune' -Category 'Windows security configuration' -Severity High -Effort 2 `
    -Title 'Windows LAPS policy manages local administrator passwords' `
    -Needs 'IntunePolicySettings', 'ManagedDevices' `
    -Recommendation 'In Endpoint security, Account protection, create a Local admin password solution (Windows LAPS) policy that backs up the password to Microsoft Entra ID, rotates it at least every 30 days and after use, and assign it to all Windows devices. Microsoft Entra LAPS must also be enabled in Entra device settings (IAM-25).' `
    -Reference 'https://learn.microsoft.com/intune/intune-service/protect/windows-laps-policy' `
    -Test {
    if (-not (Get-TRWindowsDeviceCount)) { return New-TRResult Info 'No Windows devices are managed.' }
    $all = Get-TRIntuneSettings -Like 'device_vendor_msft_laps_policies_*'
    $laps = @($all | Where-Object { $_.Assigned })
    if (-not $laps.Count) {
        if ($all.Count) { return New-TRResult Fail ('A LAPS policy exists ({0}) but is not assigned.' -f (Join-TRList (@($all | Select-Object -ExpandProperty Policy -Unique)) 3)) }
        return New-TRResult Fail 'No Windows LAPS policy is assigned, so local administrator passwords are not managed by Intune.'
    }
    $pols = @($laps | Select-Object -ExpandProperty Policy -Unique)
    $dir = @($laps | Where-Object { $_.Setting -eq 'device_vendor_msft_laps_policies_backupdirectory' } | ForEach-Object { Get-TRIntuneChoice $_.Value })
    $age = @($laps | Where-Object { $_.Setting -eq 'device_vendor_msft_laps_policies_passwordagedays_aad' -or $_.Setting -eq 'device_vendor_msft_laps_policies_passwordagedays' } | ForEach-Object { [int]$_.Value })
    $where = if ($dir -contains '1') { 'Microsoft Entra ID' } elseif ($dir -contains '2') { 'Active Directory' } elseif ($dir -contains '0') { 'nowhere (backup disabled)' } else { 'the default location' }
    $text = 'Assigned LAPS {0}: {1}. Passwords are backed up to {2}{3}.' -f (Select-TRText $pols.Count 'policy' 'policies'), (Join-TRList $pols 3), $where, $(if ($age.Count) { ', rotated every ' + (Format-TRN ($age | Measure-Object -Maximum).Maximum 'day') } else { '' })
    if ($dir -contains '0' -and -not ($dir -contains '1' -or $dir -contains '2')) { return New-TRResult Fail $text }
    if ($age.Count -and ($age | Measure-Object -Maximum).Maximum -gt 30) { return New-TRResult Warning $text }
    New-TRResult Pass $text
}

Register-TRCheck -Id 'END-20' -Area 'Intune' -Category 'Windows security configuration' -Severity High -Effort 3 `
    -Title 'BitLocker policy requires encryption and escrows recovery keys' `
    -Needs 'IntunePolicySettings', 'ManagedDevices' `
    -Recommendation 'In Endpoint security, Disk encryption, create a BitLocker policy that requires device encryption, uses silent encryption, and saves operating system drive recovery information to Microsoft Entra ID before encrypting. Assign it to all Windows devices.' `
    -Reference 'https://learn.microsoft.com/intune/intune-service/protect/encrypt-devices' `
    -Test {
    if (-not (Get-TRWindowsDeviceCount)) { return New-TRResult Info 'No Windows devices are managed.' }
    $req = @(Get-TRIntuneSettings -Like 'device_vendor_msft_bitlocker_requiredeviceencryption' -AssignedOnly | Where-Object { (Get-TRIntuneChoice $_.Value) -eq '1' })
    $legacy = @(Get-TRItems 'DeviceConfigurations' | Where-Object { [string]$_.'@odata.type' -match 'windows10EndpointProtectionConfiguration' -and $_.bitLockerEncryptDevice -eq $true -and @($_.assignments).Count })
    if (-not $req.Count -and -not $legacy.Count) { return New-TRResult Fail 'No assigned policy requires BitLocker encryption.' }
    $escrow = @(Get-TRIntuneSettings -Like '*bitlocker_systemdrivesrecoveryoptions_os*backup*' -AssignedOnly | Where-Object { (Get-TRIntuneChoice $_.Value) -in @('1', 'true') })
    $legacyEscrow = @($legacy | Where-Object { $_.bitLockerSystemDrivePolicy.recoveryOptions.enableRecoveryInformationSaveToStore -eq $true -or $_.bitLockerSystemDrivePolicy.recoveryOptions.blockDataRecoveryAgent -ne $null })
    $names = @(@($req | Select-Object -ExpandProperty Policy -Unique) + @($legacy | ForEach-Object { [string]$_.displayName }))
    if (-not $escrow.Count -and -not $legacyEscrow.Count) { return New-TRResult Warning ('BitLocker encryption is required (policy: {0}), but no assigned policy makes devices save recovery keys to Entra ID before encrypting.' -f (Join-TRList $names 3)) }
    New-TRResult Pass ('BitLocker encryption is required and recovery keys are escrowed (policy: {0}).' -f (Join-TRList $names 3))
}

Register-TRCheck -Id 'END-21' -Area 'Intune' -Category 'Windows security configuration' -Severity Medium -Effort 2 `
    -Title 'Windows Firewall is enforced on every profile' `
    -Needs 'IntunePolicySettings', 'ManagedDevices' `
    -Recommendation 'In Endpoint security, Firewall, create a Windows Firewall policy that turns the firewall on for the domain, private and public profiles, blocks inbound connections by default and stops local rules being merged on public networks. Assign it to all Windows devices.' `
    -Reference 'https://learn.microsoft.com/intune/intune-service/protect/endpoint-security-firewall-policy' `
    -Test {
    if (-not (Get-TRWindowsDeviceCount)) { return New-TRResult Info 'No Windows devices are managed.' }
    $on = @{}
    foreach ($prof in 'domain', 'private', 'public') {
        $rows = @(Get-TRIntuneSettings -Like ('vendor_msft_firewall_mdmstore_{0}profile_enablefirewall' -f $prof) -AssignedOnly)
        $on[$prof] = [bool]@($rows | Where-Object { (Get-TRIntuneChoice $_.Value) -eq 'true' }).Count
        if (@($rows | Where-Object { (Get-TRIntuneChoice $_.Value) -eq 'false' }).Count) { $on[$prof] = $false }
    }
    $legacy = @(Get-TRItems 'DeviceConfigurations' | Where-Object { [string]$_.'@odata.type' -match 'windows10EndpointProtectionConfiguration' -and @($_.assignments).Count -and ($_.firewallProfileDomain -or $_.firewallProfilePublic) })
    $missing = @('domain', 'private', 'public' | Where-Object { -not $on[$_] })
    if ($missing.Count -eq 3) {
        if ($legacy.Count) { return New-TRResult Warning ('Firewall settings come only from legacy endpoint protection profiles ({0}). Move them to an Endpoint security firewall policy.' -f (Join-TRList (@($legacy | ForEach-Object { [string]$_.displayName })) 3)) }
        return New-TRResult Fail 'No assigned policy turns on Windows Firewall.'
    }
    if ($missing.Count) { return New-TRResult Warning ('The firewall is not enforced for the {0} {1}.' -f (Join-TRList $missing 3), (Select-TRText $missing.Count 'profile' 'profiles')) }
    New-TRResult Pass 'Windows Firewall is enforced for the domain, private and public profiles.'
}

Register-TRCheck -Id 'END-22' -Area 'Intune' -Category 'Windows security configuration' -Severity High -Effort 4 `
    -Title 'Attack surface reduction rules are in block mode' `
    -Needs 'IntunePolicySettings', 'ManagedDevices' `
    -Recommendation 'Deploy the attack surface reduction rules from Endpoint security, Attack surface reduction. Put the three standard protection rules (vulnerable signed drivers, credential stealing from LSASS, persistence through WMI) into block mode straight away, run the others in audit mode for two to four weeks, review the audit events in Defender, then switch them to block.' `
    -Reference 'https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-deployment' `
    -Test {
    if (-not (Get-TRWindowsDeviceCount)) { return New-TRResult Info 'No Windows devices are managed.' }
    $rules = @(Get-TRAsrRules)
    if (-not $rules.Count) { return New-TRResult Fail 'No attack surface reduction rules are configured in an assigned policy.' }
    $best = @{}
    $rank = @{ block = 3; warn = 2; audit = 1; off = 0 }
    foreach ($r in $rules) { if (-not $best.ContainsKey($r.Rule) -or $rank[$r.Mode] -gt $rank[$best[$r.Rule].Mode]) { $best[$r.Rule] = $r } }
    $block = @($best.Values | Where-Object { $_.Mode -eq 'block' })
    $weak = @($best.Values | Where-Object { $_.Mode -ne 'block' } | Sort-Object Name)
    $std = @($script:TRAsrStandardRules | Where-Object { -not $best.ContainsKey($_) -or $best[$_].Mode -ne 'block' })
    $aff = @($weak | ForEach-Object { New-TRAffected $_.Name ('{0} ({1})' -f $_.Mode, $_.Policy) }) + @($std | Where-Object { -not $best.ContainsKey($_) } | ForEach-Object { New-TRAffected $script:TRAsrRuleNames[$_] 'Not configured' })
    $text = '{0} configured: {1} in block mode, {2} in audit, warn or off.' -f (Format-TRN $best.Count 'rule' 'rules'), $block.Count, $weak.Count
    if ($std.Count) { return New-TRResult Warning ($text + (' {0} of the three standard protection rules {1} not blocked.' -f $std.Count, (Select-TRText $std.Count 'is' 'are'))) $aff }
    if ($weak.Count) { return New-TRResult Warning $text $aff }
    New-TRResult Pass $text
}

Register-TRCheck -Id 'END-23' -Area 'Intune' -Category 'Windows security configuration' -Severity Medium -Effort 2 `
    -Title 'Microsoft Defender Antivirus protections are on' `
    -Needs 'IntunePolicySettings', 'ManagedDevices' `
    -Recommendation 'In the Endpoint security antivirus policy, keep real-time, behaviour and cloud-delivered protection on, set the cloud block level to High, block potentially unwanted apps, turn on network protection in block mode, and send safe samples automatically.' `
    -Reference 'https://learn.microsoft.com/defender-endpoint/configure-microsoft-defender-antivirus-features' `
    -Test {
    if (-not (Get-TRWindowsDeviceCount)) { return New-TRResult Info 'No Windows devices are managed.' }
    $p = 'device_vendor_msft_policy_config_defender_'
    $get = { param($n) @(Get-TRIntuneSettings -Like ($p + $n) -AssignedOnly | ForEach-Object { Get-TRIntuneChoice $_.Value }) }
    $av = @(Get-TRItems 'IntunePolicySettings' | Where-Object { $_.Assigned -and [string]$_.Setting -like ($p + '*') -and [string]$_.Setting -notlike ($script:TRAsrPrefix + '*') -and [string]$_.Setting -ne ($p + 'attacksurfacereductionrules') })
    if (-not $av.Count) { return New-TRResult Warning 'No assigned policy configures Microsoft Defender Antivirus, so devices use the Windows defaults (potentially unwanted app blocking and network protection are off by default).' }
    $off = @(); $gaps = @()
    foreach ($n in 'allowrealtimemonitoring', 'allowcloudprotection', 'allowbehaviormonitoring', 'allowioavprotection') { if ((& $get $n) -contains '0') { $off += $n } }
    $pua = & $get 'puaprotection'
    if ($pua -notcontains '1') { $gaps += $(if ($pua -contains '2') { 'potentially unwanted apps only audited' } else { 'potentially unwanted apps not blocked' }) }
    $np = & $get 'enablenetworkprotection'
    if ($np -notcontains '1') { $gaps += $(if ($np -contains '2') { 'network protection only in audit mode' } else { 'network protection not on' }) }
    $cbl = & $get 'cloudblocklevel'
    if ($cbl.Count -and -not @($cbl | Where-Object { $_ -in @('2', '4', '6') }).Count) { $gaps += 'cloud block level below High' }
    if ((& $get 'submitsamplesconsent') -contains '2') { $gaps += 'samples are never sent' }
    $names = @{ allowrealtimemonitoring = 'real-time protection'; allowcloudprotection = 'cloud-delivered protection'; allowbehaviormonitoring = 'behaviour monitoring'; allowioavprotection = 'scanning of downloads and attachments' }
    if ($off.Count) { return New-TRResult Fail ('These protections are turned off by policy: {0}.' -f (Join-TRList (@($off | ForEach-Object { $names[$_] })) 4)) }
    if ($gaps.Count) { return New-TRResult Warning ('Defender Antivirus gaps: {0}.' -f (Join-TRList $gaps 5)) }
    New-TRResult Pass 'Real-time and cloud protection are on, potentially unwanted apps are blocked and network protection is in block mode.'
}

Register-TRCheck -Id 'END-24' -Area 'Intune' -Category 'Windows security configuration' -Severity Medium -Effort 3 `
    -Title 'Windows Hello for Business is configured' `
    -Needs 'EnrollmentConfigurations', 'ManagedDevices' `
    -Recommendation 'Turn on Windows Hello for Business for Entra joined devices (Devices, Enrolment, Windows Hello for Business, or an Account protection policy) with a PIN of at least six digits and biometrics allowed, so users sign in with a phishing-resistant credential instead of a password.' `
    -Reference 'https://learn.microsoft.com/windows/security/identity-protection/hello-for-business/configure' `
    -Test {
    if (-not (Get-TRWindowsDeviceCount)) { return New-TRResult Info 'No Windows devices are managed.' }
    $w = @(Get-TRItems 'EnrollmentConfigurations' | Where-Object { [string]$_.'@odata.type' -match 'WindowsHelloForBusinessConfiguration' })
    $state = if ($w.Count) { [string](@($w | Sort-Object { [int]$_.priority })[0].state) } else { '' }
    $policy = @(Get-TRItems 'IntunePolicySettings' | Where-Object { $_.Assigned -and [string]$_.Setting -match 'passportforwork.*usepassportforwork$' -and (Get-TRIntuneChoice $_.Value) -eq 'true' })
    $off = @(Get-TRItems 'IntunePolicySettings' | Where-Object { $_.Assigned -and [string]$_.Setting -match 'passportforwork.*usepassportforwork$' -and (Get-TRIntuneChoice $_.Value) -eq 'false' })
    if ($off.Count -and -not $policy.Count) { return New-TRResult Warning ('Windows Hello for Business is turned off by {0}.' -f (Join-TRList (@($off | Select-Object -ExpandProperty Policy -Unique)) 3)) }
    if ($state -eq 'enabled' -or $policy.Count) { return New-TRResult Pass $(if ($policy.Count) { 'Enabled by ' + (Join-TRList (@($policy | Select-Object -ExpandProperty Policy -Unique)) 3) + '.' } else { 'Enabled in the tenant-wide enrolment setting.' }) }
    if ($state -eq 'disabled') { return New-TRResult Warning 'Windows Hello for Business is disabled in the tenant-wide enrolment setting.' }
    New-TRResult Warning 'Windows Hello for Business is not configured by Intune.'
}

Register-TRCheck -Id 'END-25' -Area 'Intune' -Category 'Windows security configuration' -Severity Medium -Effort 6 `
    -Title 'Security baselines are deployed and current' `
    -Needs 'ConfigurationPolicies', 'ManagedDevices' `
    -Recommendation 'Deploy the current Windows security baseline, and the Defender for Endpoint and Edge baselines where licensed, to a pilot group first and then to all Windows devices. When Microsoft releases a new baseline version, update the profile to it. Re-create baselines still in the old format.' `
    -Reference 'https://learn.microsoft.com/intune/intune-service/protect/security-baselines' `
    -Test {
    if (-not (Get-TRWindowsDeviceCount)) { return New-TRResult Info 'No Windows devices are managed.' }
    $bases = @(Get-TRItems 'ConfigurationPolicies' | Where-Object { [string]$_.templateReference.templateFamily -eq 'baseline' })
    $assigned = @($bases | Where-Object { @($_.assignments).Count -gt 0 })
    $tpl = @(Get-TRItems 'IntuneBaselineTemplates')
    $old = @()
    foreach ($b in $assigned) {
        $id = [string]$b.templateReference.templateId
        $t = @($tpl | Where-Object { [string]$_.id -eq $id })[0]
        if (-not $t) { continue }
        $newer = @($tpl | Where-Object { [string]$_.baseId -eq [string]$t.baseId -and [int]$_.version -gt [int]$t.version -and [string]$_.lifecycleState -eq 'active' } | Sort-Object { [int]$_.version } -Descending)
        if ($newer.Count -or [string]$t.lifecycleState -in @('deprecated', 'superseded', 'retired')) {
            $old += (New-TRAffected ([string]$b.name) ('{0} {1}{2}' -f $b.templateReference.templateDisplayName, $b.templateReference.templateDisplayVersion, $(if ($newer.Count) { '; newer version ' + [string]$newer[0].displayVersion } else { '; ' + [string]$t.lifecycleState })))
        }
    }
    $legacy = @(Get-TRItems 'Intents' | Where-Object { $_.isAssigned -eq $true })
    $legTpl = @{}
    foreach ($t in (Get-TRItems 'IntuneIntentTemplates')) { $legTpl[[string]$t.id] = $t }
    $legBase = @($legacy | Where-Object { $t = $legTpl[[string]$_.templateId]; $t -and ([string]$t.templateType -match 'Baseline') })
    foreach ($l in $legBase) { $old += (New-TRAffected ([string]$l.displayName) ('Old-format baseline ({0})' -f $legTpl[[string]$l.templateId].displayName)) }
    if (-not $assigned.Count -and -not $legBase.Count) { return New-TRResult Warning $(if ($bases.Count) { 'Security baseline profiles exist but none is assigned.' } else { 'No security baseline is deployed.' }) }
    $names = @(@($assigned | ForEach-Object { [string]$_.templateReference.templateDisplayName }) | Select-Object -Unique)
    if ($old.Count) { return New-TRResult Warning ('{0} {1} on an old version or format.' -f (Format-TRN $old.Count 'assigned baseline' 'assigned baselines'), (Select-TRText $old.Count 'is' 'are')) $old }
    New-TRResult Pass ('Assigned and current: {0}.' -f (Join-TRList $names 4))
}

Register-TRCheck -Id 'END-26' -Area 'Intune' -Category 'Autopilot and enrolment' -Severity Medium -Effort 2 `
    -Title 'Autopilot profiles are assigned and users are not local administrators' `
    -Needs 'AutopilotDevices', 'AutopilotProfiles' `
    -Recommendation 'Assign an Autopilot deployment profile to every registered device (for example through a dynamic group on the group tag or ZTDId), set the user account type to Standard so users are not local administrators, and use Microsoft Entra join rather than hybrid join for new devices.' `
    -Reference 'https://learn.microsoft.com/autopilot/profiles' `
    -Test {
    $devs = @(Get-TRItems 'AutopilotDevices')
    $profs = @(Get-TRItems 'AutopilotProfiles')
    if (-not $devs.Count -and -not $profs.Count) { return New-TRResult Info 'Windows Autopilot is not in use.' }
    $issues = @()
    foreach ($p in $profs) {
        if ((Test-TRHasProperty $p 'assignments') -and -not @($p.assignments).Count) { $issues += (New-TRAffected ([string]$p.displayName) 'Profile is not assigned') }
        if ([string]$p.outOfBoxExperienceSettings.userType -eq 'administrator' -or [string]$p.outOfBoxExperienceSetting.userType -eq 'administrator') { $issues += (New-TRAffected ([string]$p.displayName) 'Users become local administrators') }
        if ([string]$p.'@odata.type' -match 'activeDirectory') { $issues += (New-TRAffected ([string]$p.displayName) 'Hybrid Entra join profile') }
    }
    $noProf = @($devs | Where-Object { [string]$_.deploymentProfileAssignmentStatus -in @('notAssigned', 'failed') })
    if ($noProf.Count) { $issues += @($noProf | Select-Object -First 200 | ForEach-Object { New-TRAffected ([string]$_.serialNumber) ('{0}; profile {1}' -f $_.model, $_.deploymentProfileAssignmentStatus) }) }
    if (-not $profs.Count -and $devs.Count) { return New-TRResult Warning ('{0} registered but there is no deployment profile.' -f (Format-TRN $devs.Count 'Autopilot device is' 'Autopilot devices are')) }
    $admins = @($issues | Where-Object { $_.Detail -eq 'Users become local administrators' })
    $text = '{0}; {1}.' -f (Format-TRN $devs.Count 'registered device'), (Format-TRN $profs.Count 'deployment profile')
    if ($noProf.Count) { $text += (' {0} no profile.' -f (Format-TRN $noProf.Count 'device has' 'devices have')) }
    if ($admins.Count) { return New-TRResult Warning ($text + (' {0} {1} users local administrators.' -f (Format-TRN $admins.Count 'profile'), (Select-TRText $admins.Count 'makes' 'make'))) $issues }
    if ($issues.Count) { return New-TRResult Warning $text $issues }
    New-TRResult Pass ($text + ' All devices have a profile and users are standard users.')
}

Register-TRCheck -Id 'END-27' -Area 'Intune' -Category 'Autopilot and enrolment' -Severity Medium -Effort 2 `
    -Title 'Enrolment Status Page holds users until setup completes' `
    -Needs 'EnrollmentConfigurations', 'AutopilotDevices' `
    -Recommendation 'Turn on the Enrolment Status Page for Autopilot devices with Show app and profile configuration progress, block device use until required apps and security policies are installed, and allow a reset on failure. Without it users reach the desktop before BitLocker, Defender and other policies apply.' `
    -Reference 'https://learn.microsoft.com/intune/intune-service/enrollment/windows-enrollment-status' `
    -Test {
    $ap = @(Get-TRItems 'AutopilotDevices')
    $esp = @(Get-TRItems 'EnrollmentConfigurations' | Where-Object { [string]$_.'@odata.type' -match 'EnrollmentCompletionPageConfiguration' })
    if (-not $ap.Count) { return New-TRResult Info 'No Autopilot devices are registered.' }
    $on = @($esp | Where-Object { $_.showInstallationProgress -eq $true })
    if (-not $on.Count) { return New-TRResult Warning 'The Enrolment Status Page is off, so users reach the desktop before apps and security policies are installed.' }
    $block = @($on | Where-Object { $_.blockDeviceSetupRetryByUser -eq $true -or $_.allowDeviceUseOnInstallFailure -eq $false -or @($_.selectedMobileAppIds).Count })
    $names = Join-TRList (@($on | ForEach-Object { [string]$_.displayName })) 3
    if (-not $block.Count) { return New-TRResult Warning ('The Enrolment Status Page shows progress ({0}) but does not block use until required apps are installed.' -f $names) }
    New-TRResult Pass ('The Enrolment Status Page is on: {0}.' -f $names)
}

Register-TRCheck -Id 'END-28' -Area 'Intune' -Category 'Intune configuration health' -Severity Medium -Effort 3 `
    -Title 'Required apps install successfully' `
    -Needs 'IntuneAppInstall' `
    -Recommendation 'Open each listed app in Intune (Apps, Monitor, App install status), check the error codes on the failed devices, and fix the package, detection rule or requirement rules.' `
    -Reference 'https://learn.microsoft.com/intune/intune-service/apps/troubleshoot-app-install' `
    -Test {
    $apps = @(Get-TRItems 'IntuneAppInstall')
    if (-not $apps.Count) { return New-TRResult Info 'No required app assignments were found.' }
    $bad = @($apps | Where-Object { [int]$_.Failed -gt 0 } | Sort-Object { -[int]$_.Failed })
    if (-not $bad.Count) { return New-TRResult Pass ('All {0} install without failures.' -f (Format-TRN $apps.Count 'required app')) }
    New-TRResult Warning ('{0} of {1} required apps {3} failed installs ({2} device failures in total).' -f $bad.Count, $apps.Count, ($bad | Measure-Object -Property Failed -Sum).Sum, (Select-TRText $bad.Count 'has' 'have')) @($bad | ForEach-Object { New-TRAffected $_.App ('{0} failed, {1} installed, {2} pending; {3}' -f $_.Failed, $_.Installed, $_.Pending, $_.Type) })
}

Register-TRCheck -Id 'END-29' -Area 'Intune' -Category 'Intune configuration health' -Severity Low -Effort 0.5 `
    -Title 'Device clean-up rule removes inactive devices' `
    -Needs 'IntuneCleanupRules' `
    -Recommendation 'In Devices, Device clean-up rules, remove devices that have not checked in for 90 to 180 days, so stale records do not skew compliance reports and licence counts.' `
    -Reference 'https://learn.microsoft.com/intune/intune-service/remote-actions/devices-wipe#automatically-hide-devices-with-cleanup-rules' `
    -Test {
    $rules = @(Get-TRItems 'IntuneCleanupRules' | Where-Object { [int]$_.deviceInactivityBeforeRetirementInDays -gt 0 })
    if (-not $rules.Count) { return New-TRResult Warning 'No device clean-up rule is set, so devices that stop checking in stay in Intune indefinitely.' }
    $d = ($rules | Measure-Object -Property deviceInactivityBeforeRetirementInDays -Maximum).Maximum
    $text = 'Devices are removed after {0} without check-in.' -f (Format-TRN ([int]$d) 'day')
    if ([int]$d -gt 270) { return New-TRResult Warning $text }
    New-TRResult Pass $text
}

Register-TRCheck -Id 'END-30' -Area 'Intune' -Category 'Compliance' -Severity Medium -Effort 2 `
    -Title 'Windows compliance policy checks the essentials' `
    -Needs 'CompliancePolicies', 'ManagedDevices' `
    -Recommendation 'Make the assigned Windows compliance policy require BitLocker, Secure Boot, code integrity, a TPM, a minimum OS version, an active firewall and antivirus, and the Defender for Endpoint machine risk score where licensed, so Conditional Access only allows healthy devices.' `
    -Reference 'https://learn.microsoft.com/intune/intune-service/protect/compliance-policy-create-windows' `
    -Test {
    if (-not (Get-TRWindowsDeviceCount)) { return New-TRResult Info 'No Windows devices are managed.' }
    $pols = @(Get-TRItems 'CompliancePolicies' | Where-Object { [string]$_.'@odata.type' -match 'windows10CompliancePolicy' -and @($_.assignments).Count -gt 0 })
    if (-not $pols.Count) { return New-TRResult Fail 'No Windows compliance policy is assigned (see END-01).' }
    $req = [ordered]@{
        'BitLocker'                 = { param($p) $p.bitLockerEnabled -eq $true }
        'Secure Boot'               = { param($p) $p.secureBootEnabled -eq $true }
        'code integrity'            = { param($p) $p.codeIntegrityEnabled -eq $true }
        'TPM'                       = { param($p) $p.tpmRequired -eq $true }
        'minimum OS version'        = { param($p) [bool][string]$p.osMinimumVersion }
        'firewall'                  = { param($p) $p.activeFirewallRequired -eq $true }
        'antivirus'                 = { param($p) $p.antivirusRequired -eq $true -or $p.defenderEnabled -eq $true }
        'Defender for Endpoint risk' = { param($p) $p.deviceThreatProtectionEnabled -eq $true }
    }
    $missing = @($req.Keys | Where-Object { $k = $_; -not @($pols | Where-Object { & $req[$k] $_ }).Count })
    $names = Join-TRList (@($pols | ForEach-Object { [string]$_.displayName })) 3
    if (-not $missing.Count) { return New-TRResult Pass ('{0} requires all the essentials.' -f $names) }
    $crit = @($missing | Where-Object { $_ -in @('BitLocker', 'Secure Boot', 'minimum OS version') })
    $status = if ($crit.Count -ge 2) { 'Fail' } else { 'Warning' }
    New-TRResult $status ('{0} does not require: {1}.' -f $names, (Join-TRList $missing 8)) @($missing | ForEach-Object { New-TRAffected $_ 'Not required by any assigned Windows compliance policy' })
}

Register-TRCheck -Id 'END-31' -Area 'Intune' -Category 'Compliance' -Severity Medium -Effort 2 `
    -Title 'Mobile compliance policies require a passcode and block jailbroken devices' `
    -Needs 'CompliancePolicies', 'ManagedDevices' `
    -Recommendation 'Make the assigned iOS/iPadOS and Android compliance policies require a device passcode, block jailbroken or rooted devices (and require Play Integrity on Android), and set a minimum OS version.' `
    -Reference 'https://learn.microsoft.com/intune/intune-service/protect/compliance-policy-create-ios' `
    -Test {
    $devs = @(Get-TRItems 'ManagedDevices')
    $out = @()
    $plat = @(
        @{ Name = 'iOS/iPadOS'; Os = 'iOS|iPadOS'; Type = 'iosCompliancePolicy'; Pass = 'passcodeRequired'; Jail = 'securityBlockJailbrokenDevices' },
        @{ Name = 'Android'; Os = 'Android'; Type = 'android\w*CompliancePolicy|aosp'; Pass = 'passwordRequired'; Jail = 'securityBlockJailbrokenDevices' }
    )
    $any = $false
    foreach ($pl in $plat) {
        if (-not @($devs | Where-Object { [string]$_.operatingSystem -match $pl.Os }).Count) { continue }
        $any = $true
        $pols = @(Get-TRItems 'CompliancePolicies' | Where-Object { [string]$_.'@odata.type' -match $pl.Type -and @($_.assignments).Count -gt 0 })
        if (-not $pols.Count) { $out += (New-TRAffected $pl.Name 'No assigned compliance policy'); continue }
        $gaps = @()
        if (-not @($pols | Where-Object { $_.($pl.Pass) -eq $true -or $_.workProfilePasswordRequired -eq $true }).Count) { $gaps += 'passcode' }
        if (-not @($pols | Where-Object { $_.($pl.Jail) -eq $true -or $_.securityRequireSafetyNetAttestationBasicIntegrity -eq $true -or [string]$_.securityRequiredAndroidSafetyNetEvaluationType }).Count) { $gaps += 'jailbreak or root detection' }
        if (-not @($pols | Where-Object { [string]$_.osMinimumVersion }).Count) { $gaps += 'minimum OS version' }
        if ($gaps.Count) { $out += (New-TRAffected $pl.Name ('Not required: ' + ($gaps -join ', '))) }
    }
    if (-not $any) { return New-TRResult Info 'No iOS, iPadOS or Android devices are managed.' }
    if ($out.Count) { return New-TRResult Warning ('Gaps for {0}.' -f (Join-TRList (@($out | ForEach-Object { $_.Item })) 2)) $out }
    New-TRResult Pass 'Mobile compliance policies require a passcode, block jailbroken or rooted devices and set a minimum OS version.'
}

Register-TRCheck -Id 'END-32' -Area 'Intune' -Category 'Compliance' -Severity Low -Effort 0.5 `
    -Title 'Devices that stop checking in become non-compliant within 30 days' `
    -Needs 'DeviceManagement' `
    -Recommendation 'In Endpoint security, Device compliance, Compliance policy settings, keep the compliance status validity period at 30 days or less so devices that stop checking in lose access.' `
    -Reference 'https://learn.microsoft.com/intune/intune-service/protect/device-compliance-get-started#compliance-policy-settings' `
    -Test {
    $s = (Get-TRRawValue 'DeviceManagement').settings
    $d = [int]$s.deviceComplianceCheckinThresholdDays
    if (-not $d) { return New-TRResult Info 'The compliance status validity period was not returned.' }
    if ($d -gt 30) { return New-TRResult Warning ('Devices stay compliant for {0} without checking in.' -f (Format-TRN $d 'day')) }
    New-TRResult Pass ('Devices that do not check in for {0} become non-compliant.' -f (Format-TRN $d 'day'))
}
