$script:TROppDefs = New-Object System.Collections.ArrayList

$script:TROppStatus = [ordered]@{
    NotUsed       = 'Not used'
    Partial       = 'Partly used'
    Verify        = 'Check in portal'
    NotAssessed   = 'Not assessed'
    InUse         = 'In use'
    NotApplicable = 'Not applicable'
    NotLicensed   = 'Not licensed'
}

function Register-TROpportunity {
    param(
        [string]$Id,
        [string]$Category,
        [string]$Feature,
        [string[]]$Plans,
        [string[]]$AlsoRequires = @(),
        [string[]]$Needs = @(),
        [string]$Opportunity,
        [string]$Benefit,
        [double]$EffortDays,
        [string]$Reference,
        [scriptblock]$Evidence,
        [ValidateSet('Microsoft', 'Google')][string]$Platform = 'Microsoft'
    )
    [void]$script:TROppDefs.Add([pscustomobject]@{
            Id = $Id; Category = $Category; Feature = $Feature; Plans = $Plans; AlsoRequires = $AlsoRequires; Needs = $Needs
            Opportunity = $Opportunity; Benefit = $Benefit; EffortDays = $EffortDays; Reference = $Reference; Evidence = $Evidence; Platform = $Platform
        })
}

function New-TROppResult {
    param(
        [ValidateSet('NotUsed', 'Partial', 'InUse', 'NotApplicable', 'Verify', 'NotAssessed', 'NotLicensed')][string]$Status,
        [string]$Evidence
    )
    [pscustomobject]@{ Status = $Status; Evidence = $Evidence }
}

function Get-TROppStatusLabel {
    param([string]$Status)
    $l = $script:TROppStatus[$Status]
    if ($l) { return $l }
    $Status
}

function Get-TROppPeople {
    $plans = @($script:TROppPlans)
    $index = Get-TRUserPlanIndex
    @(Get-TRPeople | Where-Object {
            $set = $index[[string]$_.id]
            $hit = $false
            if ($set) { foreach ($p in $plans) { if ($set.ContainsKey($p)) { $hit = $true; break } } }
            $hit
        })
}

function Get-TRActivityShare {
    param([string]$LicenceColumn, [string]$ActivityColumn, [int]$Days = 30)
    $rows = @(Get-TRItems 'ActiveUserDetail' | Where-Object { [string]$_.'Is Deleted' -ne 'True' -and [string]$_.$LicenceColumn -eq 'True' })
    $active = @($rows | Where-Object { $d = Get-TRDaysSince $_.$ActivityColumn; $null -ne $d -and $d -le $Days }).Count
    [pscustomobject]@{ Licensed = $rows.Count; Active = $active; Percent = (Get-TRPercent $active $rows.Count) }
}

function Get-TRAdoptionResult {
    param($Share, [string]$Workload)
    $text = '{0} of {1} licensed users were active in {2} in the last 30 days ({3}%).' -f $Share.Active, $Share.Licensed, $Workload, $Share.Percent
    if ($Share.Licensed -eq 0) { return New-TROppResult NotAssessed 'The usage report returned no licensed users.' }
    if ($Share.Percent -ge 70) { return New-TROppResult InUse $text }
    if ($Share.Active -eq 0 -or $Share.Percent -lt 20) { return New-TROppResult NotUsed $text }
    New-TROppResult Partial $text
}

function Get-TRMdeReference {
    if (Test-TRCollected @('ManagedDevices')) {
        return [pscustomobject]@{ Count = @(Get-TRItems 'ManagedDevices' | Where-Object { [string]$_.operatingSystem -match '^(Windows|macOS)' }).Count; Label = 'Intune managed Windows and macOS devices' }
    }
    if (Test-TRCollected @('Devices')) {
        $stale = [int](Get-TRSetting 'StaleDeviceDays' 180)
        $n = @(Get-TRItems 'Devices' | Where-Object { $d = Get-TRDaysSince $_.approximateLastSignInDateTime; [string]$_.operatingSystem -match '^(Windows|Mac)' -and $_.accountEnabled -eq $true -and $null -ne $d -and $d -le $stale }).Count
        return [pscustomobject]@{ Count = $n; Label = 'active Entra ID Windows and macOS devices' }
    }
    $null
}

Register-TROpportunity -Id 'OPP-01' -Category 'Identity and access' -Feature 'Conditional Access' `
    -Plans $script:TRPlanSets.P1 -Needs 'ConditionalAccessPolicies', 'SecurityDefaults' -EffortDays 2 `
    -Opportunity 'Replace security defaults with a Conditional Access baseline: MFA for all users, block legacy authentication, phishing-resistant MFA for admins, compliant devices for corporate data and tighter controls for guests, with emergency access accounts excluded.' `
    -Benefit 'Granular, auditable access control that security defaults cannot provide, without blocking legitimate users.' `
    -Reference 'https://learn.microsoft.com/entra/identity/conditional-access/plan-conditional-access' `
    -Evidence {
    param($Users)
    $en = @(Get-TRCaPolicies)
    $ro = @(Get-TRCaPolicies -State 'enabledForReportingButNotEnforced')
    $sd = Get-TRRawValue 'SecurityDefaults'
    $sdOn = ($sd -and $sd.isEnabled -eq $true)
    $mfaAll = @($en | Where-Object { (Test-TRCaAllUsers $_) -and (Test-TRCaMfa $_) })
    $text = 'Enabled policies: {0}; report-only: {1}; security defaults: {2}.' -f $en.Count, $ro.Count, $(if ($sdOn) { 'on' } else { 'off' })
    if (-not $en.Count) { return New-TROppResult NotUsed $text }
    if ($mfaAll.Count -and $en.Count -ge 3) { return New-TROppResult InUse $text }
    New-TROppResult Partial ($text + ' No full baseline (MFA for all users plus supporting policies).')
}

Register-TROpportunity -Id 'OPP-02' -Category 'Identity and access' -Feature 'Self-service password reset' `
    -Plans $script:TRPlanSets.P1 -Needs 'RegistrationDetails', 'Users' -EffortDays 0.5 `
    -Opportunity 'Enable self-service password reset for all users with combined MFA and SSPR registration, password writeback for synced accounts and admin notifications.' `
    -Benefit 'Fewer password reset calls to the service desk and faster recovery for users out of hours.' `
    -Reference 'https://learn.microsoft.com/entra/identity/authentication/tutorial-enable-sspr' `
    -Evidence {
    param($Users)
    $people = @(Get-TROppPeople)
    $reg = Get-TRRegIndex
    $enabled = @($people | Where-Object { $r = $reg[[string]$_.id]; $r -and $r.isSsprEnabled -eq $true }).Count
    $registered = @($people | Where-Object { $r = $reg[[string]$_.id]; $r -and $r.isSsprRegistered -eq $true }).Count
    $text = 'Enabled for SSPR: {0} of {1} licensed users; registered: {2}.' -f $enabled, $people.Count, $registered
    if (-not $enabled) { return New-TROppResult NotUsed $text }
    if ((Get-TRPercent $enabled $people.Count) -lt 80 -or $registered -lt ($enabled / 2)) { return New-TROppResult Partial $text }
    New-TROppResult InUse $text
}

Register-TROpportunity -Id 'OPP-03' -Category 'Identity and access' -Feature 'Dynamic groups' `
    -Plans $script:TRPlanSets.P1 -Needs 'Groups' -EffortDays 0.5 `
    -Opportunity 'Create dynamic groups for departments, locations and device platforms so licences, Intune policies, Teams and app access follow joiners, movers and leavers automatically.' `
    -Benefit 'Less manual administration and fewer access mistakes when staff change roles.' `
    -Reference 'https://learn.microsoft.com/entra/identity/users/groups-dynamic-membership' `
    -Evidence {
    param($Users)
    $dyn = @(Get-TRItems 'Groups' | Where-Object { $_.membershipRule })
    $text = 'Dynamic membership groups: {0}.' -f $dyn.Count
    if ($dyn.Count) { return New-TROppResult InUse $text }
    New-TROppResult NotUsed $text
}

Register-TROpportunity -Id 'OPP-04' -Category 'Identity and access' -Feature 'Identity Protection risk-based policies' `
    -Plans $script:TRPlanSets.P2 -Needs 'ConditionalAccessPolicies' -EffortDays 0.5 `
    -Opportunity 'Turn on risk-based Conditional Access: require a secure password change for high user risk and MFA for medium and high sign-in risk, with risky user alerts sent to the IT provider.' `
    -Benefit 'Automatically contains compromised accounts using Microsoft threat intelligence, often before a human would notice.' `
    -Reference 'https://learn.microsoft.com/entra/id-protection/howto-identity-protection-configure-risk-policies' `
    -Evidence {
    param($Users)
    $en = @(Get-TRCaPolicies)
    $userRisk = @($en | Where-Object { @($_.conditions.userRiskLevels | Where-Object { $_ }).Count })
    $signInRisk = @($en | Where-Object { @($_.conditions.signInRiskLevels | Where-Object { $_ }).Count })
    $text = 'Enabled user risk policies: {0}; sign-in risk policies: {1}.' -f $userRisk.Count, $signInRisk.Count
    if ($userRisk.Count -and $signInRisk.Count) { return New-TROppResult InUse $text }
    if ($userRisk.Count -or $signInRisk.Count) { return New-TROppResult Partial $text }
    New-TROppResult NotUsed $text
}

Register-TROpportunity -Id 'OPP-05' -Category 'Identity and access' -Feature 'Privileged Identity Management' `
    -Plans $script:TRPlanSets.P2 -Needs 'RoleAssignments', 'RoleEligibility' -EffortDays 1 `
    -Opportunity 'Move standing administrator roles to just-in-time PIM eligibility with MFA and justification on activation, approval for Global Administrator, and alerts on activation.' `
    -Benefit 'Admin accounts hold no standing privilege, which limits the damage from a compromised account.' `
    -Reference 'https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-deployment-plan' `
    -Evidence {
    param($Users)
    $rows = @(Get-TRRoleRows)
    $eligible = @($rows | Where-Object { $_.Assignment -eq 'Eligible' }).Count
    $standing = @($rows | Where-Object { $_.Assignment -eq 'Active' -and $_.Privileged -and $_.PrincipalType -eq 'user' } | Select-Object -ExpandProperty PrincipalId -Unique).Count
    $text = 'Eligible role assignments: {0}; users with standing privileged roles: {1}.' -f $eligible, $standing
    if (-not $eligible) { return New-TROppResult NotUsed $text }
    if ($standing -gt 2) { return New-TROppResult Partial $text }
    New-TROppResult InUse $text
}

Register-TROpportunity -Id 'OPP-06' -Category 'Identity and access' -Feature 'Access reviews' `
    -Plans $script:TRPlanSets.P2 -Needs 'AccessReviews' -EffortDays 0.5 `
    -Opportunity 'Set up recurring access reviews for guest users, privileged roles and Microsoft 365 groups, with access removed automatically when it is not confirmed.' `
    -Benefit 'Evidence for audits and insurers that access is reviewed, and stale guest and group access cleaned up.' `
    -Reference 'https://learn.microsoft.com/entra/id-governance/deploy-access-reviews' `
    -Evidence {
    param($Users)
    $n = @(Get-TRItems 'AccessReviews').Count
    $text = 'Access review definitions: {0}.' -f $n
    if ($n) { return New-TROppResult InUse $text }
    New-TROppResult NotUsed $text
}

Register-TROpportunity -Id 'OPP-07' -Category 'Devices and endpoints' -Feature 'Intune device management' `
    -Plans $script:TRPlanSets.Intune -Needs 'ManagedDevices' -EffortDays 5 `
    -Opportunity 'Enrol corporate Windows devices (Autopilot or Entra join) and mobiles in Intune, with compliance policies, security baselines, BitLocker, Windows LAPS and app deployment.' `
    -Benefit 'Consistent, provable device security and remote wipe for lost or stolen devices.' `
    -Reference 'https://learn.microsoft.com/intune/intune-service/fundamentals/deployment-guide-intune-setup' `
    -Evidence {
    param($Users)
    $devs = @(Get-TRItems 'ManagedDevices')
    $desk = @($devs | Where-Object { [string]$_.operatingSystem -match '^(Windows|macOS)' }).Count
    $mob = $devs.Count - $desk
    $comp = @(Get-TRItems 'CompliancePolicies' | Where-Object { @($_.assignments).Count -gt 0 }).Count
    $text = 'Managed devices: {0} ({1} Windows or macOS, {2} mobile) for {3} licensed users; assigned compliance policies: {4}.' -f $devs.Count, $desk, $mob, $Users, $comp
    if (-not $devs.Count) { return New-TROppResult NotUsed $text }
    if ($desk -lt ($Users * 0.5) -or -not $comp) { return New-TROppResult Partial $text }
    New-TROppResult InUse $text
}

Register-TROpportunity -Id 'OPP-08' -Category 'Devices and endpoints' -Feature 'Windows Autopilot' `
    -Plans $script:TRPlanSets.Intune -Needs 'AutopilotDevices', 'ManagedDevices' -EffortDays 2 `
    -Opportunity 'Register devices with Autopilot (through the supplier or by hardware hash) and build Autopilot profiles and an Enrollment Status Page so new and rebuilt laptops are ready for users without imaging.' `
    -Benefit 'Zero-touch provisioning that ships laptops straight to users and cuts build time.' `
    -Reference 'https://learn.microsoft.com/autopilot/overview' `
    -Evidence {
    param($Users)
    $ap = @(Get-TRItems 'AutopilotDevices').Count
    $corp = @(Get-TRItems 'ManagedDevices' | Where-Object { [string]$_.operatingSystem -match '^Windows' -and [string]$_.managedDeviceOwnerType -eq 'company' }).Count
    $text = 'Autopilot registered devices: {0}; corporate Windows devices in Intune: {1}.' -f $ap, $corp
    if (-not $ap) { return New-TROppResult NotUsed $text }
    if ($corp -and $ap -lt ($corp * 0.5)) { return New-TROppResult Partial $text }
    New-TROppResult InUse $text
}

Register-TROpportunity -Id 'OPP-09' -Category 'Devices and endpoints' -Feature 'Device-based Conditional Access' `
    -Plans $script:TRPlanSets.Intune -AlsoRequires $script:TRPlanSets.P1 -Needs 'ConditionalAccessPolicies' -EffortDays 1.5 `
    -Opportunity 'Require a compliant or hybrid-joined device for access to email and files from desktops, and app protection on mobiles, so corporate data only reaches managed devices.' `
    -Benefit 'Stolen passwords alone cannot be used to download company data to an unmanaged computer.' `
    -Reference 'https://learn.microsoft.com/entra/identity/conditional-access/policy-all-users-device-compliance' `
    -Evidence {
    param($Users)
    $p = @(Get-TRCaPolicies | Where-Object { $c = @($_.grantControls.builtInControls); ($c -contains 'compliantDevice') -or ($c -contains 'domainJoinedDevice') })
    $all = @($p | Where-Object { Test-TRCaAllUsers $_ })
    $text = 'Enabled policies requiring a compliant or joined device: {0} ({1} for all users).' -f $p.Count, $all.Count
    if ($all.Count) { return New-TROppResult InUse $text }
    if ($p.Count) { return New-TROppResult Partial $text }
    New-TROppResult NotUsed $text
}

Register-TROpportunity -Id 'OPP-10' -Category 'Devices and endpoints' -Feature 'App protection for mobiles' `
    -Plans $script:TRPlanSets.Intune -Needs 'IosAppProtection', 'AndroidAppProtection' -EffortDays 1 `
    -Opportunity 'Protect Outlook, Teams and OneDrive on phones with app protection policies (PIN, no copy to personal apps, selective wipe) without enrolling personal devices.' `
    -Benefit 'Supports bring-your-own phones while keeping company data contained.' `
    -Reference 'https://learn.microsoft.com/intune/intune-service/apps/app-protection-policy' `
    -Evidence {
    param($Users)
    $ios = @(Get-TRItems 'IosAppProtection' | Where-Object { @($_.assignments).Count -gt 0 }).Count
    $and = @(Get-TRItems 'AndroidAppProtection' | Where-Object { @($_.assignments).Count -gt 0 }).Count
    $text = 'Assigned app protection policies: iOS {0}, Android {1}.' -f $ios, $and
    if ($ios -and $and) { return New-TROppResult InUse $text }
    if ($ios -or $and) { return New-TROppResult Partial $text }
    New-TROppResult NotUsed $text
}

Register-TROpportunity -Id 'OPP-11' -Category 'Devices and endpoints' -Feature 'Defender for Endpoint or Defender for Business' `
    -Plans $script:TRPlanSets.DefenderEndpoint -Needs 'DefenderDevices' -EffortDays 3 `
    -Opportunity 'Onboard all Windows, macOS and server endpoints through Intune, configure next-generation protection, attack surface reduction rules, EDR in block mode and automated investigation, and route alerts to the IT provider monitoring.' `
    -Benefit 'Endpoint detection and response that can stop ransomware, often replacing a separately licensed antivirus product.' `
    -Reference 'https://learn.microsoft.com/defender-business/mdb-setup-configuration' `
    -Evidence {
    param($Users)
    if ((Get-TRMeta 'DefenderNotProvisioned') -eq $true) { return New-TROppResult NotUsed 'Licensed, but Defender for Endpoint has never been set up in this tenant. No devices are onboarded.' }
    $onb = @(Get-TRMdeOnboarded).Count
    $ref = Get-TRMdeReference
    if ($ref -and $ref.Count) {
        $pct = Get-TRPercent ([Math]::Min($onb, $ref.Count)) $ref.Count
        $text = 'Onboarded devices: {0}; {1}: {2} ({3}% coverage).' -f $onb, $ref.Label, $ref.Count, $pct
    }
    else { $pct = $(if ($onb) { 100 } else { 0 }); $text = 'Onboarded devices: {0}.' -f $onb }
    if (-not $onb) { return New-TROppResult NotUsed $text }
    if ($pct -lt 80) { return New-TROppResult Partial $text }
    New-TROppResult InUse $text
}

Register-TROpportunity -Id 'OPP-12' -Category 'Devices and endpoints' -Feature 'Defender for Identity' `
    -Plans $script:TRPlanSets.DefenderIdentity -EffortDays 1 `
    -Opportunity 'Install Defender for Identity sensors on domain controllers (and AD FS or AD CS servers) to detect credential theft, lateral movement and reconnaissance in on-premises Active Directory.' `
    -Benefit 'Visibility of attacks against Active Directory, the most common route to a full ransomware compromise.' `
    -Reference 'https://learn.microsoft.com/defender-for-identity/deploy/deploy-defender-identity' `
    -Evidence {
    param($Users)
    $org = Get-TRRawValue 'Organization'
    $hybrid = ($org -and $org.onPremisesSyncEnabled -eq $true) -or @(Get-TRItems 'Users' | Where-Object { $_.onPremisesSyncEnabled -eq $true } | Select-Object -First 1).Count
    if (-not $hybrid) { return New-TROppResult NotApplicable 'Cloud-only directory, so there is no on-premises Active Directory to protect.' }
    if (-not (Test-TRCollected @('DefenderIdentitySensors'))) { return New-TROppResult Verify ('Directory sync is on, but sensor status could not be read. ' + (Get-TRMissingReason @('DefenderIdentitySensors'))) }
    $s = @(Get-TRItems 'DefenderIdentitySensors')
    $text = 'Directory sync is on. Defender for Identity sensors: {0}.' -f $s.Count
    if ($s.Count) { return New-TROppResult InUse $text }
    New-TROppResult NotUsed $text
}

Register-TROpportunity -Id 'OPP-13' -Category 'Devices and endpoints' -Feature 'Defender for Cloud Apps' `
    -Plans $script:TRPlanSets.DefenderCloudApps -EffortDays 2 `
    -Opportunity 'Connect Microsoft 365 and key SaaS apps to Defender for Cloud Apps, turn on Cloud Discovery through Defender for Endpoint, and add policies for unsanctioned apps, mass downloads and risky OAuth apps.' `
    -Benefit 'Shadow IT discovery and control over data leaving through cloud apps.' `
    -Reference 'https://learn.microsoft.com/defender-cloud-apps/get-started' `
    -Evidence {
    param($Users)
    New-TROppResult Verify 'Configuration is not readable through Microsoft Graph. Check app connectors, Cloud Discovery and policies in the Defender portal.'
}

Register-TROpportunity -Id 'OPP-14' -Category 'Devices and endpoints' -Feature 'Universal Print' `
    -Plans $script:TRPlanSets.UniversalPrint -Needs 'Printers' -EffortDays 1.5 `
    -Opportunity 'Move printers to Universal Print (natively or through the connector) and deploy them to users with Intune, removing on-premises print servers and driver management.' `
    -Benefit 'Cloud printing from Entra joined devices with no print server to patch.' `
    -Reference 'https://learn.microsoft.com/universal-print/fundamentals/universal-print-getting-started' `
    -Evidence {
    param($Users)
    $n = @(Get-TRItems 'Printers').Count
    $text = 'Printers registered in Universal Print: {0}.' -f $n
    if ($n) { return New-TROppResult InUse $text }
    New-TROppResult NotUsed $text
}

Register-TROpportunity -Id 'OPP-15' -Category 'Threat protection' -Feature 'Defender for Office 365 (Safe Links, Safe Attachments, impersonation)' `
    -Plans $script:TRPlanSets.DefenderO365 -Needs 'ExoSafeLinksPolicies', 'ExoSafeAttachmentPolicies', 'ExoAntiPhishPolicies' -EffortDays 1 `
    -Opportunity 'Apply the Standard or Strict preset security policies, or tuned custom policies, for Safe Links, Safe Attachments and impersonation protection across email, Teams and Office apps, with priority accounts for directors and finance.' `
    -Benefit 'Stronger protection against phishing, business email compromise and malicious attachments than the default built-in policy.' `
    -Reference 'https://learn.microsoft.com/defender-office-365/preset-security-policies' `
    -Evidence {
    param($Users)
    $preset = @(Get-TRItems 'ExoPresetAtp' | Where-Object { [string]$_.State -eq 'Enabled' }).Count
    $sl = @(Get-TRItems 'ExoSafeLinksRules' | Where-Object { [string]$_.State -eq 'Enabled' }).Count
    $sa = @(Get-TRItems 'ExoSafeAttachmentRules' | Where-Object { [string]$_.State -eq 'Enabled' }).Count
    $imp = @(Get-TRItems 'ExoAntiPhishPolicies' | Where-Object { $_.Enabled -ne $false -and ($_.EnableTargetedUserProtection -eq $true -or $_.EnableOrganizationDomainsProtection -eq $true) }).Count
    $text = 'Enabled preset policies: {0}; custom Safe Links rules: {1}; custom Safe Attachments rules: {2}; anti-phishing policies with impersonation protection: {3}.' -f $preset, $sl, $sa, $imp
    if (($preset -or ($sl -and $sa)) -and ($preset -or $imp)) { return New-TROppResult InUse $text }
    if ($preset -or $sl -or $sa -or $imp) { return New-TROppResult Partial $text }
    New-TROppResult Partial ($text + ' Only the Built-in protection policy applies, with default settings and no impersonation protection.')
}

Register-TROpportunity -Id 'OPP-16' -Category 'Threat protection' -Feature 'Attack simulation training' `
    -Plans $script:TRPlanSets.DefenderO365P2 -Needs 'AttackSimulations' -EffortDays 1 `
    -Opportunity 'Run a quarterly phishing simulation programme with automatic training for users who click and a trend report for management.' `
    -Benefit 'Measurably reduces click rates and supports cyber insurance and Cyber Essentials evidence.' `
    -Reference 'https://learn.microsoft.com/defender-office-365/attack-simulation-training-get-started' `
    -Evidence {
    param($Users)
    $recent = @(Get-TRItems 'AttackSimulations' | Where-Object { $d = Get-TRDaysSince $(if ($_.launchDateTime) { $_.launchDateTime } else { $_.createdDateTime }); $null -ne $d -and $d -le 365 }).Count
    $text = 'Simulations in the last 12 months: {0}.' -f $recent
    if ($recent -ge 2) { return New-TROppResult InUse $text }
    if ($recent) { return New-TROppResult Partial $text }
    New-TROppResult NotUsed $text
}

Register-TROpportunity -Id 'OPP-17' -Category 'Information protection and compliance' -Feature 'Sensitivity labels' `
    -Plans $script:TRPlanSets.InfoProtection -Needs 'SccLabels', 'SccLabelPolicies' -EffortDays 4 `
    -Opportunity 'Design and publish a sensitivity label taxonomy (Public, Internal, Confidential, Highly confidential) with encryption and visual markings, default labels for email and documents, and labels for Teams and SharePoint sites.' `
    -Benefit 'Sensitive documents stay protected wherever they go, and it prepares the tenant for Copilot by controlling what it can surface.' `
    -Reference 'https://learn.microsoft.com/purview/deploymentmodels/depmod-securebydefault-intro' `
    -Evidence {
    param($Users)
    $labels = @(Get-TRItems 'SccLabels' | Where-Object { $_.Disabled -ne $true }).Count
    $pol = @(Get-TRItems 'SccLabelPolicies' | Where-Object { Test-TRPolicyActive $_ }).Count
    $text = 'Sensitivity labels: {0}; active label policies: {1}.' -f $labels, $pol
    if (-not $labels) { return New-TROppResult NotUsed $text }
    if (-not $pol) { return New-TROppResult Partial ($text + ' Labels are not published.') }
    New-TROppResult InUse $text
}

Register-TROpportunity -Id 'OPP-18' -Category 'Information protection and compliance' -Feature 'Automatic labelling' `
    -Plans $script:TRPlanSets.AutoLabelling -Needs 'SccAutoLabelPolicies' -EffortDays 3 `
    -Opportunity 'Automatically label documents and emails that contain UK financial and personal data, in Office apps and at rest in SharePoint and OneDrive.' `
    -Benefit 'Protection that does not rely on users remembering to label, including historic files.' `
    -Reference 'https://learn.microsoft.com/purview/apply-sensitivity-label-automatically' `
    -Evidence {
    param($Users)
    $n = @(Get-TRItems 'SccAutoLabelPolicies' | Where-Object { Test-TRPolicyActive $_ }).Count
    $text = 'Active auto-labelling policies: {0}.' -f $n
    if ($n) { return New-TROppResult InUse $text }
    New-TROppResult NotUsed $text
}

Register-TROpportunity -Id 'OPP-19' -Category 'Information protection and compliance' -Feature 'Data loss prevention for email and files' `
    -Plans $script:TRPlanSets.Dlp -Needs 'SccDlpPolicies' -EffortDays 3 `
    -Opportunity 'Deploy DLP policies for UK financial and personal data across Exchange, SharePoint, OneDrive and Teams, starting in simulation mode, then policy tips and blocking for external sharing.' `
    -Benefit 'Reduces the risk of a reportable data breach from misdirected email or oversharing.' `
    -Reference 'https://learn.microsoft.com/purview/dlp-create-deploy-policy' `
    -Evidence {
    param($Users)
    $pol = @(Get-TRItems 'SccDlpPolicies' | Where-Object { $_.Enabled -ne $false })
    $enf = @($pol | Where-Object { [string]$_.Mode -eq 'Enable' })
    $wl = @{}
    foreach ($p in $enf) { foreach ($w in (Get-TRPolicyWorkloads $p)) { $wl[$w] = $true } }
    $text = 'Enabled DLP policies: {0} ({1} enforced); enforced workloads: {2}.' -f $pol.Count, $enf.Count, $(if ($wl.Count) { (@($wl.Keys | Sort-Object) -join ', ') } else { 'none' })
    if (-not $pol.Count) { return New-TROppResult NotUsed $text }
    if ($enf.Count -and $wl.ContainsKey('Exchange') -and $wl.ContainsKey('SharePoint') -and $wl.ContainsKey('OneDrive')) { return New-TROppResult InUse $text }
    New-TROppResult Partial $text
}

Register-TROpportunity -Id 'OPP-20' -Category 'Information protection and compliance' -Feature 'Endpoint data loss prevention' `
    -Plans $script:TRPlanSets.EndpointDlp -Needs 'SccDlpPolicies' -EffortDays 2 `
    -Opportunity 'Extend DLP to Windows and macOS devices to control copying sensitive files to USB drives, personal cloud storage, printers and unapproved browsers or AI sites.' `
    -Benefit 'Stops data walking out on removable media or personal accounts.' `
    -Reference 'https://learn.microsoft.com/purview/endpoint-dlp-getting-started' `
    -Evidence {
    param($Users)
    $n = @(Get-TRItems 'SccDlpPolicies' | Where-Object { $_.Enabled -ne $false -and (Get-TRPolicyWorkloads $_) -contains 'Devices' }).Count
    $text = 'DLP policies covering devices: {0}.' -f $n
    if ($n) { return New-TROppResult InUse $text }
    New-TROppResult NotUsed $text
}

Register-TROpportunity -Id 'OPP-21' -Category 'Information protection and compliance' -Feature 'Retention policies' `
    -Plans $script:TRPlanSets.Retention -Needs 'SccRetentionPolicies' -EffortDays 1 `
    -Opportunity 'Agree retention requirements with the client and apply org-wide retention policies for Exchange, SharePoint, OneDrive and Teams so deleted or altered content can be recovered and records are kept for the required period.' `
    -Benefit 'Protection against accidental or malicious deletion beyond the default recycle bin periods, and support for legal obligations.' `
    -Reference 'https://learn.microsoft.com/purview/retention' `
    -Evidence {
    param($Users)
    $pol = @(Get-TRItems 'SccRetentionPolicies' | Where-Object { Test-TRPolicyActive $_ })
    $wl = @{}
    foreach ($p in $pol) {
        if ($p.ExchangeLocation -eq 'All') { $wl['Exchange'] = $true }
        if ($p.SharePointLocation -eq 'All') { $wl['SharePoint'] = $true }
        if ($p.OneDriveLocation -eq 'All') { $wl['OneDrive'] = $true }
        if ($p.TeamsChatLocation -eq 'All' -or $p.TeamsChannelLocation -eq 'All') { $wl['Teams'] = $true }
        if ($p.IsAdaptivePolicy -eq $true) { foreach ($w in (Get-TRPolicyWorkloads $p)) { $wl[$w] = $true } }
    }
    $text = 'Active retention policies: {0}; workloads covered org-wide: {1}.' -f $pol.Count, $(if ($wl.Count) { (@($wl.Keys | Sort-Object) -join ', ') } else { 'none' })
    if (-not $pol.Count) { return New-TROppResult NotUsed $text }
    if ($wl.ContainsKey('Exchange') -and $wl.ContainsKey('SharePoint') -and $wl.ContainsKey('OneDrive') -and $wl.ContainsKey('Teams')) { return New-TROppResult InUse $text }
    New-TROppResult Partial $text
}

Register-TROpportunity -Id 'OPP-22' -Category 'Information protection and compliance' -Feature 'Online archiving' `
    -Plans $script:TRPlanSets.ExchangeArchive -Needs 'ExoMailboxes' -EffortDays 0.5 `
    -Opportunity 'Enable online archives with auto-expanding archiving and an archive policy for large mailboxes, and retire PST files.' `
    -Benefit 'Keeps large mailboxes fast and within quota without buying extra storage.' `
    -Reference 'https://learn.microsoft.com/purview/enable-archive-mailboxes' `
    -Evidence {
    param($Users)
    $mbx = @(Get-TRItems 'ExoMailboxes' | Where-Object { [string]$_.RecipientTypeDetails -eq 'UserMailbox' })
    $arch = @($mbx | Where-Object { [string]$_.ArchiveStatus -eq 'Active' }).Count
    $big = @(Get-TRItems 'MailboxUsage' | Where-Object { [string]$_.'Is Deleted' -ne 'True' -and [string]$_.'Has Archive' -ne 'True' -and [double]$_.'Storage Used (Byte)' -ge 40GB }).Count
    $text = 'User mailboxes with an active archive: {0} of {1}; mailboxes over 40 GB without an archive: {2}.' -f $arch, $mbx.Count, $big
    if ($big) { return New-TROppResult $(if ($arch) { 'Partial' } else { 'NotUsed' }) $text }
    if ($arch) { return New-TROppResult InUse $text }
    New-TROppResult NotUsed $text
}

Register-TROpportunity -Id 'OPP-23' -Category 'Information protection and compliance' -Feature 'eDiscovery (Premium)' `
    -Plans $script:TRPlanSets.EdiscoveryPremium -Needs 'EdiscoveryCases' -EffortDays 1 `
    -Opportunity 'Set up eDiscovery roles, a case template and holds so HR and legal requests, including subject access requests, can be handled in the tenant with review sets and export.' `
    -Benefit 'Faster, cheaper responses to subject access requests and disputes, without third-party tools.' `
    -Reference 'https://learn.microsoft.com/purview/edisc-get-started' `
    -Evidence {
    param($Users)
    $n = @(Get-TRItems 'EdiscoveryCases').Count
    $text = 'eDiscovery cases: {0}.' -f $n
    if ($n) { return New-TROppResult InUse $text }
    New-TROppResult NotUsed $text
}

Register-TROpportunity -Id 'OPP-24' -Category 'Information protection and compliance' -Feature 'Insider risk management' `
    -Plans $script:TRPlanSets.InsiderRisk -Needs 'SccInsiderRisk' -EffortDays 2 `
    -Opportunity 'Enable insider risk policies for data theft by departing users and general data leaks, using HR or Entra ID leaver signals, with pseudonymised review.' `
    -Benefit 'Early warning when a leaver downloads or shares large amounts of company data.' `
    -Reference 'https://learn.microsoft.com/purview/insider-risk-management-configure' `
    -Evidence {
    param($Users)
    $n = @(Get-TRItems 'SccInsiderRisk').Count
    $text = 'Insider risk policies: {0}.' -f $n
    if ($n) { return New-TROppResult InUse $text }
    New-TROppResult NotUsed $text
}

Register-TROpportunity -Id 'OPP-25' -Category 'Information protection and compliance' -Feature 'Audit (Premium)' `
    -Plans $script:TRPlanSets.AuditPremium -Needs 'SccAuditRetention' -EffortDays 0.5 `
    -Opportunity 'Add audit retention policies for sign-in, admin and mailbox activity beyond the default year, and confirm high-value events such as MailItemsAccessed are captured for all licensed users.' `
    -Benefit 'Longer forensic history for investigating a breach or an insurance claim.' `
    -Reference 'https://learn.microsoft.com/purview/audit-log-retention-policies' `
    -Evidence {
    param($Users)
    $n = @(Get-TRItems 'SccAuditRetention').Count
    $text = 'Custom audit retention policies: {0}. Licensed users get one year of retention by default.' -f $n
    if ($n) { return New-TROppResult InUse $text }
    New-TROppResult Partial $text
}

Register-TROpportunity -Id 'OPP-26' -Category 'Information protection and compliance' -Feature 'Customer Lockbox' `
    -Plans $script:TRPlanSets.CustomerLockbox -Needs 'ExoOrganizationConfig' -EffortDays 0.1 `
    -Opportunity 'Turn on Customer Lockbox so Microsoft engineers need explicit approval before accessing tenant content during support cases.' `
    -Benefit 'Control and an audit trail over Microsoft support access to client data.' `
    -Reference 'https://learn.microsoft.com/purview/customer-lockbox-requests' `
    -Evidence {
    param($Users)
    $o = Get-TRRawValue 'ExoOrganizationConfig'
    if ($o -and $o.CustomerLockBoxEnabled -eq $true) { return New-TROppResult InUse 'Customer Lockbox is on.' }
    New-TROppResult NotUsed 'Customer Lockbox is off.'
}

Register-TROpportunity -Id 'OPP-27' -Category 'Productivity and AI' -Feature 'Microsoft 365 desktop apps' `
    -Plans $script:TRPlanSets.OfficeApps -Needs 'AppActivations' -EffortDays 1 `
    -Opportunity 'Deploy Microsoft 365 Apps through Intune on a supported update channel, use shared computer activation where needed, and retire older perpetual Office versions.' `
    -Benefit 'Users get current, supported Office apps and the client can stop paying for separate Office licences.' `
    -Reference 'https://learn.microsoft.com/intune/intune-service/apps/apps-add-office365' `
    -Evidence {
    param($Users)
    $act = @{}
    foreach ($r in (Get-TRItems 'AppActivations')) {
        if ([string]$r.'Product Type' -match 'PROJECT|VISIO') { continue }
        $n = 0; $m = 0
        [void][int]::TryParse([string]$r.Windows, [ref]$n)
        [void][int]::TryParse([string]$r.Mac, [ref]$m)
        if (($n + $m) -gt 0) { $act[[string]$r.'User Principal Name'] = $true }
    }
    $pct = Get-TRPercent $act.Count $Users
    $text = 'Users with desktop apps activated on Windows or Mac: {0} of {1} licensed ({2}%).' -f $act.Count, $Users, $pct
    if (-not $act.Count) { return New-TROppResult NotUsed $text }
    if ($pct -lt 70) { return New-TROppResult Partial $text }
    New-TROppResult InUse $text
}

Register-TROpportunity -Id 'OPP-28' -Category 'Productivity and AI' -Feature 'OneDrive' `
    -Plans $script:TRPlanSets.SharePoint -Needs 'ActiveUserDetail' -EffortDays 1 `
    -Opportunity 'Configure OneDrive silently with Known Folder Move (Desktop, Documents and Pictures) through Intune so user files are protected and available on any device.' `
    -Benefit 'User files are backed up to the cloud and a lost laptop no longer means lost work.' `
    -Reference 'https://learn.microsoft.com/sharepoint/redirect-known-folders' `
    -Evidence {
    param($Users)
    Get-TRAdoptionResult (Get-TRActivityShare 'Has OneDrive License' 'OneDrive Last Activity Date') 'OneDrive'
}

Register-TROpportunity -Id 'OPP-29' -Category 'Productivity and AI' -Feature 'SharePoint for company files' `
    -Plans $script:TRPlanSets.SharePoint -Needs 'ActiveUserDetail' -EffortDays 5 `
    -Opportunity 'Migrate remaining file shares to SharePoint and Teams with a clear site structure, permissions based on groups, and retirement of the old file server.' `
    -Benefit 'Secure access from anywhere, version history and co-authoring, and one less server to maintain and back up.' `
    -Reference 'https://learn.microsoft.com/sharepointmigration/migrate-to-sharepoint-online' `
    -Evidence {
    param($Users)
    Get-TRAdoptionResult (Get-TRActivityShare 'Has SharePoint License' 'SharePoint Last Activity Date') 'SharePoint'
}

Register-TROpportunity -Id 'OPP-30' -Category 'Productivity and AI' -Feature 'Microsoft Teams' `
    -Plans $script:TRPlanSets.Teams -Needs 'ActiveUserDetail' -EffortDays 2 `
    -Opportunity 'Run a Teams adoption plan: team and channel structure per department, meeting room setup, guest access settings and short training sessions.' `
    -Benefit 'One place for chat, meetings and files, and fewer separately paid conferencing tools.' `
    -Reference 'https://learn.microsoft.com/microsoftteams/teams-adoption-get-started' `
    -Evidence {
    param($Users)
    Get-TRAdoptionResult (Get-TRActivityShare 'Has Teams License' 'Teams Last Activity Date') 'Teams'
}

Register-TROpportunity -Id 'OPP-31' -Category 'Productivity and AI' -Feature 'Teams Phone' `
    -Plans $script:TRPlanSets.TeamsPhone -Needs 'TeamsNumbers' -EffortDays 3 `
    -Opportunity 'Set up Teams Phone with Operator Connect, Direct Routing or Calling Plans, port the numbers, build auto attendants and call queues, and assign numbers to licensed users.' `
    -Benefit 'Replaces a separate phone system and puts calling in the app users already have open.' `
    -Reference 'https://learn.microsoft.com/microsoftteams/what-is-phone-system-in-office-365' `
    -Evidence {
    param($Users)
    $assigned = @(Get-TRItems 'TeamsNumbers' | Where-Object { [string]$_.assignmentStatus -match 'Assigned$' -and [string]$_.assignmentStatus -ne 'unassigned' })
    $toUsers = @($assigned | Where-Object { [string]$_.assignmentStatus -eq 'userAssigned' }).Count
    $text = 'Users licensed for Teams Phone: {0}; numbers assigned to users: {1}; other assigned numbers: {2}.' -f $Users, $toUsers, ($assigned.Count - $toUsers)
    if (-not $assigned.Count) { return New-TROppResult NotUsed $text }
    if ($toUsers -lt ($Users * 0.7)) { return New-TROppResult Partial $text }
    New-TROppResult InUse $text
}

Register-TROpportunity -Id 'OPP-32' -Category 'Productivity and AI' -Feature 'Microsoft 365 Copilot' `
    -Plans $script:TRPlanSets.Copilot -Needs 'CopilotUsage' -EffortDays 2 `
    -Opportunity 'Run a Copilot adoption programme: check oversharing and sensitivity labels first, train champions, run role-based scenario sessions, and review usage monthly to reassign idle licences.' `
    -Benefit 'A return on an expensive licence, and idle licences moved to people who will use them.' `
    -Reference 'https://learn.microsoft.com/copilot/microsoft-365/microsoft-365-copilot-enablement-resources' `
    -Evidence {
    param($Users)
    $active = @(Get-TRItems 'CopilotUsage' | Where-Object { $d = Get-TRDaysSince $_.LastActivityDate; $null -ne $d -and $d -le 30 }).Count
    $pct = Get-TRPercent $active $Users
    $text = 'Users licensed for Copilot: {0}; active in the last 30 days: {1} ({2}%).' -f $Users, $active, $pct
    if (-not $active) { return New-TROppResult NotUsed $text }
    if ($pct -lt 70) { return New-TROppResult Partial $text }
    New-TROppResult InUse $text
}

function Invoke-TROpportunities {
    $rows = New-Object System.Collections.ArrayList
    $platform = Get-TRPlatform
    $gws = $platform -eq 'Google'
    $tenant = if ($gws) { @{} } else { Get-TRServicePlans }
    foreach ($def in $script:TROppDefs) {
        if ($def.Platform -ne $platform) { continue }
        $licensed = $false
        if ($gws) { foreach ($p in $def.Plans) { if (Test-TRGwsCapability $p) { $licensed = $true; break } } }
        else { foreach ($p in $def.Plans) { if ($tenant[$p]) { $licensed = $true; break } } }
        if ($licensed -and @($def.AlsoRequires).Count) {
            $licensed = $false
            if ($gws) { foreach ($p in $def.AlsoRequires) { if (Test-TRGwsCapability $p) { $licensed = $true; break } } }
            else { foreach ($p in $def.AlsoRequires) { if ($tenant[$p]) { $licensed = $true; break } } }
        }
        $users = 0
        $res = $null
        if (-not $licensed) {
            if (Test-TRLicenceDataKnown) { $res = New-TROppResult NotLicensed '' }
            else { $res = New-TROppResult NotAssessed 'The licences could not be read, so it is not known whether this feature is licensed. See Collection diagnostics.' }
        }
        else {
            $users = if ($gws) { Get-TRGwsFeatureUserCount $def.Plans } else { Get-TRFeatureUserCount $def.Plans }
            if ($users -eq 0 -and (Test-TRCollected @($(if ($gws) { 'GwsLicences' } else { 'Users' })))) {
                $res = New-TROppResult NotUsed 'Included in a subscription the tenant owns, but no enabled user has a licence that includes it.'
            }
            elseif (@($def.Needs).Count -and -not (Test-TRCollected $def.Needs)) {
                $res = New-TROppResult NotAssessed ('Usage could not be read. ' + (Get-TRMissingReason $def.Needs))
            }
            else {
                try {
                    $script:TROppPlans = $def.Plans
                    $res = & $def.Evidence $users
                    if ($res -is [System.Array]) { $res = $res[-1] }
                    if (-not $res) { $res = New-TROppResult NotAssessed 'No result.' }
                }
                catch { $res = New-TROppResult NotAssessed ('Could not be evaluated: ' + $_.Exception.Message) }
            }
        }
        [void]$rows.Add([pscustomobject][ordered]@{
                Id            = $def.Id
                Category      = $def.Category
                Feature       = $def.Feature
                Status        = $res.Status
                StatusLabel   = (Get-TROppStatusLabel $res.Status)
                LicensedUsers = $users
                LicensedVia   = $(if (-not $licensed) { '' } elseif ($gws) { Get-TRGwsFeatureSkus $def.Plans } else { Get-TRFeatureSkus (@($def.Plans) + @($def.AlsoRequires)) })
                Evidence      = $res.Evidence
                Opportunity   = $def.Opportunity
                Benefit       = $def.Benefit
                EffortDays    = $(if ($res.Status -in @('NotUsed', 'Partial')) { $def.EffortDays } else { 0 })
                Reference     = $def.Reference
            })
    }
    $n = @($rows | Where-Object { $_.Status -eq 'NotUsed' }).Count
    $p = @($rows | Where-Object { $_.Status -eq 'Partial' }).Count
    Write-TRLog ("Licence utilisation: {0} licensed features not used, {1} partly used." -f $n, $p)
    , $rows.ToArray()
}
