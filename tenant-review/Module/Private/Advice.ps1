$script:TRAdviceKinds = [ordered]@{
    Permission  = @{ Label = 'Permission'; Action = $true; Order = 0 }
    Consent     = @{ Label = 'Consent'; Action = $true; Order = 1 }
    Approval    = @{ Label = 'Not approved'; Action = $true; Order = 2 }
    AccountLic  = @{ Label = 'Account licence'; Action = $true; Order = 3 }
    Temporary   = @{ Label = 'Service error'; Action = $true; Order = 4 }
    Other       = @{ Label = 'Error'; Action = $true; Order = 5 }
    TenantLic   = @{ Label = 'Not licensed'; Action = $false; Order = 6 }
    NotSetUp    = @{ Label = 'Not set up'; Action = $false; Order = 7 }
}

function Get-TRDiagGroup {
    param([string]$Item, [string]$Area)
    switch -Regex ($Item) {
        '^Scc' { return 'Purview (Security & Compliance)' }
        '^(Exo|Mailbox)' { return 'Exchange Online' }
        '^(Defender|Mtd|AttackSimulations)' { return 'Microsoft Defender' }
        '^Teams(Numbers)$' { return 'Teams Phone numbers' }
        '^Teams' { return 'Teams admin settings' }
        '^(Spo|SharePointSettings$)' { return 'SharePoint admin settings' }
        '^PowerBI' { return 'Power BI and Fabric settings' }
        '^Pp' { return 'Power Platform settings' }
        '^Az' { return 'Azure' }
        '^(Intune|ManagedDevices|CompliancePolicies|DeviceConfigurations|ConfigurationPolicies|ConfigPolicy|Autopilot|IosAppProtection|AndroidAppProtection|EnrollmentConfigurations|Intents|DeviceManagement$)' { return 'Intune' }
        '^(RoleEligibility|RiskyUsers|AccessReview|RoleAssignmentInstances|RoleManagementPolicies)' { return 'Entra ID P2 features' }
        '(Usage|ActiveUserDetail|AppActivations|ReportSettings)' { return 'Usage reports' }
        '^SharingAudit' { return 'Audit log search' }
        '^Printers' { return 'Universal Print' }
        '^(Server|Linux|VMware)' { return 'Server data' }
        '^Gws' { return 'Google Workspace' }
    }
    if ($Area) { return $Area }
    'Other'
}

function Get-TRPermissionFix {
    param([string]$Group)
    $google = (Get-TRPlatform) -eq 'Google'
    if ($google) { return 'Sign in as a super admin of the Google Workspace. Delegated admin roles cannot read this.' }
    switch ($Group) {
        'Purview (Security & Compliance)' { return 'Give the review account the Compliance Administrator role, or add it to the Purview Organization Management role group (Global Administrator also covers this). Role group changes can take up to 30 minutes to apply.' }
        'Exchange Online' { return 'Give the review account Exchange Administrator or Global Reader (through GDAP if you use it).' }
        'Microsoft Defender' { return 'Give the review account Security Reader or Global Reader, and make sure ThreatHunting.Read.All has been consented (use Grant consent again).' }
        'Teams admin settings' { return 'Give the review account Teams Administrator, or use a Global Administrator.' }
        'Teams Phone numbers' { return 'Give the review account Teams Communications Administrator, or use a Global Administrator.' }
        'SharePoint admin settings' { return 'Give the review account SharePoint Administrator, or use a Global Administrator.' }
        'Power BI and Fabric settings' { return 'Give the review account Fabric Administrator, or use a Global Administrator.' }
        'Power Platform settings' { return 'Give the review account Power Platform Administrator, or use a Global Administrator.' }
        'Azure' { return 'Assign the review account Reader and Security Reader on each Azure subscription, or on a management group above them. Global Administrator alone does not give access to subscriptions.' }
        'Intune' { return 'Give the review account Intune Administrator or Global Reader.' }
        'Usage reports' { return 'Give the review account Reports Reader or Global Reader.' }
        'Audit log search' { return 'Give the review account audit log search rights, for example Compliance Administrator or the Purview Audit Reader role group.' }
        'Universal Print' { return 'Give the review account the Printer Administrator role.' }
    }
    'Give the review account Global Reader, or use a Global Administrator.'
}

function Get-TRDiagAdvice {
    param($Diag, [hashtable]$Index)
    $item = [string]$Diag.Item
    $msg = [string]$Diag.Message
    $http = 0
    try { $http = [int]$Diag.HttpStatus } catch { }
    $group = Get-TRDiagGroup -Item $item -Area ([string]$Diag.Area)
    $google = (Get-TRPlatform) -eq 'Google'
    $kind = 'Other'
    $fix = ''
    if ($msg -match 'See (\w+) for the error' -and $Index -and $Index.ContainsKey($Matches[1]) -and $Matches[1] -ne $item) {
        $root = Get-TRDiagAdvice -Diag $Index[$Matches[1]] -Index $null
        return [pscustomobject]@{ Item = $item; Group = $root.Group; Kind = $root.Kind; Fix = $root.Fix; Message = $msg; DependsOn = $Matches[1] }
    }
    if ($group -eq 'Server data') { $kind = 'Other'; $fix = 'Check the server data folder and run the collectors again as an administrator.' }
    elseif ($msg -match 'SharePointAdminUrl') { $kind = 'Other'; $fix = 'Set SharePointAdminUrl in config.json to the SharePoint admin address, for example https://contoso-admin.sharepoint.com, then run the review again.' }
    elseif ($msg -match 'has no Power BI or Fabric licence|User is not licensed' -or ($group -eq 'Power BI and Fabric settings' -and $msg -match 'not licensed')) {
        $kind = 'AccountLic'; $fix = 'Assign the free Microsoft Fabric (Free) licence to the review account, or sign in once at app.powerbi.com with it.'
    }
    elseif ($group -eq 'Universal Print' -and $msg -match 'licen|Printer Administrator') {
        $kind = 'TenantLic'; $fix = 'Needs a Universal Print licence or the Printer Administrator role. No action unless the client uses Universal Print.'
    }
    elseif ($msg -match 'not been set up|has no device data|not set up in (this|the) tenant|is not set up|not provisioned|no Azure Resource Manager service principal') {
        $kind = 'NotSetUp'; $fix = 'Nothing to fix in the review: this feature is not set up for the client.'
    }
    elseif ($msg -match 'not licen[cs]ed|LicenseRequired|license required|PremiumLicense|is not licensed|isn''t licensed|requires a licen|Entra ID P2') {
        $kind = 'TenantLic'
        $fix = if ($group -eq 'Entra ID P2 features') { 'The tenant has no Entra ID P2 or ID Governance licence, so these features cannot be used. Related controls show Not applicable. No action needed.' } else { 'The client is not licensed for this feature. No action needed unless they buy it.' }
    }
    elseif ($google -and $msg -match 'insufficient authentication scopes|ACCESS_TOKEN_SCOPE_INSUFFICIENT') {
        $kind = 'Consent'; $fix = 'Sign in again and tick every permission on the Google consent screen.'
    }
    elseif ($google -and $msg -match 'has not been used in project|is disabled|SERVICE_DISABLED') {
        $kind = 'Consent'; $fix = 'Enable this API in your Google Cloud project, wait a few minutes, then run the review again.'
    }
    elseif ($msg -match 'access was not granted|was not approved|not completed|access_denied|declined|Timed out waiting for the browser|access was not requested') {
        $kind = 'Approval'; $fix = 'Approve read access when the browser asks at the start of the review, then run the review again.'
    }
    elseif ($msg -match 'cannot see any active Azure subscription') {
        $kind = 'Permission'; $fix = Get-TRPermissionFix -Group 'Azure'
    }
    elseif ($msg -match 'scope|consent|AADSTS65001|invalid_grant' -and $msg -match 'missing|not granted|required|consent') {
        $kind = 'Consent'; $fix = 'Use Grant consent again for this client (and run the app setup script with -UpdateExisting if the tool was upgraded).'
    }
    elseif ($http -in @(401, 403) -or $msg -match 'Forbidden|not allowed to call|Access is denied|AccessDenied|Authorization_RequestDenied|Insufficient privileges|does not have permission|not authori[sz]ed|Unauthori[sz]ed|lacks an? .*role') {
        $kind = 'Permission'; $fix = Get-TRPermissionFix -Group $group
    }
    elseif ($http -eq 429 -or $http -ge 500 -or $msg -match 'timed out|timeout|temporarily|Gateway|Service Unavailable|Too many requests|throttl') {
        $kind = 'Temporary'; $fix = 'A temporary service error. Run the review again.'
    }
    else { $fix = 'Check the error message. If it happens again, keep the Review.log so it can be investigated.' }
    [pscustomobject]@{ Item = $item; Group = $group; Kind = $kind; Fix = $fix; Message = $msg; DependsOn = '' }
}

function Get-TRCollectionAdvice {
    param($Diagnostics)
    $diag = @($Diagnostics | Where-Object { $null -ne $_ -and [string]$_.Status -ne 'OK' })
    if (-not $diag.Count) { return }
    $index = @{}
    foreach ($d in @($Diagnostics | Where-Object { $null -ne $_ })) { $index[[string]$d.Item] = $d }
    $rows = @($diag | ForEach-Object { Get-TRDiagAdvice -Diag $_ -Index $index })
    $groups = [ordered]@{}
    foreach ($r in $rows) {
        $k = '{0}|{1}|{2}' -f $r.Kind, $r.Group, $r.Fix
        if (-not $groups.Contains($k)) { $groups[$k] = [pscustomobject]@{ Kind = $r.Kind; Group = $r.Group; Fix = $r.Fix; Items = New-Object System.Collections.ArrayList; Messages = New-Object System.Collections.ArrayList } }
        [void]$groups[$k].Items.Add($r.Item)
        if ($r.Message -and -not $r.DependsOn -and $groups[$k].Messages -notcontains $r.Message) { [void]$groups[$k].Messages.Add($r.Message) }
    }
    $out = foreach ($g in $groups.Values) {
        $meta = $script:TRAdviceKinds[$g.Kind]
        [pscustomobject]@{ Kind = $g.Kind; KindLabel = $meta.Label; Action = [bool]$meta.Action; Order = [int]$meta.Order; Group = $g.Group; Fix = $g.Fix; Items = @($g.Items); Messages = @($g.Messages) }
    }
    @($out) | Sort-Object Order, Group
}

function Get-TRAdviceEffect {
    param($Advice, $Findings, $Benchmarks)
    $pattern = '(?<![A-Za-z0-9])(' + ((@($Advice.Items) | ForEach-Object { [regex]::Escape([string]$_) }) -join '|') + ')(:| was not)'
    $checks = @($Findings | Where-Object { $_.Status -eq 'NotAssessed' -and [string]$_.Current -match $pattern }).Count
    $controls = @($Benchmarks | Where-Object { [string]$_.Status -eq 'NotAssessed' -and [string]$_.Evidence -match $pattern }).Count
    [pscustomobject]@{ Checks = $checks; Controls = $controls }
}

function Format-TRAdviceEffect {
    param($Effect)
    $parts = @()
    if ($Effect.Checks) { $parts += (Format-TRN $Effect.Checks 'check') }
    if ($Effect.Controls) { $parts += (Format-TRN $Effect.Controls 'benchmark control') }
    if (-not $parts.Count) { return 'No checks affected' }
    ($parts -join ' and ') + ' not assessed'
}

function Write-TRCollectionAdvice {
    param($Diagnostics, $Findings, $Benchmarks)
    $advice = @(Get-TRCollectionAdvice $Diagnostics)
    if (-not $advice.Count) { return }
    $act = @($advice | Where-Object { $_.Action })
    $info = @($advice | Where-Object { -not $_.Action })
    if ($act.Count) {
        Write-TRLog ('{0} could not be read because of the review account''s access or a service error. Fix these, then run the review again:' -f (Format-TRN @($act | ForEach-Object { $_.Items.Count } | Measure-Object -Sum).Sum 'item')) 'Warn'
        foreach ($a in $act) {
            $eff = Format-TRAdviceEffect (Get-TRAdviceEffect -Advice $a -Findings $Findings -Benchmarks $Benchmarks)
            $effText = $eff.Substring(0, 1).ToLower() + $eff.Substring(1)
            Write-TRLog ('  {0} - {1} ({2}; {3}): {4}' -f $a.KindLabel, $a.Group, ($a.Items -join ', '), $effText, $a.Fix) 'Warn'
        }
    }
    if ($info.Count) {
        Write-TRLog 'Not available in this tenant (no action needed unless the client adds these):'
        foreach ($a in $info) { Write-TRLog ('  {0} - {1} ({2}): {3}' -f $a.KindLabel, $a.Group, ($a.Items -join ', '), $a.Fix) }
    }
    Write-TRLog 'The same list, with the checks each one affects, is in the report under Method and limitations.'
}
