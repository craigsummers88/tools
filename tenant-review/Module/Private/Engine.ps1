$script:TRToolVersion = '1.4.1'

$script:TRRequiredGraphScopes = @(
    'User.Read', 'Directory.Read.All', 'Policy.Read.All', 'AuditLog.Read.All', 'Reports.Read.All', 'ReportSettings.Read.All',
    'RoleManagement.Read.Directory', 'Application.Read.All', 'SecurityEvents.Read.All', 'IdentityRiskyUser.Read.All',
    'UserAuthenticationMethod.Read.All', 'Domain.Read.All', 'Organization.Read.All', 'Group.Read.All', 'GroupMember.Read.All',
    'DeviceManagementConfiguration.Read.All', 'DeviceManagementManagedDevices.Read.All', 'DeviceManagementApps.Read.All',
    'DeviceManagementServiceConfig.Read.All', 'SharePointTenantSettings.Read.All', 'OnPremDirectorySynchronization.Read.All',
    'AuditLogsQuery-SharePoint.Read.All', 'AuditLogsQuery-OneDrive.Read.All', 'ThreatHunting.Read.All', 'SecurityIncident.Read.All',
    'AttackSimulation.Read.All', 'RecordsManagement.Read.All', 'eDiscovery.Read.All', 'offline_access', 'openid', 'profile'
)
$script:TROptionalGraphScopes = @('Policy.Read.DeviceConfiguration', 'AccessReview.Read.All', 'Printer.Read.All', 'TeamsTelephoneNumber.Read.All', 'SecurityIdentitiesSensors.Read.All', 'OrgSettings-AppsAndServices.Read.All', 'OrgSettings-Forms.Read.All', 'RoleManagementPolicy.Read.Directory')
$script:TRExchangeScopes = @('Exchange.Manage', 'Exchange.ManageV2')
$script:TRComplianceScopes = @('Exchange.Manage', 'Exchange.ManageV2')

function Get-TRToolVersion { $script:TRToolVersion }
function Get-TRRequiredScopes {
    [pscustomobject]@{ Graph = $script:TRRequiredGraphScopes; GraphOptional = $script:TROptionalGraphScopes; Exchange = $script:TRExchangeScopes; Compliance = $script:TRComplianceScopes }
}

function Get-TRDefaultSettings {
    [pscustomobject]@{
        ClientId              = ''
        CompanyName           = 'Your Company'
        CompanyShortName      = 'Your Company'
        HoursPerDay           = 7.5
        PlanDaysPerWeek       = 2
        DayRate               = 0
        CurrencySymbol        = [string][char]0xA3
        PatchingViaRmm        = $true
        MinimumWindows11Build = 26100
        InactiveDays          = 90
        StaleDeviceDays       = 180
        InactiveSiteDays      = 180
        MaxMailboxes          = 3000
        OutputRoot            = ''
        DnsMode               = 'Auto'
        LogoPath              = ''
        CreatePdf             = $true
        CreateSummaryPdf      = $true
        PdfBrowserPath        = ''
        SharePointAdminUrl    = ''
        GoogleClientId        = ''
        GoogleClientSecret    = ''
        MaxGroups             = 1000
    }
}

function Import-TRSettings {
    param([string]$Path)
    $s = Get-TRDefaultSettings
    if ($Path -and (Test-Path -LiteralPath $Path)) {
        try {
            $loaded = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
            foreach ($p in $loaded.PSObject.Properties) {
                if ($p.Name -like '_*') { continue }
                if ($s.PSObject.Properties[$p.Name]) { $s.($p.Name) = $p.Value } else { $s | Add-Member -NotePropertyName $p.Name -NotePropertyValue $p.Value }
            }
        }
        catch { Write-TRLog ("Could not read settings from {0}: {1}" -f $Path, $_.Exception.Message) 'Warn' }
    }
    $script:TRSettings = $s
    $s
}

function Set-TRSettingsObject {
    param($Settings)
    $script:TRSettings = $Settings
}

function Test-TRGrantedScopes {
    $ctx = Get-TRContext
    $granted = @(([string]$ctx.Scopes['Graph']) -split '\s+' | Where-Object { $_ })
    $missing = @($script:TRRequiredGraphScopes | Where-Object { $_ -notin @('offline_access', 'openid', 'profile') -and $granted -notcontains $_ })
    [pscustomobject]@{ Granted = $granted; Missing = $missing }
}

function Get-TRConsentUrl {
    param([Parameter(Mandatory = $true)][string]$Tenant, [Parameter(Mandatory = $true)][string]$ClientId)
    'https://login.microsoftonline.com/{0}/adminconsent?client_id={1}&redirect_uri={2}' -f [uri]::EscapeDataString($Tenant), [uri]::EscapeDataString($ClientId), [uri]::EscapeDataString('https://login.microsoftonline.com/common/oauth2/nativeclient')
}

function Initialize-TRAnalysis {
    param($Raw)
    $script:TRR = $Raw
    $script:TRCache = @{}
    $script:TRDiagIndex = @{}
    foreach ($d in (Get-TRItems 'Diagnostics')) { $script:TRDiagIndex[[string]$d.Item] = $d }
}

function Read-TRRawFile {
    param([Parameter(Mandatory = $true)][string]$Path)
    $text = [IO.File]::ReadAllText($Path, [Text.Encoding]::UTF8)
    try {
        $obj = $text | ConvertFrom-Json -ErrorAction Stop
        return $obj
    }
    catch {
        if ($PSVersionTable.PSVersion.Major -ge 6) { throw }
        Add-Type -AssemblyName System.Web.Extensions
        $ser = New-Object System.Web.Script.Serialization.JavaScriptSerializer
        $ser.MaxJsonLength = [int]::MaxValue
        $ser.RecursionLimit = 200
        return $ser.DeserializeObject($text)
    }
}

function Save-TRRawFile {
    param([Parameter(Mandatory = $true)]$Raw, [Parameter(Mandatory = $true)][string]$Path)
    $json = ConvertTo-Json -InputObject $Raw -Depth 30 -Compress
    Write-TRTextFile -Path $Path -Text $json
}

function Get-TRSafeName {
    param([string]$Name)
    $s = ($Name -replace '[^A-Za-z0-9 _-]+', '' -replace '\s+', ' ').Trim()
    if (-not $s) { $s = 'Tenant' }
    $s
}

function Invoke-TenantAnalysis {
    param(
        $Raw,
        [string]$RawPath,
        [string]$OutputFolder,
        [string[]]$Areas,
        [string]$ServerDataPath
    )
    if ($RawPath) {
        Write-TRLog ("Loading saved data from {0}" -f $RawPath)
        $Raw = Read-TRRawFile -Path $RawPath
        if (-not $OutputFolder) { $OutputFolder = Split-Path -Parent $RawPath }
    }
    if ($null -eq $Raw) { throw 'No review data supplied.' }
    if (-not $OutputFolder) { throw 'No output folder supplied.' }
    if (-not $script:TRSettings) { Import-TRSettings | Out-Null }
    if ($ServerDataPath) {
        Import-TRServerData -Path $ServerDataPath -Raw $Raw
        if ($Areas -and $Areas -notcontains 'Servers') { $Areas = @($Areas) + 'Servers' }
    }
    Initialize-TRAnalysis -Raw $Raw
    if (-not $Areas) { $Areas = @(Get-TRMeta 'Areas') }
    $checkAreas = @(@($Areas) + @('Identity', 'Licensing') | Select-Object -Unique)
    Set-TRProgress 90 'Evaluating checks'
    $findings = Invoke-TRChecks -Areas $checkAreas
    Write-TRLog ("Evaluated {0} checks: {1} fail, {2} warning, {3} pass, {4} not assessed." -f $findings.Count, @($findings | Where-Object { $_.Status -eq 'Fail' }).Count, @($findings | Where-Object { $_.Status -eq 'Warning' }).Count, @($findings | Where-Object { $_.Status -eq 'Pass' }).Count, @($findings | Where-Object { $_.Status -eq 'NotAssessed' }).Count)
    $opps = @()
    if (@($Areas) -contains 'Opportunities') {
        Set-TRProgress 92 'Comparing licences with usage'
        $opps = Invoke-TROpportunities
    }
    $bench = @()
    $benchSum = @()
    if (@($Areas) -contains 'Benchmarks') {
        Set-TRProgress 93 'Assessing CIS and SCuBA benchmark controls'
        $bench = Invoke-TRBenchmarks -Findings $findings
        $benchSum = @(Get-TRBenchmarkSummary $bench)
        foreach ($b in $benchSum) {
            Write-TRLog ('{0}: {1}% of assessed controls met ({2} met, {3} not met, {4} to check manually, {5} not assessed, {6} not applicable).' -f $b.Short, $b.Score, $b.Pass, $b.Fail, $b.Manual, $b.NotAssessed, $b.NotApplicable)
        }
    }
    Set-TRProgress 94 'Building inventories'
    $inv = Get-TRInventories
    Set-TRProgress 97 'Writing HTML and CSV reports'
    $out = Write-TRReport -Findings $findings -Inventories $inv -Opportunities $opps -Benchmarks $bench -OutputFolder $OutputFolder
    Set-TRProgress 100 'Review complete'
    [pscustomobject]@{
        Html          = $out.Html
        Pdf           = $out.Pdf
        SummaryPdf    = $out.SummaryPdf
        CsvFolder     = $out.CsvFolder
        OutputFolder  = $OutputFolder
        Score         = (Get-TRScore @($findings | Where-Object { (Get-TRWorkload $_) -eq 'Tenant' }))
        AzureScore    = (Get-TRScore @($findings | Where-Object { (Get-TRWorkload $_) -eq 'Azure' }))
        ServerScore   = (Get-TRScore @($findings | Where-Object { (Get-TRWorkload $_) -eq 'Servers' }))
        Fail          = @($findings | Where-Object { $_.Status -eq 'Fail' -and (Get-TRWorkload $_) -eq 'Tenant' }).Count
        Warning       = @($findings | Where-Object { $_.Status -eq 'Warning' -and (Get-TRWorkload $_) -eq 'Tenant' }).Count
        Pass          = @($findings | Where-Object { $_.Status -eq 'Pass' -and (Get-TRWorkload $_) -eq 'Tenant' }).Count
        NotAssessed   = @($findings | Where-Object { $_.Status -eq 'NotAssessed' -and (Get-TRWorkload $_) -eq 'Tenant' }).Count
        NotUsed       = @($opps | Where-Object { $_.Status -eq 'NotUsed' }).Count
        PartlyUsed    = @($opps | Where-Object { $_.Status -eq 'Partial' }).Count
        Findings      = $findings
        Opportunities = $opps
        Benchmarks    = $bench
        BenchmarkSummary = $benchSum
    }
}

function Invoke-TenantReview {
    param(
        [string[]]$Areas,
        [string]$ClientName,
        [Parameter(Mandatory = $true)][string]$OutputRoot,
        [int]$MaxMailboxes = 0,
        [string]$ServerDataPath
    )
    $ctx = Get-TRContext
    if (-not $ctx -or -not $ctx.TenantId) { throw 'Sign in to the client tenant first.' }
    if (-not $script:TRSettings) { Import-TRSettings | Out-Null }
    $google = $ctx.Platform -eq 'Google'
    if (-not $Areas) { $Areas = $(if ($google) { $script:TRGoogleDefaultAreas } else { $script:TRDefaultAreas }) }
    if (-not $ClientName) { $ClientName = $(if ($ctx.TenantName) { $ctx.TenantName } else { $ctx.InitialDomain }) }
    if ($MaxMailboxes -le 0) { $MaxMailboxes = [int](Get-TRSetting 'MaxMailboxes' 3000) }
    $folder = Join-Path (Join-Path $OutputRoot (Get-TRSafeName $ClientName)) ((Get-Date).ToString('yyyy-MM-dd_HHmm'))
    New-Item -ItemType Directory -Path $folder -Force | Out-Null
    $script:TRLogFile = Join-Path $folder 'Review.log'
    try {
        Write-TRLog ("Tenant Review v{0} ({2}). Output folder: {1}" -f $script:TRToolVersion, $folder, $(if ($google) { 'Google Workspace' } else { 'Microsoft 365' }))
        if ($google) {
            $miss = @(Get-TRGoogleMissingScopes)
            if ($miss.Count) { Write-TRLog ('These permissions were not approved at sign-in, so related checks will be Not assessed: {0}.' -f (($miss | ForEach-Object { $script:TRGoogleScopeAreas[$_] }) -join ', ')) 'Warn' }
            $raw = Invoke-TRGoogleCollection -Areas $Areas -ClientName $ClientName -MaxUsers $MaxMailboxes -MaxGroups ([int](Get-TRSetting 'MaxGroups' 1000)) -ToolVersion $script:TRToolVersion
        }
        else {
            $scopeCheck = Test-TRGrantedScopes
            if ($scopeCheck.Missing.Count) {
                Write-TRLog ("The sign-in token is missing these permissions: {0}. Related checks will be Not assessed. Re-run Grant consent if the app registration has been updated." -f ($scopeCheck.Missing -join ', ')) 'Warn'
            }
            $raw = Invoke-TenantCollection -Areas $Areas -ClientName $ClientName -MaxMailboxes $MaxMailboxes -ToolVersion $script:TRToolVersion
        }
        if ($ServerDataPath) {
            Set-TRProgress 87 'Importing server data'
            Import-TRServerData -Path $ServerDataPath -Raw $raw
            $Areas = @(@($Areas) + 'Servers' | Select-Object -Unique)
        }
        Set-TRProgress 88 'Saving collected data'
        Save-TRRawFile -Raw $raw -Path (Join-Path $folder 'RawData.json')
        $result = Invoke-TenantAnalysis -Raw $raw -OutputFolder $folder -Areas $Areas
        $msg = "Score {0}%: {1} fail, {2} warning, {3} pass." -f $result.Score, $result.Fail, $result.Warning, $result.Pass
        if (@($result.Opportunities).Count) { $msg += (" Licensed features not used: {0}; partly used: {1}." -f $result.NotUsed, $result.PartlyUsed) }
        foreach ($b in @($result.BenchmarkSummary)) { $msg += (' {0}: {1}%.' -f $b.Short, $b.Score) }
        if ($null -ne $result.AzureScore) { $msg += (' Azure: {0}%.' -f $result.AzureScore) }
        if ($null -ne $result.ServerScore) { $msg += (' Servers: {0}%.' -f $result.ServerScore) }
        Write-TRLog $msg 'Success'
        $result
    }
    finally {
        $script:TRLogFile = $null
    }
}
