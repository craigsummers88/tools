param(
    [string]$Tenant = 'organizations',
    [string]$DisplayName = 'Tenant Review',
    [switch]$UpdateExisting
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSCommandPath
$configPath = Join-Path $root 'config.json'
Import-Module (Join-Path $root 'Module\TenantReview.psm1') -Force -DisableNameChecking
Import-TRSettings -Path $configPath | Out-Null

$graphCommandLineTools = '14d82eec-204b-4c2f-b7e8-296a70dab67e'
$graphAppId = '00000003-0000-0000-c000-000000000000'
$exoAppId = '00000002-0000-0ff1-ce00-000000000000'
$complianceAppId = '00000007-0000-0ff1-ce00-000000000000'

Write-Host ''
Write-Host 'Tenant Review: app registration setup' -ForegroundColor Cyan
Write-Host 'Sign in to your own tenant as a Global Administrator or Application Administrator.'
Write-Host 'This creates one multi-tenant, read-only, delegated app registration that engineers use to review client tenants.'
Write-Host ''

Connect-TRTenant -Tenant $Tenant -ClientId $graphCommandLineTools -Scope 'https://graph.microsoft.com/Application.ReadWrite.All https://graph.microsoft.com/User.Read offline_access openid profile' | Out-Null
$ctx = Get-TRContext
Write-Host ("Signed in to {0} as {1}" -f $ctx.TenantName, $ctx.Account) -ForegroundColor Green

function Get-ScopeIds {
    param([string]$ResourceAppId, [string[]]$Values, [switch]$Optional)
    $sp = Invoke-TRGraph -Path ("/servicePrincipals(appId='{0}')?`$select=id,displayName,oauth2PermissionScopes" -f $ResourceAppId)
    $map = @{}
    foreach ($s in @($sp.oauth2PermissionScopes)) { $map[[string]$s.value] = [string]$s.id }
    $access = New-Object System.Collections.ArrayList
    foreach ($v in $Values) {
        if ($map.ContainsKey($v)) { [void]$access.Add(@{ id = $map[$v]; type = 'Scope' }) }
        elseif ($Optional) { Write-Host ("  Optional permission {0} is not offered by {1}; skipped." -f $v, $sp.displayName) -ForegroundColor DarkGray }
        else { Write-Host ("  Permission {0} was not found on {1}; skipped. Related checks will show Not assessed." -f $v, $sp.displayName) -ForegroundColor Yellow }
    }
    , $access.ToArray()
}

function Get-ComplianceAccess {
    param([string[]]$Values)
    $name = 'https://ps.compliance.protection.outlook.com'
    $sel = '$select=id,appId,displayName,oauth2PermissionScopes'
    $sp = $null
    try {
        $filter = [uri]::EscapeDataString(("servicePrincipalNames/any(n:n eq '{0}')" -f $name))
        $sp = @((Invoke-TRGraph -Path ('/servicePrincipals?$filter={0}&{1}' -f $filter, $sel)).value)[0]
    }
    catch { }
    if (-not $sp) {
        try { $sp = Invoke-TRGraph -Path ("/servicePrincipals(appId='{0}')?{1}" -f $complianceAppId, $sel) } catch { }
    }
    if (-not $sp) {
        try {
            Invoke-TRGraph -Path '/servicePrincipals' -Method POST -Body @{ appId = $complianceAppId } | Out-Null
            Start-Sleep -Seconds 5
            $sp = Invoke-TRGraph -Path ("/servicePrincipals(appId='{0}')?{1}" -f $complianceAppId, $sel)
        }
        catch { }
    }
    if (-not $sp) {
        Write-Host '  The Security & Compliance API was not found in this tenant. Purview policy checks will fall back to Secure Score evidence.' -ForegroundColor Yellow
        return $null
    }
    $map = @{}
    foreach ($s in @($sp.oauth2PermissionScopes)) { if ($s -and $s.isEnabled -ne $false) { $map[[string]$s.value] = [string]$s.id } }
    $access = New-Object System.Collections.ArrayList
    $names = New-Object System.Collections.ArrayList
    foreach ($v in $Values) { if ($map.ContainsKey($v)) { [void]$access.Add(@{ id = $map[$v]; type = 'Scope' }); [void]$names.Add($v) } }
    if ($access.Count -eq 0 -and $map.Count) {
        $pick = @($map.Keys | Where-Object { $_ -match 'Manage' } | Select-Object -First 1)
        if ($pick.Count) { [void]$access.Add(@{ id = $map[$pick[0]]; type = 'Scope' }); [void]$names.Add($pick[0]) }
    }
    if ($access.Count -eq 0) {
        Write-Host ("  {0} offers no delegated permission this tool can use. Purview policy checks will fall back to Secure Score evidence." -f $sp.displayName) -ForegroundColor Yellow
        return $null
    }
    if ([string]$sp.appId -eq $exoAppId) { Write-Host ("  Security & Compliance uses the {0} permission ({1})." -f $sp.displayName, ($names -join ', ')) }
    else { Write-Host ("  Security & Compliance permission added: {0} on {1}." -f ($names -join ', '), $sp.displayName) }
    @{ resourceAppId = [string]$sp.appId; resourceAccess = $access.ToArray() }
}

$req = Get-TRRequiredScopes
Write-Host 'Resolving permissions...'
$graphRequired = Get-ScopeIds -ResourceAppId $graphAppId -Values $req.Graph
$graphOptional = Get-ScopeIds -ResourceAppId $graphAppId -Values $req.GraphOptional -Optional
$graphAccess = @($graphRequired) + @($graphOptional)
$exoAccess = Get-ScopeIds -ResourceAppId $exoAppId -Values $req.Exchange -Optional
if (@($exoAccess).Count -eq 0) { Write-Host '  No Exchange Online delegated permission was found. Exchange checks will not work.' -ForegroundColor Yellow }
$complianceAccess = Get-ComplianceAccess -Values $req.Compliance

function Merge-ResourceAccess {
    param([object[]]$Entries)
    $order = New-Object System.Collections.ArrayList
    $byApp = @{}
    foreach ($e in $Entries) {
        if (-not $e -or -not $e.resourceAppId) { continue }
        $key = ([string]$e.resourceAppId).ToLower()
        if (-not $byApp.ContainsKey($key)) {
            $byApp[$key] = @{ resourceAppId = [string]$e.resourceAppId; ids = New-Object System.Collections.ArrayList; access = New-Object System.Collections.ArrayList }
            [void]$order.Add($key)
        }
        foreach ($a in @($e.resourceAccess)) {
            if (-not $a -or -not $a.id) { continue }
            $id = ([string]$a.id).ToLower()
            if ($byApp[$key].ids.Contains($id)) { continue }
            [void]$byApp[$key].ids.Add($id)
            [void]$byApp[$key].access.Add(@{ id = [string]$a.id; type = [string]$a.type })
        }
    }
    $out = New-Object System.Collections.ArrayList
    foreach ($key in $order) {
        if ($byApp[$key].access.Count -eq 0) { continue }
        [void]$out.Add(@{ resourceAppId = $byApp[$key].resourceAppId; resourceAccess = $byApp[$key].access.ToArray() })
    }
    , $out.ToArray()
}

$resources = Merge-ResourceAccess -Entries @(
    @{ resourceAppId = $graphAppId; resourceAccess = @($graphAccess) },
    @{ resourceAppId = $exoAppId; resourceAccess = @($exoAccess) },
    $complianceAccess
)

$body = @{
    displayName            = $DisplayName
    signInAudience         = 'AzureADMultipleOrgs'
    isFallbackPublicClient = $true
    publicClient           = @{ redirectUris = @('http://localhost', 'https://login.microsoftonline.com/common/oauth2/nativeclient') }
    requiredResourceAccess = @($resources)
    notes                  = 'Read-only Microsoft 365 tenant review tool for IT consultants and managed service providers. Delegated permissions only; no secrets or certificates.'
}

$filter = [uri]::EscapeDataString(("displayName eq '{0}'" -f $DisplayName.Replace("'", "''")))
$existing = @((Invoke-TRGraph -Path ('/applications?$filter={0}&$select=id,appId,displayName' -f $filter)).value)
if ($existing.Count -gt 0) {
    if (-not $UpdateExisting) {
        Write-Host ("An app called '{0}' already exists (client ID {1}). Re-run with -UpdateExisting to refresh its permissions." -f $DisplayName, $existing[0].appId) -ForegroundColor Yellow
        $app = $existing[0]
    }
    else {
        Invoke-TRGraph -Path ('/applications/{0}' -f $existing[0].id) -Method PATCH -Body $body | Out-Null
        $app = $existing[0]
        Write-Host ("Updated permissions on {0}" -f $DisplayName) -ForegroundColor Green
    }
}
else {
    $app = Invoke-TRGraph -Path '/applications' -Method POST -Body $body
    Write-Host ("Created app registration {0}" -f $DisplayName) -ForegroundColor Green
    Start-Sleep -Seconds 5
}

try {
    Invoke-TRGraph -Path '/servicePrincipals' -Method POST -Body @{ appId = $app.appId } | Out-Null
    Write-Host 'Created the enterprise application in your own tenant.'
}
catch {
    if ($_.Exception.Message -notmatch 'already|exists|conflict') { Write-Host ('Enterprise application: ' + $_.Exception.Message) -ForegroundColor Yellow }
}

$cfg = [ordered]@{}
if (Test-Path -LiteralPath $configPath) {
    $loaded = Get-Content -LiteralPath $configPath -Raw -Encoding UTF8 | ConvertFrom-Json
    foreach ($p in $loaded.PSObject.Properties) { $cfg[$p.Name] = $p.Value }
}
$cfg['ClientId'] = [string]$app.appId
[IO.File]::WriteAllText($configPath, (ConvertTo-Json -InputObject $cfg -Depth 5), (New-Object System.Text.UTF8Encoding($false)))

Write-Host ''
Write-Host ("Client ID: {0}" -f $app.appId) -ForegroundColor Cyan
Write-Host ("Saved to {0}" -f $configPath)
Write-Host ''
Write-Host 'Next steps:'
Write-Host '  1. Share this folder (with config.json) with the engineers who will run reviews.'
Write-Host '  2. For each client, use Grant consent in the app once (and again after running this script with -UpdateExisting), or send the client this link:'
Write-Host ('     https://login.microsoftonline.com/<client-tenant>/adminconsent?client_id={0}' -f $app.appId)
Write-Host '  3. Optional: verify your organisation as the publisher of this app (Microsoft Partner ID) so the consent screen shows a verified publisher.'
Write-Host ''
