if ($PSVersionTable.PSEdition -ne 'Core') {
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { }
}

$script:TRRoot = Split-Path -Parent $PSScriptRoot

foreach ($file in 'Api', 'Auth', 'GoogleApi', 'Collect', 'AzureCollect', 'GoogleCollect', 'Helpers', 'GoogleHelpers', 'Checks', 'IntuneChecks', 'AzureChecks', 'ServerChecks', 'GoogleChecks', 'Opportunities', 'GoogleOpportunities', 'Baselines', 'BaselinesCis', 'BaselinesScuba', 'GoogleBaselinesCis', 'GoogleBaselinesScuba', 'Inventory', 'GoogleInventory', 'ActionPlan', 'Report', 'Engine') {
    . (Join-Path (Join-Path $PSScriptRoot 'Private') ($file + '.ps1'))
}

Export-ModuleMember -Function @(
    'Write-TRLog', 'Set-TRHost', 'Set-TRProgress', 'New-TRContext', 'Get-TRContext',
    'Connect-TRTenant', 'Request-TRAdminConsent', 'Request-TRServiceAccess', 'Remove-TRTenantApp', 'Clear-TRSession', 'Set-TRTestToken', 'Get-TRAccessToken',
    'Connect-TRGoogle', 'Remove-TRGoogleAccess', 'Invoke-TRGoogle', 'Invoke-TRGoogleCollection', 'Set-TRGoogleTestToken', 'Get-TRGoogleMissingScopes', 'Get-TRGoogleScopeString',
    'Invoke-TRGraph', 'Invoke-TRExo', 'Invoke-TRCompliance', 'Invoke-TRHunting', 'Resolve-TRDns',
    'Invoke-TenantCollection', 'Invoke-TenantAnalysis', 'Invoke-TenantReview', 'Import-TRServerData',
    'Import-TRSettings', 'Set-TRSettingsObject', 'Get-TRDefaultSettings', 'Get-TRToolVersion', 'Get-TRRequiredScopes',
    'Test-TRGrantedScopes', 'Get-TRConsentUrl', 'Read-TRRawFile', 'Save-TRRawFile', 'ConvertFrom-TRJwt'
)
