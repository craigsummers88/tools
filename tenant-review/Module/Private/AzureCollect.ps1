$script:TRAzureKeys = @('AzSubscriptions', 'AzResourceCounts', 'AzVms', 'AzVmExtensions', 'AzArcMachines', 'AzNics', 'AzNsgRules', 'AzSubnets', 'AzPublicIps', 'AzLoadBalancers', 'AzBastions', 'AzNetworkWatchers', 'AzVnets', 'AzStorage', 'AzKeyVaults', 'AzSqlServers', 'AzWebApps', 'AzDisks', 'AzBackupItems', 'AzRecoveryVaults', 'AzAdvisor', 'AzSecurityAssessments', 'AzSecureScores', 'AzRegulatory', 'AzRegulatoryControls', 'AzRoleAssignments', 'AzRoleDefinitions', 'AzPrincipals', 'AzPolicyAssignments', 'AzPatchAssessments', 'AzDefenderPlans', 'AzSecurityContacts', 'AzActivityLogSettings', 'AzLocks', 'AzBudgets', 'AzAccess')

$script:TRArgQueries = [ordered]@{
    AzResourceCounts       = "resources | summarize count=count() by type, subscriptionId"
    AzVms                  = "resources | where type =~ 'microsoft.compute/virtualmachines' | project id=tolower(id), name, resourceGroup, subscriptionId, location, vmSize=tostring(properties.hardwareProfile.vmSize), osType=tostring(properties.storageProfile.osDisk.osType), osName=tostring(properties.extended.instanceView.osName), osVersion=tostring(properties.extended.instanceView.osVersion), powerState=tostring(properties.extended.instanceView.powerState.code), imagePublisher=tostring(properties.storageProfile.imageReference.publisher), imageOffer=tostring(properties.storageProfile.imageReference.offer), imageSku=tostring(properties.storageProfile.imageReference.sku), securityType=tostring(properties.securityProfile.securityType), licenseType=tostring(properties.licenseType), zones=tostring(zones), bootDiagnostics=tostring(properties.diagnosticsProfile.bootDiagnostics.enabled), patchMode=tostring(properties.osProfile.windowsConfiguration.patchSettings.patchMode), assessmentMode=tostring(properties.osProfile.windowsConfiguration.patchSettings.assessmentMode), tags=tostring(tags)"
    AzVmExtensions         = "resources | where type =~ 'microsoft.compute/virtualmachines/extensions' or type =~ 'microsoft.hybridcompute/machines/extensions' | project vmId=tolower(tostring(split(id, '/extensions/')[0])), name, publisher=tostring(properties.publisher), extensionType=tostring(properties.type), state=tostring(properties.provisioningState)"
    AzArcMachines          = "resources | where type =~ 'microsoft.hybridcompute/machines' | project id=tolower(id), name, resourceGroup, subscriptionId, location, status=tostring(properties.status), osName=tostring(properties.osName), osVersion=tostring(properties.osVersion), osSku=tostring(properties.osSku), lastStatusChange=tostring(properties.lastStatusChange), agentVersion=tostring(properties.agentVersion), esu=tostring(properties.licenseProfile.esuProfile.licenseAssignmentState)"
    AzNics                 = "resources | where type =~ 'microsoft.network/networkinterfaces' | mv-expand ipc=properties.ipConfigurations | project nicId=tolower(id), vmId=tolower(tostring(properties.virtualMachine.id)), publicIpId=tolower(tostring(ipc.properties.publicIPAddress.id)), subnetId=tolower(tostring(ipc.properties.subnet.id)), privateIp=tostring(ipc.properties.privateIPAddress), nsgId=tolower(tostring(properties.networkSecurityGroup.id))"
    AzNsgRules             = "resources | where type =~ 'microsoft.network/networksecuritygroups' | mv-expand rule=properties.securityRules | extend r=rule.properties | where tostring(r.direction) =~ 'Inbound' and tostring(r.access) =~ 'Allow' | project nsgId=tolower(id), nsg=name, resourceGroup, subscriptionId, rule=tostring(rule.name), priority=toint(r.priority), protocol=tostring(r.protocol), source=tostring(r.sourceAddressPrefix), sources=tostring(r.sourceAddressPrefixes), port=tostring(r.destinationPortRange), ports=tostring(r.destinationPortRanges)"
    AzSubnets              = "resources | where type =~ 'microsoft.network/virtualnetworks' | mv-expand s=properties.subnets | project vnet=name, resourceGroup, subscriptionId, location, subnetId=tolower(tostring(s.id)), subnet=tostring(s.name), prefix=tostring(s.properties.addressPrefix), nsgId=tolower(tostring(s.properties.networkSecurityGroup.id)), delegated=array_length(s.properties.delegations)"
    AzVnets                = "resources | where type =~ 'microsoft.network/virtualnetworks' | project id=tolower(id), name, resourceGroup, subscriptionId, location, ddos=tostring(properties.enableDdosProtection), peerings=array_length(properties.virtualNetworkPeerings)"
    AzPublicIps            = "resources | where type =~ 'microsoft.network/publicipaddresses' | project id=tolower(id), name, resourceGroup, subscriptionId, location, sku=tostring(sku.name), ipAddress=tostring(properties.ipAddress), attachedTo=tolower(tostring(properties.ipConfiguration.id)), allocation=tostring(properties.publicIPAllocationMethod)"
    AzLoadBalancers        = "resources | where type =~ 'microsoft.network/loadbalancers' | project id=tolower(id), name, resourceGroup, subscriptionId, sku=tostring(sku.name)"
    AzBastions             = "resources | where type =~ 'microsoft.network/bastionhosts' | project id=tolower(id), name, resourceGroup, subscriptionId, location, sku=tostring(sku.name)"
    AzNetworkWatchers      = "resources | where type =~ 'microsoft.network/networkwatchers' | project name, subscriptionId, location"
    AzStorage              = "resources | where type =~ 'microsoft.storage/storageaccounts' | project id=tolower(id), name, resourceGroup, subscriptionId, location, kind, sku=tostring(sku.name), allowBlobPublicAccess=tostring(properties.allowBlobPublicAccess), minimumTlsVersion=tostring(properties.minimumTlsVersion), httpsOnly=tostring(properties.supportsHttpsTrafficOnly), allowSharedKeyAccess=tostring(properties.allowSharedKeyAccess), defaultAction=tostring(properties.networkAcls.defaultAction), publicNetworkAccess=tostring(properties.publicNetworkAccess), crossTenantReplication=tostring(properties.allowCrossTenantReplication)"
    AzKeyVaults            = "resources | where type =~ 'microsoft.keyvault/vaults' | project id=tolower(id), name, resourceGroup, subscriptionId, location, softDelete=tostring(properties.enableSoftDelete), purgeProtection=tostring(properties.enablePurgeProtection), rbac=tostring(properties.enableRbacAuthorization), defaultAction=tostring(properties.networkAcls.defaultAction), publicNetworkAccess=tostring(properties.publicNetworkAccess)"
    AzSqlServers           = "resources | where type =~ 'microsoft.sql/servers' | project id=tolower(id), name, resourceGroup, subscriptionId, location, publicNetworkAccess=tostring(properties.publicNetworkAccess), minimalTlsVersion=tostring(properties.minimalTlsVersion), entraOnly=tostring(properties.administrators.azureADOnlyAuthentication), entraAdmin=tostring(properties.administrators.login)"
    AzWebApps              = "resources | where type =~ 'microsoft.web/sites' | project id=tolower(id), name, resourceGroup, subscriptionId, location, kind, state=tostring(properties.state), httpsOnly=tostring(properties.httpsOnly), publicNetworkAccess=tostring(properties.publicNetworkAccess), minTlsVersion=tostring(properties.siteConfig.minTlsVersion), ftpsState=tostring(properties.siteConfig.ftpsState), clientCertEnabled=tostring(properties.clientCertEnabled)"
    AzDisks                = "resources | where type =~ 'microsoft.compute/disks' | project id=tolower(id), name, resourceGroup, subscriptionId, location, diskState=tostring(properties.diskState), sizeGb=toint(properties.diskSizeGB), sku=tostring(sku.name), managedBy=tolower(tostring(managedBy)), networkAccessPolicy=tostring(properties.networkAccessPolicy), timeCreated=tostring(properties.timeCreated)"
    AzBackupItems          = "recoveryservicesresources | where type =~ 'microsoft.recoveryservices/vaults/backupfabrics/protectioncontainers/protecteditems' | project sourceId=tolower(tostring(properties.sourceResourceId)), vault=tostring(split(id, '/')[8]), subscriptionId, workload=tostring(properties.workloadType), lastBackup=tostring(properties.lastBackupTime), lastBackupStatus=tostring(properties.lastBackupStatus), health=tostring(properties.healthStatus), protectionState=tostring(properties.protectionState), policy=tostring(properties.policyName), friendlyName=tostring(properties.friendlyName)"
    AzRecoveryVaults       = "resources | where type =~ 'microsoft.recoveryservices/vaults' | project id=tolower(id), name, resourceGroup, subscriptionId, location, softDelete=tostring(properties.securitySettings.softDeleteSettings.softDeleteState), immutability=tostring(properties.securitySettings.immutabilitySettings.state), redundancy=tostring(properties.redundancySettings.standardTierStorageRedundancy), crossRegionRestore=tostring(properties.redundancySettings.crossRegionRestore), publicNetworkAccess=tostring(properties.publicNetworkAccess), resourceGuard=array_length(properties.resourceGuardOperationRequests)"
    AzAdvisor              = "advisorresources | where type =~ 'microsoft.advisor/recommendations' | project subscriptionId, category=tostring(properties.category), impact=tostring(properties.impact), problem=tostring(properties.shortDescription.problem), solution=tostring(properties.shortDescription.solution), resource=tostring(properties.impactedValue), resourceType=tostring(properties.impactedField), annualSavings=todouble(properties.extendedProperties.annualSavingsAmount), currency=tostring(properties.extendedProperties.savingsCurrency)"
    AzSecurityAssessments  = "securityresources | where type =~ 'microsoft.security/assessments' | where tostring(properties.status.code) =~ 'Unhealthy' | summarize resources=count() by subscriptionId, recommendation=tostring(properties.displayName), severity=tostring(properties.metadata.severity)"
    AzSecureScores         = "securityresources | where type =~ 'microsoft.security/securescores' | where name =~ 'ascScore' | project subscriptionId, current=todouble(properties.score.current), max=todouble(properties.score.max), percentage=todouble(properties.score.percentage)"
    AzRegulatory           = "securityresources | where type =~ 'microsoft.security/regulatorycompliancestandards' | project subscriptionId, standard=name, state=tostring(properties.state), passed=toint(properties.passedControls), failed=toint(properties.failedControls), skipped=toint(properties.skippedControls)"
    AzRegulatoryControls   = "securityresources | where type =~ 'microsoft.security/regulatorycompliancestandards/regulatorycompliancecontrols' | where tostring(properties.state) =~ 'Failed' | extend standard=tostring(split(id, '/')[6]) | where standard =~ 'Microsoft-cloud-security-benchmark' | project subscriptionId, standard, control=name, description=tostring(properties.description), failedAssessments=toint(properties.failedAssessments)"
    AzRoleAssignments      = "authorizationresources | where type =~ 'microsoft.authorization/roleassignments' | project id=tolower(id), scope=tolower(tostring(properties.scope)), principalId=tostring(properties.principalId), principalType=tostring(properties.principalType), roleDefinitionId=tolower(tostring(properties.roleDefinitionId)), createdOn=tostring(properties.createdOn)"
    AzRoleDefinitions      = "authorizationresources | where type =~ 'microsoft.authorization/roledefinitions' | project id=tolower(id), name=tolower(name), roleName=tostring(properties.roleName), roleType=tostring(properties.type)"
    AzPolicyAssignments    = "policyresources | where type =~ 'microsoft.authorization/policyassignments' | project name, displayName=tostring(properties.displayName), scope=tolower(tostring(properties.scope)), policyDefinitionId=tolower(tostring(properties.policyDefinitionId)), enforcementMode=tostring(properties.enforcementMode)"
    AzPatchAssessments     = "patchassessmentresources | where type =~ 'microsoft.compute/virtualmachines/patchassessmentresults' or type =~ 'microsoft.hybridcompute/machines/patchassessmentresults' | project vmId=tostring(split(tolower(id), '/patchassessmentresults/')[0]), status=tostring(properties.status), lastModified=tostring(properties.lastModifiedDateTime), critical=toint(properties.availablePatchCountByClassification.critical), security=toint(properties.availablePatchCountByClassification.security), rebootPending=tostring(properties.rebootPending)"
}

function Invoke-TRArm {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [string]$Method = 'GET',
        $Body,
        [switch]$All,
        [int]$MaxItems = 0,
        [int]$MaxRetry = 4
    )
    $ctx = Get-TRContext
    $uri = if ($Path -match '^https?://') { $Path } else { $ctx.ArmBase + $Path }
    $json = $null
    if ($null -ne $Body) { $json = if ($Body -is [string]) { $Body } else { ConvertTo-Json -InputObject $Body -Depth 20 -Compress } }
    $results = New-Object System.Collections.ArrayList
    while ($uri) {
        $headers = @{ Authorization = 'Bearer ' + (Get-TRAccessToken -Resource Azure) }
        $r = Invoke-TRRest -Method $Method -Uri $uri -Headers $headers -Body $json -MaxRetry $MaxRetry
        if (-not $All) { return $r }
        if (Test-TRHasProperty $r 'value') { foreach ($i in @($r.value)) { if ($null -ne $i) { [void]$results.Add($i) } } }
        elseif ($null -ne $r) { [void]$results.Add($r) }
        if ($MaxItems -gt 0 -and $results.Count -ge $MaxItems) { break }
        $uri = $null
        if ((Test-TRHasProperty $r 'nextLink') -and $r.nextLink) {
            $uri = [string]$r.nextLink
            if ($ctx.ArmBase -ne 'https://management.azure.com') { $uri = $uri -replace '^https://management\.azure\.com', $ctx.ArmBase }
        }
    }
    , $results.ToArray()
}

function Invoke-TRArg {
    param([Parameter(Mandatory = $true)][string]$Query, [string[]]$Subscriptions, [int]$MaxRows = 20000)
    $rows = New-Object System.Collections.ArrayList
    $subs = @($Subscriptions | Where-Object { $_ })
    for ($i = 0; $i -lt [Math]::Max(1, $subs.Count); $i += 1000) {
        $batch = @($subs | Select-Object -Skip $i -First 1000)
        $skip = $null
        do {
            Test-TRCancelled
            $opts = [ordered]@{ '$top' = 1000; resultFormat = 'objectArray' }
            if ($skip) { $opts['$skipToken'] = $skip }
            $body = [ordered]@{ query = $Query; options = $opts }
            if ($batch.Count) { $body['subscriptions'] = $batch }
            $r = Invoke-TRArm -Path '/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01' -Method POST -Body $body
            foreach ($d in @($r.data)) { if ($null -ne $d) { [void]$rows.Add($d) } }
            $skip = $null
            if ((Test-TRHasProperty $r '$skipToken') -and $r.'$skipToken') { $skip = [string]$r.'$skipToken' }
        } while ($skip -and $rows.Count -lt $MaxRows)
    }
    , $rows.ToArray()
}

function Get-TRAzureOfferType {
    param([string]$QuotaId)
    switch -Regex ($QuotaId) {
        '^CSP' { 'CSP'; break }
        '^Enterprise|^EA' { 'Enterprise Agreement'; break }
        '^PayAsYouGo' { 'Pay as you go'; break }
        'MSDN|VisualStudio|MPN' { 'Visual Studio or partner benefit'; break }
        'Sponsored|AzurePass' { 'Sponsored'; break }
        'FreeTrial' { 'Free trial'; break }
        '^Internal' { 'Microsoft internal'; break }
        default { if ($QuotaId) { $QuotaId } else { 'Unknown' } }
    }
}

function Invoke-TRCollectAzure {
    Set-TRProgress 78 'Collecting Azure subscriptions and resources'
    $state = [string]$script:TRRaw['Meta']['ServiceAccess']['Azure']
    if ($state -ne 'Ready') {
        $why = if ($state -like 'Skipped*') { 'Azure is not set up in this tenant (no Azure Resource Manager service principal).' } else { 'Azure Resource Manager access was not granted: ' + $state }
        Skip-TRStep 'Azure' $script:TRAzureKeys $why
        $script:TRRaw['Meta']['AzureAvailable'] = $false
        return
    }
    $ok = Invoke-TRStep 'Azure' 'AzSubscriptions' -List {
        Invoke-TRArm -Path '/subscriptions?api-version=2022-12-01' -All | ForEach-Object { $_ } | ForEach-Object {
            [pscustomobject]@{ subscriptionId = [string]$_.subscriptionId; displayName = [string]$_.displayName; state = [string]$_.state; authorizationSource = [string]$_.authorizationSource; quotaId = [string]$_.subscriptionPolicies.quotaId; spendingLimit = [string]$_.subscriptionPolicies.spendingLimit; offer = (Get-TRAzureOfferType ([string]$_.subscriptionPolicies.quotaId)); managedByTenants = @($_.managedByTenants | ForEach-Object { [string]$_.tenantId }) -join ', ' }
        }
    }
    $subs = @(@($script:TRRaw['AzSubscriptions']) | Where-Object { $_ -and $_.state -in @('Enabled', 'PastDue', 'Warned') })
    $rest = @($script:TRAzureKeys | Where-Object { $_ -ne 'AzSubscriptions' })
    if (-not $ok) { Skip-TRStep 'Azure' $rest 'Azure subscriptions could not be listed.'; $script:TRRaw['Meta']['AzureAvailable'] = $false; return }
    if (-not $subs.Count) {
        Skip-TRStep 'Azure' $rest 'The signed-in account cannot see any active Azure subscription in this tenant.'
        $script:TRRaw['Meta']['AzureAvailable'] = $false
        Write-TRLog 'No active Azure subscription is visible to the signed-in account. If the client has Azure, give the account Reader on each subscription (or use CSP admin access) and run the review again.' 'Warn'
        return
    }
    $script:TRRaw['Meta']['AzureAvailable'] = $true
    $ids = @($subs | ForEach-Object { $_.subscriptionId })
    Write-TRLog ('Azure: {0} visible.' -f (Format-TRN $subs.Count 'active subscription is' 'active subscriptions are'))
    $n = 0
    foreach ($k in $script:TRArgQueries.Keys) {
        $n++
        Set-TRProgress (78 + [int](4 * $n / $script:TRArgQueries.Count)) ('Reading Azure resources: ' + $k.Substring(2))
        $q = $script:TRArgQueries[$k]
        Invoke-TRStep 'Azure' $k -List -Optional { Invoke-TRArg -Query $q -Subscriptions $ids } | Out-Null
    }
    Invoke-TRStep 'Azure' 'AzPrincipals' -List -Optional {
        $pids = @(@($script:TRRaw['AzRoleAssignments']) | Where-Object { $_ } | ForEach-Object { [string]$_.principalId } | Where-Object { $_ } | Select-Object -Unique)
        for ($i = 0; $i -lt $pids.Count; $i += 1000) {
            $chunk = @($pids | Select-Object -Skip $i -First 1000)
            $r = Invoke-TRGraph -Path '/directoryObjects/getByIds' -Method POST -Body @{ ids = $chunk; types = @('user', 'group', 'servicePrincipal') } -All
            foreach ($o in @($r)) {
                if ($null -eq $o) { continue }
                [pscustomobject]@{ id = [string]$o.id; type = ([string]$o.'@odata.type' -replace '^#microsoft\.graph\.', ''); displayName = [string]$o.displayName; userPrincipalName = [string]$o.userPrincipalName; userType = [string]$o.userType; appId = [string]$o.appId }
            }
        }
    } | Out-Null
    Set-TRProgress 83 'Reading Azure security and governance settings'
    $perSub = [ordered]@{
        AzDefenderPlans       = @{ Path = '/subscriptions/{0}/providers/Microsoft.Security/pricings?api-version=2024-01-01'; Fallback = '/subscriptions/{0}/providers/Microsoft.Security/pricings?api-version=2023-01-01' }
        AzSecurityContacts    = @{ Path = '/subscriptions/{0}/providers/Microsoft.Security/securityContacts?api-version=2023-12-01-preview'; Fallback = '/subscriptions/{0}/providers/Microsoft.Security/securityContacts?api-version=2020-01-01-preview' }
        AzActivityLogSettings = @{ Path = '/subscriptions/{0}/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview'; Fallback = $null }
        AzLocks               = @{ Path = '/subscriptions/{0}/providers/Microsoft.Authorization/locks?api-version=2020-05-01'; Fallback = $null }
        AzBudgets             = @{ Path = '/subscriptions/{0}/providers/Microsoft.Consumption/budgets?api-version=2023-05-01'; Fallback = $null }
    }
    $access = New-Object System.Collections.ArrayList
    foreach ($k in $perSub.Keys) {
        $def = $perSub[$k]
        Invoke-TRStep 'Azure' $k -List -Optional {
            $okCount = 0
            $errs = @()
            foreach ($s in ($subs | Select-Object -First 50)) {
                Test-TRCancelled
                try {
                    $items = $null
                    try { $items = Invoke-TRArm -Path ($def.Path -f $s.subscriptionId) -All -MaxRetry 3 }
                    catch {
                        if (-not $def.Fallback -or [int]$_.Exception.Data['HttpStatus'] -in @(401, 403, 404)) { throw }
                        $items = Invoke-TRArm -Path ($def.Fallback -f $s.subscriptionId) -All -MaxRetry 3
                    }
                    $okCount++
                    foreach ($i in @($items)) { if ($null -ne $i) { $i | Add-Member -NotePropertyName 'subscriptionId' -NotePropertyValue $s.subscriptionId -Force; $i } }
                }
                catch {
                    $http = [int]$_.Exception.Data['HttpStatus']
                    $errs += ('{0}: {1}' -f $s.displayName, $_.Exception.Message)
                    [void]$access.Add([pscustomobject]@{ subscriptionId = $s.subscriptionId; subscription = $s.displayName; item = $k; http = $http; message = $_.Exception.Message })
                }
            }
            if (-not $okCount -and $errs.Count) { throw ($errs[0]) }
        } | Out-Null
    }
    Invoke-TRStep 'Azure' 'AzAccess' -List -Optional { $access.ToArray() } | Out-Null
}
