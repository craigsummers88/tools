function Get-TRGwsInventories {
    $inv = New-Object System.Collections.Specialized.OrderedDictionary
    $usage = Get-TRGwsUsage
    $lic = Get-TRGwsUserLicences
    $roles = @{}
    foreach ($r in (Get-TRGwsRoleRows)) {
        $k = $r.Email.ToLower()
        if (-not $roles.ContainsKey($k)) { $roles[$k] = New-Object System.Collections.ArrayList }
        if (-not $roles[$k].Contains($r.Role)) { [void]$roles[$k].Add($r.Role) }
    }

    if (Test-TRCollected @('GwsUsers')) {
        $rows = foreach ($u in (Get-TRItems 'GwsUsers' | Sort-Object primaryEmail)) {
            $k = ([string]$u.primaryEmail).ToLower()
            $x = $usage[$k]
            [pscustomobject][ordered]@{
                'Email'           = $u.primaryEmail
                'Name'            = $u.name.fullName
                'Status'          = $(if ($u.archived) { 'Archived' } elseif ($u.suspended) { 'Suspended' } else { 'Active' })
                'Organisational unit' = $u.orgUnitPath
                'Super admin'     = ConvertTo-TRYesNo ([bool]$u.isAdmin)
                'Admin roles'     = $(if ($roles.ContainsKey($k)) { ($roles[$k] -join ', ') } else { '' })
                '2SV enrolled'    = ConvertTo-TRYesNo ([bool]$u.isEnrolledIn2Sv)
                '2SV enforced'    = ConvertTo-TRYesNo ([bool]$u.isEnforcedIn2Sv)
                'Security keys'   = $(if ($x) { $x.accounts_num_security_keys } else { '' })
                'Passkeys'        = $(if ($x) { $x.accounts_num_passkeys_enrolled } else { '' })
                'Password strength' = $(if ($x) { $x.accounts_password_strength } else { '' })
                'Licences'        = $(if ($lic.ContainsKey($k)) { (@($lic[$k] | ForEach-Object { Get-TRGwsSkuName $_ }) -join ', ') } else { '' })
                'Last sign-in'    = $(if ($null -ne (Get-TRGwsDays $u.lastLoginTime)) { Format-TRDate $u.lastLoginTime } else { 'Never' })
                'Created'         = Format-TRDate $u.creationTime
                'Recovery email'  = $u.recoveryEmail
                'Storage used (MB)' = $(if ($x) { $x.accounts_used_quota_in_mb } else { '' })
                'Third-party apps' = $(if ($x) { $x.accounts_num_authorized_apps } else { '' })
            }
        }
        Add-TRInventory $inv 'GwsUsers' 'Users' 'All user accounts with status, 2-Step Verification, admin roles and licences.' $rows
    }

    $rr = @(Get-TRGwsRoleRows)
    if ($rr.Count) {
        $rows = foreach ($r in ($rr | Sort-Object @{ e = { -not $_.IsSuperAdmin } }, Role, Email)) {
            [pscustomobject][ordered]@{ 'Role' = $r.Role; 'Assigned to' = $r.Email; 'Type' = $r.AssigneeType; 'Super admin role' = ConvertTo-TRYesNo $r.IsSuperAdmin; 'Built-in' = ConvertTo-TRYesNo $r.IsSystemRole; 'Scope' = $r.Scope; 'Suspended' = ConvertTo-TRYesNo $r.Suspended }
        }
        Add-TRInventory $inv 'GwsAdminRoles' 'Admin roles' 'Every admin role assignment.' $rows
    }

    if (Test-TRCollected @('GwsLicences')) {
        $rows = foreach ($l in (Get-TRItems 'GwsLicences' | Sort-Object userId)) {
            [pscustomobject][ordered]@{ 'User' = $l.userId; 'Licence' = (Get-TRGwsSkuName ([string]$l.skuId) ([string]$l.skuName)); 'Product' = $l.productName; 'SKU ID' = $l.skuId }
        }
        Add-TRInventory $inv 'GwsLicences' 'Licences' 'Licence assignments from the License Manager API.' $rows
    }

    if (Test-TRCollected @('GwsDomains')) {
        $dns = @{}
        foreach ($d in (Get-TRItems 'GwsDnsRecords')) { $dns[$d.Domain] = $d }
        $rows = foreach ($d in (Get-TRItems 'GwsDomains')) {
            $names = @(@{ N = [string]$d.domainName; T = $(if ($d.isPrimary) { 'Primary' } else { 'Secondary' }); V = $d.verified }) + @(@($d.domainAliases) | Where-Object { $_ } | ForEach-Object { @{ N = [string]$_.domainAliasName; T = 'Alias'; V = $_.verified } })
            foreach ($n in $names) {
                $r = $dns[$n.N]
                [pscustomobject][ordered]@{
                    'Domain'   = $n.N
                    'Type'     = $n.T
                    'Verified' = ConvertTo-TRYesNo ([bool]$n.V)
                    'MX'       = $(if ($r) { (Get-TRStrings $r.Mx | ForEach-Object { (($_ -split '\s+')[-1]).TrimEnd('.') }) -join ', ' } else { '' })
                    'SPF'      = $(if ($r) { (Get-TRStrings $r.Spf) -join ' | ' } else { '' })
                    'DKIM'     = $(if ($r) { $b = Get-TRGwsDkimBits $r; if ($b) { '{0}-bit ({1})' -f $b, $r.DkimSelector } else { 'Not found' } } else { '' })
                    'DMARC'    = $(if ($r) { (Get-TRStrings $r.Dmarc) -join ' | ' } else { '' })
                    'MTA-STS'  = $(if ($r) { ConvertTo-TRYesNo ([bool]@(Get-TRStrings $r.MtaSts).Count) } else { '' })
                }
            }
        }
        Add-TRInventory $inv 'GwsDomains' 'Domains and DNS' 'Domains in Google Workspace with their mail DNS records.' $rows
    }

    if (Test-TRCollected @('GwsOrgUnits')) {
        $counts = @{}
        foreach ($u in (Get-TRItems 'GwsUsers')) { $p = [string]$u.orgUnitPath; if ($counts.ContainsKey($p)) { $counts[$p]++ } else { $counts[$p] = 1 } }
        $rows = foreach ($o in (Get-TRItems 'GwsOrgUnits' | Sort-Object orgUnitPath)) {
            [pscustomobject][ordered]@{ 'Path' = $o.orgUnitPath; 'Name' = $o.name; 'Description' = $o.description; 'Users' = $(if ($counts.ContainsKey([string]$o.orgUnitPath)) { $counts[[string]$o.orgUnitPath] } else { 0 }) }
        }
        Add-TRInventory $inv 'GwsOrgUnits' 'Organisational units' 'The organisational unit structure and how many users are in each unit.' $rows
    }

    if (Test-TRCollected @('GwsPolicies')) {
        $idx = Get-TRGwsPolicyIndex
        $rows = foreach ($t in ($idx.Keys | Sort-Object)) {
            foreach ($p in ($idx[$t] | Sort-Object @{ e = { -not $_.IsRoot } }, Scope)) {
                $val = ConvertTo-Json -InputObject $p.Value -Depth 8 -Compress
                if ($val.Length -gt 600) { $val = $val.Substring(0, 600) + '...' }
                [pscustomobject][ordered]@{ 'Setting' = $t; 'Applies to' = $p.Scope; 'Value' = $val }
            }
        }
        Add-TRInventory $inv 'GwsSettings' 'Admin console settings' 'Every setting returned by the Google Policy API, including organisational unit and group overrides.' $rows
    }

    if (Test-TRCollected @('GwsGroups')) {
        $set = @{}
        foreach ($s in (Get-TRItems 'GwsGroupSettings')) { $set[([string]$s.email).ToLower()] = $s }
        $rows = foreach ($g in (Get-TRItems 'GwsGroups' | Sort-Object email)) {
            $s = $set[([string]$g.email).ToLower()]
            [pscustomobject][ordered]@{
                'Group' = $g.email; 'Name' = $g.name; 'Members' = $g.directMembersCount; 'Created by admin' = ConvertTo-TRYesNo $g.adminCreated
                'Who can join' = $(if ($s) { $s.whoCanJoin } else { '' }); 'Who can post' = $(if ($s) { $s.whoCanPostMessage } else { '' })
                'Who can view conversations' = $(if ($s) { $s.whoCanViewGroup } else { '' }); 'External members allowed' = $(if ($s) { ConvertTo-TRYesNo $s.allowExternalMembers } else { '' })
            }
        }
        Add-TRInventory $inv 'GwsGroups' 'Groups' 'Groups with their access settings.' $rows
    }

    if (Test-TRCollected @('GwsGroupMembers')) {
        $rows = foreach ($m in (Get-TRItems 'GwsGroupMembers' | Sort-Object Group, Role, Member)) {
            [pscustomobject][ordered]@{ 'Group' = $m.Group; 'Member' = $m.Member; 'Role' = $m.Role; 'Type' = $m.Type; 'External' = ConvertTo-TRYesNo (-not (Test-TRGwsInternal $m.Member)) }
        }
        Add-TRInventory $inv 'GwsGroupMembers' 'Group membership' 'Direct members of every group, with external members flagged.' $rows
    }

    if (Test-TRCollected @('GwsTokens')) {
        $rows = foreach ($g in (Get-TRItems 'GwsTokens' | Where-Object { -not $_.NativeApp } | Group-Object App | Sort-Object Count -Descending)) {
            $scopes = @($g.Group | ForEach-Object { $_.Scopes } | Select-Object -Unique)
            [pscustomobject][ordered]@{
                'App' = $g.Name; 'Client ID' = $g.Group[0].ClientId; 'Users' = $g.Count
                'High-impact access' = ConvertTo-TRYesNo ([bool]@(Get-TRGwsTokenRisk $scopes).Count)
                'Scopes' = ((@($scopes) | ForEach-Object { $_ -replace '^https://www\.googleapis\.com/auth/', '' }) -join ', ')
                'Granted by' = (Join-TRList ($g.Group | ForEach-Object { $_.User }) 10)
            }
        }
        Add-TRInventory $inv 'GwsApps' 'Third-party apps' 'Apps users have granted access to their Google data.' $rows
    }

    if (Test-TRCollected @('GwsAsps')) {
        Add-TRInventory $inv 'GwsAsps' 'App passwords' 'App passwords that bypass 2-Step Verification.' (@(Get-TRItems 'GwsAsps' | ForEach-Object { [pscustomobject][ordered]@{ 'User' = $_.User; 'Name' = $_.Name } }))
    }

    if (Test-TRCollected @('GwsDevices')) {
        $owner = @{}
        foreach ($du in (Get-TRItems 'GwsDeviceUsers')) { $dn = ([string]$du.name -replace '/deviceUsers/.*$', ''); if ($du.userEmail) { $owner[$dn] = [string]$du.userEmail } }
        $rows = foreach ($d in (Get-TRItems 'GwsDevices' | Sort-Object deviceType, model)) {
            [pscustomobject][ordered]@{
                'Type' = $d.deviceType; 'Model' = $d.model; 'Serial' = $d.serialNumber; 'OS' = $d.osVersion; 'User' = $owner[[string]$d.name]
                'Ownership' = $d.ownerType; 'Encryption' = $d.encryptionState; 'Compromised' = $d.compromisedState
                'Last sync' = Format-TRDate $d.lastSyncTime; 'Security patch' = Format-TRDate $d.securityPatchTime
            }
        }
        Add-TRInventory $inv 'GwsDevices' 'Devices' 'Devices in Google endpoint management.' $rows
    }

    if (Test-TRCollected @('GwsChromeDevices')) {
        $rows = foreach ($c in (Get-TRItems 'GwsChromeDevices')) {
            [pscustomobject][ordered]@{ 'Serial' = $c.serialNumber; 'Model' = $c.model; 'Status' = $c.status; 'ChromeOS' = $c.osVersion; 'Organisational unit' = $c.orgUnitPath; 'User' = $c.annotatedUser; 'Last sync' = Format-TRDate $c.lastSync; 'Updates until' = Format-TRDate $c.autoUpdateThrough }
        }
        Add-TRInventory $inv 'GwsChromeDevices' 'ChromeOS devices' 'Managed ChromeOS devices.' $rows
    }

    if (Test-TRCollected @('GwsAlerts')) {
        $rows = foreach ($a in (Get-TRItems 'GwsAlerts' | Sort-Object createTime -Descending)) {
            [pscustomobject][ordered]@{ 'Created' = Format-TRDate $a.createTime -WithTime; 'Type' = $a.type; 'Source' = $a.source; 'Severity' = (Get-TRPath $a 'metadata.severity'); 'Status' = (Get-TRPath $a 'metadata.status'); 'Assignee' = (Get-TRPath $a 'metadata.assignee') }
        }
        Add-TRInventory $inv 'GwsAlerts' 'Alert Center' 'Alerts raised in the last 90 days.' $rows
    }

    if (Test-TRCollected @('GwsLoginEvents')) {
        $rows = foreach ($e in (Get-TRItems 'GwsLoginEvents' | Sort-Object Time -Descending)) {
            [pscustomobject][ordered]@{ 'Time' = Format-TRDate $e.Time -WithTime; 'User' = $e.Actor; 'Event' = $e.Event; 'IP address' = $e.IpAddress }
        }
        Add-TRInventory $inv 'GwsLoginEvents' 'Security sign-in events' 'Suspicious sign-ins, leaked passwords and attack warnings in the last 30 days.' $rows
    }

    if (Test-TRCollected @('GwsDriveSharing')) {
        $rows = foreach ($e in (Get-TRItems 'GwsDriveSharing' | Sort-Object Time -Descending)) {
            [pscustomobject][ordered]@{ 'Time' = Format-TRDate $e.Time -WithTime; 'User' = $e.Actor; 'Event' = $e.Event; 'File' = $e.doc_title; 'Owner' = $e.owner; 'Visibility' = $e.visibility; 'Shared with' = $e.target_user }
        }
        Add-TRInventory $inv 'GwsDriveSharing' 'Drive sharing activity' 'External and link sharing logged in the last 30 days.' $rows
    }

    Add-TRServerInventories $inv
    $diag = foreach ($d in (Get-TRItems 'Diagnostics')) {
        [pscustomobject][ordered]@{ 'Area' = $d.Area; 'Item' = $d.Item; 'Status' = $d.Status; 'Count' = $d.Count; 'HTTP' = $(if ([int]$d.HttpStatus) { $d.HttpStatus } else { '' }); 'Message' = $d.Message; 'Duration ms' = $d.DurationMs }
    }
    Add-TRInventory $inv 'Diagnostics' 'Collection diagnostics' 'Every data collection step, with errors where something could not be read.' $diag
    $inv
}

function Get-TRGwsSummaryStats {
    $tiles = New-Object System.Collections.ArrayList
    $users = @(Get-TRGwsEnabledUsers)
    if (Test-TRCollected @('GwsUsers')) {
        $en = @($users | Where-Object { $_.isEnrolledIn2Sv }).Count
        [void]$tiles.Add(@{ Label = 'Active users'; Value = [string]$users.Count; Note = ('{0} suspended' -f @(Get-TRItems 'GwsUsers' | Where-Object { $_.suspended }).Count) })
        [void]$tiles.Add(@{ Label = '2SV enrolled'; Value = ('{0}%' -f (Get-TRPercent $en $users.Count)); Note = ('{0} of {1} users' -f $en, $users.Count) })
        [void]$tiles.Add(@{ Label = 'Super admins'; Value = [string]@(Get-TRGwsSuperAdmins).Count; Note = 'Recommended 2 to 4' })
    }
    if (Test-TRCollected @('GwsLicences')) { [void]$tiles.Add(@{ Label = 'Licences assigned'; Value = [string]@(Get-TRItems 'GwsLicences').Count; Note = $(& { $c = Get-TRGwsSkuCounts; (@($c.Keys | Sort-Object { -$c[$_] } | Select-Object -First 2 | ForEach-Object { Get-TRGwsSkuName $_ }) -join ', ') }) }) }
    if (Test-TRCollected @('GwsTokens')) { [void]$tiles.Add(@{ Label = 'Third-party apps'; Value = [string]@(Get-TRItems 'GwsTokens' | Where-Object { -not $_.NativeApp } | Select-Object -ExpandProperty App -Unique).Count; Note = 'Granted by users' }) }
    if (Test-TRCollected @('GwsDevices')) { [void]$tiles.Add(@{ Label = 'Managed devices'; Value = [string]@(Get-TRItems 'GwsDevices').Count; Note = ('{0} not encrypted' -f @(Get-TRItems 'GwsDevices' | Where-Object { [string]$_.encryptionState -eq 'NOT_ENCRYPTED' }).Count) }) }
    if (Test-TRCollected @('GwsAlerts')) { [void]$tiles.Add(@{ Label = 'Alerts (90 days)'; Value = [string]@(Get-TRItems 'GwsAlerts').Count; Note = ('{0} not closed' -f @(Get-TRItems 'GwsAlerts' | Where-Object { [string](Get-TRPath $_ 'metadata.status') -ne 'CLOSED' }).Count) }) }
    , $tiles.ToArray()
}
