$script:TRBackupProducts = 'Veeam|Datto|Acronis|Azure Recovery Services|Azure Backup|Backup Exec|Arcserve|Cove Data Protection|N-able Backup|SolarWinds Backup|Unitrends|StorageCraft|ShadowProtect|Altaro|Nakivo|Commvault|Rubrik|Cohesity|Druva|Carbonite|Axcient|Redstor|Barracuda Backup|IDrive|MSP360|CloudBerry'
$script:TREdrProducts = 'CrowdStrike|SentinelOne|Sophos|Bitdefender|ESET|Webroot|Trend Micro|Symantec|McAfee|Trellix|Malwarebytes|Cylance|Carbon Black|Cortex XDR|Panda|Kaspersky|Huntress|WithSecure|F-Secure|Heimdal|Blackpoint'
$script:TREdrServices = '^(CSFalconService|SentinelAgent|Sophos.*|EPSecurityService|ekrn|WRSVC|ds_agent|ccSvcHst|mfemms|MBEndpointAgent|CylanceSvc|CbDefense|cyserver|HuntressAgent|fsdevcon)$'
$script:TROldSoftware = @(
    @{ Match = '^Microsoft SQL Server (2005|2008|2012|2014|2016)( |$)'; Note = 'SQL Server {0} is out of support' }
    @{ Match = '^Microsoft Exchange Server (2010|2013|2016|2019)'; Note = 'Exchange Server {0} is out of support (2016 and 2019 ended on 14 October 2025)' }
    @{ Match = '^Microsoft SharePoint Server (2010|2013|2016|2019)'; Note = 'SharePoint Server {0} is out of support or ends July 2026' }
    @{ Match = '^Adobe Flash'; Note = 'Adobe Flash Player is end of life' }
    @{ Match = '^Java\(TM\) [67]|^Java [67] Update'; Note = 'Java {0} is out of support' }
    @{ Match = '^Microsoft \.NET Core [123]\.|^Microsoft \.NET (5|6|7)\.\d+\.\d+ - '; Note = '.NET {0} runtime is out of support' }
    @{ Match = '^PHP [5-7]\.'; Note = 'PHP {0} is out of support' }
)

$script:TRWinBaseline = @(
    @{ Id = 'WB-01'; Title = 'SMBv1 is disabled'; Ref = 'CIS L1, MS baseline'; Test = { param($s) -not (Test-TRTrue (Get-TRPath $s 'Smb.Smb1Enabled')) } }
    @{ Id = 'WB-02'; Title = 'SMB server signing is required'; Ref = 'CIS L1, MS baseline'; Test = { param($s) Test-TRTrue (Get-TRPath $s 'Smb.ServerSigningRequired') } }
    @{ Id = 'WB-03'; Title = 'SMB client signing is required'; Ref = 'CIS L1'; Test = { param($s) $v = Get-TRPath $s 'Smb.ClientSigningRequired'; if ($null -eq $v) { $null } else { Test-TRTrue $v } } }
    @{ Id = 'WB-04'; Title = 'Only NTLMv2 is accepted (LAN Manager level 5)'; Ref = 'CIS L1, MS baseline'; Test = { param($s) [int](Get-TRPath $s 'Hardening.LmCompatibilityLevel') -eq 5 } }
    @{ Id = 'WB-05'; Title = 'LM hashes are not stored'; Ref = 'CIS L1, MS baseline'; Test = { param($s) [string](Get-TRPath $s 'Hardening.NoLmHash') -ne '0' } }
    @{ Id = 'WB-06'; Title = 'WDigest does not keep passwords in memory'; Ref = 'MS baseline'; Test = { param($s) [string](Get-TRPath $s 'Hardening.WDigestUseLogonCredential') -ne '1' } }
    @{ Id = 'WB-07'; Title = 'LSA protection is on'; Ref = 'MS baseline'; Test = { param($s) [string](Get-TRPath $s 'Hardening.RunAsPpl') -in @('1', '2') } }
    @{ Id = 'WB-08'; Title = 'Anonymous enumeration of accounts and shares is blocked'; Ref = 'CIS L1'; Test = { param($s) [int](Get-TRPath $s 'Hardening.RestrictAnonymous') -ge 1 -and [string](Get-TRPath $s 'Hardening.RestrictAnonymousSam') -ne '0' } }
    @{ Id = 'WB-09'; Title = 'LLMNR is turned off'; Ref = 'CIS L1'; Test = { param($s) Test-TRTrue (Get-TRPath $s 'Hardening.LlmnrDisabled') } }
    @{ Id = 'WB-10'; Title = 'NetBIOS over TCP/IP is disabled'; Ref = 'Hardening'; Test = { param($s) $n = @(Get-TRPath $s 'Hardening.NetbiosOptions'); if (-not $n.Count) { $null } else { -not @($n | Where-Object { [int]$_ -ne 2 }).Count } } }
    @{ Id = 'WB-11'; Title = 'User Account Control is on'; Ref = 'CIS L1, MS baseline'; Test = { param($s) [string](Get-TRPath $s 'Hardening.EnableLua') -ne '0' } }
    @{ Id = 'WB-12'; Title = 'UAC restrictions apply to local accounts over the network'; Ref = 'MS baseline'; Test = { param($s) [string](Get-TRPath $s 'Hardening.LocalAccountTokenFilterPolicy') -ne '1' } }
    @{ Id = 'WB-13'; Title = 'AutoPlay is off for all drives'; Ref = 'CIS L1'; Test = { param($s) [int](Get-TRPath $s 'Hardening.NoDriveTypeAutoRun') -eq 255 } }
    @{ Id = 'WB-14'; Title = 'PowerShell 2.0 is removed'; Ref = 'MS baseline'; Test = { param($s) $v = Get-TRPath $s 'Hardening.PowerShellV2Installed'; if ($null -eq $v) { $null } else { -not (Test-TRTrue $v) } } }
    @{ Id = 'WB-15'; Title = 'PowerShell script block logging is on'; Ref = 'CIS L1'; Test = { param($s) [string](Get-TRPath $s 'Hardening.ScriptBlockLogging') -eq '1' } }
    @{ Id = 'WB-16'; Title = 'Process creation events include the command line'; Ref = 'CIS L1'; Test = { param($s) [string](Get-TRPath $s 'Hardening.ProcessCommandLine') -eq '1' } }
    @{ Id = 'WB-17'; Title = 'Remote Desktop requires Network Level Authentication'; Ref = 'CIS L1, MS baseline'; Test = { param($s) if (-not (Test-TRTrue (Get-TRPath $s 'RemoteDesktop.Enabled'))) { $null } else { [string](Get-TRPath $s 'RemoteDesktop.Nla') -eq '1' } } }
    @{ Id = 'WB-18'; Title = 'Remote Desktop encryption is set to High'; Ref = 'CIS L1'; Test = { param($s) if (-not (Test-TRTrue (Get-TRPath $s 'RemoteDesktop.Enabled'))) { $null } else { [int](Get-TRPath $s 'RemoteDesktop.MinEncryptionLevel') -ge 3 } } }
    @{ Id = 'WB-19'; Title = 'TLS 1.0 is disabled for incoming connections'; Ref = 'MS guidance'; Test = { param($s) [string](Get-TRV (Get-TRV (Get-TRPath $s 'Protocols.Schannel') 'TLS 1.0') 'ServerEnabled') -eq '0' } }
    @{ Id = 'WB-20'; Title = 'TLS 1.1 is disabled for incoming connections'; Ref = 'MS guidance'; Test = { param($s) [string](Get-TRV (Get-TRV (Get-TRPath $s 'Protocols.Schannel') 'TLS 1.1') 'ServerEnabled') -eq '0' } }
    @{ Id = 'WB-21'; Title = '.NET applications use strong cryptography'; Ref = 'MS guidance'; Test = { param($s) [string](Get-TRPath $s 'Protocols.StrongCrypto64') -eq '1' } }
    @{ Id = 'WB-22'; Title = 'Windows Firewall is on for every profile'; Ref = 'CIS L1, MS baseline'; Test = { param($s) $p = @(Get-TRPath $s 'Firewall.Profiles'); if (-not $p.Count) { $null } else { -not @($p | Where-Object { [string](Get-TRV $_ 'Enabled') -ne 'True' }).Count } } }
    @{ Id = 'WB-23'; Title = 'Windows Firewall blocks inbound by default'; Ref = 'CIS L1, MS baseline'; Test = { param($s) $p = @(Get-TRPath $s 'Firewall.Profiles'); if (-not $p.Count) { $null } else { -not @($p | Where-Object { [string](Get-TRV $_ 'DefaultInboundAction') -notin @('Block', 'NotConfigured') }).Count } } }
    @{ Id = 'WB-24'; Title = 'Windows Firewall logs dropped packets'; Ref = 'CIS L1'; Test = { param($s) $p = @(Get-TRPath $s 'Firewall.Profiles'); if (-not $p.Count) { $null } else { -not @($p | Where-Object { [string](Get-TRV $_ 'LogBlocked') -ne 'True' }).Count } } }
    @{ Id = 'WB-25'; Title = 'Security event log is at least 192 MB'; Ref = 'CIS L1'; Test = { param($s) $l = @(Get-TRPath $s 'EventLogs' | Where-Object { (Get-TRV $_ 'Name') -eq 'Security' })[0]; if (-not $l) { $null } else { [int](Get-TRV $l 'MaxSizeKB') -ge 196608 } } }
    @{ Id = 'WB-26'; Title = 'Credential Guard is running'; Ref = 'MS baseline'; Test = { param($s) if ([int](Get-TRPath $s 'System.DomainRole') -ge 4) { $null } else { $v = Get-TRPath $s 'Hardening.CredentialGuardRunning'; if ($null -eq $v) { $null } else { Test-TRTrue $v } } } }
    @{ Id = 'WB-27'; Title = 'No more than four cached logons'; Ref = 'CIS L1'; Test = { param($s) $v = Get-TRPath $s 'Hardening.CachedLogonsCount'; if ($null -eq $v) { $false } else { [int]$v -le 4 } } }
    @{ Id = 'WB-28'; Title = 'Secure Boot is on'; Ref = 'MS baseline'; Test = { param($s) $v = Get-TRPath $s 'Hardening.SecureBoot'; if ($null -eq $v) { $null } else { Test-TRTrue $v } } }
    @{ Id = 'WB-29'; Title = 'Credential validation is audited'; Ref = 'CIS L1, MS baseline'; Test = { param($s) Test-TRAuditSet $s 'Credential Validation' 'Success and Failure' } }
    @{ Id = 'WB-30'; Title = 'Logons are audited'; Ref = 'CIS L1, MS baseline'; Test = { param($s) Test-TRAuditSet $s 'Logon' 'Success and Failure' } }
    @{ Id = 'WB-31'; Title = 'Process creation is audited'; Ref = 'CIS L1, MS baseline'; Test = { param($s) Test-TRAuditSet $s 'Process Creation' 'Success' } }
    @{ Id = 'WB-32'; Title = 'Security group changes are audited'; Ref = 'CIS L1, MS baseline'; Test = { param($s) Test-TRAuditSet $s 'Security Group Management' 'Success' } }
    @{ Id = 'WB-33'; Title = 'Audit policy changes are audited'; Ref = 'CIS L1, MS baseline'; Test = { param($s) Test-TRAuditSet $s 'Audit Policy Change' 'Success' } }
)

function Test-TRAuditSet {
    param($Server, [string]$Subcategory, [string]$Want)
    $ap = Get-TRV $Server 'AuditPolicy'
    if ($null -eq $ap) { return $null }
    $v = [string](Get-TRV $ap $Subcategory)
    if (-not $v) { return $null }
    if ($Want -eq 'Success and Failure') { return $v -eq 'Success and Failure' }
    $v -match $Want
}

function Set-TRRawKey {
    param($Target, [string]$Key, $Value)
    if ($Target -is [System.Collections.IDictionary]) { $Target[$Key] = $Value; return }
    if ($Target.PSObject.Properties[$Key]) { $Target.$Key = $Value } else { $Target | Add-Member -NotePropertyName $Key -NotePropertyValue $Value }
}

function Import-TRServerData {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)]$Raw)
    $diag = New-Object System.Collections.ArrayList
    $files = @()
    if (Test-Path -LiteralPath $Path -PathType Leaf) { $files = @(Get-Item -LiteralPath $Path) }
    elseif (Test-Path -LiteralPath $Path) { $files = @(Get-ChildItem -LiteralPath $Path -Recurse -File -Filter '*.json' -ErrorAction SilentlyContinue | Where-Object { $_.Name -like '*.server-review.json' -or $_.Name -like '*server-review*.json' }) }
    else { Write-TRLog ('Server data folder not found: {0}' -f $Path) 'Warn' }
    $latest = @{}
    $list = New-Object System.Collections.ArrayList
    foreach ($f in $files) {
        try {
            $o = Read-TRRawFile -Path $f.FullName
            $col = [string](Get-TRV $o 'Collector')
            $name = [string](Get-TRV $o 'ComputerName')
            if (-not $col -or -not $name) { throw 'Not a server data file.' }
            $when = ConvertTo-TRDate (Get-TRV $o 'CollectedUtc')
            $key = ('{0}|{1}' -f $col, $name).ToLower()
            [void]$list.Add([pscustomobject][ordered]@{ File = $f.Name; Collector = $col; Server = $name; Collected = (Get-TRV $o 'CollectedUtc'); Errors = @(Get-TRV $o 'Errors').Count; Used = $false })
            if ($latest.ContainsKey($key) -and $latest[$key].When -ge $when) { continue }
            $latest[$key] = [pscustomobject]@{ When = $when; Data = $o; File = $f.Name }
        }
        catch { [void]$list.Add([pscustomobject][ordered]@{ File = $f.Name; Collector = ''; Server = ''; Collected = ''; Errors = 1; Used = $false; Problem = $_.Exception.Message }) }
    }
    $win = @(); $lin = @(); $vmw = @()
    foreach ($k in @($latest.Keys | Sort-Object)) {
        $e = $latest[$k]
        foreach ($row in $list) { if ($row.File -eq $e.File) { $row.Used = $true } }
        switch ([string](Get-TRV $e.Data 'Collector')) { 'windows' { $win += $e.Data } 'linux' { $lin += $e.Data } 'vmware' { $vmw += $e.Data } }
    }
    Set-TRRawKey $Raw 'WinServers' @($win)
    Set-TRRawKey $Raw 'LinuxServers' @($lin)
    Set-TRRawKey $Raw 'VMwareData' @($vmw)
    Set-TRRawKey $Raw 'ServerFiles' $list.ToArray()
    $n = $win.Count + $lin.Count + $vmw.Count
    foreach ($pair in @(@('WinServers', $win.Count), @('LinuxServers', $lin.Count), @('VMwareData', $vmw.Count), @('ServerFiles', $list.Count))) {
        [void]$diag.Add([pscustomobject][ordered]@{ Area = 'Servers'; Item = $pair[0]; Status = $(if ($files.Count) { 'OK' } else { 'Unavailable' }); Count = $pair[1]; HttpStatus = 0; Message = $(if ($files.Count) { '' } else { 'No server data files were found in ' + $Path }); DurationMs = 0 })
    }
    $old = @(Get-TRV $Raw 'Diagnostics' | Where-Object { $null -ne $_ -and [string](Get-TRV $_ 'Area') -ne 'Servers' })
    Set-TRRawKey $Raw 'Diagnostics' @($old + $diag.ToArray())
    $meta = Get-TRV $Raw 'Meta'
    $areas = @(Get-TRV $meta 'Areas')
    if ($areas -notcontains 'Servers') { Set-TRRawKey $meta 'Areas' @($areas + 'Servers') }
    Set-TRRawKey $meta 'ServerDataPath' $Path
    Write-TRLog ('Server data: {0} from {1} ({2} Windows, {3} Linux, {4} VMware).' -f (Format-TRN $n 'system'), (Format-TRN $files.Count 'file'), $win.Count, $lin.Count, $vmw.Count) $(if ($n) { 'Success' } else { 'Warn' })
}

function Format-TROf {
    param([int]$N, [int]$Total, [string]$One, [string]$Many)
    if ($N -eq $Total -and $Total -eq 1) { return ('The only ' + $One) }
    if ($N -eq $Total -and $Total -eq 2) { return ('Both ' + $Many) }
    if ($N -eq $Total) { return ('All {0} {1}' -f $Total, $Many) }
    '{0} of {1} {2}' -f $N, $Total, $Many
}

function Get-TRWinServers { @(Get-TRItems 'WinServers') }
function Get-TRSrvName { param($S) $n = [string](Get-TRPath $S 'System.Name'); if ($n) { $n } else { [string](Get-TRV $S 'ComputerName') } }
function Test-TRSrvDc { param($S) [int](Get-TRPath $S 'System.DomainRole') -ge 4 }

function Get-TRSrvOs {
    param($S)
    $c = [string](Get-TRPath $S 'System.OsCaption')
    if ($c -match 'Windows Server (\d{4})( R2)?') { return 'Windows Server ' + $Matches[1] + $Matches[2] }
    $b = [string](Get-TRPath $S 'System.OsBuild')
    $map = @{ '7601' = 'Windows Server 2008 R2'; '9200' = 'Windows Server 2012'; '9600' = 'Windows Server 2012 R2'; '14393' = 'Windows Server 2016'; '17763' = 'Windows Server 2019'; '20348' = 'Windows Server 2022'; '26100' = 'Windows Server 2025' }
    if ($map[$b]) { return $map[$b] }
    ($c -replace '^Microsoft ', '')
}

function Get-TRSrvRoles {
    param($S)
    $f = @(Get-TRV $S 'Features')
    $r = @()
    if ($f -contains 'AD-Domain-Services' -or (Test-TRSrvDc $S)) { $r += 'Domain controller' }
    if ($f -contains 'Hyper-V') { $r += 'Hyper-V host' }
    if ($f -contains 'DHCP') { $r += 'DHCP' }
    if ($f -contains 'DNS') { $r += 'DNS' }
    if ($f -contains 'Print-Server') { $r += 'Print server' }
    if (@($f | Where-Object { $_ -like 'RDS-*' }).Count) { $r += 'Remote Desktop Services' }
    if (@($f | Where-Object { $_ -like 'ADCS-*' }).Count) { $r += 'Certificate Services' }
    if ($f -contains 'Web-Server') { $r += 'IIS' }
    if ($f -contains 'Failover-Clustering') { $r += 'Failover cluster' }
    if (@(Get-TRV $S 'Software' | Where-Object { [string](Get-TRV $_ 'Name') -match '^Microsoft SQL Server \d{4} \(64-bit\)|^Microsoft SQL Server \d{4}$' }).Count) { $r += 'SQL Server' }
    if (@(Get-TRV $S 'Software' | Where-Object { [string](Get-TRV $_ 'Name') -match '^Microsoft Exchange Server' }).Count) { $r += 'Exchange' }
    $r
}

function Get-TRSrvEdr {
    param($S)
    $d = Get-TRV $S 'Defender'
    if (Test-TRTrue (Get-TRV $d 'MdeOnboarded')) { return 'Microsoft Defender for Endpoint' }
    $sw = @(Get-TRV $S 'Software' | Where-Object { [string](Get-TRV $_ 'Name') -match $script:TREdrProducts } | ForEach-Object { [string](Get-TRV $_ 'Name') })
    $svc = @(Get-TRV $S 'Services' | Where-Object { [string](Get-TRV $_ 'Name') -match $script:TREdrServices -and [string](Get-TRV $_ 'State') -eq 'Running' } | ForEach-Object { [string](Get-TRV $_ 'DisplayName') })
    if ($sw.Count) { return ($sw | Select-Object -First 1) }
    if ($svc.Count) { return ($svc | Select-Object -First 1) }
    $null
}

function Get-TRSrvBackup {
    param($S)
    $sw = @(Get-TRV $S 'Software' | Where-Object { [string](Get-TRV $_ 'Name') -match $script:TRBackupProducts } | ForEach-Object { [string](Get-TRV $_ 'Name') })
    if ($sw.Count) { return ($sw | Select-Object -First 1) }
    $wsb = Get-TRPath $S 'Backup.WindowsServerBackup'
    if ($wsb -and (Get-TRV $wsb 'LastSuccess')) { return ('Windows Server Backup (last success {0})' -f (Format-TRDate (Get-TRV $wsb 'LastSuccess'))) }
    $null
}

function Get-TRSrvBaseline {
    param($S)
    Get-TRCached ('Baseline|' + (Get-TRSrvName $S)) {
        $rows = foreach ($b in $script:TRWinBaseline) {
            $r = $null
            try { $r = & $b.Test $S } catch { $r = $null }
            [pscustomobject]@{ Id = $b.Id; Title = $b.Title; Ref = $b.Ref; Result = $r }
        }
        @($rows)
    }
}

function New-TRSrvAffected {
    param($S, [string]$Detail)
    New-TRAffected (Get-TRSrvName $S) $Detail
}

Register-TRCheck -Platform Any -Id 'SRV-01' -Area 'Servers' -Category 'Windows servers' -Severity High -Effort 16 `
    -Title 'Windows servers run a supported version' `
    -Needs 'WinServers' `
    -Recommendation 'Upgrade or replace servers whose Windows Server version is out of support (2012 and 2012 R2 extended security updates ended on 13 October 2026; Windows Server 2016 support ends on 12 January 2027). Plan upgrades for anything ending within six months.' `
    -Reference 'https://learn.microsoft.com/lifecycle/products/?terms=windows%20server' `
    -Test {
    $srv = @(Get-TRWinServers)
    if (-not $srv.Count) { return New-TRResult Info 'No Windows server data was imported.' }
    $bad = @(); $soon = @()
    foreach ($s in $srv) {
        $os = Get-TRSrvOs $s
        $sup = Get-TROsSupport $os
        if (-not $sup) { continue }
        if ($sup.State -in @('Ended', 'Esu')) { $bad += (New-TRSrvAffected $s ('{0}; support ended {1}' -f $os, (Format-TRDate $sup.End))) }
        elseif ($sup.State -eq 'Ending') { $soon += (New-TRSrvAffected $s ('{0}; support ends {1}' -f $os, (Format-TRDate $sup.End))) }
    }
    if ($bad.Count) { return New-TRResult Fail ('{0} {1} out of support{2}.' -f (Format-TROf -N $bad.Count -Total $srv.Count -One 'Windows server' -Many 'Windows servers'), (Select-TRText $bad.Count 'is' 'are'), $(if ($soon.Count) { ('; {0} more {1} support within six months' -f $soon.Count, (Select-TRText $soon.Count 'loses' 'lose')) } else { '' })) @($bad + $soon) }
    if ($soon.Count) { return New-TRResult Warning ('{0} {1} support within six months.' -f (Format-TROf -N $soon.Count -Total $srv.Count -One 'Windows server' -Many 'Windows servers'), (Select-TRText $soon.Count 'loses' 'lose')) $soon }
    New-TRResult Pass ('{0} {1} a supported version of Windows Server.' -f (Format-TROf -N $srv.Count -Total $srv.Count -One 'server' -Many 'servers'), (Select-TRText $srv.Count 'runs' 'run'))
}

Register-TRCheck -Platform Any -Id 'SRV-02' -Area 'Servers' -Category 'Windows servers' -Severity High -Effort 4 `
    -Title 'Windows servers are patched and rebooted' `
    -Needs 'WinServers' `
    -Recommendation 'Install the outstanding security updates and restart servers that are waiting for a reboot. Check the RMM patch policy covers every server and that servers are restarted at least monthly.' `
    -Reference 'https://learn.microsoft.com/windows/deployment/update/waas-overview' `
    -Test {
    $srv = @(Get-TRWinServers)
    if (-not $srv.Count) { return New-TRResult Info 'No Windows server data was imported.' }
    $fail = @(); $warn = @()
    foreach ($s in $srv) {
        $u = Get-TRV $s 'Updates'
        $miss = @(Get-TRV $u 'Missing' | Where-Object { [string](Get-TRV $_ 'Severity') -in @('Critical', 'Important') -or [string](Get-TRV $_ 'Categories') -match 'Security' })
        $age = Get-TRDaysSince (Get-TRV $u 'LastHotfixDate')
        $up = Get-TRDaysSince (Get-TRPath $s 'System.LastBoot')
        $g = @()
        if ($miss.Count) { $g += ('{0} missing' -f (Format-TRN $miss.Count 'security update')) }
        if ($null -ne $age -and $age -gt 45) { $g += ('last update installed {0} days ago' -f $age) }
        if (Test-TRTrue (Get-TRV $u 'RebootPending')) { $g += 'restart pending' }
        if ($null -ne $up -and $up -gt 60) { $g += ('not restarted for {0} days' -f $up) }
        if (-not $g.Count) { continue }
        $a = New-TRSrvAffected $s ($g -join '; ')
        if ($miss.Count -or ($null -ne $age -and $age -gt 60)) { $fail += $a } else { $warn += $a }
    }
    $searchRan = @($srv | Where-Object { [string](Get-TRPath $_ 'Updates.SearchStatus') -eq 'Completed' }).Count
    $note = if ($searchRan -lt $srv.Count) { (' The missing update search ran on {0} of {1} servers.' -f $searchRan, $srv.Count) } else { '' }
    if ($fail.Count) { return New-TRResult Fail (('{0} {1} security updates.' -f (Format-TROf -N $fail.Count -Total $srv.Count -One 'server' -Many 'servers'), (Select-TRText $fail.Count 'is missing' 'are missing')) + $note) @($fail + $warn) }
    if ($warn.Count) { return New-TRResult Warning (('{0} {1} a restart.' -f (Format-TROf -N $warn.Count -Total $srv.Count -One 'server' -Many 'servers'), (Select-TRText $warn.Count 'needs' 'need')) + $note) $warn }
    New-TRResult Pass (('{0} {1} up to date and restarted recently.' -f (Format-TROf -N $srv.Count -Total $srv.Count -One 'server' -Many 'servers'), (Select-TRText $srv.Count 'is' 'are')) + $note)
}

Register-TRCheck -Platform Any -Id 'SRV-03' -Area 'Servers' -Category 'Windows servers' -Severity High -Effort 2 `
    -Title 'Windows servers have working EDR and antivirus' `
    -Needs 'WinServers' `
    -Recommendation 'Onboard every server to Microsoft Defender for Endpoint (Defender for Servers or Defender for Business servers) or the client''s chosen EDR, keep real-time protection and tamper protection on, and make sure signatures update daily.' `
    -Reference 'https://learn.microsoft.com/defender-endpoint/configure-server-endpoints' `
    -Test {
    $srv = @(Get-TRWinServers)
    if (-not $srv.Count) { return New-TRResult Info 'No Windows server data was imported.' }
    $none = @(); $weak = @()
    foreach ($s in $srv) {
        $edr = Get-TRSrvEdr $s
        $d = Get-TRV $s 'Defender'
        $active = Test-TRTrue (Get-TRV $d 'RealTimeProtectionEnabled')
        $sig = [int](Get-TRV $d 'SignatureAgeDays')
        if (-not $edr -and -not $active) { $none += (New-TRSrvAffected $s 'No EDR detected and Defender real-time protection is off'); continue }
        if (-not $edr) { $none += (New-TRSrvAffected $s 'Defender Antivirus only; not onboarded to an EDR'); continue }
        $g = @()
        if ([string](Get-TRV $d 'RunningMode') -eq 'Normal' -and -not $active) { $g += 'real-time protection off' }
        if ($active -and $sig -gt 3) { $g += ('signatures {0} days old' -f $sig) }
        if ($edr -eq 'Microsoft Defender for Endpoint' -and -not (Test-TRTrue (Get-TRV $d 'IsTamperProtected'))) { $g += 'tamper protection off' }
        if ($g.Count) { $weak += (New-TRSrvAffected $s ('{0}; {1}' -f $edr, ($g -join ', '))) }
    }
    if ($none.Count) { return New-TRResult Fail ('{0} {1} no EDR.' -f (Format-TROf -N $none.Count -Total $srv.Count -One 'server' -Many 'servers'), (Select-TRText $none.Count 'has' 'have')) @($none + $weak) }
    if ($weak.Count) { return New-TRResult Warning ('{0} {1} protection gaps.' -f (Format-TROf -N $weak.Count -Total $srv.Count -One 'server' -Many 'servers'), (Select-TRText $weak.Count 'has' 'have')) $weak }
    New-TRResult Pass ('{0} {1} EDR with real-time protection.' -f (Format-TROf -N $srv.Count -Total $srv.Count -One 'server' -Many 'servers'), (Select-TRText $srv.Count 'has' 'have'))
}

Register-TRCheck -Platform Any -Id 'SRV-04' -Area 'Servers' -Category 'Windows servers' -Severity High -Effort 2 `
    -Title 'Remote management is not exposed or weakly protected' `
    -Needs 'WinServers' `
    -Recommendation 'Require Network Level Authentication for Remote Desktop, limit RDP, SMB and WinRM firewall rules to management subnets instead of any address, and turn off unencrypted and Basic authentication on WinRM.' `
    -Reference 'https://learn.microsoft.com/windows-server/remote/remote-desktop-services/clients/remote-desktop-allow-access' `
    -Test {
    $srv = @(Get-TRWinServers)
    if (-not $srv.Count) { return New-TRResult Info 'No Windows server data was imported.' }
    $fail = @(); $warn = @()
    foreach ($s in $srv) {
        $g = @(); $hard = $false
        if ((Test-TRTrue (Get-TRPath $s 'RemoteDesktop.Enabled')) -and [string](Get-TRPath $s 'RemoteDesktop.Nla') -ne '1') { $g += 'RDP without Network Level Authentication'; $hard = $true }
        if ([string](Get-TRPath $s 'WinRM.AllowUnencrypted') -eq 'true') { $g += 'WinRM allows unencrypted traffic'; $hard = $true }
        if ([string](Get-TRPath $s 'WinRM.BasicAuth') -eq 'true') { $g += 'WinRM Basic authentication on'; $hard = $true }
        $open = @(Get-TRPath $s 'Firewall.OpenRules')
        if ($open.Count) { $g += ('{0} from any address ({1})' -f (Format-TRN $open.Count 'firewall rule allows' 'firewall rules allow'), (Join-TRList (@($open | ForEach-Object { [string](Get-TRV $_ 'Name') })) 3)) }
        if (-not $g.Count) { continue }
        if ($hard) { $fail += (New-TRSrvAffected $s ($g -join '; ')) } else { $warn += (New-TRSrvAffected $s ($g -join '; ')) }
    }
    if ($fail.Count) { return New-TRResult Fail ('{0} {1} weakly protected remote access.' -f (Format-TROf -N $fail.Count -Total $srv.Count -One 'server' -Many 'servers'), (Select-TRText $fail.Count 'allows' 'allow')) @($fail + $warn) }
    if ($warn.Count) { return New-TRResult Warning ('{0} {1} management ports from any address in Windows Firewall.' -f (Format-TROf -N $warn.Count -Total $srv.Count -One 'server' -Many 'servers'), (Select-TRText $warn.Count 'allows' 'allow')) $warn }
    New-TRResult Pass 'Remote management is restricted on every server.'
}

Register-TRCheck -Platform Any -Id 'SRV-05' -Area 'Servers' -Category 'Windows servers' -Severity High -Effort 2 `
    -Title 'SMBv1 is disabled and SMB signing is required' `
    -Needs 'WinServers' `
    -Recommendation 'Remove the SMB 1.0 feature, and require SMB signing on servers (Microsoft network server: Digitally sign communications (always)) through Group Policy, after checking for old devices such as copiers that still need SMBv1.' `
    -Reference 'https://learn.microsoft.com/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3' `
    -Test {
    $srv = @(Get-TRWinServers)
    if (-not $srv.Count) { return New-TRResult Info 'No Windows server data was imported.' }
    $v1 = @($srv | Where-Object { Test-TRTrue (Get-TRPath $_ 'Smb.Smb1Enabled') })
    $sign = @($srv | Where-Object { (Get-TRV $_ 'Smb') -and -not (Test-TRTrue (Get-TRPath $_ 'Smb.ServerSigningRequired')) })
    $aff = @($v1 | ForEach-Object { New-TRSrvAffected $_ 'SMBv1 enabled' }) + @($sign | ForEach-Object { New-TRSrvAffected $_ 'SMB signing not required' })
    if ($v1.Count) { return New-TRResult Fail ('SMBv1 is enabled on {0}; signing is not required on {1}.' -f (Format-TRN $v1.Count 'server'), (Format-TRN $sign.Count 'server')) $aff }
    if ($sign.Count) { return New-TRResult Warning ('SMB signing is not required on {0} of {1} servers.' -f $sign.Count, $srv.Count) $aff }
    New-TRResult Pass 'SMBv1 is off and SMB signing is required on every server.'
}

Register-TRCheck -Platform Any -Id 'SRV-06' -Area 'Servers' -Category 'Windows servers' -Severity Medium -Effort 6 `
    -Title 'Windows servers meet the hardening baseline' `
    -Needs 'WinServers' `
    -Recommendation 'Apply the missing baseline settings through Group Policy (or the Intune server baseline): they are drawn from CIS Windows Server Level 1 and the Microsoft security baseline. The Servers tab shows each setting by server.' `
    -Reference 'https://learn.microsoft.com/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines' `
    -Test {
    $srv = @(Get-TRWinServers)
    if (-not $srv.Count) { return New-TRResult Info 'No Windows server data was imported.' }
    $rows = foreach ($s in $srv) {
        $b = @(Get-TRSrvBaseline $s | Where-Object { $null -ne $_.Result })
        $p = @($b | Where-Object { $_.Result -eq $true }).Count
        [pscustomobject]@{ Server = $s; Pass = $p; Total = $b.Count; Failed = @($b | Where-Object { $_.Result -eq $false } | ForEach-Object { $_.Title }) }
    }
    $rows = @($rows | Where-Object { $_.Total -gt 0 })
    if (-not $rows.Count) { return New-TRResult NotAssessed 'The baseline settings could not be read (the collector needs administrator rights).' }
    $tp = ($rows | Measure-Object -Property Pass -Sum).Sum
    $tt = ($rows | Measure-Object -Property Total -Sum).Sum
    $pct = Get-TRPercent $tp $tt
    $aff = @($rows | Sort-Object { $_.Pass / [Math]::Max(1, $_.Total) } | ForEach-Object { New-TRSrvAffected $_.Server ('{0} of {1} settings met. Missing: {2}' -f $_.Pass, $_.Total, (Join-TRList $_.Failed 6)) })
    $low = @($rows | Where-Object { $_.Pass / $_.Total -lt 0.6 })
    $text = '{0}% of baseline settings are met across {1}.' -f $pct, (Format-TRN $rows.Count 'server')
    if ($low.Count) { return New-TRResult Fail ($text + (' {0} below 60%.' -f (Format-TRN $low.Count 'server is' 'servers are'))) $aff }
    if ($pct -lt 90) { return New-TRResult Warning $text $aff }
    New-TRResult Pass $text $aff
}

Register-TRCheck -Platform Any -Id 'SRV-07' -Area 'Servers' -Category 'Windows servers' -Severity High -Effort 3 `
    -Title 'Local administrator accounts are managed' `
    -Needs 'WinServers' `
    -Recommendation 'Deploy Windows LAPS to every member server so the local administrator password is unique and rotated, disable the Guest account, and remove broad groups such as Domain Users or Everyone from the local Administrators group.' `
    -Reference 'https://learn.microsoft.com/windows-server/identity/laps/laps-overview' `
    -Test {
    $srv = @(Get-TRWinServers | Where-Object { -not (Test-TRSrvDc $_) })
    if (-not $srv.Count) { return New-TRResult Info 'No member server data was imported.' }
    $fail = @(); $warn = @()
    foreach ($s in $srv) {
        $la = Get-TRV $s 'LocalAccounts'
        if (-not $la) { continue }
        $laps = Get-TRV $la 'Laps'
        $hasLaps = ([string](Get-TRV $laps 'WindowsLapsBackupDirectory') -in @('1', '2')) -or ([string](Get-TRV $laps 'WindowsLapsGpoBackupDirectory') -in @('1', '2')) -or ([string](Get-TRV $laps 'LegacyLapsEnabled') -eq '1')
        $users = @(Get-TRV $la 'Users')
        $guest = @($users | Where-Object { [string](Get-TRV $_ 'Sid') -match '-501$' -and (Test-TRTrue (Get-TRV $_ 'Enabled')) })
        $admin = @($users | Where-Object { [string](Get-TRV $_ 'Sid') -match '-500$' })[0]
        $broad = @(Get-TRV $la 'Administrators' | Where-Object { [string](Get-TRV $_ 'Name') -match '\\(Domain Users|Everyone|Authenticated Users|Users)$' })
        $g = @(); $hard = $false
        if (-not $hasLaps) { $g += 'no LAPS policy'; $hard = $true }
        if ($guest.Count) { $g += 'Guest account enabled'; $hard = $true }
        if ($broad.Count) { $g += ('local Administrators includes ' + (Join-TRList (@($broad | ForEach-Object { Get-TRV $_ 'Name' })) 3)); $hard = $true }
        if ($admin -and (Test-TRTrue (Get-TRV $admin 'Enabled')) -and (Get-TRDaysSince (Get-TRV $admin 'PasswordLastSet')) -gt 365) { $g += ('built-in Administrator password is {0} days old' -f (Get-TRDaysSince (Get-TRV $admin 'PasswordLastSet'))) }
        if (-not $g.Count) { continue }
        if ($hard) { $fail += (New-TRSrvAffected $s ($g -join '; ')) } else { $warn += (New-TRSrvAffected $s ($g -join '; ')) }
    }
    if ($fail.Count) { return New-TRResult Fail ('{0} {1} unmanaged local administrator accounts.' -f (Format-TROf -N $fail.Count -Total $srv.Count -One 'member server' -Many 'member servers'), (Select-TRText $fail.Count 'has' 'have')) @($fail + $warn) }
    if ($warn.Count) { return New-TRResult Warning ('{0} {1} old local administrator passwords.' -f (Format-TROf -N $warn.Count -Total $srv.Count -One 'member server' -Many 'member servers'), (Select-TRText $warn.Count 'has' 'have')) $warn }
    New-TRResult Pass ('LAPS manages the local administrator on {0}.' -f $(if ($srv.Count -eq 1) { 'the only member server' } elseif ($srv.Count -eq 2) { 'both member servers' } else { 'all {0} member servers' -f $srv.Count }))
}

Register-TRCheck -Platform Any -Id 'SRV-08' -Area 'Servers' -Category 'Windows servers' -Severity Medium -Effort 2 `
    -Title 'Security logging and audit policy are in place' `
    -Needs 'WinServers' `
    -Recommendation 'Set advanced audit policy for logons, credential validation, process creation, group and policy changes through Group Policy, size the Security log to at least 192 MB (or forward events to a SIEM), and investigate any Security log that has been cleared.' `
    -Reference 'https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations' `
    -Test {
    $srv = @(Get-TRWinServers)
    if (-not $srv.Count) { return New-TRResult Info 'No Windows server data was imported.' }
    $fail = @(); $warn = @()
    foreach ($s in $srv) {
        $b = @(Get-TRSrvBaseline $s | Where-Object { $_.Id -in @('WB-15', 'WB-25', 'WB-29', 'WB-30', 'WB-31', 'WB-32', 'WB-33') -and $_.Result -eq $false } | ForEach-Object { $_.Title })
        $cleared = [int](Get-TRPath $s 'Events.SecurityLogCleared30d')
        if ($cleared) { $fail += (New-TRSrvAffected $s ('Security log cleared {0} in the last 30 days{1}' -f (Format-TRN $cleared 'time'), $(if ($b.Count) { '; ' + ($b -join ', ') } else { '' }))) }
        elseif ($b.Count) { $warn += (New-TRSrvAffected $s ($b -join ', ')) }
    }
    if ($fail.Count) { return New-TRResult Fail ('The Security log was cleared on {0}.' -f (Format-TRN $fail.Count 'server')) @($fail + $warn) }
    if ($warn.Count) { return New-TRResult Warning ('{0} {1} logging gaps.' -f (Format-TROf -N $warn.Count -Total $srv.Count -One 'server' -Many 'servers'), (Select-TRText $warn.Count 'has' 'have')) $warn }
    New-TRResult Pass 'Audit policy and log sizes meet the baseline on every server.'
}

Register-TRCheck -Platform Any -Id 'SRV-09' -Area 'Servers' -Category 'Windows servers' -Severity Medium -Effort 1 `
    -Title 'Server volumes have free space' `
    -Needs 'WinServers' `
    -Recommendation 'Free space or extend volumes with less than 15% free, starting with system drives and database or mailbox volumes, and add free-space alerts to the RMM.' `
    -Reference 'https://learn.microsoft.com/windows-server/storage/disk-management/extend-a-basic-volume' `
    -Test {
    $srv = @(Get-TRWinServers)
    if (-not $srv.Count) { return New-TRResult Info 'No Windows server data was imported.' }
    $fail = @(); $warn = @()
    foreach ($s in $srv) {
        foreach ($d in @(Get-TRV $s 'Disks')) {
            $size = [double](Get-TRV $d 'SizeGB'); $free = [double](Get-TRV $d 'FreeGB')
            if ($size -le 1) { continue }
            $pct = [Math]::Round(100 * $free / $size, 0)
            $a = New-TRAffected ('{0} {1}' -f (Get-TRSrvName $s), (Get-TRV $d 'Drive')) ('{0}% free ({1} GB of {2} GB)' -f $pct, $free, $size)
            if ($pct -lt 10) { $fail += $a } elseif ($pct -lt 15) { $warn += $a }
        }
    }
    if ($fail.Count) { return New-TRResult Fail ('{0} under 10% free.' -f (Format-TRN $fail.Count 'volume is' 'volumes are')) @($fail + $warn) }
    if ($warn.Count) { return New-TRResult Warning ('{0} under 15% free.' -f (Format-TRN $warn.Count 'volume is' 'volumes are')) $warn }
    New-TRResult Pass 'Every server volume has at least 15% free.'
}

Register-TRCheck -Platform Any -Id 'SRV-10' -Area 'Servers' -Category 'Windows servers' -Severity High -Effort 2 `
    -Title 'Servers are backed up' `
    -Needs 'WinServers' `
    -Recommendation 'Confirm every server is covered by a backup with offsite or immutable copies: physical servers need a backup agent, and virtual machines need either an agent or host-level backup. Test a restore at least quarterly.' `
    -Reference 'https://www.ncsc.gov.uk/collection/small-business-guide/backing-your-data' `
    -Test {
    $srv = @(Get-TRWinServers)
    if (-not $srv.Count) { return New-TRResult Info 'No Windows server data was imported.' }
    $phys = @(); $virt = @(); $stale = @()
    foreach ($s in $srv) {
        $b = Get-TRSrvBackup $s
        $wsb = Get-TRPath $s 'Backup.WindowsServerBackup'
        if ($wsb -and (Get-TRV $wsb 'LastSuccess') -and (Get-TRDaysSince (Get-TRV $wsb 'LastSuccess')) -gt 2) { $stale += (New-TRSrvAffected $s ('Windows Server Backup last succeeded {0}' -f (Format-TRDate (Get-TRV $wsb 'LastSuccess')))) }
        if ($b) { continue }
        if (Test-TRTrue (Get-TRPath $s 'System.IsVirtual')) { $virt += (New-TRSrvAffected $s 'Virtual machine with no backup agent; confirm host-level backup') } else { $phys += (New-TRSrvAffected $s 'Physical server with no backup agent detected') }
    }
    if ($phys.Count -or $stale.Count) {
        $parts = @()
        if ($phys.Count) { $parts += ('{0} no backup agent' -f (Format-TRN $phys.Count 'physical server has' 'physical servers have')) }
        if ($stale.Count) { $parts += ('{0} not completed a Windows Server Backup in the last two days' -f (Format-TRN $stale.Count 'server has' 'servers have')) }
        return New-TRResult Fail (($parts -join '; ') + '.') @($phys + $stale + $virt)
    }
    if ($virt.Count) { return New-TRResult Warning ('{0} no backup agent. Confirm they are backed up at the hypervisor or cloud level.' -f (Format-TRN $virt.Count 'virtual server has' 'virtual servers have')) $virt }
    New-TRResult Pass 'A backup agent was found on every server.'
}

Register-TRCheck -Platform Any -Id 'SRV-11' -Area 'Servers' -Category 'Windows servers' -Severity Medium -Effort 2 `
    -Title 'Unnecessary and risky services are not running' `
    -Needs 'WinServers' `
    -Recommendation 'Stop and disable the Print Spooler on servers that are not print servers, Remote Registry, SNMP v1/v2, Telnet and FTP where they are not needed, and quote service paths that contain spaces.' `
    -Reference 'https://learn.microsoft.com/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server' `
    -Test {
    $srv = @(Get-TRWinServers)
    if (-not $srv.Count) { return New-TRResult Info 'No Windows server data was imported.' }
    $aff = @()
    foreach ($s in $srv) {
        $svc = @(Get-TRV $s 'Services')
        $run = @{}
        foreach ($x in $svc) { if ([string](Get-TRV $x 'State') -eq 'Running') { $run[[string](Get-TRV $x 'Name')] = $true } }
        $g = @()
        if ($run['Spooler'] -and (@(Get-TRV $s 'Features') -notcontains 'Print-Server')) { $g += 'Print Spooler running' }
        if ($run['RemoteRegistry']) { $g += 'Remote Registry running' }
        if ($run['SNMP']) { $g += 'SNMP service running' }
        if ($run['TlntSvr']) { $g += 'Telnet server running' }
        if ($run['ftpsvc'] -or $run['MSFTPSVC']) { $g += 'FTP server running' }
        $uq = @($svc | Where-Object { Test-TRTrue (Get-TRV $_ 'UnquotedPath') })
        if ($uq.Count) { $g += ('{0} with unquoted paths ({1})' -f (Format-TRN $uq.Count 'service'), (Join-TRList (@($uq | ForEach-Object { Get-TRV $_ 'Name' })) 3)) }
        if ($g.Count) { $aff += (New-TRSrvAffected $s ($g -join '; ')) }
    }
    if ($aff.Count) { return New-TRResult Warning ('{0} {1} unnecessary or risky services.' -f (Format-TROf -N $aff.Count -Total $srv.Count -One 'server' -Many 'servers'), (Select-TRText $aff.Count 'runs' 'run')) $aff }
    New-TRResult Pass 'No unnecessary or risky services were found running.'
}

Register-TRCheck -Platform Any -Id 'SRV-12' -Area 'Servers' -Category 'Windows servers' -Severity High -Effort 8 `
    -Title 'No out-of-support server software' `
    -Needs 'WinServers' `
    -Recommendation 'Plan upgrades or migrations for software that no longer receives security updates, such as SQL Server 2016 and older, Exchange Server 2016 and 2019 (move to Exchange Online or Exchange Server Subscription Edition), and old Java, PHP or .NET runtimes.' `
    -Reference 'https://learn.microsoft.com/lifecycle/products/' `
    -Test {
    $srv = @(Get-TRWinServers)
    if (-not $srv.Count) { return New-TRResult Info 'No Windows server data was imported.' }
    $aff = @()
    foreach ($s in $srv) {
        $seen = @{}
        foreach ($sw in @(Get-TRV $s 'Software')) {
            $n = [string](Get-TRV $sw 'Name')
            foreach ($o in $script:TROldSoftware) {
                if ($n -match $o.Match) {
                    $note = $o.Note -f $(if ($Matches[1]) { $Matches[1] } else { '' })
                    if (-not $seen[$note]) { $seen[$note] = $true; $aff += (New-TRSrvAffected $s ('{0} ({1})' -f $note, $n)) }
                }
            }
        }
    }
    if ($aff.Count) { return New-TRResult Fail ('{0} out-of-support software {1} found.' -f (Format-TRN $aff.Count 'item of' 'items of'), (Select-TRText $aff.Count 'was' 'were')) $aff }
    New-TRResult Pass 'No out-of-support server software was found.'
}

Register-TRCheck -Platform Any -Id 'SRV-13' -Area 'Servers' -Category 'Windows servers' -Severity Medium -Effort 1 `
    -Title 'Server time, certificates and stability' `
    -Needs 'WinServers' `
    -Recommendation 'Fix servers that are not syncing time (members should follow the domain hierarchy, the PDC emulator an external NTP source), renew certificates that expire within 30 days, and investigate unexpected shutdowns and disk errors.' `
    -Reference 'https://learn.microsoft.com/windows-server/networking/windows-time-service/windows-time-service-top' `
    -Test {
    $srv = @(Get-TRWinServers)
    if (-not $srv.Count) { return New-TRResult Info 'No Windows server data was imported.' }
    $aff = @(); $hard = 0
    foreach ($s in $srv) {
        $g = @()
        $src = [string](Get-TRPath $s 'TimeSync.Source')
        if ($src -match 'Local CMOS Clock|Free-running') { $g += ('time source is ' + $src) }
        foreach ($c in @(Get-TRV $s 'Certificates' | Where-Object { -not (Test-TRTrue (Get-TRV $_ 'SelfSigned')) })) {
            $d = Get-TRDaysSince (Get-TRV $c 'NotAfter')
            if ($null -ne $d -and $d -gt -30) { $g += ('certificate {0} {1} {2}' -f ([string](Get-TRV $c 'Subject') -replace '^CN=([^,]+).*', '$1'), $(if ($d -gt 0) { 'expired' } else { 'expires' }), (Format-TRDate (Get-TRV $c 'NotAfter'))); if ($d -gt 0) { $hard++ } }
        }
        $sd = [int](Get-TRPath $s 'Events.UnexpectedShutdowns30d')
        $de = [int](Get-TRPath $s 'Events.DiskErrors30d')
        if ($sd) { $g += (Format-TRN $sd 'unexpected shutdown') + ' in 30 days' }
        if ($de) { $g += (Format-TRN $de 'disk error') + ' in 30 days'; $hard++ }
        if ($g.Count) { $aff += (New-TRSrvAffected $s ($g -join '; ')) }
    }
    if ($aff.Count) { return New-TRResult $(if ($hard) { 'Fail' } else { 'Warning' }) ('{0} {1} time, certificate or stability issues.' -f (Format-TROf -N $aff.Count -Total $srv.Count -One 'server' -Many 'servers'), (Select-TRText $aff.Count 'has' 'have')) $aff }
    New-TRResult Pass 'Time sync, certificates and event logs look healthy on every server.'
}

Register-TRCheck -Platform Any -Id 'SRV-14' -Area 'Servers' -Category 'Windows servers' -Severity Low -Effort 2 `
    -Title 'Physical servers encrypt their disks' `
    -Needs 'WinServers' `
    -Recommendation 'Turn on BitLocker with TPM protection for physical servers, especially in branch offices or shared racks, and store recovery keys in Active Directory or Entra ID.' `
    -Reference 'https://learn.microsoft.com/windows/security/operating-system-security/data-protection/bitlocker/' `
    -Test {
    if (-not @(Get-TRWinServers).Count) { return New-TRResult Info 'No Windows server data was imported.' }
    $phys = @(Get-TRWinServers | Where-Object { -not (Test-TRTrue (Get-TRPath $_ 'System.IsVirtual')) })
    if (-not $phys.Count) { return New-TRResult Info 'All imported Windows servers are virtual machines.' }
    $bad = @($phys | Where-Object { $os = @(Get-TRV $_ 'Disks' | Where-Object { [string](Get-TRV $_ 'Drive') -eq 'C:' })[0]; -not $os -or [string](Get-TRV $os 'BitLocker') -ne 'On' })
    if ($bad.Count) { return New-TRResult Warning ('{0} {1} have BitLocker on the system drive.' -f (Format-TROf -N $bad.Count -Total $phys.Count -One 'physical server' -Many 'physical servers'), (Select-TRText $bad.Count 'does not' 'do not')) @($bad | ForEach-Object { New-TRSrvAffected $_ ([string](Get-TRPath $_ 'System.Model')) }) }
    New-TRResult Pass 'BitLocker protects the system drive on every physical server.'
}

Register-TRCheck -Platform Any -Id 'SRV-15' -Area 'Servers' -Category 'Windows servers' -Severity Info -Effort 0 `
    -Title 'Server data coverage' `
    -Needs 'ServerFiles' `
    -Recommendation 'Run the collector on every server (through the RMM, locally or over WinRM) as an administrator or SYSTEM, so all checks can be assessed. Data older than 30 days should be collected again.' `
    -Reference 'https://learn.microsoft.com/powershell/scripting/learn/remoting/running-remote-commands' `
    -Test {
    $files = @(Get-TRItems 'ServerFiles')
    if (-not $files.Count) { return New-TRResult Info 'No server data files were found.' }
    $used = @($files | Where-Object { $_.Used })
    $aff = @($files | ForEach-Object { New-TRAffected $(if ($_.Server) { $_.Server } else { $_.File }) ('{0}; collected {1}; {2}{3}' -f $(if ($_.Collector) { $_.Collector } else { 'unreadable' }), (Format-TRDate $_.Collected), $(if ($_.Used) { 'used' } else { 'older copy, not used' }), $(if ([int]$_.Errors) { '; ' + (Format-TRN ([int]$_.Errors) 'section') + ' could not be read' } else { '' })) })
    $old = @($used | Where-Object { (Get-TRDaysSince $_.Collected) -gt 30 })
    $na = @(Get-TRWinServers | Where-Object { -not (Test-TRTrue (Get-TRV $_ 'IsAdmin')) })
    $text = '{0} imported from {1}.' -f (Format-TRN $used.Count 'system'), (Format-TRN $files.Count 'file')
    if ($old.Count) { $text += (' {0} older than 30 days.' -f (Format-TRN $old.Count 'data set is' 'data sets are')) }
    if ($na.Count) { $text += (' {0} collected without administrator rights, so some checks are incomplete.' -f (Format-TRN $na.Count 'server was' 'servers were')) }
    New-TRResult Info $text $aff
}

function Get-TRAdData {
    Get-TRCached 'AdDomains' {
        $h = @{}
        foreach ($s in (Get-TRWinServers)) {
            $ad = Get-TRV $s 'ActiveDirectory'
            if (-not $ad) { continue }
            $d = [string](Get-TRV $ad 'Domain')
            $when = ConvertTo-TRDate (Get-TRV $s 'CollectedUtc')
            if (-not $h.ContainsKey($d) -or $h[$d].When -lt $when) { $h[$d] = [pscustomobject]@{ When = $when; Ad = $ad; Dc = (Get-TRSrvName $s) } }
        }
        @($h.Keys | Sort-Object | ForEach-Object { $h[$_] })
    }
}

function Get-TRAdMembers {
    param($Ad, [string]$Group)
    $g = Get-TRPath $Ad ('Groups.' + $Group)
    if (-not $g) { return $null }
    @(Get-TRV $g 'Members')
}

Register-TRCheck -Platform Any -Id 'AD-01' -Area 'Servers' -Category 'Active Directory' -Severity High -Effort 4 `
    -Title 'Active Directory replication and SYSVOL are healthy' `
    -Needs 'WinServers' `
    -Recommendation 'Fix replication errors (repadmin /showrepl, dcdiag) so every domain controller has replicated in the last day, and migrate SYSVOL from FRS to DFS Replication if it has not been done.' `
    -Reference 'https://learn.microsoft.com/troubleshoot/windows-server/active-directory/diagnose-replication-failures' `
    -Test {
    $doms = @(Get-TRAdData)
    if (-not $doms.Count) { return New-TRResult Info 'No domain controller data was imported.' }
    $aff = @()
    foreach ($d in $doms) {
        foreach ($r in @(Get-TRV $d.Ad 'Replication')) {
            $fails = [int](Get-TRV $r 'Failures')
            $last = Get-TRDaysSince (Get-TRV $r 'LastSuccess')
            if ($fails -gt 0 -or ($null -ne $last -and $last -gt 1)) { $aff += (New-TRAffected ('{0} from {1}' -f (Get-TRV $r 'Destination'), (Get-TRV $r 'Source')) ('{0}; {1}; last success {2}' -f (Get-TRV $r 'NamingContext'), (Format-TRN $fails 'failure'), (Get-TRV $r 'LastSuccess'))) }
        }
        $sv = [string](Get-TRV $d.Ad 'SysvolState')
        if ($sv -and $sv -notmatch 'Eliminated') { $aff += (New-TRAffected (Get-TRV $d.Ad 'Domain') ('SYSVOL is not on DFS Replication: ' + $sv)) }
    }
    if ($aff.Count) { return New-TRResult Fail ('{0} replication or SYSVOL problems found.' -f $aff.Count) $aff }
    New-TRResult Pass ('Replication is healthy for {0}.' -f (Join-TRList (@($doms | ForEach-Object { Get-TRV $_.Ad 'Domain' })) 3))
}

Register-TRCheck -Platform Any -Id 'AD-02' -Area 'Servers' -Category 'Active Directory' -Severity High -Effort 3 `
    -Title 'Privileged AD groups are small and protected' `
    -Needs 'WinServers' `
    -Recommendation 'Keep Domain Admins to two to four named admin accounts (separate from day-to-day accounts), leave Enterprise Admins and Schema Admins empty until needed, empty Account, Server, Print and Backup Operators, and add admin accounts to Protected Users.' `
    -Reference 'https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models' `
    -Test {
    $doms = @(Get-TRAdData)
    if (-not $doms.Count) { return New-TRResult Info 'No domain controller data was imported.' }
    $aff = @(); $hard = $false
    foreach ($d in $doms) {
        $dn = Get-TRV $d.Ad 'Domain'
        $da = @(Get-TRAdMembers $d.Ad 'Domain Admins' | Where-Object { [string](Get-TRV $_ 'Class') -eq 'user' })
        if ($da.Count -gt 5) { $aff += (New-TRAffected ($dn + ': Domain Admins') ('{0} members: {1}' -f $da.Count, (Join-TRList (@($da | ForEach-Object { Get-TRV $_ 'Name' })) 8))); $hard = $true }
        foreach ($g in 'Enterprise Admins', 'Schema Admins') {
            $m = @(Get-TRAdMembers $d.Ad $g | Where-Object { [string](Get-TRV $_ 'Name') -ne 'Administrator' })
            if ($m.Count) { $aff += (New-TRAffected ('{0}: {1}' -f $dn, $g) ('Not empty: ' + (Join-TRList (@($m | ForEach-Object { Get-TRV $_ 'Name' })) 5))) }
        }
        foreach ($g in 'Account Operators', 'Server Operators', 'Print Operators', 'Backup Operators') {
            $m = @(Get-TRAdMembers $d.Ad $g)
            if ($m.Count) { $aff += (New-TRAffected ('{0}: {1}' -f $dn, $g) ('Members: ' + (Join-TRList (@($m | ForEach-Object { Get-TRV $_ 'Name' })) 5))) }
        }
        $pu = @(Get-TRAdMembers $d.Ad 'Protected Users' | ForEach-Object { [string](Get-TRV $_ 'Name') })
        $unprot = @($da | Where-Object { $pu -notcontains [string](Get-TRV $_ 'Name') -and [string](Get-TRV $_ 'Name') -ne 'Administrator' })
        if ($unprot.Count) { $aff += (New-TRAffected ($dn + ': Protected Users') ('{0} not in Protected Users' -f (Format-TRN $unprot.Count 'domain admin'))) }
    }
    $big = @($aff | Where-Object { $_.Item -like '*: Domain Admins' })
    if ($hard) { return New-TRResult Fail ('Domain Admins is too large ({0}; two to four is recommended).' -f (Join-TRList (@($big | ForEach-Object { ($_.Detail -split ':')[0] })) 3)) $aff }
    if ($aff.Count) { return New-TRResult Warning ('{0} privileged group {1} found.' -f (Format-TRN $aff.Count 'issue'), (Select-TRText $aff.Count 'was' 'were')) $aff }
    New-TRResult Pass 'Privileged groups are small, operator groups are empty and admins are in Protected Users.'
}

Register-TRCheck -Platform Any -Id 'AD-03' -Area 'Servers' -Category 'Active Directory' -Severity High -Effort 4 `
    -Title 'No accounts open to Kerberos and delegation attacks' `
    -Needs 'WinServers' `
    -Recommendation 'Remove service principal names from admin accounts and use group managed service accounts with long random passwords for services, turn Kerberos pre-authentication back on, clear "password not required" and reversible encryption flags, remove unconstrained delegation from non-DC computers and users, and remove passwords from account descriptions.' `
    -Reference 'https://learn.microsoft.com/windows-server/security/kerberos/kerberos-constrained-delegation-overview' `
    -Test {
    $doms = @(Get-TRAdData)
    if (-not $doms.Count) { return New-TRResult Info 'No domain controller data was imported.' }
    $fail = @(); $warn = @()
    foreach ($d in $doms) {
        $u = Get-TRV $d.Ad 'Users'
        foreach ($x in @(Get-TRV $u 'Kerberoastable')) { $a = New-TRAffected (Get-TRV $x 'Name') ('Service principal name set; password last set {0}' -f (Format-TRDate (Get-TRV $x 'PasswordLastSet'))); if (Test-TRTrue (Get-TRV $x 'Admin')) { $fail += $a } else { $warn += $a } }
        foreach ($x in @(Get-TRV $u 'PreAuthDisabled')) { $fail += (New-TRAffected (Get-TRV $x 'Name') 'Kerberos pre-authentication not required') }
        foreach ($x in @(Get-TRV $u 'ReversibleEncryption')) { $fail += (New-TRAffected (Get-TRV $x 'Name') 'Password stored with reversible encryption') }
        foreach ($x in @(Get-TRV $u 'PasswordNotRequired')) { $warn += (New-TRAffected (Get-TRV $x 'Name') 'Password not required flag set') }
        foreach ($x in @(Get-TRV $u 'UnconstrainedDelegation')) { $fail += (New-TRAffected (Get-TRV $x 'Name') 'User trusted for unconstrained delegation') }
        foreach ($x in @(Get-TRPath $d.Ad 'Computers.UnconstrainedDelegation')) { $fail += (New-TRAffected $x 'Computer trusted for unconstrained delegation') }
        foreach ($x in @(Get-TRV $u 'DescriptionMentionsPassword')) { $warn += (New-TRAffected $x 'Account description mentions a password') }
    }
    if ($fail.Count) { return New-TRResult Fail ('{0} high-risk account settings found ({1} more to review).' -f $fail.Count, $warn.Count) @($fail + $warn) }
    if ($warn.Count) { return New-TRResult Warning ('{0} account settings to review.' -f $warn.Count) $warn }
    New-TRResult Pass 'No roastable, delegation or weak password flags were found.'
}

Register-TRCheck -Platform Any -Id 'AD-04' -Area 'Servers' -Category 'Active Directory' -Severity High -Effort 2 `
    -Title 'Domain password and lockout policy is strong' `
    -Needs 'WinServers' `
    -Recommendation 'Set the default domain password policy to a minimum of 14 characters with complexity, keep 24 passwords of history, lock accounts after 5 to 10 failed attempts for at least 15 minutes, and never allow reversible encryption. Use fine-grained policies for admins and service accounts.' `
    -Reference 'https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/password-policy' `
    -Test {
    $doms = @(Get-TRAdData)
    if (-not $doms.Count) { return New-TRResult Info 'No domain controller data was imported.' }
    $fail = @(); $warn = @()
    foreach ($d in $doms) {
        $p = Get-TRV $d.Ad 'PasswordPolicy'
        $dn = Get-TRV $d.Ad 'Domain'
        $len = [int](Get-TRV $p 'MinLength'); $lock = [int](Get-TRV $p 'LockoutThreshold')
        $g = @(); $h = $false
        if ($len -lt 8) { $g += ('minimum length ' + $len); $h = $true } elseif ($len -lt 14) { $g += ('minimum length ' + $len) }
        if (-not (Test-TRTrue (Get-TRV $p 'Complexity'))) { $g += 'complexity off'; $h = $true }
        if ($lock -eq 0) { $g += 'no account lockout'; $h = $true } elseif ($lock -gt 10) { $g += ('lockout after ' + $lock + ' attempts') }
        if (Test-TRTrue (Get-TRV $p 'Reversible')) { $g += 'reversible encryption'; $h = $true }
        if ([int](Get-TRV $p 'History') -lt 24) { $g += ('history ' + (Get-TRV $p 'History')) }
        if ($g.Count) { if ($h) { $fail += (New-TRAffected $dn ($g -join ', ')) } else { $warn += (New-TRAffected $dn ($g -join ', ')) } }
    }
    $detail = if (@($fail + $warn).Count -eq 1) { ': ' + @($fail + $warn)[0].Detail } else { '' }
    if ($fail.Count) { return New-TRResult Fail ('The domain password or lockout policy is weak{0}.' -f $detail) @($fail + $warn) }
    if ($warn.Count) { return New-TRResult Warning ('The domain password policy falls short of current guidance{0}.' -f $detail) $warn }
    New-TRResult Pass 'The domain password and lockout policy meets current guidance.'
}

Register-TRCheck -Platform Any -Id 'AD-05' -Area 'Servers' -Category 'Active Directory' -Severity Medium -Effort 2 `
    -Title 'Directory recovery and krbtgt hygiene' `
    -Needs 'WinServers' `
    -Recommendation 'Turn on the AD Recycle Bin, reset the krbtgt password (twice, at least 10 hours apart) if it has not changed in 180 days, set ms-DS-MachineAccountQuota to 0 so ordinary users cannot join computers, and raise the domain and forest functional levels to Windows Server 2016.' `
    -Reference 'https://learn.microsoft.com/windows-server/identity/ad-ds/manage/ad-forest-recovery-resetting-the-krbtgt-password' `
    -Test {
    $doms = @(Get-TRAdData)
    if (-not $doms.Count) { return New-TRResult Info 'No domain controller data was imported.' }
    $aff = @(); $hard = $false
    foreach ($d in $doms) {
        $dn = Get-TRV $d.Ad 'Domain'
        $g = @()
        if (-not (Test-TRTrue (Get-TRV $d.Ad 'RecycleBin'))) { $g += 'AD Recycle Bin off'; $hard = $true }
        $k = Get-TRDaysSince (Get-TRV $d.Ad 'KrbtgtPasswordLastSet')
        if ($null -ne $k -and $k -gt 180) { $g += ('krbtgt password {0} days old' -f $k) }
        $maq = Get-TRV $d.Ad 'MachineAccountQuota'
        if ($null -ne $maq -and [int]$maq -gt 0) { $g += ('machine account quota ' + $maq) }
        $fl = [string](Get-TRV $d.Ad 'DomainMode')
        if ($fl -match 'Windows(2003|2008|2008R2|2012|2012R2)') { $g += ('domain functional level ' + $fl) }
        if ($g.Count) { $aff += (New-TRAffected $dn ($g -join '; ')) }
    }
    if ($aff.Count -eq 1) { return New-TRResult $(if ($hard) { 'Fail' } else { 'Warning' }) ('{0}: {1}.' -f $aff[0].Item, $aff[0].Detail) $aff }
    if ($aff.Count) { return New-TRResult $(if ($hard) { 'Fail' } else { 'Warning' }) ('{0} attention.' -f (Format-TRN $aff.Count 'domain needs' 'domains need')) $aff }
    New-TRResult Pass 'Recycle Bin is on, krbtgt is recent, machine account quota is 0 and functional levels are current.'
}

Register-TRCheck -Platform Any -Id 'AD-06' -Area 'Servers' -Category 'Active Directory' -Severity Medium -Effort 3 `
    -Title 'Stale and out-of-support accounts are cleaned up' `
    -Needs 'WinServers' `
    -Recommendation 'Disable, then delete, user and computer accounts that have not signed in for 90 days, and remove or upgrade computers running out-of-support Windows versions.' `
    -Reference 'https://learn.microsoft.com/services-hub/unified/health/remediation-steps-ad/regularly-check-for-and-remove-inactive-user-accounts-in-active-directory' `
    -Test {
    $doms = @(Get-TRAdData)
    if (-not $doms.Count) { return New-TRResult Info 'No domain controller data was imported.' }
    $aff = @(); $su = 0; $sc = 0; $old = 0
    foreach ($d in $doms) {
        $u = Get-TRV $d.Ad 'Users'
        $c = Get-TRV $d.Ad 'Computers'
        $su += [int](Get-TRV $u 'StaleCount')
        $sc += @(Get-TRV $c 'Stale').Count
        $old += @(Get-TRV $c 'OldOs').Count
        $aff += @(Get-TRV $u 'Stale' | Select-Object -First 200 | ForEach-Object { New-TRAffected (Get-TRV $_ 'Name') ('User; last sign-in {0}' -f $(if (Get-TRV $_ 'LastLogon') { Format-TRDate (Get-TRV $_ 'LastLogon') } else { 'never' })) })
        $aff += @(Get-TRV $c 'Stale' | Select-Object -First 200 | ForEach-Object { New-TRAffected (Get-TRV $_ 'Name') ('Computer {0}; last sign-in {1}' -f (Get-TRV $_ 'Os'), (Format-TRDate (Get-TRV $_ 'LastLogon'))) })
        $aff += @(Get-TRV $c 'OldOs' | ForEach-Object { New-TRAffected (Get-TRV $_ 'Name') ('Out-of-support OS: ' + (Get-TRV $_ 'Os')) })
    }
    if (-not ($su + $sc + $old)) { return New-TRResult Pass 'No stale or out-of-support accounts were found.' }
    New-TRResult Warning ('{0}, {1} and {2} found.' -f (Format-TRN $su 'stale user'), (Format-TRN $sc 'stale computer'), (Format-TRN $old 'out-of-support computer')) $aff
}

Register-TRCheck -Platform Any -Id 'AD-07' -Area 'Servers' -Category 'Active Directory' -Severity High -Effort 3 `
    -Title 'Domain controllers are hardened' `
    -Needs 'WinServers' `
    -Recommendation 'On every domain controller require LDAP signing (LDAPServerIntegrity 2) and enforce LDAP channel binding, disable the Print Spooler, run a supported Windows Server version, and do not install other roles or software on DCs.' `
    -Reference 'https://learn.microsoft.com/troubleshoot/windows-server/active-directory/enable-ldap-signing-in-windows-server' `
    -Test {
    $dcs = @(Get-TRWinServers | Where-Object { Test-TRSrvDc $_ })
    if (-not $dcs.Count) { return New-TRResult Info 'No domain controller data was imported.' }
    $fail = @(); $warn = @()
    foreach ($s in $dcs) {
        $ad = Get-TRV $s 'ActiveDirectory'
        $g = @(); $h = $false
        $run = @(Get-TRV $s 'Services' | Where-Object { [string](Get-TRV $_ 'Name') -eq 'Spooler' -and [string](Get-TRV $_ 'State') -eq 'Running' })
        if ($run.Count) { $g += 'Print Spooler running'; $h = $true }
        if ($ad -and [string](Get-TRV $ad 'LdapServerSigning') -ne '2') { $g += 'LDAP signing not required'; $h = $true }
        if ($ad -and [string](Get-TRV $ad 'LdapChannelBinding') -ne '2') { $g += 'LDAP channel binding not enforced' }
        $extra = @(Get-TRSrvRoles $s | Where-Object { $_ -notin @('Domain controller', 'DNS', 'DHCP') })
        if ($extra.Count) { $g += ('other roles: ' + ($extra -join ', ')) }
        if (-not $g.Count) { continue }
        if ($h) { $fail += (New-TRSrvAffected $s ($g -join '; ')) } else { $warn += (New-TRSrvAffected $s ($g -join '; ')) }
    }
    if ($fail.Count) { return New-TRResult Fail ('{0} {1} hardening.' -f (Format-TROf -N $fail.Count -Total $dcs.Count -One 'domain controller' -Many 'domain controllers'), (Select-TRText $fail.Count 'needs' 'need')) @($fail + $warn) }
    if ($warn.Count) { return New-TRResult Warning ('{0} {1} minor hardening gaps.' -f (Format-TROf -N $warn.Count -Total $dcs.Count -One 'domain controller' -Many 'domain controllers'), (Select-TRText $warn.Count 'has' 'have')) $warn }
    New-TRResult Pass ('{0} {1} hardened.' -f (Format-TROf -N $dcs.Count -Total $dcs.Count -One 'domain controller' -Many 'domain controllers'), (Select-TRText $dcs.Count 'is' 'are'))
}

Register-TRCheck -Platform Any -Id 'AD-08' -Area 'Servers' -Category 'Active Directory' -Severity High -Effort 3 `
    -Title 'LAPS covers domain computers' `
    -Needs 'WinServers' `
    -Recommendation 'Extend the schema for Windows LAPS (Update-LapsADSchema), grant computers permission to update their password (Set-LapsADComputerSelfPermission) and deploy a LAPS policy to every workstation and member server OU.' `
    -Reference 'https://learn.microsoft.com/windows-server/identity/laps/laps-scenarios-windows-server-active-directory' `
    -Test {
    $doms = @(Get-TRAdData)
    if (-not $doms.Count) { return New-TRResult Info 'No domain controller data was imported.' }
    $aff = @(); $worst = 100
    foreach ($d in $doms) {
        $c = Get-TRV $d.Ad 'Computers'
        $total = [int](Get-TRV $c 'Enabled')
        $with = [int](Get-TRV $c 'WithLaps')
        $pct = if ($total) { Get-TRPercent $with $total } else { 100 }
        if (-not (Test-TRTrue (Get-TRV $d.Ad 'LapsSchema'))) { $pct = 0 }
        if ($pct -lt $worst) { $worst = $pct }
        $aff += (New-TRAffected (Get-TRV $d.Ad 'Domain') ('{0} of {1} enabled computers have a LAPS password{2}' -f $with, $total, $(if (-not (Test-TRTrue (Get-TRV $d.Ad 'LapsSchema'))) { '; schema not extended' } else { '' })))
    }
    if ($worst -lt 50) { return New-TRResult Fail ('LAPS covers {0}% of computers in the weakest domain.' -f $worst) $aff }
    if ($worst -lt 95) { return New-TRResult Warning ('LAPS covers {0}% of computers in the weakest domain.' -f $worst) $aff }
    New-TRResult Pass 'LAPS covers the domain computers.' $aff
}

Register-TRCheck -Platform Any -Id 'HV-01' -Area 'Servers' -Category 'Hyper-V' -Severity Medium -Effort 2 `
    -Title 'Hyper-V virtual machines are healthy' `
    -Needs 'WinServers' `
    -Recommendation 'Delete checkpoints older than a week (they grow and slow the VM), fix failed or warning replication, update integration services and VM configuration versions, set the automatic stop action to Save or Shut down, and use Secure Boot and a virtual TPM on Generation 2 VMs.' `
    -Reference 'https://learn.microsoft.com/windows-server/virtualization/hyper-v/manage/choose-between-standard-or-production-checkpoints-in-hyper-v' `
    -Test {
    $hosts = @(Get-TRWinServers | Where-Object { Get-TRV $_ 'HyperV' })
    if (-not $hosts.Count) { return New-TRResult Info 'No Hyper-V host data was imported.' }
    $fail = @(); $warn = @(); $count = 0
    foreach ($h in $hosts) {
        foreach ($v in @(Get-TRPath $h 'HyperV.Vms')) {
            $count++
            $g = @(); $bad = $false
            $age = Get-TRDaysSince (Get-TRV $v 'OldestCheckpoint')
            if ([int](Get-TRV $v 'Checkpoints') -gt 0 -and $null -ne $age -and $age -gt 7) { $g += ('{0}, oldest {1} days' -f (Format-TRN ([int](Get-TRV $v 'Checkpoints')) 'checkpoint'), $age); $bad = $true }
            if ([string](Get-TRV $v 'ReplicationHealth') -in @('Critical', 'Warning')) { $g += ('replication ' + (Get-TRV $v 'ReplicationHealth')); $bad = $true }
            if ([string](Get-TRV $v 'AutomaticStopAction') -eq 'TurnOff') { $g += 'turned off (not shut down) when the host stops' }
            if ([string](Get-TRV $v 'IntegrationServicesState') -match 'Update required') { $g += 'integration services out of date' }
            if ([int](Get-TRV $v 'Generation') -eq 2 -and [string](Get-TRV $v 'SecureBoot') -eq 'Off') { $g += 'Secure Boot off' }
            if ([int](Get-TRV $v 'Generation') -eq 1) { $g += 'Generation 1' }
            if (-not $g.Count) { continue }
            $a = New-TRAffected ('{0} on {1}' -f (Get-TRV $v 'Name'), (Get-TRSrvName $h)) ($g -join '; ')
            if ($bad) { $fail += $a } else { $warn += $a }
        }
        $c = Get-TRPath $h 'HyperV.Cluster'
        if ($c) {
            foreach ($n in @(Get-TRV $c 'Nodes' | Where-Object { [string](Get-TRV $_ 'State') -ne 'Up' })) { $fail += (New-TRAffected ('Cluster node ' + (Get-TRV $n 'Name')) ('State ' + (Get-TRV $n 'State'))) }
            foreach ($v in @(Get-TRV $c 'Csv' | Where-Object { [double](Get-TRV $_ 'FreePercent') -lt 15 })) { $warn += (New-TRAffected ('CSV ' + (Get-TRV $v 'Name')) ('{0}% free' -f (Get-TRV $v 'FreePercent'))) }
        }
    }
    if ($fail.Count) { return New-TRResult Fail ('{0} old checkpoints, replication or cluster problems.' -f (Format-TRN $fail.Count 'virtual machine has' 'virtual machines have')) @($fail + $warn) }
    if ($warn.Count) { return New-TRResult Warning ('{0} {1} configuration gaps.' -f (Format-TROf -N $warn.Count -Total $count -One 'virtual machine' -Many 'virtual machines'), (Select-TRText $warn.Count 'has' 'have')) $warn }
    New-TRResult Pass ('{0} on {1} {2} healthy.' -f (Format-TROf -N $count -Total $count -One 'virtual machine' -Many 'virtual machines'), (Format-TRN $hosts.Count 'host'), (Select-TRText $count 'looks' 'look'))
}

Register-TRCheck -Platform Any -Id 'HV-02' -Area 'Servers' -Category 'Hyper-V' -Severity Medium -Effort 8 `
    -Title 'Hyper-V hosts are dedicated' `
    -Needs 'WinServers' `
    -Recommendation 'Keep Hyper-V hosts to the Hyper-V role (plus clustering and storage features). Move domain controller, file, print, SQL or other workloads into virtual machines, and keep the host off the general user network.' `
    -Reference 'https://learn.microsoft.com/windows-server/virtualization/hyper-v/plan/plan-hyper-v-security-in-windows-server' `
    -Test {
    $hosts = @(Get-TRWinServers | Where-Object { Get-TRV $_ 'HyperV' })
    if (-not $hosts.Count) { return New-TRResult Info 'No Hyper-V host data was imported.' }
    $aff = @($hosts | ForEach-Object { $r = @(Get-TRSrvRoles $_ | Where-Object { $_ -notin @('Hyper-V host', 'Failover cluster') }); if ($r.Count) { New-TRSrvAffected $_ ('Also runs: ' + ($r -join ', ')) } })
    if ($aff.Count) { return New-TRResult Warning ('{0} {1} other roles.' -f (Format-TROf -N $aff.Count -Total $hosts.Count -One 'Hyper-V host' -Many 'Hyper-V hosts'), (Select-TRText $aff.Count 'runs' 'run')) $aff }
    New-TRResult Pass 'Every Hyper-V host is dedicated to virtualisation.'
}

Register-TRCheck -Platform Any -Id 'LNX-01' -Area 'Servers' -Category 'Linux servers' -Severity High -Effort 8 `
    -Title 'Linux servers run a supported release and are patched' `
    -Needs 'LinuxServers' `
    -Recommendation 'Upgrade servers on releases that no longer receive security updates (or add extended support such as Ubuntu Pro), install outstanding security updates, restart servers that need it, and turn on automatic security updates where the workload allows.' `
    -Reference 'https://ubuntu.com/about/release-cycle' `
    -Test {
    $srv = @(Get-TRItems 'LinuxServers')
    if (-not $srv.Count) { return New-TRResult Info 'No Linux server data was imported.' }
    $fail = @(); $warn = @()
    foreach ($s in $srv) {
        $os = Get-TROsName -Name ([string](Get-TRPath $s 'System.OsName'))
        $sup = Get-TROsSupport $os
        $g = @(); $h = $false
        if ($sup -and $sup.State -in @('Ended', 'Esu')) { $g += ('{0} support ended {1}' -f $os, (Format-TRDate $sup.End)); $h = $true }
        elseif ($sup -and $sup.State -eq 'Ending') { $g += ('{0} support ends {1}' -f $os, (Format-TRDate $sup.End)) }
        $sec = Get-TRPath $s 'Updates.Security'
        if ($null -ne $sec -and [int]$sec -gt 0) { $g += (Format-TRN ([int]$sec) 'security update') + ' pending'; $h = $true }
        $up = Get-TRPath $s 'Updates.Upgradable'
        if ($null -ne $up -and [int]$up -gt 20) { $g += ('{0} packages to update' -f $up) }
        if (Test-TRTrue (Get-TRPath $s 'Updates.RebootRequired')) { $g += 'restart required' }
        if (-not $g.Count) { continue }
        $a = New-TRAffected ([string](Get-TRV $s 'ComputerName')) ($g -join '; ')
        if ($h) { $fail += $a } else { $warn += $a }
    }
    if ($fail.Count) { return New-TRResult Fail ('{0} {1} out of support or missing security updates.' -f (Format-TROf -N $fail.Count -Total $srv.Count -One 'Linux server' -Many 'Linux servers'), (Select-TRText $fail.Count 'is' 'are')) @($fail + $warn) }
    if ($warn.Count) { return New-TRResult Warning ('{0} {1} updates or a restart.' -f (Format-TROf -N $warn.Count -Total $srv.Count -One 'Linux server' -Many 'Linux servers'), (Select-TRText $warn.Count 'needs' 'need')) $warn }
    New-TRResult Pass ('{0} {1} supported and up to date.' -f (Format-TROf -N $srv.Count -Total $srv.Count -One 'Linux server' -Many 'Linux servers'), (Select-TRText $srv.Count 'is' 'are'))
}

Register-TRCheck -Platform Any -Id 'LNX-02' -Area 'Servers' -Category 'Linux servers' -Severity High -Effort 2 `
    -Title 'Linux SSH and accounts are hardened' `
    -Needs 'LinuxServers' `
    -Recommendation 'In sshd_config set PermitRootLogin no, PasswordAuthentication no (keys only), PermitEmptyPasswords no and MaxAuthTries 4 or lower. Remove extra UID 0 accounts and empty passwords, and limit passwordless sudo to specific commands.' `
    -Reference 'https://www.ncsc.gov.uk/collection/device-security-guidance' `
    -Test {
    $srv = @(Get-TRItems 'LinuxServers')
    if (-not $srv.Count) { return New-TRResult Info 'No Linux server data was imported.' }
    $fail = @(); $warn = @()
    foreach ($s in $srv) {
        $g = @(); $h = $false
        $root = [string](Get-TRPath $s 'Ssh.PermitRootLogin')
        if ($root -eq 'yes') { $g += 'root can sign in over SSH with a password'; $h = $true } elseif ($root -in @('prohibit-password', 'without-password')) { $g += 'root can sign in over SSH with a key' }
        if ([string](Get-TRPath $s 'Ssh.PasswordAuthentication') -eq 'yes') { $g += 'SSH password sign-in allowed' }
        if ([string](Get-TRPath $s 'Ssh.PermitEmptyPasswords') -eq 'yes') { $g += 'SSH empty passwords allowed'; $h = $true }
        if ([int](Get-TRPath $s 'Ssh.MaxAuthTries') -gt 4) { $g += ('SSH MaxAuthTries ' + (Get-TRPath $s 'Ssh.MaxAuthTries')) }
        $uid0 = @(Get-TRPath $s 'Accounts.Uid0' | Where-Object { $_ -ne 'root' })
        if ($uid0.Count) { $g += ('extra UID 0 accounts: ' + ($uid0 -join ', ')); $h = $true }
        $empty = @(Get-TRPath $s 'Accounts.EmptyPasswords')
        if ($empty.Count) { $g += ('accounts with empty passwords: ' + ($empty -join ', ')); $h = $true }
        $np = @(Get-TRPath $s 'Accounts.SudoNoPassword' | Where-Object { $_ -match 'NOPASSWD:\s*ALL' })
        if ($np.Count) { $g += (Format-TRN $np.Count 'unrestricted passwordless sudo rule') }
        if (-not $g.Count) { continue }
        $a = New-TRAffected ([string](Get-TRV $s 'ComputerName')) ($g -join '; ')
        if ($h) { $fail += $a } else { $warn += $a }
    }
    if ($fail.Count) { return New-TRResult Fail ('{0} {1} risky SSH or account access.' -f (Format-TROf -N $fail.Count -Total $srv.Count -One 'Linux server' -Many 'Linux servers'), (Select-TRText $fail.Count 'allows' 'allow')) @($fail + $warn) }
    if ($warn.Count) { return New-TRResult Warning ('{0} {1} SSH or sudo settings to tighten.' -f (Format-TROf -N $warn.Count -Total $srv.Count -One 'Linux server' -Many 'Linux servers'), (Select-TRText $warn.Count 'has' 'have')) $warn }
    New-TRResult Pass 'SSH and accounts are hardened on every Linux server.'
}

Register-TRCheck -Platform Any -Id 'LNX-03' -Area 'Servers' -Category 'Linux servers' -Severity High -Effort 3 `
    -Title 'Linux servers have EDR, a firewall and audit logging' `
    -Needs 'LinuxServers' `
    -Recommendation 'Install Defender for Endpoint on Linux (or the client''s EDR), turn on the host firewall (ufw or firewalld) with a default-deny inbound policy, keep SELinux enforcing or AppArmor enabled, run auditd, and make sure time is synchronised.' `
    -Reference 'https://learn.microsoft.com/defender-endpoint/microsoft-defender-endpoint-linux' `
    -Test {
    $srv = @(Get-TRItems 'LinuxServers')
    if (-not $srv.Count) { return New-TRResult Info 'No Linux server data was imported.' }
    $fail = @(); $warn = @()
    foreach ($s in $srv) {
        $g = @(); $h = $false
        if (-not [string](Get-TRPath $s 'Security.Edr')) { $g += 'no EDR detected'; $h = $true }
        $fw = ([string](Get-TRPath $s 'Firewall.Ufw') -eq 'active') -or ([string](Get-TRPath $s 'Firewall.Firewalld') -eq 'running') -or ([int](Get-TRPath $s 'Firewall.NftRules') -gt 0) -or ([int](Get-TRPath $s 'Firewall.IptablesRules') -gt 0)
        if (-not $fw) { $g += 'no host firewall rules' }
        $mac = ([string](Get-TRPath $s 'Security.SELinux') -eq 'Enforcing') -or ([string](Get-TRPath $s 'Security.AppArmor') -eq 'enabled')
        if (-not $mac) { $g += 'SELinux or AppArmor not enforcing' }
        if ([string](Get-TRPath $s 'Security.Auditd') -ne 'active') { $g += 'auditd not running' }
        if ([string](Get-TRPath $s 'Security.NtpSynchronized') -eq 'no') { $g += 'time not synchronised' }
        if (-not $g.Count) { continue }
        $a = New-TRAffected ([string](Get-TRV $s 'ComputerName')) ($g -join '; ')
        if ($h) { $fail += $a } else { $warn += $a }
    }
    if ($fail.Count) { return New-TRResult Fail ('{0} {1} no EDR.' -f (Format-TROf -N $fail.Count -Total $srv.Count -One 'Linux server' -Many 'Linux servers'), (Select-TRText $fail.Count 'has' 'have')) @($fail + $warn) }
    if ($warn.Count) { return New-TRResult Warning ('{0} {1} protection gaps.' -f (Format-TROf -N $warn.Count -Total $srv.Count -One 'Linux server' -Many 'Linux servers'), (Select-TRText $warn.Count 'has' 'have')) $warn }
    New-TRResult Pass 'EDR, firewall, mandatory access control and auditd are in place on every Linux server.'
}

Register-TRCheck -Platform Any -Id 'LNX-04' -Area 'Servers' -Category 'Linux servers' -Severity Medium -Effort 1 `
    -Title 'Linux disk space, packages and kernel settings' `
    -Needs 'LinuxServers' `
    -Recommendation 'Free space on file systems over 85% full, remove legacy network services (telnet, rsh, FTP, TFTP, NIS), and keep kernel hardening defaults (ASLR on, ICMP redirects off, no core dumps of setuid programs).' `
    -Reference 'https://www.cisecurity.org/cis-benchmarks' `
    -Test {
    $srv = @(Get-TRItems 'LinuxServers')
    if (-not $srv.Count) { return New-TRResult Info 'No Linux server data was imported.' }
    $fail = @(); $warn = @()
    foreach ($s in $srv) {
        $g = @(); $h = $false
        foreach ($d in @(Get-TRV $s 'Disks')) {
            $p = ([string]$d) -split '\|'
            if ($p.Count -ge 3 -and [int]$p[2] -ge 85 -and $p[0] -notmatch '^/(boot/efi|snap)') { $g += ('{0} {1}% used' -f $p[0], $p[2]); if ([int]$p[2] -ge 90) { $h = $true } }
        }
        $risky = @(Get-TRV $s 'RiskyPackages')
        if ($risky.Count) { $g += ('legacy services installed: ' + ($risky -join ', ')); $h = $true }
        if ([string](Get-TRPath $s 'Kernel.RandomizeVaSpace') -ne '2') { $g += 'ASLR not fully on' }
        if ([string](Get-TRPath $s 'Kernel.AcceptRedirects') -eq '1') { $g += 'accepts ICMP redirects' }
        if ([string](Get-TRPath $s 'Kernel.SuidDumpable') -notin @('0', '')) { $g += 'setuid core dumps allowed' }
        if (-not $g.Count) { continue }
        $a = New-TRAffected ([string](Get-TRV $s 'ComputerName')) ($g -join '; ')
        if ($h) { $fail += $a } else { $warn += $a }
    }
    if ($fail.Count) { return New-TRResult Fail ('{0} {1} nearly full or {2} legacy services.' -f (Format-TROf -N $fail.Count -Total $srv.Count -One 'Linux server' -Many 'Linux servers'), (Select-TRText $fail.Count 'is' 'are'), (Select-TRText $fail.Count 'runs' 'run')) @($fail + $warn) }
    if ($warn.Count) { return New-TRResult Warning ('{0} {1} settings to tighten.' -f (Format-TROf -N $warn.Count -Total $srv.Count -One 'Linux server' -Many 'Linux servers'), (Select-TRText $warn.Count 'has' 'have')) $warn }
    New-TRResult Pass 'Disk space, packages and kernel settings are fine on every Linux server.'
}

function Get-TRToolsText {
    param([string]$Status)
    switch -Regex ($Status) {
        'NotInstalled' { return 'not installed' }
        'NotRunning' { return 'not running' }
        'NeedUpgrade' { return 'needs an upgrade' }
        'TooOld|Unsupported' { return 'too old to be supported' }
        'SupportedOld' { return 'an old version' }
    }
    $Status
}

function Get-TREsxiSupport {
    param([string]$Version)
    if ($Version -match '^([5-6])\.') { return [pscustomobject]@{ State = 'Ended'; Text = ('ESXi {0} support ended in October 2022 or earlier' -f $Version) } }
    if ($Version -match '^7\.') { return [pscustomobject]@{ State = 'Ended'; Text = ('ESXi {0} general support ended on 2 October 2025' -f $Version) } }
    if ($Version -match '^8\.') { return [pscustomobject]@{ State = 'Supported'; Text = ('ESXi {0} is supported until October 2027' -f $Version) } }
    [pscustomobject]@{ State = 'Unknown'; Text = $Version }
}

Register-TRCheck -Platform Any -Id 'VMW-01' -Area 'Servers' -Category 'VMware' -Severity High -Effort 16 `
    -Title 'VMware hosts run a supported, hardened ESXi' `
    -Needs 'VMwareData' `
    -Recommendation 'Upgrade ESXi and vCenter 7.0 and older to 8.0 (or plan a move to another platform), keep SSH and the ESXi Shell stopped unless needed, turn on lockdown mode, and configure NTP and remote syslog on every host.' `
    -Reference 'https://knowledge.broadcom.com/external/article?legacyId=2145103' `
    -Test {
    $data = @(Get-TRItems 'VMwareData')
    if (-not $data.Count) { return New-TRResult Info 'No VMware data was imported.' }
    $fail = @(); $warn = @(); $n = 0
    foreach ($x in $data) {
        foreach ($h in @(Get-TRV $x 'Hosts')) {
            $n++
            $g = @(); $bad = $false
            $sup = Get-TREsxiSupport ([string](Get-TRV $h 'Version'))
            if ($sup.State -eq 'Ended') { $g += $sup.Text; $bad = $true }
            if ([string](Get-TRV $h 'ConnectionState') -notin @('Connected', 'Maintenance')) { $g += ('state ' + (Get-TRV $h 'ConnectionState')); $bad = $true }
            if (Test-TRTrue (Get-TRPath $h 'Ssh.Running')) { $g += 'SSH running' }
            if (Test-TRTrue (Get-TRPath $h 'Shell.Running')) { $g += 'ESXi Shell running' }
            if ([string](Get-TRV $h 'LockdownMode') -eq 'lockdownDisabled') { $g += 'lockdown mode off' }
            if (-not @(Get-TRV $h 'NtpServers').Count -or -not (Test-TRTrue (Get-TRPath $h 'Ntp.Running'))) { $g += 'NTP not configured or not running' }
            if (-not [string](Get-TRV (Get-TRV $h 'Advanced') 'Syslog.global.logHost')) { $g += 'no remote syslog' }
            if (-not $g.Count) { continue }
            $a = New-TRAffected ([string](Get-TRV $h 'Name')) ($g -join '; ')
            if ($bad) { $fail += $a } else { $warn += $a }
        }
        $ab = Get-TRV $x 'About'
        if ([string](Get-TRV $ab 'ProductLine') -eq 'vpx' -and [string](Get-TRV $ab 'Version') -match '^[5-7]\.') { $fail += (New-TRAffected ([string](Get-TRV $x 'ComputerName')) ('vCenter {0} is out of general support' -f (Get-TRV $ab 'Version'))) }
    }
    if ($fail.Count) {
        $vc = @($fail | Where-Object { $_.Detail -like 'vCenter *' }).Count
        $hc = $fail.Count - $vc
        $parts = @()
        if ($hc) { $parts += (Format-TRN $hc 'ESXi host') }
        if ($vc) { $parts += $(if ($vc -eq 1) { 'the vCenter' } else { '{0} vCenters' -f $vc }) }
        $t = ($parts -join ' and ') + $(if ($fail.Count -eq 1) { ' is' } else { ' are' }) + ' out of support or disconnected.'
        return New-TRResult Fail ($t.Substring(0, 1).ToUpper() + $t.Substring(1)) @($fail + $warn)
    }
    if ($warn.Count) { return New-TRResult Warning ('{0} {1} hardening gaps.' -f (Format-TROf -N $warn.Count -Total $n -One 'ESXi host' -Many 'ESXi hosts'), (Select-TRText $warn.Count 'has' 'have')) $warn }
    New-TRResult Pass ('{0} {1} supported and hardened.' -f (Format-TROf -N $n -Total $n -One 'ESXi host' -Many 'ESXi hosts'), (Select-TRText $n 'is' 'are'))
}

Register-TRCheck -Platform Any -Id 'VMW-02' -Area 'Servers' -Category 'VMware' -Severity Medium -Effort 2 `
    -Title 'VMware virtual machines, datastores and clusters are healthy' `
    -Needs 'VMwareData' `
    -Recommendation 'Delete snapshots older than three days, keep VMware Tools current and running, disconnect ISO images, keep datastores above 15% free, and turn on vSphere HA for clusters.' `
    -Reference 'https://knowledge.broadcom.com/external/article?legacyId=1025279' `
    -Test {
    $data = @(Get-TRItems 'VMwareData')
    if (-not $data.Count) { return New-TRResult Info 'No VMware data was imported.' }
    $fail = @(); $warn = @()
    foreach ($x in $data) {
        foreach ($v in @(Get-TRV $x 'Vms')) {
            $g = @(); $bad = $false
            $age = Get-TRDaysSince (Get-TRV $v 'OldestSnapshot')
            if ([int](Get-TRV $v 'Snapshots') -gt 0 -and $null -ne $age -and $age -gt 3) { $g += ('{0}, oldest {1} days ({2} GB)' -f (Format-TRN ([int](Get-TRV $v 'Snapshots')) 'snapshot'), $age, (Get-TRV $v 'SnapshotGB')); $bad = $true }
            if ([string](Get-TRV $v 'PowerState') -eq 'PoweredOn' -and [string](Get-TRV $v 'ToolsStatus') -match 'NotInstalled|NotRunning|guestToolsNotInstalled|guestToolsNeedUpgrade|guestToolsTooOld|guestToolsSupportedOld') { $g += ('VMware Tools ' + (Get-TRToolsText ([string](Get-TRV $v 'ToolsStatus')))) }
            if (Test-TRTrue (Get-TRV $v 'IsoConnected')) { $g += 'ISO connected' }
            if ($g.Count) { $a = New-TRAffected ([string](Get-TRV $v 'Name')) ($g -join '; '); if ($bad) { $fail += $a } else { $warn += $a } }
        }
        foreach ($d in @(Get-TRV $x 'Datastores')) {
            $cap = [double](Get-TRV $d 'CapacityGB'); $free = [double](Get-TRV $d 'FreeGB')
            if ($cap -le 0) { continue }
            $pct = [Math]::Round(100 * $free / $cap, 0)
            if ($pct -lt 10) { $fail += (New-TRAffected ('Datastore ' + (Get-TRV $d 'Name')) ('{0}% free' -f $pct)) } elseif ($pct -lt 15) { $warn += (New-TRAffected ('Datastore ' + (Get-TRV $d 'Name')) ('{0}% free' -f $pct)) }
        }
        foreach ($c in @(Get-TRV $x 'Clusters' | Where-Object { -not (Test-TRTrue (Get-TRV $_ 'HaEnabled')) })) { $warn += (New-TRAffected ('Cluster ' + (Get-TRV $c 'Name')) 'vSphere HA off') }
    }
    $snapVms = @($fail | Where-Object { $_.Item -notlike 'Datastore *' }).Count
    $fullDs = @($fail | Where-Object { $_.Item -like 'Datastore *' }).Count
    if ($fail.Count) {
        $parts = @()
        if ($snapVms) { $parts += ('{0} snapshots older than three days' -f (Format-TRN $snapVms 'virtual machine has' 'virtual machines have')) }
        if ($fullDs) { $parts += ('{0} under 10% free' -f (Format-TRN $fullDs 'datastore is' 'datastores are')) }
        if ($warn.Count) { $parts += ('{0} to tidy up' -f (Format-TRN $warn.Count 'other item' 'other items')) }
        return New-TRResult Fail (($parts -join '; ') + '.') @($fail + $warn)
    }
    if ($warn.Count) { return New-TRResult Warning ('{0} to tidy up (VMware Tools, ISO images, low datastore space or vSphere HA).' -f (Format-TRN $warn.Count 'VMware item' 'VMware items')) $warn }
    New-TRResult Pass 'No old snapshots, Tools problems or full datastores were found.'
}

function Get-TRServerSummary {
    Get-TRCached 'ServerSummary' {
        $rows = New-Object System.Collections.ArrayList
        foreach ($s in (Get-TRWinServers)) {
            $os = Get-TRSrvOs $s
            $sup = Get-TROsSupport $os
            $b = @(Get-TRSrvBaseline $s | Where-Object { $null -ne $_.Result })
            [void]$rows.Add([pscustomobject]@{
                    Name = (Get-TRSrvName $s); Kind = 'Windows'; Os = $os; Support = $sup; Roles = ((Get-TRSrvRoles $s) -join ', '); Virtual = (Test-TRTrue (Get-TRPath $s 'System.IsVirtual'))
                    LastBoot = (Get-TRPath $s 'System.LastBoot'); LastUpdate = (Get-TRPath $s 'Updates.LastHotfixDate'); Edr = (Get-TRSrvEdr $s); Backup = (Get-TRSrvBackup $s)
                    Baseline = $(if ($b.Count) { Get-TRPercent @($b | Where-Object { $_.Result -eq $true }).Count $b.Count } else { $null }); Collected = (Get-TRV $s 'CollectedUtc')
                })
        }
        foreach ($s in (Get-TRItems 'LinuxServers')) {
            $os = Get-TROsName -Name ([string](Get-TRPath $s 'System.OsName'))
            [void]$rows.Add([pscustomobject]@{
                    Name = [string](Get-TRV $s 'ComputerName'); Kind = 'Linux'; Os = $os; Support = (Get-TROsSupport $os); Roles = ''; Virtual = ([string](Get-TRPath $s 'System.Virtualisation') -notin @('none', ''))
                    LastBoot = (Get-TRPath $s 'System.LastBoot'); LastUpdate = (Get-TRPath $s 'Updates.LastUpdate'); Edr = [string](Get-TRPath $s 'Security.Edr'); Backup = [string](Get-TRPath $s 'Security.Backup'); Baseline = $null; Collected = (Get-TRV $s 'CollectedUtc')
                })
        }
        foreach ($x in (Get-TRItems 'VMwareData')) {
            foreach ($h in @(Get-TRV $x 'Hosts')) {
                $sup = Get-TREsxiSupport ([string](Get-TRV $h 'Version'))
                [void]$rows.Add([pscustomobject]@{
                        Name = [string](Get-TRV $h 'Name'); Kind = 'ESXi'; Os = ('ESXi {0} build {1}' -f (Get-TRV $h 'Version'), (Get-TRV $h 'Build')); Support = $(if ($sup.State -eq 'Ended') { [pscustomobject]@{ State = 'Ended'; End = $null } } else { $null }); Roles = ('Cluster ' + (Get-TRV $h 'Cluster')); Virtual = $false
                        LastBoot = (Get-TRV $h 'BootTime'); LastUpdate = $null; Edr = ''; Backup = ''; Baseline = $null; Collected = (Get-TRV $x 'CollectedUtc')
                    })
            }
        }
        @($rows.ToArray())
    }
}

function Add-TRServerInventories {
    param($Inv)
    if (-not (Test-TRCollected @('ServerFiles'))) { return }
    $rows = foreach ($r in (Get-TRServerSummary | Sort-Object Kind, Name)) {
        [pscustomobject][ordered]@{
            'Server' = $r.Name; 'Type' = $r.Kind; 'Operating system' = $r.Os
            'Support' = $(if ($r.Support) { switch ($r.Support.State) { 'Ended' { 'Ended' } 'Esu' { 'Extended updates only' } 'Ending' { 'Ends ' + (Format-TRDate $r.Support.End) } default { 'Supported' } } } else { '' })
            'Roles' = $r.Roles; 'Virtual' = ConvertTo-TRYesNo $r.Virtual; 'Last boot' = (Format-TRDate $r.LastBoot); 'Last update' = (Format-TRDate $r.LastUpdate)
            'EDR' = $r.Edr; 'Backup' = $r.Backup; 'Baseline met' = $(if ($null -ne $r.Baseline) { '{0}%' -f $r.Baseline } else { '' }); 'Data collected' = (Format-TRDate $r.Collected)
        }
    }
    Add-TRInventory $Inv 'Servers' 'Servers' 'Servers from the imported server data, with support status, protection and baseline score.' $rows
    $win = @(Get-TRWinServers)
    if ($win.Count) {
        $rows = foreach ($s in $win) {
            foreach ($b in (Get-TRSrvBaseline $s)) { [pscustomobject][ordered]@{ 'Server' = (Get-TRSrvName $s); 'Setting' = $b.Title; 'Source' = $b.Ref; 'Result' = $(if ($b.Result -eq $true) { 'Met' } elseif ($b.Result -eq $false) { 'Not met' } else { 'Not assessed' }) } }
        }
        Add-TRInventory $Inv 'ServerBaseline' 'Server hardening baseline' 'Each Windows hardening baseline setting by server.' $rows
        $rows = foreach ($s in $win) {
            foreach ($u in @(Get-TRPath $s 'Updates.Missing')) { [pscustomobject][ordered]@{ 'Server' = (Get-TRSrvName $s); 'Update' = (Get-TRV $u 'Title'); 'Severity' = (Get-TRV $u 'Severity'); 'Categories' = (Get-TRV $u 'Categories'); 'KB' = (Get-TRV $u 'Kb') } }
        }
        Add-TRInventory $Inv 'ServerUpdates' 'Missing server updates' 'Windows updates the servers reported as missing.' $rows
        $rows = foreach ($s in $win) {
            foreach ($sw in @(Get-TRV $s 'Software')) { [pscustomobject][ordered]@{ 'Server' = (Get-TRSrvName $s); 'Software' = (Get-TRV $sw 'Name'); 'Version' = (Get-TRV $sw 'Version'); 'Publisher' = (Get-TRV $sw 'Publisher') } }
        }
        Add-TRInventory $Inv 'ServerSoftware' 'Server software' 'Software installed on the Windows servers.' $rows
        $rows = foreach ($s in $win) {
            foreach ($sh in @(Get-TRPath $s 'Smb.Shares')) { [pscustomobject][ordered]@{ 'Server' = (Get-TRSrvName $s); 'Share' = (Get-TRV $sh 'Name'); 'Path' = (Get-TRV $sh 'Path'); 'Broad write access' = (Get-TRV $sh 'OpenAccess'); 'Encrypted' = ConvertTo-TRYesNo (Get-TRV $sh 'EncryptData') } }
        }
        Add-TRInventory $Inv 'ServerShares' 'Server file shares' 'SMB shares, flagging Full or Change access for Everyone, Authenticated Users or Domain Users.' $rows
    }
    $hv = @(Get-TRWinServers | Where-Object { Get-TRV $_ 'HyperV' })
    if ($hv.Count) {
        $rows = foreach ($h in $hv) {
            foreach ($v in @(Get-TRPath $h 'HyperV.Vms')) { [pscustomobject][ordered]@{ 'VM' = (Get-TRV $v 'Name'); 'Host' = (Get-TRSrvName $h); 'State' = (Get-TRV $v 'State'); 'Generation' = (Get-TRV $v 'Generation'); 'Version' = (Get-TRV $v 'Version'); 'CPUs' = (Get-TRV $v 'Cpus'); 'Memory GB' = (Get-TRV $v 'MemoryStartupGB'); 'Checkpoints' = (Get-TRV $v 'Checkpoints'); 'Replication' = (Get-TRV $v 'ReplicationHealth'); 'Integration services' = (Get-TRV $v 'IntegrationServicesState') } }
        }
        Add-TRInventory $Inv 'HyperVVms' 'Hyper-V virtual machines' 'Virtual machines on the Hyper-V hosts.' $rows
    }
    foreach ($d in (Get-TRAdData)) {
        $rows = foreach ($g in 'Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators', 'Account Operators', 'Server Operators', 'Print Operators', 'Backup Operators', 'Protected Users') {
            foreach ($m in @(Get-TRAdMembers $d.Ad $g)) { [pscustomobject][ordered]@{ 'Domain' = (Get-TRV $d.Ad 'Domain'); 'Group' = $g; 'Member' = (Get-TRV $m 'Name'); 'Type' = (Get-TRV $m 'Class') } }
        }
        Add-TRInventory $Inv ('AdGroups' + ([string](Get-TRV $d.Ad 'NetBios'))) ('AD privileged groups (' + (Get-TRV $d.Ad 'Domain') + ')') 'Members of the privileged Active Directory groups, including nested members.' $rows
    }
    $vm = @(Get-TRItems 'VMwareData')
    if ($vm.Count) {
        $rows = foreach ($x in $vm) {
            foreach ($v in @(Get-TRV $x 'Vms')) { [pscustomobject][ordered]@{ 'VM' = (Get-TRV $v 'Name'); 'Host' = (Get-TRV $v 'Host'); 'Power' = (Get-TRV $v 'PowerState'); 'Guest OS' = $(if (Get-TRV $v 'GuestOs') { Get-TRV $v 'GuestOs' } else { Get-TRV $v 'ConfiguredOs' }); 'Hardware' = (Get-TRV $v 'HardwareVersion'); 'Tools' = (Get-TRV $v 'ToolsStatus'); 'Snapshots' = (Get-TRV $v 'Snapshots'); 'Provisioned GB' = (Get-TRV $v 'ProvisionedGB') } }
        }
        Add-TRInventory $Inv 'VMwareVms' 'VMware virtual machines' 'Virtual machines from vCenter or ESXi.' $rows
    }
    Add-TRInventory $Inv 'ServerFiles' 'Server data files' 'Every server data file found, and whether it was used.' @(Get-TRItems 'ServerFiles' | ForEach-Object { [pscustomobject][ordered]@{ 'File' = $_.File; 'Server' = $_.Server; 'Collector' = $_.Collector; 'Collected' = (Format-TRDate $_.Collected -WithTime); 'Used' = ConvertTo-TRYesNo $_.Used; 'Sections not read' = $_.Errors } })
}

function New-TRServersHtml {
    param($Findings, [int]$Number, [string]$Client)
    $sb = New-Object System.Text.StringBuilder
    $sum = @(Get-TRServerSummary)
    $f = @($Findings)
    $score = Get-TRScore $f
    [void]$sb.Append(('<section id="tab-servers" class="tab"><h2>{0}. Servers</h2>' -f $Number))
    $files = @(Get-TRItems 'ServerFiles' | Where-Object { $_.Used })
    $oldest = @($files | Where-Object { $_.Collected } | Sort-Object { ConvertTo-TRDate $_.Collected } | Select-Object -First 1)
    [void]$sb.Append(('<p class="note">{0}</p>' -f (ConvertTo-TRHtml ('Server data was collected read-only by the collector on each server (locally, through the RMM or over WinRM), and from vCenter or ESXi for VMware. The hardening baseline is drawn from CIS Windows Server Level 1 and the Microsoft security baseline. {0} were imported{1}.' -f (Format-TRN $sum.Count 'system'), $(if ($oldest.Count) { ', the oldest collected on ' + (Format-TRDate $oldest[0].Collected) } else { '' })))))
    $ended = @($sum | Where-Object { $_.Support -and $_.Support.State -in @('Ended', 'Esu') }).Count
    $noEdr = @($sum | Where-Object { $_.Kind -ne 'ESXi' -and -not $_.Edr }).Count
    $bl = @($sum | Where-Object { $null -ne $_.Baseline })
    $tiles = @(
        @{ V = $(if ($null -ne $score) { '{0}%' -f $score } else { 'n/a' }); L = 'Server score'; N = ('{0} fail, {1} warning, {2} pass' -f @($f | Where-Object { $_.Status -eq 'Fail' }).Count, @($f | Where-Object { $_.Status -eq 'Warning' }).Count, @($f | Where-Object { $_.Status -eq 'Pass' }).Count) },
        @{ V = [string]$sum.Count; L = 'Systems'; N = (@($sum | Group-Object Kind | ForEach-Object { '{0} {1}' -f $_.Count, $_.Name }) -join ', ') },
        @{ V = [string]$ended; L = 'Out of support'; N = 'Operating system or hypervisor' },
        @{ V = [string]$noEdr; L = 'Without EDR'; N = 'Servers with no EDR detected' }
    )
    if ($bl.Count) { $tiles += @{ V = ('{0}%' -f [Math]::Round(($bl | Measure-Object -Property Baseline -Average).Average)); L = 'Baseline met'; N = 'Windows hardening, average' } }
    [void]$sb.Append('<div class="opp-sum">')
    foreach ($t in $tiles) { [void]$sb.Append(('<div class="tile"><div class="v">{0}</div><div class="l">{1}</div><div class="n">{2}</div></div>' -f (ConvertTo-TRHtml $t.V), (ConvertTo-TRHtml $t.L), (ConvertTo-TRHtml $t.N))) }
    [void]$sb.Append('</div>')
    if ($sum.Count) {
        [void]$sb.Append('<h3>Servers</h3><div class="table-wrap static"><table><thead><tr><th>Server</th><th>Operating system</th><th>Roles</th><th>Last update</th><th>EDR</th><th>Backup</th><th class="num">Baseline</th></tr></thead><tbody>')
        foreach ($r in ($sum | Sort-Object Kind, Name)) {
            $os = $r.Os
            if ($r.Support -and $r.Support.State -in @('Ended', 'Esu')) { $os += ' <span class="chip s-Fail">Out of support</span>' } elseif ($r.Support -and $r.Support.State -eq 'Ending') { $os += (' <span class="chip s-Warning">Ends {0}</span>' -f (Format-TRDate $r.Support.End)) }
            [void]$sb.Append(('<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td><td class="num">{6}</td></tr>' -f (ConvertTo-TRHtml $r.Name), ($os -replace '&(?!amp;)', '&amp;'), (ConvertTo-TRHtml $r.Roles), (Format-TRDate $r.LastUpdate), $(if ($r.Edr) { ConvertTo-TRHtml $r.Edr } elseif ($r.Kind -eq 'ESXi') { '' } else { '<span class="chip s-Fail">None</span>' }), $(if ($r.Backup) { ConvertTo-TRHtml $r.Backup } elseif ($r.Kind -eq 'ESXi') { '' } else { 'None detected' }), $(if ($null -ne $r.Baseline) { '{0}%' -f $r.Baseline } else { '' })))
        }
        [void]$sb.Append('</tbody></table></div>')
    }
    $win = @(Get-TRWinServers)
    if ($win.Count) {
        [void]$sb.Append('<h3>Windows hardening baseline</h3>')
        if ($win.Count -le 12) {
            [void]$sb.Append('<div class="table-wrap static"><table class="matrix"><thead><tr><th>Setting</th><th>Source</th>')
            foreach ($s in $win) { [void]$sb.Append(('<th class="num">{0}</th>' -f (ConvertTo-TRHtml (Get-TRSrvName $s)))) }
            [void]$sb.Append('</tr></thead><tbody>')
            foreach ($b in $script:TRWinBaseline) {
                [void]$sb.Append(('<tr><td>{0}</td><td>{1}</td>' -f (ConvertTo-TRHtml $b.Title), (ConvertTo-TRHtml $b.Ref)))
                foreach ($s in $win) {
                    $r = @(Get-TRSrvBaseline $s | Where-Object { $_.Id -eq $b.Id })[0]
                    $cell = if ($r.Result -eq $true) { '<span class="chip s-Pass">Met</span>' } elseif ($r.Result -eq $false) { '<span class="chip s-Fail">Not met</span>' } else { '<span class="chip s-Info">n/a</span>' }
                    [void]$sb.Append(('<td class="num">{0}</td>' -f $cell))
                }
                [void]$sb.Append('</tr>')
            }
            [void]$sb.Append('</tbody></table></div>')
        }
        else {
            [void]$sb.Append('<div class="table-wrap static"><table><thead><tr><th>Setting</th><th>Source</th><th class="num">Servers meeting it</th></tr></thead><tbody>')
            foreach ($b in $script:TRWinBaseline) {
                $res = @($win | ForEach-Object { @(Get-TRSrvBaseline $_ | Where-Object { $_.Id -eq $b.Id })[0].Result } | Where-Object { $null -ne $_ })
                [void]$sb.Append(('<tr><td>{0}</td><td>{1}</td><td class="num">{2} of {3}</td></tr>' -f (ConvertTo-TRHtml $b.Title), (ConvertTo-TRHtml $b.Ref), @($res | Where-Object { $_ -eq $true }).Count, $res.Count))
            }
            [void]$sb.Append('</tbody></table></div>')
        }
    }
    $order = @{ Fail = 0; Warning = 1; Manual = 2; NotAssessed = 3; Info = 4; Pass = 5 }
    $sev = @{ High = 0; Medium = 1; Low = 2; Info = 3 }
    $shown = @($f | Where-Object { $_.Status -ne 'Info' -or $_.Id -eq 'SRV-15' } | Sort-Object @{ e = { $order[[string]$_.Status] } }, @{ e = { $sev[[string]$_.Severity] } }, Id)
    if ($shown.Count) {
        [void]$sb.Append('<h3>Server findings</h3><div class="table-wrap static"><table><thead><tr><th>Status</th><th>Check</th><th>Current state</th></tr></thead><tbody>')
        foreach ($x in $shown) { [void]$sb.Append(('<tr><td><span class="chip s-{0}">{1}</span></td><td><a href="#" data-goto="f-{2}">{3}</a> <span class="f-id">{2}</span></td><td>{4}</td></tr>' -f $x.Status, (Get-TRStatusLabel $x.Status), (ConvertTo-TRHtml $x.Id), (ConvertTo-TRHtml $x.Title), (ConvertTo-TRHtml $x.Current))) }
        [void]$sb.Append('</tbody></table></div>')
    }
    [void]$sb.Append('</section>')
    $sb.ToString()
}
