param(
    [string]$OutputPath = (Join-Path $env:ProgramData 'TenantReview\ServerData'),
    [switch]$AsJson,
    [switch]$SkipUpdateSearch,
    [int]$UpdateSearchTimeoutSeconds = 240,
    [int]$MaxAdObjects = 50000
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$collectorVersion = '1.0.0'
$computer = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { [Environment]::MachineName }
$started = Get-Date
$result = [ordered]@{
    SchemaVersion    = 1
    Collector        = 'windows'
    CollectorVersion = $collectorVersion
    CollectedUtc     = $started.ToUniversalTime().ToString('o')
    ComputerName     = $computer
    RunAs            = ('{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME)
    IsAdmin          = $false
    Errors           = @()
}

function Add-TRSection {
    param([string]$Name, [scriptblock]$Script)
    try { $result[$Name] = & $Script }
    catch {
        $result['Errors'] += ('{0}: {1}' -f $Name, $_.Exception.Message)
        $result[$Name] = $null
    }
}

function Get-TRReg {
    param([string]$Path, [string]$Name)
    try { (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name } catch { $null }
}

function ConvertTo-TRIso {
    param($Date)
    if ($null -eq $Date) { return $null }
    try { ([datetime]$Date).ToUniversalTime().ToString('o') } catch { $null }
}

try {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $result['IsAdmin'] = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
catch { }

Add-TRSection 'System' {
    $cs = Get-CimInstance Win32_ComputerSystem
    $os = Get-CimInstance Win32_OperatingSystem
    $bios = Get-CimInstance Win32_BIOS
    $cv = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $fqdn = $computer
    try { $fqdn = [System.Net.Dns]::GetHostEntry($computer).HostName } catch { }
    [ordered]@{
        Name           = $cs.Name
        Fqdn           = $fqdn
        Domain         = $cs.Domain
        PartOfDomain   = [bool]$cs.PartOfDomain
        DomainRole     = [int]$cs.DomainRole
        Manufacturer   = $cs.Manufacturer
        Model          = $cs.Model
        SerialNumber   = $bios.SerialNumber
        BiosVersion    = $bios.SMBIOSBIOSVersion
        BiosDate       = ConvertTo-TRIso $bios.ReleaseDate
        MemoryGB       = [Math]::Round([double]$cs.TotalPhysicalMemory / 1GB, 1)
        LogicalCpus    = [int]$cs.NumberOfLogicalProcessors
        OsCaption      = $os.Caption
        OsVersion      = $os.Version
        OsBuild        = [string]$os.BuildNumber
        Ubr            = Get-TRReg $cv 'UBR'
        DisplayVersion = Get-TRReg $cv 'DisplayVersion'
        EditionId      = Get-TRReg $cv 'EditionID'
        InstallationType = Get-TRReg $cv 'InstallationType'
        InstallDate    = ConvertTo-TRIso $os.InstallDate
        LastBoot       = ConvertTo-TRIso $os.LastBootUpTime
        IsVirtual      = [bool](($cs.Model -match 'Virtual|VMware|KVM|HVM|Xen') -or ($cs.Manufacturer -match 'VMware|QEMU|Xen|Amazon|Google|Nutanix'))
        TimeZone       = (Get-CimInstance Win32_TimeZone).Caption
    }
}

Add-TRSection 'Features' {
    if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) { @(Get-WindowsFeature | Where-Object { $_.Installed } | ForEach-Object { [string]$_.Name }) }
    else { @(Get-WindowsOptionalFeature -Online | Where-Object { $_.State -eq 'Enabled' } | ForEach-Object { [string]$_.FeatureName }) }
}

Add-TRSection 'Updates' {
    $hf = @(Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object { [datetime]$_.InstalledOn } -Descending)
    $pending = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') -or [bool](Get-TRReg 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' 'PendingFileRenameOperations')
    $wu = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    $out = [ordered]@{
        LastHotfix       = $(if ($hf.Count) { [string]$hf[0].HotFixID } else { $null })
        LastHotfixDate   = $(if ($hf.Count) { ConvertTo-TRIso $hf[0].InstalledOn } else { $null })
        HotfixCount      = $hf.Count
        RebootPending    = [bool]$pending
        WsusServer       = Get-TRReg $wu 'WUServer'
        UseWsus          = Get-TRReg "$wu\AU" 'UseWUServer'
        AutoUpdateOption = Get-TRReg "$wu\AU" 'AUOptions'
        NoAutoUpdate     = Get-TRReg "$wu\AU" 'NoAutoUpdate'
        SearchStatus     = 'NotRun'
        Missing          = @()
    }
    if (-not $SkipUpdateSearch) {
        $job = Start-Job -ScriptBlock {
            $s = New-Object -ComObject Microsoft.Update.Session
            $r = $s.CreateUpdateSearcher().Search("IsInstalled=0 and Type='Software' and IsHidden=0")
            foreach ($u in $r.Updates) {
                [pscustomobject]@{ Title = [string]$u.Title; Severity = [string]$u.MsrcSeverity; Categories = (@($u.Categories | ForEach-Object { $_.Name }) -join ', '); Kb = (@($u.KBArticleIDs) -join ','); Published = $u.LastDeploymentChangeTime }
            }
        }
        if (Wait-Job $job -Timeout $UpdateSearchTimeoutSeconds) {
            try {
                $out['Missing'] = @(Receive-Job $job -ErrorAction Stop | ForEach-Object { [ordered]@{ Title = $_.Title; Severity = $_.Severity; Categories = $_.Categories; Kb = $_.Kb; Published = ConvertTo-TRIso $_.Published } })
                $out['SearchStatus'] = 'Completed'
            }
            catch { $out['SearchStatus'] = 'Failed: ' + $_.Exception.Message }
        }
        else { Stop-Job $job; $out['SearchStatus'] = 'TimedOut' }
        Remove-Job $job -Force
    }
    $out
}

Add-TRSection 'Defender' {
    $out = [ordered]@{ Present = $false }
    if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
        $mp = Get-MpComputerStatus
        $pref = Get-MpPreference
        $out = [ordered]@{
            Present                   = $true
            RunningMode               = [string]$mp.AMRunningMode
            AntivirusEnabled          = [bool]$mp.AntivirusEnabled
            RealTimeProtectionEnabled = [bool]$mp.RealTimeProtectionEnabled
            BehaviorMonitorEnabled    = [bool]$mp.BehaviorMonitorEnabled
            IoavProtectionEnabled     = [bool]$mp.IoavProtectionEnabled
            IsTamperProtected         = [bool]$mp.IsTamperProtected
            SignatureLastUpdated      = ConvertTo-TRIso $mp.AntivirusSignatureLastUpdated
            SignatureAgeDays          = [int]$mp.AntivirusSignatureAge
            ProductVersion            = [string]$mp.AMProductVersion
            PuaProtection             = [int]$pref.PUAProtection
            NetworkProtection         = [int]$pref.EnableNetworkProtection
            MapsReporting             = [int]$pref.MAPSReporting
            CloudBlockLevel           = [int]$pref.CloudBlockLevel
            SubmitSamplesConsent      = [int]$pref.SubmitSamplesConsent
            AsrIds                    = @($pref.AttackSurfaceReductionRules_Ids | ForEach-Object { [string]$_ })
            AsrActions                = @($pref.AttackSurfaceReductionRules_Actions | ForEach-Object { [int]$_ })
            ExclusionPathCount        = @($pref.ExclusionPath | Where-Object { $_ -and $_ -notmatch 'N/A' }).Count
            ExclusionProcessCount     = @($pref.ExclusionProcess | Where-Object { $_ -and $_ -notmatch 'N/A' }).Count
        }
    }
    $out['MdeOnboarded'] = ((Get-TRReg 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status' 'OnboardingState') -eq 1)
    $sense = Get-Service -Name 'Sense' -ErrorAction SilentlyContinue
    $out['SenseRunning'] = [bool]($sense -and $sense.Status -eq 'Running')
    $out
}

Add-TRSection 'Firewall' {
    $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object {
            [ordered]@{ Name = [string]$_.Name; Enabled = [string]$_.Enabled; DefaultInboundAction = [string]$_.DefaultInboundAction; DefaultOutboundAction = [string]$_.DefaultOutboundAction; LogBlocked = [string]$_.LogBlocked; LogAllowed = [string]$_.LogAllowed; LogMaxSizeKilobytes = [int]$_.LogMaxSizeKilobytes }
        })
    $risky = @()
    $watch = @('3389', '445', '135', '139', '5985', '5986', '22', '1433', '3306', '5900', '23', '21')
    foreach ($r in @(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Inbound -Enabled True -Action Allow -ErrorAction SilentlyContinue)) {
        try {
            $pf = $r | Get-NetFirewallPortFilter -ErrorAction Stop
            $af = $r | Get-NetFirewallAddressFilter -ErrorAction Stop
            $ports = @($pf.LocalPort | ForEach-Object { [string]$_ })
            $remote = @($af.RemoteAddress | ForEach-Object { [string]$_ })
            $anyRemote = $remote -contains 'Any'
            $hit = @($ports | Where-Object { $_ -eq 'Any' -or $watch -contains $_ })
            if ($anyRemote -and $hit.Count) { $risky += [ordered]@{ Name = [string]$r.DisplayName; Profile = [string]$r.Profile; Protocol = [string]$pf.Protocol; Ports = ($ports -join ','); Program = [string]($r | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue).Program } }
        }
        catch { }
    }
    [ordered]@{ Profiles = $profiles; OpenRules = @($risky | Select-Object -First 200) }
}

Add-TRSection 'RemoteDesktop' {
    $ts = 'HKLM:\System\CurrentControlSet\Control\Terminal Server'
    $tcp = "$ts\WinStations\RDP-Tcp"
    $pol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    $nla = Get-TRReg $pol 'UserAuthentication'
    if ($null -eq $nla) { $nla = Get-TRReg $tcp 'UserAuthentication' }
    $layer = Get-TRReg $pol 'SecurityLayer'
    if ($null -eq $layer) { $layer = Get-TRReg $tcp 'SecurityLayer' }
    $enc = Get-TRReg $pol 'MinEncryptionLevel'
    if ($null -eq $enc) { $enc = Get-TRReg $tcp 'MinEncryptionLevel' }
    $deny = Get-TRReg $pol 'fDenyTSConnections'
    if ($null -eq $deny) { $deny = Get-TRReg $ts 'fDenyTSConnections' }
    [ordered]@{ Enabled = ($deny -eq 0); Nla = $nla; SecurityLayer = $layer; MinEncryptionLevel = $enc; Port = Get-TRReg $tcp 'PortNumber'; DisableClipboard = Get-TRReg $pol 'fDisableClip'; DisableDriveMapping = Get-TRReg $pol 'fDisableCdm'; IdleTimeoutMs = Get-TRReg $pol 'MaxIdleTime' }
}

Add-TRSection 'Smb' {
    $srv = Get-SmbServerConfiguration
    $cli = $null
    try { $cli = Get-SmbClientConfiguration } catch { }
    $shares = @()
    foreach ($s in @(Get-SmbShare | Where-Object { -not $_.Special -and $_.Name -notmatch '^(ADMIN|IPC|print)\$$' })) {
        $open = @()
        try {
            foreach ($a in @(Get-SmbShareAccess -Name $s.Name -ErrorAction Stop)) {
                if ([string]$a.AccessControlType -eq 'Allow' -and [string]$a.AccessRight -in @('Full', 'Change') -and [string]$a.AccountName -match '^(Everyone|NT AUTHORITY\\Authenticated Users|.*\\Domain Users|BUILTIN\\Users)$') { $open += ('{0} {1}' -f $a.AccountName, $a.AccessRight) }
            }
        }
        catch { }
        $shares += [ordered]@{ Name = [string]$s.Name; Path = [string]$s.Path; EncryptData = [bool]$s.EncryptData; OpenAccess = ($open -join '; ') }
    }
    $smb1Feature = $null
    try { $smb1Feature = [string](Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop).State } catch { }
    [ordered]@{
        Smb1Enabled            = [bool]$srv.EnableSMB1Protocol
        Smb1Feature            = $smb1Feature
        ServerSigningRequired  = [bool]$srv.RequireSecuritySignature
        ServerSigningEnabled   = [bool]$srv.EnableSecuritySignature
        EncryptData            = [bool]$srv.EncryptData
        RejectUnencrypted      = [bool]$srv.RejectUnencryptedAccess
        ClientSigningRequired  = $(if ($cli) { [bool]$cli.RequireSecuritySignature } else { $null })
        Shares                 = $shares
    }
}

Add-TRSection 'Protocols' {
    $base = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
    $p = [ordered]@{}
    foreach ($n in 'SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1', 'TLS 1.2', 'TLS 1.3') {
        $p[$n] = [ordered]@{ ServerEnabled = Get-TRReg "$base\$n\Server" 'Enabled'; ServerDisabledByDefault = Get-TRReg "$base\$n\Server" 'DisabledByDefault'; ClientEnabled = Get-TRReg "$base\$n\Client" 'Enabled' }
    }
    [ordered]@{
        Schannel        = $p
        StrongCrypto64  = Get-TRReg 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' 'SchUseStrongCrypto'
        StrongCrypto32  = Get-TRReg 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319' 'SchUseStrongCrypto'
    }
}

Add-TRSection 'Hardening' {
    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $sys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $cg = $null
    try { $dg = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction Stop; $cg = (@($dg.SecurityServicesRunning) -contains 1) } catch { }
    $nb = @()
    try { $nb = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | ForEach-Object { [int]$_.TcpipNetbiosOptions }) } catch { }
    $ps2 = $null
    try {
        if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) { $ps2 = [bool](Get-WindowsFeature -Name PowerShell-V2 -ErrorAction Stop).Installed }
        else { $ps2 = ([string](Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -ErrorAction Stop).State -eq 'Enabled') }
    }
    catch { }
    [ordered]@{
        RunAsPpl                 = Get-TRReg $lsa 'RunAsPPL'
        LmCompatibilityLevel     = Get-TRReg $lsa 'LmCompatibilityLevel'
        NoLmHash                 = Get-TRReg $lsa 'NoLMHash'
        RestrictAnonymous        = Get-TRReg $lsa 'RestrictAnonymous'
        RestrictAnonymousSam     = Get-TRReg $lsa 'RestrictAnonymousSAM'
        EveryoneIncludesAnonymous = Get-TRReg $lsa 'EveryoneIncludesAnonymous'
        WDigestUseLogonCredential = Get-TRReg 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential'
        CredentialGuardRunning   = $cg
        LlmnrDisabled            = ((Get-TRReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast') -eq 0)
        NetbiosOptions           = $nb
        CachedLogonsCount        = Get-TRReg 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'CachedLogonsCount'
        EnableLua                = Get-TRReg $sys 'EnableLUA'
        ConsentPromptBehaviorAdmin = Get-TRReg $sys 'ConsentPromptBehaviorAdmin'
        FilterAdministratorToken = Get-TRReg $sys 'FilterAdministratorToken'
        LocalAccountTokenFilterPolicy = Get-TRReg $sys 'LocalAccountTokenFilterPolicy'
        NoDriveTypeAutoRun       = Get-TRReg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun'
        PowerShellV2Installed    = $ps2
        ScriptBlockLogging       = Get-TRReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging'
        ModuleLogging            = Get-TRReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' 'EnableModuleLogging'
        Transcription            = Get-TRReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' 'EnableTranscripting'
        ProcessCommandLine       = Get-TRReg "$sys\Audit" 'ProcessCreationIncludeCmdLine_Enabled'
        LdapClientSigning        = Get-TRReg 'HKLM:\SYSTEM\CurrentControlSet\Services\LDAP' 'LDAPClientIntegrity'
        SecureBoot               = $(try { [bool](Confirm-SecureBootUEFI -ErrorAction Stop) } catch { $null })
    }
}

Add-TRSection 'AuditPolicy' {
    $csv = @(& auditpol.exe /get /category:* /r 2>$null)
    if ($LASTEXITCODE -ne 0 -or -not $csv.Count) { throw 'auditpol returned no data (needs administrator rights).' }
    $h = [ordered]@{}
    foreach ($row in ($csv | Where-Object { $_ } | ConvertFrom-Csv)) { if ($row.Subcategory) { $h[[string]$row.Subcategory] = [string]$row.'Inclusion Setting' } }
    $h
}

Add-TRSection 'EventLogs' {
    @(foreach ($n in 'Security', 'System', 'Application', 'Microsoft-Windows-PowerShell/Operational', 'Microsoft-Windows-Sysmon/Operational') {
            try {
                $l = Get-WinEvent -ListLog $n -ErrorAction Stop
                [ordered]@{ Name = $n; Enabled = [bool]$l.IsEnabled; MaxSizeKB = [int]($l.MaximumSizeInBytes / 1KB); Mode = [string]$l.LogMode; Records = [long]$l.RecordCount }
            }
            catch { }
        })
}

Add-TRSection 'Events' {
    $since30 = (Get-Date).AddDays(-30)
    $since7 = (Get-Date).AddDays(-7)
    $count = { param($f) try { @(Get-WinEvent -FilterHashtable $f -MaxEvents 5000 -ErrorAction Stop).Count } catch { 0 } }
    [ordered]@{
        UnexpectedShutdowns30d = & $count @{ LogName = 'System'; Id = 6008; StartTime = $since30 }
        DiskErrors30d          = & $count @{ LogName = 'System'; Id = 7, 11, 51, 153, 129; StartTime = $since30 }
        SystemErrors7d         = & $count @{ LogName = 'System'; Level = 1, 2; StartTime = $since7 }
        ApplicationErrors7d    = & $count @{ LogName = 'Application'; Level = 1, 2; StartTime = $since7 }
        AccountLockouts7d      = & $count @{ LogName = 'Security'; Id = 4740; StartTime = $since7 }
        FailedLogons7d         = & $count @{ LogName = 'Security'; Id = 4625; StartTime = $since7 }
        SecurityLogCleared30d  = & $count @{ LogName = 'Security'; Id = 1102; StartTime = $since30 }
    }
}

Add-TRSection 'LocalAccounts' {
    if ([int](Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4) { return [ordered]@{ Skipped = 'Domain controller' } }
    $users = @()
    if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
        $users = @(Get-LocalUser | ForEach-Object { [ordered]@{ Name = [string]$_.Name; Sid = [string]$_.SID; Enabled = [bool]$_.Enabled; PasswordLastSet = ConvertTo-TRIso $_.PasswordLastSet; PasswordExpires = ConvertTo-TRIso $_.PasswordExpires; PasswordRequired = [bool]$_.PasswordRequired; LastLogon = ConvertTo-TRIso $_.LastLogon } })
    }
    else {
        $users = @(Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=True' | ForEach-Object {
                $age = $null
                try { $age = [int]([ADSI]('WinNT://{0}/{1},user' -f $computer, $_.Name)).PasswordAge.Value } catch { }
                [ordered]@{ Name = [string]$_.Name; Sid = [string]$_.SID; Enabled = -not [bool]$_.Disabled; PasswordLastSet = $(if ($null -ne $age) { ConvertTo-TRIso ((Get-Date).AddSeconds(-$age)) } else { $null }); PasswordExpires = $null; PasswordRequired = [bool]$_.PasswordRequired; LastLogon = $null }
            })
    }
    $admins = @()
    try {
        $g = [ADSI]('WinNT://{0}/Administrators,group' -f $computer)
        foreach ($m in @($g.psbase.Invoke('Members'))) {
            $path = [string]$m.GetType().InvokeMember('ADsPath', 'GetProperty', $null, $m, $null)
            $cls = [string]$m.GetType().InvokeMember('Class', 'GetProperty', $null, $m, $null)
            $admins += [ordered]@{ Name = ($path -replace '^WinNT://', '' -replace '/', '\'); Class = $cls }
        }
    }
    catch { }
    $laps = [ordered]@{
        WindowsLapsBackupDirectory = Get-TRReg 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS' 'BackupDirectory'
        WindowsLapsGpoBackupDirectory = Get-TRReg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS' 'BackupDirectory'
        LegacyLapsEnabled = Get-TRReg 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd' 'AdmPwdEnabled'
    }
    [ordered]@{ Users = $users; Administrators = $admins; Laps = $laps }
}

Add-TRSection 'Services' {
    @(Get-CimInstance Win32_Service | ForEach-Object {
            $path = [string]$_.PathName
            $exe = if ($path -match '^"') { '' } elseif ($path -match '^(.+?\.exe)') { $Matches[1] } else { '' }
            [ordered]@{ Name = [string]$_.Name; DisplayName = [string]$_.DisplayName; State = [string]$_.State; StartMode = [string]$_.StartMode; StartName = [string]$_.StartName; UnquotedPath = [bool]($exe -and $exe -match ' ' -and $exe -notmatch '^[A-Za-z]:\\Windows\\') }
        })
}

Add-TRSection 'Software' {
    $keys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    $seen = @{}
    @(foreach ($k in $keys) {
            foreach ($i in @(Get-ItemProperty $k -ErrorAction SilentlyContinue)) {
                $n = [string]$i.DisplayName
                if (-not $n -or $i.SystemComponent -eq 1 -or $n -match '^(Update for|Security Update for|Hotfix for)') { continue }
                $key = $n + '|' + [string]$i.DisplayVersion
                if ($seen[$key]) { continue }
                $seen[$key] = $true
                [ordered]@{ Name = $n; Version = [string]$i.DisplayVersion; Publisher = [string]$i.Publisher; InstallDate = [string]$i.InstallDate }
            }
        })
}

Add-TRSection 'Disks' {
    $bl = @{}
    if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) {
        try { foreach ($v in @(Get-BitLockerVolume -ErrorAction Stop)) { $bl[[string]$v.MountPoint] = $v } } catch { }
    }
    @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object {
            $b = $bl[[string]$_.DeviceID]
            [ordered]@{ Drive = [string]$_.DeviceID; Label = [string]$_.VolumeName; FileSystem = [string]$_.FileSystem; SizeGB = [Math]::Round([double]$_.Size / 1GB, 1); FreeGB = [Math]::Round([double]$_.FreeSpace / 1GB, 1); BitLocker = $(if ($b) { [string]$b.ProtectionStatus } else { $null }); EncryptionMethod = $(if ($b) { [string]$b.EncryptionMethod } else { $null }) }
        })
}

Add-TRSection 'Backup' {
    $out = [ordered]@{ WindowsServerBackup = $null }
    if (Get-Command Get-WBSummary -ErrorAction SilentlyContinue) {
        try {
            $s = Get-WBSummary -ErrorAction Stop
            $out['WindowsServerBackup'] = [ordered]@{ LastSuccess = ConvertTo-TRIso $s.LastSuccessfulBackupTime; LastResult = [string]$s.LastBackupResultHR; NextBackup = ConvertTo-TRIso $s.NextBackupTime; Versions = [int]$s.NumberOfVersions }
        }
        catch { }
    }
    $out
}

Add-TRSection 'TimeSync' {
    $st = @(& w32tm.exe /query /status 2>$null)
    $cfg = @(& w32tm.exe /query /configuration 2>$null)
    $pick = { param($lines, $label) foreach ($l in $lines) { if ($l -match ('^\s*' + [regex]::Escape($label) + '\s*:\s*(.*)$')) { return $Matches[1].Trim() } }; $null }
    [ordered]@{ Source = & $pick $st 'Source'; LastSync = & $pick $st 'Last Successful Sync Time'; Stratum = & $pick $st 'Stratum'; Type = & $pick $cfg 'Type'; NtpServer = & $pick $cfg 'NtpServer' }
}

Add-TRSection 'Certificates' {
    @(Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.HasPrivateKey } | ForEach-Object { [ordered]@{ Subject = [string]$_.Subject; Issuer = [string]$_.Issuer; NotAfter = ConvertTo-TRIso $_.NotAfter; Thumbprint = [string]$_.Thumbprint; SelfSigned = ($_.Subject -eq $_.Issuer) } })
}

Add-TRSection 'WinRM' {
    $l = @()
    try { $l = @(Get-ChildItem WSMan:\localhost\Listener -ErrorAction Stop | ForEach-Object { $keys = @($_.Keys); [ordered]@{ Transport = [string](@($keys | Where-Object { $_ -match '^Transport=' }) -replace '^Transport=', ''); Address = [string](@($keys | Where-Object { $_ -match '^Address=' }) -replace '^Address=', '') } }) } catch { }
    [ordered]@{ Listeners = $l; AllowUnencrypted = $(try { [string](Get-Item WSMan:\localhost\Service\AllowUnencrypted -ErrorAction Stop).Value } catch { $null }); BasicAuth = $(try { [string](Get-Item WSMan:\localhost\Service\Auth\Basic -ErrorAction Stop).Value } catch { $null }) }
}

Add-TRSection 'HyperV' {
    if (-not (Get-Command Get-VM -ErrorAction SilentlyContinue) -or -not (Get-Service -Name vmms -ErrorAction SilentlyContinue)) { return $null }
    $h = Get-VMHost
    $vms = @(foreach ($vm in @(Get-VM)) {
            $snaps = @()
            try { $snaps = @(Get-VMSnapshot -VM $vm -ErrorAction Stop) } catch { }
            $fw = $null; $sec = $null
            if ($vm.Generation -eq 2) {
                try { $fw = Get-VMFirmware -VM $vm -ErrorAction Stop } catch { }
                try { $sec = Get-VMSecurity -VM $vm -ErrorAction Stop } catch { }
            }
            $ic = @()
            try { $ic = @(Get-VMIntegrationService -VM $vm -ErrorAction Stop | Where-Object { $_.Enabled } | ForEach-Object { [string]$_.PrimaryStatusDescription }) } catch { }
            $disks = @()
            try { $disks = @(Get-VMHardDiskDrive -VM $vm -ErrorAction Stop | ForEach-Object { [string]$_.Path }) } catch { }
            [ordered]@{
                Name = [string]$vm.Name; State = [string]$vm.State; Generation = [int]$vm.Generation; Version = [string]$vm.Version; Cpus = [int]$vm.ProcessorCount
                MemoryStartupGB = [Math]::Round([double]$vm.MemoryStartup / 1GB, 1); DynamicMemory = [bool]$vm.DynamicMemoryEnabled; UptimeHours = [int]$vm.Uptime.TotalHours
                IntegrationServicesState = [string]$vm.IntegrationServicesState; IntegrationStatus = ($ic | Select-Object -Unique) -join ', '
                ReplicationState = [string]$vm.ReplicationState; ReplicationHealth = [string]$vm.ReplicationHealth
                AutomaticStartAction = [string]$vm.AutomaticStartAction; AutomaticStopAction = [string]$vm.AutomaticStopAction
                Checkpoints = $snaps.Count; OldestCheckpoint = $(if ($snaps.Count) { ConvertTo-TRIso (($snaps | Sort-Object CreationTime | Select-Object -First 1).CreationTime) } else { $null })
                SecureBoot = $(if ($fw) { [string]$fw.SecureBoot } else { $null }); Tpm = $(if ($sec) { [bool]$sec.TpmEnabled } else { $null })
                Disks = $disks
            }
        })
    $switches = @(Get-VMSwitch | ForEach-Object { [ordered]@{ Name = [string]$_.Name; Type = [string]$_.SwitchType } })
    $cluster = $null
    if (Get-Command Get-Cluster -ErrorAction SilentlyContinue) {
        try {
            $c = Get-Cluster -ErrorAction Stop
            $cluster = [ordered]@{ Name = [string]$c.Name; Nodes = @(Get-ClusterNode | ForEach-Object { [ordered]@{ Name = [string]$_.Name; State = [string]$_.State } }); Csv = @(Get-ClusterSharedVolume -ErrorAction SilentlyContinue | ForEach-Object { $p = $_.SharedVolumeInfo.Partition; [ordered]@{ Name = [string]$_.Name; State = [string]$_.State; FreePercent = [Math]::Round([double]$p.PercentFree, 1) } }) }
        }
        catch { }
    }
    [ordered]@{ Host = [ordered]@{ VirtualMachinePath = [string]$h.VirtualMachinePath; VirtualHardDiskPath = [string]$h.VirtualHardDiskPath; LogicalProcessors = [int]$h.LogicalProcessorCount; NumaSpanning = [bool]$h.NumaSpanningEnabled; LiveMigration = [bool]$h.VirtualMachineMigrationEnabled }; Vms = $vms; Switches = $switches; Cluster = $cluster }
}

Add-TRSection 'ActiveDirectory' {
    if ([int](Get-CimInstance Win32_ComputerSystem).DomainRole -lt 4) { return $null }
    if (-not (Get-Module -ListAvailable ActiveDirectory)) { throw 'The ActiveDirectory PowerShell module is not available on this domain controller.' }
    Import-Module ActiveDirectory -ErrorAction Stop
    $dom = Get-ADDomain
    $for = Get-ADForest
    $root = Get-ADRootDSE
    $now = Get-Date
    $stale = $now.AddDays(-90)
    $sid = [string]$dom.DomainSID
    $ll = { param($v) if ($v) { [datetime]::FromFileTimeUtc([long]$v) } else { $null } }
    $groups = [ordered]@{}
    foreach ($g in @(@{ N = 'Domain Admins'; S = "$sid-512" }, @{ N = 'Enterprise Admins'; S = "$sid-519" }, @{ N = 'Schema Admins'; S = "$sid-518" }, @{ N = 'Administrators'; S = 'S-1-5-32-544' }, @{ N = 'Account Operators'; S = 'S-1-5-32-548' }, @{ N = 'Server Operators'; S = 'S-1-5-32-549' }, @{ N = 'Print Operators'; S = 'S-1-5-32-550' }, @{ N = 'Backup Operators'; S = 'S-1-5-32-551' }, @{ N = 'Protected Users'; S = "$sid-525" }, @{ N = 'Pre-Windows 2000 Compatible Access'; S = 'S-1-5-32-554' })) {
        try {
            $direct = @(Get-ADGroupMember -Identity $g.S -ErrorAction Stop | ForEach-Object { [string]$_.SamAccountName })
            $members = @()
            if ($g.N -ne 'Pre-Windows 2000 Compatible Access') { $members = @(Get-ADGroupMember -Identity $g.S -Recursive -ErrorAction Stop | ForEach-Object { [ordered]@{ Name = [string]$_.SamAccountName; Class = [string]$_.objectClass } }) }
            $groups[$g.N] = [ordered]@{ Direct = $direct; Members = $members }
        }
        catch { $groups[$g.N] = [ordered]@{ Error = $_.Exception.Message } }
    }
    $users = @(Get-ADUser -Filter * -ResultSetSize $MaxAdObjects -Properties Enabled, lastLogonTimestamp, PasswordLastSet, PasswordNeverExpires, PasswordNotRequired, DoesNotRequirePreAuth, AllowReversiblePasswordEncryption, ServicePrincipalName, AdminCount, TrustedForDelegation, Description, WhenCreated)
    $enabled = @($users | Where-Object { $_.Enabled })
    $flag = { param($u) [ordered]@{ Name = [string]$u.SamAccountName; LastLogon = ConvertTo-TRIso (& $ll $u.lastLogonTimestamp); PasswordLastSet = ConvertTo-TRIso $u.PasswordLastSet; Admin = ([int]$u.AdminCount -eq 1) } }
    $staleUsers = @($enabled | Where-Object { $t = & $ll $_.lastLogonTimestamp; ($t -and $t -lt $stale.ToUniversalTime()) -or (-not $t -and $_.WhenCreated -lt $stale) })
    $computers = @(Get-ADComputer -Filter * -ResultSetSize $MaxAdObjects -Properties Enabled, OperatingSystem, OperatingSystemVersion, lastLogonTimestamp, TrustedForDelegation, PrimaryGroupID, 'ms-Mcs-AdmPwdExpirationTime', 'msLAPS-PasswordExpirationTime')
    $enabledC = @($computers | Where-Object { $_.Enabled })
    $pp = Get-ADDefaultDomainPasswordPolicy
    $recycle = $false
    try { $recycle = [bool](@((Get-ADOptionalFeature -Filter "name -eq 'Recycle Bin Feature'").EnabledScopes).Count) } catch { }
    $tomb = $null
    try { $tomb = (Get-ADObject ('CN=Directory Service,CN=Windows NT,CN=Services,' + $root.configurationNamingContext) -Properties tombstoneLifetime).tombstoneLifetime } catch { }
    $maq = $null
    try { $maq = (Get-ADObject $dom.DistinguishedName -Properties 'ms-DS-MachineAccountQuota').'ms-DS-MachineAccountQuota' } catch { }
    $lapsSchema = $false
    try { $lapsSchema = [bool](Get-ADObject -SearchBase $root.schemaNamingContext -Filter "lDAPDisplayName -eq 'msLAPS-Password' -or lDAPDisplayName -eq 'ms-Mcs-AdmPwd'") } catch { }
    $repl = @()
    try {
        $csv = @(& repadmin.exe /showrepl * /csv 2>$null)
        $repl = @($csv | Where-Object { $_ -match '^(showrepl_COLUMNS|showrepl_INFO)' } | ForEach-Object { $_ } | ConvertFrom-Csv | ForEach-Object { [ordered]@{ Destination = [string]$_.'Destination DSA'; Source = [string]$_.'Source DSA'; NamingContext = [string]$_.'Naming Context'; Failures = [int]$_.'Number of Failures'; LastFailure = [string]$_.'Last Failure Time'; LastSuccess = [string]$_.'Last Success Time'; LastStatus = [string]$_.'Last Failure Status' } })
    }
    catch { }
    $sysvol = $null
    try { $sysvol = ((& dfsrmig.exe /getglobalstate 2>$null) -join ' ').Trim() } catch { }
    $trusts = @()
    try { $trusts = @(Get-ADTrust -Filter * | ForEach-Object { [ordered]@{ Name = [string]$_.Name; Direction = [string]$_.Direction; Type = [string]$_.TrustType; SidFiltering = [bool]$_.SIDFilteringQuarantined; SelectiveAuth = [bool]$_.SelectiveAuthentication } }) } catch { }
    $gpoCount = $null
    try { if (Get-Module -ListAvailable GroupPolicy) { Import-Module GroupPolicy; $gpoCount = @(Get-GPO -All).Count } } catch { }
    [ordered]@{
        Domain            = [string]$dom.DNSRoot
        NetBios           = [string]$dom.NetBIOSName
        Forest            = [string]$for.Name
        DomainMode        = [string]$dom.DomainMode
        ForestMode        = [string]$for.ForestMode
        PdcEmulator       = [string]$dom.PDCEmulator
        RidMaster         = [string]$dom.RIDMaster
        InfrastructureMaster = [string]$dom.InfrastructureMaster
        SchemaMaster      = [string]$for.SchemaMaster
        DomainNamingMaster = [string]$for.DomainNamingMaster
        DomainControllers = @(Get-ADDomainController -Filter * | ForEach-Object { [ordered]@{ Name = [string]$_.HostName; OperatingSystem = [string]$_.OperatingSystem; Version = [string]$_.OperatingSystemVersion; GlobalCatalog = [bool]$_.IsGlobalCatalog; ReadOnly = [bool]$_.IsReadOnly; Site = [string]$_.Site } })
        RecycleBin        = $recycle
        TombstoneLifetime = $tomb
        KrbtgtPasswordLastSet = ConvertTo-TRIso (Get-ADUser krbtgt -Properties PasswordLastSet).PasswordLastSet
        MachineAccountQuota = $maq
        LapsSchema        = $lapsSchema
        PasswordPolicy    = [ordered]@{ MinLength = [int]$pp.MinPasswordLength; Complexity = [bool]$pp.ComplexityEnabled; LockoutThreshold = [int]$pp.LockoutThreshold; LockoutMinutes = [int]$pp.LockoutDuration.TotalMinutes; MaxAgeDays = [int]$pp.MaxPasswordAge.TotalDays; History = [int]$pp.PasswordHistoryCount; Reversible = [bool]$pp.ReversibleEncryptionEnabled }
        FineGrainedPolicies = @(Get-ADFineGrainedPasswordPolicy -Filter * -ErrorAction SilentlyContinue).Count
        Groups            = $groups
        Users             = [ordered]@{
            Total = $users.Count; Enabled = $enabled.Count
            Stale = @($staleUsers | Select-Object -First 500 | ForEach-Object { & $flag $_ }); StaleCount = $staleUsers.Count
            PasswordNeverExpires = @($enabled | Where-Object { $_.PasswordNeverExpires } | Select-Object -First 500 | ForEach-Object { & $flag $_ })
            PasswordNotRequired = @($enabled | Where-Object { $_.PasswordNotRequired } | ForEach-Object { & $flag $_ })
            PreAuthDisabled = @($enabled | Where-Object { $_.DoesNotRequirePreAuth } | ForEach-Object { & $flag $_ })
            ReversibleEncryption = @($enabled | Where-Object { $_.AllowReversiblePasswordEncryption } | ForEach-Object { & $flag $_ })
            Kerberoastable = @($enabled | Where-Object { @($_.ServicePrincipalName).Count -and $_.SamAccountName -ne 'krbtgt' } | ForEach-Object { & $flag $_ })
            UnconstrainedDelegation = @($enabled | Where-Object { $_.TrustedForDelegation } | ForEach-Object { & $flag $_ })
            DescriptionMentionsPassword = @($enabled | Where-Object { [string]$_.Description -match 'pass|pwd|kennwort' } | ForEach-Object { [string]$_.SamAccountName })
        }
        Computers         = [ordered]@{
            Total = $computers.Count; Enabled = $enabledC.Count
            ByOs = @($enabledC | Group-Object OperatingSystem | ForEach-Object { [ordered]@{ Os = [string]$_.Name; Count = $_.Count } })
            Stale = @($enabledC | Where-Object { $t = & $ll $_.lastLogonTimestamp; $t -and $t -lt $stale.ToUniversalTime() } | Select-Object -First 500 | ForEach-Object { [ordered]@{ Name = [string]$_.Name; Os = [string]$_.OperatingSystem; LastLogon = ConvertTo-TRIso (& $ll $_.lastLogonTimestamp) } })
            UnconstrainedDelegation = @($enabledC | Where-Object { $_.TrustedForDelegation -and [int]$_.PrimaryGroupID -ne 516 } | ForEach-Object { [string]$_.Name })
            WithLaps = @($enabledC | Where-Object { $_.'ms-Mcs-AdmPwdExpirationTime' -or $_.'msLAPS-PasswordExpirationTime' }).Count
            OldOs = @($enabledC | Where-Object { [string]$_.OperatingSystem -match 'Windows (XP|Vista|7|8|8\.1) |Server 200[38]|Server 2012' } | ForEach-Object { [ordered]@{ Name = [string]$_.Name; Os = [string]$_.OperatingSystem } })
        }
        Replication       = $repl
        SysvolState       = $sysvol
        Trusts            = $trusts
        GpoCount          = $gpoCount
        LdapServerSigning = Get-TRReg 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' 'LDAPServerIntegrity'
        LdapChannelBinding = Get-TRReg 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' 'LdapEnforceChannelBinding'
    }
}

$result['DurationSeconds'] = [int]((Get-Date) - $started).TotalSeconds
$json = $result | ConvertTo-Json -Depth 8 -Compress
if ($AsJson) { return $json }
if (-not (Test-Path -LiteralPath $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$file = Join-Path $OutputPath ('{0}-{1}.server-review.json' -f $computer, (Get-Date).ToString('yyyyMMdd-HHmm'))
[IO.File]::WriteAllText($file, $json, (New-Object Text.UTF8Encoding($false)))
Write-Output ('Server data written to {0} ({1} KB, {2} seconds, {3} sections with errors).' -f $file, [int]((Get-Item $file).Length / 1KB), $result['DurationSeconds'], @($result['Errors']).Count)
