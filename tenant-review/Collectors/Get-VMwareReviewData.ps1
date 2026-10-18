param(
    [Parameter(Mandatory = $true)][string]$Server,
    [pscredential]$Credential,
    [string]$OutputPath = (Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'Server Review Data'),
    [switch]$AsJson
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
if (-not (Get-Module -ListAvailable VMware.VimAutomation.Core)) { throw 'VMware PowerCLI is not installed. Run: Install-Module VMware.PowerCLI -Scope CurrentUser' }
Import-Module VMware.VimAutomation.Core -ErrorAction Stop
Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -ParticipateInCeip $false -Scope Session -Confirm:$false | Out-Null
$p = @{ Server = $Server }
if ($Credential) { $p['Credential'] = $Credential }
$vi = Connect-VIServer @p
$started = Get-Date
$result = [ordered]@{
    SchemaVersion    = 1
    Collector        = 'vmware'
    CollectorVersion = '1.0.0'
    CollectedUtc     = $started.ToUniversalTime().ToString('o')
    ComputerName     = $Server
    Errors           = @()
}

function ConvertTo-TRIso {
    param($Date)
    if ($null -eq $Date) { return $null }
    try { ([datetime]$Date).ToUniversalTime().ToString('o') } catch { $null }
}

function Add-TRSection {
    param([string]$Name, [scriptblock]$Script)
    try { $result[$Name] = & $Script }
    catch { $result['Errors'] += ('{0}: {1}' -f $Name, $_.Exception.Message); $result[$Name] = $null }
}

try {
    Add-TRSection 'About' {
        $a = $vi.ExtensionData.Content.About
        [ordered]@{ FullName = [string]$a.FullName; Version = [string]$a.Version; Build = [string]$a.Build; ProductLine = [string]$a.ProductLineId; ApiVersion = [string]$a.ApiVersion }
    }
    Add-TRSection 'Hosts' {
        @(foreach ($h in @(Get-VMHost)) {
                $svc = @{}
                foreach ($s in @(Get-VMHostService -VMHost $h -ErrorAction SilentlyContinue)) { $svc[[string]$s.Key] = [ordered]@{ Running = [bool]$s.Running; Policy = [string]$s.Policy } }
                $adv = @{}
                foreach ($n in 'Syslog.global.logHost', 'UserVars.ESXiShellInteractiveTimeOut', 'UserVars.ESXiShellTimeOut', 'Security.AccountLockFailures', 'Security.PasswordQualityControl', 'UserVars.SuppressShellWarning', 'Config.HostAgent.plugins.solo.enableMob') {
                    try { $adv[$n] = [string](Get-AdvancedSetting -Entity $h -Name $n -ErrorAction Stop).Value } catch { }
                }
                $boot = $h.ExtensionData.Runtime.BootTime
                [ordered]@{
                    Name = [string]$h.Name; ConnectionState = [string]$h.ConnectionState; PowerState = [string]$h.PowerState; Version = [string]$h.Version; Build = [string]$h.Build
                    Manufacturer = [string]$h.Manufacturer; Model = [string]$h.Model; Cpus = [int]$h.NumCpu; MemoryGB = [Math]::Round([double]$h.MemoryTotalGB, 0)
                    Cluster = [string]$h.Parent; LockdownMode = [string]$h.ExtensionData.Config.LockdownMode; BootTime = ConvertTo-TRIso $boot
                    Ssh = $svc['TSM-SSH']; Shell = $svc['TSM']; Ntp = $svc['ntpd']; NtpServers = @(Get-VMHostNtpServer -VMHost $h -ErrorAction SilentlyContinue | ForEach-Object { [string]$_ })
                    Advanced = $adv
                }
            })
    }
    Add-TRSection 'Vms' {
        @(foreach ($v in @(Get-VM)) {
                $snaps = @(Get-Snapshot -VM $v -ErrorAction SilentlyContinue)
                $cd = @(Get-CDDrive -VM $v -ErrorAction SilentlyContinue | Where-Object { $_.ConnectionState.Connected -and $_.IsoPath })
                [ordered]@{
                    Name = [string]$v.Name; PowerState = [string]$v.PowerState; Host = [string]$v.VMHost; GuestOs = [string]$v.ExtensionData.Guest.GuestFullName; ConfiguredOs = [string]$v.ExtensionData.Config.GuestFullName
                    HardwareVersion = [string]$v.HardwareVersion; ToolsStatus = [string]$v.ExtensionData.Guest.ToolsVersionStatus2; ToolsRunning = [string]$v.ExtensionData.Guest.ToolsRunningStatus
                    Cpus = [int]$v.NumCpu; MemoryGB = [double]$v.MemoryGB; ProvisionedGB = [Math]::Round([double]$v.ProvisionedSpaceGB, 0)
                    Snapshots = $snaps.Count; OldestSnapshot = $(if ($snaps.Count) { ConvertTo-TRIso (($snaps | Sort-Object Created | Select-Object -First 1).Created) } else { $null }); SnapshotGB = [Math]::Round([double](($snaps | Measure-Object -Property SizeGB -Sum).Sum), 1)
                    IsoConnected = [bool]$cd.Count
                }
            })
    }
    Add-TRSection 'Datastores' { @(Get-Datastore | ForEach-Object { [ordered]@{ Name = [string]$_.Name; Type = [string]$_.Type; CapacityGB = [Math]::Round([double]$_.CapacityGB, 0); FreeGB = [Math]::Round([double]$_.FreeSpaceGB, 0) } }) }
    Add-TRSection 'Clusters' { @(Get-Cluster -ErrorAction SilentlyContinue | ForEach-Object { [ordered]@{ Name = [string]$_.Name; HaEnabled = [bool]$_.HAEnabled; HaAdmissionControl = [bool]$_.HAAdmissionControlEnabled; DrsEnabled = [bool]$_.DrsEnabled; DrsLevel = [string]$_.DrsAutomationLevel } }) }
}
finally {
    Disconnect-VIServer -Server $vi -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
}
$result['DurationSeconds'] = [int]((Get-Date) - $started).TotalSeconds
$json = $result | ConvertTo-Json -Depth 8 -Compress
if ($AsJson) { return $json }
if (-not (Test-Path -LiteralPath $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$file = Join-Path $OutputPath ('vmware-{0}-{1}.server-review.json' -f ($Server -replace '[^A-Za-z0-9._-]', '_'), (Get-Date).ToString('yyyyMMdd-HHmm'))
[IO.File]::WriteAllText($file, $json, (New-Object Text.UTF8Encoding($false)))
Write-Output ('VMware data written to {0}.' -f $file)
