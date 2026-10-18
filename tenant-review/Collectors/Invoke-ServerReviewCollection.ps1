param(
    [string[]]$ComputerName,
    [switch]$FromActiveDirectory,
    [pscredential]$Credential,
    [string]$OutputPath = (Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'Server Review Data'),
    [switch]$SkipUpdateSearch,
    [int]$ThrottleLimit = 8,
    [switch]$UseSSL
)

$ErrorActionPreference = 'Stop'
$collector = Join-Path $PSScriptRoot 'Get-ServerReviewData.ps1'
if (-not (Test-Path -LiteralPath $collector)) { throw "Get-ServerReviewData.ps1 was not found next to this script." }
if ($FromActiveDirectory) {
    Import-Module ActiveDirectory -ErrorAction Stop
    $found = @(Get-ADComputer -Filter "OperatingSystem -like '*Server*' -and Enabled -eq 'True'" -Properties OperatingSystem, lastLogonTimestamp | Where-Object { $_.lastLogonTimestamp -and [datetime]::FromFileTime($_.lastLogonTimestamp) -gt (Get-Date).AddDays(-30) } | ForEach-Object { if ($_.DNSHostName) { $_.DNSHostName } else { $_.Name } })
    $ComputerName = @(@($ComputerName) + $found | Where-Object { $_ } | Select-Object -Unique)
    Write-Output ('Found {0} servers in Active Directory that signed in during the last 30 days.' -f $found.Count)
}
if (-not $ComputerName -or -not @($ComputerName).Count) { throw 'Give one or more server names with -ComputerName, or use -FromActiveDirectory.' }
if (-not (Test-Path -LiteralPath $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$code = Get-Content -LiteralPath $collector -Raw
$p = @{
    ComputerName  = $ComputerName
    ScriptBlock   = { param($Code, $Skip) $sb = [scriptblock]::Create($Code); & $sb -AsJson -SkipUpdateSearch:$Skip }
    ArgumentList  = @($code, [bool]$SkipUpdateSearch)
    ThrottleLimit = $ThrottleLimit
    ErrorAction   = 'SilentlyContinue'
    ErrorVariable = 'remoteErrors'
}
if ($Credential) { $p['Credential'] = $Credential }
if ($UseSSL) { $p['UseSSL'] = $true }
Write-Output ('Collecting from {0} over WinRM. This takes one to five minutes per server, {1} at a time.' -f (@($ComputerName).Count), $ThrottleLimit)
$stamp = (Get-Date).ToString('yyyyMMdd-HHmm')
$ok = @()
foreach ($r in @(Invoke-Command @p)) {
    $name = [string]$r.PSComputerName
    $file = Join-Path $OutputPath ('{0}-{1}.server-review.json' -f ($name -replace '[^A-Za-z0-9._-]', '_'), $stamp)
    [IO.File]::WriteAllText($file, [string]$r, (New-Object Text.UTF8Encoding($false)))
    $ok += $name
    Write-Output ('  {0}: saved {1}' -f $name, (Split-Path -Leaf $file))
}
foreach ($e in @($remoteErrors)) { Write-Output ('  {0}: FAILED {1}' -f $e.TargetObject, $e.Exception.Message) }
Write-Output ('Done. {0} of {1} servers collected. Point the review tool''s Server data folder at {2}.' -f $ok.Count, @($ComputerName).Count, $OutputPath)
