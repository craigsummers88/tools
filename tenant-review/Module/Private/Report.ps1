function ConvertTo-TRHtml {
    param($Value)
    if ($null -eq $Value) { return '' }
    [Net.WebUtility]::HtmlEncode([string]$Value)
}

$script:TRJsonControl = [regex]('[' + [char]0 + '-' + [char]31 + [char]0x2028 + [char]0x2029 + ']')
$script:TRJsonEvaluator = [System.Text.RegularExpressions.MatchEvaluator] { param($m) '\u{0:x4}' -f [int][char]$m.Value }

function ConvertTo-TRJsonString {
    param($Value)
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [bool]) { if ($Value) { return 'true' } else { return 'false' } }
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [double] -or $Value -is [decimal]) {
        return ([string]::Format([Globalization.CultureInfo]::InvariantCulture, '{0}', $Value))
    }
    $s = ([string]$Value).Replace('\', '\\').Replace('"', '\"').Replace('<', '\u003c').Replace('>', '\u003e').Replace('&', '\u0026')
    if ($script:TRJsonControl.IsMatch($s)) { $s = $script:TRJsonControl.Replace($s, $script:TRJsonEvaluator) }
    '"' + $s + '"'
}

function ConvertTo-TRJsonArray {
    param($Values)
    $parts = foreach ($v in @($Values)) { ConvertTo-TRJsonString $v }
    '[' + ((@($parts)) -join ',') + ']'
}

function Resolve-TRAssetPath {
    param([string]$Path, [string]$Default)
    $p = if ($Path) { [Environment]::ExpandEnvironmentVariables($Path) } else { $Default }
    if (-not $p) { return $null }
    if (-not [IO.Path]::IsPathRooted($p) -and $script:TRRoot) { $p = Join-Path $script:TRRoot $p }
    if (Test-Path -LiteralPath $p -PathType Leaf) { return (Resolve-Path -LiteralPath $p).Path }
    $null
}

function Get-TRLogoDataUri {
    $default = if ($script:TRRoot) { Join-Path (Join-Path $script:TRRoot 'Assets') 'logo.svg' } else { $null }
    $path = Resolve-TRAssetPath -Path ([string](Get-TRSetting 'LogoPath' '')) -Default $default
    if (-not $path) { return $null }
    $mime = switch ([IO.Path]::GetExtension($path).ToLower()) {
        '.svg' { 'image/svg+xml' }
        '.png' { 'image/png' }
        '.jpg' { 'image/jpeg' }
        '.jpeg' { 'image/jpeg' }
        default { $null }
    }
    if (-not $mime) { return $null }
    try { 'data:{0};base64,{1}' -f $mime, [Convert]::ToBase64String([IO.File]::ReadAllBytes($path)) }
    catch { $null }
}

function Get-TRIconDataUri {
    if (-not $script:TRRoot) { return $null }
    $path = Join-Path (Join-Path $script:TRRoot 'Assets') 'app-icon.svg'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $null }
    try { 'data:image/svg+xml;base64,' + [Convert]::ToBase64String([IO.File]::ReadAllBytes($path)) }
    catch { $null }
}

function Find-TRPdfBrowser {
    $configured = [string](Get-TRSetting 'PdfBrowserPath' '')
    if ($configured) {
        $p = [Environment]::ExpandEnvironmentVariables($configured)
        if (Test-Path -LiteralPath $p -PathType Leaf) { return $p }
    }
    $candidates = @()
    foreach ($base in @(${env:ProgramFiles(x86)}, $env:ProgramFiles, $env:LOCALAPPDATA)) {
        if (-not $base) { continue }
        $candidates += Join-Path $base 'Microsoft\Edge\Application\msedge.exe'
    }
    foreach ($base in @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:LOCALAPPDATA)) {
        if (-not $base) { continue }
        $candidates += Join-Path $base 'Google\Chrome\Application\chrome.exe'
    }
    foreach ($c in $candidates) { if (Test-Path -LiteralPath $c -PathType Leaf) { return $c } }
    foreach ($n in 'msedge', 'microsoft-edge', 'google-chrome', 'chromium', 'chromium-browser') {
        $cmd = Get-Command -Name $n -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($cmd) { return $cmd.Source }
    }
    $null
}

function Export-TRPdf {
    param([Parameter(Mandatory = $true)][string]$HtmlPath, [Parameter(Mandatory = $true)][string]$PdfPath, [int]$TimeoutSeconds = 180)
    $browser = Find-TRPdfBrowser
    if (-not $browser) {
        Write-TRLog 'PDF not created: Microsoft Edge or Google Chrome was not found. Open the HTML report and use Save as PDF instead.' 'Warn'
        return $null
    }
    $profileDir = Join-Path ([IO.Path]::GetTempPath()) ('tr-pdf-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
    if (Test-Path -LiteralPath $PdfPath) { Remove-Item -LiteralPath $PdfPath -Force -ErrorAction SilentlyContinue }
    $url = (New-Object System.Uri((Resolve-Path -LiteralPath $HtmlPath).Path)).AbsoluteUri
    $argList = @('--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check', '--disable-extensions', '--hide-scrollbars',
        ('--user-data-dir="{0}"' -f $profileDir), '--no-pdf-header-footer', '--print-to-pdf-no-header', ('--print-to-pdf="{0}"' -f $PdfPath), ('"{0}"' -f $url))
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { $argList = @('--no-sandbox') + $argList }
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $browser
    $psi.Arguments = ($argList -join ' ')
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardError = $true
    $psi.RedirectStandardOutput = $true
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try {
        $proc = [System.Diagnostics.Process]::Start($psi)
        $errTask = $proc.StandardError.ReadToEndAsync()
        $outTask = $proc.StandardOutput.ReadToEndAsync()
        if (-not $proc.WaitForExit($TimeoutSeconds * 1000)) {
            try { $proc.Kill() } catch { }
            Write-TRLog ('PDF not created: the browser did not finish within {0} seconds.' -f $TimeoutSeconds) 'Warn'
            return $null
        }
        [void]$errTask.Wait(5000)
        [void]$outTask.Wait(5000)
    }
    catch {
        Write-TRLog ('PDF not created: ' + $_.Exception.Message) 'Warn'
        return $null
    }
    finally {
        Start-Sleep -Milliseconds 300
        Remove-Item -LiteralPath $profileDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    if ((Test-Path -LiteralPath $PdfPath) -and (Get-Item -LiteralPath $PdfPath).Length -gt 0) {
        Write-TRLog ('PDF written to {0} ({1:N1} s)' -f $PdfPath, $sw.Elapsed.TotalSeconds) 'Success'
        return $PdfPath
    }
    Write-TRLog 'PDF not created: the browser did not produce a file. Open the HTML report and use Save as PDF instead.' 'Warn'
    $null
}

function Get-TRScore {
    param($Findings)
    $w = @{ High = 3; Medium = 2; Low = 1; Info = 0 }
    $num = 0.0; $den = 0.0
    foreach ($f in @($Findings)) {
        if ($f.Status -notin @('Pass', 'Warning', 'Fail')) { continue }
        $weight = $w[[string]$f.Severity]
        if (-not $weight) { continue }
        $den += $weight
        if ($f.Status -eq 'Pass') { $num += $weight } elseif ($f.Status -eq 'Warning') { $num += 0.5 * $weight }
    }
    if ($den -eq 0) { return $null }
    [int][Math]::Round(100 * $num / $den)
}

function Get-TRWorkload {
    param($Finding)
    switch ([string]$Finding.Area) { 'Azure' { 'Azure' } 'Servers' { 'Servers' } default { 'Tenant' } }
}

function New-TRAzureHtml {
    param($Findings, [int]$Number, [string]$Client)
    $sb = New-Object System.Text.StringBuilder
    $subs = @(Get-TRItems 'AzSubscriptions')
    $vms = @(Get-TRAzVms)
    $arc = @(Get-TRItems 'AzArcMachines')
    $az = @($Findings)
    $score = Get-TRScore $az
    [void]$sb.Append(('<section id="tab-azure" class="tab"><h2>{0}. Azure</h2>' -f $Number))
    $denied = @(Get-TRItems 'AzAccess' | Select-Object -ExpandProperty subscription -Unique)
    $note = 'Azure was read through Azure Resource Manager, Azure Resource Graph, Defender for Cloud and Azure Advisor with the review account''s own Azure roles. Only subscriptions where that account has a role are visible, so confirm with {0} that nothing is missing.' -f $Client
    if ($denied.Count) { $note += (' Some settings could not be read in {0}; the related checks say so.' -f (Join-TRList $denied 3)) }
    [void]$sb.Append(('<p class="note">{0}</p>' -f (ConvertTo-TRHtml $note)))
    $sc = @(Get-TRItems 'AzSecureScores')
    $avg = if ($sc.Count) { [Math]::Round(100 * ($sc | Measure-Object -Property percentage -Average).Average) } else { $null }
    $reg = @(Get-TRItems 'AzRegulatory' | Where-Object { [string]$_.standard -match 'Microsoft-cloud-security-benchmark' })
    $rp = ($reg | Measure-Object -Property passed -Sum).Sum
    $rf = ($reg | Measure-Object -Property failed -Sum).Sum
    $cost = @(Get-TRItems 'AzAdvisor' | Where-Object { [string]$_.category -eq 'Cost' })
    $save = ($cost | Measure-Object -Property annualSavings -Sum).Sum
    $cur = @($cost | Where-Object { $_.currency } | Select-Object -ExpandProperty currency -Unique)[0]
    $tiles = @(
        @{ V = $(if ($null -ne $score) { '{0}%' -f $score } else { 'n/a' }); L = 'Azure score'; N = ('{0} fail, {1} warning, {2} pass' -f @($az | Where-Object { $_.Status -eq 'Fail' }).Count, @($az | Where-Object { $_.Status -eq 'Warning' }).Count, @($az | Where-Object { $_.Status -eq 'Pass' }).Count) },
        @{ V = [string]$subs.Count; L = 'Subscriptions'; N = (@($subs | Group-Object offer | ForEach-Object { '{0} {1}' -f $_.Count, $_.Name }) -join ', ') },
        @{ V = [string]$vms.Count; L = 'Virtual machines'; N = ('{0} running; {1} Arc servers' -f @($vms | Where-Object { $_.Running }).Count, $arc.Count) },
        @{ V = $(if ($null -ne $avg) { '{0}%' -f $avg } else { 'n/a' }); L = 'Secure score'; N = 'Defender for Cloud, average' },
        @{ V = $(if ($rp + $rf) { '{0}%' -f (Get-TRPercent $rp ($rp + $rf)) } else { 'n/a' }); L = 'MCSB controls passed'; N = ('{0} passed, {1} failed' -f $rp, $rf) }
    )
    $symbols = @{ GBP = [string][char]0xA3; EUR = [string][char]0x20AC; USD = '$' }
    $money = if ($symbols.ContainsKey([string]$cur)) { $symbols[[string]$cur] + ([double]$save).ToString('N0', [Globalization.CultureInfo]::InvariantCulture) } else { '{0} {1}' -f $cur, ([double]$save).ToString('N0', [Globalization.CultureInfo]::InvariantCulture) }
    if ($save -gt 0) { $tiles += @{ V = $money; L = 'Possible savings'; N = 'A year, from Azure Advisor' } }
    [void]$sb.Append('<div class="opp-sum">')
    foreach ($t in $tiles) { [void]$sb.Append(('<div class="tile"><div class="v">{0}</div><div class="l">{1}</div><div class="n">{2}</div></div>' -f (ConvertTo-TRHtml $t.V), (ConvertTo-TRHtml $t.L), (ConvertTo-TRHtml $t.N))) }
    [void]$sb.Append('</div>')
    if ($subs.Count) {
        $counts = @{}
        foreach ($r in (Get-TRItems 'AzResourceCounts')) { $counts[[string]$r.subscriptionId] += [int]$r.count }
        $scIdx = @{}
        foreach ($x in $sc) { $scIdx[[string]$x.subscriptionId] = $x }
        [void]$sb.Append('<h3>Subscriptions</h3><div class="table-wrap static"><table><thead><tr><th>Subscription</th><th>Offer</th><th>State</th><th class="num">Resources</th><th class="num">Secure score</th></tr></thead><tbody>')
        foreach ($x in ($subs | Sort-Object displayName)) {
            $ss = $scIdx[[string]$x.subscriptionId]
            [void]$sb.Append(('<tr><td>{0}</td><td>{1}</td><td>{2}</td><td class="num">{3}</td><td class="num">{4}</td></tr>' -f (ConvertTo-TRHtml $x.displayName), (ConvertTo-TRHtml $x.offer), (ConvertTo-TRHtml $x.state), [int]$counts[[string]$x.subscriptionId], $(if ($ss) { '{0}%' -f [Math]::Round(100 * [double]$ss.percentage) } else { '' })))
        }
        [void]$sb.Append('</tbody></table></div>')
    }
    $order = @{ Fail = 0; Warning = 1; Manual = 2; NotAssessed = 3; Info = 4; Pass = 5 }
    $sev = @{ High = 0; Medium = 1; Low = 2; Info = 3 }
    $shown = @($az | Sort-Object @{ e = { $order[[string]$_.Status] } }, @{ e = { $sev[[string]$_.Severity] } }, Id)
    if ($shown.Count) {
        [void]$sb.Append('<h3>Azure findings</h3><div class="table-wrap static"><table><thead><tr><th>Status</th><th>Check</th><th>Current state</th></tr></thead><tbody>')
        foreach ($f in $shown) {
            [void]$sb.Append(('<tr><td><span class="chip s-{0}">{1}</span></td><td><a href="#" data-goto="f-{2}">{3}</a> <span class="f-id">{2}</span></td><td>{4}</td></tr>' -f $f.Status, (Get-TRStatusLabel $f.Status), (ConvertTo-TRHtml $f.Id), (ConvertTo-TRHtml $f.Title), (ConvertTo-TRHtml $f.Current)))
        }
        [void]$sb.Append('</tbody></table></div>')
    }
    if ($vms.Count) {
        [void]$sb.Append('<h3>Virtual machines</h3><div class="table-wrap static"><table><thead><tr><th>VM</th><th>Operating system</th><th>Power</th><th>Backed up</th><th>Defender for Endpoint</th><th>Public IP</th></tr></thead><tbody>')
        foreach ($v in ($vms | Sort-Object Name)) {
            $os = $v.Os
            if ($v.Support -and $v.Support.State -in @('Ended', 'Esu')) { $os += ' (out of support)' } elseif ($v.Support -and $v.Support.State -eq 'Ending') { $os += (' (support ends {0})' -f (Format-TRDate $v.Support.End)) }
            [void]$sb.Append(('<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td></tr>' -f (ConvertTo-TRHtml $v.Name), (ConvertTo-TRHtml $os), (ConvertTo-TRHtml $v.PowerState), $(if ($v.Backup) { 'Yes' } else { 'No' }), $(if ($v.Mde) { 'Yes' } else { 'No' }), $(if ($v.PublicIp) { 'Yes' } else { 'No' })))
        }
        [void]$sb.Append('</tbody></table></div>')
    }
    [void]$sb.Append('<p class="note">The full Azure detail is in the Inventory tab: subscriptions, virtual machines, inbound internet rules, storage accounts, role assignments, Defender for Cloud recommendations, Azure Advisor and resources by type.</p></section>')
    $sb.ToString()
}

function Get-TRRag {
    param([string]$Status)
    switch ($Status) {
        'Fail' { 'Red' }
        'Warning' { 'Amber' }
        'Pass' { 'Green' }
        default { '' }
    }
}

function Get-TRStatusLabel {
    param([string]$Status)
    switch ($Status) {
        'NotAssessed' { 'Not assessed' }
        'Manual' { 'Manual check' }
        default { $Status }
    }
}

function Get-TRSummaryStats {
    if ((Get-TRPlatform) -eq 'Google') { return (Get-TRGwsSummaryStats) }
    $people = @(Get-TRPeople)
    $reg = Get-TRRegIndex
    $mfa = @($people | Where-Object { $r = $reg[[string]$_.id]; $r -and $r.isMfaCapable -eq $true }).Count
    $ga = @(Get-TRRoleRows | Where-Object { $_.RoleTemplate -eq '62e90394-69f5-4237-9190-012177145e10' } | Select-Object -ExpandProperty PrincipalId -Unique).Count
    $guests = @(Get-TRItems 'Users' | Where-Object { $_.userType -eq 'Guest' }).Count
    $ss = Get-TRRawValue 'SecureScore'
    $spare = 0
    foreach ($s in (Get-TRItems 'SubscribedSkus')) {
        if ($script:TRFreeSkus -contains [string]$s.skuPartNumber) { continue }
        $en = [int]$s.prepaidUnits.enabled
        if ($en -ge 10000) { continue }
        $x = $en - [int]$s.consumedUnits
        if ($x -gt 0) { $spare += $x }
    }
    $tiles = New-Object System.Collections.ArrayList
    if (Test-TRCollected @('Users')) { [void]$tiles.Add(@{ Label = 'Licensed users'; Value = [string]$people.Count; Note = 'Enabled, licensed members' }) }
    if (Test-TRCollected @('RegistrationDetails')) { [void]$tiles.Add(@{ Label = 'MFA capable'; Value = ('{0}%' -f (Get-TRPercent $mfa $people.Count)); Note = ('{0} of {1} users' -f $mfa, $people.Count) }) }
    if (Test-TRCollected @('RoleAssignments')) { [void]$tiles.Add(@{ Label = 'Global admins'; Value = [string]$ga; Note = 'Recommended 2 to 4' }) }
    if (Test-TRCollected @('Users')) { [void]$tiles.Add(@{ Label = 'Guests'; Value = [string]$guests; Note = 'External accounts' }) }
    if (Test-TRCollected @('ExoMailboxes')) { [void]$tiles.Add(@{ Label = 'Mailboxes'; Value = [string]@(Get-TRItems 'ExoMailboxes').Count; Note = ('{0} shared' -f @(Get-TRItems 'ExoMailboxes' | Where-Object { $_.RecipientTypeDetails -eq 'SharedMailbox' }).Count) }) }
    if (Test-TRCollected @('ManagedDevices')) { [void]$tiles.Add(@{ Label = 'Intune devices'; Value = [string]@(Get-TRItems 'ManagedDevices').Count; Note = ('{0} non-compliant' -f @(Get-TRItems 'ManagedDevices' | Where-Object { $_.complianceState -eq 'noncompliant' }).Count) }) }
    if (Test-TRCollected @('DefenderDevices')) {
        $mde = @(Get-TRItems 'DefenderDevices')
        $onb = @($mde | Where-Object { [string]$_.OnboardingStatus -eq 'Onboarded' }).Count
        [void]$tiles.Add(@{ Label = 'Defender devices'; Value = [string]$onb; Note = ('{0} discovered, not onboarded' -f @($mde | Where-Object { [string]$_.OnboardingStatus -eq 'CanBeOnboarded' }).Count) })
    }
    if ($ss) { [void]$tiles.Add(@{ Label = 'Secure Score'; Value = ('{0}%' -f (Get-TRPercent ([double]$ss.currentScore) ([double]$ss.maxScore))); Note = ('{0:N0} of {1:N0} points' -f [double]$ss.currentScore, [double]$ss.maxScore) }) }
    if (Test-TRCollected @('SubscribedSkus')) { [void]$tiles.Add(@{ Label = 'Spare licences'; Value = [string]$spare; Note = 'Paid, unassigned' }) }
    , $tiles.ToArray()
}

function Get-TRReportCss {
    @'
:root{--navy:#0F4761;--navy-2:#1B5E7E;--ink:#1D2730;--muted:#5F6B76;--line:#D9E1E7;--bg:#F5F7F9;--card:#FFFFFF;
--red:#B3261E;--red-bg:#FCE8E6;--amber:#A65F00;--amber-bg:#FFF2DB;--green:#2E7D32;--green-bg:#E7F4E8;--grey:#5F6B76;--grey-bg:#EEF1F4;--blue:#1F5FA8;--blue-bg:#E6EEF8}
*{box-sizing:border-box}html{-webkit-text-size-adjust:100%}
body{margin:0;font-family:Arial,Helvetica,sans-serif;color:var(--ink);background:var(--bg);font-size:14px;line-height:1.5}
a{color:var(--navy-2)}
.masthead{background:#fff;color:var(--navy);padding:14px 32px;display:flex;justify-content:space-between;align-items:center;gap:16px;flex-wrap:wrap}
.brand{display:flex;align-items:center;gap:12px;font-weight:bold;letter-spacing:.2px}
.brand-logo{display:block;height:60px;width:auto}
.logo{display:inline-flex;align-items:center;justify-content:center;width:44px;height:44px;border:2px solid var(--navy);border-radius:6px;font-size:15px}
.masthead .doc{display:flex;align-items:center;gap:14px;font-size:13px;color:var(--muted)}
.masthead .btn{font-size:13px;padding:7px 12px}
.cover{background:linear-gradient(115deg,#0F4761 0%,#15587A 62%,#1E6B8E 100%);color:#fff;padding:30px 32px 24px}
.cover h1{margin:0;font-size:30px;color:#fff;letter-spacing:.2px}
.cover .sub{margin:4px 0 20px;color:#C9DAE5;font-size:15px}
.cover .meta dt{color:#A9C2D2}.cover .meta dd{color:#fff}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px 28px;margin:0}
.meta div{min-width:0}.meta dt{font-size:11px;text-transform:uppercase;letter-spacing:.6px;color:var(--muted)}.meta dd{margin:2px 0 0;font-weight:bold;overflow-wrap:anywhere}
.tabs{position:sticky;top:0;z-index:5;background:#fff;border-bottom:1px solid var(--line);padding:0 24px;display:flex;gap:2px;overflow-x:auto}
.tabs button{font:inherit;background:none;border:0;border-bottom:3px solid transparent;padding:13px 14px;color:var(--muted);cursor:pointer;white-space:nowrap}
.tabs button.active{color:var(--navy);border-bottom-color:var(--navy);font-weight:bold}
main{max-width:1280px;margin:0 auto;padding:24px 32px 48px}
.tab{display:none}.tab.active{display:block}
h2{color:var(--navy);font-size:21px;margin:4px 0 16px}h3{color:var(--navy);font-size:16px;margin:28px 0 10px}
.summary-grid{display:grid;grid-template-columns:300px 1fr;gap:20px;align-items:stretch}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:20px}
.score{display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center}
.score svg{width:170px;height:170px}
.score .rag{display:inline-block;margin-top:8px;padding:3px 12px;border-radius:999px;font-weight:bold;font-size:13px}
.score p{margin:10px 0 0;color:var(--muted);font-size:13px}
.tiles{display:grid;grid-template-columns:repeat(auto-fill,minmax(170px,1fr));gap:12px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:14px 16px}
.tile .v{font-size:26px;font-weight:bold;color:var(--navy);line-height:1.2}.tile .l{font-weight:bold;margin-top:2px}.tile .n{color:var(--muted);font-size:12px}
.lead{font-size:15px;max-width:960px;margin:0 0 10px}
table{border-collapse:collapse;width:100%;background:#fff}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
thead th{background:var(--navy);color:#fff;font-weight:bold;font-size:13px;position:sticky;top:0}
.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:8px;max-height:70vh}
.table-wrap.static{max-height:none}
td.num,th.num{text-align:right}td.nw{white-space:nowrap}
.toggle{font:inherit;font-size:12px;font-weight:bold;border:1px solid var(--line);background:#fff;border-radius:999px;padding:5px 11px;cursor:pointer;color:var(--muted)}
.otoggle{font:inherit;font-size:12px;font-weight:bold;border:1px solid var(--line);background:#fff;border-radius:999px;padding:5px 11px;cursor:pointer;color:var(--muted)}
.chip{display:inline-block;padding:2px 9px;border-radius:999px;font-size:12px;font-weight:bold;white-space:nowrap}
.s-Fail,.rag-Red{background:var(--red-bg);color:var(--red)}.s-Warning,.rag-Amber{background:var(--amber-bg);color:var(--amber)}
.s-Pass,.rag-Green{background:var(--green-bg);color:var(--green)}.rag-None{background:var(--grey-bg);color:var(--grey)}.s-Info,.s-NotAssessed{background:var(--grey-bg);color:var(--grey)}.s-Manual{background:var(--blue-bg);color:var(--blue)}
.o-NotUsed{background:var(--amber-bg);color:var(--amber)}.o-Partial{background:var(--blue-bg);color:var(--blue)}.o-InUse{background:var(--green-bg);color:var(--green)}
.o-Verify{background:#EFE9F7;color:#5B3F8C}.o-NotAssessed,.o-NotApplicable,.o-NotLicensed{background:var(--grey-bg);color:var(--grey)}
.opp{background:#fff;border:1px solid var(--line);border-left:5px solid var(--grey);border-radius:8px;padding:14px 16px;margin-bottom:10px}
.opp.st-NotUsed{border-left-color:var(--amber)}.opp.st-Partial{border-left-color:var(--blue)}.opp.st-InUse{border-left-color:var(--green)}.opp.st-Verify{border-left-color:#5B3F8C}
.otoggle.on{border-color:transparent}.otoggle:not(.on){background:#fff!important;color:var(--muted)!important;text-decoration:line-through}
.opp-sum{display:grid;grid-template-columns:repeat(auto-fill,minmax(170px,1fr));gap:12px;margin:0 0 16px}
.sev{font-size:12px;color:var(--muted)}
.filters{display:flex;flex-wrap:wrap;gap:8px;align-items:center;background:#fff;border:1px solid var(--line);border-radius:8px;padding:12px;margin-bottom:16px}
.filters input[type=search],.filters select,.inv-bar input,.inv-bar select{font:inherit;padding:7px 10px;border:1px solid var(--line);border-radius:6px;background:#fff;min-width:0}
.filters input[type=search]{flex:1 1 220px}
.toggle.on.s-Fail,.toggle.on.s-Warning,.toggle.on.s-Pass,.toggle.on.s-Info,.toggle.on.s-Manual,.toggle.on.s-NotAssessed{border-color:transparent}
.toggle:not(.on){background:#fff!important;color:var(--muted)!important;text-decoration:line-through}
.btn{font:inherit;background:var(--navy);color:#fff;border:0;border-radius:6px;padding:8px 14px;cursor:pointer;font-weight:bold}
.btn.secondary{background:#fff;color:var(--navy);border:1px solid var(--navy)}
.count{color:var(--muted);font-size:13px;margin-left:auto}
.finding{background:#fff;border:1px solid var(--line);border-left:5px solid var(--grey);border-radius:8px;padding:14px 16px;margin-bottom:10px}
.finding.st-Fail{border-left-color:var(--red)}.finding.st-Warning{border-left-color:var(--amber)}.finding.st-Pass{border-left-color:var(--green)}.finding.st-Manual{border-left-color:var(--blue)}
.f-head{display:flex;gap:10px;align-items:baseline;flex-wrap:wrap}
.f-id{font-family:Consolas,Menlo,monospace;font-size:12px;color:var(--muted)}
.f-title{font-weight:bold;font-size:15px;flex:1 1 300px}
.f-grid{display:grid;grid-template-columns:150px 1fr;gap:4px 14px;margin-top:10px}
.f-grid dt{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.4px;padding-top:2px}.f-grid dd{margin:0;overflow-wrap:anywhere}
details{margin-top:10px}summary{cursor:pointer;color:var(--navy-2);font-weight:bold}
details .table-wrap{margin-top:8px;max-height:360px}
#inv-table td{white-space:nowrap;max-width:420px;overflow:hidden;text-overflow:ellipsis}#inv-table th{white-space:nowrap}
.cat-h{display:flex;align-items:center;gap:10px}
.inv-bar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:10px}
.inv-bar input{flex:1 1 220px}
.inv-desc{color:var(--muted);margin:0 0 12px}
th.sortable{cursor:pointer;user-select:none}th.sortable:after{content:' \2195';opacity:.5;font-size:11px}
th.asc:after{content:' \2191';opacity:1}th.desc:after{content:' \2193';opacity:1}
.pager{display:flex;gap:8px;align-items:center;justify-content:flex-end;margin-top:10px;color:var(--muted)}
.pager button{font:inherit;border:1px solid var(--line);background:#fff;border-radius:6px;padding:5px 10px;cursor:pointer}
.pager button:disabled{opacity:.4;cursor:default}
.note{background:var(--blue-bg);border-radius:8px;padding:12px 14px;color:#173E66}
.prio{font-weight:bold}
footer{border-top:1px solid var(--line);color:var(--muted);font-size:12px;padding:18px 32px;text-align:center;background:#fff}
ul.tight{margin:6px 0;padding-left:20px}
@media (max-width:820px){.summary-grid{grid-template-columns:1fr}.f-grid{grid-template-columns:1fr}.f-grid dt{padding-top:6px}main{padding:16px}.masthead,.cover{padding-left:16px;padding-right:16px}.tabs{padding:0 8px}.brand-logo{height:46px}}
.b-cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(330px,1fr));gap:16px;margin:0 0 18px}
.b-card{display:flex;gap:18px;align-items:center}
.b-card svg{width:132px;height:132px;flex:0 0 auto}
.b-card h4{margin:0 0 2px;color:var(--navy);font-size:15px}.b-card .ver{color:var(--muted);font-size:12px;margin:0 0 8px}
.b-card dl{display:grid;grid-template-columns:auto auto;gap:2px 14px;margin:0;font-size:13px}.b-card dt{color:var(--muted)}.b-card dd{margin:0;font-weight:bold;text-align:right}
.ctl{background:#fff;border:1px solid var(--line);border-left:5px solid var(--grey);border-radius:8px;padding:10px 14px;margin-bottom:8px}
.ctl.st-Fail{border-left-color:var(--red)}.ctl.st-Pass{border-left-color:var(--green)}.ctl.st-Manual{border-left-color:var(--blue)}
.s-NotApplicable{background:var(--grey-bg);color:var(--grey)}
.lvl{font-size:11px;border:1px solid var(--line);border-radius:4px;padding:1px 6px;color:var(--muted);white-space:nowrap}
.ctl .ev{margin:6px 0 0}.ctl .how{margin:4px 0 0;color:var(--ink)}.ctl .how b{color:var(--muted);font-weight:normal}
.ctl-meta{font-size:12px;color:var(--muted);margin-top:4px;display:flex;flex-wrap:wrap;gap:4px 16px}
.btoggle{font:inherit;font-size:12px;font-weight:bold;border:1px solid var(--line);border-radius:999px;padding:5px 11px;cursor:pointer}
.btoggle.on{border-color:transparent}.btoggle:not(.on){background:#fff!important;color:var(--muted)!important;text-decoration:line-through}
.fw-tag{display:inline-block;font-size:11px;font-weight:bold;border-radius:4px;padding:1px 6px;background:var(--navy);color:#fff}.fw-tag.SCuBA{background:#3D5A80}
.ap-phases{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px;margin:0 0 14px}
.ap-card{background:#fff;border:1px solid var(--line);border-top:6px solid var(--grey);border-radius:8px;padding:12px 16px}
.ap-card .l{font-weight:bold;font-size:15px;color:var(--ink)}.ap-card .v{font-size:28px;font-weight:bold;color:var(--navy);line-height:1.2}.ap-card .v span{font-size:14px;color:var(--muted);font-weight:normal}
.ap-card .w{font-weight:bold;font-size:13px}.ap-card .e,.ap-card .c{color:var(--muted);font-size:13px}
.ap-card.ph-Must{border-top-color:var(--red)}.ap-card.ph-Must .w{color:var(--red)}.ap-card.ph-Should{border-top-color:#C77700}.ap-card.ph-Should .w{color:var(--amber)}
.ap-card.ph-Could{border-top-color:var(--blue)}.ap-card.ph-Could .w{color:var(--blue)}.ap-card.ph-Licences{border-top-color:var(--green)}.ap-card.ph-Licences .w{color:var(--green)}
.chip.ph-Must{background:var(--red);color:#fff}.chip.ph-Should{background:#C77700;color:#fff}.chip.ph-Could{background:var(--blue);color:#fff}.chip.ph-Licences{background:var(--green);color:#fff}
h3.ap-ph{display:flex;align-items:center;gap:10px;border-bottom:2px solid var(--line);padding-bottom:6px;margin-top:30px}h3.ap-ph .chip{font-size:13px;min-width:24px;text-align:center}
.ap-intro{margin:0 0 12px;color:var(--muted)}.ap-none{background:var(--green-bg);color:var(--green);border-radius:8px;padding:10px 14px;font-weight:bold}
.ap-theme{background:#fff;border:1px solid var(--line);border-radius:8px;padding:14px 16px;margin-bottom:12px}
.ap-head{display:flex;justify-content:space-between;gap:12px;align-items:baseline;flex-wrap:wrap}.ap-head h4{margin:0;color:var(--navy);font-size:15px}
.ap-eff{font-weight:bold;color:var(--navy);white-space:nowrap}.ap-why{margin:6px 0 10px}.ap-why b{color:var(--navy)}
.ap-items{list-style:none;margin:0;padding:0;border-top:1px solid var(--line)}
.ap-items li{display:grid;grid-template-columns:1fr auto;gap:1px 16px;padding:7px 0;border-bottom:1px solid var(--line)}
.ap-items .goal{font-weight:bold;color:var(--ink);text-decoration:none}.ap-items .goal:hover{text-decoration:underline}
.ap-items .h{grid-column:2;grid-row:1;white-space:nowrap;color:var(--muted);font-size:13px;text-align:right}
.ap-items .found{grid-column:1;color:var(--muted);font-size:13px;overflow-wrap:anywhere}
.ap-items.compact li{padding:4px 0}.ap-items.compact .goal{font-weight:normal}
.ap-confirm{background:#fff;border:1px solid var(--line);border-radius:8px;padding:0 16px}.ap-confirm li:last-child{border-bottom:0}
.ap-foot{display:grid;grid-template-columns:1fr 1fr;gap:6px 20px;margin-top:10px;font-size:13px}
.ap-foot b{display:block;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.4px}
.tl{background:#fff;border:1px solid var(--line);border-radius:8px;padding:12px 16px}
.tl-row{display:grid;grid-template-columns:200px 1fr 120px;gap:12px;align-items:center;margin:7px 0}
.tl-label{font-weight:bold;font-size:13px}.tl-when{color:var(--muted);font-size:12px}
.tl-track{position:relative;height:20px;background:var(--grey-bg);border-radius:4px}
.tl-bar{position:absolute;top:0;bottom:0;border-radius:4px;min-width:6px}
.tl-bar.ph-Must{background:var(--red)}.tl-bar.ph-Should{background:#C77700}.tl-bar.ph-Could{background:var(--blue)}.tl-bar.ph-Licences{background:var(--green)}
.tl-scale .tl-track{background:none;height:14px}.tl-scale span{position:absolute;top:0;font-size:11px;color:var(--muted)}
.tl-note{color:var(--muted);font-size:12px;margin:8px 0 0}
table.matrix th,table.matrix td{font-size:12px;padding:6px 8px}table.matrix td.num,table.matrix th.num{text-align:center}
@media (max-width:820px){.tl-row{grid-template-columns:1fr}.tl-scale{display:none}.ap-foot{grid-template-columns:1fr}}
.adv-items{display:block;font-family:Consolas,Menlo,monospace;font-size:11px;color:var(--muted);margin-top:2px;overflow-wrap:anywhere}
.chip.adv-act{background:var(--amber-bg);color:var(--amber)}.chip.adv-ok{background:var(--grey-bg);color:var(--grey)}
.edit-bar{position:sticky;top:48px;z-index:6;background:#FFF8E6;border:1px solid #EBCB8B;border-radius:8px;padding:10px 14px;margin:0 0 16px;display:flex;flex-wrap:wrap;gap:8px 10px;align-items:center;box-shadow:0 4px 14px rgba(15,71,97,.10)}
.edit-bar[hidden]{display:none}.edit-bar .msg{flex:1 1 360px;font-size:13px}.edit-bar .btn{font-size:13px;padding:6px 12px}.edit-bar .btn:disabled{opacity:.45;cursor:default}
.edit-msg{display:block;color:var(--green);font-weight:bold}.edit-msg.bad{color:var(--red)}.edit-msg:empty{display:none}
@media screen{body.editing .eff{cursor:pointer;background:#FFF1CC;border-bottom:1px dashed #A65F00;border-radius:3px;padding:0 3px}body.editing .eff:hover{background:#FFE29A}body.editing .eff.edited{background:#DDF1DE;border-bottom-color:var(--green)}body.editing .eff:empty:before{content:'add';color:var(--muted);font-style:italic}}
.eff-input{font:inherit;font-size:13px;width:90px;padding:1px 5px;border:1px solid var(--navy);border-radius:4px;text-align:right}
@page{size:A4;margin:12mm 10mm}
@media print{html,body{-webkit-print-color-adjust:exact;print-color-adjust:exact}body{background:#fff;font-size:11px}.tabs,.filters,.inv-bar,.pager,.btn,.edit-bar,#tab-inventory{display:none!important}.masthead{padding:8px 0}.cover{padding:16px 18px;border-radius:6px}.brand-logo{height:52px}h2{page-break-after:avoid}h3{page-break-after:avoid}.ocat-block.print-empty,.bsec-block.print-empty,.ctl.st-Pass,.ctl.st-NotApplicable,.b-filters{display:none!important}.b-cards{grid-template-columns:1fr 1fr}.ctl{page-break-inside:avoid;padding:8px 10px}.summary-grid{grid-template-columns:230px 1fr}.score svg{width:140px;height:140px}.tiles,.opp-sum{grid-template-columns:repeat(4,1fr);gap:8px}.tile{padding:8px 10px}.tile .v{font-size:20px}.f-grid{grid-template-columns:120px 1fr;gap:2px 12px}.f-grid dt{padding-top:1px}.finding,.opp{padding:10px 12px;margin-bottom:8px}main{padding:16px 0}summary:after{content:' (listed in the HTML report and FindingDetails.csv)';font-weight:normal;color:var(--muted)}.ctl summary:after{content:' (listed in the HTML report and BenchmarkDetails.csv)'}.tab{display:block!important;page-break-before:always}#tab-summary{page-break-before:avoid}
body.pack .tab:not(#tab-summary):not(#tab-actionplan){display:none!important}body.pack .cover .sub:after{content:': summary and action plan'}.ap-card,.tl,.ap-items li,.ap-why,.ap-foot{page-break-inside:avoid}.ap-foot{font-size:11px}.ap-head,h3.ap-ph,.ap-intro{page-break-after:avoid}.ap-theme{padding:10px 12px;margin-bottom:8px}.ap-items li{padding:4px 0}.ap-phases{grid-template-columns:repeat(4,1fr);gap:8px}.ap-card{padding:8px 10px}.ap-card .v{font-size:22px}.tl-row{grid-template-columns:150px 1fr 95px;margin:5px 0}.tl-scale{display:grid}.ap-foot{grid-template-columns:1fr 1fr}.ap-items .h,.ap-items .found{font-size:11px}.finding,.opp{page-break-inside:avoid;display:block!important}.opp.st-NotLicensed,.opp.st-NotApplicable{display:none!important}.cat-block,.ocat-block,.bsec-block{display:block!important}.table-wrap{max-height:none;overflow:visible}thead th{position:static}details>*{display:block}main{max-width:none}}
'@
}

function Get-TRReportJs {
    @'
(function(){
var data=JSON.parse(document.getElementById('tr-data').textContent);
function $(s,r){return (r||document).querySelector(s)}function $$(s,r){return Array.prototype.slice.call((r||document).querySelectorAll(s))}
function showTab(t){var ok=false;$$('.tabs button').forEach(function(b){var on=b.getAttribute('data-tab')===t;b.classList.toggle('active',on);if(on)ok=true});
if(!ok)return;$$('.tab').forEach(function(s){s.classList.toggle('active',s.id==='tab-'+t)});try{history.replaceState(null,'','#'+t)}catch(e){}}
$$('.tabs button').forEach(function(b){b.addEventListener('click',function(){showTab(b.getAttribute('data-tab'))})});
if(location.hash)showTab(location.hash.slice(1));window.addEventListener('hashchange',function(){if(location.hash)showTab(location.hash.slice(1))});
$$('[data-tab-link]').forEach(function(a){a.addEventListener('click',function(e){e.preventDefault();showTab(a.getAttribute('data-tab-link'));window.scrollTo(0,0)})});
var bp=$('#btn-pdf');if(bp)bp.addEventListener('click',function(){window.print()});
$$('[data-goto]').forEach(function(a){a.addEventListener('click',function(e){e.preventDefault();var id=a.getAttribute('data-goto');showTab(id.indexOf('o-')===0?'opportunities':(id.indexOf('b-')===0?'benchmarks':'findings'));var el=document.getElementById(id);if(el){el.scrollIntoView({behavior:'smooth',block:'center'})}})});
function csvCell(v){if(v===null||v===undefined)return '';v=String(v);if(/[",\r\n]/.test(v))v='"'+v.replace(/"/g,'""')+'"';return v}
function download(name,cols,rows){var lines=[cols.map(csvCell).join(',')];rows.forEach(function(r){lines.push(r.map(csvCell).join(','))});
var blob=new Blob(['\ufeff'+lines.join('\r\n')],{type:'text/csv;charset=utf-8'});var a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=name;document.body.appendChild(a);a.click();setTimeout(function(){URL.revokeObjectURL(a.href);a.remove()},500)}
var fstate={status:{},q:'',sev:'',cat:''};
$$('.toggle[data-status]').forEach(function(t){fstate.status[t.getAttribute('data-status')]=t.classList.contains('on');t.addEventListener('click',function(){t.classList.toggle('on');fstate.status[t.getAttribute('data-status')]=t.classList.contains('on');applyF()})});
var fq=$('#f-q'),fs=$('#f-sev'),fc=$('#f-cat');
if(fq)fq.addEventListener('input',function(){fstate.q=fq.value.toLowerCase();applyF()});
if(fs)fs.addEventListener('change',function(){fstate.sev=fs.value;applyF()});
if(fc)fc.addEventListener('change',function(){fstate.cat=fc.value;applyF()});
function applyF(){var n=0;$$('.finding').forEach(function(f){var ok=fstate.status[f.getAttribute('data-status')]!==false&&(!fstate.sev||f.getAttribute('data-sev')===fstate.sev)&&(!fstate.cat||f.getAttribute('data-cat')===fstate.cat)&&(!fstate.q||f.textContent.toLowerCase().indexOf(fstate.q)>-1);f.style.display=ok?'':'none';if(ok)n++});
$$('.cat-block').forEach(function(b){var any=$$('.finding',b).some(function(f){return f.style.display!=='none'});b.style.display=any?'':'none'});var c=$('#f-count');if(c)c.textContent=n+' of '+data.findings.length+' checks shown'}
applyF();
var fx=$('#f-export');if(fx)fx.addEventListener('click',function(){var vis={};$$('.finding').forEach(function(f){if(f.style.display!=='none')vis[f.getAttribute('data-id')]=1});
var cols=['ID','Category','Check','Status','Severity','Priority','Current state','Recommendation','Effort hours','Affected items','Reference','Benchmarks'];
download(data.meta.filePrefix+'-Findings.csv',cols,data.findings.filter(function(f){return vis[f.Id]}).map(function(f){return [f.Id,f.Category,f.Title,f.StatusLabel,f.Severity,f.Priority,f.Current,f.Recommendation,f.EffortHours,f.AffectedCount,f.Reference,f.Frameworks]}))});
var ostate={status:{},q:'',cat:''};
$$('.otoggle[data-status]').forEach(function(t){ostate.status[t.getAttribute('data-status')]=t.classList.contains('on');t.addEventListener('click',function(){t.classList.toggle('on');ostate.status[t.getAttribute('data-status')]=t.classList.contains('on');applyO()})});
var oq=$('#o-q'),oc=$('#o-cat');
if(oq)oq.addEventListener('input',function(){ostate.q=oq.value.toLowerCase();applyO()});
if(oc)oc.addEventListener('change',function(){ostate.cat=oc.value;applyO()});
function applyO(){var n=0;$$('.opp').forEach(function(f){var ok=ostate.status[f.getAttribute('data-status')]!==false&&(!ostate.cat||f.getAttribute('data-cat')===ostate.cat)&&(!ostate.q||f.textContent.toLowerCase().indexOf(ostate.q)>-1);f.style.display=ok?'':'none';if(ok)n++});
$$('.ocat-block').forEach(function(b){var any=$$('.opp',b).some(function(f){return f.style.display!=='none'});b.style.display=any?'':'none'});var c=$('#o-count');if(c)c.textContent=n+' of '+data.opportunities.length+' features shown'}
if($('#o-count'))applyO();
var ox=$('#o-export');if(ox)ox.addEventListener('click',function(){var vis={};$$('.opp').forEach(function(f){if(f.style.display!=='none')vis[f.getAttribute('data-id')]=1});
var cols=['ID','Category','Feature','Status','Licensed users','Licensed through','Current use','Opportunity','Benefit','Effort days','Reference'];
download(data.meta.filePrefix+'-Opportunities.csv',cols,data.opportunities.filter(function(o){return vis[o.Id]}).map(function(o){return [o.Id,o.Category,o.Feature,o.StatusLabel,o.LicensedUsers,o.LicensedVia,o.Evidence,o.Opportunity,o.Benefit,o.EffortDays,o.Reference]}))});
var bstate={status:{},q:'',fw:'',lvl:'',sec:''};
$$('.btoggle[data-status]').forEach(function(t){bstate.status[t.getAttribute('data-status')]=t.classList.contains('on');t.addEventListener('click',function(){t.classList.toggle('on');bstate.status[t.getAttribute('data-status')]=t.classList.contains('on');applyB()})});
var bq=$('#b-q'),bf=$('#b-fw'),bl=$('#b-lvl'),bs=$('#b-sec');
if(bq)bq.addEventListener('input',function(){bstate.q=bq.value.toLowerCase();applyB()});
if(bf)bf.addEventListener('change',function(){bstate.fw=bf.value;applyB()});
if(bl)bl.addEventListener('change',function(){bstate.lvl=bl.value;applyB()});
if(bs)bs.addEventListener('change',function(){bstate.sec=bs.value;applyB()});
function applyB(){var n=0;$$('.ctl').forEach(function(f){var ok=bstate.status[f.getAttribute('data-status')]!==false&&(!bstate.fw||f.getAttribute('data-fw')===bstate.fw)&&(!bstate.lvl||f.getAttribute('data-lvl')===bstate.lvl)&&(!bstate.sec||f.getAttribute('data-sec')===bstate.sec)&&(!bstate.q||f.textContent.toLowerCase().indexOf(bstate.q)>-1);f.style.display=ok?'':'none';if(ok)n++});
$$('.bsec-block').forEach(function(b){var any=$$('.ctl',b).some(function(f){return f.style.display!=='none'});b.style.display=any?'':'none'});var c=$('#b-count');if(c)c.textContent=n+' of '+data.benchmarks.length+' controls shown'}
if($('#b-count'))applyB();
var bx=$('#b-export');if(bx)bx.addEventListener('click',function(){var vis={};$$('.ctl').forEach(function(f){if(f.style.display!=='none')vis[f.getAttribute('data-key')]=1});
var cols=['Framework','ID','Section','Control','Level','Profile','Status','Evidence','How to meet it','Mapped controls','Related checks','Licence needed'];
download(data.meta.filePrefix+'-Benchmarks.csv',cols,data.benchmarks.filter(function(b){return vis[b.Framework+'|'+b.Id]}).map(function(b){return [b.Framework,b.Id,b.Section,b.Title,b.Level,b.Profile,b.StatusLabel,b.Evidence,b.Guidance,b.Mapped,b.RelatedChecks,b.Licence]}))});
var ix=$('#inv-select'),iq=$('#inv-q'),ie=$('#inv-export'),itable=$('#inv-table'),ipager=$('#inv-pager'),idesc=$('#inv-desc');
var cur=null,curRows=[],sortCol=-1,sortDir=1,page=0,pageSize=50;
function key(v){if(v===null||v===undefined)return '';var s=String(v);var m=s.match(/^(\d{2})\/(\d{2})\/(\d{4})/);if(m)return m[3]+m[2]+m[1]+s.slice(10);return s}
function isNum(v){return v!==''&&v!==null&&!isNaN(Number(v))}
function filterRows(){var q=(iq.value||'').toLowerCase();curRows=cur.rows.filter(function(r){if(!q)return true;for(var i=0;i<r.length;i++){if(r[i]!==null&&String(r[i]).toLowerCase().indexOf(q)>-1)return true}return false});
if(sortCol>-1){var num=curRows.every(function(r){return r[sortCol]===''||r[sortCol]===null||isNum(r[sortCol])});curRows.sort(function(a,b){var x=a[sortCol],y=b[sortCol];var ex=(x===''||x===null),ey=(y===''||y===null);if(ex&&!ey)return 1;if(ey&&!ex)return -1;if(num){x=x===''||x===null?-Infinity:Number(x);y=y===''||y===null?-Infinity:Number(y)}else{x=key(x).toLowerCase();y=key(y).toLowerCase()}return x<y?-sortDir:x>y?sortDir:0})}}
function esc(s){return String(s===null||s===undefined?'':s).replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]})}
function render(){var start=page*pageSize,rows=curRows.slice(start,start+pageSize);var h='<thead><tr>'+cur.columns.map(function(c,i){return '<th class="sortable'+(i===sortCol?(sortDir>0?' asc':' desc'):'')+'" data-i="'+i+'">'+esc(c)+'</th>'}).join('')+'</tr></thead><tbody>';
if(!rows.length)h+='<tr><td colspan="'+cur.columns.length+'">No rows.</td></tr>';rows.forEach(function(r){h+='<tr>'+r.map(function(v){var s=esc(v);if(/^https?:\/\//.test(String(v)))s='<a href="'+s+'" target="_blank" rel="noopener">'+s+'</a>';return '<td title="'+esc(v)+'">'+s+'</td>'}).join('')+'</tr>'});itable.innerHTML=h+'</tbody>';
$$('th.sortable',itable).forEach(function(th){th.addEventListener('click',function(){var i=+th.getAttribute('data-i');if(sortCol===i)sortDir=-sortDir;else{sortCol=i;sortDir=1}filterRows();page=0;render()})});
var pages=Math.max(1,Math.ceil(curRows.length/pageSize));ipager.innerHTML='<span>'+curRows.length+' of '+cur.rows.length+' rows</span><button '+(page<=0?'disabled':'')+' data-p="-1">Previous</button><span>Page '+(page+1)+' of '+pages+'</span><button '+(page>=pages-1?'disabled':'')+' data-p="1">Next</button>';
$$('button',ipager).forEach(function(b){b.addEventListener('click',function(){page+=+b.getAttribute('data-p');render()})})}
function open(name){cur=null;for(var i=0;i<data.inventories.length;i++){if(data.inventories[i].name===name)cur=data.inventories[i]}if(!cur)return;sortCol=-1;sortDir=1;page=0;iq.value='';idesc.textContent=cur.description;filterRows();render()}
if(ix){ix.addEventListener('change',function(){open(ix.value)});iq.addEventListener('input',function(){page=0;filterRows();render()});
ie.addEventListener('click',function(){if(cur)download(data.meta.filePrefix+'-'+cur.name+'.csv',cur.columns,curRows)});if(data.inventories.length)open(ix.value)}
window.__trData=data;
})();
'@
}

function Get-TRSvgRing {
    param([int]$Score, [string]$Colour, [string]$Label = 'weighted score', [string]$Text)
    $r = 70; $c = [Math]::Round(2 * [Math]::PI * $r, 2)
    $dash = [Math]::Round($c * $Score / 100, 2)
    @"
<svg viewBox="0 0 170 170" role="img" aria-label="Score $Score per cent"><circle cx="85" cy="85" r="$r" fill="none" stroke="#E3E9EE" stroke-width="16"/>
<circle cx="85" cy="85" r="$r" fill="none" stroke="$Colour" stroke-width="16" stroke-linecap="round" stroke-dasharray="$dash $c" transform="rotate(-90 85 85)"/>
<text x="85" y="84" text-anchor="middle" font-family="Arial" font-size="38" font-weight="bold" fill="#0F4761">$(if ($Text) { $Text } else { "$Score%" })</text>
<text x="85" y="108" text-anchor="middle" font-family="Arial" font-size="12" fill="#5F6B76">$Label</text></svg>
"@
}

function New-TRBenchmarkHtml {
    param($Bench, $Summary, [int]$Number, [string]$Client)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append(('<section id="tab-benchmarks" class="tab"><h2>{0}. CIS and CISA SCuBA benchmarks</h2>' -f $Number))
    $fi = Get-TRFrameworkInfo
    $gws = (Get-TRPlatform) -eq 'Google'
    [void]$sb.Append('<p class="note">Every control in the ' + (ConvertTo-TRHtml ('{0} {1}' -f $fi.CIS.Name, $fi.CIS.Version)) + ' and the ' + (ConvertTo-TRHtml ('{0} ({1})' -f $fi.SCuBA.Name, $fi.SCuBA.Version)) + ' was assessed from the same data as the findings. Met and Not met are automated results. Check manually covers settings that have no API or need a judgement call. Not applicable means the control needs a licence the tenant does not have, or applies only to US federal agencies.' + $(if ($gws) { ' Settings are read from the Admin console through the Google Policy API, including any organisational unit or group that overrides the organisation-wide value. A few settings the API does not expose are read from the admin audit log for the last 180 days; where no change was logged, the Google default is assumed.' } else { '' }) + ' The percentage is controls met divided by controls met plus not met. Control titles are short summaries; the published benchmarks hold the full wording. Mapped controls shows the matching control in the other framework, and Related checks shows the related findings in this report.</p>')
    [void]$sb.Append('<div class="b-cards">')
    foreach ($b in @($Summary)) {
        $rag = if ($b.Score -ge 80) { '#2E7D32' } elseif ($b.Score -ge 60) { '#C77700' } else { '#B3261E' }
        [void]$sb.Append('<div class="card b-card">')
        [void]$sb.Append((Get-TRSvgRing -Score $b.Score -Colour $rag -Label 'controls met'))
        [void]$sb.Append(('<div><h4>{0}</h4><p class="ver">{1}</p><dl>' -f (ConvertTo-TRHtml $b.Name), (ConvertTo-TRHtml $b.Version)))
        foreach ($row in @(@('Met', $b.Pass), @('Not met', $b.Fail), @('Check manually', $b.Manual), @('Not assessed', $b.NotAssessed), @('Not applicable', $b.NotApplicable), @(($b.CoreLabel + ' controls met'), ('{0}%' -f $b.CoreScore)))) {
            [void]$sb.Append(('<dt>{0}</dt><dd>{1}</dd>' -f (ConvertTo-TRHtml $row[0]), (ConvertTo-TRHtml ([string]$row[1]))))
        }
        [void]$sb.Append('</dl></div></div>')
    }
    [void]$sb.Append('</div>')
    [void]$sb.Append('<h3>Results by section</h3><div class="table-wrap static"><table><thead><tr><th>Framework</th><th>Section</th><th class="num">Met</th><th class="num">Not met</th><th class="num">Check manually</th><th class="num">Other</th></tr></thead><tbody>')
    $groups = New-Object System.Collections.ArrayList
    $seen = @{}
    foreach ($c in $Bench) {
        $k = $c.Framework + '|' + $c.Section
        if (-not $seen.ContainsKey($k)) { $seen[$k] = New-Object System.Collections.ArrayList; [void]$groups.Add($k) }
        [void]$seen[$k].Add($c)
    }
    foreach ($k in $groups) {
        $g = @($seen[$k])
        $fw = (Get-TRFrameworkInfo)[$g[0].Framework].Short
        $m = @($g | Where-Object { $_.Status -eq 'Pass' }).Count
        $f = @($g | Where-Object { $_.Status -eq 'Fail' }).Count
        $man = @($g | Where-Object { $_.Status -eq 'Manual' }).Count
        [void]$sb.Append(('<tr><td>{0}</td><td>{1}</td><td class="num">{2}</td><td class="num">{3}</td><td class="num">{4}</td><td class="num">{5}</td></tr>' -f (ConvertTo-TRHtml $fw), (ConvertTo-TRHtml $g[0].Section), $m, $f, $man, ($g.Count - $m - $f - $man)))
    }
    [void]$sb.Append('</tbody></table></div>')
    [void]$sb.Append('<h3>Controls</h3><div class="filters"><input type="search" id="b-q" placeholder="Search controls" aria-label="Search controls">')
    [void]$sb.Append('<select id="b-fw" aria-label="Framework"><option value="">Both frameworks</option>')
    foreach ($b in @($Summary)) { [void]$sb.Append(('<option value="{0}">{1}</option>' -f $b.Framework, (ConvertTo-TRHtml $b.Short))) }
    [void]$sb.Append('</select><select id="b-lvl" aria-label="Level"><option value="">All levels</option>')
    foreach ($l in @($Bench | Select-Object -ExpandProperty Level -Unique)) { [void]$sb.Append(('<option>{0}</option>' -f (ConvertTo-TRHtml $l))) }
    [void]$sb.Append('</select>')
    foreach ($s in $script:TRCtlStatus.Keys) {
        $n = @($Bench | Where-Object { $_.Status -eq $s }).Count
        if (-not $n) { continue }
        $on = if ($s -eq 'NotApplicable') { '' } else { ' on' }
        [void]$sb.Append(('<button class="btoggle s-{0}{1}" data-status="{0}">{2} ({3})</button>' -f $s, $on, $script:TRCtlStatus[$s], $n))
    }
    [void]$sb.Append('<select id="b-sec" aria-label="Section"><option value="">All sections</option>')
    foreach ($sname in @($Bench | Select-Object -ExpandProperty Section -Unique)) { [void]$sb.Append(('<option>{0}</option>' -f (ConvertTo-TRHtml $sname))) }
    [void]$sb.Append('</select><button class="btn secondary" id="b-export">Export CSV</button><span class="count" id="b-count"></span></div>')
    foreach ($k in $groups) {
        $g = @($seen[$k])
        $fw = (Get-TRFrameworkInfo)[$g[0].Framework].Short
        $printable = @($g | Where-Object { $_.Status -notin @('Pass', 'NotApplicable') }).Count
        [void]$sb.Append(('<div class="bsec-block{0}"><h3 class="cat-h">{1}: {2}</h3>' -f $(if ($printable) { '' } else { ' print-empty' }), (ConvertTo-TRHtml $fw), (ConvertTo-TRHtml $g[0].Section)))
        foreach ($c in $g) {
            $anchor = 'b-' + $c.Framework + '-' + ($c.Id -replace '[^A-Za-z0-9]+', '-')
            $lvl = if ($c.Profile) { '{0} {1}' -f $c.Profile, $c.Level } else { $c.Level }
            [void]$sb.Append(('<article class="ctl st-{0}" id="{1}" data-key="{2}|{3}" data-fw="{2}" data-status="{0}" data-lvl="{4}" data-sec="{5}"{6}>' -f $c.Status, $anchor, $c.Framework, (ConvertTo-TRHtml $c.Id), (ConvertTo-TRHtml $c.Level), (ConvertTo-TRHtml $c.Section), $(if ($c.Status -eq 'NotApplicable') { ' style="display:none"' } else { '' })))
            [void]$sb.Append(('<div class="f-head"><span class="chip s-{0}">{1}</span><span class="f-title">{2}</span><span class="lvl">{3}</span><span class="fw-tag {4}">{5}</span><span class="f-id">{6}</span></div>' -f $c.Status, (ConvertTo-TRHtml $c.StatusLabel), (ConvertTo-TRHtml $c.Title), (ConvertTo-TRHtml $lvl), $c.Framework, $(if ($c.Framework -eq 'CIS') { 'CIS' } else { 'SCuBA' }), (ConvertTo-TRHtml $c.Id)))
            [void]$sb.Append(('<p class="ev">{0}</p>' -f (ConvertTo-TRHtml $c.Evidence)))
            if ($c.Status -in @('Fail', 'Manual', 'NotAssessed') -and $c.Guidance) { [void]$sb.Append(('<p class="how"><b>How to meet it:</b> {0}</p>' -f (ConvertTo-TRHtml $c.Guidance))) }
            $metaBits = @()
            if ($c.Mapped) { $metaBits += ('<span>Mapped controls: {0}</span>' -f (ConvertTo-TRRefLinks $c.Mapped)) }
            if ($c.RelatedChecks) { $metaBits += ('<span>Related checks: {0}</span>' -f (ConvertTo-TRRefLinks $c.RelatedChecks -Checks)) }
            if ($c.Licence) { $metaBits += ('<span>Needs: {0}</span>' -f (ConvertTo-TRHtml $c.Licence)) }
            if ($metaBits.Count) { [void]$sb.Append('<div class="ctl-meta">' + ($metaBits -join '') + '</div>') }
            $aff = @($c.Affected)
            if ($aff.Count) {
                [void]$sb.Append(('<details><summary>{0} affected item{1}</summary><div class="table-wrap"><table><thead><tr><th>Item</th><th>Detail</th></tr></thead><tbody>' -f $aff.Count, $(if ($aff.Count -eq 1) { '' } else { 's' })))
                foreach ($a in ($aff | Select-Object -First 200)) { [void]$sb.Append(('<tr><td>{0}</td><td>{1}</td></tr>' -f (ConvertTo-TRHtml $a.Item), (ConvertTo-TRHtml $a.Detail))) }
                if ($aff.Count -gt 200) { [void]$sb.Append(('<tr><td colspan="2">Showing 200 of {0}. The full list is in BenchmarkDetails.csv.</td></tr>' -f $aff.Count)) }
                [void]$sb.Append('</tbody></table></div></details>')
            }
            [void]$sb.Append('</article>')
        }
        [void]$sb.Append('</div>')
    }
    [void]$sb.Append('<p class="note">' + (ConvertTo-TRHtml $fi.CIS.Name) + ' is published by the Center for Internet Security. The SCuBA baselines are published by CISA. Control numbers are used for reference; this report does not reproduce either benchmark.</p></section>')
    $sb.ToString()
}

function ConvertTo-TRRefLinks {
    param([string]$Text, [switch]$Checks)
    if (-not $Text) { return '' }
    $parts = foreach ($t in ($Text -split ';\s*')) {
        if (-not $t) { continue }
        if ($Checks) {
            $id = ($t -split ' ')[0]
            '<a href="#" data-goto="f-{0}">{1}</a>' -f (ConvertTo-TRHtml $id), (ConvertTo-TRHtml $t)
            continue
        }
        if ($t -like 'CIS *') { $fw = 'CIS'; $id = $t.Substring(4) }
        elseif ($t -like 'MS.*' -or $t -like 'GWS.*') { $fw = 'SCuBA'; $id = $t }
        else { ConvertTo-TRHtml $t; continue }
        '<a href="#" data-goto="b-{0}-{1}">{2}</a>' -f $fw, ($id -replace '[^A-Za-z0-9]+', '-'), (ConvertTo-TRHtml $t)
    }
    @($parts) -join '; '
}

function New-TRReportHtml {
    param($Findings, $Inventories, $Opportunities = @(), $Benchmarks = @(), [string]$FilePrefix)
    $opps = @($Opportunities | Where-Object { $null -ne $_ })
    $bench = @($Benchmarks | Where-Object { $null -ne $_ })
    $benchSum = @(Get-TRBenchmarkSummary $bench)
    $oppNotUsed = @($opps | Where-Object { $_.Status -eq 'NotUsed' })
    $oppPartial = @($opps | Where-Object { $_.Status -eq 'Partial' })
    $oppInUse = @($opps | Where-Object { $_.Status -eq 'InUse' })
    $oppEffort = 0.0
    foreach ($o in $opps) { $oppEffort += [double]$o.EffortDays }
    $oppOrder = @{ NotUsed = 0; Partial = 1; Verify = 2; NotAssessed = 3; InUse = 4; NotApplicable = 5; NotLicensed = 6 }
    $secNo = 5
    $secOpp = 0; $secBench = 0; $secAzure = 0; $secServers = 0
    $azureF = @($Findings | Where-Object { (Get-TRWorkload $_) -eq 'Azure' })
    $showAzure = (Test-TRCollected @('AzSubscriptions')) -or @($azureF | Where-Object { $_.Status -ne 'NotAssessed' }).Count -gt 0
    $serverF = @($Findings | Where-Object { (Get-TRWorkload $_) -eq 'Servers' })
    $showServers = Test-TRCollected @('ServerFiles')
    if ($opps.Count) { $secOpp = $secNo; $secNo++ }
    if ($bench.Count) { $secBench = $secNo; $secNo++ }
    if ($showAzure) { $secAzure = $secNo; $secNo++ }
    if ($showServers) { $secServers = $secNo; $secNo++ }
    $sec = @{ Inventory = $secNo; Method = $secNo + 1 }
    $meta = @{}
    foreach ($k in 'ClientName', 'TenantName', 'TenantId', 'InitialDomain', 'DefaultDomain', 'Reviewer', 'ReviewerName', 'StartedUtc', 'ToolVersion', 'Areas') { $meta[$k] = Get-TRMeta $k }
    $gws = (Get-TRPlatform) -eq 'Google'
    $product = if ($gws) { 'Google Workspace' } else { 'Microsoft 365' }
    $client = if ($meta.ClientName) { [string]$meta.ClientName } elseif ($meta.TenantName) { [string]$meta.TenantName } else { $product + ' tenant' }
    $company = [string](Get-TRSetting 'CompanyName' 'Your Company')
    $short = [string](Get-TRSetting 'CompanyShortName' 'Your Company')
    $hoursPerDay = [double](Get-TRSetting 'HoursPerDay' 7.5)
    $date = Format-TRDate $meta.StartedUtc
    $all = @($Findings)
    $core = @($all | Where-Object { (Get-TRWorkload $_) -eq 'Tenant' })
    $assessed = @($core | Where-Object { $_.Status -in @('Pass', 'Warning', 'Fail') })
    $fail = @($core | Where-Object { $_.Status -eq 'Fail' })
    $warn = @($core | Where-Object { $_.Status -eq 'Warning' })
    $pass = @($core | Where-Object { $_.Status -eq 'Pass' })
    $score = Get-TRScore $core
    $azureScore = Get-TRScore $azureF
    $serverScore = Get-TRScore $serverF
    $plan = Get-TRActionPlan -Findings $Findings -Opportunities $opps
    $scored = $null -ne $score
    if (-not $scored) { $score = 0 }
    $rag = if (-not $scored) { 'None' } elseif ($score -ge 80) { 'Green' } elseif ($score -ge 60) { 'Amber' } else { 'Red' }
    $ringColour = @{ Green = '#2E7D32'; Amber = '#C77700'; Red = '#B3261E'; None = '#9AA5AE' }[$rag]
    $effort = 0.0
    foreach ($f in $all) { $effort += [double]$f.EffortHours }
    $effortDays = [Math]::Round($effort / $hoursPerDay, 1)
    $areaMap = if ($gws) { $script:TRGoogleAreas } else { $script:TRAreas }
    $areaNames = @($meta.Areas | ForEach-Object { $n = $areaMap[[string]$_]; if ($n) { $n } else { [string]$_ } })
    $highFails = @($fail | Where-Object { $_.Severity -eq 'High' })
    $sb = New-Object System.Text.StringBuilder
    $title = ConvertTo-TRHtml ($(if ($gws) { 'Google Workspace Review - ' } else { 'Microsoft 365 Tenant Review - ' }) + $client)
    [void]$sb.Append("<!doctype html><html lang=`"en-GB`"><head><meta charset=`"utf-8`"><meta name=`"viewport`" content=`"width=device-width, initial-scale=1`"><title>$title</title>")
    $fav = Get-TRIconDataUri
    if ($fav) { [void]$sb.Append(('<link rel="icon" type="image/svg+xml" href="{0}">' -f $fav)) }
    [void]$sb.Append('<style>')
    [void]$sb.Append((Get-TRReportCss))
    [void]$sb.Append('</style></head><body>')
    $logo = Get-TRLogoDataUri
    $brand = if ($logo) { '<img class="brand-logo" src="{0}" alt="{1}">' -f $logo, (ConvertTo-TRHtml $company) } else { '<span class="logo">{0}</span><span>{1}</span>' -f (ConvertTo-TRHtml $short), (ConvertTo-TRHtml $company) }
    [void]$sb.Append(('<header class="masthead"><div class="brand">{0}</div><div class="doc"><span>{1} | Confidential</span><button class="btn secondary" id="btn-edit" type="button" title="Change the effort estimates before you print or send the report">Edit effort</button><button class="btn secondary" id="btn-pack" type="button" title="Print only the executive summary and the action plan">Summary PDF</button><button class="btn secondary" id="btn-pdf" type="button">Save as PDF</button></div></header>' -f $brand, $(if ($gws) { 'Google Workspace Review' } else { 'Microsoft 365 Tenant Review' })))
    [void]$sb.Append(('<section class="cover"><h1>{0}</h1><p class="sub">{1}</p><dl class="meta">' -f (ConvertTo-TRHtml $client), $(if ($gws) { 'Google Workspace review' } else { 'Microsoft 365 tenant review' })))
    $metaRows = [ordered]@{
        $(if ($gws) { 'Organisation' } else { 'Tenant' }) = $(if ($meta.TenantName) { $meta.TenantName } else { $meta.InitialDomain })
        'Primary domain' = $meta.DefaultDomain
        $(if ($gws) { 'Customer ID' } else { 'Tenant ID' }) = $meta.TenantId
        'Review date'   = $date
        'Reviewed by'   = $(if ($meta.ReviewerName) { '{0} ({1})' -f $meta.ReviewerName, $meta.Reviewer } else { $meta.Reviewer })
        'Report version' = $(if ($meta.ToolVersion -and [string]$meta.ToolVersion -ne $script:TRToolVersion) { 'Tool v{0} (data collected with v{1})' -f $script:TRToolVersion, $meta.ToolVersion } else { 'Tool v{0}' -f $script:TRToolVersion })
    }
    foreach ($k in $metaRows.Keys) { [void]$sb.Append(('<div><dt>{0}</dt><dd>{1}</dd></div>' -f (ConvertTo-TRHtml $k), (ConvertTo-TRHtml $metaRows[$k]))) }
    [void]$sb.Append('</dl></section>')
    $oppTab = if ($opps.Count) { '<button data-tab="opportunities">Opportunities</button>' } else { '' }
    if ($bench.Count) { $oppTab += '<button data-tab="benchmarks">Benchmarks</button>' }
    if ($showAzure) { $oppTab += '<button data-tab="azure">Azure</button>' }
    if ($showServers) { $oppTab += '<button data-tab="servers">Servers</button>' }
    [void]$sb.Append('<nav class="tabs" aria-label="Report sections"><button class="active" data-tab="summary">Summary</button><button data-tab="actionplan">Action plan</button><button data-tab="findings">Findings</button><button data-tab="recommendations">Recommendations</button>' + $oppTab + '<button data-tab="inventory">Inventory</button><button data-tab="method">Method and limitations</button></nav><main>' + (Get-TREditBarHtml))

    [void]$sb.Append('<section id="tab-summary" class="tab active"><h2>1. Executive summary</h2><div class="summary-grid"><div class="card score">')
    [void]$sb.Append((Get-TRSvgRing -Score $score -Colour $ringColour -Text $(if ($scored) { '' } else { 'n/a' })))
    [void]$sb.Append(('<span class="rag rag-{0}">{5}</span><p>{1} checks assessed: {2} pass, {3} warning, {4} fail</p></div><div class="tiles">' -f $rag, $assessed.Count, $pass.Count, $warn.Count, $fail.Count, $(if ($scored) { $rag } else { 'Not scored' })))
    $stats = Get-TRSummaryStats
    $tileList = New-Object System.Collections.ArrayList
    foreach ($t in @($stats)) { [void]$tileList.Add($t) }
    if ($opps.Count) { [void]$tileList.Add(@{ Label = 'Unused licensed features'; Value = [string]$oppNotUsed.Count; Note = ('{0} more partly used' -f $oppPartial.Count) }) }
    foreach ($b in $benchSum) { [void]$tileList.Add(@{ Label = $b.Short; Value = ('{0}%' -f $b.Score); Note = ('{0} of {1} assessed controls met' -f $b.Pass, ($b.Pass + $b.Fail)) }) }
    if ($showAzure -and $null -ne $azureScore) { [void]$tileList.Add(@{ Label = 'Azure score'; Value = ('{0}%' -f $azureScore); Note = ('{0} fail, {1} warning (see Azure)' -f @($azureF | Where-Object { $_.Status -eq 'Fail' }).Count, @($azureF | Where-Object { $_.Status -eq 'Warning' }).Count) }) }
    if ($showServers -and $null -ne $serverScore) { [void]$tileList.Add(@{ Label = 'Server score'; Value = ('{0}%' -f $serverScore); Note = ('{0} fail, {1} warning (see Servers)' -f @($serverF | Where-Object { $_.Status -eq 'Fail' }).Count, @($serverF | Where-Object { $_.Status -eq 'Warning' }).Count) }) }
    foreach ($t in $tileList) {
        [void]$sb.Append(('<div class="tile"><div class="v">{0}</div><div class="l">{1}</div><div class="n">{2}</div></div>' -f (ConvertTo-TRHtml $t.Value), (ConvertTo-TRHtml $t.Label), (ConvertTo-TRHtml $t.Note)))
    }
    [void]$sb.Append('</div></div>')
    $lead = '{0}''s {9} was reviewed on {1} against {2} checks across {3} areas. The weighted score is {4}% ({5}). Of the checks assessed, {6} failed, {7} need attention and {8} passed.' -f $client, $date, $core.Count, @($areaNames | Where-Object { $_ -notmatch '^(Azure|Servers)' }).Count, $score, $rag, $fail.Count, $warn.Count, $pass.Count, $(if ($gws) { 'Google Workspace' } else { 'Microsoft 365 tenant' })
    if (-not $scored) { $lead = '{0}''s {1} was reviewed on {2}, but none of the {3} checks could be assessed because the data could not be read. The Method and limitations section and the Collection diagnostics inventory show what failed and why.' -f $client, $(if ($gws) { 'Google Workspace' } else { 'Microsoft 365 tenant' }), $date, $core.Count }
    if ($highFails.Count -eq 1) { $lead += ' One high-severity issue should be addressed first.' }
    elseif ($highFails.Count) { $lead += (' {0} high-severity issues should be addressed first.' -f $highFails.Count) }
    if ($effort -gt 0) { $lead += (' Estimated remediation effort for all failed and warning items is about [[effH]] hours ([[effD]] days).') }
    if ($oppNotUsed.Count -or $oppPartial.Count) {
        $lead += ('|| The {2} already has licences for features that are not being used. Not used: {0}. Partly used: {1}. Setting these up is estimated at [[oppD]] days (see Opportunities).' -f $oppNotUsed.Count, $oppPartial.Count, $(if ($gws) { 'organisation' } else { 'tenant' }))
    }
    if ($benchSum.Count) {
        $parts = @($benchSum | ForEach-Object { '{0} {1}% ({2} of {3} assessed controls, {4} to check manually)' -f $_.Short, $_.Score, $_.Pass, ($_.Pass + $_.Fail), $_.Manual })
        $lead += ('|| Against the published benchmarks the {1} meets: {0} (see Benchmarks).' -f ($parts -join '; '), $(if ($gws) { 'organisation' } else { 'tenant' }))
    }
    if ($showAzure -and $null -ne $azureScore) {
        $azSubs = @(Get-TRItems 'AzSubscriptions').Count
        $lead += ('|| Azure was reviewed separately ({0}): the Azure score is {1}%, with {2} failed and {3} needing attention (see Azure).' -f (Format-TRN $azSubs 'subscription'), $azureScore, @($azureF | Where-Object { $_.Status -eq 'Fail' }).Count, @($azureF | Where-Object { $_.Status -eq 'Warning' }).Count)
    }
    if ($showServers -and $null -ne $serverScore) {
        $srvCount = @(Get-TRServerSummary).Count
        $lead += ('|| Servers were reviewed separately ({0} from collected server data): the server score is {1}%, with {2} failed and {3} needing attention (see Servers).' -f (Format-TRN $srvCount 'system'), $serverScore, @($serverF | Where-Object { $_.Status -eq 'Fail' }).Count, @($serverF | Where-Object { $_.Status -eq 'Warning' }).Count)
    }
    [void]$sb.Append('<h3>Overview</h3>')
    $tokens = @{
        '[[effH]]' = ('<span class="effsum" data-sum="all" data-fmt="N1">{0}</span>' -f (ConvertTo-TRHtml ('{0:N1}' -f $effort)))
        '[[effD]]' = ('<span class="effsum" data-sum="all" data-fmt="D1">{0}</span>' -f (ConvertTo-TRHtml ('{0:N1}' -f $effortDays)))
        '[[oppD]]' = ('<span class="effsum" data-sum="opps" data-fmt="N1">{0}</span>' -f (ConvertTo-TRHtml ('{0:N1}' -f $oppEffort)))
    }
    foreach ($para in ($lead -split '\|\| ')) {
        if (-not $para.Trim()) { continue }
        $h = ConvertTo-TRHtml $para.Trim()
        foreach ($t in $tokens.Keys) { $h = $h.Replace($t, $tokens[$t]) }
        [void]$sb.Append(('<p class="lead">{0}</p>' -f $h))
    }

    [void]$sb.Append((New-TRPlanSummaryHtml $plan))
    [void]$sb.Append('<h3>Results by area</h3><div class="table-wrap static"><table><thead><tr><th>Area</th><th>RAG</th><th class="num">Fail</th><th class="num">Warning</th><th class="num">Pass</th><th class="num">Info or manual</th></tr></thead><tbody>')
    foreach ($g in ($all | Group-Object Category)) {
        $gf = @($g.Group | Where-Object { $_.Status -eq 'Fail' })
        $gw = @($g.Group | Where-Object { $_.Status -eq 'Warning' })
        $gp = @($g.Group | Where-Object { $_.Status -eq 'Pass' })
        $go = $g.Count - $gf.Count - $gw.Count - $gp.Count
        $grag = if (@($gf | Where-Object { $_.Severity -eq 'High' }).Count) { 'Red' } elseif ($gf.Count -or $gw.Count) { 'Amber' } elseif ($gp.Count) { 'Green' } else { '' }
        $chip = if ($grag) { '<span class="chip rag-{0}">{0}</span>' -f $grag } else { '<span class="chip s-Info">Not rated</span>' }
        [void]$sb.Append(('<tr><td>{0}</td><td>{1}</td><td class="num">{2}</td><td class="num">{3}</td><td class="num">{4}</td><td class="num">{5}</td></tr>' -f (ConvertTo-TRHtml $g.Name), $chip, $gf.Count, $gw.Count, $gp.Count, $go))
    }
    [void]$sb.Append('</tbody></table></div>')

    $topOpps = @(@($oppNotUsed) + @($oppPartial) | Sort-Object @{ e = { $oppOrder[[string]$_.Status] } }, @{ e = { [int]$_.LicensedUsers }; Descending = $true } | Select-Object -First 8)
    if ($topOpps.Count) {
        [void]$sb.Append('<h3>Licensed but not used</h3><div class="table-wrap static"><table><thead><tr><th>Status</th><th>Feature</th><th class="num">Licensed users</th><th>Current use</th></tr></thead><tbody>')
        foreach ($o in $topOpps) {
            [void]$sb.Append(('<tr><td><span class="chip o-{0}">{1}</span></td><td><a href="#" data-goto="o-{2}">{3}</a></td><td class="num">{4}</td><td>{5}</td></tr>' -f $o.Status, (ConvertTo-TRHtml $o.StatusLabel), (ConvertTo-TRHtml $o.Id), (ConvertTo-TRHtml $o.Feature), [int]$o.LicensedUsers, (ConvertTo-TRHtml $o.Evidence)))
        }
        [void]$sb.Append('</tbody></table></div>')
    }
    [void]$sb.Append('</section>')
    [void]$sb.Append((New-TRActionPlanHtml -Plan $plan -Number 2 -Client $client))

    [void]$sb.Append('<section id="tab-findings" class="tab"><h2>3. Findings</h2><div class="filters"><input type="search" id="f-q" placeholder="Search findings" aria-label="Search findings">')
    foreach ($s in 'Fail', 'Warning', 'Pass', 'Info', 'Manual', 'NotAssessed') {
        $on = if ($s -in @('Fail', 'Warning', 'Manual', 'Pass', 'Info', 'NotAssessed')) { ' on' } else { '' }
        $n = @($all | Where-Object { $_.Status -eq $s }).Count
        [void]$sb.Append(('<button class="toggle s-{0}{1}" data-status="{0}">{2} ({3})</button>' -f $s, $on, (Get-TRStatusLabel $s), $n))
    }
    [void]$sb.Append('<select id="f-sev" aria-label="Severity"><option value="">All severities</option><option>High</option><option>Medium</option><option>Low</option><option>Info</option></select><select id="f-cat" aria-label="Area"><option value="">All areas</option>')
    $cats = @($all | Select-Object -ExpandProperty Category -Unique)
    foreach ($c in $cats) { [void]$sb.Append(('<option>{0}</option>' -f (ConvertTo-TRHtml $c))) }
    [void]$sb.Append('</select><button class="btn secondary" id="f-export">Export CSV</button><span class="count" id="f-count"></span></div>')
    $order = @{ Fail = 0; Warning = 1; Manual = 2; NotAssessed = 3; Info = 4; Pass = 5 }
    $sevOrder = @{ High = 0; Medium = 1; Low = 2; Info = 3 }
    foreach ($c in $cats) {
        [void]$sb.Append(('<div class="cat-block"><h3 class="cat-h">{0}</h3>' -f (ConvertTo-TRHtml $c)))
        foreach ($f in ($all | Where-Object { $_.Category -eq $c } | Sort-Object @{ e = { $order[[string]$_.Status] } }, @{ e = { $sevOrder[[string]$_.Severity] } }, Id)) {
            [void]$sb.Append(('<article class="finding st-{0}" id="f-{1}" data-id="{1}" data-status="{0}" data-sev="{2}" data-cat="{3}">' -f $f.Status, (ConvertTo-TRHtml $f.Id), $f.Severity, (ConvertTo-TRHtml $f.Category)))
            [void]$sb.Append(('<div class="f-head"><span class="chip s-{0}">{1}</span><span class="f-title">{2}</span><span class="sev">{3} severity</span><span class="f-id">{4}</span></div>' -f $f.Status, (Get-TRStatusLabel $f.Status), (ConvertTo-TRHtml $f.Title), $f.Severity, (ConvertTo-TRHtml $f.Id)))
            [void]$sb.Append(('<dl class="f-grid"><dt>Current state</dt><dd>{0}</dd>' -f (ConvertTo-TRHtml $f.Current)))
            if ($f.Status -ne 'Pass') { [void]$sb.Append(('<dt>Recommendation</dt><dd>{0}</dd>' -f (ConvertTo-TRHtml $f.Recommendation))) }
            if ($f.Status -in @('Fail', 'Warning')) { [void]$sb.Append(('<dt>Estimated effort</dt><dd><span class="eff" data-ef="{0}" data-fmt="H">{1}</span></dd>' -f (ConvertTo-TRHtml $f.Id), (ConvertTo-TRHtml (Format-TRHoursText ([double]$f.EffortHours))))) }
            if ($f.Priority) { [void]$sb.Append(('<dt>Priority</dt><dd class="prio">{0}</dd>' -f $f.Priority)) }
            if ($f.Reference) { [void]$sb.Append(('<dt>Reference</dt><dd><a href="{0}" target="_blank" rel="noopener">{0}</a></dd>' -f (ConvertTo-TRHtml $f.Reference))) }
            if ((Test-TRHasProperty $f 'Frameworks') -and $f.Frameworks) { [void]$sb.Append(('<dt>Benchmarks</dt><dd>{0}</dd>' -f $(if ($bench.Count) { ConvertTo-TRRefLinks $f.Frameworks } else { ConvertTo-TRHtml $f.Frameworks }))) }
            [void]$sb.Append('</dl>')
            $aff = @($f.Affected)
            if ($aff.Count) {
                [void]$sb.Append(('<details><summary>{0} affected item{1}</summary><div class="table-wrap"><table><thead><tr><th>Item</th><th>Detail</th></tr></thead><tbody>' -f $aff.Count, $(if ($aff.Count -eq 1) { '' } else { 's' })))
                foreach ($a in ($aff | Select-Object -First 300)) { [void]$sb.Append(('<tr><td>{0}</td><td>{1}</td></tr>' -f (ConvertTo-TRHtml $a.Item), (ConvertTo-TRHtml $a.Detail))) }
                if ($aff.Count -gt 300) { [void]$sb.Append(('<tr><td colspan="2">Showing 300 of {0}. The full list is in FindingDetails.csv.</td></tr>' -f $aff.Count)) }
                [void]$sb.Append('</tbody></table></div></details>')
            }
            [void]$sb.Append('</article>')
        }
        [void]$sb.Append('</div>')
    }
    [void]$sb.Append('</section>')

    $recs = @($all | Where-Object { $_.Status -in @('Fail', 'Warning', 'Manual') } | Sort-Object Priority, @{ e = { $sevOrder[[string]$_.Severity] } }, Id)
    [void]$sb.Append('<section id="tab-recommendations" class="tab"><h2>4. Prioritised recommendations</h2>')
    [void]$sb.Append(('<p class="note">This is the technical list for engineers; the Action plan gives the same work in plain English. Priority P1 items (must do) are high-severity failures to fix first, P2 (should do) are medium-severity failures or high-severity warnings, and P3 (could do) are improvements and manual checks. Effort is an estimate of engineer hours for remediation and is for scoping only. Total: {0} hours ({1} days at {2} hours per day).</p>' -f $tokens['[[effH]]'], $tokens['[[effD]]'], $hoursPerDay))
    [void]$sb.Append('<div class="table-wrap static"><table><thead><tr><th>Priority</th><th>Recommendation</th><th>Area</th><th>Status</th><th class="num">Effort (hours)</th></tr></thead><tbody>')
    foreach ($f in $recs) {
        [void]$sb.Append(('<tr><td class="prio">{0}</td><td><strong>{1}</strong> <span class="f-id">{2}</span><br>{3}</td><td>{4}</td><td><span class="chip s-{5}">{6}</span></td><td class="num"><span class="eff" data-ef="{2}" data-fmt="N">{7}</span></td></tr>' -f $f.Priority, (ConvertTo-TRHtml $f.Title), (ConvertTo-TRHtml $f.Id), (ConvertTo-TRHtml $f.Recommendation), (ConvertTo-TRHtml $f.Category), $f.Status, (Get-TRStatusLabel $f.Status), $(if ([double]$f.EffortHours -gt 0) { Format-TRNumber ([double]$f.EffortHours) '0.##' } else { '' })))
    }
    [void]$sb.Append(('<tr><td></td><td><strong>Total</strong></td><td></td><td></td><td class="num"><strong>{0}</strong></td></tr></tbody></table></div></section>' -f $tokens['[[effH]]']))

    if ($opps.Count) {
        [void]$sb.Append(('<section id="tab-opportunities" class="tab"><h2>{0}. Licence utilisation opportunities</h2>' -f $secOpp))
        [void]$sb.Append(('<p class="note">Each feature below is included in licences {0} already pays for. It is compared with what is configured or used in the tenant, so the client can see where they are paying for capability they are not getting value from. Licensed users counts enabled users whose assigned licences include the feature. Effort is an estimate in days for {1} to plan and configure the feature, and is for scoping only.</p>' -f (ConvertTo-TRHtml $client), (ConvertTo-TRHtml $short)))
        $verify = @($opps | Where-Object { $_.Status -eq 'Verify' }).Count
        [void]$sb.Append('<div class="opp-sum">')
        foreach ($t in @(
                @{ V = $oppNotUsed.Count; L = 'Not used'; N = 'Licensed, not set up' },
                @{ V = $oppPartial.Count; L = 'Partly used'; N = 'Licensed, partly set up' },
                @{ V = $oppInUse.Count; L = 'In use'; N = 'Licensed and in use' },
                @{ V = ('{0:N1}' -f $oppEffort); Html = $tokens['[[oppD]]']; L = 'Days to adopt'; N = 'Estimated effort' })) {
            [void]$sb.Append(('<div class="tile"><div class="v">{0}</div><div class="l">{1}</div><div class="n">{2}</div></div>' -f $(if ($t.Html) { $t.Html } else { ConvertTo-TRHtml $t.V }), (ConvertTo-TRHtml $t.L), (ConvertTo-TRHtml $t.N)))
        }
        if ($verify) { [void]$sb.Append(('<div class="tile"><div class="v">{0}</div><div class="l">Check in portal</div><div class="n">Usage not readable</div></div>' -f $verify)) }
        [void]$sb.Append('</div>')
        [void]$sb.Append('<div class="filters"><input type="search" id="o-q" placeholder="Search features" aria-label="Search features">')
        foreach ($s in $script:TROppStatus.Keys) {
            $n = @($opps | Where-Object { $_.Status -eq $s }).Count
            if (-not $n) { continue }
            $on = if ($s -eq 'NotLicensed') { '' } else { ' on' }
            [void]$sb.Append(('<button class="otoggle o-{0}{1}" data-status="{0}">{2} ({3})</button>' -f $s, $on, (Get-TROppStatusLabel $s), $n))
        }
        [void]$sb.Append('<select id="o-cat" aria-label="Category"><option value="">All categories</option>')
        $ocats = @($opps | Select-Object -ExpandProperty Category -Unique)
        foreach ($c in $ocats) { [void]$sb.Append(('<option>{0}</option>' -f (ConvertTo-TRHtml $c))) }
        [void]$sb.Append('</select><button class="btn secondary" id="o-export">Export CSV</button><span class="count" id="o-count"></span></div>')
        foreach ($c in $ocats) {
            $printable = @($opps | Where-Object { $_.Category -eq $c -and $_.Status -notin @('NotLicensed', 'NotApplicable') }).Count
            [void]$sb.Append(('<div class="ocat-block{0}"><h3 class="cat-h">{1}</h3>' -f $(if ($printable) { '' } else { ' print-empty' }), (ConvertTo-TRHtml $c)))
            foreach ($o in ($opps | Where-Object { $_.Category -eq $c } | Sort-Object @{ e = { $oppOrder[[string]$_.Status] } }, Id)) {
                $usersText = if ($o.Status -eq 'NotLicensed') { 'Not in current licences' } elseif ([int]$o.LicensedUsers -eq 1) { '1 licensed user' } else { '{0} licensed users' -f [int]$o.LicensedUsers }
                [void]$sb.Append(('<article class="opp st-{0}" id="o-{1}" data-id="{1}" data-status="{0}" data-cat="{2}"{3}>' -f $o.Status, (ConvertTo-TRHtml $o.Id), (ConvertTo-TRHtml $o.Category), $(if ($o.Status -eq 'NotLicensed') { ' style="display:none"' } else { '' })))
                [void]$sb.Append(('<div class="f-head"><span class="chip o-{0}">{1}</span><span class="f-title">{2}</span><span class="sev">{3}</span><span class="f-id">{4}</span></div>' -f $o.Status, (ConvertTo-TRHtml $o.StatusLabel), (ConvertTo-TRHtml $o.Feature), (ConvertTo-TRHtml $usersText), (ConvertTo-TRHtml $o.Id)))
                [void]$sb.Append('<dl class="f-grid">')
                if ($o.LicensedVia) { [void]$sb.Append(('<dt>Licensed through</dt><dd>{0}</dd>' -f (ConvertTo-TRHtml $o.LicensedVia))) }
                $ev = if ($o.Status -eq 'NotLicensed') { 'Not included in the licences the tenant currently has.' } else { [string]$o.Evidence }
                [void]$sb.Append(('<dt>Current use</dt><dd>{0}</dd>' -f (ConvertTo-TRHtml $ev)))
                if ($o.Status -in @('NotUsed', 'Partial', 'Verify', 'NotLicensed')) {
                    $label = if ($o.Status -eq 'NotLicensed') { 'What it would add' } else { 'Opportunity' }
                    [void]$sb.Append(('<dt>{0}</dt><dd>{1}</dd><dt>Benefit</dt><dd>{2}</dd>' -f $label, (ConvertTo-TRHtml $o.Opportunity), (ConvertTo-TRHtml $o.Benefit)))
                }
                if ($o.Status -in @('NotUsed', 'Partial')) { [void]$sb.Append(('<dt>Estimated effort</dt><dd><span class="eff" data-eo="{0}" data-fmt="DR">{1}</span></dd>' -f (ConvertTo-TRHtml $o.Id), (ConvertTo-TRHtml (Format-TRDaysText ([double]$o.EffortDays))))) }
                if ($o.Reference) { [void]$sb.Append(('<dt>Reference</dt><dd><a href="{0}" target="_blank" rel="noopener">{0}</a></dd>' -f (ConvertTo-TRHtml $o.Reference))) }
                [void]$sb.Append('</dl></article>')
            }
            [void]$sb.Append('</div>')
        }
        [void]$sb.Append('</section>')
    }

    if ($bench.Count) { [void]$sb.Append((New-TRBenchmarkHtml -Bench $bench -Summary $benchSum -Number $secBench -Client $client)) }
    if ($showAzure) { [void]$sb.Append((New-TRAzureHtml -Findings $azureF -Number $secAzure -Client $client)) }
    if ($showServers) { [void]$sb.Append((New-TRServersHtml -Findings $serverF -Number $secServers -Client $client)) }

    $invList = @($Inventories.Values)
    [void]$sb.Append(('<section id="tab-inventory" class="tab"><h2>{0}. Inventory</h2><div class="inv-bar"><select id="inv-select" aria-label="Inventory">' -f $sec.Inventory))
    foreach ($i in $invList) { [void]$sb.Append(('<option value="{0}">{1} ({2})</option>' -f (ConvertTo-TRHtml $i.Name), (ConvertTo-TRHtml $i.Title), @($i.Rows).Count)) }
    [void]$sb.Append('</select><input type="search" id="inv-q" placeholder="Search this inventory" aria-label="Search inventory"><button class="btn secondary" id="inv-export">Export CSV</button></div><p class="inv-desc" id="inv-desc"></p><div class="table-wrap"><table id="inv-table"></table></div><div class="pager" id="inv-pager"></div></section>')

    $diag = @(Get-TRItems 'Diagnostics')
    $dFail = @($diag | Where-Object { $_.Status -eq 'Failed' })
    $dUn = @($diag | Where-Object { $_.Status -in @('Unavailable', 'Skipped') })
    [void]$sb.Append(('<section id="tab-method" class="tab"><h2>{0}. Method and limitations</h2>' -f $sec.Method))
    if ($gws) {
        [void]$sb.Append(('<p>Data was collected read-only through the Google Admin SDK (Directory, Reports and License Manager APIs), the Cloud Identity Policy, Devices and SSO APIs, the Groups Settings API and the Alert Center API, using the delegated sign-in of {0}{2}. No settings were changed. Admin console settings were read for the whole organisation and for every organisational unit or group that overrides them. Settings the APIs do not expose were inferred from the admin audit log (180 days) where possible. DNS records were checked from public DNS. Each check compares the current configuration with Google guidance and {1} standards.</p>' -f (ConvertTo-TRHtml $meta.Reviewer), (ConvertTo-TRHtml $short), $(if ((Get-TRMeta 'IsSuperAdmin') -eq $false) { ' (not a super admin, so some data could not be read)' } else { ', a super admin' })))
    }
    else {
    [void]$sb.Append(('<p>Data was collected read-only through Microsoft Graph (including Defender XDR advanced hunting for the last 30 days), the Exchange Online management API and the Security &amp; Compliance management API{2}, using delegated access by {0}. No settings were changed. DNS records were checked from public DNS. Each check compares the current configuration with Microsoft guidance and {1} standards.</p>' -f (ConvertTo-TRHtml $meta.Reviewer), (ConvertTo-TRHtml $short), $(if (@($meta.Areas) -contains 'ServiceSettings') { ', plus the Teams, SharePoint, Fabric and Power Platform admin APIs where access was approved' } else { '' })))
    }
    if ($showAzure) { [void]$sb.Append(('<p>Azure was read through Azure Resource Manager, Azure Resource Graph, Defender for Cloud and Azure Advisor with the Azure roles of {0}, after read access was approved at the start of the review. Only subscriptions where that account has a role are included ({1}).</p>' -f (ConvertTo-TRHtml $meta.Reviewer), (Format-TRN @(Get-TRItems 'AzSubscriptions').Count 'subscription'))) }
    if ($showServers) { [void]$sb.Append(('<p>Server data was collected separately with the {0} server collectors (run on each Windows server as an administrator, through the RMM or over WinRM; a shell script on Linux; PowerCLI for VMware) and imported from {1}. Each server is compared with CIS Level 1 and Microsoft security baseline settings, supported versions, patching, protection and backup.</p>' -f (ConvertTo-TRHtml $short), (ConvertTo-TRHtml (Format-TRN @(Get-TRItems 'ServerFiles').Count 'data file')))) }
    if ($opps.Count) {
        if ($gws) { [void]$sb.Append('<p>Licence utilisation compares the Google Workspace editions and add-ons assigned to users with Admin console settings, audit logs and usage reports. A feature shown as Not used is included in an assigned edition but has no matching configuration or activity. Usage reports lag by two to three days.</p>') }
        else { [void]$sb.Append('<p>Licence utilisation compares the service plans in each user''s assigned licences (excluding plans switched off on the licence) with configuration and 30-day usage reports. A feature shown as Not used is licensed but has no matching configuration or activity. Usage reports can lag by up to 48 hours.</p>') }
    }
    [void]$sb.Append(('<p>{0} of {1} collection steps succeeded. {2} failed and {3} were unavailable or skipped (often because a feature is not licensed). Checks that depend on missing data are shown as Not assessed. The Collection diagnostics inventory lists every step.</p>' -f @($diag | Where-Object { $_.Status -eq 'OK' }).Count, $diag.Count, $dFail.Count, $dUn.Count))
    $advice = @(Get-TRCollectionAdvice $diag)
    if ($advice.Count) {
        $actN = @($advice | Where-Object { $_.Action }).Count
        [void]$sb.Append('<h3>What could not be read, and how to fix it</h3>')
        $intro = if ($actN) { 'Rows marked Action needed can be fixed on the review account (a role, a licence or an approval). Make the change and run the review again to fill in the checks they affect. Rows marked No action reflect what the client has licensed or set up.' } else { 'Nothing here needs action: these rows reflect what the client has licensed or set up.' }
        [void]$sb.Append(('<p>{0}</p>' -f (ConvertTo-TRHtml $intro)))
        [void]$sb.Append('<div class="table-wrap static"><table><thead><tr><th></th><th>What</th><th>Why</th><th>Effect</th><th>What to do</th></tr></thead><tbody>')
        foreach ($a in $advice) {
            $eff = Format-TRAdviceEffect (Get-TRAdviceEffect -Advice $a -Findings $all -Benchmarks $bench)
            $chip = if ($a.Action) { '<span class="chip adv-act">Action needed</span>' } else { '<span class="chip adv-ok">No action</span>' }
            $why = $a.KindLabel
            if ($a.Messages.Count) { $why += ': ' + (Get-TRShortText ([string]$a.Messages[0]) 180) }
            [void]$sb.Append(('<tr><td>{0}</td><td><strong>{1}</strong><span class="adv-items">{2}</span></td><td>{3}</td><td>{4}</td><td>{5}</td></tr>' -f $chip, (ConvertTo-TRHtml $a.Group), (ConvertTo-TRHtml ($a.Items -join ', ')), (ConvertTo-TRHtml $why), (ConvertTo-TRHtml $eff), (ConvertTo-TRHtml $a.Fix)))
        }
        [void]$sb.Append('</tbody></table></div>')
    }
    if ($gws) { [void]$sb.Append('<h3>Not covered by automated checks</h3><ul class="tight"><li>Gmail delegates, filters and forwarding set by individual users (the Gmail API needs per-user access that an admin sign-in does not give; the organisation-wide forwarding and delegation settings are checked)</li><li>Sharing of individual files in My Drive and shared drives, beyond the Drive audit log</li><li>Vault retention rules and holds (these need Vault access, which this review does not request)</li><li>Domain-wide delegation clients and context-aware access levels (not available through the Workspace APIs)</li><li>Backup of Google Workspace data</li></ul>') }
    else {
    [void]$sb.Append('<h3>Not covered by automated checks</h3><ul class="tight">' + $(if (@($meta.Areas) -notcontains 'ServiceSettings') { '<li>Teams external access, guest and meeting policies</li>' } else { '' }) + '<li>Backup of Microsoft 365 data</li><li>File and folder level permissions inside SharePoint sites and OneDrive (site membership is covered through groups and Teams)</li><li>Defender for Cloud Apps policies and Defender portal advanced settings (licence use is flagged in Opportunities)</li><li>Purview communication compliance, information barriers and records management file plans</li></ul>')
    }
    [void]$sb.Append('<h3>Areas reviewed</h3><p>' + (ConvertTo-TRHtml ($areaNames -join ', ')) + '</p><p>Effort estimates assume the remediation is carried out by an experienced engineer with suitable admin access and exclude user communication, change control and testing with the client unless stated.</p></section>')
    [void]$sb.Append('</main>')
    [void]$sb.Append(('<footer>Prepared by {0} for {1}. Confidential. Generated {2} by {4} v{3}.</footer>' -f (ConvertTo-TRHtml $company), (ConvertTo-TRHtml $client), (Format-TRDate (Get-Date) -WithTime), (ConvertTo-TRHtml $script:TRToolVersion), $(if ($gws) { 'Tenant Review' } else { 'Tenant Review' })))

    $json = New-Object System.Text.StringBuilder
    [void]$json.Append('{"meta":{"filePrefix":').Append((ConvertTo-TRJsonString $FilePrefix))
    [void]$json.Append(',"reportKey":').Append((ConvertTo-TRJsonString ('{0}|{1}|{2}' -f $FilePrefix, [string]$meta.StartedUtc, [string]$meta.TenantId)))
    [void]$json.Append(',"fileOverrides":').Append((ConvertTo-TREffortMapJson $script:TREffortFileOverrides))
    [void]$json.Append('},"plan":').Append((New-TRPlanModelJson $plan)).Append(',"findings":[')
    $first = $true
    foreach ($f in $all) {
        if (-not $first) { [void]$json.Append(',') }
        $first = $false
        [void]$json.Append('{"Id":').Append((ConvertTo-TRJsonString $f.Id))
        foreach ($p in 'Category', 'Title', 'Status', 'Severity', 'Priority', 'Current', 'Recommendation', 'Reference') {
            [void]$json.Append(',"').Append($p).Append('":').Append((ConvertTo-TRJsonString ([string]$f.$p)))
        }
        [void]$json.Append(',"Frameworks":').Append((ConvertTo-TRJsonString $(if (Test-TRHasProperty $f 'Frameworks') { [string]$f.Frameworks } else { '' })))
        [void]$json.Append(',"StatusLabel":').Append((ConvertTo-TRJsonString (Get-TRStatusLabel $f.Status)))
        [void]$json.Append(',"EffortHours":').Append((ConvertTo-TRJsonString ([double]$f.EffortHours)))
        [void]$json.Append(',"AffectedCount":').Append((ConvertTo-TRJsonString ([int]$f.AffectedCount))).Append('}')
    }
    [void]$json.Append('],"opportunities":[')
    $first = $true
    foreach ($o in $opps) {
        if (-not $first) { [void]$json.Append(',') }
        $first = $false
        [void]$json.Append('{"Id":').Append((ConvertTo-TRJsonString $o.Id))
        foreach ($p in 'Category', 'Feature', 'Status', 'StatusLabel', 'LicensedVia', 'Evidence', 'Opportunity', 'Benefit', 'Reference') {
            [void]$json.Append(',"').Append($p).Append('":').Append((ConvertTo-TRJsonString ([string]$o.$p)))
        }
        [void]$json.Append(',"LicensedUsers":').Append((ConvertTo-TRJsonString ([int]$o.LicensedUsers)))
        [void]$json.Append(',"EffortDays":').Append((ConvertTo-TRJsonString ([double]$o.EffortDays))).Append('}')
    }
    [void]$json.Append('],"benchmarks":[')
    $first = $true
    foreach ($b in $bench) {
        if (-not $first) { [void]$json.Append(',') }
        $first = $false
        [void]$json.Append('{"Framework":').Append((ConvertTo-TRJsonString $b.Framework))
        foreach ($p in 'Id', 'Section', 'Title', 'Level', 'Profile', 'StatusLabel', 'Evidence', 'Guidance', 'Mapped', 'RelatedChecks', 'Licence') {
            [void]$json.Append(',"').Append($p).Append('":').Append((ConvertTo-TRJsonString ([string]$b.$p)))
        }
        [void]$json.Append('}')
    }
    [void]$json.Append('],"inventories":[')
    $first = $true
    foreach ($i in $invList) {
        if (-not $first) { [void]$json.Append(',') }
        $first = $false
        $rows = @($i.Rows)
        $cols = @()
        if ($rows.Count) { $cols = @($rows[0].PSObject.Properties | ForEach-Object { $_.Name }) }
        [void]$json.Append('{"name":').Append((ConvertTo-TRJsonString $i.Name)).Append(',"title":').Append((ConvertTo-TRJsonString $i.Title)).Append(',"description":').Append((ConvertTo-TRJsonString $i.Description)).Append(',"columns":').Append((ConvertTo-TRJsonArray $cols)).Append(',"rows":[')
        $firstRow = $true
        foreach ($r in $rows) {
            if (-not $firstRow) { [void]$json.Append(',') }
            $firstRow = $false
            $vals = foreach ($c in $cols) { $v = $r.$c; if ($v -is [bool]) { ConvertTo-TRYesNo $v } else { $v } }
            [void]$json.Append((ConvertTo-TRJsonArray @($vals)))
        }
        [void]$json.Append(']}')
    }
    [void]$json.Append(']}')
    [void]$sb.Append('<script id="tr-edits" type="application/json"></script><script id="tr-data" type="application/json">').Append($json.ToString()).Append('</script><script>').Append((Get-TRReportJs)).Append((Get-TREffortJs)).Append('</script></body></html>')
    $sb.ToString()
}

function Write-TRTextFile {
    param([string]$Path, [string]$Text)
    [IO.File]::WriteAllText($Path, $Text, (New-Object System.Text.UTF8Encoding($false)))
}

function Export-TRCsv {
    param($Rows, [string]$Path)
    $enc = if ($PSVersionTable.PSVersion.Major -ge 6) { 'utf8BOM' } else { 'UTF8' }
    $list = @($Rows | Where-Object { $null -ne $_ })
    if ($list.Count -eq 0) { Write-TRTextFile -Path $Path -Text ''; return }
    $list | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding $enc
}

function Write-TRReport {
    param(
        [Parameter(Mandatory = $true)]$Findings,
        [Parameter(Mandatory = $true)]$Inventories,
        $Opportunities = @(),
        $Benchmarks = @(),
        [Parameter(Mandatory = $true)][string]$OutputFolder
    )
    if (-not (Test-Path -LiteralPath $OutputFolder)) { New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null }
    $client = [string](Get-TRMeta 'ClientName')
    if (-not $client) { $client = [string](Get-TRMeta 'TenantName') }
    $safe = ($client -replace '[^A-Za-z0-9]+', '-').Trim('-')
    if (-not $safe) { $safe = 'Tenant' }
    $stamp = (ConvertTo-TRDate (Get-TRMeta 'StartedUtc'))
    if (-not $stamp) { $stamp = (Get-Date).ToUniversalTime() }
    $prefix = '{0}-{2}-Review-{1}' -f $safe, $stamp.ToLocalTime().ToString('yyyy-MM-dd'), $(if ((Get-TRPlatform) -eq 'Google') { 'Google-Workspace' } else { 'M365' })
    $htmlPath = Join-Path $OutputFolder ($prefix + '.html')
    $html = New-TRReportHtml -Findings $Findings -Inventories $Inventories -Opportunities $Opportunities -Benchmarks $Benchmarks -FilePrefix $prefix
    Write-TRTextFile -Path $htmlPath -Text $html
    $csvFolder = Join-Path $OutputFolder 'CSV'
    if (-not (Test-Path -LiteralPath $csvFolder)) { New-Item -ItemType Directory -Path $csvFolder -Force | Out-Null }
    $flat = foreach ($f in @($Findings)) {
        [pscustomobject][ordered]@{
            'ID'             = $f.Id
            'Category'       = $f.Category
            'Check'          = $f.Title
            'Status'         = (Get-TRStatusLabel $f.Status)
            'RAG'            = (Get-TRRag $f.Status)
            'Severity'       = $f.Severity
            'Priority'       = $f.Priority
            'Current state'  = $f.Current
            'Recommendation' = $f.Recommendation
            'Effort hours'   = $f.EffortHours
            'Affected items' = $f.AffectedCount
            'Reference'      = $f.Reference
            'Benchmarks'     = $(if (Test-TRHasProperty $f 'Frameworks') { $f.Frameworks } else { '' })
        }
    }
    Export-TRCsv -Rows $flat -Path (Join-Path $csvFolder ($prefix + '-Findings.csv'))
    $details = foreach ($f in @($Findings)) {
        foreach ($a in @($f.Affected)) {
            [pscustomobject][ordered]@{ 'ID' = $f.Id; 'Check' = $f.Title; 'Status' = (Get-TRStatusLabel $f.Status); 'Item' = $a.Item; 'Detail' = $a.Detail }
        }
    }
    Export-TRCsv -Rows $details -Path (Join-Path $csvFolder ($prefix + '-FindingDetails.csv'))
    $recs = foreach ($f in (@($Findings) | Where-Object { $_.Status -in @('Fail', 'Warning', 'Manual') } | Sort-Object Priority, Id)) {
        [pscustomobject][ordered]@{ 'Priority' = $f.Priority; 'ID' = $f.Id; 'Recommendation' = $f.Title; 'Detail' = $f.Recommendation; 'Area' = $f.Category; 'Status' = (Get-TRStatusLabel $f.Status); 'Effort hours' = $f.EffortHours }
    }
    Export-TRCsv -Rows $recs -Path (Join-Path $csvFolder ($prefix + '-Recommendations.csv'))
    $planRows = @(Get-TRActionPlanRows (Get-TRActionPlan -Findings $Findings -Opportunities $Opportunities))
    Export-TRCsv -Rows $planRows -Path (Join-Path $csvFolder ($prefix + '-ActionPlan.csv'))
    $oppRows = @($Opportunities | Where-Object { $null -ne $_ })
    if ($oppRows.Count) {
        $oppFlat = foreach ($o in $oppRows) {
            [pscustomobject][ordered]@{
                'ID'               = $o.Id
                'Category'         = $o.Category
                'Feature'          = $o.Feature
                'Status'           = $o.StatusLabel
                'Licensed users'   = $o.LicensedUsers
                'Licensed through' = $o.LicensedVia
                'Current use'      = $o.Evidence
                'Opportunity'      = $o.Opportunity
                'Benefit'          = $o.Benefit
                'Effort days'      = $o.EffortDays
                'Reference'        = $o.Reference
            }
        }
        Export-TRCsv -Rows $oppFlat -Path (Join-Path $csvFolder ($prefix + '-Opportunities.csv'))
    }
    $benchRows = @($Benchmarks | Where-Object { $null -ne $_ })
    if ($benchRows.Count) {
        $bFlat = foreach ($b in $benchRows) {
            [pscustomobject][ordered]@{
                'Framework'       = $b.Framework
                'ID'              = $b.Id
                'Section'         = $b.Section
                'Control'         = $b.Title
                'Level'           = $b.Level
                'Profile'         = $b.Profile
                'Status'          = $b.StatusLabel
                'Evidence'        = $b.Evidence
                'How to meet it'  = $b.Guidance
                'Mapped controls' = $b.Mapped
                'Related checks'      = $b.RelatedChecks
                'Licence needed'  = $b.Licence
                'Affected items'  = $b.AffectedCount
            }
        }
        Export-TRCsv -Rows $bFlat -Path (Join-Path $csvFolder ($prefix + '-Benchmarks.csv'))
        $bDetails = foreach ($b in $benchRows) {
            foreach ($a in @($b.Affected)) { [pscustomobject][ordered]@{ 'Framework' = $b.Framework; 'ID' = $b.Id; 'Control' = $b.Title; 'Status' = $b.StatusLabel; 'Item' = $a.Item; 'Detail' = $a.Detail } }
        }
        if (@($bDetails).Count) { Export-TRCsv -Rows $bDetails -Path (Join-Path $csvFolder ($prefix + '-BenchmarkDetails.csv')) }
    }
    foreach ($i in @($Inventories.Values)) {
        Export-TRCsv -Rows $i.Rows -Path (Join-Path $csvFolder ('{0}-{1}.csv' -f $prefix, $i.Name))
    }
    Write-TRLog ("Report written to {0}" -f $htmlPath) 'Success'
    $pdf = $null
    $packPdf = $null
    $want = Get-TRSetting 'CreatePdf' $true
    if ($want -eq $true -or [string]$want -eq 'True') {
        Set-TRProgress 98 'Creating the PDF report'
        $pdf = Export-TRPdf -HtmlPath $htmlPath -PdfPath (Join-Path $OutputFolder ($prefix + '.pdf'))
        $wantPack = Get-TRSetting 'CreateSummaryPdf' $true
        if ($pdf -and ($wantPack -eq $true -or [string]$wantPack -eq 'True')) {
            Set-TRProgress 99 'Creating the summary and action plan PDF'
            $tmp = Join-Path $OutputFolder ($prefix + '-pack.tmp.html')
            Write-TRTextFile -Path $tmp -Text ($html -replace '<body>', '<body class="pack">')
            $packPdf = Export-TRPdf -HtmlPath $tmp -PdfPath (Join-Path $OutputFolder ($prefix + '-Summary-and-Action-Plan.pdf'))
            Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        }
    }
    [pscustomobject]@{ Html = $htmlPath; Pdf = $pdf; SummaryPdf = $packPdf; CsvFolder = $csvFolder; Prefix = $prefix }
}
