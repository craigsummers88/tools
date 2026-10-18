$script:TRPlanThemes = [ordered]@{
    Identity  = @{ Name = 'Protect sign-ins and accounts'; Why = 'Most attacks start with a stolen or guessed password. These changes make it much harder for anyone to get into a staff account, even if they have the password.'; Staff = 'Staff may be asked to set up an authenticator app and could be prompted to sign in again on their devices.'; Input = 'Agree a date to tell staff, and confirm any shared or emergency accounts that need different treatment.' }
    Admin     = @{ Name = 'Lock down administrator access'; Why = 'Administrator accounts can change or delete anything. Keeping them few in number and well protected limits the damage if one is compromised.'; Staff = 'Only IT administrators are affected.'; Input = 'Confirm who genuinely needs administrator access.' }
    Email     = @{ Name = 'Strengthen email security'; Why = 'Email is the most common way criminals reach staff, through phishing and harmful attachments. These settings block more threats and stop email being quietly forwarded outside the business.'; Staff = 'Little change for staff. Some suspicious messages will be held in quarantine instead of reaching inboxes.'; Input = 'Tell us about any automatic forwarding to outside addresses that the business relies on.' }
    EmailAuth = @{ Name = 'Stop others sending email as you'; Why = 'SPF, DKIM and DMARC records prove your email is genuine. Without them, criminals can send convincing emails that look as if they come from you, to your staff, customers and suppliers.'; Staff = 'No change for staff.'; Input = 'Access to your DNS provider, and a list of other services that send email for you (for example invoicing or marketing systems).' }
    Devices   = @{ Name = 'Secure laptops, desktops and phones'; Why = 'Devices hold company data and are used to sign in. Managing, encrypting and updating them protects that data if a device is lost, stolen or infected.'; Staff = 'Devices may restart for updates, and staff may be asked to enrol phones or accept new settings.'; Input = 'Agree a small pilot group first, then a date for everyone else.' }
    DeviceMgmt = @{ Name = 'Keep device management working'; Why = 'Device management relies on certificates and connections to Apple and Google. If these lapse, company phones and tablets can no longer be managed or wiped, and fixing it can mean re-enrolling every device.'; Staff = 'No change for staff if this is done before the expiry date.'; Input = 'Access to the Apple or Google account that was used to set these up.' }
    Threat    = @{ Name = 'Detect and respond to threats'; Why = 'Security tools only help if they are switched on, cover every device and someone acts on their alerts.'; Staff = 'No change for staff.'; Input = 'Confirm who should receive security alerts, including out of hours.' }
    Files     = @{ Name = 'Control file sharing'; Why = 'Files shared with open links can be passed on to anyone. Tightening sharing reduces the chance of sensitive documents reaching the wrong people.'; Staff = 'Staff may need to share with named people rather than with anyone who has the link.'; Input = 'Agree how staff should share files with clients and suppliers.' }
    Collab    = @{ Name = 'Secure meetings, chat and groups'; Why = 'Settings for who can join meetings, message your staff and create groups decide how easily outsiders get in and how easily information leaks out.'; Staff = 'External guests may wait in a lobby or need an invitation to join.'; Input = 'Confirm which outside organisations staff need to work with.' }
    Apps      = @{ Name = 'Control connected apps'; Why = 'Apps connected to your accounts can often read email and files. Reviewing them, and requiring approval for new ones, stops data being handed to unsafe apps without anyone noticing.'; Staff = 'Staff will need approval before connecting new apps to their work account.'; Input = 'Confirm which connected apps are used for business.' }
    Data      = @{ Name = 'Protect and keep important information'; Why = 'Backup, retention, audit logging and data loss prevention help you meet obligations such as UK GDPR, recover deleted information and investigate problems.'; Staff = 'Staff may see a tip before sharing sensitive information outside the business.'; Input = 'Confirm how long different types of information must be kept.' }
    Access    = @{ Name = 'Tidy up who can see what'; Why = 'Over time people collect access to mailboxes, sites and groups they no longer need. Removing it limits what a leaver or an attacker could see.'; Staff = 'Some staff will lose access to mailboxes or sites they no longer use.'; Input = 'Confirm who should keep access.' }
    Licensing = @{ Name = 'Make sure licences are right'; Why = 'Unused or unsuitable licences cost money every month and can leave security features out of reach.'; Staff = 'No change for staff.'; Input = 'Approve any licence changes.' }
    Servers   = @{ Name = 'Patch, protect and back up servers'; Why = 'Servers hold your most important data and systems. Servers that are out of support, unpatched, unprotected or not backed up are the most common way ransomware gets in and causes lasting damage.'; Staff = 'Servers may need short, planned restarts outside working hours.'; Input = 'Agree a maintenance window, and budget for replacing any servers that are out of support.' }
    Ad        = @{ Name = 'Secure Active Directory'; Why = 'Active Directory controls sign-in to every PC and server. A weakness here can let one compromised account take over the whole network.'; Staff = 'Mostly no change. A few old accounts may be disabled and some service accounts given new passwords.'; Input = 'Confirm which old accounts and service accounts are still needed.' }
    Virt      = @{ Name = 'Keep virtualisation hosts healthy'; Why = 'One host runs many servers, so a problem there affects all of them. Old snapshots, unsupported versions and missing redundancy put every virtual server at risk.'; Staff = 'Hosts may need planned maintenance windows.'; Input = 'Agree maintenance windows and any budget for host upgrades.' }
    Linux     = @{ Name = 'Patch and harden Linux servers'; Why = 'Linux servers often run websites, databases and file transfers that face the internet. Keeping them patched and locked down stops them becoming a way in.'; Staff = 'Servers may need short, planned restarts outside working hours.'; Input = 'Agree a maintenance window and who owns each server.' }
    AzureSec  = @{ Name = 'Secure your Azure services'; Why = 'Cloud servers and services that are open to the internet, or have no security monitoring, are a frequent target for attackers.'; Staff = 'No change for staff.'; Input = 'Confirm which Azure services must be reachable from the internet.' }
    AzureRes  = @{ Name = 'Make sure Azure can recover'; Why = 'Backups and protection against accidental deletion mean a mistake or a ransomware attack does not become a lasting outage.'; Staff = 'No change for staff.'; Input = 'Confirm how much data you could afford to lose and how quickly systems must be back.' }
    AzureGov  = @{ Name = 'Control Azure access and cost'; Why = 'Clear ownership, budgets and removing unused resources stop surprise bills and limit who can change live systems.'; Staff = 'No change for staff.'; Input = 'Agree a monthly Azure budget and who should be alerted.' }
}

$script:TRPlanCategoryMap = @{
    'Identity and access' = 'Identity'; 'Privileged access' = 'Admin'
    'Exchange Online' = 'Email'; 'Gmail' = 'Email'
    'Email authentication' = 'EmailAuth'; 'Email DNS' = 'EmailAuth'
    'Intune and devices' = 'Devices'; 'Intune configuration health' = 'Devices'; 'Autopilot and enrolment' = 'Devices'; 'Windows security configuration' = 'Devices'; 'Devices' = 'Devices'
    'Intune connections' = 'DeviceMgmt'
    'Microsoft Defender XDR' = 'Threat'; 'Security operations' = 'Threat'; 'Microsoft Secure Score' = 'Threat'
    'SharePoint and OneDrive' = 'Files'; 'Drive and Docs' = 'Files'
    'Teams and groups' = 'Collab'; 'Calendar, Chat and Meet' = 'Collab'; 'Groups' = 'Collab'
    'Applications' = 'Apps'
    'Microsoft Purview' = 'Data'; 'Compliance' = 'Data'; 'Governance' = 'Data'
    'Permissions' = 'Access'
    'Licensing' = 'Licensing'
    'Windows servers' = 'Servers'; 'Active Directory' = 'Ad'; 'Hyper-V' = 'Virt'; 'VMware' = 'Virt'; 'Linux servers' = 'Linux'
    'Azure security' = 'AzureSec'; 'Azure resilience' = 'AzureRes'; 'Azure governance and cost' = 'AzureGov'
}

$script:TRPlanPhases = @(
    @{ Key = 'Must'; Name = 'Must do'; When = 'Start within 2 weeks'; Text = 'Serious gaps that leave the business open to attack, data loss or disruption today. These should be fixed first.' }
    @{ Key = 'Should'; Name = 'Should do'; When = 'Within 3 months'; Text = 'Important improvements that close real risks. Plan these into the next three months.' }
    @{ Key = 'Could'; Name = 'Could do'; When = 'Within 6 months'; Text = 'Good-practice improvements that tighten security further and bring you in line with the published benchmarks. Select an item to see what we found.' }
)

function Get-TRPlanTheme {
    param([string]$Category)
    $key = $script:TRPlanCategoryMap[$Category]
    $i = 0
    foreach ($k in $script:TRPlanThemes.Keys) {
        if ($k -eq $key) { $t = $script:TRPlanThemes[$k]; return [pscustomobject]@{ Key = $k; Order = $i; Name = $t.Name; Why = $t.Why; Staff = $t.Staff; Input = $t.Input } }
        $i++
    }
    [pscustomobject]@{ Key = ('Cat|' + $Category); Order = 100; Name = $Category; Why = ''; Staff = ''; Input = '' }
}

function Get-TRPlanPhaseKey {
    param($Finding)
    $p = [string]$Finding.Priority
    if ($p -eq 'P1') { return 'Must' }
    if ($p -eq 'P2') { return 'Should' }
    if ($p -eq 'P3') { if ([string]$Finding.Status -eq 'Manual') { return 'Confirm' } return 'Could' }
    ''
}

function Format-TRNumber {
    param([double]$Value, [string]$Format = '0.#')
    $Value.ToString($Format, [Globalization.CultureInfo]::InvariantCulture)
}

function Format-TREffort {
    param([double]$Hours, [double]$HoursPerDay = 7.5)
    if ($Hours -le 0) { return 'Minimal' }
    if ($Hours -lt $HoursPerDay) {
        $h = [Math]::Ceiling($Hours * 2) / 2
        if ($h -eq 0.5) { return '30 minutes' }
        return ('{0} {1}' -f (Format-TRNumber $h), $(if ($h -eq 1) { 'hour' } else { 'hours' }))
    }
    Format-TRDays ($Hours / $HoursPerDay)
}

function Format-TRDays {
    param([double]$Days)
    if ($Days -le 0) { return 'Minimal' }
    $d = [Math]::Ceiling($Days * 2) / 2
    '{0} {1}' -f (Format-TRNumber $d), $(if ($d -eq 1) { 'day' } else { 'days' })
}

function Format-TRMoney {
    param([double]$Amount, [string]$Symbol)
    $Symbol + (Format-TRNumber $Amount 'N0')
}

function Format-TRWeeks {
    param([int]$Start, [int]$Weeks)
    if ($Weeks -le 0) { return '' }
    if ($Weeks -eq 1) { return ('Week {0}' -f $Start) }
    'Weeks {0} to {1}' -f $Start, ($Start + $Weeks - 1)
}

function Get-TRActionPlan {
    param($Findings, $Opportunities = @())
    $hpd = [double](Get-TRSetting 'HoursPerDay' 7.5)
    if ($hpd -le 0) { $hpd = 7.5 }
    $cap = [double](Get-TRSetting 'PlanDaysPerWeek' 2)
    if ($cap -le 0) { $cap = 2 }
    $rate = [double](Get-TRSetting 'DayRate' 0)
    $sym = [string](Get-TRSetting 'CurrencySymbol' ([string][char]0xA3))
    $sevOrder = @{ High = 0; Medium = 1; Low = 2; Info = 3 }
    $all = @($Findings | Where-Object { $null -ne $_ })
    $phases = New-Object System.Collections.ArrayList
    $week = 1
    $totalDays = 0.0
    foreach ($p in $script:TRPlanPhases) {
        $items = @($all | Where-Object { (Get-TRPlanPhaseKey $_) -eq $p.Key })
        $groups = @{}
        foreach ($f in $items) {
            $t = Get-TRPlanTheme ([string]$f.Category)
            if (-not $groups.ContainsKey($t.Key)) { $groups[$t.Key] = [pscustomobject]@{ Theme = $t; Items = @(); Hours = 0.0; High = 0 } }
            $g = $groups[$t.Key]
            $g.Items += $f
            $g.Hours += [double]$f.EffortHours
            if ([string]$f.Severity -eq 'High') { $g.High++ }
        }
        foreach ($g in $groups.Values) { $g.Items = @($g.Items | Sort-Object @{ e = { $sevOrder[[string]$_.Severity] } }, @{ e = { if ($_.Status -eq 'Fail') { 0 } else { 1 } } }, Id) }
        $themes = @($groups.Values | Sort-Object @{ e = { $_.High }; Descending = $true }, @{ e = { $_.Theme.Order } }, @{ e = { $_.Theme.Name } })
        $hours = 0.0
        foreach ($f in $items) { $hours += [double]$f.EffortHours }
        $days = if ($hours -gt 0) { [Math]::Ceiling($hours / $hpd * 2) / 2 } else { 0 }
        $weeks = if ($items.Count) { [Math]::Max(1, [int][Math]::Ceiling($days / $cap)) } else { 0 }
        [void]$phases.Add([pscustomobject]@{
                Key = $p.Key; Name = $p.Name; When = $p.When; Text = $p.Text; Items = $items; Themes = $themes
                Hours = $hours; Days = $days; Weeks = $weeks; Start = $week; Cost = $(if ($rate -gt 0) { $days * $rate } else { $null })
            })
        $week += $weeks
        $totalDays += $days
    }
    $opps = @($Opportunities | Where-Object { $null -ne $_ -and $_.Status -in @('NotUsed', 'Partial') } | Sort-Object @{ e = { if ($_.Status -eq 'NotUsed') { 0 } else { 1 } } }, @{ e = { [int]$_.LicensedUsers }; Descending = $true }, Id)
    $ld = 0.0
    foreach ($o in $opps) { $ld += [double]$o.EffortDays }
    $ld = [Math]::Ceiling($ld * 2) / 2
    $lw = if ($opps.Count) { [Math]::Max(1, [int][Math]::Ceiling($ld / $cap)) } else { 0 }
    $lic = [pscustomobject]@{
        Key = 'Licences'; Name = 'Use what you already pay for'; When = 'After the fixes above'
        Text = 'Features included in your current licences that are not set up yet. Using them adds protection or saves time at no extra licence cost.'
        Items = $opps; Days = $ld; Weeks = $lw; Start = $week; Cost = $(if ($rate -gt 0) { $ld * $rate } else { $null })
    }
    $week += $lw
    $confirm = @($all | Where-Object { $_.Status -eq 'Manual' } | Sort-Object @{ e = { $sevOrder[[string]$_.Severity] } }, Id)
    $quick = @($all | Where-Object { (Get-TRPlanPhaseKey $_) -in @('Must', 'Should') -and [double]$_.EffortHours -gt 0 -and [double]$_.EffortHours -le 1 }).Count
    [pscustomobject]@{
        Phases = $phases.ToArray(); Licences = $lic; Confirm = $confirm
        NotAssessed = @($all | Where-Object { $_.Status -eq 'NotAssessed' }).Count
        QuickWins = $quick; HoursPerDay = $hpd; Capacity = $cap; Rate = $rate; Symbol = $sym
        FixDays = $totalDays; FixWeeks = ($lic.Start - 1); TotalWeeks = ($week - 1)
    }
}

function Get-TRPlanSentence {
    param($Plan)
    $m = $Plan.Phases[0]; $s = $Plan.Phases[1]; $c = $Plan.Phases[2]
    $parts = @()
    if ($m.Items.Count) { $parts += ('{0} should be started within two weeks (about {1})' -f (Format-TRN $m.Items.Count 'must-do item'), (Format-TRDays $m.Days)) }
    if ($s.Items.Count) { $parts += ('{0} within three months (about {1})' -f (Format-TRN $s.Items.Count 'should-do item'), (Format-TRDays $s.Days)) }
    if ($c.Items.Count) { $parts += ('{0} within six months (about {1})' -f (Format-TRN $c.Items.Count 'could-do item'), (Format-TRDays $c.Days)) }
    if (-not $parts.Count) { return 'No fixes are needed: every assessed check passed.' }
    $t = ''
    if (-not $m.Items.Count) { $t = 'No must-do items were found. ' }
    if ($parts.Count -eq 1) { $t += $parts[0] }
    else { $t += (($parts[0..($parts.Count - 2)] -join ', ') + ' and ' + $parts[-1]) }
    $t = $t.Substring(0, 1).ToUpper() + $t.Substring(1) + '.'
    $t += (' In total this is about {0} of engineer time, or roughly {1} at {2} engineer {3} a week.' -f (Format-TRDays $Plan.FixDays), (Format-TRN $Plan.FixWeeks 'week'), (Format-TRNumber $Plan.Capacity), $(if ($Plan.Capacity -eq 1) { 'day' } else { 'days' }))
    if ($Plan.QuickWins) { $t += (' {0} of the must-do and should-do items {1} quick {2} of an hour or less.' -f $Plan.QuickWins, (Select-TRText $Plan.QuickWins 'is a' 'are'), (Select-TRText $Plan.QuickWins 'win' 'wins')) }
    if ($Plan.Licences.Items.Count) { $t += (' A further {0} you already pay for could be put to use (about {1}).' -f (Format-TRN $Plan.Licences.Items.Count 'licensed feature'), (Format-TRDays $Plan.Licences.Days)) }
    if ($Plan.Rate -gt 0) {
        $fix = 0.0
        foreach ($p in $Plan.Phases) { $fix += [double]$p.Cost }
        $t += (' Indicative cost of the fixes: {0} at {1} a day.' -f (Format-TRMoney $fix $Plan.Symbol), (Format-TRMoney $Plan.Rate $Plan.Symbol))
    }
    $t
}

function New-TRPlanCardsHtml {
    param($Plan)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<div class="ap-phases">')
    foreach ($p in @($Plan.Phases) + @($Plan.Licences)) {
        if ($p.Key -eq 'Licences' -and -not $p.Items.Count) { continue }
        $n = @($p.Items).Count
        $unit = if ($p.Key -eq 'Licences') { Select-TRText $n 'feature' 'features' } else { Select-TRText $n 'item' 'items' }
        $eff = if ($n) { 'About ' + (Format-TRDays $p.Days) } else { 'Nothing found' }
        if ($n -and $p.Days -le 0) { $eff = 'Minimal effort' }
        $cost = if ($null -ne $p.Cost -and $n) { '<div class="c">Indicative cost ' + (ConvertTo-TRHtml (Format-TRMoney $p.Cost $Plan.Symbol)) + '</div>' } else { '' }
        [void]$sb.Append(('<div class="ap-card ph-{0}"><div class="l">{1}</div><div class="v">{2} <span>{3}</span></div><div class="w">{4}</div><div class="e">{5}</div>{6}</div>' -f $p.Key, (ConvertTo-TRHtml $p.Name), $n, $unit, (ConvertTo-TRHtml $p.When), (ConvertTo-TRHtml $eff), $cost))
    }
    [void]$sb.Append('</div>')
    $sb.ToString()
}

function New-TRPlanSummaryHtml {
    param($Plan)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<h3>What needs doing</h3>')
    [void]$sb.Append((New-TRPlanCardsHtml $Plan))
    [void]$sb.Append(('<p class="lead">{0} <a href="#actionplan" data-tab-link="actionplan">See the action plan</a>.</p>' -f (ConvertTo-TRHtml (Get-TRPlanSentence $Plan))))
    $top = @(Get-TRPlanTop $Plan 10)
    if ($top.Count) {
        [void]$sb.Append('<h3>Top priorities</h3><div class="table-wrap static"><table><thead><tr><th>When</th><th>What good looks like</th><th>What we found</th><th class="num">Effort</th></tr></thead><tbody>')
        foreach ($f in $top) {
            $k = Get-TRPlanPhaseKey $f
            [void]$sb.Append(('<tr><td><span class="chip ph-{0}">{1}</span></td><td><a href="#" data-goto="f-{2}">{3}</a></td><td>{4}</td><td class="num nw">{5}</td></tr>' -f $k, $(if ($k -eq 'Must') { 'Must do' } else { 'Should do' }), (ConvertTo-TRHtml $f.Id), (ConvertTo-TRHtml $f.Title), (ConvertTo-TRHtml (Get-TRShortText $f.Current)), (Format-TREffort ([double]$f.EffortHours) $Plan.HoursPerDay)))
        }
        [void]$sb.Append('</tbody></table></div>')
    }
    $sb.ToString()
}

function Get-TRPlanTop {
    param($Plan, [int]$Max = 10)
    $out = New-Object System.Collections.ArrayList
    foreach ($p in @($Plan.Phases[0], $Plan.Phases[1])) {
        $lists = @($p.Themes | ForEach-Object { , @($_.Items) })
        $i = 0
        while ($out.Count -lt $Max) {
            $added = $false
            foreach ($l in $lists) {
                if ($i -lt $l.Count -and $out.Count -lt $Max) { [void]$out.Add($l[$i]); $added = $true }
            }
            if (-not $added) { break }
            $i++
        }
        if ($out.Count -ge $Max) { break }
    }
    $out.ToArray()
}

function Get-TRShortText {
    param([string]$Text, [int]$Max = 260)
    if (-not $Text -or $Text.Length -le $Max) { return $Text }
    $cut = $Text.Substring(0, $Max)
    $sp = $cut.LastIndexOf(' ')
    if ($sp -gt $Max - 40) { $cut = $cut.Substring(0, $sp) }
    $cut.TrimEnd(',', ';', ' ') + '...'
}

function New-TRActionPlanHtml {
    param($Plan, [int]$Number, [string]$Client)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append(('<section id="tab-actionplan" class="tab"><h2>{0}. Action plan</h2>' -f $Number))
    $capText = '{0} engineer {1} a week' -f (Format-TRNumber $Plan.Capacity), $(if ($Plan.Capacity -eq 1) { 'day' } else { 'days' })
    [void]$sb.Append(('<p class="note">{0}</p>' -f (ConvertTo-TRHtml ('This plan turns the findings into work, grouped by what it protects and ordered by urgency. Must do items are serious gaps to fix first, should do items are important improvements, and could do items are good practice. Effort is the estimated engineer time to make each change; it is for planning only and does not include time for agreeing changes, telling staff or testing with {0}.' -f $Client))))
    [void]$sb.Append((New-TRPlanCardsHtml $Plan))
    [void]$sb.Append(('<p class="lead">{0}</p>' -f (ConvertTo-TRHtml (Get-TRPlanSentence $Plan))))
    $rows = @(@($Plan.Phases) + @($Plan.Licences) | Where-Object { $_.Weeks -gt 0 })
    if ($rows.Count -and $Plan.TotalWeeks -gt 0) {
        $tw = [double]$Plan.TotalWeeks
        [void]$sb.Append('<h3>Indicative timeline</h3><div class="tl">')
        $step = if ($tw -le 12) { 1 } elseif ($tw -le 26) { 2 } elseif ($tw -le 52) { 4 } else { 8 }
        [void]$sb.Append('<div class="tl-row tl-scale"><div></div><div class="tl-track">')
        for ($w = 1; $w -le $tw; $w += $step) { [void]$sb.Append(('<span style="left:{0}%">{1}</span>' -f (Format-TRNumber (100 * ($w - 1) / $tw) '0.##'), $w)) }
        [void]$sb.Append('</div><div class="tl-when">Week</div></div>')
        foreach ($r in $rows) {
            $left = 100 * ($r.Start - 1) / $tw
            $width = 100 * $r.Weeks / $tw
            [void]$sb.Append(('<div class="tl-row"><div class="tl-label">{0}</div><div class="tl-track"><div class="tl-bar ph-{1}" style="left:{2}%;width:{3}%"></div></div><div class="tl-when">{4}</div></div>' -f (ConvertTo-TRHtml $r.Name), $r.Key, (Format-TRNumber $left '0.##'), (Format-TRNumber $width '0.##'), (Format-TRWeeks $r.Start $r.Weeks)))
        }
        [void]$sb.Append(('<p class="tl-note">{0}</p></div>' -f (ConvertTo-TRHtml ('Based on {0}. With more engineer time the phases can overlap and finish sooner. Some licensed features overlap with the fixes, so that work may take less time once the earlier phases are done.' -f $capText))))
    }
    $n = 0
    foreach ($p in $Plan.Phases) {
        $n++
        [void]$sb.Append(('<h3 class="ap-ph"><span class="chip ph-{0}">{1}</span>{2}: {3}</h3><p class="ap-intro">{4}</p>' -f $p.Key, $n, (ConvertTo-TRHtml $p.Name), (ConvertTo-TRHtml $p.When.ToLower()), (ConvertTo-TRHtml $p.Text)))
        if (-not $p.Items.Count) {
            [void]$sb.Append(('<p class="ap-none">{0}</p>' -f $(if ($p.Key -eq 'Must') { 'Nothing in this group. No serious gaps were found in the areas reviewed.' } else { 'Nothing in this group.' })))
            continue
        }
        foreach ($g in $p.Themes) {
            [void]$sb.Append(('<div class="ap-theme"><div class="ap-head"><h4>{0}</h4><span class="ap-eff">About {1}</span></div>' -f (ConvertTo-TRHtml $g.Theme.Name), (ConvertTo-TRHtml (Format-TREffort $g.Hours $Plan.HoursPerDay))))
            if ($g.Theme.Why) { [void]$sb.Append(('<p class="ap-why"><b>Why it matters.</b> {0}</p>' -f (ConvertTo-TRHtml $g.Theme.Why))) }
            $compact = $p.Key -eq 'Could'
            [void]$sb.Append($(if ($compact) { '<ul class="ap-items compact">' } else { '<ul class="ap-items">' }))
            foreach ($f in $g.Items) {
                $found = if ($compact) { '' } else { '<span class="found">We found: {0}</span>' -f (ConvertTo-TRHtml (Get-TRShortText $f.Current)) }
                [void]$sb.Append(('<li><a class="goal" href="#" data-goto="f-{0}">{1}</a><span class="h">{2}</span>{3}</li>' -f (ConvertTo-TRHtml $f.Id), (ConvertTo-TRHtml $f.Title), (ConvertTo-TRHtml (Format-TREffort ([double]$f.EffortHours) $Plan.HoursPerDay)), $found))
            }
            [void]$sb.Append('</ul>')
            if ($g.Theme.Staff -or $g.Theme.Input) { [void]$sb.Append(('<div class="ap-foot"><div><b>What your staff will notice</b>{0}</div><div><b>What we need from you</b>{1}</div></div>' -f (ConvertTo-TRHtml $g.Theme.Staff), (ConvertTo-TRHtml $g.Theme.Input))) }
            [void]$sb.Append('</div>')
        }
    }
    $lic = $Plan.Licences
    if ($lic.Items.Count) {
        [void]$sb.Append(('<h3 class="ap-ph"><span class="chip ph-Licences">4</span>{0}</h3><p class="ap-intro">{1}</p>' -f (ConvertTo-TRHtml $lic.Name), (ConvertTo-TRHtml $lic.Text)))
        [void]$sb.Append('<div class="table-wrap static"><table><thead><tr><th>Feature</th><th>Now</th><th>What it gives you</th><th class="num">Effort</th></tr></thead><tbody>')
        foreach ($o in $lic.Items) {
            [void]$sb.Append(('<tr><td><a href="#" data-goto="o-{0}">{1}</a></td><td><span class="chip o-{2}">{3}</span></td><td>{4}</td><td class="num">{5}</td></tr>' -f (ConvertTo-TRHtml $o.Id), (ConvertTo-TRHtml $o.Feature), $o.Status, (ConvertTo-TRHtml $o.StatusLabel), (ConvertTo-TRHtml $o.Benefit), (Format-TRDays ([double]$o.EffortDays))))
        }
        [void]$sb.Append('</tbody></table></div>')
    }
    if ($Plan.Confirm.Count) {
        [void]$sb.Append('<h3>Things to confirm with you</h3><p class="ap-intro">These could not be checked automatically. We will go through them with you.</p><ul class="ap-items ap-confirm">')
        foreach ($f in $Plan.Confirm) { [void]$sb.Append(('<li><a class="goal" href="#" data-goto="f-{0}">{1}</a><span class="found">{2}</span></li>' -f (ConvertTo-TRHtml $f.Id), (ConvertTo-TRHtml $f.Title), (ConvertTo-TRHtml (Get-TRShortText $f.Current)))) }
        [void]$sb.Append('</ul>')
    }
    if ($Plan.NotAssessed) { [void]$sb.Append(('<p class="tl-note">{0} could not be assessed because the data was not available. They are not included in this plan; the Method and limitations section explains why.</p>' -f (ConvertTo-TRHtml (Format-TRN $Plan.NotAssessed 'check')))) }
    [void]$sb.Append('</section>')
    $sb.ToString()
}

function Get-TRActionPlanRows {
    param($Plan)
    $n = 0
    foreach ($p in $Plan.Phases) {
        $n++
        foreach ($g in $p.Themes) {
            foreach ($f in $g.Items) {
                [pscustomobject][ordered]@{
                    'Phase' = ('{0}. {1}' -f $n, $p.Name); 'When' = $p.When; 'Theme' = $g.Theme.Name; 'What good looks like' = $f.Title; 'What we found' = $f.Current
                    'Effort hours' = $f.EffortHours; 'Why it matters' = $g.Theme.Why; 'What staff will notice' = $g.Theme.Staff; 'What we need from you' = $g.Theme.Input; 'ID' = $f.Id; 'Severity' = $f.Severity
                }
            }
        }
    }
    foreach ($o in $Plan.Licences.Items) {
        [pscustomobject][ordered]@{
            'Phase' = ('4. ' + $Plan.Licences.Name); 'When' = $Plan.Licences.When; 'Theme' = $o.Category; 'What good looks like' = $o.Feature; 'What we found' = $o.Evidence
            'Effort hours' = ([double]$o.EffortDays * $Plan.HoursPerDay); 'Why it matters' = $o.Benefit; 'What staff will notice' = ''; 'What we need from you' = ''; 'ID' = $o.Id; 'Severity' = ''
        }
    }
    foreach ($f in $Plan.Confirm) {
        [pscustomobject][ordered]@{
            'Phase' = 'To confirm'; 'When' = 'At the review meeting'; 'Theme' = (Get-TRPlanTheme ([string]$f.Category)).Name; 'What good looks like' = $f.Title; 'What we found' = $f.Current
            'Effort hours' = ''; 'Why it matters' = ''; 'What staff will notice' = ''; 'What we need from you' = ''; 'ID' = $f.Id; 'Severity' = $f.Severity
        }
    }
}
