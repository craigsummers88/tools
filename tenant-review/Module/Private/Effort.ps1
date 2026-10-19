$script:TREffortOverrides = @{ Findings = @{}; Opportunities = @{} }
$script:TREffortFileOverrides = @{ Findings = @{}; Opportunities = @{} }
$script:TREffortFileName = 'EffortOverrides.json'

function Get-TRPairs {
    param($Object)
    if ($null -eq $Object) { return }
    if ($Object -is [System.Collections.IDictionary]) {
        foreach ($k in @($Object.Keys)) { [pscustomobject]@{ Name = [string]$k; Value = $Object[$k] } }
        return
    }
    if ($Object -is [string] -or $Object -is [ValueType]) { return }
    foreach ($p in $Object.PSObject.Properties) { [pscustomobject]@{ Name = [string]$p.Name; Value = $p.Value } }
}

function ConvertTo-TREffortNumber {
    param($Value)
    if ($null -eq $Value) { return $null }
    $d = 0.0
    if ($Value -is [ValueType]) { try { $d = [double]$Value } catch { return $null } }
    elseif (-not [double]::TryParse(([string]$Value).Trim(), [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$d)) { return $null }
    if ([double]::IsNaN($d) -or $d -lt 0 -or $d -gt 10000) { return $null }
    $d
}

function Add-TREffortOverrides {
    param([hashtable]$Map, $Source)
    $n = 0
    foreach ($pair in @(Get-TRPairs $Source)) {
        if ($pair.Name -like '_*') { continue }
        if ($pair.Name -in @('Findings', 'Opportunities')) {
            foreach ($q in @(Get-TRPairs $pair.Value)) {
                $v = ConvertTo-TREffortNumber $q.Value
                if ($null -ne $v -and $q.Name -notlike '_*') { $Map[$pair.Name][$q.Name.Trim().ToUpperInvariant()] = $v; $n++ }
            }
            continue
        }
        $v = ConvertTo-TREffortNumber $pair.Value
        if ($null -eq $v) { continue }
        $kind = if ($pair.Name -match '^G?OPP-') { 'Opportunities' } else { 'Findings' }
        $Map[$kind][$pair.Name.Trim().ToUpperInvariant()] = $v
        $n++
    }
    $n
}

function Import-TREffortOverrides {
    param([string]$Folder)
    $map = @{ Findings = @{}; Opportunities = @{} }
    $fileMap = @{ Findings = @{}; Opportunities = @{} }
    $cfg = Get-TRSetting 'EffortOverrides' $null
    if ($null -ne $cfg) {
        $n = Add-TREffortOverrides -Map $map -Source $cfg
        if ($n) { Write-TRLog ('Using {0} from EffortOverrides in config.json.' -f (Format-TRN $n 'standard effort estimate')) }
    }
    if ($Folder) {
        $file = Join-Path $Folder $script:TREffortFileName
        if (Test-Path -LiteralPath $file) {
            try {
                $text = [IO.File]::ReadAllText($file, [Text.Encoding]::UTF8).TrimStart([char]0xFEFF)
                $obj = ConvertFrom-Json -InputObject $text -ErrorAction Stop
                $n = Add-TREffortOverrides -Map $fileMap -Source $obj
                foreach ($kind in 'Findings', 'Opportunities') { foreach ($k in @($fileMap[$kind].Keys)) { $map[$kind][$k] = $fileMap[$kind][$k] } }
                Write-TRLog ('Using {0} saved for this review in {1}.' -f (Format-TRN $n 'effort change'), $file)
            }
            catch { Write-TRLog ('Could not read the effort changes in {0}: {1}' -f $file, $_.Exception.Message) 'Warn' }
        }
    }
    $script:TREffortOverrides = $map
    $script:TREffortFileOverrides = $fileMap
}

function Get-TREffortValue {
    param([ValidateSet('Findings', 'Opportunities')][string]$Kind, [string]$Id, [double]$Default)
    $m = $script:TREffortOverrides
    if ($m -and $m[$Kind] -and $Id -and $m[$Kind].ContainsKey($Id.ToUpperInvariant())) { return [double]$m[$Kind][$Id.ToUpperInvariant()] }
    $Default
}

function Format-TRHoursText {
    param([double]$Hours)
    if ($Hours -le 0) { return 'Minimal' }
    if ($Hours -lt 1) { return ('{0} minutes' -f [int][Math]::Round($Hours * 60)) }
    '{0} {1}' -f (Format-TRNumber $Hours '0.##'), $(if ($Hours -eq 1) { 'hour' } else { 'hours' })
}

function Format-TRDaysText {
    param([double]$Days)
    if ($Days -le 0) { return 'Minimal' }
    '{0} {1}' -f (Format-TRNumber $Days '0.##'), $(if ($Days -eq 1) { 'day' } else { 'days' })
}

function ConvertTo-TREffortMapJson {
    param($Map)
    $parts = foreach ($kind in 'Findings', 'Opportunities') {
        $m = if ($Map) { $Map[$kind] } else { $null }
        $inner = if ($m) { @($m.Keys | Sort-Object | ForEach-Object { (ConvertTo-TRJsonString ([string]$_)) + ':' + (ConvertTo-TRJsonString ([double]$m[$_])) }) } else { @() }
        (ConvertTo-TRJsonString $kind) + ':{' + ($inner -join ',') + '}'
    }
    '{' + (@($parts) -join ',') + '}'
}

function Get-TREditBarHtml {
    '<div class="edit-bar" id="edit-bar" hidden><div class="msg"><b>Editing effort.</b> Select any highlighted figure and type a new value, for example 30m, 2h or 1.5d. Totals, the action plan, the timeline and costs update as you go. <span id="edit-count"></span> <span id="edit-msg" class="edit-msg"></span></div><button class="btn" type="button" id="edit-save" title="Save the changes to a file the app uses when you rebuild the report, so the PDFs and CSV files match">Save changes for rebuild</button><button class="btn secondary" type="button" id="edit-copy" title="Save a copy of this report with the new figures">Save edited copy</button><button class="btn secondary" type="button" id="edit-undo" data-edit-needs="1">Undo all changes</button><button class="btn secondary" type="button" id="edit-done">Finish editing</button></div>'
}

function Get-TREffortJs {
    @'
(function(){
var data=window.__trData;if(!data||!data.plan)return;
var P=data.plan,M=data.meta||{};
function $(s,r){return (r||document).querySelector(s)}function $$(s,r){return Array.prototype.slice.call((r||document).querySelectorAll(s))}
function esc(s){return String(s===null||s===undefined?'':s).replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]})}
var origF={},origO={};
data.findings.forEach(function(f){origF[f.Id]=+f.EffortHours||0});
data.opportunities.forEach(function(o){origO[o.Id]=+o.EffortDays||0});
var E={f:{},o:{}};
var store='tr-effort|'+(M.reportKey||M.filePrefix||'report');
function readJson(t){try{if(t&&String(t).trim())return JSON.parse(t)}catch(e){}return null}
function readStored(){try{return readJson(window.localStorage.getItem(store))}catch(e){return null}}
function save(){try{window.localStorage.setItem(store,JSON.stringify(E))}catch(e){}}
function tidy(){[['f',origF],['o',origO]].forEach(function(p){var k=p[0],orig=p[1];Object.keys(E[k]).forEach(function(id){var v=+E[k][id];if(!(id in orig)||isNaN(v)||v<0||Math.abs(v-orig[id])<1e-9)delete E[k][id];else E[k][id]=v})})}
var embedded=readJson(($('#tr-edits')||{}).textContent),stored=readStored(),start=stored||embedded;
if(start){E.f=start.f||{};E.o=start.o||{};tidy()}
function hF(id){return (id in E.f)?E.f[id]:(origF[id]||0)}
function dO(id){return (id in E.o)?E.o[id]:(origO[id]||0)}
var hpd=+P.hpd||7.5,cap=+P.cap||2,rate=+P.rate||0,sym=P.sym||'';
function num(v,dp){var m=Math.pow(10,dp===undefined?1:dp);return String(Math.round(v*m)/m)}
function n1(v){return Number(v).toLocaleString('en-GB',{minimumFractionDigits:1,maximumFractionDigits:1})}
function money(v){return sym+Math.round(v).toLocaleString('en-GB')}
function fmtDays(d){if(d<=0)return 'Minimal';var x=Math.ceil(d*2)/2;return num(x)+' '+(x===1?'day':'days')}
function fmtEffort(h){if(h<=0)return 'Minimal';if(h<hpd){var x=Math.ceil(h*2)/2;if(x===0.5)return '30 minutes';return num(x)+' '+(x===1?'hour':'hours')}return fmtDays(h/hpd)}
function fmtHours(h){if(h<=0)return 'Minimal';if(h<1)return Math.round(h*60)+' minutes';return num(h,2)+' '+(h===1?'hour':'hours')}
function fmtDaysRaw(d){if(d<=0)return 'Minimal';return num(d,2)+' '+(d===1?'day':'days')}
function plural(n,one,many){return n===1?'1 '+one:n+' '+(many||one+'s')}
function fmtWeeks(s,w){if(w<=0)return '';if(w===1)return 'Week '+s;return 'Weeks '+s+' to '+(s+w-1)}
function fmtFor(v,f){switch(f){case 'E':return fmtEffort(v);case 'H':return fmtHours(v);case 'N':return v>0?num(v,2):'';case 'D':return fmtDays(v);case 'DR':return fmtDaysRaw(v);case 'N1':return n1(v);case 'D1':return n1(Math.round(v/hpd*10)/10)}return String(v)}
function compute(){var week=1,total=0,ph=[];
P.phases.forEach(function(p){var h=0;p.items.forEach(function(id){h+=hF(id)});var d=h>0?Math.ceil(h/hpd*2)/2:0;var w=p.items.length?Math.max(1,Math.ceil(d/cap)):0;ph.push({key:p.key,name:p.name,when:p.when,n:p.items.length,days:d,weeks:w,start:week,cost:rate>0?d*rate:null});week+=w;total+=d});
var ld=0;P.lic.items.forEach(function(id){ld+=dO(id)});ld=Math.ceil(ld*2)/2;var lw=P.lic.items.length?Math.max(1,Math.ceil(ld/cap)):0;
var lic={key:'Licences',name:P.lic.name,when:P.lic.when,n:P.lic.items.length,days:ld,weeks:lw,start:week,cost:rate>0?ld*rate:null};week+=lw;
var quick=0;P.phases.slice(0,2).forEach(function(p){p.items.forEach(function(id){var h=hF(id);if(h>0&&h<=1)quick++})});
return {ph:ph,lic:lic,fixDays:total,fixWeeks:lic.start-1,totalWeeks:week-1,quick:quick}}
function sentence(R){var m=R.ph[0],s=R.ph[1],c=R.ph[2],parts=[];
if(m.n)parts.push(plural(m.n,'must-do item')+' should be started within two weeks (about '+fmtDays(m.days)+')');
if(s.n)parts.push(plural(s.n,'should-do item')+' within three months (about '+fmtDays(s.days)+')');
if(c.n)parts.push(plural(c.n,'could-do item')+' within six months (about '+fmtDays(c.days)+')');
if(!parts.length)return 'No fixes are needed: every assessed check passed.';
var t=m.n?'':'No must-do items were found. ';t+=parts.length===1?parts[0]:parts.slice(0,-1).join(', ')+' and '+parts[parts.length-1];
t=t.charAt(0).toUpperCase()+t.slice(1)+'.';
t+=' In total this is about '+fmtDays(R.fixDays)+' of engineer time, or roughly '+plural(R.fixWeeks,'week')+' at '+num(cap)+' engineer '+(cap===1?'day':'days')+' a week.';
if(R.quick)t+=' '+R.quick+' of the must-do and should-do items '+(R.quick===1?'is a':'are')+' quick '+(R.quick===1?'win':'wins')+' of an hour or less.';
if(R.lic.n)t+=' A further '+plural(R.lic.n,'licensed feature')+' you already pay for could be put to use (about '+fmtDays(R.lic.days)+').';
if(rate>0){var fix=0;R.ph.forEach(function(p){fix+=p.cost||0});t+=' Indicative cost of the fixes: '+money(fix)+' at '+money(rate)+' a day.'}
return t}
function cardsHtml(R){var h='';R.ph.concat([R.lic]).forEach(function(p){if(p.key==='Licences'&&!p.n)return;var unit=p.key==='Licences'?(p.n===1?'feature':'features'):(p.n===1?'item':'items');var eff=p.n?'About '+fmtDays(p.days):'Nothing found';if(p.n&&p.days<=0)eff='Minimal effort';var cost=(p.cost!==null&&p.n)?'<div class="c">Indicative cost '+esc(money(p.cost))+'</div>':'';
h+='<div class="ap-card ph-'+p.key+'"><div class="l">'+esc(p.name)+'</div><div class="v">'+p.n+' <span>'+unit+'</span></div><div class="w">'+esc(p.when)+'</div><div class="e">'+esc(eff)+'</div>'+cost+'</div>'});return h}
function tlHtml(R){var rows=R.ph.concat([R.lic]).filter(function(r){return r.weeks>0}),tw=R.totalWeeks;if(!rows.length||tw<=0)return '';
var step=tw<=12?1:tw<=26?2:tw<=52?4:8,h='<div class="tl-row tl-scale"><div></div><div class="tl-track">';
for(var w=1;w<=tw;w+=step)h+='<span style="left:'+num(100*(w-1)/tw,2)+'%">'+w+'</span>';
h+='</div><div class="tl-when">Week</div></div>';
rows.forEach(function(r){h+='<div class="tl-row"><div class="tl-label">'+esc(r.name)+'</div><div class="tl-track"><div class="tl-bar ph-'+r.key+'" style="left:'+num(100*(r.start-1)/tw,2)+'%;width:'+num(100*r.weeks/tw,2)+'%"></div></div><div class="tl-when">'+fmtWeeks(r.start,r.weeks)+'</div></div>'});
return h+'<p class="tl-note">Based on '+num(cap)+' engineer '+(cap===1?'day':'days')+' a week. With more engineer time the phases can overlap and finish sooner. Some licensed features overlap with the fixes, so that work may take less time once the earlier phases are done.</p>'}
function recalc(){var R=compute(),all=0,od=0,sums={};
data.findings.forEach(function(f){var h=hF(f.Id);f.EffortHours=h;all+=h});
data.opportunities.forEach(function(o){var d=dO(o.Id);o.EffortDays=d;od+=d});
P.phases.forEach(function(p){p.themes.forEach(function(t){var h=0;t.items.forEach(function(id){h+=hF(id)});sums['theme:'+p.key+':'+t.key]=h})});
$$('.eff[data-ef]').forEach(function(s){if(s.querySelector('input'))return;var id=s.getAttribute('data-ef');s.textContent=fmtFor(hF(id),s.getAttribute('data-fmt'));s.classList.toggle('edited',id in E.f)});
$$('.eff[data-eo]').forEach(function(s){if(s.querySelector('input'))return;var id=s.getAttribute('data-eo');s.textContent=fmtFor(dO(id),s.getAttribute('data-fmt'));s.classList.toggle('edited',id in E.o)});
$$('.effsum').forEach(function(s){var k=s.getAttribute('data-sum'),v=k==='all'?all:(k==='opps'?od:(sums[k]||0));s.textContent=fmtFor(v,s.getAttribute('data-fmt'))});
$$('[data-plan=cards]').forEach(function(el){el.innerHTML=cardsHtml(R)});
$$('[data-plan=sentence]').forEach(function(el){el.textContent=sentence(R)});
$$('[data-plan=timeline]').forEach(function(el){el.innerHTML=tlHtml(R)});
bar()}
window.__trEffortRecalc=recalc;
var editing=false,eb=$('#edit-bar'),be=$('#btn-edit'),undoArmed=false;
function count(){return Object.keys(E.f).length+Object.keys(E.o).length}
function bar(){var n=count();if(be)be.textContent=editing?'Finish editing':(n?'Edit effort ('+n+' changed)':'Edit effort');var c=$('#edit-count');if(c)c.textContent=n?plural(n,'estimate')+' changed from the original.':'No changes yet.';$$('[data-edit-needs]').forEach(function(b){b.disabled=!n});var u=$('#edit-undo');if(u&&!undoArmed)u.textContent='Undo all changes'}
function msg(t,bad){var m=$('#edit-msg');if(!m)return;m.textContent=t;m.classList.toggle('bad',!!bad);clearTimeout(msg.t);msg.t=setTimeout(function(){m.textContent=''},12000)}
function setEditing(on){editing=on;document.body.classList.toggle('editing',on);if(eb)eb.hidden=!on;undoArmed=false;bar()}
if(be)be.addEventListener('click',function(){setEditing(!editing)});
var bd=$('#edit-done');if(bd)bd.addEventListener('click',function(){setEditing(false)});
function toText(v,isF){if(v<=0)return '0';if(isF)return v<1?Math.round(v*60)+'m':num(v,2)+'h';return num(v,2)+'d'}
function parse(t,isF){t=String(t).trim().toLowerCase().replace(',','.');if(!t)return null;if(/^(minimal|none|nil|0)$/.test(t))return 0;
var m=t.match(/^(\d+(?:\.\d+)?|\.\d+)\s*(m|min|mins|minute|minutes|h|hr|hrs|hour|hours|d|day|days)?$/);if(!m)return null;
var v=parseFloat(m[1]),u=m[2]||(isF?'h':'d'),h=u.charAt(0)==='m'?v/60:(u.charAt(0)==='h'?v:v*hpd);if(!(h>=0)||h>5000)return null;
return isF?Math.round(h*1000)/1000:Math.round(h/hpd*10000)/10000}
function setValue(isF,id,v){var k=isF?'f':'o',orig=isF?(origF[id]||0):(origO[id]||0);if(Math.abs(v-orig)<1e-9)delete E[k][id];else E[k][id]=v;save();recalc()}
function startEdit(s){var isF=s.hasAttribute('data-ef'),id=s.getAttribute(isF?'data-ef':'data-eo'),cur=isF?hF(id):dO(id),old=s.textContent;
var inp=document.createElement('input');inp.type='text';inp.className='eff-input';inp.value=toText(cur,isF);inp.setAttribute('aria-label','Effort for '+id);
s.textContent='';s.appendChild(inp);inp.focus();inp.select();var done=false;
function finish(keep){if(done)return;done=true;var raw=inp.value,v=keep?parse(raw,isF):null;if(inp.parentNode)inp.parentNode.removeChild(inp);
if(v===null){s.textContent=old;if(keep&&String(raw).trim()!=='')msg('"'+raw+'" was not understood. Type a number with m, h or d, for example 30m, 2h or 1.5d.',true);return}setValue(isF,id,v)}
inp.addEventListener('keydown',function(e){if(e.key==='Enter'){e.preventDefault();finish(true)}else if(e.key==='Escape'){e.preventDefault();finish(false)}else if(e.key==='Tab'){finish(true)}});
inp.addEventListener('blur',function(){finish(true)})}
document.addEventListener('click',function(e){if(!editing)return;var s=e.target&&e.target.closest?e.target.closest('.eff'):null;if(!s||s.querySelector('input'))return;e.preventDefault();e.stopPropagation();startEdit(s)},true);
function download(name,text,mime){var a=document.createElement('a');a.href=URL.createObjectURL(new Blob([text],{type:mime}));a.download=name;document.body.appendChild(a);a.click();setTimeout(function(){URL.revokeObjectURL(a.href);a.remove()},500)}
function saveFile(name,text,mime,ext,desc){if(window.showSaveFilePicker){var acc={};acc[mime]=[ext];
try{return window.showSaveFilePicker({suggestedName:name,types:[{description:desc,accept:acc}]}).then(function(h){return h.createWritable().then(function(w){return w.write(new Blob([text],{type:mime})).then(function(){return w.close()})}).then(function(){return h.name||name})},function(err){if(err&&err.name==='AbortError')return null;download(name,text,mime);return name})}catch(e){}}
download(name,text,mime);return Promise.resolve(name)}
function folder(){try{if(location.protocol!=='file:')return '';var p=decodeURIComponent(location.pathname);if(/^\/[A-Za-z]:\//.test(p))p=p.slice(1).replace(/\//g,'\\');return p.replace(/[\\\/][^\\\/]*$/,'')}catch(e){return ''}}
function changesObj(){var o={_about:'Effort changes for this review, made in the HTML report. Findings are in hours and Opportunities in days. Keep this file in the review folder next to RawData.json and use Rebuild from saved data to update the HTML, PDF and CSV files.',Findings:{},Opportunities:{}},fo=M.fileOverrides||{};
['Findings','Opportunities'].forEach(function(k){var src=fo[k]||{};Object.keys(src).forEach(function(id){o[k][id]=src[id]})});
Object.keys(E.f).sort().forEach(function(id){o.Findings[id]=E.f[id]});Object.keys(E.o).sort().forEach(function(id){o.Opportunities[id]=E.o[id]});return o}
var bs=$('#edit-save');if(bs)bs.addEventListener('click',function(){var f=folder();saveFile('EffortOverrides.json',JSON.stringify(changesObj(),null,2),'application/json','.json','Effort changes').then(function(n){if(!n)return;msg('Saved '+n+'. It must be in the review folder'+(f?' ('+f+')':'')+', next to RawData.json. Then select Rebuild from saved data in the app so the PDFs and CSV files use the new figures.')})});
var bc=$('#edit-copy');if(bc)bc.addEventListener('click',function(){var was=editing;setEditing(false);var el=$('#tr-edits');if(el)el.textContent=JSON.stringify(E).replace(/</g,'\\u003c');
var html='<!doctype html>\n'+document.documentElement.outerHTML;if(was)setEditing(true);
saveFile((M.filePrefix||'Report')+'-edited.html',html,'text/html','.html','HTML report').then(function(n){if(n)msg('Saved '+n+'. It opens with your changes on any computer.')})});
var bu=$('#edit-undo');if(bu)bu.addEventListener('click',function(){if(!undoArmed){undoArmed=true;bu.textContent='Select again to undo all';setTimeout(function(){undoArmed=false;bar()},5000);return}undoArmed=false;E={f:{},o:{}};save();recalc();msg('All effort changes were undone.')});
var bk=$('#btn-pack');if(bk)bk.addEventListener('click',function(){var was=editing;if(was)setEditing(false);document.body.classList.add('pack');var done=false;function off(){if(done)return;done=true;document.body.classList.remove('pack');window.removeEventListener('afterprint',off);if(was)setEditing(true)}window.addEventListener('afterprint',off);window.print();setTimeout(off,1500)});
if(count())recalc();else bar();
})();
'@
}
