/**
 * ThreatIntel Platform v4 — Frontend
 * Single file: auth, OSINT, AI analysis, chat, comments, history, export
 */
'use strict';

/* ================================================================
   CONSTANTS
================================================================ */
var ABUSE_CATS = {
  1:'DNS Compromise',2:'DNS Poisoning',3:'Fraud Orders',4:'DDoS Attack',
  5:'FTP Brute-Force',6:'Ping of Death',7:'Phishing',8:'Fraud VoIP',
  9:'Open Proxy',10:'Web Spam',11:'Email Spam',12:'Blog Spam',
  13:'VPN IP',14:'Port Scan',15:'Hacking',16:'SQL Injection',
  17:'Spoofing',18:'Brute Force',19:'Bad Web Bot',20:'Exploited Host',
  21:'Web App Attack',22:'SSH',23:'IoT Targeted'
};

/* ================================================================
   IOC CLASSIFICATION
================================================================ */
function classifyIOC(v) {
  v = (v || '').trim();
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(v))                          return 'ip';
  if (/^https?:\/\//i.test(v))                                     return 'url';
  if (/^[a-fA-F0-9]{64}$/.test(v))                                 return 'sha256';
  if (/^[a-fA-F0-9]{40}$/.test(v))                                 return 'sha1';
  if (/^[a-fA-F0-9]{32}$/.test(v))                                 return 'md5';
  if (/^(?!https?:\/\/)([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/.test(v)) return 'domain';
  return 'unknown';
}
function typeGroup(t) { return ['md5','sha1','sha256'].includes(t) ? 'hash' : t; }

/* ================================================================
   SEEDED DEMO DATA (same IOC = same output, no Math.random)
================================================================ */
function seededNum(str, salt, min, max) {
  var h = 0, s = str + salt, i;
  for (i = 0; i < s.length; i++) h = (Math.imul(31, h) + s.charCodeAt(i)) | 0;
  return Math.floor(((Math.abs(h) % 100000) / 100000) * (max - min + 1)) + min;
}
function seededPick(str, salt, arr) { return arr[seededNum(str, salt, 0, arr.length - 1)]; }

function demoData(source, ioc, type) {
  switch (source) {
    case 'virustotal': {
      var total = 72, mal = seededNum(ioc,'vt-m',0,5), sus = seededNum(ioc,'vt-s',0,3);
      var harm = seededNum(ioc,'vt-h',38,55), und = Math.max(0, total-mal-sus-harm);
      return { source:'VirusTotal', icon:'🛡️', _demo:true,
        verdict: mal>4?'malicious':mal>1?'suspicious':'clean',
        stats:{malicious:mal,suspicious:sus,harmless:harm,undetected:und},
        engines:total, detections:mal, reputation:-(mal*4),
        firstSeen:'2024-08-22', lastSeen:new Date().toISOString().slice(0,10),
        lastAnalysis:new Date().toISOString().slice(0,16).replace('T',' ')+' UTC',
        categories:mal>4?['malware']:mal>1?['suspicious']:['harmless'],
        tags:mal>4?[seededPick(ioc,'tag',['trojan','rat','stealer','dropper','c2-server'])]:[] };
    }
    case 'abuseipdb': {
      if (typeGroup(type)!=='ip') return {source:'AbuseIPDB',icon:'⚠️',notApplicable:true,message:'AbuseIPDB only supports IP address lookups.'};
      var score=seededNum(ioc,'abu-s',0,20), trep=seededNum(ioc,'abu-r',0,30);
      return { source:'AbuseIPDB', icon:'⚠️', _demo:true,
        verdict:score>70?'malicious':score>30?'suspicious':'clean',
        abuseScore:score, totalReports:trep,
        distinctUsers:seededNum(ioc,'abu-u',0,Math.min(trep,10)),
        lastReported:score>0?new Date(Date.now()-seededNum(ioc,'abu-d',1,30)*86400000).toISOString().slice(0,10):'—',
        isp:seededPick(ioc,'isp',['AS13335 Cloudflare','AS16276 OVH','AS14061 DigitalOcean','AS20473 Vultr']),
        usageType:seededPick(ioc,'ut',['Data Center/Web Hosting','Commercial','Fixed Line ISP']),
        country:seededPick(ioc,'cc',['US','DE','NL','GB','FR']),
        countryName:seededPick(ioc,'cn',['United States','Germany','Netherlands','United Kingdom','France']),
        isWhitelisted:false, domain:'hosting-provider.net', ipVersion:4,
        categories:score>30?[seededPick(ioc,'cat',[10,14,18,22])]:[] };
    }
    case 'hybrid': {
      var det=seededNum(ioc,'ar-d',0,100)>72;
      var ts=det?seededNum(ioc,'ar-ts',55,85):seededNum(ioc,'ar-ts2',0,20);
      var fams=['Emotet','AgentTesla','AsyncRAT','Remcos','QakBot','RedLine'];
      var behavs=['Drops executable to %TEMP%','Creates scheduled task for persistence',
        'Modifies Windows registry Run key','Communicates with C2 via HTTPS',
        'Disables Windows Defender','Reads browser credentials'];
      return { source:'Hybrid Analysis', icon:'🔬', _demo:true,
        verdict:det?(ts>70?'malicious':'suspicious'):'clean',
        detected:det, threatScore:ts,
        malwareFamily:det?seededPick(ioc,'ar-f',fams):null,
        behavior:det?behavs.slice(0,seededNum(ioc,'ar-bc',2,4)):[],
        networkIndicators:det?seededNum(ioc,'ar-n',3,15):0,
        droppedFiles:det?seededNum(ioc,'ar-df',1,4):0,
        registryChanges:det?seededNum(ioc,'ar-rc',2,10):0,
        sandboxEnv:'Windows 10 x64 (22H2)',
        analysisTime:seededNum(ioc,'ar-t',20,75)+' seconds' };
    }
    case 'shodan': {
      var g=typeGroup(type);
      if (g!=='ip'&&g!=='domain') return {source:'Shodan',icon:'🌐',notApplicable:true,message:'Shodan requires an IP or domain.'};
      var ports=[80,443,...[22,21,8080,3389].slice(0,seededNum(ioc,'sh-p',0,2))].sort(function(a,b){return a-b;});
      var hv=seededNum(ioc,'sh-v',0,100)>78;
      return { source:'Shodan', icon:'🌐', _demo:true,
        verdict:hv?'suspicious':'info', ports:ports,
        org:seededPick(ioc,'sh-o',['AS13335 Cloudflare','AS16509 Amazon AWS','AS20473 Vultr']),
        country:seededPick(ioc,'sh-cn',['United States','Germany','Netherlands']),
        city:seededPick(ioc,'sh-ci',['San Francisco','Frankfurt','Amsterdam']),
        os:null,
        vulns:hv?[['CVE-2021-44228','CVE-2022-0001','CVE-2023-44487'][seededNum(ioc,'sh-cve',0,2)]]:[],
        banners:['nginx/1.24.0','OpenSSH_8.9p1'].slice(0,seededNum(ioc,'sh-b',1,2)),
        lastUpdate:new Date(Date.now()-seededNum(ioc,'sh-d',1,14)*86400000).toISOString().slice(0,10),
        hostnames:[], tags:[], isp:'—' };
    }
    case 'whois': {
      var isIP=typeGroup(type)==='ip', days=seededNum(ioc,'wh-a',120,1400);
      var created=new Date(Date.now()-days*86400000).toISOString().slice(0,10);
      return { source:'WHOIS', icon:'📋', verdict:'info', _demo:true,
        registrar:isIP?'RIPE NCC':seededPick(ioc,'wh-r',['GoDaddy.com, LLC','Namecheap, Inc.','Porkbun LLC']),
        organization:'REDACTED FOR PRIVACY', createdDate:created,
        updatedDate:new Date(Date.now()-seededNum(ioc,'wh-u',1,60)*86400000).toISOString().slice(0,10),
        expiryDate:isIP?'N/A':new Date(Date.now()+seededNum(ioc,'wh-e',90,730)*86400000).toISOString().slice(0,10),
        nameservers:isIP?[]:['ns1.registrar.com','ns2.registrar.com'],
        registrant:'REDACTED FOR PRIVACY',
        country:seededPick(ioc,'wh-c',['US','DE','NL','GB']),
        status:isIP?[]:['clientTransferProhibited'],
        dnssec:'unsigned', daysOld:days, newDomain:days<30, emails:[] };
    }
    default: return { source:source, verdict:'unknown', _demo:true };
  }
}

/* ================================================================
   API LAYER — all calls go through /api/* proxy
================================================================ */
function callAPI(endpoint, body, method) {
  method = method || (body !== undefined ? 'POST' : 'GET');
  var opts = { method: method, credentials: 'include', headers: { 'Content-Type': 'application/json' } };
  if (body !== undefined && method !== 'GET') opts.body = JSON.stringify(body);
  return fetch(endpoint, opts).then(function (res) {
    if (res.status === 401) { window.location.href = '/'; return null; }
    return res.json().then(function (data) {
      if (!res.ok) throw new Error(data.error || 'HTTP ' + res.status);
      return data;
    });
  });
}

function querySource(name, ioc, type) {
  return callAPI('/api/' + name, { ioc: ioc, type: type }).then(function (r) {
    return r;
  }).catch(function (err) {
    console.warn('[TIP]', name, 'failed:', err.message, '— demo');
    var d = demoData(name, ioc, type);
    d._apiError = err.message;
    return d;
  });
}

/* ================================================================
   AI ANALYSIS
================================================================ */
function getAIAnalysis(ioc, iocType, results) {
  var vt=results.virustotal||{}, abu=results.abuseipdb||{};
  var run=results.hybrid||{}, sh=results.shodan||{}, wh=results.whois||{};
  var summary = [
    'VirusTotal: '+(vt.detections||0)+'/'+(vt.engines||72)+' detections, verdict: '+(vt.verdict||'unknown'),
    !abu.notApplicable ? 'AbuseIPDB: '+(abu.abuseScore||0)+'% confidence, '+(abu.totalReports||0)+' reports' : 'AbuseIPDB: N/A for this IOC type',
    'Hybrid Analysis: score '+(run.threatScore||0)+'/100, malicious reports: '+(run.maliciousCount||0)+', malware: '+(run.malwareFamily||'none'),
    !sh.notApplicable ? 'Shodan: ports ['+(sh.ports||[]).join(', ')+'], CVEs ['+(sh.vulns||[]).join(', ')||'none'+']' : 'Shodan: N/A',
    'WHOIS: created '+(wh.createdDate||'?')+(wh.newDomain?' NEWLY REGISTERED ('+wh.daysOld+'d)':''),
  ].join('\n');

  var prompt = 'You are an elite Tier-3 SOC Analyst. Analyze this IOC and return ONLY a raw JSON object with no markdown.\n\nIOC: '+ioc+'\nType: '+iocType+'\nIntelligence:\n'+summary+'\n\nReturn exactly this JSON shape:\n{"executiveSummary":"2-3 sentences","riskScore":0,"verdict":"clean","threatActor":null,"malwareFamily":null,"attackTechniques":["T1234 - Name"],"iocContext":"2-3 sentences","recommendations":["action1","action2","action3","action4","action5"],"iocRelationships":[],"confidence":"low","tlp":"GREEN","tags":[],"priorityAction":"single sentence"}';

  return callAPI('/api/ai', { prompt: prompt, maxTokens: 1024 }).then(function (text) {
    if (!text) return buildDerivedAI(ioc, iocType, results);
    var clean = text.replace(/```json\s*|```/g, '').trim();
    try { return JSON.parse(clean); }
    catch(e) {
      var m = clean.match(/\{[\s\S]*\}/);
      if (m) return JSON.parse(m[0]);
      return buildDerivedAI(ioc, iocType, results);
    }
  }).catch(function (err) {
    console.warn('[TIP] AI analysis failed:', err.message);
    return buildDerivedAI(ioc, iocType, results);
  });
}

function buildDerivedAI(ioc, iocType, results) {
  var vt=results.virustotal||{}, abu=results.abuseipdb||{};
  var run=results.hybrid||{}, sh=results.shodan||{}, wh=results.whois||{};
  var rs = 10;
  if (vt.verdict==='malicious')  rs += 40;
  if (vt.verdict==='suspicious') rs += 20;
  if ((vt.detections||0) > 10)   rs += 10;
  if (!abu.notApplicable && (abu.abuseScore||0) > 70) rs += 25;
  if (!abu.notApplicable && (abu.abuseScore||0) > 30) rs += 10;
  if (run.detected)               rs += 20;
  if ((sh.vulns||[]).length > 0)  rs += 10;
  if (wh.newDomain)               rs += 8;
  rs = Math.min(100, rs);
  var v = rs>=70?'malicious':rs>=40?'suspicious':rs>=15?'unknown':'clean';
  return {
    executiveSummary: rs>70 ? 'High-confidence malicious indicator. '+(run.malwareFamily?'Malware family '+run.malwareFamily+' identified. ':'')+'Multiple OSINT sources corroborate. Immediate containment required.'
      : rs>40 ? 'Suspicious characteristics detected across multiple intelligence sources. Elevated monitoring warranted. Verify before blocking.'
      : 'Minimal threat indicators detected. Low risk profile based on current intelligence data.',
    riskScore:rs, verdict:v, threatActor:null, malwareFamily:run.malwareFamily||null,
    attackTechniques: rs>50 ? ['T1071.001 - Application Layer Protocol: Web Protocols','T1059.003 - Windows Command Shell'] : [],
    iocContext: ioc+' ('+iocType+') cross-referenced across VirusTotal, AbuseIPDB, Shodan, and WHOIS. '
      +(wh.newDomain?'Recently registered domain — indicator of new malicious infrastructure. ':'')
      +((sh.vulns||[]).length?'Shodan reports CVEs: '+sh.vulns.join(', ')+'. ':'')
      +'Intelligence confidence: '+(rs>70?'HIGH':rs>40?'MEDIUM':'LOW')+'.',
    recommendations: [
      (rs>50?'Block':'Monitor')+' '+ioc+' at perimeter firewall and web proxy',
      'Search SIEM for connections to this IOC in the past 90 days',
      rs>50?'Isolate endpoints that communicated with this IOC':'No immediate containment required',
      'Add to EDR detection rules and threat intelligence watchlist',
      'Re-evaluate when new intelligence becomes available'
    ],
    iocRelationships:[], confidence:rs>70?'high':rs>40?'medium':'low',
    tlp:rs>70?'AMBER':'GREEN', tags:[v,iocType],
    priorityAction: rs>60 ? 'Immediately block '+ioc+' at all network egress points'
      : 'Monitor '+ioc+' for 48 hours before escalating'
  };
}

/* ================================================================
   AI CHAT — multi-turn with full context
================================================================ */
var chatHistory = [];
var chatContext  = {};
var chatBusy     = false;

function setChatContext(ioc, iocType, results, ai) {
  chatHistory = [];
  chatBusy    = false;
  chatContext = { ioc:ioc, iocType:iocType, results:results, ai:ai };
}

function getChatReply() {
  var ctx = chatContext;
  var ai  = ctx.ai || {};
  var vt  = (ctx.results||{}).virustotal || {};
  var abu = (ctx.results||{}).abuseipdb  || {};
  var run = (ctx.results||{}).hybrid     || {};
  var sh  = (ctx.results||{}).shodan     || {};
  var wh  = (ctx.results||{}).whois      || {};

  var system = [
    'You are an expert Tier-3 SOC analyst AI assistant. The analyst is investigating:',
    '',
    'IOC: '+ctx.ioc+' ('+ctx.iocType+') | Risk: '+(ai.riskScore||0)+'/100 | Verdict: '+(ai.verdict||'unknown')+' | Confidence: '+(ai.confidence||'medium'),
    'VirusTotal: '+(vt.detections||0)+'/'+(vt.engines||72)+' detections (verdict: '+(vt.verdict||'unknown')+')',
    'AbuseIPDB: '+(!abu.notApplicable?(abu.abuseScore||0)+'% confidence, '+(abu.totalReports||0)+' reports':'N/A for this IOC type'),
    'Hybrid: '+(run.detected?'DETECTED — malware: '+(run.malwareFamily||'unknown')+', score '+(run.threatScore||0)+'/100':'No reports found'),
    'Shodan: ports ['+(sh.ports||[]).join(', ')||'N/A'+'], CVEs ['+(sh.vulns||[]).join(', ')||'none'+']',
    'WHOIS: created '+(wh.createdDate||'?')+(wh.newDomain?' ⚠️ NEWLY REGISTERED':'')+', registrar: '+(wh.registrar||'—'),
    'Malware: '+(ai.malwareFamily||'none identified')+' | Threat actor: '+(ai.threatActor||'unattributed'),
    'Priority action: '+(ai.priorityAction||''),
    'Executive summary: '+(ai.executiveSummary||''),
    '',
    'Use the FULL conversation history. Never repeat a previous answer — build on it. Be specific, technical, and actionable. Use MITRE ATT&CK IDs. Format multi-step answers as numbered lists.'
  ].join('\n');

  return callAPI('/api/ai', {
    system: system,
    messages: chatHistory.map(function (m) { return { role: m.role, content: m.content }; }),
    maxTokens: 900
  }).then(function (reply) {
    return reply || '(No response)';
  }).catch(function (err) {
    console.warn('[TIP] Chat API error:', err.message, '— local fallback');
    return buildLocalChatReply(ctx.ioc, ai, vt, sh, wh, run);
  });
}

function buildLocalChatReply(ioc, ai, vt, sh, wh, run) {
  var q    = (chatHistory[chatHistory.length-1] || {}).content || '';
  var ql   = q.toLowerCase();
  var rs   = ai.riskScore || 0;
  var prev = chatHistory.filter(function(m){return m.role==='assistant';}).map(function(m){return m.content||'';}).join(' ').toLowerCase();

  if ((ql.includes('block')||ql.includes('firewall')||ql.includes('rule')) && !prev.includes('perimeter firewall'))
    return '**Blocking rules for `'+ioc+'` (Risk: '+rs+'/100):**\n\n1. **Perimeter firewall** — deny all ports, both directions (in + egress)\n2. **NGFW/Web proxy** — override category to "Blocked: Malicious"\n3. **DNS RPZ sinkhole** — `'+ioc+'` → 0.0.0.0\n4. **EDR** — custom IOC block rule, auto-isolate on match\n5. **Email gateway** — add domain/IP to blocklist\n6. **ITSM** — document with risk score '+rs+'/100, analyst name, timestamp\n\n'+(rs>70?'⚠️ **HIGH RISK — apply all blocks immediately.**':'ℹ️ Moderate risk — apply and monitor.') ;

  if ((ql.includes('siem')||ql.includes('hunt')||ql.includes('query')||ql.includes('splunk')||ql.includes('elastic')) && !prev.includes('index=*'))
    return '**SIEM hunting queries for `'+ioc+'`:**\n\n**Splunk:**\n```\nindex=* (dest_ip="'+ioc+'" OR dest_host="'+ioc+'" OR url="*'+ioc+'*")\n| stats count, dc(src_ip) as unique_src, values(src_ip) as sources, values(user), first(_time), last(_time) by dest_ip\n| sort -count\n```\n\n**Elastic KQL:**\n```\ndestination.ip: "'+ioc+'" OR dns.question.name: "'+ioc+'" OR http.request.headers.host: "'+ioc+'"\n```\n\n**Key indicators to look for:** Regular beaconing (fixed intervals), large outbound data (>10MB), off-hours connections, privileged accounts making contact.';

  if (ql.includes('mitre')||ql.includes('ttp')||ql.includes('technique')) {
    var techs = ai.attackTechniques || [];
    if (techs.length) return '**MITRE ATT&CK techniques:**\n\n'+techs.map(function(t,i){return (i+1)+'. **'+t+'**';}).join('\n')+'\n\nSearch attack.mitre.org for full kill-chain detail. Cross-reference with EDR telemetry around connection timestamps.';
    return '**Likely MITRE ATT&CK techniques (risk '+rs+'/100):**\n\n1. **T1071.001** — C2 over HTTPS\n2. **T1566.001** — Spear-phishing initial access\n3. **T1078** — Valid accounts for persistence\n4. **T1018** — Remote system discovery\n\nVerify in your EDR correlated with connection timestamps.';
  }

  if (ql.includes('false positive')||ql.includes('legit')||ql.includes('whitelist'))
    return '**False positive assessment (risk: '+rs+'/100):**\n\n'+(rs<15?'Very unlikely malicious.':rs<40?'Some indicators — verify carefully.':'Multiple sources flagging — FP unlikely.')+'\n\n**Verification checklist:**\n1. Is `'+ioc+'` in your asset inventory or known vendor list?\n2. Shodan banners match expected services? '+(sh.ports&&sh.ports.length?'(ports: '+sh.ports.join(', ')+')':'no Shodan data')+'\n3. WHOIS registrar matches expected owner? ('+((wh||{}).registrar||'unknown')+')\n4. Ask the business owner if they recognise outbound connections\n5. Review SSL certificate for this host\n\n'+(rs>50?'⚠️ **Do NOT whitelist without completing all checks.**':'✓ Safe to whitelist if all checks pass — document justification.');

  if (ql.includes('incident')||ql.includes('ir ')||ql.includes('playbook')||ql.includes('respond'))
    return '**IR Playbook — `'+ioc+'` (P'+(rs>70?'1':rs>40?'2':'3')+' Severity):**\n\n**Phase 1 — Contain (0–1h):**\n1. Block IOC at all enforcement points\n2. SIEM query — identify all affected endpoints\n3. Isolate confirmed-infected hosts\n4. Preserve volatile evidence (memory dump)\n\n**Phase 2 — Investigate (1–24h):**\n5. Review process trees for parent-child anomalies\n6. Check persistence: registry Run keys, scheduled tasks, services\n7. Auth logs — lateral movement and privilege escalation\n8. Open P'+(rs>70?'1':'2')+' ticket, notify SOC manager\n\n**Phase 3 — Remediate (24–72h):**\n9. Reimage or restore affected systems\n10. Rotate all potentially harvested credentials\n11. Patch exploited vulnerabilities'+(sh&&sh.vulns&&sh.vulns.length?' ('+sh.vulns.join(', ')+')':'')+'\n12. Write post-incident report';

  if (ql.includes('malware')||ql.includes('family')) {
    var fam = ai.malwareFamily || run.malwareFamily;
    if (fam) return '**Malware: '+fam+'**\n\n**Key capabilities:**\n1. Credential harvesting from browsers and email clients\n2. Persistence via registry Run keys (T1547.001) and scheduled tasks (T1053.005)\n3. Encrypted C2 over HTTPS (T1071.001)\n4. Lateral movement with stolen credentials\n\n**Detection steps:**\n1. Search EDR for '+fam+' YARA signatures\n2. Process trees: Office/browser spawning cmd.exe or powershell.exe\n3. New scheduled tasks and Run registry entries\n4. Regular HTTPS beaconing at fixed intervals';
    return 'No malware family identified. Submit to:\n- **VirusTotal** — virustotal.com\n- **ANY.RUN** — app.any.run (interactive sandbox)\n- **Hybrid Analysis** — hybrid-analysis.com (free)';
  }

  return rs > 60
    ? '**`'+ioc+'` — HIGH RISK ('+rs+'/100)**\n\n'+(ai.executiveSummary||'')+'\n\n**Priority:** '+(ai.priorityAction||'Contain immediately')+'\n\nAsk about: **firewall rules**, **SIEM queries**, **MITRE techniques**, **IR playbook**, **threat attribution**, **false positive check**.'
    : '**`'+ioc+'` — LOW RISK ('+rs+'/100)**\n\n'+(ai.executiveSummary||'')+'\n\n**Posture:** Monitor, do not block yet.\n\nAsk about: **verification steps**, **SIEM monitoring**, **escalation criteria**, or any specific concern.';
}

/* ================================================================
   APP STATE
================================================================ */
var state = {
  ioc: '', iocType: '', results: {}, ai: null,
  currentInvId: null,
  history: []
};

/* ================================================================
   INVESTIGATE
================================================================ */
function investigate() {
  var ioc = document.getElementById('iocInput').value.trim();
  if (!ioc) { showToast('Please enter an IOC to investigate.', 'warning'); return; }
  var iocType = classifyIOC(ioc);
  if (iocType === 'unknown') { showToast('Unrecognized format. Try: IP, domain, hash, or URL.', 'warning'); return; }

  state.ioc = ioc; state.iocType = iocType;
  state.results = {}; state.ai = null; state.currentInvId = null;

  document.getElementById('goBtn').disabled = true;
  document.getElementById('goBtnTxt').textContent = 'Analyzing...';
  showSection('loading');
  setLoadStage('Querying all intelligence sources...');
  ['ls-vt','ls-abuse','ls-hybrid','ls-shodan','ls-whois','ls-ai'].forEach(function(id) {
    var el = document.getElementById(id);
    if (el) el.classList.remove('done');
  });

  Promise.all([
    querySource('virustotal', ioc, iocType).then(function(r){ state.results.virustotal=r; markDone('ls-vt'); }),
    querySource('abuseipdb',  ioc, iocType).then(function(r){ state.results.abuseipdb=r;  markDone('ls-abuse'); }),
    querySource('hybrid',     ioc, iocType).then(function(r){ state.results.hybrid=r;     markDone('ls-hybrid'); }),
    querySource('shodan',     ioc, iocType).then(function(r){ state.results.shodan=r;     markDone('ls-shodan'); }),
    querySource('whois',      ioc, iocType).then(function(r){ state.results.whois=r;      markDone('ls-whois'); })
  ]).then(function() {
    setLoadStage('Running AI threat analysis...');
    return getAIAnalysis(ioc, iocType, state.results);
  }).then(function(ai) {
    state.ai = ai;
    markDone('ls-ai');

    renderHero();
    renderOverview();
    renderVT();
    renderAbuse();
    renderAnyrun();
    renderShodan();
    renderWhois();
    renderAITab();
    setChatContext(ioc, iocType, state.results, state.ai);
    renderChatWelcome();
    renderComments([]);

    return callAPI('/api/investigations', { ioc:ioc, iocType:iocType, results:state.results, aiAnalysis:state.ai });
  }).then(function(saved) {
    if (saved) state.currentInvId = saved.id;
    return loadHistory();
  }).then(function() {
    showSection('results');
    document.getElementById('exportBtn').classList.add('visible');
    switchTab('overview');
    document.getElementById('goBtn').disabled = false;
    document.getElementById('goBtnTxt').textContent = 'Investigate';
    var rs = (state.ai||{}).riskScore || 0;
    var lbl = rs>=80?'CRITICAL':rs>=50?'HIGH':rs>=20?'MEDIUM':'LOW';
    showToast('Analysis complete — '+lbl+' risk ('+rs+'/100)', (state.ai||{}).verdict==='malicious'?'error':(state.ai||{}).verdict==='suspicious'?'warning':'success');
  }).catch(function(err) {
    console.error('[TIP] investigate error:', err);
    document.getElementById('goBtn').disabled = false;
    document.getElementById('goBtnTxt').textContent = 'Investigate';
    showToast('Investigation error: ' + err.message, 'error');
  });
}

/* ================================================================
   HISTORY
================================================================ */
function loadHistory() {
  return callAPI('/api/investigations', undefined, 'GET').then(function(invs) {
    if (Array.isArray(invs)) {
      state.history = invs;
      renderHistory();
      renderAllInvestigations();
    }
  }).catch(function(e){ console.warn('[loadHistory]', e.message); });
}


function loadInvestigation(invId) {
  callAPI('/api/investigations/' + invId, undefined, 'GET').then(function(inv) {
    if (!inv) return;
    state.ioc = inv.ioc; state.iocType = inv.iocType;
    state.results = inv.results; state.ai = inv.aiAnalysis;
    state.currentInvId = inv.id;
    document.getElementById('iocInput').value = inv.ioc;
    updateBadge(inv.ioc);
    renderHero(); renderOverview();
    renderVT(); renderAbuse(); renderAnyrun(); renderShodan(); renderWhois(); renderAITab();
    setChatContext(inv.ioc, inv.iocType, inv.results, inv.aiAnalysis);
    renderChatWelcome();
    renderComments(inv.comments || []);
    showSection('results');
    document.getElementById('exportBtn').classList.add('visible');
    switchTab('overview');
    showToast('Loaded: ' + inv.ioc, 'info');
  }).catch(function(e) { showToast('Failed to load: ' + e.message, 'error'); });
}

function renderHistory() {
  // Update the investigations page list if it's currently visible
  var page = document.getElementById('page-tool-investigations');
  if (page && page.classList.contains('active')) {
    renderAllInvestigations();
  }
}

function renderHistoryOld() {
  var list = document.getElementById('histList');
  if (!list) return;
  if (!state.history.length) {
    list.innerHTML = '<div class="hist-empty">No investigations yet.<br>Run one to see it here.</div>';
    return;
  }
  var riskColor = { malicious:'var(--critical)', suspicious:'var(--high)', clean:'var(--low)', unknown:'var(--t-2)' };
  var riskBg    = { malicious:'rgba(240,48,96,.10)', suspicious:'rgba(240,112,32,.10)', clean:'rgba(32,208,128,.08)', unknown:'rgba(74,106,138,.08)' };
  var typeIcon  = { ip:'⬡', domain:'◎', url:'↗', md5:'#', sha1:'#', sha256:'#', hash:'#' };

  list.innerHTML = state.history.map(function(h) {
    var rs    = h.riskScore || 0;
    var verd  = h.verdict || 'unknown';
    var rc    = riskColor[verd] || 'var(--t-2)';
    var rbg   = riskBg[verd]   || 'rgba(74,106,138,.08)';
    var icon  = typeIcon[h.iocType] || '?';
    var pct   = Math.min(100, rs);
    var iocShort = h.ioc.length > 26 ? h.ioc.slice(0,24)+'…' : h.ioc;
    // Relative time
    var ago   = Date.now() - new Date(h.createdAt).getTime();
    var agoStr = ago < 3600000 ? Math.round(ago/60000)+'m ago'
               : ago < 86400000 ? Math.round(ago/3600000)+'h ago'
               : Math.round(ago/86400000)+'d ago';

    return '<div class="hist-item-v2" data-invid="'+esc(h.id)+'">'
      +'<div class="hist-risk-stripe" style="background:'+rc+'"></div>'
      +'<div class="hist-body">'
      // IOC type icon + full value on its own line
      +'<div class="hist-type-row">'
      +'<span class="hist-type-badge" style="color:'+rc+';background:'+rbg+';border:1px solid '+rc+'45;">'
      +esc(h.iocType ? h.iocType.toUpperCase() : '?')+'</span>'
      +(h.commentCount>0?'<span class="hist-notes-badge">💬 '+h.commentCount+'</span>':'')
      +'<span class="hist-time">'+agoStr+'</span>'
      +'</div>'
      +'<div class="hist-ioc-v2" title="'+esc(h.ioc)+'">'+esc(iocShort)+'</div>'
      // Risk bar
      +'<div class="hist-bar-wrap"><div class="hist-bar-fill" style="width:'+pct+'%;background:'+rc+'"></div></div>'
      // Verdict + score
      +'<div class="hist-bottom-row">'
      +'<span class="hist-verdict-chip" style="color:'+rc+';background:'+rbg+';border:1px solid '+rc+'">'+verd.toUpperCase()+'</span>'
      +'<span class="hist-score" style="color:'+rc+'">'+rs+'<span style="color:var(--t-3);font-size:9px;">/100</span></span>'
      +'</div>'
      +'</div>'
      +'</div>';
  }).join('');

  list.querySelectorAll('.hist-item-v2').forEach(function(el) {
    el.addEventListener('click', function() { loadInvestigation(el.dataset.invid); });
  });
}

/* ================================================================
   ANALYST NOTES (Comments)
================================================================ */
var NOTE_TAGS = [
  { label:'🔴 Confirmed Malicious', color:'var(--critical)', bg:'rgba(240,48,96,.12)', border:'rgba(240,48,96,.3)' },
  { label:'🟠 Suspicious', color:'var(--high)', bg:'rgba(240,112,32,.12)', border:'rgba(240,112,32,.3)' },
  { label:'🟢 False Positive', color:'var(--low)', bg:'rgba(32,208,128,.12)', border:'rgba(32,208,128,.3)' },
  { label:'🔵 Under Investigation', color:'var(--cyan)', bg:'rgba(0,200,240,.10)', border:'rgba(0,200,240,.28)' },
  { label:'🎫 Ticket Created', color:'#a78bfa', bg:'rgba(139,92,246,.12)', border:'rgba(139,92,246,.3)' },
  { label:'📋 False Alert', color:'var(--t-1)', bg:'rgba(74,106,138,.12)', border:'rgba(74,106,138,.3)' },
];

function getNotePriority(text) {
  var t = text.toLowerCase();
  if (t.includes('[confirmed malicious]') || t.includes('confirmed c2') || t.includes('confirmed malware')) return 'critical';
  if (t.includes('[suspicious]') || t.includes('suspicious')) return 'suspicious';
  if (t.includes('[false positive]') || t.includes('fp:') || t.includes('false positive')) return 'fp';
  if (t.includes('[ticket]') || t.includes('ticket #') || t.includes('jira') || t.includes('incident')) return 'ticket';
  return 'default';
}

function renderComments(comments) {
  var el = document.getElementById('commentsPanel');
  if (!el) return;
  var count = (comments||[]).length;

  var priorityMap = {
    critical: { color:'var(--critical)', bg:'rgba(240,48,96,.10)', border:'rgba(240,48,96,.3)',  label:'CONFIRMED MALICIOUS' },
    suspicious:{ color:'var(--high)',     bg:'rgba(240,112,32,.10)',border:'rgba(240,112,32,.3)', label:'SUSPICIOUS'           },
    fp:        { color:'var(--low)',       bg:'rgba(32,208,128,.10)',border:'rgba(32,208,128,.3)',label:'FALSE POSITIVE'        },
    ticket:    { color:'#a78bfa',          bg:'rgba(139,92,246,.10)',border:'rgba(139,92,246,.3)',label:'TICKET'                },
    default:   { color:'var(--cyan)',      bg:'var(--cyan-dim)',     border:'var(--cyan-border)', label:''                      },
  };

  /* ── Notes list HTML ──────────────────────────────────────── */
  var lst = (comments||[]).map(function(c) {
    var p   = getNotePriority(c.text||'');
    var pm  = priorityMap[p] || priorityMap.default;
    var ago = Date.now() - new Date(c.createdAt).getTime();
    var ts  = ago < 3600000   ? Math.round(ago/60000)+'m ago'
            : ago < 86400000  ? Math.round(ago/3600000)+'h ago'
            : new Date(c.createdAt).toLocaleDateString();
    return '<div class="note-card" data-cid="'+esc(c.id)+'" style="--note-color:'+pm.color+';--note-bg:'+pm.bg+';--note-border:'+pm.border+';">'
      + '<div class="note-card-stripe"></div>'
      + '<div class="note-card-body">'
      +   '<div class="note-card-meta">'
      +     (pm.label ? '<span class="note-priority-chip">'+pm.label+'</span>' : '')
      +     '<span class="note-ts">'+ts+'</span>'
      +     '<button class="note-del" data-cid="'+esc(c.id)+'" title="Delete">✕</button>'
      +   '</div>'
      +   '<div class="note-text">'+esc(c.text||'')+'</div>'
      + '</div>'
      + '</div>';
  }).join('');

  /* ── Quick-tag buttons ───────────────────────────────────── */
  var tags = NOTE_TAGS.map(function(t) {
    var shortLabel = t.label.replace(/^[\uD800-\uDFFF\u2000-\u3300\u{1F000}-\u{1FFFF}]\s*/u, '');
    return '<button class="ntag" data-tag="['+esc(shortLabel.trim())+'] "'
      + ' style="--ntag-color:'+t.color+';--ntag-bg:'+t.bg+';--ntag-border:'+t.border+';">'
      + esc(t.label)
      + '</button>';
  }).join('');

  /* ── Full panel HTML ──────────────────────────────────────── */
  el.innerHTML =
    '<div class="notes-wrap">'

    // ── Header ─────────────────────────────────────────────
    + '<div class="notes-head">'
    +   '<div class="notes-head-left">'
    +     '<span class="notes-icon">✏️</span>'
    +     '<span class="notes-heading">Analyst Notes</span>'
    +     '<span class="notes-badge">'+count+'</span>'
    +   '</div>'
    +   '<span class="notes-kbd">Ctrl+K to focus</span>'
    + '</div>'

    // ── Quick tags ─────────────────────────────────────────
    + '<div class="notes-tags-label">Quick tags</div>'
    + '<div class="notes-tags">' + tags + '</div>'

    // ── Notes list ─────────────────────────────────────────
    + '<div class="notes-list" id="notesList">'
    + (lst || (
        '<div class="notes-zero">'
        + '<div class="notes-zero-icon">📝</div>'
        + '<div class="notes-zero-title">No notes yet</div>'
        + '<div class="notes-zero-sub">Tag findings, link tickets, document indicators using quick tags or write your own below.</div>'
        + '</div>'
      ))
    + '</div>'

    // ── Input card ─────────────────────────────────────────
    + '<div class="notes-composer">'
    +   '<textarea id="commentTA" class="notes-ta" rows="3"'
    +     ' placeholder="Write a note…  e.g. Confirmed C2 for Emotet — blocking at FW, ticket #4521"></textarea>'
    +   '<div class="notes-composer-bar">'
    +     '<span class="notes-composer-hint">Ctrl+Enter to save</span>'
    +     '<button class="notes-save-btn" id="commentAddBtn">💾 Save Note</button>'
    +   '</div>'
    + '</div>'

    + '</div>'; // .notes-wrap

  /* ── Wire events ──────────────────────────────────────── */
  var addBtn = document.getElementById('commentAddBtn');
  if (addBtn) addBtn.addEventListener('click', addComment);

  var ta = document.getElementById('commentTA');
  if (ta) {
    ta.addEventListener('keydown', function(e) {
      if (e.key === 'Enter' && e.ctrlKey) { e.preventDefault(); addComment(); }
    });
    ta.addEventListener('input', function() {
      ta.style.height = 'auto';
      ta.style.height = Math.min(ta.scrollHeight, 220) + 'px';
    });
  }

  el.querySelectorAll('.note-del').forEach(function(btn) {
    btn.addEventListener('click', function() { deleteComment(btn.dataset.cid); });
  });

  el.querySelectorAll('.ntag').forEach(function(btn) {
    btn.addEventListener('click', function() {
      var ta2 = document.getElementById('commentTA');
      if (!ta2) return;
      var cur = ta2.value.trimEnd();
      ta2.value = (cur ? cur + '\n' : '') + btn.dataset.tag;
      ta2.focus();
      ta2.setSelectionRange(ta2.value.length, ta2.value.length);
      ta2.style.height = 'auto';
      ta2.style.height = Math.min(ta2.scrollHeight, 220) + 'px';
    });
  });
}


function addComment() {
  if (!state.currentInvId) { showToast('Run an investigation first.', 'warning'); return; }
  var ta = document.getElementById('commentTA');
  var text = ta ? ta.value.trim() : '';
  if (!text) { showToast('Note cannot be empty.', 'warning'); return; }
  var btn = document.getElementById('commentAddBtn');
  if (btn) { btn.disabled=true; btn.textContent='Saving...'; }
  callAPI('/api/investigations/'+state.currentInvId+'/comments', { text:text }).then(function() {
    if (ta) { ta.value=''; ta.style.height='auto'; }
    if (btn) { btn.disabled=false; btn.textContent='💾 Save Note'; }
    return callAPI('/api/investigations/'+state.currentInvId, undefined, 'GET');
  }).then(function(inv) {
    if (inv) renderComments(inv.comments || []);
    return loadHistory();
  }).then(function() {
    showToast('Note saved.', 'success');
  }).catch(function(e) {
    if (btn) { btn.disabled=false; btn.textContent='💾 Save Note'; }
    showToast('Failed: ' + e.message, 'error');
  });
}

function deleteComment(commentId) {
  if (!state.currentInvId) return;
  if (!confirm('Delete this note?')) return;
  callAPI('/api/investigations/'+state.currentInvId+'/comments/'+commentId, undefined, 'DELETE').then(function() {
    return callAPI('/api/investigations/'+state.currentInvId, undefined, 'GET');
  }).then(function(inv) {
    if (inv) renderComments(inv.comments || []);
    return loadHistory();
  }).then(function() { showToast('Note deleted.', 'success'); })
  .catch(function(e) { showToast('Failed: ' + e.message, 'error'); });
}

function logout() {
  callAPI('/api/auth/logout', {}).catch(function(){}).then(function() {
    sessionStorage.clear();
    window.location.href = '/';
  });
}

/* ================================================================
   RENDER HELPERS
================================================================ */
function esc(s) {
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function vbadge(v, cls) {
  var m = {malicious:'vd-malicious',suspicious:'vd-suspicious',clean:'vd-clean',info:'vd-info',unknown:'vd-unknown'};
  return '<span class="'+(cls||'smc-badge')+' '+(m[v]||'vd-unknown')+'">'+(v||'UNKNOWN').toUpperCase()+'</span>';
}
function drow(k, v, col) {
  return '<div class="data-row"><span class="dr-key">'+esc(k)+'</span><span class="dr-val '+(col||'')+'">'+esc(String(v===null||v===undefined?'—':v))+'</span></div>';
}
function chip(t, c) { return '<span class="chip '+(c||'chip-gray')+'">'+esc(t)+'</span>'; }
function demoNote(d) {
  if (!d || !d._demo) return '';
  var extra = d._apiError ? ' API error: '+esc(d._apiError) : ' Add your API key in server/index.js';
  return '<div class="demo-note">ℹ️ DEMO DATA —'+extra+'</div>';
}
function setText(id, txt) { var e=document.getElementById(id); if(e) e.textContent=txt; }
function setHTML(id, html) { var e=document.getElementById(id); if(e) e.innerHTML=html; }

/* ================================================================
   RENDER: HERO BAR
================================================================ */
function renderHero() {
  var ai = state.ai || {}, rs = ai.riskScore || 0;
  setText('heroType', '🎯 ' + state.iocType.toUpperCase());
  setText('heroVal', state.ioc);
  var fill = document.getElementById('gaugeFill');
  var scoreEl = document.getElementById('gaugeScore');
  if (fill) fill.style.strokeDashoffset = 148 - (148 * rs / 100);
  if (scoreEl) {
    scoreEl.textContent = rs;
    scoreEl.style.fill = rs>=80?'#f03060':rs>=50?'#f07020':rs>=20?'#f0c020':'#20d080';
  }
  var vEl = document.getElementById('heroVerdict');
  if (vEl) {
    vEl.textContent = (ai.verdict||'unknown').toUpperCase();
    vEl.style.color = ({malicious:'var(--critical)',suspicious:'var(--high)',clean:'var(--low)'})[ai.verdict]||'var(--t-1)';
  }
  setText('heroConf', (ai.confidence||'—').toUpperCase());
  var tEl = document.getElementById('heroTLP');
  if (tEl) {
    tEl.textContent = 'TLP:'+(ai.tlp||'—');
    tEl.style.color = ({RED:'var(--critical)',AMBER:'var(--medium)',GREEN:'var(--low)',WHITE:'#e0e0e0'})[ai.tlp]||'var(--t-1)';
  }
}

/* ================================================================
   RENDER: OVERVIEW TAB
================================================================ */
function renderOverview() {
  var r = state.results, ai = state.ai || {};
  var defs = [
    { key:'virustotal', color:'#1a73e8', metric:function(d){ return '<div class="smc-number" style="color:'+((d.detections||0)>10?'var(--critical)':(d.detections||0)>3?'var(--high)':'var(--low)')+';">'+(d.detections||0)+'/'+(d.engines||0)+'</div><div class="smc-number-label">engines flagged</div>'; } },
    { key:'abuseipdb',  color:'#f07020', metric:function(d){ return d.notApplicable?'<div style="font-size:10px;color:var(--t-2);margin-top:8px;">N/A for '+state.iocType+'</div>':'<div class="smc-number" style="color:'+((d.abuseScore||0)>70?'var(--critical)':(d.abuseScore||0)>30?'var(--high)':'var(--low)')+';">'+(d.abuseScore||0)+'%</div><div class="smc-number-label">abuse confidence</div>'; } },
    { key:'hybrid',     color:'#8b5cf6', metric:function(d){ return d.notApplicable?'<div style="font-size:10px;color:var(--t-2);margin-top:8px;">Key not configured</div>':'<div class="smc-number" style="color:'+((d.threatScore||0)>70?'var(--critical)':(d.threatScore||0)>40?'var(--high)':'var(--low)')+';">'+(d.threatScore||0)+'</div><div class="smc-number-label">threat score</div>'; } },
    { key:'shodan',     color:'#f03060', metric:function(d){ return d.notApplicable?'<div style="font-size:10px;color:var(--t-2);margin-top:8px;">N/A for '+state.iocType+'</div>':'<div class="smc-number" style="color:var(--cyan);">'+(d.ports||[]).length+'</div><div class="smc-number-label">open ports</div>'; } },
    { key:'whois',      color:'#20d080', metric:function(d){ return '<div class="smc-number" style="color:var(--low);font-size:20px;">'+(d.daysOld>=0?d.daysOld+'d':'—')+'</div><div class="smc-number-label">domain age</div>'; } }
  ];
  var cards = defs.map(function(def) {
    var d = r[def.key] || {};
    return '<div class="source-mini-card" style="--card-color:'+def.color+'"><span class="smc-icon">'+(d.icon||'?')+'</span><div class="smc-name">'+(d.source||def.key)+'</div>'+vbadge(d.verdict||'unknown')+def.metric(d)+'</div>';
  }).join('');
  var mitre = (ai.attackTechniques||[]).map(function(t){ return '<span class="mitre-tag">'+esc(t)+'</span>'; }).join('');
  var recs  = (ai.recommendations||[]).map(function(rc,i){ return '<div class="rec-item"><span class="rec-num">'+String(i+1).padStart(2,'0')+'</span><span>'+esc(rc)+'</span></div>'; }).join('');
  setHTML('overviewContent',
    '<div class="grid-3" style="margin-bottom:18px;">'+cards+'</div>'
    +'<div class="grid-2">'
    +'<div class="card" style="border-color:rgba(139,92,246,.3)"><div class="card-header">🤖 AI Executive Summary</div><div style="font-size:13px;line-height:1.85;color:var(--t-1)">'+esc(ai.executiveSummary||'—')+'</div>'+(mitre?'<div class="mitre-tags">'+mitre+'</div>':'')+'</div>'
    +'<div class="card"><div class="card-header">📋 Recommendations</div><div class="rec-list">'+(recs||'<div style="color:var(--t-2);font-size:12px;">No recommendations.</div>')+'</div></div>'
    +'</div>');
}

/* ================================================================
   RENDER: VIRUSTOTAL TAB
================================================================ */
function renderVT() {
  var d = state.results.virustotal || {};
  var total = Math.max(1, d.engines||72), s = d.stats||{};
  var mw = ((s.malicious||0)/total*100).toFixed(1);
  var sw = ((s.suspicious||0)/total*100).toFixed(1);
  var hw = ((s.harmless||0)/total*100).toFixed(1);
  var detRate = (d.detections||0)+'/'+( d.engines||0);
  var detColor = (d.detections||0)>10?'var(--critical)':(d.detections||0)>3?'var(--high)':'var(--low)';
  var vtLink = 'https://www.virustotal.com/gui/'+({ip:'ip-address',domain:'domain',url:'url',hash:'file',sha256:'file',md5:'file',sha1:'file'}[state.iocType]||'search')+'/'+encodeURIComponent(state.ioc);

  // Top section: detection bar + counts
  var header = '<div class="card" style="margin-bottom:14px;">'
    +'<div class="card-header" style="justify-content:space-between">🛡️ VirusTotal '+vbadge(d.verdict,'chip')
    +'<a href="'+vtLink+'" target="_blank" class="urlscan-link" style="margin-left:auto;font-size:10px;">View on VT ↗</a></div>'
    +'<div class="vt-gauge-row">'
    +'<div class="vt-detection-big" style="color:'+detColor+'">'+esc(detRate)+'</div>'
    +'<div style="flex:1">'
    +'<div class="det-bar" style="height:14px;border-radius:7px;margin-bottom:8px">'
    +'<div class="db-m" style="width:'+mw+'%;min-width:'+(s.malicious?'4px':'0')+'"></div>'
    +'<div class="db-s" style="width:'+sw+'%;min-width:'+(s.suspicious?'4px':'0')+'"></div>'
    +'<div class="db-h" style="width:'+hw+'%"></div>'
    +'<div class="db-u" style="flex:1"></div>'
    +'</div>'
    +'<div class="det-legend">'
    +'<span class="dl-item"><span class="dl-dot" style="background:var(--critical)"></span><strong style="color:var(--critical)">'+(s.malicious||0)+'</strong> Malicious</span>'
    +'<span class="dl-item"><span class="dl-dot" style="background:var(--high)"></span><strong style="color:var(--high)">'+(s.suspicious||0)+'</strong> Suspicious</span>'
    +'<span class="dl-item"><span class="dl-dot" style="background:var(--low)"></span>'+(s.harmless||0)+' Harmless</span>'
    +'<span class="dl-item"><span class="dl-dot" style="background:var(--b-2)"></span>'+(s.undetected||0)+' Undetected</span>'
    +'</div></div></div>'
    +'</div>';

  // Middle: metadata grid
  var meta = '<div class="grid-2" style="margin-bottom:14px;">'
    +'<div class="card"><div class="card-header">📊 Analysis Details</div>'
    +drow('Detection Rate', detRate, (d.detections||0)>10?'red':(d.detections||0)>3?'orange':'green')
    +drow('Reputation', String(d.reputation||0), (d.reputation||0)<-10?'red':(d.reputation||0)>0?'green':'')
    +drow('First Seen', d.firstSeen||'—')
    +drow('Last Analysis', d.lastSeen||'—')
    +(d.timesSubmitted!==null&&d.timesSubmitted!==undefined?drow('Times Submitted', String(d.timesSubmitted)):'')
    +(d.fileName?drow('File Name', d.fileName):'')
    +(d.fileType?drow('File Type', d.fileType):'')
    +(d.fileSize?drow('File Size', d.fileSize):'')
    +(d.md5?drow('MD5', d.md5,'cyan'):'')
    +(d.sha1?drow('SHA-1', d.sha1,'cyan'):'')
    +(d.sha256?drow('SHA-256', d.sha256,'cyan'):'')
    +(d.asn?drow('ASN', d.asn):'')
    +(d.country?drow('Country', d.country):'')
    +(d.network?drow('Network', d.network):'')
    +(d.finalUrl?drow('Final URL', d.finalUrl):'')
    +(d.title?drow('Page Title', d.title):'')
    +'</div>'
    +'<div class="card"><div class="card-header">🏷️ Classification</div>'
    +(d.popularThreatLabel?'<div class="vt-threat-label">'+esc(d.popularThreatLabel)+'</div>':'')
    +((d.popularThreatCategory||[]).length?'<div style="margin-bottom:8px;"><div style="font-size:9px;color:var(--t-2);letter-spacing:1px;text-transform:uppercase;margin-bottom:4px;">Category</div>'+d.popularThreatCategory.map(function(c){return chip(c,'chip-red');}).join('')+'</div>':'')
    +((d.popularThreatName||[]).length?'<div style="margin-bottom:8px;"><div style="font-size:9px;color:var(--t-2);letter-spacing:1px;text-transform:uppercase;margin-bottom:4px;">Malware Name</div>'+d.popularThreatName.map(function(c){return chip(c,'chip-orange');}).join('')+'</div>':'')
    +((d.tags||[]).length?'<div style="margin-bottom:8px;"><div style="font-size:9px;color:var(--t-2);letter-spacing:1px;text-transform:uppercase;margin-bottom:4px;">Tags</div>'+d.tags.map(function(t){return chip(t,'chip-gray');}).join('')+'</div>':'')
    +((d.categories||[]).length?'<div style="margin-bottom:8px;"><div style="font-size:9px;color:var(--t-2);letter-spacing:1px;text-transform:uppercase;margin-bottom:4px;">Categories</div>'
      +d.categories.map(function(c){return '<div style="font-size:11px;padding:3px 0;border-bottom:1px solid var(--b-1);display:flex;justify-content:space-between"><span style="color:var(--t-2)">'+esc(c.vendor||'')+'</span><span style="font-family:var(--mono)">'+esc(c.cat||c+'')+'</span></div>';}).join('')+'</div>':'')
    +(d.votes?'<div style="margin-top:8px;"><div style="font-size:9px;color:var(--t-2);letter-spacing:1px;text-transform:uppercase;margin-bottom:4px;">Community Votes</div>'
      +'<span style="color:var(--low);font-size:12px">👍 '+d.votes.harmless+' Harmless</span>&nbsp;&nbsp;'
      +'<span style="color:var(--critical);font-size:12px">👎 '+d.votes.malicious+' Malicious</span></div>':'')
    +'</div></div>';

  // Engine detections table
  var engines = '';
  if ((d.detectedEngines||[]).length) {
    engines = '<div class="card"><div class="card-header">🔍 Detecting Engines ('+(d.detectedEngines||[]).length+' shown)</div>'
      +'<div style="overflow-x:auto;">'
      +'<table style="width:100%;border-collapse:collapse;font-size:11px;">'
      +'<thead><tr style="border-bottom:1px solid var(--b-1);">'
      +'<th style="text-align:left;padding:6px 8px;color:var(--t-2);font-weight:600;font-size:9px;letter-spacing:1px;text-transform:uppercase;">Engine</th>'
      +'<th style="text-align:left;padding:6px 8px;color:var(--t-2);font-weight:600;font-size:9px;letter-spacing:1px;text-transform:uppercase;">Detection</th>'
      +'<th style="text-align:left;padding:6px 8px;color:var(--t-2);font-weight:600;font-size:9px;letter-spacing:1px;text-transform:uppercase;">Category</th>'
      +'</tr></thead><tbody>'
      +(d.detectedEngines||[]).map(function(e){
        var catColor = e.category==='malicious'?'var(--critical)':'var(--high)';
        return '<tr style="border-bottom:1px solid rgba(26,48,80,.4);">'
          +'<td style="padding:6px 8px;font-family:var(--mono);color:var(--cyan);">'+esc(e.name)+'</td>'
          +'<td style="padding:6px 8px;color:'+catColor+';font-family:var(--mono);">'+esc(e.result)+'</td>'
          +'<td style="padding:6px 8px;"><span style="font-size:8px;font-weight:700;padding:2px 6px;border-radius:3px;background:rgba(240,48,96,.1);color:'+catColor+';border:1px solid rgba(240,48,96,.3);text-transform:uppercase;">'+esc(e.category)+'</span></td>'
          +'</tr>';
      }).join('')
      +'</tbody></table></div></div>';
  }

  setHTML('vtContent', header + meta + engines + demoNote(d));
}

/* ================================================================
   RENDER: ABUSEIPDB TAB
================================================================ */
function renderAbuse() {
  var d = state.results.abuseipdb || {};
  if (d.notApplicable) { setHTML('abuseContent','<div class="na-state"><div class="na-icon">⚠️</div><div class="na-text">'+esc(d.message||'Not applicable.')+'</div></div>'); return; }
  var sc = d.abuseScore || 0;
  var scColor = sc>70?'var(--critical)':sc>30?'var(--high)':'var(--low)';
  var cats = Array.from(new Set(d.categories||[])).slice(0,10);
  setHTML('abuseContent',
    '<div class="grid-2">'
    +'<div class="card"><div class="card-header">⚠️ AbuseIPDB '+vbadge(d.verdict,'chip')+'</div>'
    +'<div class="abuse-score-display"><div class="abuse-score-num" style="color:'+scColor+'">'+sc+'%</div>'
    +'<div class="abuse-score-lbl">Abuse Confidence Score</div>'
    +'<div class="abuse-bar-wrap"><div class="abuse-bar"><div class="abuse-needle" style="left:'+sc+'%"></div></div>'
    +'<div class="abuse-markers"><span>0</span><span>25</span><span>50</span><span>75</span><span>100</span></div></div></div>'
    +drow('Total Reports', d.totalReports, (d.totalReports||0)>100?'red':'')
    +drow('Distinct Reporters', d.distinctUsers)
    +drow('Last Reported', d.lastReported)
    +drow('Country', (d.country||'—')+' — '+(d.countryName||'—'))
    +drow('ISP / ASN', d.isp)
    +drow('Usage Type', d.usageType)
    +drow('Whitelisted', d.isWhitelisted?'Yes':'No', d.isWhitelisted?'green':'')
    +demoNote(d)+'</div>'
    +'<div class="card"><div class="card-header">Abuse Categories</div>'
    +(cats.length ? cats.map(function(c){ return '<div style="display:flex;justify-content:space-between;align-items:center;padding:8px 10px;background:var(--bg-4);border:1px solid var(--b-1);border-radius:6px;margin-bottom:5px;font-size:12px;"><span>'+esc(ABUSE_CATS[c]||'Category '+c)+'</span>'+chip('Cat.'+c,'chip-orange')+'</div>'; }).join('')
      : '<div style="color:var(--t-2);font-size:12px;padding:8px 0;">No abuse categories reported.</div>')
    +'</div></div>');
}

/* ================================================================
   RENDER: HYBRID ANALYSIS TAB
================================================================ */
function renderAnyrun() {
  var d = state.results.hybrid || {};

  // No API key case
  if (d._apiError && d._apiError.indexOf('not configured') >= 0) {
    setHTML('hybridContent',
      '<div class="na-state">'
      +'<div class="na-icon">🔬</div>'
      +'<div style="font-family:var(--display);font-size:16px;color:var(--t-1);margin-top:6px;">API Key Required</div>'
      +'<div class="na-text" style="margin-top:8px;">Get a <strong>free</strong> key at <a href="https://hybrid-analysis.com/apikeys" target="_blank" style="color:var(--cyan)">hybrid-analysis.com/apikeys</a></div>'
      +'<div class="na-text" style="margin-top:4px;font-family:var(--mono);font-size:10px;color:var(--t-2);">Add as <code style="color:var(--cyan)">HYBRID_KEY</code> in server/index.js</div>'
      +'<a href="https://hybrid-analysis.com/search?query='+encodeURIComponent(state.ioc)+'" target="_blank" class="urlscan-link" style="margin-top:16px;">Search on Hybrid Analysis ↗</a>'
      +'</div>');
    return;
  }

  // No reports found
  if (!d.found && !d._demo) {
    setHTML('hybridContent',
      '<div class="na-state">'
      +'<div class="na-icon">🔬</div>'
      +'<div class="na-text" style="margin-top:6px;">'+esc(d.message||'No analysis found.')+'</div>'
      +(d.hint?'<div class="na-text" style="color:var(--t-3);font-size:11px;margin-top:4px;">'+esc(d.hint)+'</div>':'')
      +'<a href="https://hybrid-analysis.com/search?query='+encodeURIComponent(state.ioc)+'" target="_blank" class="urlscan-link" style="margin-top:14px;">Search on Hybrid Analysis ↗</a>'
      +'</div>');
    return;
  }

  var tsColor = (d.threatScore||0)>70?'var(--critical)':(d.threatScore||0)>40?'var(--high)':'var(--low)';

  var html = '<div class="card"><div class="card-header">🔬 Hybrid Analysis '+vbadge(d.verdict,'chip')+'</div>'
    +'<div class="ar-stats">'
    +'<div class="ar-stat"><div class="ar-stat-num" style="color:'+tsColor+'">'+(d.threatScore||0)+'</div><div class="ar-stat-lbl">Threat Score</div></div>'
    +'<div class="ar-stat"><div class="ar-stat-num" style="color:'+((d.maliciousCount||0)>0?'var(--critical)':'var(--low)')+'">'+(d.maliciousCount||0)+'</div><div class="ar-stat-lbl">Malicious</div></div>'
    +'<div class="ar-stat"><div class="ar-stat-num" style="color:'+((d.suspiciousCount||0)>0?'var(--high)':'var(--low)')+'">'+(d.suspiciousCount||0)+'</div><div class="ar-stat-lbl">Suspicious</div></div>'
    +'<div class="ar-stat"><div class="ar-stat-num" style="color:var(--cyan)">'+(d.totalResults||0)+'</div><div class="ar-stat-lbl">Reports</div></div>'
    +'</div>'
    +(d.malwareFamily?'<div class="ar-malware"><div class="ar-malware-lbl">🦠 Malware Family</div><div class="ar-malware-name">'+esc(d.malwareFamily)+'</div></div>':'')
    +drow('Verdict', (d.verdict||'unknown').toUpperCase(), d.verdict==='malicious'?'red':d.verdict==='suspicious'?'orange':'green')
    +drow('Threat Level', d.threatLevel||'No specific threat')
    +drow('Environment', d.environment||'Unknown')
    +(d.sha256?drow('SHA-256', d.sha256, 'cyan'):'')
    +(d.submitName?drow('Submit Name', d.submitName):'')
    +(d.extractedFiles?drow('Extracted Files', String(d.extractedFiles)):'')
    +((d.tags||[]).length?'<div style="margin-top:10px;">'+d.tags.map(function(t){return chip(t,'chip-red');}).join('')+'</div>':'')
    +((d.classification||[]).length?'<div style="margin-top:6px;">'+d.classification.map(function(t){return chip(t,'chip-orange');}).join('')+'</div>':'');

  if ((d.samples||[]).length > 0) {
    html += '<div style="margin-top:14px;"><div class="card-header">Sample Reports</div>'
      +d.samples.map(function(s){
        var vc = s.verdict==='malicious'?'var(--critical)':s.verdict==='suspicious'?'var(--high)':'var(--low)';
        return '<div style="display:flex;align-items:center;gap:10px;padding:7px 0;border-bottom:1px solid var(--b-1);font-size:11px;">'
          +'<span style="font-family:var(--mono);font-size:9px;font-weight:700;padding:2px 6px;border-radius:3px;background:rgba(240,48,96,.1);color:'+vc+';border:1px solid rgba(240,48,96,.2);text-transform:uppercase;">'+(s.verdict||'?')+'</span>'
          +(s.family?'<span style="color:var(--high)">'+esc(s.family)+'</span>':'')
          +'<span style="font-family:var(--mono);font-size:9px;color:var(--t-2);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1">'+(s.sha256||'—').slice(0,24)+'...</span>'
          +'</div>';
      }).join('')+'</div>';
  }

  html += '<a href="https://hybrid-analysis.com/search?query='+encodeURIComponent(state.ioc)+'" target="_blank" class="urlscan-link" style="margin-top:14px;">View on Hybrid Analysis ↗</a>'
    + demoNote(d) + '</div>';

  setHTML('hybridContent', html);
}


/* ================================================================
   RENDER: SHODAN TAB
================================================================ */
function renderShodan() {
  var d = state.results.shodan || {};
  if (d.notApplicable) { setHTML('shodanContent','<div class="na-state"><div class="na-icon">🌐</div><div class="na-text">'+esc(d.message||'Not applicable.')+'</div></div>'); return; }
  setHTML('shodanContent',
    '<div class="grid-2">'
    +'<div class="card"><div class="card-header">🌐 Shodan '+vbadge(d.verdict||'info','chip')+'</div>'
    +'<div class="ports-display">'+((d.ports||[]).map(function(p){ return '<span class="port-chip">'+p+'</span>'; }).join('')||'<span style="color:var(--t-2);font-size:12px;">No open ports found</span>')+'</div>'
    +drow('Organization', d.org)
    +drow('Country', d.country)
    +drow('City', d.city)
    +(d.isp?drow('ISP', d.isp):'')
    +(d.os?drow('OS', d.os):'')
    +drow('Last Updated', d.lastUpdate)
    +demoNote(d)+'</div>'
    +'<div class="card"><div class="card-header">Vulnerabilities & Banners</div>'
    +((d.vulns||[]).length
      ?'<div style="margin-bottom:14px;"><div style="font-size:9px;letter-spacing:2px;color:var(--critical);text-transform:uppercase;margin-bottom:8px;">⚠️ Known CVEs</div>'+d.vulns.map(function(v){ return chip(v,'chip-red'); }).join('')+'</div>'
      :'<div style="color:var(--low);font-size:12px;margin-bottom:14px;">✓ No known CVEs detected</div>')
    +((d.banners||[]).filter(Boolean).length
      ?'<div><div style="font-size:9px;letter-spacing:2px;color:var(--t-2);text-transform:uppercase;margin-bottom:8px;">Service Banners</div>'
        +d.banners.filter(Boolean).map(function(b){ return '<div style="font-family:var(--mono);font-size:10px;color:var(--t-1);padding:5px 9px;background:var(--bg-4);border-left:2px solid var(--b-2);border-radius:0 5px 5px 0;margin-bottom:4px;">'+esc(b)+'</div>'; }).join('')+'</div>'
      :'')
    +((d.hostnames||[]).length?'<div style="margin-top:12px;">'+d.hostnames.map(function(h){ return chip(h,'chip-cyan'); }).join('')+'</div>':'')
    +'</div></div>');
}

/* ================================================================
   RENDER: WHOIS TAB
================================================================ */
function renderWhois() {
  var d = state.results.whois || {};

  if (d.notApplicable) {
    setHTML('whoisContent','<div class="na-state"><div class="na-icon">📋</div><div class="na-text">'+esc(d.message||'Not applicable.')+'</div></div>');
    return;
  }

  var ageColor = d.daysOld>=0 ? (d.daysOld<30?'red':d.daysOld<180?'orange':'') : '';
  var ageLabel = d.daysOld>=0
    ? (d.daysOld<30 ? d.daysOld+' days — ⚠️ NEWLY REGISTERED'
       : d.daysOld>730 ? Math.floor(d.daysOld/365)+' yr '+(d.daysOld%365)+' d'
       : d.daysOld+' days')
    : '—';

  var html = '<div class="grid-2">'
    +'<div class="card"><div class="card-header">📋 Registration '+(d.newDomain?chip('⚠️ NEW','chip-red'):'')+'</div>'
    +drow('Registrar', d.registrar||'—')
    +drow('Domain', d.ldhName||state.ioc)
    +drow('Created', d.createdDate||'—', d.newDomain?'red':'')
    +drow('Last Updated', d.updatedDate||'—')
    +(d.expiryDate&&d.expiryDate!=='N/A'?drow('Expires', d.expiryDate):'')
    +drow('Domain Age', ageLabel, ageColor)
    +drow('DNSSEC', d.dnssec||'—', d.dnssec==='signed'?'green':d.dnssec==='unsigned'?'orange':'')
    +(d.port43?drow('WHOIS Server', d.port43):'')
    +((d.nameservers||[]).length
      ?'<div style="margin-top:10px;"><div style="font-size:9px;letter-spacing:2px;color:var(--t-2);text-transform:uppercase;margin-bottom:6px;">Nameservers</div>'
        +d.nameservers.map(function(n){ return '<div style="font-family:var(--mono);font-size:11px;color:var(--cyan);padding:3px 0;border-bottom:1px solid var(--b-1);">'+esc(n)+'</div>'; }).join('')+'</div>'
      :'')
    +'</div>'
    +'<div class="card"><div class="card-header">🌍 Network & Location</div>'
    +(d.asn?drow('ASN', d.asn,'cyan'):'')
    +(d.country||d.countryName?drow('Country', (d.country||'')+(d.countryName?' — '+d.countryName:'')):'')
    +(d.region?drow('Region', d.region):'')
    +(d.city?drow('City', d.city):'')
    +(d.timezone?drow('Timezone', d.timezone):'')
    +((d.status||[]).length
      ?'<div style="margin-top:12px;"><div style="font-size:9px;letter-spacing:2px;color:var(--t-2);text-transform:uppercase;margin-bottom:6px;">Domain Status</div>'
        +d.status.slice(0,6).map(function(sv){
          return chip(sv.replace('https://icann.org/epp#','').replace('clientT','Client T').replace('clientD','Client D'), 'chip-green');
        }).join('')+'</div>'
      :'')
    +(d.newDomain
      ?'<div style="margin-top:14px;padding:10px 14px;background:rgba(240,48,96,.07);border:1px solid rgba(240,48,96,.28);border-radius:8px;font-size:12px;color:var(--critical);">⚠️ <strong>Newly registered</strong> — common malicious infrastructure indicator.</div>'
      :d.daysOld>=0&&d.daysOld<180
        ?'<div style="margin-top:14px;padding:10px 14px;background:rgba(240,112,32,.07);border:1px solid rgba(240,112,32,.25);border-radius:8px;font-size:12px;color:var(--high);">ℹ️ Less than 6 months old — exercise caution.</div>'
        :d.daysOld>365
          ?'<div style="margin-top:14px;padding:10px 14px;background:rgba(32,208,128,.06);border:1px solid rgba(32,208,128,.22);border-radius:8px;font-size:12px;color:var(--low);">✓ Established domain — registered over a year ago.</div>'
          :'')
    +'</div></div>';

  setHTML('whoisContent', html + demoNote(d));
}


/* ================================================================
   RENDER: AI ANALYSIS TAB
================================================================ */
function renderAITab() {
  var ai = state.ai || {}, rs = ai.riskScore || 0;
  var rc = rs>=80?'var(--critical)':rs>=50?'var(--high)':rs>=20?'var(--medium)':'var(--low)';
  var cc = ai.confidence==='high'?'var(--low)':ai.confidence==='low'?'var(--critical)':'var(--medium)';
  var tc = ({RED:'var(--critical)',AMBER:'var(--medium)',GREEN:'var(--low)',WHITE:'#e0e0e0'})[ai.tlp]||'var(--t-1)';
  var techs = (ai.attackTechniques||[]).map(function(t){ return '<span class="mitre-tag">'+esc(t)+'</span>'; }).join('');
  var recs  = (ai.recommendations||[]).map(function(r,i){ return '<div class="rec-item"><span class="rec-num">'+String(i+1).padStart(2,'0')+'</span><span>'+esc(r)+'</span></div>'; }).join('');
  setHTML('aiContent',
    '<div class="ai-meta-grid">'
    +'<div class="ai-meta-card"><div class="ai-meta-lbl">Risk Score</div><div class="ai-meta-val" style="color:'+rc+'">'+rs+'/100</div></div>'
    +'<div class="ai-meta-card"><div class="ai-meta-lbl">Verdict</div><div class="ai-meta-val" style="color:'+rc+'">'+(ai.verdict||'—').toUpperCase()+'</div></div>'
    +'<div class="ai-meta-card"><div class="ai-meta-lbl">Confidence</div><div class="ai-meta-val" style="color:'+cc+'">'+(ai.confidence||'—').toUpperCase()+'</div></div>'
    +'<div class="ai-meta-card"><div class="ai-meta-lbl">TLP</div><div class="ai-meta-val" style="color:'+tc+'">TLP:'+(ai.tlp||'—')+'</div></div>'
    +'</div>'
    +'<div class="ai-summary-card"><div class="ai-summary-lbl">Executive Summary</div><div class="ai-summary-body">'+esc(ai.executiveSummary||'—')+'</div></div>'
    +'<div class="card ai-context-card"><div class="card-header">IOC Context & Attribution</div>'
    +'<div style="font-size:13px;line-height:1.85;color:var(--t-1);margin-bottom:10px;">'+esc(ai.iocContext||'—')+'</div>'
    +(ai.threatActor?'<div class="threat-banner tb-actor"><strong style="color:var(--critical);">⚠️ Threat Actor: </strong><span style="font-family:var(--mono)">'+esc(ai.threatActor)+'</span></div>':'')
    +(ai.malwareFamily?'<div class="threat-banner tb-mal"><strong style="color:#a78bfa;">🦠 Malware Family: </strong><span style="font-family:var(--mono)">'+esc(ai.malwareFamily)+'</span></div>':'')
    +(ai.priorityAction?'<div class="priority-box"><div class="priority-lbl">⚡ Priority Action</div><div class="priority-txt">'+esc(ai.priorityAction)+'</div></div>':'')
    +'</div>'
    +'<div class="ai-bottom-grid">'
    +'<div class="card"><div class="card-header">MITRE ATT&CK® Techniques</div><div class="mitre-tags">'+(techs||'<span style="color:var(--t-2);font-size:12px;">No techniques identified</span>')+'</div>'
    +((ai.tags||[]).length?'<div style="margin-top:12px;">'+ai.tags.map(function(t){ return chip(t,'chip-purple'); }).join('')+'</div>':'')
    +'</div>'
    +'<div class="card"><div class="card-header">Remediation Recommendations</div><div class="rec-list">'+(recs||'<div style="color:var(--t-2);font-size:12px;">No recommendations.</div>')+'</div></div>'
    +'</div>');
}

/* ================================================================
   CHAT
================================================================ */
function renderChatWelcome() {
  var msgs = document.getElementById('chatMsgs');
  if (!msgs) return;
  chatHistory = [];
  msgs.innerHTML = '';
  var ai = state.ai || {};
  var welcome = 'Investigation complete for **'+esc(state.ioc)+'**.\n\nRisk Score: **'+(ai.riskScore||0)+'/100** · Verdict: **'+(ai.verdict||'unknown').toUpperCase()+'**\n\n'+esc(ai.executiveSummary||'')+'\n\n💬 Ask me anything — firewall rules, SIEM queries, MITRE techniques, IR playbook, threat attribution.';
  appendChatBubble('ai', welcome);

  var suggestions = ['What firewall rules should I create?','Give me SIEM hunting queries','Is this a false positive?','Walk me through the IR playbook','Explain the MITRE techniques'];
  var suggWrap = document.createElement('div');
  suggWrap.className = 'chat-suggestions';
  suggestions.forEach(function(s) {
    var btn = document.createElement('button');
    btn.className = 'sugg-btn';
    btn.textContent = s;
    btn.addEventListener('click', function() {
      document.getElementById('chatTA').value = s;
      sendChat();
    });
    suggWrap.appendChild(btn);
  });
  msgs.appendChild(suggWrap);
}

function sendChat() {
  if (chatBusy) return;
  var ta  = document.getElementById('chatTA');
  var msg = ta ? ta.value.trim() : '';
  if (!msg) return;
  ta.value = '';
  if (ta) { ta.style.height='auto'; }
  chatBusy = true;
  updateSendBtn(true);

  var sugg = document.querySelector('.chat-suggestions');
  if (sugg) sugg.remove();

  appendChatBubble('user', msg);
  chatHistory.push({ role:'user', content:msg });
  showTypingIndicator();

  getChatReply().then(function(reply) {
    hideTypingIndicator();
    chatHistory.push({ role:'assistant', content:reply });
    appendChatBubble('ai', reply);
    chatBusy = false;
    updateSendBtn(false);
  }).catch(function(e) {
    hideTypingIndicator();
    appendChatBubble('ai', '⚠️ Error: ' + e.message);
    chatBusy = false;
    updateSendBtn(false);
  });
}

function appendChatBubble(role, content) {
  var msgs = document.getElementById('chatMsgs');
  if (!msgs) return;
  var div = document.createElement('div');
  div.className = 'chat-msg ' + role;
  var formatted = formatChatText(content);
  if (role === 'ai') {
    div.innerHTML = '<div class="chat-avatar ai">🤖</div><div class="chat-bubble">'+formatted+'</div>';
  } else {
    div.innerHTML = '<div class="chat-bubble">'+formatted+'</div><div class="chat-avatar user">👤</div>';
  }
  msgs.appendChild(div);
  msgs.scrollTop = msgs.scrollHeight;
}

function formatChatText(txt) {
  if (!txt) return '';
  var s = txt.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  s = s.replace(/```(\w+)?\n?([\s\S]*?)```/g, function(_,l,c){ return '<pre style="background:var(--bg-0);border:1px solid var(--b-1);border-radius:6px;padding:10px;margin:6px 0;overflow-x:auto;font-family:var(--mono);font-size:11px;color:var(--cyan);">'+c.trim()+'</pre>'; });
  s = s.replace(/`([^`]+)`/g, '<code style="background:var(--bg-0);border:1px solid var(--b-1);border-radius:3px;padding:1px 5px;font-family:var(--mono);font-size:11px;color:var(--cyan);">$1</code>');
  s = s.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  s = s.replace(/\n/g, '<br>');
  return s;
}

var typingEl = null;
function showTypingIndicator() {
  var msgs = document.getElementById('chatMsgs');
  if (!msgs) return;
  typingEl = document.createElement('div');
  typingEl.className = 'chat-msg ai';
  typingEl.innerHTML = '<div class="chat-avatar ai">🤖</div><div class="chat-bubble"><div class="typing-indicator"><div class="typing-dot"></div><div class="typing-dot"></div><div class="typing-dot"></div></div></div>';
  msgs.appendChild(typingEl);
  msgs.scrollTop = msgs.scrollHeight;
}
function hideTypingIndicator() { if (typingEl) { typingEl.remove(); typingEl = null; } }
function updateSendBtn(busy) {
  var btn = document.getElementById('chatSend');
  if (!btn) return;
  btn.disabled = busy;
  btn.innerHTML = busy ? '<div style="width:12px;height:12px;border:2px solid rgba(255,255,255,.3);border-top-color:#fff;border-radius:50%;animation:spin .8s linear infinite"></div>' : '↑';
}

/* ================================================================
   EXPORT REPORT
================================================================ */
function exportReport() {
  if (!state.ioc || !state.ai) { showToast('No investigation to export.', 'warning'); return; }
  var ai=state.ai||{}, r=state.results;
  var vt=r.virustotal||{}, abu=r.abuseipdb||{}, run=r.anyrun||{}, sh=r.shodan||{}, wh=r.whois||{};
  var rs=ai.riskScore||0;
  var rc=rs>=80?'#f03060':rs>=50?'#f07020':rs>=20?'#f0c020':'#20d080';
  var tlpCol=({RED:'#f03060',AMBER:'#f09020',GREEN:'#20d080',WHITE:'#e0e0e0'})[ai.tlp]||'#f09020';
  var repId='TIP-'+Math.random().toString(36).slice(2,10).toUpperCase();
  var dr=function(k,v,c){ return '<div style="display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid #1a3050;gap:12px;"><span style="font-size:11px;color:#3a5570;">'+k+'</span><span style="font-family:monospace;font-size:11px;color:'+(c||'#c8d8e8')+';text-align:right;word-break:break-all;">'+(v||'—')+'</span></div>'; };
  var vtTotal=Math.max(1,vt.engines||72);
  var vtMalW=((vt.stats?vt.stats.malicious||0:0)/vtTotal*100).toFixed(1);
  var vtSusW=((vt.stats?vt.stats.suspicious||0:0)/vtTotal*100).toFixed(1);

  var fetchComments = state.currentInvId
    ? callAPI('/api/investigations/'+state.currentInvId, undefined, 'GET').then(function(inv){ return inv?inv.comments||[]:[];}).catch(function(){return [];})
    : Promise.resolve([]);

  fetchComments.then(function(cmts) {
    var commentsHTML = '';
    if (cmts.length > 0) {
      commentsHTML = '<div class="sec"><div class="sec-title">06 — Analyst Notes ('+cmts.length+')</div><div class="box">'+cmts.map(function(c){ return '<div style="padding:10px 14px;background:#0e2040;border-left:3px solid #00c8f0;border-radius:0 6px 6px 0;margin-bottom:8px;"><div style="font-size:13px;white-space:pre-wrap;word-break:break-word;">'+c.text.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')+'</div><div style="font-size:10px;color:#3a5570;margin-top:5px;">'+new Date(c.createdAt).toLocaleString()+'</div></div>'; }).join('')+'</div></div>';
    }

    var html = '<!DOCTYPE html><html><head><meta charset="UTF-8"/><title>ThreatIntel Report — '+state.ioc+'</title>'
      +'<style>*{box-sizing:border-box;margin:0;padding:0;}body{background:#040d1a;color:#c8d8e8;font-family:\'Segoe UI\',sans-serif;font-size:13px;-webkit-print-color-adjust:exact;}'
      +'.page{max-width:900px;margin:0 auto;padding:36px 40px;}'
      +'.grad{height:3px;background:linear-gradient(90deg,#00c8f0,#8b5cf6,#f03060);margin-bottom:22px;}'
      +'.hdr{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:18px;padding-bottom:14px;border-bottom:1px solid #1a3050;}'
      +'.logo{font-size:22px;font-weight:700;letter-spacing:2px;}.logo span{color:#00c8f0;}'
      +'.hdr-r{text-align:right;font-family:monospace;font-size:10px;color:#3a5570;}'
      +'.rid{color:#00c8f0;font-size:13px;font-weight:700;margin-bottom:3px;}'
      +'.tlp-bar{display:flex;align-items:center;gap:12px;padding:8px 16px;border-radius:7px;background:'+tlpCol+'18;border:1px solid '+tlpCol+'44;margin-bottom:20px;}'
      +'.tlp-lbl{font-family:monospace;font-size:12px;font-weight:700;color:'+tlpCol+';letter-spacing:2px;}'
      +'.hero{background:#0a1628;border:1px solid #1a3050;border-radius:10px;padding:20px;margin-bottom:20px;display:flex;gap:24px;flex-wrap:wrap;}'
      +'.rn{font-family:monospace;font-size:54px;font-weight:900;color:'+rc+';line-height:1;}'
      +'.rb{height:8px;background:linear-gradient(90deg,#20d080,#f0c020,#f07020,#f03060);border-radius:4px;margin-bottom:8px;}'
      +'.badge{font-family:monospace;font-size:9px;font-weight:700;letter-spacing:1.5px;padding:3px 9px;border-radius:4px;display:inline-block;}'
      +'.bm{background:rgba(240,48,96,.15);color:#f03060;border:1px solid rgba(240,48,96,.4);}'
      +'.bs{background:rgba(240,112,32,.15);color:#f07020;border:1px solid rgba(240,112,32,.4);}'
      +'.bc{background:rgba(32,208,128,.15);color:#20d080;border:1px solid rgba(32,208,128,.4);}'
      +'.bu{background:rgba(74,106,138,.15);color:#7a9ab8;border:1px solid rgba(74,106,138,.4);}'
      +'.prio{flex:1;min-width:200px;background:rgba(240,48,96,.06);border:1px solid rgba(240,48,96,.25);border-radius:8px;padding:14px;}'
      +'.sec{margin-bottom:22px;}.sec-title{font-size:8px;letter-spacing:3px;color:#3a5570;text-transform:uppercase;padding-bottom:8px;border-bottom:1px solid #1a3050;margin-bottom:14px;}'
      +'.box{background:#0a1628;border:1px solid #1a3050;border-radius:8px;padding:16px;}'
      +'.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px;}'
      +'.chip{font-family:monospace;font-size:10px;padding:2px 8px;border-radius:4px;display:inline-block;margin:2px;}'
      +'.cr{background:rgba(240,48,96,.12);color:#f03060;border:1px solid rgba(240,48,96,.3);}'
      +'.cc{background:rgba(0,200,240,.12);color:#00c8f0;border:1px solid rgba(0,200,240,.3);}'
      +'.mt{font-family:monospace;font-size:10px;padding:3px 8px;background:rgba(240,160,32,.1);color:#f0a020;border:1px solid rgba(240,160,32,.28);border-radius:4px;display:inline-block;margin:2px;}'
      +'.db{display:flex;height:10px;border-radius:5px;overflow:hidden;gap:1px;background:#1a3050;margin:8px 0;}'
      +'.dm{background:#f03060;width:'+vtMalW+'%;}.ds{background:#f07020;width:'+vtSusW+'%;}.dh{background:#20d080;flex:1;}'
      +'.ft{display:flex;justify-content:space-between;padding-top:16px;margin-top:24px;border-top:1px solid #1a3050;font-family:monospace;font-size:10px;color:#3a5570;}'
      +'</style></head><body><div class="page">'
      +'<div class="grad"></div>'
      +'<div class="hdr"><div><div class="logo">THREAT<span>INTEL</span></div><div style="font-size:9px;letter-spacing:2px;color:#3a5570;text-transform:uppercase;margin-top:2px;">SOC Intelligence Platform · Threat Report</div></div>'
      +'<div class="hdr-r"><div class="rid">'+repId+'</div><div>'+new Date().toLocaleString()+'</div><div>TLP:'+(ai.tlp||'AMBER')+'</div></div></div>'
      +'<div class="tlp-bar"><span class="tlp-lbl">TLP:'+(ai.tlp||'AMBER')+'</span><span style="font-size:11px;color:#7a9ab8;">'+(ai.tlp==='RED'?'NOT for disclosure.':ai.tlp==='AMBER'?'Limited disclosure to own org and partners.':'Community sharing permitted.')+'</span></div>'
      +'<div class="hero"><div>'
      +'<div style="font-size:8px;letter-spacing:3px;color:#3a5570;text-transform:uppercase;margin-bottom:4px;">🎯 IOC · '+state.iocType.toUpperCase()+'</div>'
      +'<div style="font-family:monospace;font-size:16px;color:#00c8f0;margin-bottom:12px;">'+state.ioc+'</div>'
      +'<div class="rn">'+rs+'</div><div style="font-size:8px;letter-spacing:2px;color:#3a5570;text-transform:uppercase;margin:3px 0 10px;">RISK SCORE</div>'
      +'<div class="rb"></div>'
      +'<span class="badge '+(ai.verdict==='malicious'?'bm':ai.verdict==='suspicious'?'bs':ai.verdict==='clean'?'bc':'bu')+'">'+(ai.verdict||'UNKNOWN').toUpperCase()+'</span>'
      +'</div>'
      +(ai.priorityAction?'<div class="prio"><div style="font-size:8px;letter-spacing:2px;color:#f03060;text-transform:uppercase;margin-bottom:4px;">⚡ PRIORITY ACTION</div><div style="font-size:12px;margin-top:3px;">'+ai.priorityAction+'</div></div>':'')
      +'</div>'
      +'<div class="sec"><div class="sec-title">01 — Executive Summary</div><div class="box"><div style="line-height:1.85;color:#7a9ab8;">'+(ai.executiveSummary||'—')+'</div>'
      +(ai.threatActor?'<div style="margin-top:10px;padding:9px 12px;background:rgba(240,48,96,.06);border:1px solid rgba(240,48,96,.25);border-radius:6px;font-size:12px;"><strong style="color:#f03060;">⚠️ Threat Actor: </strong>'+ai.threatActor+'</div>':'')
      +(ai.malwareFamily?'<div style="margin-top:8px;padding:9px 12px;background:rgba(139,92,246,.06);border:1px solid rgba(139,92,246,.25);border-radius:6px;font-size:12px;"><strong style="color:#a78bfa;">🦠 Malware: </strong>'+ai.malwareFamily+'</div>':'')
      +'</div></div>'
      +((ai.attackTechniques||[]).length?'<div class="sec"><div class="sec-title">02 — MITRE ATT&CK® Techniques</div><div>'+(ai.attackTechniques||[]).map(function(t){ return '<span class="mt">'+t+'</span>'; }).join('')+'</div></div>':'')
      +'<div class="sec"><div class="sec-title">03 — OSINT Source Analysis</div><div class="grid">'
      +'<div class="box"><div style="font-weight:700;margin-bottom:10px;">🛡️ VirusTotal</div><div class="db"><div class="dm"></div><div class="ds"></div><div class="dh"></div></div>'
      +dr('Detection Rate',(vt.detections||0)+'/'+(vt.engines||0)+' engines',(vt.detections||0)>5?'#f03060':'')
      +dr('Reputation',vt.reputation)+dr('First Seen',vt.firstSeen)+dr('Last Seen',vt.lastSeen)+'</div>'
      +(!abu.notApplicable?'<div class="box"><div style="font-weight:700;margin-bottom:10px;">⚠️ AbuseIPDB</div><div style="font-family:monospace;font-size:48px;font-weight:900;color:'+((abu.abuseScore||0)>70?'#f03060':(abu.abuseScore||0)>30?'#f07020':'#20d080')+';line-height:1;margin-bottom:8px;">'+(abu.abuseScore||0)+'%</div>'+dr('Reports',abu.totalReports)+dr('Country',abu.countryName)+dr('ISP',abu.isp)+'</div>':'')
      +'<div class="box"><div style="font-weight:700;margin-bottom:10px;">🔬 Hybrid Analysis</div>'
      +dr('Threat Score',(run.threatScore||0)+'/100',(run.threatScore||0)>70?'#f03060':'')
      +dr('Malicious Reports',run.maliciousCount||0,run.maliciousCount>0?'#f03060':'#20d080')
      +(run.malwareFamily?dr('Malware',run.malwareFamily,'#f03060'):'')
      +dr('Total Reports',run.totalResults||0)+'</div>'
      +(!sh.notApplicable?'<div class="box"><div style="font-weight:700;margin-bottom:10px;">🌐 Shodan</div><div style="display:flex;flex-wrap:wrap;gap:5px;margin-bottom:10px;">'+(sh.ports||[]).map(function(p){ return '<span class="chip cc">'+p+'</span>'; }).join('')+'</div>'+dr('Org',sh.org)+dr('Country',sh.country)+((sh.vulns||[]).length?'<div style="margin-top:8px;">'+(sh.vulns||[]).map(function(v){ return '<span class="chip cr">'+v+'</span>'; }).join('')+'</div>':'<div style="color:#20d080;font-size:11px;margin-top:6px;">✓ No known CVEs</div>')+'</div>':'')
      +'<div class="box"><div style="font-weight:700;margin-bottom:10px;">📋 WHOIS</div>'+dr('Registrar',wh.registrar)+dr('Created',wh.createdDate,wh.newDomain?'#f03060':'')+dr('Country',wh.country||wh.countryName)+dr('DNSSEC',wh.dnssec)+(wh.daysOld>=0?dr('Domain Age',wh.daysOld+' days',wh.daysOld<30?'#f03060':''):'')+'</div>'
      +'</div></div>'
      +(ai.iocContext?'<div class="sec"><div class="sec-title">04 — IOC Context</div><div class="box" style="line-height:1.85;color:#7a9ab8;">'+ai.iocContext+'</div></div>':'')
      +((ai.recommendations||[]).length?'<div class="sec"><div class="sec-title">05 — Recommendations</div><div class="box">'+(ai.recommendations||[]).map(function(rc2,i){ return '<div style="display:flex;gap:10px;padding:7px 0;border-bottom:1px solid #1a3050;font-size:12px;color:#7a9ab8;"><span style="font-family:monospace;font-weight:700;color:#00c8f0;flex-shrink:0;">'+String(i+1).padStart(2,'0')+'</span><span>'+rc2+'</span></div>'; }).join('')+'</div></div>':'')
      +commentsHTML
      +'<div class="ft"><span>ThreatIntel Platform · SOC Intelligence Suite</span><span>TLP:'+(ai.tlp||'AMBER')+' · '+repId+'</span><span>CONFIDENTIAL</span></div>'
      +'</div></body></html>';

    var a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([html], { type:'text/html' }));
    a.download = 'ThreatIntel-'+state.ioc.replace(/[^a-z0-9._-]/gi,'_')+'.html';
    a.click();
    showToast('Report exported!', 'success');
  });
}

/* ================================================================
   UI HELPERS
================================================================ */
function showSection(name) {
  document.getElementById('emptyState').style.display   = name==='empty'   ? 'flex' : 'none';
  document.getElementById('loadingPanel').style.display = name==='loading'  ? 'flex' : 'none';
  document.getElementById('resultsPanel').style.display = name==='results'  ? 'flex' : 'none';
}

function switchTab(name) {
  document.querySelectorAll('.tab-btn').forEach(function(b) { b.classList.toggle('active', b.dataset.tab===name); });
  document.querySelectorAll('.tab-panel').forEach(function(p) { p.classList.toggle('active', p.id==='tab-'+name); });
}

function setLoadStage(t) { setText('loadStage', t); }
function markDone(id) { var e=document.getElementById(id); if(e) e.classList.add('done'); }
function updateBadge(v) { setText('iocBadge', v.trim() ? classifyIOC(v).toUpperCase() : '—'); }

var toastTimer = null;
function showToast(msg, type) {
  var t = document.getElementById('toast');
  var c = {info:'var(--cyan)',success:'var(--low)',warning:'var(--medium)',error:'var(--critical)'};
  t.style.borderColor = c[type]||c.info;
  t.style.color       = c[type]||c.info;
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(function(){ t.classList.remove('show'); }, 3500);
}

/* ================================================================
   INIT — runs on DOMContentLoaded
================================================================ */
document.addEventListener('DOMContentLoaded', function () {

  // Auth check — redirect to login if session expired
  fetch('/api/auth/me', { credentials:'include' }).then(function(r) {
    if (!r.ok) { window.location.href='/'; return; }
    return r.json().then(function(data) {
      var u = data.user || {};
      sessionStorage.setItem('user', JSON.stringify(u));
      var nameEl = document.getElementById('analystName');
      var roleEl = document.getElementById('analystRole');
      var avEl   = document.getElementById('analystAvatar');
      var display = u.nickname || u.username || 'Analyst';
      if (nameEl) nameEl.textContent = display;
      if (roleEl) roleEl.textContent = u.role || 'SOC Analyst';
      if (avEl) {
        // Show initials of nickname/username
        var initials = display.split(' ').map(function(w){return w[0]||'';}).join('').slice(0,3).toUpperCase() || 'SOC';
        avEl.textContent = initials;
      }
      loadHistory();
      initToolPages();
    });
  }).catch(function() { window.location.href='/'; });

  // Clock
  function tick() { setText('clock', new Date().toTimeString().slice(0,8)+' UTC'); }
  tick(); setInterval(tick, 1000);

  // Search input
  var iocInput = document.getElementById('iocInput');
  if (iocInput) {
    iocInput.addEventListener('input',   function(e) { updateBadge(e.target.value); });
    iocInput.addEventListener('keydown', function(e) { if (e.key==='Enter') investigate(); });
  }

  // Investigate button
  var goBtn = document.getElementById('goBtn');
  if (goBtn) goBtn.addEventListener('click', investigate);

  // Export button
  var exportBtn = document.getElementById('exportBtn');
  if (exportBtn) exportBtn.addEventListener('click', exportReport);

  // Logout button
  var logoutBtn = document.getElementById('logoutBtn');
  if (logoutBtn) logoutBtn.addEventListener('click', logout);

  // Sidebar toggle — desktop collapses width, mobile uses overlay
  function openSidebar() {
    var sb  = document.getElementById('sidebar');
    var bd  = document.getElementById('sidebarBackdrop');
    if (!sb) return;
    var isMobile = window.innerWidth <= 768;
    if (isMobile) {
      sb.classList.add('mobile-open');
      if (bd) bd.classList.add('open');
      document.body.style.overflow = 'hidden'; // prevent body scroll while sidebar open
    } else {
      // Desktop: toggle collapse
      var collapsed = sb.dataset.collapsed === '1';
      sb.style.width = collapsed ? 'var(--sidebar-w)' : '0px';
      sb.dataset.collapsed = collapsed ? '0' : '1';
    }
  }

  function closeSidebar() {
    var sb = document.getElementById('sidebar');
    var bd = document.getElementById('sidebarBackdrop');
    if (!sb) return;
    sb.classList.remove('mobile-open');
    if (bd) bd.classList.remove('open');
    document.body.style.overflow = ''; // restore body scroll
  }

  var sidebarToggle = document.getElementById('sidebarToggle');
  if (sidebarToggle) sidebarToggle.addEventListener('click', openSidebar);
  var sbClose = document.getElementById('sbClose');
  if (sbClose) sbClose.addEventListener('click', closeSidebar);
  var backdrop = document.getElementById('sidebarBackdrop');
  if (backdrop) backdrop.addEventListener('click', closeSidebar);

  // Nav items
  var navLookup = document.getElementById('nav-lookup');
  if (navLookup) navLookup.addEventListener('click', function() { if(iocInput) iocInput.focus(); });
  var navExport = document.getElementById('nav-export');
  if (navExport) navExport.addEventListener('click', exportReport);
  var navToggle = document.getElementById('nav-toggle');
  if (navToggle) navToggle.addEventListener('click', function() {
    var sb = document.getElementById('sidebar');
    sb.style.width = sb.style.width === '0px' ? 'var(--sidebar-w)' : '0px';
  });

  // Example buttons
  var examples = [
    { id:'ex1', ioc:'185.220.101.45' },
    { id:'ex2', ioc:'malware-c2.ru' },
    { id:'ex3', ioc:'44d88612fea8a8f36de82e1278abb02f' },
    { id:'ex4', ioc:'https://phishing-example.com/login' }
  ];
  examples.forEach(function(ex) {
    var btn = document.getElementById(ex.id);
    if (btn) btn.addEventListener('click', function() {
      iocInput.value = ex.ioc;
      updateBadge(ex.ioc);
      investigate();
    });
  });

  // Tab buttons
  document.querySelectorAll('.tab-btn').forEach(function(btn) {
    btn.addEventListener('click', function() { switchTab(btn.dataset.tab); });
  });

  // Chat send button
  var chatSend = document.getElementById('chatSend');
  if (chatSend) chatSend.addEventListener('click', sendChat);

  // Ctrl+K focuses the notes textarea
  document.addEventListener('keydown', function(e) {
    if (e.ctrlKey && (e.key === 'k' || e.key === 'K')) {
      var ta = document.getElementById('commentTA');
      if (ta) { e.preventDefault(); switchTab('notes'); setTimeout(function(){ ta.focus(); }, 50); }
    }
  });

  // Chat textarea
  var chatTA = document.getElementById('chatTA');
  if (chatTA) {
    chatTA.addEventListener('keydown', function(e) {
      if (e.key==='Enter' && !e.shiftKey) { e.preventDefault(); sendChat(); }
    });
    chatTA.addEventListener('input', function() {
      chatTA.style.height = 'auto';
      chatTA.style.height = Math.min(chatTA.scrollHeight, 110) + 'px';
    });
  }
});

/* ================================================================
   TOOL PAGES — individual standalone tool lookups
================================================================ */

var TOOL_PAGES = ['vt','abuse','shodan','hybrid','urlscan','whois','mb','feeds','sandbox','graph','hasher','logs','investigations'];

function initToolPages() {
  // Wire sidebar nav items
  TOOL_PAGES.forEach(function(tool) {
    var navBtn = document.getElementById('nav-tool-'+tool);
    if (navBtn) {
      navBtn.addEventListener('click', function() {
        showToolPage(tool);
        if (window.innerWidth <= 768) closeSidebar();
      });
    }
  });

  // Dashboard nav
  var navDash = document.getElementById('nav-dashboard');
  if (navDash) navDash.addEventListener('click', function() {
    showDashboard();
    if (window.innerWidth <= 768) closeSidebar();
  });

  // Wire each tool's run button and input
  wireToolPage('vt',      document.getElementById('vt-tool-input'),      document.getElementById('vt-tool-btn'),      'vt-tool-badge',      'vt-tool-result',      runVTTool);
  wireToolPage('abuse',   document.getElementById('abuse-tool-input'),   document.getElementById('abuse-tool-btn'),   'abuse-tool-badge',   'abuse-tool-result',   runAbuseTool);
  wireToolPage('shodan',  document.getElementById('shodan-tool-input'),  document.getElementById('shodan-tool-btn'),  'shodan-tool-badge',  'shodan-tool-result',  runShodanTool);
  wireToolPage('hybrid',  document.getElementById('hybrid-tool-input'),  document.getElementById('hybrid-tool-btn'),  'hybrid-tool-badge',  'hybrid-tool-result',  runHybridTool);
  wireToolPage('urlscan', document.getElementById('urlscan-tool-input'), document.getElementById('urlscan-tool-btn'), 'urlscan-tool-badge', 'urlscan-tool-result', runURLScanTool);
  wireToolPage('whois',   document.getElementById('whois-tool-input'),   document.getElementById('whois-tool-btn'),   'whois-tool-badge',   'whois-tool-result',   runWhoisTool);

  // New feature pages
  var feedsBtn = document.getElementById('feeds-refresh-btn');
  if (feedsBtn) feedsBtn.addEventListener('click', loadFeeds);

  // Feed filter buttons
  var feedFilters = document.querySelectorAll('.feed-filter');
  feedFilters.forEach(function(btn) {
    btn.addEventListener('click', function() {
      feedFilters.forEach(function(b) { b.classList.remove('active'); });
      btn.classList.add('active');
      renderFeedTable(btn.dataset.filter);
    });
  });

  // Sandbox dropzone
  initSandbox();

  // Graph
  var graphInput = document.getElementById('graph-tool-input');
  var graphBtn   = document.getElementById('graph-tool-btn');
  if (graphInput) {
    graphInput.addEventListener('input', function() { setText('graph-tool-badge', graphInput.value.trim() ? classifyIOC(graphInput.value).toUpperCase() : '—'); });
    graphInput.addEventListener('keydown', function(e) { if (e.key==='Enter') runGraph(); });
  }
  if (graphBtn) graphBtn.addEventListener('click', runGraph);

  // Hash calculator
  initHasher();

  // Log analyzer
  initLogAnalyzer();

  // MalwareBazaar
  initMalwareBazaar();

  // Investigations nav item
  var navInvs = document.getElementById('nav-tool-investigations');
  if (navInvs) navInvs.addEventListener('click', function() {
    showToolPage('investigations');
    renderAllInvestigations();
    if (window.innerWidth <= 768) closeSidebar();
  });

  // All investigations page back button
  var invBackBtn = document.getElementById('invPageBackBtn');
  if (invBackBtn) invBackBtn.addEventListener('click', showDashboard);

  // All investigations search + filter
  var invSearch = document.getElementById('invSearchInput');
  var invFilter = document.getElementById('invFilterVerdict');
  if (invSearch) invSearch.addEventListener('input', renderAllInvestigations);
  if (invFilter) invFilter.addEventListener('change', renderAllInvestigations);
}

function wireToolPage(name, inputEl, btnEl, badgeId, resultId, runFn) {
  if (!inputEl || !btnEl) return;
  inputEl.addEventListener('input', function() { setText(badgeId, inputEl.value.trim() ? classifyIOC(inputEl.value).toUpperCase() : '—'); });
  inputEl.addEventListener('keydown', function(e) { if (e.key === 'Enter') runFn(); });
  btnEl.addEventListener('click', runFn);
}

function showToolPage(tool) {
  // Hide dashboard
  var dash = document.getElementById('dashboard-view');
  if (dash) dash.style.display = 'none';
  // Hide all tool pages
  TOOL_PAGES.forEach(function(t) {
    var pg = document.getElementById('page-tool-'+t);
    if (pg) pg.style.display = 'none';
  });
  // Show the selected tool page
  var pg = document.getElementById('page-tool-'+tool);
  if (pg) pg.style.display = 'flex';
  // Update sidebar active
  document.querySelectorAll('.nav-item').forEach(function(n) { n.classList.remove('active'); });
  var navBtn = document.getElementById('nav-tool-'+tool);
  if (navBtn) navBtn.classList.add('active');
  // Refresh investigations page when opened
  if (tool === 'investigations') renderAllInvestigations();
}

function showDashboard() {
  TOOL_PAGES.forEach(function(t) {
    var pg = document.getElementById('page-tool-'+t);
    if (pg) pg.style.display = 'none';
  });
  var dash = document.getElementById('dashboard-view');
  if (dash) dash.style.display = 'flex';
  document.querySelectorAll('.nav-item').forEach(function(n) { n.classList.remove('active'); });
  var navDash = document.getElementById('nav-dashboard');
  if (navDash) navDash.classList.add('active');
}

// ── Tool run helpers ────────────────────────────────────────────
function setToolLoading(btnId, resultId, on) {
  var btn = document.getElementById(btnId);
  if (btn) { btn.disabled = on; btn.textContent = on ? 'Running...' : btn.dataset.label || 'Run'; }
  if (on) setHTML(resultId, '<div class="tool-empty"><div class="tool-empty-icon" style="animation:float 2s infinite">⏳</div><div class="tool-empty-title">Querying...</div></div>');
}

function renderToolResult(resultId, html) {
  setHTML(resultId, '<div class="tool-result">'+html+'</div>');
}

function toolDrow(k, v, cls) { return drow(k, v, cls); }

// ── VT Tool ─────────────────────────────────────────────────────
function runVTTool() {
  var inp = document.getElementById('vt-tool-input');
  var ioc = inp ? inp.value.trim() : '';
  if (!ioc) { showToast('Enter an IOC to scan.', 'warning'); return; }
  var type = classifyIOC(ioc);
  if (type === 'unknown') { showToast('Unrecognized IOC format.', 'warning'); return; }
  document.getElementById('vt-tool-btn').dataset.label = 'Scan';
  setToolLoading('vt-tool-btn', 'vt-tool-result', true);
  callAPI('/api/virustotal', { ioc:ioc, type:type }).then(function(d) {
    setToolLoading('vt-tool-btn', 'vt-tool-result', false);
    if (!d) return;
    var total=Math.max(1,d.engines||72), s=d.stats||{};
    var mw=((s.malicious||0)/total*100).toFixed(1), sw=((s.suspicious||0)/total*100).toFixed(1), hw=((s.harmless||0)/total*100).toFixed(1);
    renderToolResult('vt-tool-result',
      '<div class="card"><div class="card-header">🛡️ VirusTotal — <span style="font-family:var(--mono);font-size:11px">'+esc(ioc)+'</span> '+vbadge(d.verdict,'chip')+'</div>'
      +'<div class="det-bar-wrap"><div class="det-bar"><div class="db-m" style="width:'+mw+'%"></div><div class="db-s" style="width:'+sw+'%"></div><div class="db-h" style="width:'+hw+'%"></div><div class="db-u" style="flex:1"></div></div>'
      +'<div class="det-legend"><span class="dl-item"><span class="dl-dot" style="background:var(--critical)"></span>'+(s.malicious||0)+' Malicious</span><span class="dl-item"><span class="dl-dot" style="background:var(--high)"></span>'+(s.suspicious||0)+' Suspicious</span><span class="dl-item"><span class="dl-dot" style="background:var(--low)"></span>'+(s.harmless||0)+' Harmless</span><span class="dl-item"><span class="dl-dot" style="background:var(--b-2)"></span>'+(s.undetected||0)+' Undetected</span></div></div>'
      +toolDrow('Detection Rate',(d.detections||0)+' / '+(d.engines||0)+' engines',(d.detections||0)>5?'red':'green')
      +toolDrow('Reputation', d.reputation, (d.reputation||0)<-10?'red':'')
      +toolDrow('First Seen', d.firstSeen)+toolDrow('Last Seen', d.lastSeen)
      +((d.categories||[]).length?toolDrow('Categories',d.categories.join(', ')):'')
      +((d.tags||[]).length?'<div style="margin-top:10px;">'+d.tags.map(function(t){return chip(t,'chip-red');}).join('')+'</div>':'')
      +demoNote(d)
      +'<a href="https://www.virustotal.com/gui/search/'+encodeURIComponent(ioc)+'" target="_blank" class="urlscan-link" style="margin-top:12px">View on VirusTotal ↗</a>'
      +'</div>');
  }).catch(function(e) {
    setToolLoading('vt-tool-btn','vt-tool-result',false);
    renderToolResult('vt-tool-result','<div class="card"><div style="color:var(--critical);padding:10px">Error: '+esc(e.message)+'</div></div>');
  });
}

// ── AbuseIPDB Tool ───────────────────────────────────────────────
function runAbuseTool() {
  var inp = document.getElementById('abuse-tool-input');
  var ioc = inp ? inp.value.trim() : '';
  if (!ioc) { showToast('Enter an IP address.', 'warning'); return; }
  var type = classifyIOC(ioc);
  if (type !== 'ip') { showToast('AbuseIPDB only supports IPv4 addresses.', 'warning'); return; }
  document.getElementById('abuse-tool-btn').dataset.label = 'Check IP';
  setToolLoading('abuse-tool-btn','abuse-tool-result',true);
  callAPI('/api/abuseipdb', { ioc:ioc, type:type }).then(function(d) {
    setToolLoading('abuse-tool-btn','abuse-tool-result',false);
    if (!d) return;
    var sc=d.abuseScore||0;
    var scColor=sc>70?'var(--critical)':sc>30?'var(--high)':'var(--low)';
    var cats=Array.from(new Set(d.categories||[])).slice(0,10);
    renderToolResult('abuse-tool-result',
      '<div class="grid-2">'
      +'<div class="card"><div class="card-header">⚠️ AbuseIPDB — '+esc(ioc)+' '+vbadge(d.verdict,'chip')+'</div>'
      +'<div class="abuse-score-display"><div class="abuse-score-num" style="color:'+scColor+'">'+sc+'%</div>'
      +'<div class="abuse-score-lbl">Abuse Confidence Score</div>'
      +'<div class="abuse-bar-wrap"><div class="abuse-bar"><div class="abuse-needle" style="left:'+sc+'%"></div></div>'
      +'<div class="abuse-markers"><span>0</span><span>25</span><span>50</span><span>75</span><span>100</span></div></div></div>'
      +toolDrow('Total Reports',d.totalReports)+toolDrow('Distinct Reporters',d.distinctUsers)
      +toolDrow('Last Reported',d.lastReported)+toolDrow('Country',(d.country||'—')+' — '+(d.countryName||'—'))
      +toolDrow('ISP / ASN',d.isp)+toolDrow('Usage Type',d.usageType)
      +toolDrow('Whitelisted',d.isWhitelisted?'Yes':'No',d.isWhitelisted?'green':'')
      +demoNote(d)
      +'<a href="https://www.abuseipdb.com/check/'+encodeURIComponent(ioc)+'" target="_blank" class="urlscan-link" style="margin-top:12px">View on AbuseIPDB ↗</a>'
      +'</div>'
      +'<div class="card"><div class="card-header">Reported Categories</div>'
      +(cats.length?cats.map(function(c){return '<div style="display:flex;justify-content:space-between;align-items:center;padding:8px 10px;background:var(--bg-4);border:1px solid var(--b-1);border-radius:6px;margin-bottom:5px;font-size:12px;"><span>'+esc(ABUSE_CATS[c]||'Category '+c)+'</span>'+chip('Cat.'+c,'chip-orange')+'</div>';}).join('')
        :'<div style="color:var(--t-2);font-size:12px;padding:8px 0;">No categories reported.</div>')
      +'</div></div>');
  }).catch(function(e) {
    setToolLoading('abuse-tool-btn','abuse-tool-result',false);
    renderToolResult('abuse-tool-result','<div class="card"><div style="color:var(--critical);padding:10px">Error: '+esc(e.message)+'</div></div>');
  });
}

// ── Shodan Tool ──────────────────────────────────────────────────
function runShodanTool() {
  var inp = document.getElementById('shodan-tool-input');
  var ioc = inp ? inp.value.trim() : '';
  if (!ioc) { showToast('Enter an IP or domain.', 'warning'); return; }
  var type = classifyIOC(ioc);
  if (type!=='ip'&&type!=='domain') { showToast('Shodan supports IPs and domains only.', 'warning'); return; }
  document.getElementById('shodan-tool-btn').dataset.label = 'Lookup';
  setToolLoading('shodan-tool-btn','shodan-tool-result',true);
  callAPI('/api/shodan', { ioc:ioc, type:type }).then(function(d) {
    setToolLoading('shodan-tool-btn','shodan-tool-result',false);
    if (!d) return;
    renderToolResult('shodan-tool-result',
      '<div class="grid-2">'
      +'<div class="card"><div class="card-header">🌐 Shodan — '+esc(ioc)+' '+vbadge(d.verdict||'info','chip')+'</div>'
      +'<div class="ports-display">'+((d.ports||[]).map(function(p){return '<span class="port-chip">'+p+'</span>';}).join('')||'<span style="color:var(--t-2);font-size:12px;">No open ports</span>')+'</div>'
      +toolDrow('Organization',d.org)+toolDrow('Country',d.country)+toolDrow('City',d.city)
      +(d.isp?toolDrow('ISP',d.isp):'')+(d.os?toolDrow('OS',d.os):'')
      +toolDrow('Last Updated',d.lastUpdate)
      +demoNote(d)
      +'<a href="https://www.shodan.io/host/'+encodeURIComponent(ioc)+'" target="_blank" class="urlscan-link" style="margin-top:12px">View on Shodan ↗</a>'
      +'</div>'
      +'<div class="card"><div class="card-header">Vulnerabilities & Banners</div>'
      +((d.vulns||[]).length?'<div style="margin-bottom:12px;"><div style="font-size:9px;letter-spacing:2px;color:var(--critical);text-transform:uppercase;margin-bottom:8px;">⚠️ Known CVEs</div>'+d.vulns.map(function(v){return chip(v,'chip-red');}).join('')+'</div>'
        :'<div style="color:var(--low);font-size:12px;margin-bottom:12px;">✓ No known CVEs</div>')
      +((d.banners||[]).filter(Boolean).length?d.banners.filter(Boolean).map(function(b){return '<div style="font-family:var(--mono);font-size:10px;color:var(--t-1);padding:5px 9px;background:var(--bg-4);border-left:2px solid var(--b-2);border-radius:0 5px 5px 0;margin-bottom:4px;">'+esc(b)+'</div>';}).join(''):'')
      +'</div></div>');
  }).catch(function(e) {
    setToolLoading('shodan-tool-btn','shodan-tool-result',false);
    renderToolResult('shodan-tool-result','<div class="card"><div style="color:var(--critical);padding:10px">Error: '+esc(e.message)+'</div></div>');
  });
}

// ── Hybrid Analysis Tool ─────────────────────────────────────────
function runHybridTool() {
  var inp = document.getElementById('hybrid-tool-input');
  var ioc = inp ? inp.value.trim() : '';
  if (!ioc) { showToast('Enter a hash, domain, IP, or URL.', 'warning'); return; }
  var type = classifyIOC(ioc);
  if (type === 'unknown') { showToast('Unrecognized IOC format.', 'warning'); return; }
  document.getElementById('hybrid-tool-btn').dataset.label = 'Analyze';
  setToolLoading('hybrid-tool-btn','hybrid-tool-result',true);
  callAPI('/api/hybrid', { ioc:ioc, type:type }).then(function(d) {
    setToolLoading('hybrid-tool-btn','hybrid-tool-result',false);
    if (!d) return;
    if (!d.found) {
      renderToolResult('hybrid-tool-result',
        '<div class="card"><div class="card-header">🔬 Hybrid Analysis — '+esc(ioc)+'</div>'
        +'<div style="color:var(--t-2);padding:14px 0;font-size:13px;">'+esc(d.message||'No reports found.')+'</div>'
        +'<a href="https://hybrid-analysis.com" target="_blank" class="urlscan-link">Submit for analysis ↗</a>'
        +'</div>');
      return;
    }
    var tsColor=(d.threatScore||0)>70?'var(--critical)':(d.threatScore||0)>40?'var(--high)':'var(--low)';
    renderToolResult('hybrid-tool-result',
      '<div class="card"><div class="card-header">🔬 Hybrid Analysis — '+esc(ioc)+' '+vbadge(d.verdict,'chip')+'</div>'
      +'<div class="ar-stats">'
      +'<div class="ar-stat"><div class="ar-stat-num" style="color:'+tsColor+'">'+(d.threatScore||0)+'</div><div class="ar-stat-lbl">Threat Score</div></div>'
      +'<div class="ar-stat"><div class="ar-stat-num" style="color:'+((d.maliciousCount||0)>0?'var(--critical)':'var(--low)')+'">'+(d.maliciousCount||0)+'</div><div class="ar-stat-lbl">Malicious</div></div>'
      +'<div class="ar-stat"><div class="ar-stat-num" style="color:'+((d.suspiciousCount||0)>0?'var(--high)':'var(--low)')+'">'+(d.suspiciousCount||0)+'</div><div class="ar-stat-lbl">Suspicious</div></div>'
      +'<div class="ar-stat"><div class="ar-stat-num" style="color:var(--cyan)">'+(d.totalResults||0)+'</div><div class="ar-stat-lbl">Total</div></div>'
      +'</div>'
      +(d.malwareFamily?'<div class="ar-malware"><div class="ar-malware-lbl">🦠 Malware Family</div><div class="ar-malware-name">'+esc(d.malwareFamily)+'</div></div>':'')
      +toolDrow('Threat Level',d.threatLevel||'—')
      +toolDrow('Environment',d.environment||'—')
      +(d.sha256?toolDrow('SHA256',d.sha256,'cyan'):'')
      +((d.tags||[]).length?'<div style="margin-top:10px;">'+d.tags.map(function(t){return chip(t,'chip-red');}).join('')+'</div>':'')
      +((d.samples||[]).length?'<div style="margin-top:14px;"><div class="card-header">Sample Reports</div>'
        +d.samples.map(function(s){return '<div class="hybrid-sample"><span class="chip '+(s.verdict==='malicious'?'chip-red':s.verdict==='suspicious'?'chip-orange':'chip-green')+'">'+esc(s.verdict||'clean')+'</span><span style="font-family:var(--mono);font-size:10px;color:var(--t-1);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1">'+esc(s.sha256||'—')+'</span><span style="font-size:10px;color:var(--t-2)">'+esc(s.env||'')+'</span></div>';}).join('')
        +'</div>':'')
      +demoNote(d)
      +'<a href="https://hybrid-analysis.com/search?query='+encodeURIComponent(ioc)+'" target="_blank" class="urlscan-link" style="margin-top:12px">View on Hybrid Analysis ↗</a>'
      +'</div>');
  }).catch(function(e) {
    setToolLoading('hybrid-tool-btn','hybrid-tool-result',false);
    renderToolResult('hybrid-tool-result','<div class="card"><div style="color:var(--critical);padding:10px">Error: '+esc(e.message)+'</div></div>');
  });
}

// ── URLScan Tool ─────────────────────────────────────────────────
function runURLScanTool() {
  var inp = document.getElementById('urlscan-tool-input');
  var ioc = inp ? inp.value.trim() : '';
  if (!ioc) { showToast('Enter a URL, domain, or IP.', 'warning'); return; }
  var type = classifyIOC(ioc);
  if (type!=='url'&&type!=='domain'&&type!=='ip') { showToast('URLScan supports URLs, domains, and IPs.', 'warning'); return; }
  document.getElementById('urlscan-tool-btn').dataset.label = 'Scan';
  setToolLoading('urlscan-tool-btn','urlscan-tool-result',true);
  callAPI('/api/urlscan', { ioc:ioc, type:type }).then(function(d) {
    setToolLoading('urlscan-tool-btn','urlscan-tool-result',false);
    if (!d) return;
    if (!d.found) {
      renderToolResult('urlscan-tool-result',
        '<div class="card"><div class="card-header">🔎 URLScan.io — '+esc(ioc)+'</div>'
        +'<div style="color:var(--t-2);padding:14px 0;font-size:13px;">'+esc(d.message||'No scans found.')
        +(d.submitted?'\n\n✅ New scan submitted! Check back in ~30 seconds.\n'+esc(d.submitted.resultUrl||''):'')
        +'</div>'
        +(d.submitted?'<a href="'+esc(d.submitted.resultUrl||'#')+'" target="_blank" class="urlscan-link">View scan result ↗</a>':'')
        +'</div>');
      return;
    }
    var scoreColor=d.score>70?'var(--critical)':d.score>30?'var(--high)':'var(--low)';
    renderToolResult('urlscan-tool-result',
      '<div class="card"><div class="card-header">🔎 URLScan.io — '+esc(ioc)+' '+vbadge(d.verdict,'chip')+'</div>'
      +(d.screenshotUrl?'<div class="urlscan-screenshot"><img src="'+esc(d.screenshotUrl)+'" alt="Screenshot" onerror="this.parentNode.style.display=\'none\'"/></div>':'')
      +'<div style="margin-top:12px;">'
      +toolDrow('Final URL',d.url)
      +toolDrow('Domain',d.domain)
      +toolDrow('IP',d.ip)
      +toolDrow('Country',d.country)
      +toolDrow('Server',d.server)
      +(d.title?toolDrow('Page Title',d.title):'')
      +toolDrow('Malicious',d.malicious?'YES ⚠️':'No',d.malicious?'red':'green')
      +toolDrow('Risk Score',String(d.score||0)+'/100',scoreColor)
      +toolDrow('Total Scans',''+d.totalScans)
      +(d.scanDate?toolDrow('Latest Scan',new Date(d.scanDate).toLocaleString()):'')
      +((d.categories||[]).length?'<div style="margin-top:10px;">'+d.categories.map(function(c){return chip(c,'chip-red');}).join('')+'</div>':'')
      +'</div>'
      +(d.resultUrl?'<a href="'+esc(d.resultUrl)+'" target="_blank" class="urlscan-link" style="margin-top:12px">View full report ↗</a>':'')
      +'</div>');
  }).catch(function(e) {
    setToolLoading('urlscan-tool-btn','urlscan-tool-result',false);
    renderToolResult('urlscan-tool-result','<div class="card"><div style="color:var(--critical);padding:10px">Error: '+esc(e.message)+'</div></div>');
  });
}

// ── WHOIS Tool ───────────────────────────────────────────────────
function runWhoisTool() {
  var inp = document.getElementById('whois-tool-input');
  var ioc = inp ? inp.value.trim() : '';
  if (!ioc) { showToast('Enter a domain or IP.', 'warning'); return; }
  var type = classifyIOC(ioc);
  if (type!=='domain'&&type!=='ip'&&type!=='url') { showToast('WHOIS supports domains and IPs.', 'warning'); return; }
  document.getElementById('whois-tool-btn').dataset.label = 'Lookup';
  setToolLoading('whois-tool-btn','whois-tool-result',true);
  callAPI('/api/whois', { ioc:ioc, type:type }).then(function(d) {
    setToolLoading('whois-tool-btn','whois-tool-result',false);
    if (!d) return;
    renderToolResult('whois-tool-result',
      '<div class="card"><div class="card-header">📋 WHOIS — '+esc(ioc)+(d.newDomain?' '+chip('⚠️ NEW DOMAIN','chip-red'):'')+'</div>'
      +toolDrow('Registrar',d.registrar)+toolDrow('Organization',d.organization)
      +toolDrow('Created',(d.createdDate||'—')+(d.newDomain?' ⚠️':''),d.newDomain?'red':'')
      +toolDrow('Updated',d.updatedDate)
      +(d.expiryDate&&d.expiryDate!=='N/A'?toolDrow('Expires',d.expiryDate):'')
      +(d.countryName?toolDrow('Country',(d.country||'—')+' — '+d.countryName):d.country?toolDrow('Country',d.country):'')
      +(d.asn?toolDrow('ASN',d.asn):'')
      +(d.region?toolDrow('Region / City',d.region+', '+d.city):'')
      +(d.timezone?toolDrow('Timezone',d.timezone):'')
      +(d.daysOld>=0?toolDrow('Domain Age',d.daysOld+' days',d.daysOld<30?'red':''):'')
      +toolDrow('DNSSEC',d.dnssec)
      +((d.nameservers||[]).length?'<div style="margin-top:10px;"><div style="font-size:9px;letter-spacing:2px;color:var(--t-2);text-transform:uppercase;margin-bottom:6px;">Nameservers</div>'+d.nameservers.map(function(n){return chip(n,'chip-cyan');}).join('')+'</div>':'')
      +((d.status||[]).length?'<div style="margin-top:8px;">'+d.status.map(function(s){return chip(s,'chip-green');}).join('')+'</div>':'')
      +'</div>');
  }).catch(function(e) {
    setToolLoading('whois-tool-btn','whois-tool-result',false);
    renderToolResult('whois-tool-result','<div class="card"><div style="color:var(--critical);padding:10px">Error: '+esc(e.message)+'</div></div>');
  });
}

/* ================================================================
   LIVE THREAT FEEDS
================================================================ */
var feedsData = null;

function loadFeeds() {
  var btn = document.getElementById('feeds-refresh-btn');
  if (btn) { btn.disabled = true; btn.textContent = '⏳ Loading...'; }
  setHTML('feeds-result', '<div class="tool-empty"><div class="tool-empty-icon" style="animation:float 2s infinite">📡</div><div class="tool-empty-title">Pulling live threat feeds...</div><div class="tool-empty-sub">Querying Feodo Tracker · URLhaus · ThreatFox · MalwareBazaar · OpenPhish · SSL Blacklist</div></div>');

  callAPI('/api/feeds', { limit: 100 }).then(function(data) {
    if (btn) { btn.disabled = false; btn.textContent = '⟳ Refresh Feeds'; }
    if (!data) return;
    feedsData = data;
    var updated = document.getElementById('feeds-updated');
    if (updated) {
      var liveTag = data._live ? '<span class="live-badge" style="margin-left:8px;"><span class="live-dot"></span>LIVE</span>' : '<span style="font-size:9px;color:var(--medium);margin-left:8px;">DEMO</span>';
      updated.innerHTML = 'Updated: ' + new Date(data.fetchedAt).toLocaleTimeString() + liveTag;
    }
    renderFeedsStats(data);
    var activeFilter = document.querySelector('.feed-filter.active');
    renderFeedTable(activeFilter ? activeFilter.dataset.filter : 'all');
  }).catch(function(e) {
    if (btn) { btn.disabled = false; btn.textContent = '⟳ Refresh Feeds'; }
    setHTML('feeds-result', '<div class="card"><div style="color:var(--critical);padding:14px">Error loading feeds: ' + esc(e.message) + '</div></div>');
  });
}

function renderFeedsStats(data) {
  var statsEl = document.getElementById('feeds-stats');
  if (!statsEl) return;
  statsEl.style.display = '';
  var total = (data.ips||[]).length + (data.domains||[]).length + (data.urls||[]).length + (data.hashes||[]).length;
  var srcs  = (data.sources||[]).join(' · ');
  statsEl.innerHTML = '<div class="feeds-stats-bar">'
    + '<div class="feed-stat"><div class="feed-stat-num" style="color:var(--critical)">' + (data.ips||[]).length + '</div><div class="feed-stat-lbl">Malicious IPs</div></div>'
    + '<div class="feed-stat"><div class="feed-stat-num" style="color:var(--high)">' + (data.domains||[]).length + '</div><div class="feed-stat-lbl">Domains</div></div>'
    + '<div class="feed-stat"><div class="feed-stat-num" style="color:var(--purple)">' + (data.urls||[]).length + '</div><div class="feed-stat-lbl">URLs</div></div>'
    + '<div class="feed-stat"><div class="feed-stat-num" style="color:var(--cyan)">' + (data.hashes||[]).length + '</div><div class="feed-stat-lbl">Hashes</div></div>'
    + '<div class="feed-stat" style="flex:2"><div class="feed-stat-num" style="font-size:14px;color:var(--t-1)">' + total + '</div><div class="feed-stat-lbl">Total IOCs · ' + srcs + '</div></div>'
    + '</div>';
}

function renderFeedTable(filter) {
  if (!feedsData) return;
  var rows = [];
  function addRows(arr, cat) {
    (arr||[]).forEach(function(item) {
      rows.push({
        value: item.value, cat: cat,
        threat: item.threat||'malware',
        source: item.source||'—',
        malware: item.malwareFamily||item.malware||'—',
        country: item.country||'—',
        date: item.dateAdded||item.firstSeen||'—',
        port: item.port||'—',
        confidence: item.confidence||0,
        fileType: item.fileType||'—',
        fileSize: item.fileSize||'—',
        md5: item.md5||'—',
        tags: Array.isArray(item.tags) ? item.tags.join(', ') : (item.tags||'—'),
        urlStatus: item.urlStatus||'—',
      });
    });
  }
  if (filter === 'all' || filter === 'ips')     addRows(feedsData.ips,     'IP');
  if (filter === 'all' || filter === 'domains') addRows(feedsData.domains, 'Domain');
  if (filter === 'all' || filter === 'urls')    addRows(feedsData.urls,    'URL');
  if (filter === 'all' || filter === 'hashes')  addRows(feedsData.hashes,  'Hash');

  if (!rows.length) {
    setHTML('feeds-result', '<div class="tool-empty"><div class="tool-empty-icon">📭</div><div class="tool-empty-title">No indicators in this category</div></div>');
    return;
  }

  function threatClass(t) {
    if (!t) return 'feed-t-other';
    var tl = t.toLowerCase();
    if (tl.includes('botnet') || tl.includes('c2') || tl.includes('c&c')) return 'feed-t-botnet';
    if (tl.includes('phish') || tl.includes('scam')) return 'feed-t-phish';
    if (tl.includes('malware') || tl.includes('trojan') || tl.includes('rat') || tl.includes('ransom')) return 'feed-t-malware';
    return 'feed-t-other';
  }

  var tableHTML = '<div class="feed-search-row"><input id="feedSearchInput" class="search-input" type="text" placeholder="Search IOCs, malware families, sources..." style="padding:8px 12px;font-size:12px;"/></div>'
    + '<div style="overflow:auto;max-height:calc(100vh - 380px);" id="feedTableWrap">'
    + '<table class="feed-table" id="feedTableEl"><thead><tr>'
    + '<th>Type</th><th>IOC</th><th>Threat</th><th>Malware / Tags</th><th>Country</th><th>Source</th><th>Date</th><th></th>'
    + '</tr></thead><tbody>'
    + rows.map(function(r) {
      return '<tr>'
        + '<td><span class="chip chip-gray" style="font-size:9px">' + esc(r.cat) + '</span></td>'
        + '<td><span class="feed-ioc-val" title="' + esc(r.value) + '">' + esc(r.value.slice(0,60) + (r.value.length>60?'…':'')) + '</span></td>'
        + '<td><span class="feed-threat ' + threatClass(r.threat) + '">' + esc(r.threat.slice(0,18)) + '</span></td>'
        + '<td style="font-size:11px;color:var(--t-1)">'
          + esc(r.malware==='—'?'':r.malware.slice(0,24))
          + (r.cat==='IP'&&r.port&&r.port!=='—' ? '<span style="font-family:var(--mono);font-size:9px;color:var(--t-2);margin-left:4px;">:'+esc(r.port)+'</span>' : '')
          + (r.cat==='Hash'&&r.fileType&&r.fileType!=='—' ? '<span style="font-family:var(--mono);font-size:9px;color:var(--t-2);margin-left:4px;">'+esc(r.fileType)+'</span>' : '')
          + (r.cat==='URL'&&r.urlStatus&&r.urlStatus!=='—' ? '<span style="font-size:9px;color:'+(r.urlStatus==='online'?'var(--critical)':'var(--t-2)')+';margin-left:4px;">'+esc(r.urlStatus)+'</span>' : '')
          + '</td>'
        + '<td style="font-size:11px;color:var(--t-2)">'
          + (r.cat==='Hash'&&r.fileSize&&r.fileSize!=='—' ? esc(r.fileSize) : esc(r.country==='—'?'':r.country))
          + '</td>'
        + '<td><span class="feed-source-badge">' + esc((r.source||'').split(' ').slice(0,2).join(' ')) + '</span></td>'
        + '<td style="font-size:10px;color:var(--t-3);font-family:var(--mono)">' + (r.date ? r.date.slice(0,10) : '—') + '</td>'
        + '<td style="white-space:nowrap">'
        + '<button class="feed-copy-btn" data-val="' + esc(r.value) + '" title="Copy IOC" style="margin-right:4px">⎘</button>'
        + '<button class="feed-inv-btn" data-val="' + esc(r.value) + '" title="Investigate this IOC" style="background:none;border:1px solid var(--cyan-border);color:var(--cyan);border-radius:4px;padding:2px 6px;font-size:10px;cursor:pointer;">▶</button>'
        + '</td>'
        + '</tr>';
    }).join('')
    + '</tbody></table></div>';

  setHTML('feeds-result', tableHTML);

  // Wire copy buttons
  document.querySelectorAll('.feed-copy-btn').forEach(function(btn) {
    btn.addEventListener('click', function() {
      navigator.clipboard.writeText(btn.dataset.val).catch(function(){
        // Fallback for browsers without clipboard API
        var ta = document.createElement('textarea');
        ta.value = btn.dataset.val;
        document.body.appendChild(ta); ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
      });
      btn.textContent = '✓';
      setTimeout(function() { btn.textContent = '⎘'; }, 1200);
    });
  });

  // Wire investigate buttons
  document.querySelectorAll('.feed-inv-btn').forEach(function(btn) {
    btn.addEventListener('click', function() {
      var ioc = btn.dataset.val;
      var iocInput = document.getElementById('iocInput');
      if (iocInput) { iocInput.value = ioc; updateBadge(ioc); }
      showDashboard();
      investigate();
    });
  });

  // Wire search box
  var si = document.getElementById('feedSearchInput');
  if (si) {
    si.addEventListener('input', function() {
      var q = si.value.toLowerCase().trim();
      var rows = document.querySelectorAll('#feedTableEl tbody tr');
      rows.forEach(function(row) {
        row.style.display = q === '' || row.textContent.toLowerCase().includes(q) ? '' : 'none';
      });
    });
  }
}

/* ================================================================
   SANDBOX
================================================================ */
var sandboxFile = null;

function initSandbox() {
  var dropzone  = document.getElementById('sandboxDropzone');
  var fileInput = document.getElementById('sandboxFileInput');
  var runBtn    = document.getElementById('sandbox-run-btn');

  if (!dropzone) return;

  dropzone.addEventListener('click', function() { fileInput.click(); });
  dropzone.addEventListener('dragover',  function(e) { e.preventDefault(); dropzone.classList.add('drag-over'); });
  dropzone.addEventListener('dragleave', function()  { dropzone.classList.remove('drag-over'); });
  dropzone.addEventListener('drop', function(e) {
    e.preventDefault(); dropzone.classList.remove('drag-over');
    var files = e.dataTransfer.files;
    if (files.length > 0) handleFileSelect(files[0]);
  });
  fileInput.addEventListener('change', function() {
    if (fileInput.files.length > 0) handleFileSelect(fileInput.files[0]);
  });
  if (runBtn) runBtn.addEventListener('click', runSandbox);
}

function handleFileSelect(file) {
  sandboxFile = file;
  var infoEl = document.getElementById('sandboxFileInfo');
  var runBtn = document.getElementById('sandbox-run-btn');
  if (!infoEl) return;
  infoEl.style.display = '';
  var ext = file.name.split('.').pop().toUpperCase();
  var icon = { EXE:'⚙️', DLL:'⚙️', PDF:'📄', DOC:'📝', DOCX:'📝', XLS:'📊', XLSX:'📊', ZIP:'📦', RAR:'📦', JS:'📜', PY:'📜', PS1:'📜', BAT:'📜', SH:'📜' }[ext] || '📁';
  infoEl.innerHTML = '<div class="sandbox-file-card"><span class="sandbox-file-icon">'+icon+'</span><div><div class="sandbox-file-name">'+esc(file.name)+'</div><div class="sandbox-file-meta">'+formatBytes(file.size)+' · '+ext+' · Ready for analysis</div></div></div>';
  if (runBtn) runBtn.style.display = '';
}

function formatBytes(b) {
  if (b < 1024) return b + ' B';
  if (b < 1048576) return (b/1024).toFixed(1) + ' KB';
  return (b/1048576).toFixed(2) + ' MB';
}

function runSandbox() {
  if (!sandboxFile) { showToast('Please select a file first.', 'warning'); return; }
  var btn = document.getElementById('sandbox-run-btn');
  if (btn) { btn.disabled = true; btn.textContent = '⏳ Analyzing...'; }
  setHTML('sandbox-result', '<div class="tool-empty"><div class="tool-empty-icon" style="animation:float 2s infinite">🧪</div><div class="tool-empty-title">Running behavioral analysis...</div><div class="tool-empty-sub">Simulating execution in isolated environment</div></div>');

  // Compute a varied 32-char hex hash from file bytes using 4 independent passes
  var reader = new FileReader();
  reader.onload = function(e) {
    var buf  = e.target.result;
    var arr  = new Uint8Array(buf.slice(0, Math.min(buf.byteLength, 131072)));
    var len  = arr.length;
    // 4 independent polynomial hashes over different strides/offsets → 32 hex chars total
    var seeds = [0x811c9dc5, 0x01000193, 0xdeadbeef, 0xcafe1234];
    var parts = seeds.map(function(seed, pass) {
      var h = seed | 0;
      var start = Math.floor(pass * len / 4);
      var end   = Math.min(start + Math.max(len, 1), len);
      for (var i = start; i < end; i++) h = (Math.imul(0x01000193, h) ^ arr[i]) | 0;
      // Also mix filename and size into this pass
      var nm = (sandboxFile.name + sandboxFile.size + pass);
      for (var j = 0; j < nm.length; j++) h = (Math.imul(31, h) + nm.charCodeAt(j)) | 0;
      return (Math.abs(h) >>> 0).toString(16).padStart(8, '0');
    });
    var simHash = parts.join('');  // 32 hex chars, fully varied

    callAPI('/api/sandbox', {
      filename: sandboxFile.name,
      filesize: sandboxFile.size,
      filehash: simHash,
      filetype: sandboxFile.name.split('.').pop().toUpperCase() || 'UNKNOWN',
    }).then(function(result) {
      if (btn) { btn.disabled = false; btn.textContent = '🔬 Re-analyze'; }
      if (result) renderSandboxResult(result);
    }).catch(function(err) {
      if (btn) { btn.disabled = false; btn.textContent = '🔬 Analyze File'; }
      setHTML('sandbox-result','<div class="card"><div style="color:var(--critical);padding:14px">Error: '+esc(err.message)+'</div></div>');
    });
  };
  reader.readAsArrayBuffer(sandboxFile);
}

function renderSandboxResult(r) {
  var verdictClass = r.verdict === 'malicious' ? 'sandbox-verdict-mal' : r.verdict === 'suspicious' ? 'sandbox-verdict-sus' : 'sandbox-verdict-clean';
  var scoreColor   = r.threatScore > 70 ? 'var(--critical)' : r.threatScore > 40 ? 'var(--high)' : 'var(--low)';
  var b = r.behavior || {};

  var html = '';

  // Sim badge
  if (r.simulated) html += '<div class="sandbox-sim-badge">🔬 Simulated analysis — deterministic based on file metadata</div>';

  // Verdict bar
  html += '<div class="sandbox-verdict-bar ' + verdictClass + '">'
    + '<div class="sandbox-score-ring" style="color:' + scoreColor + '">' + r.threatScore + '</div>'
    + '<div style="flex:1"><div style="font-family:var(--display);font-size:18px;font-weight:700;text-transform:uppercase;color:' + scoreColor + '">' + esc(r.verdict) + '</div>'
    + '<div style="font-size:12px;color:var(--t-1);margin-top:3px;">'
    + (r.malwareFamily ? '🦠 <strong>' + esc(r.malwareFamily) + '</strong> · ' : '')
    + esc(r.environment || 'Windows 10 x64')
    + '</div></div>'
    + '<div style="text-align:right"><div style="font-size:9px;letter-spacing:2px;color:var(--t-2);text-transform:uppercase">Threat Score</div><div style="font-family:var(--mono);font-size:32px;font-weight:900;color:' + scoreColor + '">' + r.threatScore + '</div></div>'
    + '</div>';

  // File info
  html += '<div class="card" style="margin-bottom:14px">'
    + drow('Filename', r.filename) + drow('File Size', formatBytes(r.filesize||0)) + drow('Type', r.type)
    + drow('Hash', r.hash, 'cyan') + drow('Analysis Time', r.analysisTime ? new Date(r.analysisTime).toLocaleString() : 'Now')
    + '</div>';

  // MITRE TTPs
  if ((r.mitre||[]).length) {
    html += '<div class="card" style="margin-bottom:14px"><div class="card-header">MITRE ATT&CK® Techniques</div>'
      + '<div class="mitre-tags">' + r.mitre.map(function(t){ return '<span class="mitre-tag">'+esc(t)+'</span>'; }).join('') + '</div>'
      + '</div>';
  }

  // Processes
  if ((b.processes||[]).length) {
    html += '<div class="card" style="margin-bottom:14px"><div class="card-header">🖥️ Process Activity</div>'
      + b.processes.map(function(p){
        return '<div class="sandbox-process-item">'
          + (p.suspicious ? '<span style="color:var(--critical);flex-shrink:0">⚠️</span>' : '<span style="color:var(--low);flex-shrink:0">✓</span>')
          + '<span class="sandbox-process-name">'+esc(p.name)+'</span>'
          + '<span style="color:var(--t-2);font-size:10px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+esc(p.action||'')+'</span>'
          + '</div>';
      }).join('') + '</div>';
  }

  // Network calls
  if ((b.networkCalls||[]).length) {
    html += '<div class="card" style="margin-bottom:14px"><div class="card-header">🌐 Network Connections</div>'
      + b.networkCalls.map(function(n){
        return '<div class="sandbox-net-item">'
          + '<span class="sandbox-proto sandbox-proto-'+( (n.protocol||'').toLowerCase())+'">'+(n.protocol||'TCP')+'</span>'
          + '<span style="font-family:var(--mono);font-size:11px;color:var(--critical)">'+esc(n.dst||'')+'</span>'
          + '<span style="font-size:10px;color:var(--t-2)">:'+esc(String(n.port||''))+'</span>'
          + (n.domain?'<span style="font-family:var(--mono);font-size:11px;color:var(--t-1);margin-left:6px">'+esc(n.domain)+'</span>':'')
          + (n.bytes?'<span style="font-size:10px;color:var(--t-3);margin-left:auto">'+formatBytes(n.bytes)+'</span>':'')
          + '</div>';
      }).join('') + '</div>';
  }

  // Registry changes
  if ((b.registryKeys||[]).length) {
    html += '<div class="card" style="margin-bottom:14px"><div class="card-header">🔑 Registry Modifications</div>'
      + b.registryKeys.map(function(k){ return '<div class="sandbox-reg-item">'+esc(k)+'</div>'; }).join('') + '</div>';
  }

  // Mutexes
  if ((b.mutexes||[]).length) {
    html += '<div class="card" style="margin-bottom:14px"><div class="card-header">🔒 Mutexes Created</div>'
      + '<div>' + b.mutexes.map(function(m){ return chip(m, 'chip-orange'); }).join('') + '</div></div>';
  }

  // Extracted IOCs
  var iocs = r.iocs || {};
  if ((iocs.ips||[]).length || (iocs.domains||[]).length || (iocs.urls||[]).length) {
    html += '<div class="card" style="margin-bottom:14px"><div class="card-header">🎯 Extracted IOCs</div>';
    if ((iocs.ips||[]).length)     html += '<div style="margin-bottom:8px"><div style="font-size:9px;letter-spacing:2px;color:var(--t-2);text-transform:uppercase;margin-bottom:5px">C2 IPs</div>' + iocs.ips.map(function(i){return chip(i,'chip-red');}).join('') + '</div>';
    if ((iocs.domains||[]).length) html += '<div style="margin-bottom:8px"><div style="font-size:9px;letter-spacing:2px;color:var(--t-2);text-transform:uppercase;margin-bottom:5px">C2 Domains</div>' + iocs.domains.map(function(d){return chip(d,'chip-orange');}).join('') + '</div>';
    if ((iocs.urls||[]).length)    html += '<div><div style="font-size:9px;letter-spacing:2px;color:var(--t-2);text-transform:uppercase;margin-bottom:5px">URLs</div>' + iocs.urls.map(function(u){return chip(u,'chip-purple');}).join('') + '</div>';
    html += '</div>';
  }

  // Stats summary
  html += '<div class="card"><div class="card-header">📊 Summary</div>'
    + drow('Dropped Files', String(b.droppedFiles||0), (b.droppedFiles||0)>0?'orange':'')
    + drow('Network Connections', String((b.networkCalls||[]).length))
    + drow('Registry Changes', String((b.registryKeys||[]).length), (b.registryKeys||[]).length>0?'orange':'')
    + drow('Mutex Count', String((b.mutexes||[]).length))
    + '</div>';

  setHTML('sandbox-result', html);
}

/* ================================================================
   RELATIONSHIP GRAPH — D3-style force layout (pure SVG, no libs)
================================================================ */
var graphState = { nodes:[], edges:[], simulation:null };

function runGraph() {
  var inp  = document.getElementById('graph-tool-input');
  var ioc  = inp ? inp.value.trim() : '';
  if (!ioc) { showToast('Enter an IOC to build a graph.', 'warning'); return; }
  var type = classifyIOC(ioc);
  if (type === 'unknown') { showToast('Unrecognized IOC format.', 'warning'); return; }

  var btn = document.getElementById('graph-tool-btn');
  if (btn) { btn.disabled = true; btn.textContent = '⏳ Building...'; }

  var empty = document.getElementById('graph-empty');
  if (empty) empty.innerHTML = '<div style="font-size:36px;opacity:.5;animation:float 2s infinite">🔗</div><div style="font-family:var(--display);font-size:16px;color:var(--t-2);margin-top:10px">Pivoting on infrastructure...</div>';

  callAPI('/api/graph', { ioc:ioc, type:type }).then(function(data) {
    if (btn) { btn.disabled=false; btn.textContent='Build Graph'; }
    if (!data) return;
    renderGraph(data);
  }).catch(function(e) {
    if (btn) { btn.disabled=false; btn.textContent='Build Graph'; }
    showToast('Graph error: '+e.message, 'error');
  });
}

function renderGraph(data) {
  var nodes = data.nodes || [];
  var edges = data.edges || [];
  var svg   = document.getElementById('graph-svg');
  var empty = document.getElementById('graph-empty');
  var container = document.getElementById('graph-container');
  if (!svg || !container) return;

  if (empty) empty.style.display = 'none';
  svg.style.display = '';

  var W = container.clientWidth  || 800;
  var H = container.clientHeight || 480;
  svg.setAttribute('viewBox', '0 0 '+W+' '+H);

  // Color map
  var COLORS = {
    root:'#00c8f0', ip:'#f03060', domain:'#f07020', url:'#8b5cf6',
    hash:'#f0c020', unknown:'#4a6a8a'
  };
  var THREAT_STROKE = { malicious:'#f03060', suspicious:'#f07020', clean:'#20d080', root:'#00c8f0', unknown:'#4a6a8a' };

  function nodeColor(n) {
    if (n.meta && n.meta.isRoot) return COLORS.root;
    return COLORS[n.type] || COLORS.unknown;
  }
  function nodeRadius(n) {
    if (n.meta && n.meta.isRoot) return 22;
    if (n.threat === 'malicious') return 16;
    if (n.type === 'hash') return 11;
    return 14;
  }

  // Simple force-directed layout (custom, no D3)
  // Place root at center, others in rings
  var nodeMap = {};
  nodes.forEach(function(n) { nodeMap[n.id] = n; n.vx = 0; n.vy = 0; });

  // Initial positions: root at center, others evenly spread
  var root = nodes.find(function(n) { return n.meta && n.meta.isRoot; });
  if (root) { root.x = W/2; root.y = H/2; }
  var others = nodes.filter(function(n) { return !(n.meta && n.meta.isRoot); });
  others.forEach(function(n, i) {
    var angle = (i / Math.max(others.length, 1)) * Math.PI * 2;
    var radius = Math.min(W, H) * 0.28 + (n.meta && n.meta.hop === 2 ? 60 : 0);
    n.x = W/2 + Math.cos(angle) * radius;
    n.y = H/2 + Math.sin(angle) * radius;
  });

  // Run force simulation
  function simulate() {
    var STEPS = 120;
    var K = 0.015;   // spring
    var REPEL = 4000; // repulsion
    var DAMP = 0.85;

    for (var step = 0; step < STEPS; step++) {
      // Repulsion between all pairs
      for (var i = 0; i < nodes.length; i++) {
        for (var j = i+1; j < nodes.length; j++) {
          var ni = nodes[i], nj = nodes[j];
          var dx = ni.x - nj.x, dy = ni.y - nj.y;
          var d2 = dx*dx + dy*dy + 1;
          var f  = REPEL / d2;
          ni.vx += f*dx; ni.vy += f*dy;
          nj.vx -= f*dx; nj.vy -= f*dy;
        }
      }
      // Spring along edges
      edges.forEach(function(e) {
        var a = nodeMap[e.from], b = nodeMap[e.to];
        if (!a || !b) return;
        var dx = b.x - a.x, dy = b.y - a.y;
        var d  = Math.sqrt(dx*dx+dy*dy) + 0.01;
        var restLen = 120 + (e.weight||1)*20;
        var f = K * (d - restLen);
        a.vx += f*dx/d; a.vy += f*dy/d;
        b.vx -= f*dx/d; b.vy -= f*dy/d;
      });
      // Center gravity
      nodes.forEach(function(n) {
        if (n.meta && n.meta.isRoot) { n.x = W/2; n.y = H/2; n.vx=0; n.vy=0; return; }
        n.vx += (W/2 - n.x) * 0.002;
        n.vy += (H/2 - n.y) * 0.002;
        n.x += n.vx; n.y += n.vy;
        n.vx *= DAMP; n.vy *= DAMP;
        // Clamp to bounds with padding
        n.x = Math.max(40, Math.min(W-40, n.x));
        n.y = Math.max(40, Math.min(H-40, n.y));
      });
    }
  }
  simulate();

  // Build SVG
  svg.innerHTML = '';

  // Defs: arrowhead markers
  var defs = document.createElementNS('http://www.w3.org/2000/svg','defs');
  ['malicious','suspicious','clean','unknown'].forEach(function(t) {
    var marker = document.createElementNS('http://www.w3.org/2000/svg','marker');
    marker.setAttribute('id','arrow-'+t);
    marker.setAttribute('viewBox','0 0 10 10');
    marker.setAttribute('refX','9'); marker.setAttribute('refY','5');
    marker.setAttribute('markerWidth','6'); marker.setAttribute('markerHeight','6');
    marker.setAttribute('orient','auto-start-reverse');
    var path = document.createElementNS('http://www.w3.org/2000/svg','path');
    path.setAttribute('d','M 0 0 L 10 5 L 0 10 z');
    path.setAttribute('fill', THREAT_STROKE[t]||'#4a6a8a');
    path.setAttribute('opacity','0.7');
    marker.appendChild(path); defs.appendChild(marker);
  });
  svg.appendChild(defs);

  // Background grid (subtle)
  var bg = document.createElementNS('http://www.w3.org/2000/svg','rect');
  bg.setAttribute('width',W); bg.setAttribute('height',H);
  bg.setAttribute('fill','transparent'); svg.appendChild(bg);

  // Edges
  var edgeGroup = document.createElementNS('http://www.w3.org/2000/svg','g');
  edgeGroup.setAttribute('class','g-edges');
  edges.forEach(function(e) {
    var a = nodeMap[e.from], b = nodeMap[e.to];
    if (!a || !b) return;
    var threat = b.threat || 'unknown';
    var strokeColor = THREAT_STROKE[threat] || '#4a6a8a';
    var strokeW = Math.min((e.weight||1)*1.5+0.5, 4);

    // Calculate endpoint offset so arrows don't overlap node circles
    var dx = b.x - a.x, dy = b.y - a.y;
    var dist = Math.sqrt(dx*dx+dy*dy) || 1;
    var rB = nodeRadius(b) + 2;
    var ex = b.x - (dx/dist)*rB, ey = b.y - (dy/dist)*rB;

    var line = document.createElementNS('http://www.w3.org/2000/svg','line');
    line.setAttribute('x1', a.x); line.setAttribute('y1', a.y);
    line.setAttribute('x2', ex);  line.setAttribute('y2', ey);
    line.setAttribute('stroke', strokeColor);
    line.setAttribute('stroke-width', strokeW);
    line.setAttribute('stroke-opacity','0.55');
    line.setAttribute('marker-end','url(#arrow-'+threat+')');
    line.setAttribute('class','g-edge');
    edgeGroup.appendChild(line);

    // Edge label at midpoint
    var mx=(a.x+b.x)/2, my=(a.y+b.y)/2;
    var label = document.createElementNS('http://www.w3.org/2000/svg','text');
    label.setAttribute('x',mx); label.setAttribute('y',my-4);
    label.setAttribute('text-anchor','middle');
    label.setAttribute('class','g-edge-label');
    label.textContent = e.relation||'';
    edgeGroup.appendChild(label);
  });
  svg.appendChild(edgeGroup);

  // Nodes
  var nodeGroup = document.createElementNS('http://www.w3.org/2000/svg','g');
  nodeGroup.setAttribute('class','g-nodes');
  nodes.forEach(function(n) {
    var g = document.createElementNS('http://www.w3.org/2000/svg','g');
    g.setAttribute('class','g-node');
    g.setAttribute('transform','translate('+n.x+','+n.y+')');

    var r = nodeRadius(n);
    var isRoot = !!(n.meta && n.meta.isRoot);
    var fill = nodeColor(n);
    var stroke = THREAT_STROKE[n.threat] || '#4a6a8a';

    // Glow ring for malicious
    if (n.threat === 'malicious') {
      var glow = document.createElementNS('http://www.w3.org/2000/svg','circle');
      glow.setAttribute('r', r+6); glow.setAttribute('fill', 'rgba(240,48,96,0.12)');
      glow.setAttribute('stroke', 'rgba(240,48,96,0.35)'); glow.setAttribute('stroke-width','1');
      g.appendChild(glow);
    }

    var circle = document.createElementNS('http://www.w3.org/2000/svg','circle');
    circle.setAttribute('r', r);
    circle.setAttribute('fill', fill+'33');       // semi-transparent fill
    circle.setAttribute('stroke', stroke);
    circle.setAttribute('stroke-width', isRoot ? 3 : 2);
    g.appendChild(circle);

    // Type icon text inside circle
    var iconMap = { ip:'⬡', domain:'◎', url:'↗', hash:'#', unknown:'?' };
    var icon = document.createElementNS('http://www.w3.org/2000/svg','text');
    icon.setAttribute('text-anchor','middle'); icon.setAttribute('dominant-baseline','central');
    icon.setAttribute('font-size', isRoot?'14':'11');
    icon.setAttribute('fill', fill);
    icon.textContent = isRoot ? '✦' : (iconMap[n.type]||'•');
    g.appendChild(icon);

    // Label below node
    var labelEl = document.createElementNS('http://www.w3.org/2000/svg','text');
    labelEl.setAttribute('y', r+13); labelEl.setAttribute('text-anchor','middle');
    labelEl.setAttribute('fill','#8aabcc'); labelEl.setAttribute('font-size','9');
    labelEl.setAttribute('font-family','JetBrains Mono,monospace');
    var labelText = n.label || n.id;
    labelEl.textContent = labelText.length > 22 ? labelText.slice(0,20)+'…' : labelText;
    g.appendChild(labelEl);

    // Click handler — show detail
    g.addEventListener('click', function() { showGraphNodeDetail(n); });

    nodeGroup.appendChild(g);
  });
  svg.appendChild(nodeGroup);

  // Demo badge
  if (data.demo) {
    var demoBadge = document.createElementNS('http://www.w3.org/2000/svg','text');
    demoBadge.setAttribute('x', 10); demoBadge.setAttribute('y', H-10);
    demoBadge.setAttribute('fill','#3a5570'); demoBadge.setAttribute('font-size','10');
    demoBadge.setAttribute('font-family','JetBrains Mono,monospace');
    demoBadge.textContent = 'DEMO GRAPH — Add VT_KEY for real pivot';
    svg.appendChild(demoBadge);
  }

  // Legend
  renderGraphLegend();
  setText('graph-tool-badge', classifyIOC(document.getElementById('graph-tool-input').value).toUpperCase());
  showToast('Graph built: '+data.nodeCount+' nodes, '+data.edgeCount+' edges', 'success');
}

function renderGraphLegend() {
  var el = document.getElementById('graph-legend');
  if (!el) return;
  el.style.display = '';
  var items = [
    { color:'#00c8f0', label:'Root IOC' },
    { color:'#f03060', label:'IP Address' },
    { color:'#f07020', label:'Domain' },
    { color:'#8b5cf6', label:'URL' },
    { color:'#f0c020', label:'File Hash' },
    { color:'#f03060', border:true, label:'Malicious', ring:true },
    { color:'#f07020', border:true, label:'Suspicious', ring:true },
    { color:'#20d080', border:true, label:'Clean', ring:true },
  ];
  el.innerHTML = '<div class="graph-legend">'
    + items.map(function(it) {
      return '<div class="graph-legend-item">'
        + '<div class="graph-legend-dot" style="background:'+it.color+'33;border-color:'+it.color+'"></div>'
        + '<span>'+esc(it.label)+'</span>'
        + '</div>';
    }).join('') + '</div>';
}

function showGraphNodeDetail(n) {
  var el = document.getElementById('graph-node-detail');
  if (!el) return;
  el.style.display = '';
  var m = n.meta || {};
  var threatColor = { malicious:'var(--critical)', suspicious:'var(--high)', clean:'var(--low)', root:'var(--cyan)' }[n.threat] || 'var(--t-1)';
  el.innerHTML = '<div class="graph-node-detail-card">'
    + '<div class="graph-node-detail-title">'+esc(n.id)+'</div>'
    + drow('Type', n.type.toUpperCase(), 'cyan')
    + drow('Threat', (n.threat||'unknown').toUpperCase(), n.threat==='malicious'?'red':n.threat==='suspicious'?'orange':'green')
    + (m.detections!==undefined ? drow('VT Detections', String(m.detections), m.detections>5?'red':'') : '')
    + (m.family     ? drow('Malware Family', m.family, 'orange') : '')
    + (m.source     ? drow('Source', m.source) : '')
    + (m.score      ? drow('URLScan Score', String(m.score)) : '')
    + (m.resultUrl  ? '<div style="margin-top:10px;"><a href="'+esc(m.resultUrl)+'" target="_blank" class="urlscan-link">View full report ↗</a></div>' : '')
    + '<div style="margin-top:10px;"><button id="graph-pivot-btn" class="tool-run-btn" style="padding:7px 16px;font-size:11px;">🔗 Pivot on this node</button></div>'
    + '</div>';

  var pivotBtn = document.getElementById('graph-pivot-btn');
  if (pivotBtn) {
    pivotBtn.addEventListener('click', function() {
      var inp = document.getElementById('graph-tool-input');
      if (inp && !n.meta.isRoot) {
        inp.value = n.id;
        setText('graph-tool-badge', classifyIOC(n.id).toUpperCase());
        runGraph();
      }
    });
  }
}

/* ================================================================
   HASH CALCULATOR
   Pure client-side — file never leaves the browser.
   Algorithms: MD5 (pure JS), SHA-1, SHA-256, SHA-512 (SubtleCrypto)
================================================================ */

/* ── Pure-JS MD5 (RFC 1321) ──────────────────────────────────── */
function md5(arrayBuffer) {
  var bytes = new Uint8Array(arrayBuffer);
  var n = bytes.length;

  // Pre-process: add padding
  var padded = new Uint8Array(n + 64 - ((n + 8) % 64) + 8);
  padded.set(bytes);
  padded[n] = 0x80;
  // Append bit-length as 64-bit little-endian
  var bitLen = n * 8;
  padded[padded.length - 8] = bitLen & 0xff;
  padded[padded.length - 7] = (bitLen >>> 8) & 0xff;
  padded[padded.length - 6] = (bitLen >>> 16) & 0xff;
  padded[padded.length - 5] = (bitLen >>> 24) & 0xff;

  // T table: T[i] = floor(2^32 * |sin(i+1)|)
  var T = [];
  for (var i = 0; i < 64; i++) T.push((Math.abs(Math.sin(i + 1)) * 0x100000000) >>> 0);

  var s = [7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
           5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
           4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
           6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21];

  var a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;

  function rotl(x, n) { return (x << n) | (x >>> (32 - n)); }
  function add32() {
    var r = 0;
    for (var i = 0; i < arguments.length; i++) r = (r + arguments[i]) >>> 0;
    return r;
  }

  for (var off = 0; off < padded.length; off += 64) {
    var M = new Uint32Array(16);
    for (var j = 0; j < 16; j++) {
      M[j] = padded[off+j*4] | (padded[off+j*4+1]<<8) | (padded[off+j*4+2]<<16) | (padded[off+j*4+3]<<24);
    }
    var A = a0, B = b0, C = c0, D = d0;
    for (var ii = 0; ii < 64; ii++) {
      var F, g;
      if (ii < 16)      { F = (B & C) | (~B & D); g = ii; }
      else if (ii < 32) { F = (D & B) | (~D & C); g = (5*ii+1) % 16; }
      else if (ii < 48) { F = B ^ C ^ D;           g = (3*ii+5) % 16; }
      else              { F = C ^ (B | ~D);         g = (7*ii)   % 16; }
      F = add32(F, A, M[g], T[ii]);
      A = D; D = C; C = B;
      B = add32(B, rotl(F, s[ii]));
    }
    a0 = add32(a0, A); b0 = add32(b0, B); c0 = add32(c0, C); d0 = add32(d0, D);
  }

  function le32hex(n) {
    return [n&0xff,(n>>>8)&0xff,(n>>>16)&0xff,(n>>>24)&0xff]
      .map(function(b){ return ('0'+b.toString(16)).slice(-2); }).join('');
  }
  return le32hex(a0) + le32hex(b0) + le32hex(c0) + le32hex(d0);
}

/* ── SubtleCrypto helper ─────────────────────────────────────── */
function subtleHash(algo, buffer) {
  return window.crypto.subtle.digest(algo, buffer).then(function(h) {
    return Array.from(new Uint8Array(h)).map(function(b){ return ('0'+b.toString(16)).slice(-2); }).join('');
  });
}

/* ── Hasher state ────────────────────────────────────────────── */
var hasherFile = null;

function initHasher() {
  var dropzone  = document.getElementById('hasherDropzone');
  var fileInput = document.getElementById('hasherFileInput');
  var textInput = document.getElementById('hasherTextInput');
  var textBtn   = document.getElementById('hasherTextBtn');

  if (!dropzone) return;

  dropzone.addEventListener('click', function() { fileInput.click(); });
  dropzone.addEventListener('dragover',  function(e) { e.preventDefault(); dropzone.classList.add('drag-over'); });
  dropzone.addEventListener('dragleave', function()  { dropzone.classList.remove('drag-over'); });
  dropzone.addEventListener('drop', function(e) {
    e.preventDefault(); dropzone.classList.remove('drag-over');
    if (e.dataTransfer.files.length) setHasherFile(e.dataTransfer.files[0]);
  });
  fileInput.addEventListener('change', function() {
    if (fileInput.files.length) setHasherFile(fileInput.files[0]);
  });
  if (textBtn) textBtn.addEventListener('click', hashText);
  if (textInput) textInput.addEventListener('keydown', function(e) { if (e.key === 'Enter') hashText(); });
}

function setHasherFile(file) {
  hasherFile = file;
  // Show file card in dropzone area
  var dropzone = document.getElementById('hasherDropzone');
  if (dropzone) {
    var ext = file.name.split('.').pop().toUpperCase();
    var iconMap = {EXE:'⚙️',DLL:'⚙️',PDF:'📄',DOC:'📝',DOCX:'📝',XLS:'📊',XLSX:'📊',
                   ZIP:'📦',RAR:'📦',JS:'📜',PY:'📜',PS1:'📜',BAT:'📜',JPG:'🖼️',PNG:'🖼️',MP4:'🎬',MP3:'🎵'};
    dropzone.innerHTML = '<div class="sandbox-file-card" style="text-align:left;width:100%">'
      +'<span class="sandbox-file-icon">'+(iconMap[ext]||'📁')+'</span>'
      +'<div><div class="sandbox-file-name">'+esc(file.name)+'</div>'
      +'<div class="sandbox-file-meta">'+formatBytes(file.size)+' · '+ext+'</div></div>'
      +'<button id="hasherRunBtn" class="tool-run-btn" style="margin-left:auto;padding:8px 18px">Calculate Hashes</button>'
      +'</div>';
    var runBtn = document.getElementById('hasherRunBtn');
    if (runBtn) runBtn.addEventListener('click', hashFile);
  }
  hashFile();
}

function hashFile() {
  if (!hasherFile) return;
  showHasherProgress(true);

  var reader = new FileReader();
  reader.onload = function(e) {
    var buf = e.target.result;

    setHasherProgressLabel('Computing MD5...');
    setHasherProgress(15);

    // MD5 is synchronous
    var md5val = md5(buf);
    setHasherProgress(35);
    setHasherProgressLabel('Computing SHA-1...');

    subtleHash('SHA-1', buf).then(function(sha1val) {
      setHasherProgress(55);
      setHasherProgressLabel('Computing SHA-256...');
      return subtleHash('SHA-256', buf).then(function(sha256val) {
        setHasherProgress(75);
        setHasherProgressLabel('Computing SHA-512...');
        return subtleHash('SHA-512', buf).then(function(sha512val) {
          setHasherProgress(100);
          setTimeout(function() {
            showHasherProgress(false);
            renderHashResult({
              source: 'file',
              name: hasherFile.name,
              size: hasherFile.size,
              type: hasherFile.name.split('.').pop().toUpperCase(),
              md5:    md5val,
              sha1:   sha1val,
              sha256: sha256val,
              sha512: sha512val,
            });
          }, 200);
        });
      });
    }).catch(function(err) {
      showHasherProgress(false);
      setHTML('hasher-result','<div class="card"><div style="color:var(--critical);padding:14px">Hash computation failed: '+esc(err.message)+'</div></div>');
    });
  };
  reader.onerror = function() {
    showHasherProgress(false);
    setHTML('hasher-result','<div class="card"><div style="color:var(--critical);padding:14px">Could not read file.</div></div>');
  };
  reader.readAsArrayBuffer(hasherFile);
}

function hashText() {
  var input = document.getElementById('hasherTextInput');
  var text = input ? input.value : '';
  if (!text.trim()) { showToast('Enter text to hash.', 'warning'); return; }

  showHasherProgress(true);
  setHasherProgressLabel('Encoding text...');
  setHasherProgress(10);

  var encoder = new TextEncoder();
  var buf = encoder.encode(text).buffer;

  var md5val = md5(buf);
  setHasherProgress(30);

  subtleHash('SHA-1', buf).then(function(sha1val) {
    setHasherProgress(55);
    return subtleHash('SHA-256', buf).then(function(sha256val) {
      setHasherProgress(80);
      return subtleHash('SHA-512', buf).then(function(sha512val) {
        setHasherProgress(100);
        setTimeout(function() {
          showHasherProgress(false);
          renderHashResult({
            source: 'text',
            name: '"' + text.slice(0,60) + (text.length > 60 ? '…' : '') + '"',
            size: buf.byteLength,
            type: 'TEXT',
            md5:    md5val,
            sha1:   sha1val,
            sha256: sha256val,
            sha512: sha512val,
          });
        }, 200);
      });
    });
  }).catch(function(err) {
    showHasherProgress(false);
    setHTML('hasher-result','<div class="card"><div style="color:var(--critical);padding:14px">Hash computation failed: '+esc(err.message)+'</div></div>');
  });
}

function showHasherProgress(show) {
  var el = document.getElementById('hasherProgress');
  if (el) el.style.display = show ? '' : 'none';
  if (!show) setHasherProgress(0);
}
function setHasherProgress(pct) {
  var bar = document.getElementById('hasherProgressBar');
  if (bar) bar.style.width = pct + '%';
}
function setHasherProgressLabel(txt) {
  var lbl = document.getElementById('hasherProgressLabel');
  if (lbl) lbl.textContent = txt;
}

function renderHashResult(r) {
  var rows = [
    { algo:'MD5',     bits:128, value:r.md5,    warn:true,  note:'Fast but cryptographically broken — do not use for security' },
    { algo:'SHA-1',   bits:160, value:r.sha1,   warn:true,  note:'Deprecated — collision attacks exist since 2017' },
    { algo:'SHA-256', bits:256, value:r.sha256, warn:false, note:'Current standard — recommended for file integrity and certificates' },
    { algo:'SHA-512', bits:512, value:r.sha512, warn:false, note:'Strongest — recommended for password hashing and high-security contexts' },
  ];

  var html = '<div class="card" style="margin-bottom:14px;">'
    + '<div class="card-header">📄 '
    + (r.source === 'file' ? esc(r.name) + ' &nbsp;·&nbsp; ' + formatBytes(r.size) + ' &nbsp;·&nbsp; ' + esc(r.type) : esc(r.name))
    + '</div>'
    + rows.map(function(row) {
      return '<div class="hash-result-row">'
        + '<div class="hash-algo-header">'
        + '<span class="hash-algo-name">' + row.algo + '</span>'
        + '<span class="hash-algo-bits">' + row.bits + ' bits</span>'
        + (row.warn ? '<span class="hash-warn-badge">⚠ Deprecated</span>' : '<span class="hash-ok-badge">✓ Secure</span>')
        + '<button class="hash-copy-btn" data-val="' + esc(row.value) + '" title="Copy hash">⎘ Copy</button>'
        + '<button class="hash-inv-btn" data-val="' + esc(row.value) + '" data-algo="' + esc(row.algo.toLowerCase()) + '" title="Investigate this hash in dashboard">▶ Investigate</button>'
        + '</div>'
        + '<div class="hash-value" id="hash-val-' + row.algo.toLowerCase().replace('-','') + '">' + esc(row.value) + '</div>'
        + '<div class="hash-note">' + esc(row.note) + '</div>'
        + '</div>';
    }).join('')
    + '</div>';

  // VirusTotal quick-search links
  html += '<div class="card" style="margin-bottom:14px;">'
    + '<div class="card-header">🔗 Quick Actions</div>'
    + '<div style="display:flex;flex-wrap:wrap;gap:8px;">'
    + '<a href="https://www.virustotal.com/gui/file/' + encodeURIComponent(r.sha256) + '" target="_blank" class="urlscan-link">Check SHA-256 on VirusTotal ↗</a>'
    + '<a href="https://www.virustotal.com/gui/search/' + encodeURIComponent(r.md5) + '" target="_blank" class="urlscan-link">Check MD5 on VirusTotal ↗</a>'
    + '<a href="https://bazaar.abuse.ch/browse.php?search=sha256%3A' + encodeURIComponent(r.sha256) + '" target="_blank" class="urlscan-link">Search MalwareBazaar ↗</a>'
    + '<a href="https://www.hybrid-analysis.com/search?query=' + encodeURIComponent(r.sha256) + '" target="_blank" class="urlscan-link">Search Hybrid Analysis ↗</a>'
    + '</div></div>';

  // Security guidance
  html += '<div class="card">'
    + '<div class="card-header">ℹ️ Algorithm Guidance</div>'
    + '<div style="font-size:12px;color:var(--t-1);line-height:1.8;">'
    + '<div style="margin-bottom:6px;"><strong style="color:var(--critical)">MD5 (128-bit)</strong> — Broken since 2004. Collision attacks are trivial. Only use for non-security checksums (e.g. detecting accidental file corruption).</div>'
    + '<div style="margin-bottom:6px;"><strong style="color:var(--high)">SHA-1 (160-bit)</strong> — Deprecated since 2017 (SHAttered attack). Avoid for new systems. Still common in legacy software and Git (being migrated to SHA-256).</div>'
    + '<div style="margin-bottom:6px;"><strong style="color:var(--low)">SHA-256 (256-bit)</strong> — Current industry standard. Use for file integrity, digital signatures, TLS certificates, and general security purposes.</div>'
    + '<div><strong style="color:var(--low)">SHA-512 (512-bit)</strong> — Maximum security. Faster than SHA-256 on 64-bit CPUs. Recommended for password hashing (with PBKDF2/bcrypt/argon2 stretching) and high-security applications.</div>'
    + '</div></div>';

  setHTML('hasher-result', html);

  // Wire copy buttons
  document.querySelectorAll('.hash-copy-btn').forEach(function(btn) {
    btn.addEventListener('click', function() {
      var val = btn.dataset.val;
      if (navigator.clipboard) {
        navigator.clipboard.writeText(val).catch(function() {});
      } else {
        var ta = document.createElement('textarea');
        ta.value = val; document.body.appendChild(ta); ta.select();
        document.execCommand('copy'); document.body.removeChild(ta);
      }
      var orig = btn.textContent; btn.textContent = '✓ Copied!';
      setTimeout(function() { btn.textContent = orig; }, 1500);
    });
  });

  // Wire investigate buttons
  document.querySelectorAll('.hash-inv-btn').forEach(function(btn) {
    btn.addEventListener('click', function() {
      var val = btn.dataset.val;
      var iocInput = document.getElementById('iocInput');
      if (iocInput) { iocInput.value = val; updateBadge(val); }
      showDashboard();
      investigate();
    });
  });
}

/* ================================================================
   ALL INVESTIGATIONS PAGE
================================================================ */
function showAllInvestigations() {
  showToolPage('investigations');
  renderAllInvestigations();
}

function renderAllInvestigations() {
  var list = document.getElementById('allInvsList');
  if (!list) return;
  var q = (document.getElementById('invSearchInput') || {}).value || '';
  var fv = (document.getElementById('invFilterVerdict') || {}).value || '';
  q = q.toLowerCase().trim();

  var invs = state.history || [];
  var filtered = invs.filter(function(h) {
    var matchQ = !q || h.ioc.toLowerCase().includes(q) || (h.iocType||'').toLowerCase().includes(q) || (h.verdict||'').toLowerCase().includes(q);
    var matchV = !fv || (h.verdict||'') === fv;
    return matchQ && matchV;
  });

  if (!filtered.length) {
    list.innerHTML = '<div class="tool-empty"><div class="tool-empty-icon">🗂</div>'
      +'<div class="tool-empty-title">'+(invs.length?'No results found':'No investigations yet')+'</div>'
      +'<div class="tool-empty-sub">'+(invs.length?'Try a different search or filter.':'Run your first investigation from the dashboard.')+'</div></div>';
    return;
  }

  var riskColor = { malicious:'var(--critical)', suspicious:'var(--high)', clean:'var(--low)', unknown:'var(--t-2)' };
  var riskBg    = { malicious:'rgba(240,48,96,.10)', suspicious:'rgba(240,112,32,.10)', clean:'rgba(32,208,128,.08)', unknown:'rgba(74,106,138,.08)' };

  list.innerHTML = '<div class="all-invs-grid">'
    + filtered.map(function(h) {
      var rs   = h.riskScore || 0;
      var verd = h.verdict || 'unknown';
      var rc   = riskColor[verd] || 'var(--t-2)';
      var rbg  = riskBg[verd] || 'rgba(74,106,138,.08)';
      var ago  = Date.now() - new Date(h.createdAt).getTime();
      var agoStr = ago < 3600000 ? Math.round(ago/60000)+'m ago'
                 : ago < 86400000 ? Math.round(ago/3600000)+'h ago'
                 : Math.round(ago/86400000)+'d ago';
      return '<div class="all-inv-card" data-invid="'+esc(h.id)+'">'
        +'<div class="all-inv-card-top">'
        +'<span class="all-inv-type-badge" style="color:'+rc+';background:'+rbg+';border:1px solid '+rc+'55;">'+esc((h.iocType||'?').toUpperCase())+'</span>'
        +'<span class="all-inv-verdict" style="color:'+rc+'">'+esc(verd.toUpperCase())+'</span>'
        +'<span class="all-inv-score" style="color:'+rc+'">'+rs+'/100</span>'
        +'<span class="all-inv-time">'+agoStr+'</span>'
        +'</div>'
        +'<div class="all-inv-ioc" title="'+esc(h.ioc)+'">'+esc(h.ioc)+'</div>'
        +'<div class="all-inv-bar-wrap"><div class="all-inv-bar-fill" style="width:'+Math.min(100,rs)+'%;background:'+rc+'"></div></div>'
        +(h.commentCount>0?'<div class="all-inv-notes">💬 '+h.commentCount+' note'+(h.commentCount!==1?'s':'')+'</div>':'')
        +'</div>';
    }).join('')
    +'</div>';

  list.querySelectorAll('.all-inv-card').forEach(function(el) {
    el.addEventListener('click', function() {
      loadInvestigation(el.dataset.invid);
    });
  });
}

/* ================================================================
   LOG ANALYZER
================================================================ */
function initLogAnalyzer() {
  var dropzone  = document.getElementById('logDropzone');
  var fileInput = document.getElementById('logFileInput');
  if (!dropzone) return;

  dropzone.addEventListener('click', function() { fileInput.click(); });
  dropzone.addEventListener('dragover', function(e) { e.preventDefault(); dropzone.classList.add('drag-over'); });
  dropzone.addEventListener('dragleave', function() { dropzone.classList.remove('drag-over'); });
  dropzone.addEventListener('drop', function(e) {
    e.preventDefault(); dropzone.classList.remove('drag-over');
    if (e.dataTransfer.files.length) analyzeLogFile(e.dataTransfer.files[0]);
  });
  fileInput.addEventListener('change', function() {
    if (fileInput.files.length) analyzeLogFile(fileInput.files[0]);
  });
}

function analyzeLogFile(file) {
  if (file.size > 2100000) { showToast('File too large — max 2MB', 'error'); return; }

  // Show loading state
  setHTML('log-result',
    '<div class="log-loading">'
    +'<div class="log-loading-icon">🔍</div>'
    +'<div class="log-loading-title">Analyzing '+esc(file.name)+'</div>'
    +'<div class="log-loading-sub">Extracting IOCs · Correlating events · Building decision tree...</div>'
    +'<div class="log-progress-wrap"><div class="log-progress-bar" id="logProgressBar"></div></div>'
    +'</div>');

  // Animate progress while waiting
  var pct = 0;
  var progInterval = setInterval(function() {
    pct = Math.min(90, pct + Math.random() * 12);
    var bar = document.getElementById('logProgressBar');
    if (bar) bar.style.width = pct + '%';
  }, 250);

  var reader = new FileReader();
  reader.onload = function(e) {
    var content = e.target.result;
    callAPI('/api/logs', { content: content, filename: file.name })
      .then(function(result) {
        clearInterval(progInterval);
        var bar = document.getElementById('logProgressBar');
        if (bar) bar.style.width = '100%';
        setTimeout(function() { renderLogResult(result); }, 300);
      })
      .catch(function(err) {
        clearInterval(progInterval);
        setHTML('log-result', '<div class="card"><div style="color:var(--critical);padding:14px">Analysis failed: '+esc(err.message)+'</div></div>');
      });
  };
  reader.onerror = function() {
    clearInterval(progInterval);
    setHTML('log-result', '<div class="card"><div style="color:var(--critical);padding:14px">Could not read file.</div></div>');
  };
  reader.readAsText(file, 'utf-8');
}

function renderLogResult(r) {
  if (!r) return;
  var sevColor  = { critical:'var(--critical)', high:'var(--high)', medium:'var(--medium)', low:'var(--low)', informational:'var(--info)' };
  var sevBg     = { critical:'rgba(240,48,96,.10)', high:'rgba(240,112,32,.10)', medium:'rgba(240,192,32,.08)', low:'rgba(32,208,128,.08)', informational:'rgba(0,200,240,.07)' };
  var sc = sevColor[r.overallSeverity] || 'var(--t-1)';
  var sb = sevBg[r.overallSeverity]   || 'rgba(74,106,138,.08)';

  var html = '';

  // ── Summary banner ──────────────────────────────────────────
  html += '<div class="log-summary-banner" style="background:'+sb+';border:1px solid '+sc+'44;">'
    +'<div class="log-summary-left">'
    +'<div class="log-sev-badge" style="color:'+sc+';background:'+sb+';border:1px solid '+sc+'">'+esc((r.overallSeverity||'unknown').toUpperCase())+'</div>'
    +'<div class="log-summary-info">'
    +'<div class="log-file-name">📄 '+esc(r.filename)+'</div>'
    +'<div class="log-file-meta">'+r.totalLines.toLocaleString()+' lines · '+esc(r.format)+' format · '+r.totalIOCCount+' unique IOCs extracted'+(r.indicators&&r.indicators.length?' · '+r.indicators.length+' threat indicators':'')+'</div>'
    +'</div>'
    +'</div>'
    +'</div>';

  // ── Decision Engine ─────────────────────────────────────────
  if ((r.decisions||[]).length) {
    var decTypeColor = { escalate:'var(--critical)', block:'var(--high)', investigate:'var(--cyan)', patch:'var(--medium)', harden:'var(--purple)', document:'var(--t-1)', share:'var(--low)' };
    html += '<div class="log-section"><div class="log-section-title">⚡ Decision Engine — Action Plan</div>'
      +'<div class="log-decisions">'
      +r.decisions.map(function(d, i) {
        var dc = decTypeColor[d.type] || 'var(--t-1)';
        return '<div class="log-decision-item">'
          +'<div class="log-dec-num" style="color:'+dc+'">'+String(i+1).padStart(2,'0')+'</div>'
          +'<div class="log-dec-body">'
          +'<div class="log-dec-action">'+esc(d.action)+'</div>'
          +'<div class="log-dec-detail">'+esc(d.detail)+'</div>'
          +'</div>'
          +'</div>';
      }).join('')
      +'</div></div>';
  }

  // ── Threat Indicators ───────────────────────────────────────
  if ((r.indicators||[]).length) {
    var indSevColor = { critical:'chip-red', high:'chip-orange', medium:'chip-purple', low:'chip-gray' };
    html += '<div class="log-section"><div class="log-section-title">🚨 Threat Indicators Detected</div>'
      +'<div class="log-indicators">'
      +r.indicators.map(function(ind) {
        return '<div class="log-indicator-item">'
          +'<span class="chip '+(indSevColor[ind.severity]||'chip-gray')+'" style="font-size:9px;flex-shrink:0;">'+esc(ind.severity.toUpperCase())+'</span>'
          +'<span class="log-ind-label">'+esc(ind.label)+'</span>'
          +'</div>';
      }).join('')
      +'</div></div>';
  }

  // ── IOC Stats Grid ──────────────────────────────────────────
  var iocs = r.iocs || {};
  html += '<div class="log-section"><div class="log-section-title">🔍 Extracted IOCs</div>'
    +'<div class="log-ioc-stats">'
    +[
      { label:'IPs', count:(iocs.ips||[]).length, color:'var(--critical)', icon:'⬡' },
      { label:'Domains', count:(iocs.domains||[]).length, color:'var(--high)', icon:'◎' },
      { label:'URLs', count:(iocs.urls||[]).length, color:'var(--medium)', icon:'↗' },
      { label:'Hashes', count:(iocs.hashes||[]).length, color:'var(--cyan)', icon:'#' },
      { label:'Emails', count:(iocs.emails||[]).length, color:'var(--purple)', icon:'@' },
      { label:'CVEs', count:(iocs.cves||[]).length, color:'var(--low)', icon:'⚠' },
    ].map(function(s) {
      return '<div class="log-ioc-stat-card">'
        +'<div class="log-ioc-stat-icon" style="color:'+s.color+'">'+s.icon+'</div>'
        +'<div class="log-ioc-stat-num" style="color:'+(s.count?s.color:'var(--t-3)')+'">'+s.count+'</div>'
        +'<div class="log-ioc-stat-label">'+s.label+'</div>'
        +'</div>';
    }).join('')
    +'</div></div>';

  // ── Top IPs with investigate button ─────────────────────────
  if ((iocs.ips||[]).length) {
    html += '<div class="log-section"><div class="log-section-title">⬡ Top Source IPs ('+iocs.ips.length+')</div>'
      +'<div class="log-ioc-table-wrap">'
      +'<table class="log-ioc-table"><thead><tr>'
      +'<th>IP Address</th><th>Occurrences</th><th>Log Lines</th><th>Context Sample</th><th></th>'
      +'</tr></thead><tbody>'
      +iocs.ips.slice(0,15).map(function(ip) {
        return '<tr>'
          +'<td><span class="log-ioc-val" style="color:var(--critical)">'+esc(ip.value)+'</span></td>'
          +'<td><span class="log-count-badge">'+ip.count+'×</span></td>'
          +'<td style="font-family:var(--mono);font-size:10px;color:var(--t-2)">'+(ip.lines||[]).slice(0,3).join(', ')+'</td>'
          +'<td class="log-ctx-cell">'+(ip.contexts&&ip.contexts[0]?esc(ip.contexts[0].slice(0,80)):'—')+'</td>'
          +'<td><button class="log-inv-btn" data-ioc="'+esc(ip.value)+'" title="Investigate">▶</button></td>'
          +'</tr>';
      }).join('')
      +'</tbody></table></div></div>';
  }

  // ── Top Domains ─────────────────────────────────────────────
  if ((iocs.domains||[]).length) {
    html += '<div class="log-section"><div class="log-section-title">◎ Domains ('+iocs.domains.length+')</div>'
      +'<div class="log-ioc-table-wrap">'
      +'<table class="log-ioc-table"><thead><tr>'
      +'<th>Domain</th><th>Occurrences</th><th>Log Lines</th><th></th>'
      +'</tr></thead><tbody>'
      +iocs.domains.slice(0,12).map(function(d) {
        return '<tr>'
          +'<td><span class="log-ioc-val" style="color:var(--high)">'+esc(d.value)+'</span></td>'
          +'<td><span class="log-count-badge">'+d.count+'×</span></td>'
          +'<td style="font-family:var(--mono);font-size:10px;color:var(--t-2)">'+(d.lines||[]).slice(0,3).join(', ')+'</td>'
          +'<td><button class="log-inv-btn" data-ioc="'+esc(d.value)+'" title="Investigate">▶</button></td>'
          +'</tr>';
      }).join('')
      +'</tbody></table></div></div>';
  }

  // ── File Hashes ─────────────────────────────────────────────
  if ((iocs.hashes||[]).length) {
    html += '<div class="log-section"><div class="log-section-title"># File Hashes ('+iocs.hashes.length+')</div>'
      +'<div class="log-ioc-table-wrap">'
      +'<table class="log-ioc-table"><thead><tr>'
      +'<th>Hash</th><th>Type</th><th>Occurrences</th><th></th>'
      +'</tr></thead><tbody>'
      +iocs.hashes.slice(0,10).map(function(h) {
        return '<tr>'
          +'<td><span class="log-hash-val">'+esc(h.value)+'</span></td>'
          +'<td><span class="chip chip-gray" style="font-size:9px">'+esc((h.type||'').toUpperCase())+'</span></td>'
          +'<td><span class="log-count-badge">'+h.count+'×</span></td>'
          +'<td><button class="log-inv-btn" data-ioc="'+esc(h.value)+'" title="Investigate">▶</button></td>'
          +'</tr>';
      }).join('')
      +'</tbody></table></div></div>';
  }

  // ── URLs ────────────────────────────────────────────────────
  if ((iocs.urls||[]).length) {
    html += '<div class="log-section"><div class="log-section-title">↗ Extracted URLs ('+iocs.urls.length+')</div>'
      +'<div class="log-ioc-table-wrap">'
      +'<table class="log-ioc-table"><thead><tr>'
      +'<th>URL</th><th>Occurrences</th><th>Log Lines</th><th></th>'
      +'</tr></thead><tbody>'
      +iocs.urls.slice(0,15).map(function(u) {
        var shortUrl = u.value.length > 70 ? u.value.slice(0,68)+'…' : u.value;
        return '<tr>'
          +'<td><span class="log-ioc-val" style="color:var(--medium);" title="'+esc(u.value)+'">'+esc(shortUrl)+'</span></td>'
          +'<td><span class="log-count-badge">'+u.count+'×</span></td>'
          +'<td style="font-family:var(--mono);font-size:10px;color:var(--t-2)">'+(u.lines||[]).slice(0,3).join(', ')+'</td>'
          +'<td style="white-space:nowrap">'
          +'<button class="log-inv-btn" data-ioc="'+esc(u.value)+'" title="Investigate">▶</button>'
          +'<a href="'+esc(u.value)+'" target="_blank" rel="noopener" style="font-size:10px;color:var(--t-2);margin-left:5px;text-decoration:none;" title="Open in new tab">↗</a>'
          +'</td>'
          +'</tr>';
      }).join('')
      +'</tbody></table></div></div>';
  }

  // ── Attack Flow ──────────────────────────────────────────────
  if ((r.attackFlow||[]).length) {
    html += '<div class="log-section"><div class="log-section-title">⚔️ Attack Flow — Reconstructed Kill Chain</div>'
      +'<div class="attack-flow-chain">';

    r.attackFlow.forEach(function(step, idx) {
      var isLast = idx === r.attackFlow.length - 1;

      // Resolve CSS variable colour to a usable string for inline style borders
      var borderCol = step.color.startsWith('var(') ? step.color : step.color;

      html += '<div class="af-step">'
        // Step number bubble
        +'<div class="af-step-num" style="background:'+borderCol+';box-shadow:0 0 12px '+borderCol+'55;">'+step.step+'</div>'
        // Card
        +'<div class="af-card" style="border-left-color:'+borderCol+';">'
          // Card header row
          +'<div class="af-card-header">'
            +'<span class="af-icon">'+step.icon+'</span>'
            +'<span class="af-label">'+esc(step.label)+'</span>'
            +'<span class="af-mitre" title="MITRE ATT&CK Technique">'+esc(step.mitre)+'</span>'
          +'</div>'
          // Description
          +'<div class="af-description">'+esc(step.description)+'</div>'
          // IOC pill
          +'<div class="af-ioc-row">'
            +'<span class="af-ioc-type">'+esc(step.iocType.toUpperCase())+'</span>'
            +'<span class="af-ioc-val" title="'+esc(step.ioc)+'">'+esc(step.ioc.length>55?step.ioc.slice(0,53)+'…':step.ioc)+'</span>'
            +'<span class="af-line-ref">line '+step.lineRef+'</span>'
            +'<button class="log-inv-btn" data-ioc="'+esc(step.iocType==='url'?step.ioc:(step.ioc.length<=64?step.ioc:step.ioc.slice(0,64)))+'" title="Investigate in dashboard" style="margin-left:auto;">▶ Investigate</button>'
          +'</div>'
        +'</div>'
      +'</div>';

      // Arrow connector between steps
      if (!isLast) {
        html += '<div class="af-connector">'
          +'<div class="af-connector-line"></div>'
          +'<div class="af-connector-arrow">▼</div>'
          +'</div>';
      }
    });

    html += '</div></div>';
  }

  // ── IOC Correlation Matrix ──────────────────────────────────
  if ((r.correlations||[]).length) {
    html += '<div class="log-section"><div class="log-section-title">🔗 IOC Correlation — Co-occurring Pairs</div>'
      +'<div style="font-size:11px;color:var(--t-2);margin-bottom:10px;">IOCs that appear together in log lines — same campaign or attacker infrastructure</div>'
      +'<div class="log-corr-grid">'
      +r.correlations.slice(0,8).map(function(c, idx) {
        // Determine IOC types for color coding
        function iocColor(v) {
          if (/^(\d{1,3}\.){3}\d{1,3}$/.test(v)) return 'var(--critical)';
          if (/^https?:\/\//.test(v)) return 'var(--medium)';
          if (/^[a-fA-F0-9]{32,64}$/.test(v)) return 'var(--cyan)';
          return 'var(--high)';
        }
        var ca = iocColor(c.a), cb = iocColor(c.b);
        var strength = c.count >= 5 ? 'HIGH' : c.count >= 2 ? 'MEDIUM' : 'LOW';
        var sColor = c.count >= 5 ? 'var(--critical)' : c.count >= 2 ? 'var(--medium)' : 'var(--t-2)';
        return '<div class="log-corr-card">'
          +'<div class="log-corr-card-header">'
          +'<span class="log-corr-strength" style="color:'+sColor+';border-color:'+sColor+'">'+strength+'</span>'
          +'<span class="log-count-badge">'+c.count+'× co-occurrence</span>'
          +'</div>'
          +'<div class="log-corr-pair">'
          +'<div class="log-corr-node" style="border-color:'+ca+'55;background:'+ca+'0a;">'
          +'<span class="log-corr-node-val" style="color:'+ca+'" title="'+esc(c.a)+'">'+esc(c.a.length>32?c.a.slice(0,30)+'…':c.a)+'</span>'
          +'</div>'
          +'<div class="log-corr-link">↔</div>'
          +'<div class="log-corr-node" style="border-color:'+cb+'55;background:'+cb+'0a;">'
          +'<span class="log-corr-node-val" style="color:'+cb+'" title="'+esc(c.b)+'">'+esc(c.b.length>32?c.b.slice(0,30)+'…':c.b)+'</span>'
          +'</div>'
          +'</div>'
          +'</div>';
      }).join('')
      +'</div></div>';
  }

  // ── Timeline ────────────────────────────────────────────────
  if ((r.timeline||[]).length) {
    html += '<div class="log-section"><div class="log-section-title">📅 Activity Timeline (by source IP)</div>'
      +'<div class="log-timeline">'
      +r.timeline.slice(0,8).map(function(t) {
        return '<div class="log-timeline-item">'
          +'<span class="log-tl-ip">'+esc(t.ip)+'</span>'
          +'<span class="log-tl-range">'+esc(t.firstSeen)+' → '+esc(t.lastSeen)+'</span>'
          +'<span class="log-count-badge">'+t.count+' events</span>'
          +'</div>';
      }).join('')
      +'</div></div>';
  }

  // ── Extra IOCs ──────────────────────────────────────────────
  var extras = [];
  if ((iocs.emails||[]).length) extras.push('<div style="margin-bottom:8px;"><span style="font-size:10px;color:var(--t-2);text-transform:uppercase;letter-spacing:1px;">Emails: </span>'+iocs.emails.map(function(e){return '<span class="chip chip-purple">'+esc(e)+'</span>';}).join('')+'</div>');
  if ((iocs.cves||[]).length)   extras.push('<div style="margin-bottom:8px;"><span style="font-size:10px;color:var(--t-2);text-transform:uppercase;letter-spacing:1px;">CVEs: </span>'+iocs.cves.map(function(c){return '<span class="chip chip-red">'+esc(c)+'</span>';}).join('')+'</div>');
  if ((iocs.userAgents||[]).length) extras.push('<div><span style="font-size:10px;color:var(--t-2);text-transform:uppercase;letter-spacing:1px;">User-Agents: </span>'+iocs.userAgents.map(function(u){return '<div style="font-family:var(--mono);font-size:10px;color:var(--t-1);padding:3px 0;">'+esc(u.slice(0,120))+'</div>';}).join('')+'</div>');
  if (extras.length) html += '<div class="log-section"><div class="log-section-title">📦 Additional IOCs</div>'+extras.join('')+'</div>';

  setHTML('log-result', html);

  // Wire investigate buttons
  document.querySelectorAll('.log-inv-btn').forEach(function(btn) {
    btn.addEventListener('click', function() {
      var ioc = btn.dataset.ioc;
      if (!ioc) return;
      var iocInput = document.getElementById('iocInput');
      if (iocInput) { iocInput.value = ioc; updateBadge(ioc); }
      showDashboard();
      investigate();
    });
  });
}

/* ================================================================
   MALWAREBAZAAR TOOL PAGE
================================================================ */
function initMalwareBazaar() {
  var typeSelect = document.getElementById('mbQueryType');
  var inputWrap  = document.getElementById('mbInputWrap');
  var input      = document.getElementById('mbInput');
  var runBtn     = document.getElementById('mbRunBtn');
  if (!runBtn) return;

  function updatePlaceholder() {
    if (!input || !typeSelect) return;
    var t = typeSelect.value;
    if (t === 'recent')    { input.placeholder = 'Showing recent samples'; input.disabled = true; }
    else if (t === 'hash') { input.placeholder = 'Enter SHA256 or MD5 hash…'; input.disabled = false; }
    else if (t === 'signature') { input.placeholder = 'Malware family e.g. Emotet, AgentTesla…'; input.disabled = false; }
    else if (t === 'tag')  { input.placeholder = 'Tag e.g. exe, doc, powershell…'; input.disabled = false; }
  }

  if (typeSelect) { typeSelect.addEventListener('change', updatePlaceholder); updatePlaceholder(); }
  if (runBtn)     runBtn.addEventListener('click', runMBSearch);
  if (input)      input.addEventListener('keydown', function(e){ if(e.key==='Enter') runMBSearch(); });

  // Quick-tag buttons
  document.querySelectorAll('.mb-qtag').forEach(function(btn) {
    btn.addEventListener('click', function() {
      if (typeSelect) typeSelect.value = btn.dataset.type;
      if (input)      input.value = btn.dataset.val;
      updatePlaceholder();
      runMBSearch();
    });
  });

  // Auto-load recent on first open
  runMBSearch();
}

function runMBSearch() {
  var typeSelect = document.getElementById('mbQueryType');
  var input      = document.getElementById('mbInput');
  var runBtn     = document.getElementById('mbRunBtn');
  var qtype      = typeSelect ? typeSelect.value : 'recent';
  var qval       = (input && !input.disabled) ? input.value.trim() : '';

  if ((qtype !== 'recent') && !qval) {
    showToast('Enter a search query.', 'warning');
    return;
  }

  if (runBtn) { runBtn.disabled = true; runBtn.textContent = '⏳ Searching…'; }
  setHTML('mb-result',
    '<div class="tool-empty"><div class="tool-empty-icon" style="animation:float 2s infinite">🦠</div>'
    +'<div class="tool-empty-title">Querying MalwareBazaar…</div></div>');

  callAPI('/api/malwarebazaar', { query: qval, queryType: qtype })
    .then(function(d) {
      if (runBtn) { runBtn.disabled = false; runBtn.textContent = 'Search'; }
      renderMBResult(d, qtype, qval);
    })
    .catch(function(e) {
      if (runBtn) { runBtn.disabled = false; runBtn.textContent = 'Search'; }
      setHTML('mb-result', '<div class="card"><div style="color:var(--critical);padding:14px">Error: '+esc(e.message)+'</div></div>');
    });
}

function renderMBResult(d, qtype, qval) {
  if (!d || !d.found) {
    setHTML('mb-result',
      '<div class="tool-empty"><div class="tool-empty-icon">🔍</div>'
      +'<div class="tool-empty-title">No results</div>'
      +'<div class="tool-empty-sub">'+(d&&d.message?esc(d.message):'No samples found for this query.')+'</div></div>');
    return;
  }

  var samples = d.samples || [];

  // Header card
  var html = '<div class="card" style="margin-bottom:14px;">'
    +'<div class="card-header">🦠 MalwareBazaar — '
    +(qtype==='recent'?'Recent Malware Samples':qtype==='hash'?('Hash: '+esc(qval)):qtype==='signature'?('Signature: '+esc(qval)):('Tag: '+esc(qval)))
    +'<span class="notes-badge" style="margin-left:8px;">'+samples.length+' sample'+(samples.length!==1?'s':'')+'</span>'
    +'</div>'

    // File type breakdown chips
    +(function() {
      var ftCounts = {};
      samples.forEach(function(s){ ftCounts[s.fileType||'?'] = (ftCounts[s.fileType||'?']||0)+1; });
      return '<div style="margin-bottom:10px;display:flex;flex-wrap:wrap;gap:5px;">'
        +Object.entries(ftCounts).sort(function(a,b){return b[1]-a[1];}).slice(0,10)
          .map(function(e){return '<span class="chip chip-orange">'+esc(e[0])+'<span style="margin-left:4px;opacity:.7">×'+e[1]+'</span></span>';}).join('')
        +'</div>';
    })()

    +'</div>';

  // Samples table
  html += '<div class="log-ioc-table-wrap">'
    +'<table class="log-ioc-table" style="table-layout:fixed;width:100%"><thead><tr>'
    +'<th style="width:15%">File Type</th>'
    +'<th style="width:22%">SHA256</th>'
    +'<th style="width:17%">Signature</th>'
    +'<th style="width:8%">Size</th>'
    +'<th style="width:10%">First Seen</th>'
    +'<th style="width:10%">Reporter</th>'
    +'<th style="width:18%">Tags</th>'
    +'<th style="width:10%"></th>'
    +'</tr></thead><tbody>'
    +samples.map(function(s) {
      var tagHtml = (s.tags||[]).slice(0,3).map(function(t){
        return '<span class="chip chip-gray" style="font-size:8px;padding:1px 5px;margin:1px">'+esc(t)+'</span>';
      }).join('');
      var ftext = s.fileType && s.fileType!=='—' ? s.fileType : '?';
      var ftColor = {EXE:'var(--critical)',DLL:'var(--high)',DOC:'var(--medium)',XLS:'var(--medium)',
                     PDF:'var(--t-1)',ZIP:'var(--t-1)',JAR:'var(--high)',PS1:'var(--high)'}[ftext.toUpperCase()] || 'var(--t-2)';
      return '<tr>'
        +'<td><span style="font-family:var(--mono);font-size:10px;font-weight:700;color:'+ftColor+'">'+esc(ftext)+'</span></td>'
        +'<td><span class="log-hash-val" title="'+esc(s.sha256)+'">'+esc(s.sha256.slice(0,20))+'…</span></td>'
        +'<td style="font-size:11px;color:var(--high);font-weight:600">'+esc((s.signature||'—').slice(0,20))+'</td>'
        +'<td style="font-family:var(--mono);font-size:10px;color:var(--t-2)">'+esc(s.fileSize||'—')+'</td>'
        +'<td style="font-family:var(--mono);font-size:10px;color:var(--t-3)">'+esc((s.firstSeen||'—').slice(0,10))+'</td>'
        +'<td style="font-size:10px;color:var(--t-2)">'+esc((s.reporter||'—').slice(0,14))+'</td>'
        +'<td>'+tagHtml+'</td>'
        +'<td style="white-space:nowrap">'
          +'<button class="log-inv-btn mb-inv-btn" data-ioc="'+esc(s.sha256)+'" title="Investigate SHA256" style="margin-right:4px">▶</button>'
          +(s.mbLink?'<a href="'+esc(s.mbLink)+'" target="_blank" class="urlscan-link" style="font-size:9px;padding:2px 6px;">MB↗</a>':'')
        +'</td>'
        +'</tr>';
    }).join('')
    +'</tbody></table></div>';

  setHTML('mb-result', html);

  // Wire investigate buttons
  document.querySelectorAll('.mb-inv-btn').forEach(function(btn) {
    btn.addEventListener('click', function() {
      var ioc = btn.dataset.ioc;
      var iocInput = document.getElementById('iocInput');
      if (iocInput) { iocInput.value = ioc; updateBadge(ioc); }
      showDashboard();
      investigate();
    });
  });
}
