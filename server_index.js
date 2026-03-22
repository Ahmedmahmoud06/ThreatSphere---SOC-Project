'use strict';
const http   = require('http');
const https  = require('https');
const fs     = require('fs');
const path   = require('path');
const urlMod = require('url');
const db       = require('./db');
const security = require('./security');

// ── API Keys ─────────────────────────────────────────────────────
const KEYS = {
  virustotal : process.env.VT_KEY        || '20a30faf4b7cec80a11014e987427dfc5f95c27369c8369fb1d5715d95a09410',  // free  → virustotal.com/gui/my-apikey
  abuseipdb  : process.env.ABUSE_KEY     || 'e02081557356b4cd07c1f8db473d5f073048b4c024409a880362877fdb66ece19abb6021afbffb74',  // free  → abuseipdb.com/account/api
  shodan     : process.env.SHODAN_KEY    || 'gqzliKBwJQeYhqqhcMv4BjJQsDriESWy',  // free  → account.shodan.io
  hybrid     : process.env.HYBRID_KEY    || 'edy0cwfr607888af5momai5c68188ba2xd9wvihx1cdd4e53q52f4eyb7d9a44fc',  // free  → hybrid-analysis.com/apikeys
  urlscan    : process.env.URLSCAN_KEY   || '019cfe74-80ff-701c-bf76-356063a7b17b',  // free  → urlscan.io/user/signup
  groq       : process.env.GROQ_KEY      || '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',  // FREE AI → console.groq.com
  gemini     : process.env.GEMINI_KEY    || 'AIzaSyACrqo3Oa3SQ3Uy3KOeY5EuujDtlJmQzwk',  // FREE AI → aistudio.google.com/app/apikey
};
const PORT   = process.env.PORT || 3000;
const PUBLIC = path.join(__dirname, '..', 'public');

// ── HTTP helpers ─────────────────────────────────────────────────
function httpsGet(reqUrl, headers={}) {
  return new Promise((resolve,reject)=>{
    const opts={...urlMod.parse(reqUrl),headers:{'User-Agent':'ThreatIntel/5.0',...headers}};
    const req=https.get(opts,res=>{
      let b='';res.on('data',d=>b+=d);
      res.on('end',()=>{try{resolve({status:res.statusCode,data:JSON.parse(b)})}catch{resolve({status:res.statusCode,data:b})}});
    });
    req.on('error',reject);req.setTimeout(20000,()=>{req.destroy();reject(new Error('timeout'))});
  });
}
function httpsPost(reqUrl,body,headers={}) {
  return new Promise((resolve,reject)=>{
    const p=urlMod.parse(reqUrl);
    const bs=typeof body==='string'?body:JSON.stringify(body);
    // Don't override Content-Type if caller set it explicitly
    const defaultCT = headers['Content-Type'] ? {} : {'Content-Type':'application/json'};
    const opts={hostname:p.hostname,port:p.port||443,path:p.path,method:'POST',
      headers:{...defaultCT,'Content-Length':Buffer.byteLength(bs),...headers}};
    const req=https.request(opts,res=>{let d='';res.on('data',c=>d+=c);res.on('end',()=>{try{resolve({status:res.statusCode,data:JSON.parse(d)})}catch{resolve({status:res.statusCode,data:d})}})});
    req.on('error',reject);req.setTimeout(30000,()=>{req.destroy();reject(new Error('timeout'))});req.write(bs);req.end();
  });
}
function httpsPostForm(hostname,path_,formBody,headers={}) {
  return new Promise((resolve,reject)=>{
    const bs=formBody;
    const opts={hostname,port:443,path:path_,method:'POST',
      headers:{'Content-Type':'application/x-www-form-urlencoded','Content-Length':Buffer.byteLength(bs),...headers}};
    const req=https.request(opts,res=>{let d='';res.on('data',c=>d+=c);res.on('end',()=>{try{resolve({status:res.statusCode,data:JSON.parse(d)})}catch{resolve({status:res.statusCode,data:d})}})});
    req.on('error',reject);req.setTimeout(30000,()=>{req.destroy();reject(new Error('timeout'))});req.write(bs);req.end();
  });
}
function readBody(req,max=500000) {
  return new Promise((resolve,reject)=>{
    let b='',sz=0;
    req.on('data',chunk=>{sz+=chunk.length;if(sz>max){req.destroy();reject(new Error('Request too large'));return;}b+=chunk});
    req.on('end',()=>{try{resolve(JSON.parse(b))}catch{resolve({})}});
    req.on('error',reject);
  });
}
function sendJSON(res,status,data) {
  const body=JSON.stringify(data);
  security.setSecurityHeaders(res);
  res.writeHead(status,{'Content-Type':'application/json','Content-Length':Buffer.byteLength(body)});
  res.end(body);
}
function sendErr(res,status,msg){sendJSON(res,status,{error:msg});}
function getIP(req){return((req.headers['x-forwarded-for']||req.socket.remoteAddress||'unknown').split(',')[0].trim());}
function getCookie(req,name){const m=(req.headers.cookie||'').match(new RegExp('(?:^|;\\s*)'+name+'=([^;]+)'));return m?m[1]:null;}
function setSessionCookie(res,token){res.setHeader('Set-Cookie',`tip_session=${token}; HttpOnly; SameSite=Strict; Max-Age=86400; Path=/`);}
function clearSessionCookie(res){res.setHeader('Set-Cookie','tip_session=; HttpOnly; SameSite=Strict; Max-Age=0; Path=/');}
function requireAuth(req,res){
  const token=getCookie(req,'tip_session');
  const userId=db.validateSession(token);
  if(!userId){sendErr(res,401,'Authentication required');return null;}
  return {userId,token};
}
function typeGroup(t){return['md5','sha1','sha256'].includes(t)?'hash':t;}

// ── Auth handlers ─────────────────────────────────────────────────
async function handleRegister(req,res){
  const ip=getIP(req);
  const rl=security.rateLimit(ip,'register',3,3600000);
  if(!rl.allowed)return sendErr(res,429,`Too many attempts. Retry in ${rl.retryAfter}s.`);
  const b=await readBody(req);
  const username=(b.username||'').trim();
  const password=b.password||'';
  const nickname=(b.nickname||'').trim();
  const role=(b.role||'').trim();
  if(!security.validateUsername(username))return sendErr(res,400,'Username: 3–30 chars, letters/numbers/_ only');
  if(!security.validatePassword(password))return sendErr(res,400,'Password: min 8 chars, must include a number');
  try{
    const user=await db.createUser(username,password,nickname,role);
    const token=db.createSession(user.id);
    setSessionCookie(res,token);
    sendJSON(res,201,{user});
  }catch(e){sendErr(res,409,e.message);}
}
async function handleLogin(req,res){
  const ip=getIP(req);
  const rl=security.rateLimit(ip,'login',10,900000);
  if(!rl.allowed)return sendErr(res,429,`Rate limit exceeded. Retry in ${rl.retryAfter}s.`);
  const b=await readBody(req);
  const username=(b.username||'').trim(); const password=b.password||'';
  if(!security.validateUsername(username)||!password)return sendErr(res,401,'Invalid username or password');
  try{
    const user=await db.loginUser(username,password,ip);
    const token=db.createSession(user.id);
    setSessionCookie(res,token);
    sendJSON(res,200,{user});
  }catch(e){sendErr(res,401,e.message);}
}
function handleLogout(req,res){
  const token=getCookie(req,'tip_session');
  if(token)db.deleteSession(token);
  clearSessionCookie(res);sendJSON(res,200,{ok:true});
}
function handleMe(req,res){
  const auth=requireAuth(req,res);if(!auth)return;
  const user=db.getUserById(auth.userId);
  if(!user)return sendErr(res,404,'User not found');
  sendJSON(res,200,{user});
}

// ── Investigation handlers ─────────────────────────────────────────
function handleListInvs(req,res){
  const auth=requireAuth(req,res);if(!auth)return;
  const invs=db.getInvestigations(auth.userId);
  sendJSON(res,200,invs.map(inv=>({id:inv.id,ioc:inv.ioc,iocType:inv.iocType,riskScore:inv.aiAnalysis?.riskScore||0,verdict:inv.aiAnalysis?.verdict||'unknown',createdAt:inv.createdAt,commentCount:(inv.comments||[]).length})));
}
async function handleSaveInv(req,res){
  const auth=requireAuth(req,res);if(!auth)return;
  const b=await readBody(req);
  if(!b.ioc||!security.validateIOC(b.ioc))return sendErr(res,400,'Invalid IOC');
  const inv=db.saveInvestigation(auth.userId,b.ioc,b.iocType,b.results,b.aiAnalysis);
  sendJSON(res,201,{id:inv.id,createdAt:inv.createdAt});
}
function handleGetInv(req,res,invId){
  const auth=requireAuth(req,res);if(!auth)return;
  const inv=db.getInvestigation(auth.userId,invId);
  if(!inv)return sendErr(res,404,'Not found');
  sendJSON(res,200,inv);
}
function handleDelInv(req,res,invId){
  const auth=requireAuth(req,res);if(!auth)return;
  if(!db.deleteInvestigation(auth.userId,invId))return sendErr(res,404,'Not found');
  sendJSON(res,200,{ok:true});
}

// ── Comment handlers ─────────────────────────────────────────────
async function handleAddComment(req,res,invId){
  const auth=requireAuth(req,res);if(!auth)return;
  const rl=security.rateLimit(getIP(req),'comment',20,60000);
  if(!rl.allowed)return sendErr(res,429,'Too many requests');
  const b=await readBody(req);
  const text=security.validateComment(b.text||'');
  if(!text)return sendErr(res,400,'Comment must be 1–2000 characters');
  try{sendJSON(res,201,db.addComment(auth.userId,invId,text));}
  catch(e){sendErr(res,404,e.message);}
}
function handleDelComment(req,res,invId,cid){
  const auth=requireAuth(req,res);if(!auth)return;
  try{db.deleteComment(auth.userId,invId,cid);sendJSON(res,200,{ok:true});}
  catch(e){sendErr(res,404,e.message);}
}

// ── OSINT: VirusTotal ─────────────────────────────────────────────
async function handleVT(body){
  if(!KEYS.virustotal)throw new Error('VT_KEY not configured');
  if(!security.validateIOC(body.ioc))throw new Error('Invalid IOC');
  const g=typeGroup(body.type);let endpoint;
  if(g==='ip')     endpoint=`https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(body.ioc)}`;
  else if(g==='domain')endpoint=`https://www.virustotal.com/api/v3/domains/${encodeURIComponent(body.ioc)}`;
  else if(g==='hash')  endpoint=`https://www.virustotal.com/api/v3/files/${encodeURIComponent(body.ioc)}`;
  else if(g==='url'){
    const b64=Buffer.from(body.ioc).toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
    endpoint=`https://www.virustotal.com/api/v3/urls/${b64}`;
  } else throw new Error('Unsupported IOC type');
  const r=await httpsGet(endpoint,{'x-apikey':KEYS.virustotal});
  if(g==='url'&&r.status===404)return vtSubmitURL(body.ioc);
  if(r.status!==200)throw new Error(`VT ${r.status}: ${r.data?.error?.message||'error'}`);
  return normVT(r.data);
}
async function vtSubmitURL(ioc){
  const bs=`url=${encodeURIComponent(ioc)}`;
  const sub=await httpsPostForm('www.virustotal.com','/api/v3/urls',bs,{'x-apikey':KEYS.virustotal});
  const id=sub.data?.data?.id; if(!id)throw new Error('VT no analysis ID');
  for(let i=0;i<10;i++){
    await new Promise(r=>setTimeout(r,3000));
    const p=await httpsGet(`https://www.virustotal.com/api/v3/analyses/${id}`,{'x-apikey':KEYS.virustotal});
    if(p.data?.data?.attributes?.status==='completed'){
      const b64=Buffer.from(ioc).toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
      const rpt=await httpsGet(`https://www.virustotal.com/api/v3/urls/${b64}`,{'x-apikey':KEYS.virustotal});
      if(rpt.status===200)return normVT(rpt.data);
    }
  }
  throw new Error('VT analysis timed out');
}
function normVT(j){
  const a=j.data?.attributes||{}, s=a.last_analysis_stats||{};
  const mal=s.malicious||0,sus=s.suspicious||0,har=s.harmless||0,und=s.undetected||0;
  // Extract top engine detections (malicious ones first)
  const engines_detail = a.last_analysis_results || {};
  const detectedEngines = Object.entries(engines_detail)
    .filter(([,v])=>v.result && (v.category==='malicious'||v.category==='suspicious'))
    .slice(0,8)
    .map(([name,v])=>({name, result:v.result||'—', category:v.category, version:v.engine_version||'—'}));
  return{
    source:'VirusTotal', icon:'🛡️',
    verdict: mal>5?'malicious':(mal>1||sus>3)?'suspicious':'clean',
    stats:{malicious:mal,suspicious:sus,harmless:har,undetected:und},
    engines: mal+sus+har+und, detections:mal, reputation:a.reputation||0,
    // Timestamps
    firstSeen: a.first_submission_date ? new Date(a.first_submission_date*1000).toISOString().slice(0,10)
               : a.creation_date ? new Date(a.creation_date*1000).toISOString().slice(0,10) : '—',
    lastSeen: a.last_analysis_date ? new Date(a.last_analysis_date*1000).toISOString().slice(0,10) : '—',
    lastAnalysis: a.last_analysis_date ? new Date(a.last_analysis_date*1000).toLocaleString()+' UTC' : '—',
    timesSubmitted: a.times_submitted || a.total_votes ? (a.times_submitted||0) : null,
    // Classification
    categories: a.categories ? Object.entries(a.categories).slice(0,6).map(([vendor,cat])=>({vendor,cat})) : [],
    tags: a.tags||[],
    popularThreatLabel: a.popular_threat_classification?.suggested_threat_label || null,
    popularThreatCategory: (a.popular_threat_classification?.popular_threat_category||[]).slice(0,3).map(x=>x.value),
    popularThreatName: (a.popular_threat_classification?.popular_threat_name||[]).slice(0,3).map(x=>x.value),
    // File-specific fields
    fileName: a.meaningful_name || a.names?.[0] || null,
    fileType: a.type_description || a.magic || null,
    fileSize: a.size ? (a.size > 1048576 ? (a.size/1048576).toFixed(2)+'MB' : a.size > 1024 ? (a.size/1024).toFixed(1)+'KB' : a.size+'B') : null,
    md5: a.md5||null, sha1: a.sha1||null, sha256: a.sha256||null,
    // IP/Domain-specific
    asn: a.asn ? 'AS'+a.asn+' '+( a.as_owner||'') : null,
    country: a.country||null, continent: a.continent||null,
    network: a.network||null,
    // URL-specific
    finalUrl: a.last_final_url||null,
    title: a.title||null,
    // Engine detections list
    detectedEngines,
    // Community votes
    votes: a.total_votes ? { harmless:a.total_votes.harmless||0, malicious:a.total_votes.malicious||0 } : null,
  };
}

// ── OSINT: AbuseIPDB ──────────────────────────────────────────────
async function handleAbuse(body){
  if(typeGroup(body.type)!=='ip')return{source:'AbuseIPDB',icon:'⚠️',notApplicable:true,message:'AbuseIPDB only supports IP lookups.'};
  if(!KEYS.abuseipdb)throw new Error('ABUSE_KEY not configured');
  if(!security.validateIOC(body.ioc))throw new Error('Invalid IOC');
  const r=await httpsGet(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(body.ioc)}&maxAgeInDays=90`,{'Key':KEYS.abuseipdb,'Accept':'application/json'});
  if(r.status!==200)throw new Error(`AbuseIPDB ${r.status}`);
  const d=r.data?.data||{},sc=d.abuseConfidenceScore||0;
  return{source:'AbuseIPDB',icon:'⚠️',verdict:sc>70?'malicious':sc>30?'suspicious':'clean',
    abuseScore:sc,totalReports:d.totalReports||0,distinctUsers:d.numDistinctUsers||0,
    lastReported:d.lastReportedAt?.slice(0,10)||'—',isp:d.isp||'—',usageType:d.usageType||'—',
    country:d.countryCode||'—',countryName:d.countryName||'—',isWhitelisted:d.isWhitelisted||false,
    domain:d.domain||'—',ipVersion:d.ipVersion||4,
    categories:[...new Set((d.reports||[]).flatMap(r=>r.categories||[]))]};
}

// ── OSINT: Shodan ─────────────────────────────────────────────────
async function handleShodan(body){
  const g=typeGroup(body.type);
  if(g!=='ip'&&g!=='domain')return{source:'Shodan',icon:'🌐',notApplicable:true,message:'Shodan requires IP or domain.'};
  if(!KEYS.shodan)throw new Error('SHODAN_KEY not configured');
  if(!security.validateIOC(body.ioc))throw new Error('Invalid IOC');
  const r=await httpsGet(`https://api.shodan.io/shodan/host/${encodeURIComponent(body.ioc)}?key=${KEYS.shodan}`);
  if(r.status===404)return{source:'Shodan',icon:'🌐',verdict:'info',ports:[],org:'—',country:'—',city:'—',os:null,vulns:[],banners:[],lastUpdate:'—',hostnames:[],tags:[],isp:'—'};
  if(r.status!==200)throw new Error(`Shodan ${r.status}: ${r.data?.error||'error'}`);
  const d=r.data;
  return{source:'Shodan',icon:'🌐',verdict:(d.vulns&&Object.keys(d.vulns).length>0)?'suspicious':'info',
    ports:d.ports||[],org:d.org||'—',country:d.country_name||'—',city:d.city||'—',os:d.os||null,
    vulns:d.vulns?Object.keys(d.vulns):[],
    banners:(d.data||[]).slice(0,3).map(b=>(b.product||'')+(b.version?' '+b.version:'')||(b.data||'').slice(0,80)).filter(Boolean),
    lastUpdate:d.last_update?.slice(0,10)||'—',hostnames:d.hostnames||[],tags:d.tags||[],isp:d.isp||'—'};
}

// ── OSINT: Hybrid Analysis ────────────────────────────────────────
// WHY IT FAILED BEFORE: /search/terms requires application/x-www-form-urlencoded
// NOT application/json. Also: undefined fields must be excluded, and the correct
// field name for IPs is "network" not "ipv4". Fix: build URLSearchParams manually.
async function handleHybrid(body){
  if(!KEYS.hybrid)throw new Error('HYBRID_KEY not configured — get free key at hybrid-analysis.com/apikeys');
  if(!security.validateIOC(body.ioc))throw new Error('Invalid IOC');
  const g=typeGroup(body.type);

  // Build form-encoded body — ONLY include the relevant field, no undefined values
  const params=new URLSearchParams();
  if(g==='hash')        params.set('hash',body.ioc);
  else if(g==='domain') params.set('domain',body.ioc);
  else if(g==='url')    params.set('url',body.ioc);
  else if(g==='ip')     params.set('network',body.ioc);  // correct field name is "network"
  else                  params.set('hash',body.ioc);
  params.set('limit','5');

  const formStr = params.toString();
  const r = await new Promise((resolve,reject)=>{
    const opts={hostname:'www.hybrid-analysis.com',port:443,path:'/api/v2/search/terms',method:'POST',
      headers:{
        'api-key':KEYS.hybrid,
        'User-Agent':'Falcon Sandbox',
        'Content-Type':'application/x-www-form-urlencoded',
        'Content-Length':Buffer.byteLength(formStr),
        'Accept':'application/json',
      }};
    const req=https.request(opts,res=>{
      let d='';res.on('data',c=>d+=c);
      res.on('end',()=>{try{resolve({status:res.statusCode,data:JSON.parse(d)});}catch{resolve({status:res.statusCode,data:d});}});
    });
    req.on('error',reject);
    req.setTimeout(20000,()=>{req.destroy();reject(new Error('Hybrid Analysis timeout'));});
    req.write(formStr);req.end();
  });

  if(r.status===401||r.status===403){
    throw new Error('HYBRID_KEY invalid or expired — get a new free key at hybrid-analysis.com/apikeys');
  }
  if(r.status===429){
    throw new Error('Hybrid Analysis rate limit exceeded — try again in 60 seconds');
  }
  // Response: { count: N, result: [...] }
  const results = Array.isArray(r.data?.result) ? r.data.result
                : Array.isArray(r.data?.results) ? r.data.results : [];
  if(r.status===404 || !results.length){
    return{source:'Hybrid Analysis',icon:'🔬',verdict:'unknown',found:false,
      message:'No sandbox reports found for this IOC.',
      hint:'Submit the sample at hybrid-analysis.com to create a new analysis.'};
  }
  if(r.status!==200)throw new Error(`Hybrid Analysis ${r.status}: ${JSON.stringify(r.data).slice(0,120)}`);

  const top=results[0]||{};
  const malicious =results.filter(x=>x.verdict==='malicious').length;
  const suspicious=results.filter(x=>x.verdict==='suspicious').length;
  return{source:'Hybrid Analysis',icon:'🔬',found:true,
    verdict:malicious>0?'malicious':suspicious>0?'suspicious':'clean',
    totalResults:results.length, maliciousCount:malicious, suspiciousCount:suspicious,
    threatScore:top.threat_score||0,
    threatLevel:top.threat_level_human||'no specific threat',
    malwareFamily:top.vx_family||null,
    environment:top.environment_description||'Unknown',
    analysisStart:top.analysis_start_time||null,
    submitName:top.submit_name||null, sha256:top.sha256||null,
    tags:top.tags||[], classification:top.classification_tags||[],
    extractedFiles:Array.isArray(top.extracted_files)?top.extracted_files.length:0,
    samples:results.slice(0,5).map(x=>({
      verdict:x.verdict, sha256:x.sha256, family:x.vx_family,
      env:x.environment_description, score:x.threat_score,
    })),
  };
}

// ── OSINT: URLScan.io ──────────────────────────────────────────────
async function handleURLScan(body){
  if(!KEYS.urlscan)throw new Error('URLSCAN_KEY not configured — get free key at urlscan.io/user/signup');
  const g=typeGroup(body.type);
  if(g!=='url'&&g!=='domain'&&g!=='ip')
    return{source:'URLScan.io',icon:'🔎',notApplicable:true,message:'URLScan supports URLs, domains, and IPs only.'};
  if(!security.validateIOC(body.ioc))throw new Error('Invalid IOC');

  // Search for existing scans first
  const query=encodeURIComponent(g==='url'?`page.url:"${body.ioc}"`:g==='domain'?`domain:"${body.ioc}"`:`ip:"${body.ioc}"`);
  const searchR=await httpsGet(`https://urlscan.io/api/v1/search/?q=${query}&size=5`,{'API-Key':KEYS.urlscan,'Accept':'application/json'});

  if(searchR.status!==200)throw new Error(`URLScan ${searchR.status}`);
  const results=(searchR.data?.results||[]);

  // For fresh URL scans, submit if it's a URL and no recent result
  let scanResult=null;
  if(g==='url'&&results.length===0){
    const subR=await httpsPost('https://urlscan.io/api/v1/scan/',
      {url:body.ioc,visibility:'unlisted'},
      {'API-Key':KEYS.urlscan,'Content-Type':'application/json'});
    if(subR.status===200){
      scanResult={submitted:true,uuid:subR.data?.uuid,
        message:'Scan submitted. Results will be available in ~30 seconds.',
        resultUrl:`https://urlscan.io/result/${subR.data?.uuid}/`};
    }
  }

  if(!results.length&&!scanResult)
    return{source:'URLScan.io',icon:'🔎',verdict:'unknown',found:false,
      message:'No scans found for this IOC.'+(g==='url'?' Submitting new scan...':'')};

  const top=results[0]||{};
  const page=top.page||{};
  const stats=top.stats||{};
  const verdicts=top.verdicts||{};
  const overallVerdict=verdicts.overall||{};

  return{source:'URLScan.io',icon:'🔎',found:true,
    verdict:overallVerdict.malicious?'malicious':overallVerdict.score>50?'suspicious':'clean',
    malicious:overallVerdict.malicious||false,
    score:overallVerdict.score||0,
    totalScans:results.length,
    url:page.url||body.ioc,
    domain:page.domain||'—',
    ip:page.ip||'—',
    country:page.country||'—',
    server:page.server||'—',
    title:page.title||'—',
    screenshotUrl:top._id?`https://urlscan.io/screenshots/${top._id}.png`:null,
    resultUrl:top._id?`https://urlscan.io/result/${top._id}/`:null,
    scanDate:top.task?.time||null,
    categories:verdicts.urlhaus?.categories||[],
    tags:top.tags||[],
    recentScans:results.slice(0,3).map(x=>({
      date:x.task?.time||null,
      malicious:(x.verdicts?.overall?.malicious||false),
      score:x.verdicts?.overall?.score||0,
      url:`https://urlscan.io/result/${x._id}/`
    })),
    submitted:scanResult||null};
}

// ── OSINT: WHOIS ──────────────────────────────────────────────────
async function handleWhois(body){
  if(!security.validateIOC(body.ioc))throw new Error('Invalid IOC');
  const g=typeGroup(body.type);
  if(g==='ip'){
    const r=await httpsGet(`https://ipapi.co/${encodeURIComponent(body.ioc)}/json/`);
    if(r.status!==200)throw new Error(`IP lookup ${r.status}`);
    const d=r.data; if(d.error)throw new Error(d.reason||'IP lookup failed');
    return{source:'WHOIS',icon:'📋',verdict:'info',registrar:d.org||'—',organization:d.org||'—',
      createdDate:'—',updatedDate:'—',expiryDate:'N/A',nameservers:[],registrant:d.org||'—',
      country:d.country_code||'—',countryName:d.country_name||'—',region:d.region||'—',
      city:d.city||'—',asn:d.asn||'—',timezone:d.timezone||'—',
      status:[],dnssec:'N/A',daysOld:-1,newDomain:false,emails:[]};
  }
  let lookup=body.ioc;
  if(g==='url'){try{lookup=new URL(body.ioc).hostname;}catch{lookup=body.ioc.replace(/^https?:\/\//i,'').split('/')[0];}}
  if(g==='hash')return{source:'WHOIS',icon:'📋',verdict:'info',notApplicable:true,message:'WHOIS is not applicable to file hashes.'};

  // Try multiple RDAP servers — rdap.org, then iana bootstrap redirect, then verisign
  const rdapEndpoints = [
    `https://rdap.org/domain/${encodeURIComponent(lookup)}`,
    `https://rdap.iana.org/domain/${encodeURIComponent(lookup)}`,
    `https://www.rdap.net/domain/${encodeURIComponent(lookup)}`,
  ];
  let rd = null;
  for(const ep of rdapEndpoints){
    try{
      const r = await httpsGet(ep);
      if(r.status === 200 && r.data && typeof r.data === 'object' && r.data.ldhName){
        rd = r.data; break;
      }
    } catch(e){ /* try next */ }
  }
  if(!rd) {
    // RDAP unavailable — return structured demo data so the UI shows something useful
    console.warn('[whois] RDAP failed for', lookup, '— returning demo data');
    const dsh = (str, salt, mn, mx) => {
      let h=0, s2=str+salt; for(let i=0;i<s2.length;i++) h=(Math.imul(31,h)+s2.charCodeAt(i))|0;
      return Math.floor(((Math.abs(h)%100000)/100000)*(mx-mn+1))+mn;
    };
    const regs = ['GoDaddy.com, LLC','Namecheap, Inc.','Porkbun LLC','Cloudflare, Inc.','Google LLC','Network Solutions LLC'];
    const days = dsh(lookup,'da',60,2000);
    const created = new Date(Date.now()-days*86400000).toISOString().slice(0,10);
    return {source:'WHOIS',icon:'📋',verdict:'info',_demo:true,_apiError:'RDAP unavailable — deploy with internet access for live data',
      registrar:regs[dsh(lookup,'rg',0,5)], organization:'REDACTED FOR PRIVACY',
      createdDate:created, updatedDate:new Date(Date.now()-dsh(lookup,'up',1,90)*86400000).toISOString().slice(0,10),
      expiryDate:new Date(Date.now()+dsh(lookup,'ex',90,730)*86400000).toISOString().slice(0,10),
      nameservers:['ns1.'+lookup,'ns2.'+lookup],
      ldhName:lookup, registrant:'REDACTED FOR PRIVACY', country:'—', status:['clientTransferProhibited'],
      dnssec:dsh(lookup,'dn',0,1)?'signed':'unsigned', daysOld:days, newDomain:days<30, emails:[]};
  }

  const ev=rd.events||[];
  const created=ev.find(e=>e.eventAction==='registration')?.eventDate;
  const updated=ev.find(e=>e.eventAction==='last changed')?.eventDate;
  const expires=ev.find(e=>e.eventAction==='expiration')?.eventDate;
  const ns=(rd.nameservers||[]).map(n=>(n.ldhName||'').toLowerCase()).filter(Boolean);
  const re=(rd.entities||[]).find(e=>(e.roles||[]).includes('registrar'));
  const rn=re?.vcardArray?.[1]?.find(v=>v[0]==='fn')?.[3]||'—';
  const da=created?Math.floor((Date.now()-new Date(created))/86400000):-1;
  // Extract registrant country from entities if available
  const registrant=(rd.entities||[]).find(e=>(e.roles||[]).includes('registrant'));
  const country = registrant?.vcardArray?.[1]?.find(v=>v[0]==='adr')?.[3]?.countryName || '—';
  return{source:'WHOIS',icon:'📋',verdict:'info',
    registrar:rn, organization:'REDACTED FOR PRIVACY',
    createdDate:created?.slice(0,10)||'—',
    updatedDate:updated?.slice(0,10)||'—',
    expiryDate:expires?.slice(0,10)||'—',
    nameservers:ns, registrant:'REDACTED FOR PRIVACY',
    country, status:rd.status||[],
    dnssec:rd.secureDNS?.delegationSigned?'signed':'unsigned',
    port43:rd.port43||null,
    ldhName:rd.ldhName||lookup,
    daysOld:da, newDomain:da>=0&&da<30, emails:[]};
}

// ── AI Handler ────────────────────────────────────────────────────
async function handleAI(body){
  const msgs=body.messages||[{role:'user',content:body.prompt}];
  const system=body.system||null;
  const maxTok=body.maxTokens||1200;

  if(KEYS.groq){
    const groqMsgs=[];
    if(system)groqMsgs.push({role:'system',content:system});
    groqMsgs.push(...msgs);
    const r=await httpsPost('https://api.groq.com/openai/v1/chat/completions',
      {model:'llama-3.3-70b-versatile',messages:groqMsgs,max_tokens:maxTok,temperature:0.3},
      {'Authorization':'Bearer '+KEYS.groq});
    if(r.status!==200)throw new Error(`Groq ${r.status}: ${r.data?.error?.message||JSON.stringify(r.data)}`);
    return r.data.choices?.[0]?.message?.content||'';
  }
  if(KEYS.gemini){
    const parts=[];
    if(system)parts.push('System: '+system+'\n\n');
    msgs.forEach(m=>parts.push((m.role==='user'?'User: ':'Assistant: ')+m.content+'\n'));
    const r=await httpsPost(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${KEYS.gemini}`,
      {contents:[{parts:[{text:parts.join('')}]}],generationConfig:{maxOutputTokens:maxTok,temperature:0.3}},{});
    if(r.status!==200)throw new Error(`Gemini ${r.status}: ${r.data?.error?.message||JSON.stringify(r.data)}`);
    return r.data.candidates?.[0]?.content?.parts?.[0]?.text||'';
  }
  throw new Error('No AI key configured. Add GROQ_KEY or GEMINI_KEY in server/index.js');
}


// ═══════════════════════════════════════════════════════════════
// LIVE THREAT FEEDS  (all free, no API key needed)
//  Sources pulled in parallel with Promise.allSettled:
//  1. Feodo Tracker   — botnet C2 IPs (CSV + JSON fallback)
//  2. URLhaus         — malware URLs + CSV bulk export
//  3. ThreatFox       — multi-type IOC feed (3 days)
//  4. MalwareBazaar   — recent hashes (time + 100 latest)
//  5. Emerging Threats— compromised IPs
//  6. OpenPhish       — phishing URLs
//  7. Abuse.ch SSL BL — malware C2 SSL IPs
//  8. CINS Score      — threat actor IPs
//  9. PhishTank       — verified phishing (no key)
// Falls back to rich deterministic demo data if ALL sources fail
// ═══════════════════════════════════════════════════════════════
async function handleFeeds(body) {
  const limit = Math.min((body && body.limit) || 100, 300);
  const results = { ips:[], domains:[], urls:[], hashes:[], fetchedAt:new Date().toISOString(), sources:[] };
  const liveSources = [];

  // ── Shared helpers ────────────────────────────────────────────────
  function fetchText(url, extraHeaders) {
    return new Promise(resolve => {
      const parsed = urlMod.parse(url);
      const opts = {
        hostname: parsed.hostname, port: 443, path: parsed.path, method: 'GET',
        headers: { 'User-Agent': 'ThreatSphere-SOC/1.0', 'Accept': '*/*', ...(extraHeaders||{}) },
      };
      const req = https.request(opts, res => {
        if ((res.statusCode===301||res.statusCode===302) && res.headers.location) {
          fetchText(res.headers.location, extraHeaders).then(resolve);
          res.resume(); return;
        }
        let d = ''; res.on('data', c => d += c);
        res.on('end', () => resolve({ status:res.statusCode, text:d }));
      });
      req.on('error', () => resolve({ status:0, text:'' }));
      req.setTimeout(18000, () => { req.destroy(); resolve({ status:0, text:'' }); });
      req.end();
    });
  }

  function isIP(v)     { return /^(\d{1,3}\.){3}\d{1,3}$/.test(v) && v.split('.').every(n=>+n<=255); }
  function isDomain(v) { return /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/.test(v); }
  const seen = { ips:new Set(), domains:new Set(), urls:new Set(), hashes:new Set() };
  function addIP(o)     { if(o.value&&!seen.ips.has(o.value))     { seen.ips.add(o.value);     results.ips.push(o); } }
  function addDomain(o) { if(o.value&&!seen.domains.has(o.value)) { seen.domains.add(o.value); results.domains.push(o); } }
  function addURL(o)    { if(o.value&&!seen.urls.has(o.value))    { seen.urls.add(o.value);    results.urls.push(o); } }
  function addHash(o)   { if(o.value&&!seen.hashes.has(o.value))  { seen.hashes.add(o.value);  results.hashes.push(o); } }
  function today()      { return new Date().toISOString().slice(0,10); }

  // ── Run all sources in parallel ───────────────────────────────────
  await Promise.allSettled([

    // 1. Feodo Tracker CSV (recommended — only active C2s)
    (async () => {
      const r = await fetchText('https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt');
      if (r.status !== 200 || r.text.length < 100) throw new Error('no data');
      const lines = r.text.split('\n').filter(l=>l.trim()&&!l.startsWith('#'));
      lines.slice(0,80).forEach(line => {
        const p = line.trim().split(',');
        if (!isIP(p[0]?.trim())) return;
        addIP({
          value:p[0].trim(), threat:'botnet-c2',
          malware:p[5]?.trim()||'—', country:p[4]?.trim()||'—',
          port:p[1]?.trim()||'—', status:p[2]?.trim()||'—',
          firstSeen:p[3]?.trim()?.slice(0,10)||today(),
          source:'Feodo Tracker', dateAdded:p[3]?.trim()?.slice(0,10)||today(),
        });
      });
      if (results.ips.length) liveSources.push('Feodo Tracker');
    })().catch(async () => {
      // JSON fallback
      try {
        const r = await httpsGet('https://feodotracker.abuse.ch/downloads/ipblocklist.json');
        if (r.status===200 && r.data?.feodos) {
          r.data.feodos.slice(0,80).forEach(f => {
            if (!isIP(f.ip_address)) return;
            addIP({ value:f.ip_address, threat:'botnet-c2', malware:f.malware||'—',
              country:f.country||'—', port:String(f.port||'—'), status:f.status||'—',
              firstSeen:f.first_seen?.slice(0,10)||today(),
              source:'Feodo Tracker', dateAdded:f.first_seen?.slice(0,10)||today() });
          });
          if (results.ips.length) liveSources.push('Feodo Tracker');
        }
      } catch {}
    }),

    // 2. URLhaus — recent malware URLs (API POST)
    (async () => {
      const r = await httpsPost(
        'https://urlhaus-api.abuse.ch/v1/urls/recent/limit/200/',
        '', { 'Content-Type':'application/x-www-form-urlencoded' }
      );
      if (r.status!==200 || !r.data?.urls?.length) throw new Error('no data');
      r.data.urls.forEach(u => {
        if (!u.url) return;
        const tags = (u.tags||[]).join(', ') || '—';
        addURL({ value:u.url, threat:u.threat||'malware', malware:tags,
          country:u.country||'—', source:'URLhaus',
          urlStatus:u.url_status||'—', reporter:u.reporter||'—',
          dateAdded:u.date_added?.slice(0,10)||today() });
        try {
          const host = u.host || new URL(u.url).hostname;
          if (isIP(host))     addIP    ({ value:host, threat:u.threat||'malware', malware:tags, country:u.country||'—', source:'URLhaus', dateAdded:u.date_added?.slice(0,10)||'—' });
          else if (isDomain(host)) addDomain({ value:host, threat:u.threat||'malware', malware:tags, country:u.country||'—', source:'URLhaus', dateAdded:u.date_added?.slice(0,10)||'—' });
        } catch {}
      });
      if (r.data.urls.length) liveSources.push('URLhaus');
    })().catch(e => console.warn('[feeds] URLhaus:', e.message)),

    // 3. ThreatFox — multi-family IOCs (3 days for better coverage)
    (async () => {
      const r = await httpsPost(
        'https://threatfox-api.abuse.ch/api/v1/',
        { query:'get_iocs', days:3 },
        { 'Content-Type':'application/json' }
      );
      if (r.status!==200 || !r.data?.data?.length) throw new Error('no data');
      r.data.data.forEach(ioc => {
        if (!ioc.ioc) return;
        const entry = {
          value:ioc.ioc, threat:ioc.threat_type||'malware',
          malware:ioc.malware||'—', malwareFamily:ioc.malware_printable||ioc.malware||'—',
          confidence:ioc.confidence_level||0, reporter:ioc.reporter||'—',
          source:'ThreatFox', country:'—',
          dateAdded:ioc.first_seen?.slice(0,10)||today(),
          tags:(ioc.tags||[]),
        };
        const t = ioc.ioc_type||'';
        if (t==='ip:port'||t==='ip') {
          const ip=ioc.ioc.split(':')[0];
          if (isIP(ip)) addIP({...entry,value:ip,port:ioc.ioc.includes(':')?ioc.ioc.split(':')[1]:'—'});
        } else if (t==='domain'||t==='hostname') {
          if (isDomain(ioc.ioc)) addDomain(entry);
        } else if (t==='url') {
          addURL(entry);
        } else if (['md5_hash','sha256_hash','sha1_hash'].includes(t)) {
          addHash({...entry, hashType:t.replace('_hash','')});
        }
      });
      liveSources.push('ThreatFox');
    })().catch(e => console.warn('[feeds] ThreatFox:', e.message)),

    // 4a. MalwareBazaar — most recent 100 samples by upload time
    (async () => {
      const r = await httpsPost(
        'https://mb-api.abuse.ch/api/v1/',
        { query:'get_recent', selector:'time' },
        { 'Content-Type':'application/json' }
      );
      if (r.status!==200 || !r.data?.data?.length) throw new Error('no data');
      r.data.data.slice(0,60).forEach(s => {
        if (!s.sha256_hash) return;
        addHash({
          value:s.sha256_hash, threat:'malware',
          malware:s.signature||s.file_type||'—',
          malwareFamily:s.signature||'—',
          fileType:s.file_type||'—',
          fileSize:s.file_size ? (s.file_size>1048576?(s.file_size/1048576).toFixed(1)+'MB':(Math.round(s.file_size/1024))+'KB') : '—',
          md5:s.md5_hash||'—', sha1:s.sha1_hash||'—',
          country:'—', source:'MalwareBazaar',
          reporter:s.reporter||'—',
          tags:s.tags||[], mimeType:s.file_type_mime||'—',
          deliveryMethod:s.delivery_method||'—',
          dateAdded:s.first_seen?.slice(0,10)||today(),
        });
      });
      liveSources.push('MalwareBazaar');
    })().catch(e => console.warn('[feeds] MalwareBazaar:', e.message)),

    // 4b. MalwareBazaar — also pull 100 latest by signature (malware families)
    (async () => {
      const r = await httpsPost(
        'https://mb-api.abuse.ch/api/v1/',
        { query:'get_recent', selector:'100' },
        { 'Content-Type':'application/json' }
      );
      if (r.status!==200 || !r.data?.data?.length) throw new Error('no data');
      r.data.data.slice(0,40).forEach(s => {
        if (!s.sha256_hash) return;
        addHash({
          value:s.sha256_hash, threat:'malware',
          malware:s.signature||s.file_type||'—',
          malwareFamily:s.signature||'—',
          fileType:s.file_type||'—',
          fileSize:s.file_size ? (Math.round(s.file_size/1024))+'KB' : '—',
          md5:s.md5_hash||'—', sha1:s.sha1_hash||'—',
          country:'—', source:'MalwareBazaar',
          tags:s.tags||[], mimeType:s.file_type_mime||'—',
          dateAdded:s.first_seen?.slice(0,10)||today(),
        });
      });
    })().catch(() => {}),

    // 5. Emerging Threats — Proofpoint compromised IPs
    (async () => {
      const r = await fetchText('https://rules.emergingthreats.net/blockrules/compromised-ips.txt');
      if (r.status!==200 || r.text.length<100) throw new Error('no data');
      const lines = r.text.split('\n').filter(l=>l.trim()&&!l.startsWith('#'));
      lines.slice(0,60).forEach(line => {
        const ip = line.trim().split(/\s+/)[0];
        if (isIP(ip)) addIP({ value:ip, threat:'compromised', malware:'Compromised Host',
          country:'—', source:'Emerging Threats', dateAdded:today() });
      });
      if (lines.length) liveSources.push('Emerging Threats');
    })().catch(e => console.warn('[feeds] ET:', e.message)),

    // 6. OpenPhish — active phishing URLs
    (async () => {
      const r = await fetchText('https://openphish.com/feed.txt');
      if (r.status!==200 || r.text.length<100) throw new Error('no data');
      const lines = r.text.split('\n').filter(l=>l.trim().startsWith('http'));
      lines.slice(0,50).forEach(line => {
        const url = line.trim();
        addURL({ value:url, threat:'phishing', malware:'Phishing', country:'—',
          source:'OpenPhish', dateAdded:today() });
        try {
          const host = new URL(url).hostname;
          if (isIP(host))     addIP    ({ value:host, threat:'phishing', malware:'Phishing Host',   country:'—', source:'OpenPhish', dateAdded:today() });
          else if (isDomain(host)) addDomain({ value:host, threat:'phishing', malware:'Phishing Domain', country:'—', source:'OpenPhish', dateAdded:today() });
        } catch {}
      });
      if (lines.length) liveSources.push('OpenPhish');
    })().catch(e => console.warn('[feeds] OpenPhish:', e.message)),

    // 7. Abuse.ch SSL Blacklist — malware C2 SSL cert IPs
    (async () => {
      const r = await fetchText('https://sslbl.abuse.ch/blacklist/sslipblacklist_aggressive.csv');
      if (r.status!==200 || r.text.length<100) throw new Error('no data');
      const lines = r.text.split('\n').filter(l=>l.trim()&&!l.startsWith('#'));
      lines.slice(0,60).forEach(line => {
        const p = line.trim().split(',');
        if (!isIP(p[0]?.trim())) return;
        addIP({ value:p[0].trim(), threat:'malware-c2', malware:p[2]?.trim()||'—',
          country:'—', port:p[1]?.trim()||'443', source:'SSL Blacklist', dateAdded:today() });
      });
      if (results.ips.length) liveSources.push('SSL Blacklist');
    })().catch(e => console.warn('[feeds] SSL BL:', e.message)),

    // 8. CINS Score — threat actor IPs
    (async () => {
      const r = await fetchText('https://cinsscore.com/list/ci-badguys.txt');
      if (r.status!==200 || r.text.length<100) throw new Error('no data');
      r.text.split('\n').filter(l=>l.trim()&&!l.startsWith('#')).slice(0,40).forEach(line => {
        const ip=line.trim();
        if (isIP(ip)) addIP({ value:ip, threat:'threat-actor', malware:'—',
          country:'—', source:'CINS Score', dateAdded:today() });
      });
      liveSources.push('CINS Score');
    })().catch(e => console.warn('[feeds] CINS:', e.message)),

  ]); // end Promise.allSettled

  // ── Trim to limit ─────────────────────────────────────────────────
  results.ips     = results.ips.slice(0,limit);
  results.domains = results.domains.slice(0,limit);
  results.urls    = results.urls.slice(0,limit);
  results.hashes  = results.hashes.slice(0,limit);

  const totalLive = results.ips.length + results.domains.length + results.urls.length + results.hashes.length;

  if (liveSources.length > 0) {
    results.sources = [...new Set(liveSources)];
    results._live   = true;
    console.log('[feeds] live:', results.sources.join(', '), '| IOCs:', totalLive);
  } else {
    // ── Deterministic demo data when completely offline ────────────
    results._demo   = true;
    results.sources = ['Demo data — no internet access'];
    console.warn('[feeds] All sources failed — serving demo data');

    function dsh(s, salt, mn, mx) {
      let h=0,str=s+salt;
      for(let i=0;i<str.length;i++) h=(Math.imul(31,h)+str.charCodeAt(i))|0;
      return Math.floor(((Math.abs(h)%100000)/100000)*(mx-mn+1))+mn;
    }
    const td = new Date().toISOString().slice(0,10);
    const families=['Emotet','QakBot','AsyncRAT','RedLine','AgentTesla','Remcos','FormBook','Raccoon','IcedID','PlugX','Cobalt Strike','BlackCat','LockBit','Lazarus'];
    const countries=['RU','CN','NL','DE','US','UA','BR','IR','KP','RO'];
    const malTypes=['botnet-c2','ransomware','stealer','trojan','dropper','rat','loader'];
    const octs=[45,91,103,146,176,185,193,194,195,198,212];
    for(let i=0;i<30;i++){const seed=td+'ip'+i;results.ips.push({value:`${octs[dsh(seed,'o1',0,10)]}.${dsh(seed,'o2',1,254)}.${dsh(seed,'o3',1,254)}.${dsh(seed,'o4',1,254)}`,threat:i<15?'botnet-c2':malTypes[dsh(seed,'mt',0,6)],malware:families[dsh(seed,'fam',0,13)],country:countries[dsh(seed,'cc',0,9)],port:[80,443,447,449,8080,4444,8443][dsh(seed,'port',0,6)],source:i<18?'Feodo Tracker':'ThreatFox',dateAdded:new Date(Date.now()-dsh(seed,'days',0,3)*86400000).toISOString().slice(0,10)});}
    const dp1=['secure','update','cdn','api','login','auth','gate','payload','dl','sync'];const dp2=['service','delivery','track','stream','check','verify','connect','transfer'];const tlds=['.ru','.xyz','.cc','.net','.site','.top','.online','.store'];
    for(let i=0;i<25;i++){const seed=td+'dom'+i;results.domains.push({value:dp1[dsh(seed,'p1',0,9)]+'-'+dp2[dsh(seed,'p2',0,7)]+dsh(seed,'num',10,999)+tlds[dsh(seed,'tld',0,7)],threat:malTypes[dsh(seed,'mt',0,6)],malware:families[dsh(seed,'fam',0,13)],country:countries[dsh(seed,'cc',0,9)],source:i<12?'URLhaus':'ThreatFox',dateAdded:new Date(Date.now()-dsh(seed,'days',0,5)*86400000).toISOString().slice(0,10)});}
    const upaths=['/gate.php','/panel/loader','/bot/check','/payload.exe','/update','/dl/dropper.bin','/admin/gate','/c2/hb','/stage2','/check.php'];
    for(let i=0;i<25;i++){const seed=td+'url'+i;const base=results.domains[dsh(seed,'di',0,24)]?.value||('malhost'+i+'.ru');results.urls.push({value:'http'+(dsh(seed,'https',0,1)?'s':'')+'://'+base+upaths[dsh(seed,'path',0,9)],threat:i<10?'phishing':'malware',malware:families[dsh(seed,'fam',0,13)],country:countries[dsh(seed,'cc',0,9)],source:i<15?'URLhaus':'OpenPhish',dateAdded:new Date(Date.now()-dsh(seed,'days',0,2)*86400000).toISOString().slice(0,10)});}
    const fileTypes=['exe','dll','doc','xls','pdf','zip','iso','ps1','jar'];const sigs=['Emotet','AgentTesla','FormBook','AsyncRAT','RedLine','QakBot','NjRAT','BlackCat','IcedID'];
    for(let i=0;i<25;i++){const seed=td+'hash'+i;const len=dsh(seed,'type',0,1)?64:32;let hv='';for(let j=0;j<len;j++)hv+=dsh(seed,'hc'+j,0,15).toString(16);results.hashes.push({value:hv,threat:'malware',malware:sigs[dsh(seed,'sig',0,8)],malwareFamily:sigs[dsh(seed,'sig',0,8)],fileType:fileTypes[dsh(seed,'ft',0,8)].toUpperCase(),fileSize:dsh(seed,'fs',10,5000)+'KB',md5:Array.from({length:32},(_,j)=>dsh(seed,'md5'+j,0,15).toString(16)).join(''),country:'—',source:'MalwareBazaar',tags:[sigs[dsh(seed,'t1',0,8)]],dateAdded:new Date(Date.now()-dsh(seed,'days',0,7)*86400000).toISOString().slice(0,10)});}
  }

  return results;
}

// ═══════════════════════════════════════════════════════════════
// SANDBOX
// ═══════════════════════════════════════════════════════════════
// SANDBOX — file upload + behavioral analysis
// Uses Hybrid Analysis public API if key provided, else rich simulation
// ═══════════════════════════════════════════════════════════════
async function handleSandbox(body) {
  const { filename, filesize, filehash, filetype, action } = body;

  // If we have a hash, try Hybrid Analysis lookup first
  if (filehash && KEYS.hybrid) {
    try {
      const r = await httpsPost('https://www.hybrid-analysis.com/api/v2/search/hash',
        { hash: filehash },
        { 'api-key': KEYS.hybrid, 'User-Agent': 'Falcon Sandbox', 'Content-Type': 'application/json' });
      if (r.status === 200 && r.data?.length > 0) {
        const rep = r.data[0];
        return buildSandboxResult(filename, filesize, filehash, filetype, rep, false);
      }
    } catch(e) { console.warn('[sandbox] hybrid lookup:', e.message); }
  }

  // Generate deterministic simulation based on filename + hash
  return buildSandboxSimulation(filename || 'unknown.exe', filesize || 0, filehash || '', filetype || 'PE32');
}

function buildSandboxResult(filename, filesize, hash, type, rep, simulated) {
  return {
    simulated: false,
    filename, filesize, hash, type,
    verdict: rep.verdict || 'no specific threat',
    threatScore: rep.threat_score || 0,
    malwareFamily: rep.vx_family || null,
    environment: rep.environment_description || 'Unknown',
    analysisTime: rep.analysis_start_time || null,
    behavior: {
      processes: (rep.processes || []).slice(0, 8).map(p => ({ name: p.name, pid: p.pid, action: p.normalized_path || '' })),
      networkCalls: (rep.network || []).slice(0, 10),
      droppedFiles: rep.extracted_files ? rep.extracted_files.length : 0,
      registryKeys: [],
      mutexes: [],
    },
    iocs: {
      ips: (rep.domains || []).filter(d => /^\d/.test(d)).slice(0, 8),
      domains: (rep.domains || []).filter(d => !/^\d/.test(d)).slice(0, 8),
      urls: [],
      hashes: [],
    },
    mitre: rep.classification_tags || [],
    tags: rep.tags || [],
  };
}

function buildSandboxSimulation(filename, filesize, hash, filetype) {
  function sh(s, salt, min, max) {
    let h = 0, str = s + salt;
    for (let i = 0; i < str.length; i++) h = (Math.imul(31, h) + str.charCodeAt(i)) | 0;
    return Math.floor(((Math.abs(h) % 100000) / 100000) * (max - min + 1)) + min;
  }
  function sp(s, salt, arr) { return arr[sh(s, salt, 0, arr.length - 1)]; }

  const ext = (filetype || filename.split('.').pop() || '').toUpperCase().replace(/^\./, '');

  // ── Categorise extensions precisely ───────────────────────────────
  // SAFE: documents, images, audio, video, data — always clean, never show C2s
  const SAFE_EXTS = new Set([
    'PDF','DOC','DOCX','XLS','XLSX','PPT','PPTX','ODT','ODS','ODP',
    'TXT','CSV','JSON','XML','YAML','YML','MD','RTF','LOG',
    'JPG','JPEG','PNG','GIF','BMP','SVG','WEBP','ICO','TIFF',
    'MP3','WAV','OGG','FLAC','AAC','M4A','WMA',
    'MP4','AVI','MKV','MOV','WMV','FLV','WEBM',
    'ZIP','RAR','7Z','TAR','GZ','BZ2',   // archives: suspicious but not malicious by default
    'ISO','IMG','DMG',
    'PY','RB','GO','RS','JAVA','C','CPP','H','CS','PHP','HTML','CSS',
  ]);

  // RISKY: executables and scripts — can be malicious, need hash-based decision
  const RISKY_EXTS = new Set([
    'EXE','DLL','SCR','COM','PIF','MSI','SYS','DRV',  // Windows executables
    'PS1','PSM1','PSD1','BAT','CMD',                   // PowerShell / batch
    'VBS','VBE','JS','JSE','WSF','WSH','HTA',          // Script engines
    'JAR','CLASS',                                      // Java
    'LNK','INF','REG',                                  // Windows shortcuts / reg
    'SH','BASH','ZSH',                                  // Unix scripts
  ]);

  // Determine base malice likelihood from extension category
  let maliceBase;
  if (SAFE_EXTS.has(ext))  maliceBase = 0;   // documents/media: NEVER flag as malicious
  else if (RISKY_EXTS.has(ext)) maliceBase = sh(filename + hash, 'base', 0, 100);
  else maliceBase = sh(filename + hash, 'base2', 0, 60); // unknown: low probability

  // For archives (.zip etc), occasionally suspicious but rarely malicious
  const ARCHIVE_EXTS = new Set(['ZIP','RAR','7Z','TAR','GZ','BZ2']);
  if (ARCHIVE_EXTS.has(ext)) maliceBase = sh(filename + hash, 'arch', 0, 45);

  const isMalicious = maliceBase > 55;  // threshold — only clear positives get flagged
  const isSuspicious = !isMalicious && maliceBase > 35 && RISKY_EXTS.has(ext);

  const score = isMalicious  ? sh(filename + hash, 'sc',  62, 96) :
                isSuspicious ? sh(filename + hash, 'sc2', 30, 54) :
                               sh(filename + hash, 'sc3',  0, 18);

  // Malware families (only assigned for true malicious detections)
  const families = ['Emotet','AgentTesla','AsyncRAT','Remcos','RedLine',
                    'FormBook','NjRAT','Raccoon','IcedID','QakBot','PlugX','Cobalt Strike Beacon'];
  const family = isMalicious ? sp(filename + hash, 'fam', families) : null;

  // ── Processes — realistic for each verdict ──────────────────────
  const basePid = sh(filename + hash, 'pid', 2000, 6000);
  let processes = [];
  if (isMalicious) {
    processes = [
      { name: filename,       pid: basePid,       action: `C:\Users\Admin\AppData\Local\Temp\${filename}`,                      suspicious: true  },
      { name: 'cmd.exe',      pid: basePid + 284, action: `cmd.exe /c schtasks /create /tn "${(family||'Update')}Task" /tr "${filename}" /sc onlogon /f`, suspicious: true  },
      { name: 'powershell.exe',pid:basePid + 512, action: 'powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBj...',              suspicious: true  },
      { name: 'explorer.exe', pid: 2784,          action: 'C:\Windows\explorer.exe',                                                suspicious: false },
      { name: 'svchost.exe',  pid: 1024,          action: 'C:\Windows\System32\svchost.exe -k netsvcs',                            suspicious: false },
    ];
  } else if (isSuspicious) {
    processes = [
      { name: filename,   pid: basePid,       action: `C:\Users\Admin\Desktop\${filename}`,              suspicious: true  },
      { name: 'cmd.exe',  pid: basePid + 180, action: 'cmd.exe /c whoami && ipconfig /all',                  suspicious: true  },
      { name: 'svchost.exe', pid: 1024,       action: 'C:\Windows\System32\svchost.exe -k netsvcs',       suspicious: false },
    ];
  } else {
    // Clean file — only normal system processes
    processes = [
      { name: filename,      pid: basePid, action: `C:\Users\Admin\Documents\${filename}`, suspicious: false },
      { name: 'explorer.exe',pid: 2784,    action: 'C:\Windows\explorer.exe',                suspicious: false },
    ];
  }

  // ── Network calls — ONLY for malicious files, realistic C2 infra ─
  // C2 domains use realistic-looking but clearly fake domains
  const c2DomParts = [
    ['telemetry','update','cdn','sync','api','gate'],
    ['service','check','tracker','relay','beacon','report'],
  ];
  const c2Tlds = ['.xyz','.ru','.cc','.top','.site','.online'];
  const c2Dom1 = sp(filename+hash,'cd1a',c2DomParts[0]) + '-' + sp(filename+hash,'cd1b',c2DomParts[1]) + sp(filename+hash,'cd1c',c2Tlds);
  const c2Dom2 = sp(filename+hash,'cd2a',c2DomParts[0]) + sp(sh(filename+hash,'cnum',100,999).toString(),'','') + sp(filename+hash,'cd2c',c2Tlds);

  // C2 IPs use known malicious hosting ASN ranges (for realism), not random
  const maliciousOctets = [
    [45, sh(filename+hash,'ci1a',1,254), sh(filename+hash,'ci1b',1,254), sh(filename+hash,'ci1c',1,254)],
    [185, sh(filename+hash,'ci2a',100,254), sh(filename+hash,'ci2b',1,254), sh(filename+hash,'ci2c',1,254)],
  ];
  const c2IP1 = maliciousOctets[0].join('.');
  const c2IP2 = maliciousOctets[1].join('.');

  const networkCalls = isMalicious ? [
    { protocol:'HTTPS', dst:c2IP1, port:443,  domain:c2Dom1, bytes:sh(filename+hash,'nb1',4096,131072), direction:'outbound' },
    { protocol:'HTTP',  dst:c2IP2, port:sh(filename+hash,'np2',80,8080), domain:c2Dom2, bytes:sh(filename+hash,'nb2',512,16384), direction:'outbound' },
    { protocol:'DNS',   dst:'8.8.8.8', port:53, domain:c2Dom1, bytes:68, direction:'outbound' },
  ] : isSuspicious ? [
    { protocol:'DNS', dst:'8.8.8.8', port:53, domain:'microsoft.com', bytes:68, direction:'outbound' },
  ] : [];

  // ── Registry — ONLY for malicious ──────────────────────────────
  const registryKeys = isMalicious ? [
    `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\${family||'UpdateService'}`,
    `HKLM\SYSTEM\CurrentControlSet\Services\${(family||'svc').replace(/\s/g,'')}`,
    `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce\${sp(filename+hash,'rk',['cleanup','updater','svc','task'])}`,
  ] : [];

  // ── MITRE TTPs ─────────────────────────────────────────────────
  const mitreTTPs = isMalicious ? [
    'T1547.001 - Boot/Logon Autostart: Registry Run Keys',
    'T1071.001 - Application Layer Protocol: Web Protocols',
    'T1059.003 - Command and Scripting: Windows Command Shell',
    'T1055 - Process Injection',
    'T1041 - Exfiltration Over C2 Channel',
  ] : isSuspicious ? [
    'T1082 - System Information Discovery',
    'T1057 - Process Discovery',
  ] : [];

  const verdict = isMalicious ? (score > 78 ? 'malicious' : 'suspicious') : isSuspicious ? 'suspicious' : 'clean';

  return {
    simulated: true,
    filename, filesize, hash: hash || 'N/A', type: ext || filetype,
    verdict,
    threatScore: score,
    malwareFamily: family,
    environment: 'Windows 10 x64 22H2 (simulated)',
    analysisTime: new Date().toISOString(),
    behavior: {
      processes,
      networkCalls,
      droppedFiles: isMalicious ? sh(filename+hash,'df',1,4) : 0,
      registryKeys,
      mutexes: isMalicious ? [`Global\\${(family||'Mutex').replace(/\s/g,'')}_{${sh(filename+hash,'mx',1000,9999)}}`] : [],
    },
    iocs: {
      ips:     isMalicious ? [c2IP1, c2IP2] : [],
      domains: isMalicious ? [c2Dom1, c2Dom2] : [],
      urls:    isMalicious ? [`https://${c2Dom1}/gate.php`, `http://${c2IP2}:${sh(filename+hash,'np2',80,8080)}/check`] : [],
      hashes:  [],
    },
    mitre: mitreTTPs,
    tags: isMalicious ? [sp(filename+hash,'tag',['stealer','dropper','rat','ransomware','loader']), 'evasion'] :
          isSuspicious ? ['suspicious','recon'] : ['clean'],
  };
}

// ═══════════════════════════════════════════════════════════════
// RELATIONSHIP GRAPH — pivot on IOC to find related infrastructure
// Uses VT graph API + passive DNS + WHOIS + URLScan
// ═══════════════════════════════════════════════════════════════
async function handleGraph(body) {
  const { ioc, type } = body;
  if (!security.validateIOC(ioc)) throw new Error('Invalid IOC');

  const nodes = [];
  const edges = [];
  const seen  = new Set();

  function addNode(id, label, nodeType, threat, meta) {
    if (seen.has(id)) return;
    seen.add(id);
    nodes.push({ id, label, type: nodeType, threat: threat || 'unknown', meta: meta || {} });
  }
  function addEdge(from, to, relation, weight) {
    edges.push({ from, to, relation, weight: weight || 1 });
  }

  // Add the root IOC node
  addNode(ioc, ioc, type, 'root', { isRoot: true });

  // ── VT relationships (requires key) ──────────────────────────────
  if (KEYS.virustotal) {
    try {
      const g = typeGroup(type);
      let relUrl;
      if (g === 'ip')     relUrl = `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(ioc)}/resolutions?limit=10`;
      else if (g === 'domain') relUrl = `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(ioc)}/resolutions?limit=10`;
      else if (g === 'hash')   relUrl = `https://www.virustotal.com/api/v3/files/${encodeURIComponent(ioc)}/contacted_domains?limit=10`;

      if (relUrl) {
        const r = await httpsGet(relUrl, { 'x-apikey': KEYS.virustotal });
        if (r.status === 200 && r.data?.data) {
          r.data.data.slice(0, 8).forEach(rel => {
            const attrs = rel.attributes || {};
            const relIoc = attrs.ip_address || attrs.host_name || rel.id || '';
            if (!relIoc) return;
            const relType = /^(\d{1,3}\.){3}\d{1,3}$/.test(relIoc) ? 'ip' : 'domain';
            const mal = attrs.stats?.malicious || 0;
            const threat = mal > 5 ? 'malicious' : mal > 1 ? 'suspicious' : 'clean';
            addNode(relIoc, relIoc, relType, threat, { detections: mal, source: 'VirusTotal' });
            addEdge(ioc, relIoc, g === 'hash' ? 'contacts' : 'resolves-to', mal > 3 ? 3 : 1);
          });
        }
      }

      // Also get communicating files if this is an IP/domain
      if (typeGroup(type) !== 'hash') {
        const g2 = typeGroup(type);
        const comUrl = g2 === 'ip'
          ? `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(ioc)}/communicating_files?limit=5`
          : `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(ioc)}/communicating_files?limit=5`;
        const r2 = await httpsGet(comUrl, { 'x-apikey': KEYS.virustotal });
        if (r2.status === 200 && r2.data?.data) {
          r2.data.data.slice(0, 4).forEach(f => {
            const fhash = f.id || '';
            const mal   = f.attributes?.last_analysis_stats?.malicious || 0;
            const fam   = f.attributes?.popular_threat_label || '';
            const threat = mal > 5 ? 'malicious' : mal > 1 ? 'suspicious' : 'clean';
            addNode(fhash, fhash.slice(0,16)+'...', 'hash', threat, { detections: mal, family: fam, source: 'VirusTotal' });
            addEdge(fhash, ioc, 'communicates-with', mal > 5 ? 3 : 1);
          });
        }
      }
    } catch(e) { console.warn('[graph] VT pivot:', e.message); }

    // Subgraph: for each related node, get its resolutions too (1 hop)
    const firstHop = nodes.filter(n => !n.meta.isRoot).slice(0, 4);
    for (const n of firstHop) {
      try {
        const g2 = typeGroup(n.type);
        if (g2 !== 'ip' && g2 !== 'domain') continue;
        const url2 = g2 === 'ip'
          ? `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(n.id)}/resolutions?limit=5`
          : `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(n.id)}/resolutions?limit=5`;
        const r2 = await httpsGet(url2, { 'x-apikey': KEYS.virustotal });
        if (r2.status === 200 && r2.data?.data) {
          r2.data.data.slice(0, 3).forEach(rel => {
            const attrs = rel.attributes || {};
            const relId = attrs.ip_address || attrs.host_name || '';
            if (!relId || relId === ioc) return;
            const relType = /^(\d{1,3}\.){3}\d{1,3}$/.test(relId) ? 'ip' : 'domain';
            const mal = attrs.stats?.malicious || 0;
            addNode(relId, relId, relType, mal > 5 ? 'malicious' : mal > 1 ? 'suspicious' : 'clean', { detections: mal, source: 'VirusTotal', hop: 2 });
            addEdge(n.id, relId, 'resolves-to', 1);
          });
        }
      } catch {}
    }
  }

  // ── URLScan passive DNS (no auth for basic search) ───────────────
  if (KEYS.urlscan && typeGroup(type) !== 'hash') {
    try {
      const q = typeGroup(type) === 'ip' ? `ip:"${ioc}"` : `domain:"${ioc}"`;
      const r = await httpsGet(`https://urlscan.io/api/v1/search/?q=${encodeURIComponent(q)}&size=5`, { 'API-Key': KEYS.urlscan });
      if (r.status === 200 && r.data?.results) {
        r.data.results.slice(0, 5).forEach(scan => {
          const pg = scan.page || {};
          if (pg.url && pg.url !== ioc) {
            const mal = scan.verdicts?.overall?.malicious || false;
            const score = scan.verdicts?.overall?.score || 0;
            const threat = mal ? 'malicious' : score > 50 ? 'suspicious' : 'clean';
            addNode(pg.url, pg.url.slice(0,50)+'...', 'url', threat, { score, source: 'URLScan', resultUrl: `https://urlscan.io/result/${scan._id}/` });
            addEdge(ioc, pg.url, 'scanned-url', mal ? 3 : 1);
            // Link IP to domain
            if (pg.ip && pg.ip !== ioc) {
              addNode(pg.ip, pg.ip, 'ip', threat, { source: 'URLScan' });
              addEdge(pg.url, pg.ip, 'resolved-to', 1);
            }
          }
        });
      }
    } catch(e) { console.warn('[graph] URLScan pivot:', e.message); }
  }

  // ── If no API keys, build a deterministic demo graph ─────────────
  if (nodes.length <= 1) {
    function sh(s, salt, min, max) {
      let h = 0, str = s + salt;
      for (let i = 0; i < str.length; i++) h = (Math.imul(31, h) + str.charCodeAt(i)) | 0;
      return Math.floor(((Math.abs(h) % 100000) / 100000) * (max - min + 1)) + min;
    }
    const ip1  = `185.${sh(ioc,'i1',1,254)}.${sh(ioc,'i2',1,254)}.${sh(ioc,'i3',1,254)}`;
    const ip2  = `194.${sh(ioc,'i4',1,254)}.${sh(ioc,'i5',1,254)}.${sh(ioc,'i6',1,254)}`;
    const dom1 = ['update-cdn.net','secure-api.ru','telemetry-svc.xyz','cdn-proxy.cc','auth-service.net'][sh(ioc,'d1',0,4)];
    const dom2 = ['payload-host.ru','c2-gate.xyz','botnet-ctrl.net','exfil-srv.cc','dropper.site'][sh(ioc,'d2',0,4)];
    const hash1 = Array.from({length:32},(_,i)=>sh(ioc,'h1'+i,0,15).toString(16)).join('');
    const url1 = `https://${dom1}/gate.php`;

    const t = typeGroup(type);
    if (t === 'ip') {
      addNode(dom1, dom1, 'domain', 'suspicious', { source:'Demo', hop:1 });
      addNode(dom2, dom2, 'domain', 'malicious',  { source:'Demo', hop:1 });
      addNode(url1, url1, 'url',    'malicious',  { source:'Demo', hop:2 });
      addNode(hash1, hash1.slice(0,16)+'...', 'hash', 'malicious', { source:'Demo', family:'Emotet', hop:2 });
      addEdge(ioc,  dom1,  'hosted-on',        2);
      addEdge(ioc,  dom2,  'hosted-on',        3);
      addEdge(dom2, url1,  'serves',           3);
      addEdge(hash1, ioc,  'communicates-with',3);
    } else if (t === 'domain') {
      addNode(ip1,  ip1,  'ip',   'suspicious', { source:'Demo', hop:1 });
      addNode(ip2,  ip2,  'ip',   'malicious',  { source:'Demo', hop:1 });
      addNode(url1, url1, 'url',  'malicious',  { source:'Demo', hop:1 });
      addNode(hash1, hash1.slice(0,16)+'...', 'hash', 'malicious', { source:'Demo', family:'AgentTesla', hop:2 });
      addEdge(ioc,   ip1,   'resolves-to',      2);
      addEdge(ioc,   ip2,   'resolves-to',      3);
      addEdge(ioc,   url1,  'hosts',            3);
      addEdge(hash1, ioc,   'contacts',         3);
      addEdge(hash1, ip2,   'communicates-with',2);
    } else {
      addNode(dom1, dom1, 'domain', 'malicious',  { source:'Demo', hop:1 });
      addNode(ip1,  ip1,  'ip',     'malicious',  { source:'Demo', hop:1 });
      addNode(url1, url1, 'url',    'malicious',  { source:'Demo', hop:2 });
      addEdge(ioc,  dom1, 'contacts',         3);
      addEdge(ioc,  ip1,  'communicates-with',3);
      addEdge(dom1, ip1,  'resolves-to',      2);
      addEdge(dom1, url1, 'serves',           2);
    }
  }

  return { ioc, type, nodes, edges, nodeCount: nodes.length, edgeCount: edges.length, demo: nodes.some(n => n.meta.source === 'Demo') };
}


// ═══════════════════════════════════════════════════════════════
// LOG ANALYZER
// Parses common log formats, extracts IOCs, correlates events,
// runs decision engine, returns structured analyst report.
// ═══════════════════════════════════════════════════════════════
async function handleLogAnalyze(body) {
  const { content, filename } = body;
  if (!content || typeof content !== 'string') throw new Error('No log content provided');
  if (content.length > 2000000) throw new Error('Log file too large — maximum 2MB');

  const lines = content.split(/\r?\n/).filter(l => l.trim());

  // ── IOC extraction regexes ──────────────────────────────────
  const RE = {
    ipv4:    /\b((?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?))\b/g,
    domain:  /\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|ru|xyz|cc|top|site|online|info|biz|co|uk|de|fr|nl|cn|jp|br|au|in|tk|ml|ga|cf|gq|gov|edu|mil|int|arpa))\b/g,
    url:     /https?:\/\/[^\s<>"'{}|\\^`\[\]]{8,200}/g,
    md5:     /\b[a-fA-F0-9]{32}\b/g,
    sha256:  /\b[a-fA-F0-9]{64}\b/g,
    sha1:    /\b[a-fA-F0-9]{40}\b/g,
    email:   /\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b/g,
    userAgent: /(?:User-Agent|user-agent):\s*([^\r\n"]{10,200})/gi,
    cvePath: /CVE-\d{4}-\d{4,7}/gi,
    winPath:  /[A-Z]:\\(?:[^\r\n<>"|?*]{1,50}\\){1,8}[^\r\n<>"|?*\\]{1,50}/g,
    linuxPath:/\/(?:etc|tmp|var|usr|home|root|proc|bin|sbin|opt)\/[^\r\n\s'"]{1,120}/g,
    statusCode:/\b([45]\d{2})\b/g,
  };

  // Private/loopback IPs to exclude
  function isPrivate(ip) {
    return /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)|^(::1|fe80:|fc00:|0\.0\.0\.0$)/.test(ip);
  }
  function isDomainNoise(d) {
    const noise = ['localhost','local','internal','example.com','example.org','test.com','w3.org','schema.org','mozilla.org','microsoft.com','windows.com','apple.com','googleapis.com','gstatic.com','jquery.com','cdn.jsdelivr.net','cdnjs.cloudflare.com'];
    return noise.some(n => d === n || d.endsWith('.'+n));
  }

  // ── Detect log format ────────────────────────────────────────
  function detectFormat(lines) {
    const sample = lines.slice(0,20).join('\n');
    if (/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.*EventID/i.test(sample)) return 'windows-event';
    if (/\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}.*kernel|sshd|sudo|systemd/i.test(sample)) return 'syslog';
    if (/\d{1,3}\.\d{1,3}.*"(GET|POST|PUT|DELETE|HEAD)/i.test(sample)) return 'apache-nginx';
    if (/action=|dstip=|srcip=|proto=|policy=|devname=/i.test(sample)) return 'firewall';
    if (/timestamp.*alert|signature|priority|classification/i.test(sample)) return 'ids-snort';
    if (/"event_type"|"src_ip"|"dest_ip"|"proto"/i.test(sample)) return 'suricata-json';
    if (/\|.*\|.*\|/i.test(sample)) return 'csv-pipe';
    return 'generic';
  }
  const format = detectFormat(lines);

  // ── Extract all IOCs with context ────────────────────────────
  const iocMap = { ips:{}, domains:{}, urls:{}, hashes:{}, emails:[], cves:[], paths:[], userAgents:[] };

  function trackIP(ip, lineIdx, line) {
    if (isPrivate(ip)) return;
    if (!iocMap.ips[ip]) iocMap.ips[ip] = { count:0, lines:[], contexts:[] };
    iocMap.ips[ip].count++;
    if (iocMap.ips[ip].lines.length < 5) {
      iocMap.ips[ip].lines.push(lineIdx+1);
      iocMap.ips[ip].contexts.push(line.slice(0,200));
    }
  }
  function trackDomain(d, lineIdx, line) {
    if (isDomainNoise(d)) return;
    if (!iocMap.domains[d]) iocMap.domains[d] = { count:0, lines:[] };
    iocMap.domains[d].count++;
    if (iocMap.domains[d].lines.length < 5) iocMap.domains[d].lines.push(lineIdx+1);
  }
  function trackURL(u, lineIdx) {
    if (!iocMap.urls[u]) iocMap.urls[u] = { count:0, lines:[] };
    iocMap.urls[u].count++;
    if (iocMap.urls[u].lines.length < 3) iocMap.urls[u].lines.push(lineIdx+1);
  }
  function trackHash(h, lineIdx) {
    if (!iocMap.hashes[h]) iocMap.hashes[h] = { count:0, lines:[], len:h.length };
    iocMap.hashes[h].count++;
    if (iocMap.hashes[h].lines.length < 3) iocMap.hashes[h].lines.push(lineIdx+1);
  }

  const statusCounts = {};
  lines.forEach((line, idx) => {
    const l = line;
    // IPs
    for (const m of (l.matchAll ? l.matchAll(RE.ipv4) : [])) trackIP(m[1], idx, l);
    // Domains
    for (const m of (l.matchAll ? l.matchAll(RE.domain) : [])) trackDomain(m[1].toLowerCase(), idx, l);
    // URLs — also extract domain/IP from URL
    for (const m of (l.matchAll ? l.matchAll(RE.url) : [])) {
      trackURL(m[0], idx);
      try { const h = new URL(m[0]).hostname; /^\d/.test(h)?trackIP(h,idx,l):trackDomain(h.toLowerCase(),idx,l); } catch{}
    }
    // Hashes
    for (const m of (l.matchAll ? l.matchAll(RE.sha256) : [])) trackHash(m[0].toLowerCase(), idx);
    for (const m of (l.matchAll ? l.matchAll(RE.sha1) : [])) {
      if (!l.includes(m[0].toLowerCase()+'  ') && m[0].length===40) trackHash(m[0].toLowerCase(), idx);
    }
    for (const m of (l.matchAll ? l.matchAll(RE.md5) : [])) {
      if (m[0].length===32 && !/^[0]+$/.test(m[0])) trackHash(m[0].toLowerCase(), idx);
    }
    // Emails
    const emailM = l.match(RE.email);
    if (emailM) iocMap.emails.push(...emailM.filter(e=>!iocMap.emails.includes(e)).slice(0,3));
    // CVEs
    const cveM = l.match(RE.cvePath);
    if (cveM) iocMap.cves.push(...cveM.filter(c=>!iocMap.cves.includes(c)).slice(0,5));
    // Paths
    const pathM = l.match(RE.winPath) || l.match(RE.linuxPath);
    if (pathM) iocMap.paths.push(...pathM.slice(0,2));
    // User agents
    const uaM = l.match(RE.userAgent);
    if (uaM) iocMap.userAgents.push(...uaM.map(m=>m.replace(/^[Uu]ser-[Aa]gent:\s*/,'')).slice(0,3));
    // HTTP status codes
    const scM = l.match(RE.statusCode);
    if (scM) scM.forEach(sc => { statusCounts[sc]=(statusCounts[sc]||0)+1; });
  });

  // ── Correlation — build attack flow timeline ─────────────────
  // Step 1: simple co-occurrence pairs (kept for decisions engine)
  const correlations = [];
  const ipList = Object.keys(iocMap.ips);
  const domList = Object.keys(iocMap.domains);

  lines.forEach(line => {
    const lineIPs = ipList.filter(ip => line.includes(ip));
    const lineDoms = domList.filter(d => line.includes(d));
    const allInLine = [...lineIPs, ...lineDoms];
    if (allInLine.length >= 2) {
      for (let i=0;i<allInLine.length;i++) for(let j=i+1;j<allInLine.length;j++) {
        const pair = [allInLine[i],allInLine[j]].sort().join(' <-> ');
        const existing = correlations.find(c=>c.pair===pair);
        if (existing) existing.count++;
        else correlations.push({ pair, a:allInLine[i], b:allInLine[j], count:1 });
      }
    }
  });
  correlations.sort((a,b)=>b.count-a.count);

  // Step 2: Attack flow — sequence of ordered, labelled attack stages
  // Each stage is detected by keyword + IOC patterns across all lines
  const attackFlow = [];
  const lc2 = content.toLowerCase();

  // Helper: find the first IOC of a given type that matches a pattern in matching lines
  const IP_RE2   = /\b((?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?))\b/g;
  const DOM_RE2  = /\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|ru|xyz|cc|top|site|online|info|biz|co|uk|de|fr|nl|cn|jp|br|au|in|tk|ml|ga|cf|gq|gov|edu|mil|int|arpa))\b/ig;

  function extractAnyIP(line) {
    IP_RE2.lastIndex = 0;
    let m;
    while ((m = IP_RE2.exec(line)) !== null) {
      if (!isPrivate(m[1])) return m[1];
    }
    return null;
  }
  function extractAnyDomain(line) {
    DOM_RE2.lastIndex = 0;
    let m;
    while ((m = DOM_RE2.exec(line)) !== null) {
      if (!isDomainNoise(m[1].toLowerCase())) return m[1].toLowerCase();
    }
    return null;
  }

  function firstMatchingIOC(linePattern, iocType) {
    // Collect all lines that match the pattern
    const matched = [];
    for (let i = 0; i < lines.length; i++) {
      if (linePattern.test(lines[i])) matched.push(i);
    }
    if (!matched.length) return null;

    // Try directly matching lines
    for (const i of matched) {
      const l = lines[i];
      if (iocType === 'ip') {
        const v = extractAnyIP(l);
        if (v) return { value:v, line:i+1 };
      } else if (iocType === 'domain') {
        const v = extractAnyDomain(l);
        if (v) return { value:v, line:i+1 };
      } else if (iocType === 'hash') {
        const m = l.match(/\b([a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b/);
        if (m) return { value:m[1].toLowerCase(), line:i+1 };
      } else if (iocType === 'url') {
        const m = l.match(/https?:\/\/[^\s<>"']{8,200}/);
        if (m) return { value:m[0], line:i+1 };
      }
    }

    // Fallback: scan ±3 context lines around first match for any IOC
    const pivot = matched[0];
    for (let j = Math.max(0,pivot-3); j <= Math.min(lines.length-1,pivot+3); j++) {
      const v = extractAnyIP(lines[j]) || extractAnyDomain(lines[j]);
      if (v) return { value:v, line:j+1 };
    }

    // Last resort: stage detected but no clean IOC extracted
    return { value:'(see line '+(pivot+1)+')', line:pivot+1 };
  }


  // Stage definitions — ordered by attack lifecycle
  const stagePatterns = [
    {
      id:'recon',
      label:'Reconnaissance',
      icon:'🔭',
      mitre:'T1595 — Active Scanning',
      color:'#8b5cf6',
      patterns: [/nmap|masscan|zmap|nikto|dirb|gobuster|scan.*port|port.*scan|nuclei/i],
      iocType: 'ip',
      description: 'Attacker scanned target infrastructure to discover open ports and services.',
    },
    {
      id:'bruteforce',
      label:'Brute-Force Login',
      icon:'🔨',
      mitre:'T1110 — Brute Force',
      color:'var(--critical)',
      patterns: [/failed.*login|login.*fail|authentication.*fail|failed.*password|invalid.*user|brute.?force|repeated.*attempts|too many|password.*attempt/i],
      iocType: 'ip',
      description: 'Multiple failed authentication attempts detected from external IP — credential stuffing or brute-force attack.',
    },
    {
      id:'login_success',
      label:'Successful Login',
      icon:'✅',
      mitre:'T1078 — Valid Accounts',
      color:'var(--high)',
      patterns: [/login.*success|authentication.*success|accepted.*password|session.*opened|user.*logged.*in|access.*granted|200.*login|logged in/i],
      iocType: 'ip',
      description: 'Authentication succeeded — attacker gained initial access using valid or compromised credentials.',
    },
    {
      id:'malicious_domain',
      label:'Malicious Domain Access',
      icon:'🌐',
      mitre:'T1566 — Phishing / T1071 — C2',
      color:'var(--high)',
      patterns: [/malicious.*domain|blocked.*domain|evil.*domain|suspicious.*domain|phishing.*domain|request.*malware|malware.*domain/i],
      iocType: 'domain',
      description: 'User or process contacted a known-malicious or suspicious domain.',
    },
    {
      id:'download',
      label:'Malware Download',
      icon:'⬇️',
      mitre:'T1105 — Ingress Tool Transfer',
      color:'var(--high)',
      patterns: [/download|\.exe|\.dll|\.ps1|\.bat|\.vbs|\.hta|\.jar|payload|dropper|wget|curl.*http|invoke.*webrequest|certutil.*urlcache/i],
      iocType: 'url',
      description: 'Malicious file or payload was downloaded to the victim system.',
    },
    {
      id:'execution',
      label:'Code Execution',
      icon:'⚙️',
      mitre:'T1059 — Command & Scripting',
      color:'var(--high)',
      patterns: [/cmd\.exe|powershell|wscript|cscript|bash.*-c|sh.*-c|execut|spawn.*process|process.*creat|rundll32|regsvr32|mshta/i],
      iocType: 'ip',
      description: 'Malicious code or script was executed on the victim system.',
    },
    {
      id:'persistence',
      label:'Persistence Established',
      icon:'📌',
      mitre:'T1547 — Boot Autostart',
      color:'var(--medium)',
      patterns: [/schtasks|crontab|registry.*run|startup|autorun|persist|scheduled.*task|service.*install/i],
      iocType: 'ip',
      description: 'Attacker established persistence to survive reboots.',
    },
    {
      id:'c2',
      label:'C2 Communication',
      icon:'📡',
      mitre:'T1071 — Application Layer Protocol',
      color:'var(--critical)',
      patterns: [/beacon|heartbeat|check.?in|callback|established.*443|established.*4444|connect.*attacker|c2.*established|netflow.*c2/i],
      iocType: 'ip',
      description: 'Compromised host established command-and-control channel with attacker infrastructure.',
    },
    {
      id:'lateral',
      label:'Lateral Movement',
      icon:'↔️',
      mitre:'T1021 — Remote Services',
      color:'var(--critical)',
      patterns: [/lateral|psexec|wmiexec|smbexec|pass.the.hash|mimikatz|rdp.*internal|smb.*internal|move.*laterally/i],
      iocType: 'ip',
      description: 'Attacker moved laterally within the network to reach additional systems.',
    },
    {
      id:'exfil',
      label:'Data Exfiltration',
      icon:'📤',
      mitre:'T1041 — Exfiltration Over C2',
      color:'var(--critical)',
      patterns: [/exfil|bytes.?sent=\d{5,}|upload.*attacker|transfer.*MB|ftp.*put|scp.*remote|data.*exfiltrat/i],
      iocType: 'ip',
      description: 'Sensitive data was transferred to attacker-controlled infrastructure.',
    },
  ];

  // Detect which stages are present and extract relevant IOCs
  stagePatterns.forEach(stage => {
    let matched = null;
    for (const pat of stage.patterns) {
      matched = firstMatchingIOC(pat, stage.iocType);
      if (matched) break;
    }
    if (matched) {
      attackFlow.push({
        id:    stage.id,
        step:  attackFlow.length + 1,
        label: stage.label,
        icon:  stage.icon,
        mitre: stage.mitre,
        color: stage.color,
        description: stage.description,
        ioc:   matched.value,
        iocType: stage.iocType,
        lineRef: matched.line,
      });
    }
  });

  // ── Top IOCs by frequency ─────────────────────────────────────
  const topIPs = Object.entries(iocMap.ips)
    .sort((a,b)=>b[1].count-a[1].count).slice(0,20)
    .map(([ip,v])=>({ value:ip, count:v.count, lines:v.lines, contexts:v.contexts||[] }));
  const topDomains = Object.entries(iocMap.domains)
    .sort((a,b)=>b[1].count-a[1].count).slice(0,15)
    .map(([d,v])=>({ value:d, count:v.count, lines:v.lines }));
  const topURLs = Object.entries(iocMap.urls)
    .sort((a,b)=>b[1].count-a[1].count).slice(0,10)
    .map(([u,v])=>({ value:u, count:v.count, lines:v.lines }));
  const topHashes = Object.entries(iocMap.hashes)
    .sort((a,b)=>b[1].count-a[1].count).slice(0,10)
    .map(([h,v])=>({ value:h, count:v.count, lines:v.lines, type: v.len===64?'sha256':v.len===40?'sha1':'md5' }));

  // ── Threat indicators (pattern matching) ─────────────────────
  const indicators = [];
  const lc = content.toLowerCase();
  const patterns = [
    { re:/sql.*injection|' or '1'='1|union.*select|information_schema/i,     label:'SQL Injection attempt',       severity:'critical' },
    { re:/powershell.*-enc|-encodedcommand|-exec bypass|downloadstring/i,     label:'PowerShell encoded/download', severity:'critical' },
    { re:/cmd\.exe.*\/c|command\.com.*\/c/i,                                  label:'Command execution via cmd',   severity:'high'     },
    { re:/mimikatz|sekurlsa|lsadump|wdigest/i,                                label:'Credential dumping tool',     severity:'critical' },
    { re:/lateral.*move|psexec|wmiexec|smbexec|pass.the.hash/i,               label:'Lateral movement indicator',  severity:'critical' },
    { re:/\.onion|tor2web|torproject/i,                                        label:'Tor / dark web activity',     severity:'high'     },
    { re:/base64.*[a-zA-Z0-9+\/]{40,}/,                                      label:'Encoded payload detected',    severity:'high'     },
    { re:/nmap|masscan|zmap|nuclei.*scan|nikto|dirb|gobuster/i,             label:'Reconnaissance / scanning',   severity:'medium'   },
    { re:/ransomware|\.locky|\.wannacry|ryuk|conti|lockbit/i,                 label:'Ransomware indicator',        severity:'critical' },
    { re:/webshell|c99|r57|passthru.*shell|shell_exec/i,                      label:'Web shell activity',          severity:'critical' },
    { re:/exploit|shellcode|payload|stage[12]/i,                               label:'Exploit / payload activity',  severity:'high'     },
    { re:/authentication failure|failed password|invalid user|brute.?force/i, label:'Brute force / auth failure',  severity:'medium'   },
    { re:/exfiltrat|data.*transfer.*\d{2,}mb|curl.*-T|wget.*--post-file/i,    label:'Possible data exfiltration',  severity:'high'     },
    { re:/\b4[0-9]{2}\b.*\b4[0-9]{2}\b.*\b4[0-9]{2}\b/,               label:'Multiple 4xx errors (scan)',  severity:'low'      },
    { re:/\b500\b.*error|internal server error/i,                            label:'Server error activity',       severity:'low'      },
  ];
  patterns.forEach(p => {
    if (p.re.test(content)) indicators.push({ label:p.label, severity:p.severity });
  });

  // ── Timeline — first/last occurrence per source IP ────────────
  const timeline = [];
  const tsParsers = [
    /^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})/,  // ISO
    /^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})/,     // syslog
    /(\d{2}\/\w{3}\/\d{4}:\d{2}:\d{2}:\d{2})/,   // Apache
  ];
  const firstSeen={}, lastSeen={};
  lines.forEach(line => {
    let ts = null;
    for (const re of tsParsers) { const m=line.match(re); if(m){ts=m[1];break;} }
    if (!ts) return;
    const ipM = line.match(RE.ipv4);
    if (ipM) {
      const ip = ipM.find(i=>!isPrivate(i));
      if (ip) { if(!firstSeen[ip]) firstSeen[ip]=ts; lastSeen[ip]=ts; }
    }
  });
  Object.entries(firstSeen).slice(0,10).forEach(([ip,first])=>{
    timeline.push({ ip, firstSeen:first, lastSeen:lastSeen[ip]||first, count:(iocMap.ips[ip]||{}).count||1 });
  });
  timeline.sort((a,b)=>b.count-a.count);

  // ── Decision Engine ───────────────────────────────────────────
  const decisions = [];
  const criticalCount = indicators.filter(i=>i.severity==='critical').length;
  const highCount     = indicators.filter(i=>i.severity==='high').length;
  const totalIOCs     = topIPs.length+topDomains.length+topHashes.length;

  // Determine overall severity
  let overallSeverity = 'informational';
  if (criticalCount > 0)            overallSeverity = 'critical';
  else if (highCount > 0)           overallSeverity = 'high';
  else if (indicators.length > 0)   overallSeverity = 'medium';
  else if (totalIOCs > 0)           overallSeverity = 'low';

  // Decision rules
  if (criticalCount > 0) {
    decisions.push({ priority:1, action:'🚨 IMMEDIATE ESCALATION', detail:'Critical threat indicators detected. Escalate to Tier 3/IR team immediately. Do not wait for further analysis.', type:'escalate' });
    decisions.push({ priority:2, action:'🔒 ISOLATE AFFECTED SYSTEMS', detail:'Identify and network-isolate any systems associated with the detected IOCs to prevent lateral movement.', type:'block' });
  }
  if (topIPs.length > 0) {
    const topIP = topIPs[0];
    decisions.push({ priority:3, action:'🚫 BLOCK TOP SOURCE IPs', detail:`Block ${topIP.value} (seen ${topIP.count}x) at perimeter firewall. Also review: ${topIPs.slice(1,4).map(i=>i.value).join(', ')}.`, type:'block' });
  }
  if (topDomains.length > 0) {
    decisions.push({ priority:4, action:'🌐 DNS SINKHOLE / BLOCK DOMAINS', detail:`Block at DNS level: ${topDomains.slice(0,5).map(d=>d.value).join(', ')}`, type:'block' });
  }
  if (topHashes.length > 0) {
    decisions.push({ priority:5, action:'🔍 INVESTIGATE FILE HASHES', detail:`Submit these hashes to VirusTotal and Hybrid Analysis: ${topHashes.slice(0,3).map(h=>h.value.slice(0,16)+'...').join(', ')}`, type:'investigate' });
  }
  if (iocMap.cves.length > 0) {
    decisions.push({ priority:6, action:'🩹 PATCH CVEs IMMEDIATELY', detail:`Exploited vulnerabilities detected: ${iocMap.cves.join(', ')}. Apply vendor patches and review exposure.`, type:'patch' });
  }
  if (correlations.length > 0) {
    decisions.push({ priority:7, action:'🔗 INVESTIGATE CORRELATED IOCs', detail:`${correlations[0].a} and ${correlations[0].b} appear together ${correlations[0].count} times — likely same campaign. Pivot investigation.`, type:'investigate' });
  }
  const authFail = indicators.find(i=>i.label.includes('rute force'));
  if (authFail) {
    decisions.push({ priority:8, action:'🔐 ENFORCE MFA / ACCOUNT REVIEW', detail:'Authentication failure pattern detected. Enforce MFA on affected accounts, reset credentials for targeted users, review account lockout policies.', type:'harden' });
  }
  decisions.push({ priority:9, action:'📋 CREATE INCIDENT TICKET', detail:`Log this event in your ticketing system. Severity: ${overallSeverity.toUpperCase()}. Attach this report for IR team reference.`, type:'document' });
  decisions.push({ priority:10, action:'🔎 SUBMIT IOCs TO THREAT INTEL', detail:'Share confirmed malicious IOCs with your threat intelligence platform (MISP, OpenCTI) for cross-organization correlation.', type:'share' });

  // ── Summary stats ─────────────────────────────────────────────
  return {
    filename: filename || 'uploaded.log',
    format,
    totalLines: lines.length,
    overallSeverity,
    indicators,
    iocs: {
      ips:     topIPs,
      domains: topDomains,
      urls:    topURLs,
      hashes:  topHashes,
      emails:  [...new Set(iocMap.emails)].slice(0,10),
      cves:    [...new Set(iocMap.cves)].slice(0,10),
      paths:   [...new Set(iocMap.paths)].slice(0,10),
      userAgents: [...new Set(iocMap.userAgents)].slice(0,5),
    },
    correlations: correlations.slice(0,10),
    attackFlow,
    timeline,
    decisions,
    statusCounts,
    totalIOCCount: topIPs.length + topDomains.length + topURLs.length + topHashes.length,
  };
}


// ── OSINT: MalwareBazaar — search by hash, tag, signature ─────────────────
async function handleMalwareBazaar(body) {
  const { query, queryType } = body; // queryType: 'hash'|'tag'|'signature'|'recent'
  try {
    let postBody;
    if (queryType === 'hash') {
      postBody = { query:'get_info', hash: query };
    } else if (queryType === 'tag') {
      postBody = { query:'get_taginfo', tag: query, limit:50 };
    } else if (queryType === 'signature') {
      postBody = { query:'get_siginfo', signature: query, limit:50 };
    } else {
      postBody = { query:'get_recent', selector:'time' };
    }

    // MalwareBazaar API requires application/x-www-form-urlencoded, NOT JSON
    const formStr = Object.entries(postBody)
      .map(([k,v]) => encodeURIComponent(k)+'='+encodeURIComponent(String(v)))
      .join('&');
    const r = await new Promise((resolve, reject) => {
      const opts = {
        hostname: 'mb-api.abuse.ch', port: 443, path: '/api/v1/',
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Content-Length': Buffer.byteLength(formStr),
          'User-Agent': 'ThreatSphere-SOC/1.0',
          'Accept': 'application/json',
        },
      };
      const req = https.request(opts, res => {
        let d = ''; res.on('data', c => d += c);
        res.on('end', () => {
          try { resolve({ status: res.statusCode, data: JSON.parse(d) }); }
          catch { resolve({ status: res.statusCode, data: d }); }
        });
      });
      req.on('error', reject);
      req.setTimeout(25000, () => { req.destroy(); reject(new Error('MalwareBazaar timeout')); });
      req.write(formStr);
      req.end();
    });

    if (r.status !== 200) throw new Error(`MalwareBazaar ${r.status}`);
    if (r.data?.query_status === 'no_results' || r.data?.query_status === 'hash_not_found') {
      return { found:false, samples:[], message:'No results found for this query.' };
    }

    // Single hash lookup returns data as object, multi returns array
    const raw = r.data?.data;
    const samples = Array.isArray(raw) ? raw : (raw ? [raw] : []);

    return {
      found: samples.length > 0,
      queryStatus: r.data?.query_status || 'ok',
      samples: samples.slice(0,50).map(s => ({
        sha256:   s.sha256_hash  || '—',
        sha1:     s.sha1_hash    || '—',
        md5:      s.md5_hash     || '—',
        filename: s.file_name    || '—',
        fileType: s.file_type    || '—',
        mimeType: s.file_type_mime || '—',
        fileSize: s.file_size    ? (s.file_size > 1048576 ? (s.file_size/1048576).toFixed(2)+'MB' : Math.round(s.file_size/1024)+'KB') : '—',
        signature: s.signature   || '—',
        reporter:  s.reporter    || '—',
        country:   s.origin_country || '—',
        tags:      s.tags        || [],
        deliveryMethod: s.delivery_method || '—',
        firstSeen: s.first_seen  || '—',
        lastSeen:  s.last_seen   || '—',
        downloadable: !!s.sha256_hash,
        vtLink:    s.sha256_hash ? `https://www.virustotal.com/gui/file/${s.sha256_hash}` : null,
        mbLink:    s.sha256_hash ? `https://bazaar.abuse.ch/sample/${s.sha256_hash}/` : null,
      })),
    };
  } catch(e) {
    // Network unavailable — return realistic demo samples
    console.warn('[malwarebazaar]', e.message, '— serving demo data');
    function dsh(str,salt,mn,mx){let h=0,s2=str+salt;for(let i=0;i<s2.length;i++)h=(Math.imul(31,h)+s2.charCodeAt(i))|0;return Math.floor(((Math.abs(h)%100000)/100000)*(mx-mn+1))+mn;}
    const today = new Date().toISOString().slice(0,10);
    const sigs = ['Emotet','AgentTesla','FormBook','AsyncRAT','RedLine','QakBot','NjRAT','BlackCat','IcedID','Remcos','LockBit','CobaltStrike'];
    const fts  = ['exe','dll','doc','xls','pdf','zip','ps1','jar','iso','vbs'];
    const reps = ['abuse_ch','spamhaus','malpedia','cert_ee','unknown'];
    const tags_pool = [['stealer','exe'],['rat','doc'],['ransomware','zip'],['dropper','dll'],['loader','iso']];
    const seed_base = (query||today) + (queryType||'recent');
    const count = 30;
    const samples = Array.from({length:count},(_,i)=>{
      const seed = seed_base+i;
      const len = 64;
      let hv=''; for(let j=0;j<len;j++) hv+=dsh(seed,'h'+j,0,15).toString(16);
      let md5=''; for(let j=0;j<32;j++) md5+=dsh(seed,'m'+j,0,15).toString(16);
      const sig = sigs[dsh(seed,'s',0,11)];
      const ft  = fts[dsh(seed,'f',0,9)];
      const sz  = dsh(seed,'sz',8,4096);
      const rep = reps[dsh(seed,'r',0,4)];
      const tagSet = tags_pool[dsh(seed,'t',0,4)];
      const daysAgo = dsh(seed,'d',0,14);
      return {
        sha256: hv, md5, sha1: md5.slice(0,40),
        signature: sig, filename: sig.toLowerCase()+'.'+ft,
        fileType: ft.toUpperCase(), mimeType:'application/octet-stream',
        fileSize: sz > 1024 ? (sz/1024).toFixed(1)+'MB' : sz+'KB',
        reporter: rep, country: ['RU','CN','NL','US','DE','UA'][dsh(seed,'c',0,5)],
        tags: tagSet, deliveryMethod: ['email','web','smb'][dsh(seed,'dm',0,2)],
        firstSeen: new Date(Date.now()-daysAgo*86400000).toISOString().slice(0,10),
        lastSeen: today,
        vtLink: 'https://www.virustotal.com/gui/file/'+hv,
        mbLink: 'https://bazaar.abuse.ch/sample/'+hv+'/',
        downloadable: true,
      };
    });
    return { found:true, queryStatus:'demo', _demo:true, samples };
  }
}

// ── Static file server ─────────────────────────────────────────────
const MIME={'.html':'text/html','.css':'text/css','.js':'application/javascript','.json':'application/json','.png':'image/png','.svg':'image/svg+xml','.ico':'image/x-icon'};
function serveStatic(req,res){
  const pathname=urlMod.parse(req.url).pathname;
  let fp=path.join(PUBLIC,pathname==='/'?'index.html':pathname);
  if(!fp.startsWith(PUBLIC)){res.writeHead(403);res.end();return;}
  if(!path.extname(fp)){fp=path.join(PUBLIC,pathname.startsWith('/app')?'app.html':'index.html');}
  fs.readFile(fp,(err,data)=>{
    if(err){
      fs.readFile(path.join(PUBLIC,'index.html'),(e2,d2)=>{
        if(e2){res.writeHead(404);res.end('Not Found');return;}
        security.setSecurityHeaders(res);res.writeHead(200,{'Content-Type':'text/html'});res.end(d2);
      });return;
    }
    security.setSecurityHeaders(res);
    res.writeHead(200,{'Content-Type':MIME[path.extname(fp)]||'text/plain'});
    res.end(data);
  });
}

// ── Router ─────────────────────────────────────────────────────────
const OSINT_MAP={
  '/api/virustotal' : handleVT,
  '/api/abuseipdb'  : handleAbuse,
  '/api/shodan'     : handleShodan,
  '/api/hybrid'     : handleHybrid,
  '/api/urlscan'    : handleURLScan,
  '/api/whois'      : handleWhois,
};

const server=http.createServer(async(req,res)=>{
  if(req.method==='OPTIONS'){res.writeHead(204,{'Access-Control-Allow-Origin':'*','Access-Control-Allow-Methods':'POST,GET,DELETE,OPTIONS','Access-Control-Allow-Headers':'Content-Type'});res.end();return;}
  const pathname=urlMod.parse(req.url).pathname;
  const method=req.method;
  try{
    // Auth
    if(pathname==='/api/auth/register'&&method==='POST'){await handleRegister(req,res);return;}
    if(pathname==='/api/auth/login'   &&method==='POST'){await handleLogin(req,res);return;}
    if(pathname==='/api/auth/logout'  &&method==='POST'){handleLogout(req,res);return;}
    if(pathname==='/api/auth/me'      &&method==='GET') {handleMe(req,res);return;}
    if(pathname==='/api/auth/roles'   &&method==='GET') {sendJSON(res,200,db.VALID_ROLES);return;}
    // Investigations
    if(pathname==='/api/investigations'&&method==='GET') {handleListInvs(req,res);return;}
    if(pathname==='/api/investigations'&&method==='POST'){await handleSaveInv(req,res);return;}
    const im=pathname.match(/^\/api\/investigations\/([a-f0-9]{32})$/);
    if(im){if(method==='GET'){handleGetInv(req,res,im[1]);return;}if(method==='DELETE'){handleDelInv(req,res,im[1]);return;}}
    const cm=pathname.match(/^\/api\/investigations\/([a-f0-9]{32})\/comments$/);
    if(cm&&method==='POST'){await handleAddComment(req,res,cm[1]);return;}
    const dm=pathname.match(/^\/api\/investigations\/([a-f0-9]{32})\/comments\/([a-f0-9]{16})$/);
    if(dm&&method==='DELETE'){handleDelComment(req,res,dm[1],dm[2]);return;}
    // OSINT (require auth)
    if(OSINT_MAP[pathname]&&method==='POST'){
      const auth=requireAuth(req,res);if(!auth)return;
      const rl=security.rateLimit(auth.userId,'osint',30,60000);
      if(!rl.allowed){sendErr(res,429,`Rate limit. Retry in ${rl.retryAfter}s.`);return;}
      const body=await readBody(req);
      if(body.ioc&&!security.validateIOC(body.ioc)){sendErr(res,400,'Invalid IOC');return;}
      try{sendJSON(res,200,await OSINT_MAP[pathname](body));}
      catch(e){console.error(`[${pathname}]`,e.message);sendJSON(res,500,{error:e.message,_demo:true});}
      return;
    }
    // MalwareBazaar dedicated search (require auth)
    if(pathname==='/api/malwarebazaar'&&method==='POST'){
      const auth=requireAuth(req,res);if(!auth)return;
      const rl=security.rateLimit(auth.userId,'mb',10,60000);
      if(!rl.allowed){sendErr(res,429,'Rate limit.');return;}
      const body=await readBody(req);
      try{sendJSON(res,200,await handleMalwareBazaar(body));}
      catch(e){console.error('[/api/malwarebazaar]',e.message);sendErr(res,500,e.message);}
      return;
    }
    // Threat feeds (require auth)
    if(pathname==='/api/feeds'&&method==='POST'){
      const auth=requireAuth(req,res);if(!auth)return;
      const rl=security.rateLimit(auth.userId,'feeds',5,60000);
      if(!rl.allowed){sendErr(res,429,'Rate limit.');return;}
      const body=await readBody(req);
      try{sendJSON(res,200,await handleFeeds(body));}
      catch(e){console.error('[/api/feeds]',e.message);sendErr(res,500,e.message);}
      return;
    }
    // Sandbox (require auth)
    if(pathname==='/api/sandbox'&&method==='POST'){
      const auth=requireAuth(req,res);if(!auth)return;
      const rl=security.rateLimit(auth.userId,'sandbox',10,60000);
      if(!rl.allowed){sendErr(res,429,'Rate limit.');return;}
      const body=await readBody(req,5000000);
      try{sendJSON(res,200,await handleSandbox(body));}
      catch(e){console.error('[/api/sandbox]',e.message);sendErr(res,500,e.message);}
      return;
    }
    // Relationship graph (require auth)
    if(pathname==='/api/graph'&&method==='POST'){
      const auth=requireAuth(req,res);if(!auth)return;
      const rl=security.rateLimit(auth.userId,'graph',10,60000);
      if(!rl.allowed){sendErr(res,429,'Rate limit.');return;}
      const body=await readBody(req);
      if(body.ioc&&!security.validateIOC(body.ioc)){sendErr(res,400,'Invalid IOC');return;}
      try{sendJSON(res,200,await handleGraph(body));}
      catch(e){console.error('[/api/graph]',e.message);sendErr(res,500,e.message);}
      return;
    }
    // Log analyzer (require auth)
    if(pathname==='/api/logs'&&method==='POST'){
      const auth=requireAuth(req,res);if(!auth)return;
      const rl=security.rateLimit(auth.userId,'logs',10,60000);
      if(!rl.allowed){sendErr(res,429,'Rate limit.');return;}
      const body=await readBody(req,2100000);
      try{sendJSON(res,200,await handleLogAnalyze(body));}
      catch(e){console.error('[/api/logs]',e.message);sendErr(res,500,e.message);}
      return;
    }
    // AI (require auth)
    if(pathname==='/api/ai'&&method==='POST'){
      const auth=requireAuth(req,res);if(!auth)return;
      const rl=security.rateLimit(auth.userId,'ai',10,60000);
      if(!rl.allowed){sendErr(res,429,`AI rate limit. Retry in ${rl.retryAfter}s.`);return;}
      const body=await readBody(req,100000);
      try{sendJSON(res,200,await handleAI(body));}
      catch(e){console.error('[/api/ai]',e.message);sendErr(res,500,e.message);}
      return;
    }
    serveStatic(req,res);
  }catch(e){console.error('[Server]',e.message);sendErr(res,500,'Internal server error');}
});

setInterval(()=>db.cleanExpiredSessions(),3600000);

server.listen(PORT,()=>{
  const k=x=>x?'✓ SET   ':'✗ NOT SET';
  const ai=KEYS.groq?'✓ Groq (llama-3.3-70b)':KEYS.gemini?'✓ Gemini (gemini-1.5-flash)':'✗ No AI key — add GROQ_KEY';
  console.log('');
  console.log('╔══════════════════════════════════════════════════════════╗');
  console.log('║  ThreatIntel Platform v5 — http://localhost:'+PORT+'           ║');
  console.log('╠══════════════════════════════════════════════════════════╣');
  console.log('║  VirusTotal     : '+k(KEYS.virustotal).padEnd(40)+'║');
  console.log('║  AbuseIPDB      : '+k(KEYS.abuseipdb).padEnd(40) +'║');
  console.log('║  Shodan         : '+k(KEYS.shodan).padEnd(40)     +'║');
  console.log('║  Hybrid Analysis: '+k(KEYS.hybrid).padEnd(40)    +'║');
  console.log('║  URLScan.io     : '+k(KEYS.urlscan).padEnd(40)   +'║');
  console.log('╠══════════════════════════════════════════════════════════╣');
  console.log('║  AI  : '+ai.padEnd(50)+'║');
  console.log('╠══════════════════════════════════════════════════════════╣');
  console.log('║  New: Threat Feed, Sandbox, Graph pivot                  ║');
  console.log('╚══════════════════════════════════════════════════════════╝');
  console.log('');
});
