/* ─────────────────────────────────────────────────────────────
   Reachable — app.js
   All client-side logic for the Reachable UI.

   Sections in order:
     1. DNS layer (resolver config, hedged queries, retry/fallback)
     2. Lookup helpers (normalization, IPv6 reverse, DKIM CNAME)
     3. Blacklist queries (IP_LISTS, DOM_LISTS, response-code parsing)
     4. UI helpers (sevMeta, makeCard, stream log, tally cells)
     5. runAudit + auditDomain + auditIP
     6. Header Analyzer (analyzeHeaders)
     7. DNS Simulator (runSimulator)
     8. Tab switching and global keyboard handlers

   Linked from index.html via <script src="app.js" defer>.
   ─────────────────────────────────────────────────────────────*/

/* ─────────────────────────────────────────────────────────────
   DNS layer — Worker proxy with direct-DoH fallback
   ─────────────────────────────────────────────────────────────
   Primary: our Cloudflare Worker (api.reachable.info) which proxies
   queries server-side. This bypasses corporate TLS-inspection
   proxies that block DoH endpoints like cloudflare-dns.com.

   Fallback: direct DoH to Cloudflare/Google/NextDNS. Useful for
   local dev and if the Worker is temporarily down. The Worker and
   direct DoH both return Google's JSON DoH schema, so this is a
   transparent drop-in. */
const DNS_TIMEOUT=6000;
const DNS_RETRIES=2;
const DNS_RETRY_DELAY=400;

// CHANGE THIS to your deployed Worker URL once you've run `wrangler deploy`
// e.g. 'https://api.reachable.info' or 'https://reachable-dns.<your-account>.workers.dev'
const PROXY_URL='https://reachable-dns.icda-you.workers.dev';

const RESOLVERS=[
  {name:'Proxy',     url:PROXY_URL,                              accept:'application/dns-json', priority:1},
  {name:'Cloudflare',url:'https://cloudflare-dns.com/dns-query', accept:'application/dns-json', priority:0},
  {name:'Google',    url:'https://dns.google/resolve',           accept:'application/dns-json', priority:0},
  {name:'NextDNS',   url:'https://dns.nextdns.io',               accept:'application/dns-json', priority:0}
];
const resolverHealth={Proxy:2,Cloudflare:1,Google:1,NextDNS:1};
let adBlockerSuspected=false;
const KNOW_HOW={spf:`SPF lists which servers are allowed to send email for your domain. Receiving servers check it on every message. Missing SPF means anyone can impersonate you. More than 10 DNS lookups causes a permerror — treated as a hard fail.`,dkim:`DKIM signs every outbound email with a cryptographic key. The receiving server fetches your public key from DNS and verifies it wasn't tampered with. Without DKIM there's no proof an email genuinely came from you.`,dmarc:`DMARC tells receiving servers what to do when SPF or DKIM fails — nothing, quarantine, or reject. It also sends you aggregate reports so you can see who's sending from your domain. Without DMARC, spoofing goes unchecked.`,mx:`MX records tell other mail servers where to deliver email sent to your domain. Without them, replies bounce and your domain looks misconfigured.`,rdns:`Reverse DNS (PTR) maps your sending IP to a hostname. Forward-confirmed rDNS means that hostname also resolves back to the same IP. Most receiving servers check this — a missing PTR is a classic spam signal.`,blacklist:`Blocklists are real-time databases of IPs and domains flagged for spam. If listed, receiving servers may reject or bulk-folder your mail. Always fix the root cause before requesting removal.`,bimi:`BIMI lets your brand logo appear in supported inboxes like Gmail, Yahoo and Apple Mail. It needs a strong DMARC policy and a DNS record pointing to your SVG logo.`,tls:`MTA-STS enforces TLS encryption for inbound email, preventing downgrade attacks. Without it, connections can fall back to unencrypted.`};
const FIX_DATA={spf_missing:{steps:`Add a TXT record on your domain's DNS that tells the world which servers are allowed to send on your behalf.`,record:`v=spf1 include:YOUR_ESP ~all`,providers:{'Google Workspace':{record:`v=spf1 include:_spf.google.com ~all`,note:`Replace with your actual record if you send from other services too.`},'Microsoft 365':{record:`v=spf1 include:spf.protection.outlook.com ~all`,note:`Add other includes if you send from additional platforms.`},'SendGrid':{record:`v=spf1 include:sendgrid.net ~all`,note:`SendGrid recommends using DKIM as the primary authentication method.`},'Mailgun':{record:`v=spf1 include:mailgun.org ~all`,note:``},'AWS SES':{record:`v=spf1 include:amazonses.com ~all`,note:`Only needed if not using a custom MAIL FROM domain.`},'Postmark':{record:`v=spf1 include:spf.mtasv.net ~all`,note:`Postmark also provides DKIM — use both.`}}},dmarc_missing:{steps:`Add a TXT record at _dmarc.yourdomain.com. Start with p=none to monitor, then move to quarantine or reject once confident.`,record:`v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com; fo=1`,providers:{'Starter (monitoring)':{record:`v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com`,note:`p=none means monitoring only. No enforcement yet.`},'Intermediate':{record:`v=DMARC1; p=quarantine; pct=25; rua=mailto:dmarc@yourdomain.com`,note:`25% of failing mail goes to spam. Increase pct gradually.`},'Strict':{record:`v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com; ruf=mailto:dmarc@yourdomain.com; fo=1`,note:`All failing mail is rejected. Only use when fully confident.`}}},dkim_missing:{steps:`DKIM requires a private/public key pair. Your ESP generates this. Add the public key as a TXT record at selector._domainkey.yourdomain.com.`,record:`Contact your ESP to generate a DKIM key pair.`,providers:{'Google Workspace':{record:`Admin Console > Apps > Google Workspace > Gmail > Authenticate email`,note:`Google generates the key and gives you the exact record to publish.`},'Microsoft 365':{record:`Microsoft 365 Defender > Email and collaboration > Policies > DKIM`,note:`M365 uses CNAMEs, not TXT records.`},'SendGrid':{record:`Settings > Sender Authentication > Domain Authentication`,note:`SendGrid generates two CNAME records for your DNS.`},'Mailgun':{record:`Sending > Domains > your domain > DNS records`,note:`Mailgun gives you the exact TXT record.`}}}};

function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;')}
function normalizeDomain(r){r=(r||'').trim();if(!r)return '';if(r.includes('://')){try{r=new URL(r).hostname;}catch{r=r.replace(/^.*:\/\//,'').split('/')[0];}}r=r.split(':')[0].replace(/\/.*$/,'').replace(/\.$/,'').toLowerCase();try{r=new URL('http://'+r).hostname;}catch{}return r;}
function normalizeIP(r){r=(r||'').trim();if(r.startsWith('[')&&r.endsWith(']'))r=r.slice(1,-1);return r;}
function isIPv4(ip){return /^(\d{1,3}\.){3}\d{1,3}$/.test(ip);}
function isIPv6(ip){return ip.includes(':');}
function reverseIPv4(ip){return ip.split('.').reverse().join('.');}
function reverseIPv6(ip){
  // Properly expand :: shorthand to 8 groups before reversing
  let groups;
  if(ip.includes('::')){
    const [head,tail]=ip.split('::');
    const headGroups=head?head.split(':'):[];
    const tailGroups=tail?tail.split(':'):[];
    const missing=8-headGroups.length-tailGroups.length;
    groups=[...headGroups,...Array(missing).fill('0'),...tailGroups];
  }else{
    groups=ip.split(':');
  }
  if(groups.length!==8)return ip.split(':').map(g=>g.padStart(4,'0')).join('').split('').reverse().join('.');
  return groups.map(g=>g.padStart(4,'0')).join('').split('').reverse().join('.');
}

// Single resolver query — always cleans up its timer
async function querySingleResolver(resolver,name,type,timeoutMs){
  const ctrl=new AbortController();
  const tid=setTimeout(()=>ctrl.abort(),timeoutMs);
  try{
    const r=await fetch(`${resolver.url}?name=${encodeURIComponent(name)}&type=${type}`,{
      method:'GET',mode:'cors',credentials:'omit',
      headers:{'Accept':resolver.accept},signal:ctrl.signal
    });
    if(!r.ok)return{status:'error',errorType:`http_${r.status}`,answer:[],resolver:resolver.name};
    const d=await r.json();
    if(d.Status===2)return{status:'servfail',errorType:'SERVFAIL',answer:[],resolver:resolver.name};
    if(d.Status===3)return{status:'nxdomain',errorType:'NXDOMAIN',answer:[],resolver:resolver.name};
    return{status:'ok',errorType:null,answer:d.Answer||[],resolver:resolver.name};
  }catch(e){
    if(e.name==='AbortError')return{status:'timeout',errorType:'timeout',answer:[],resolver:resolver.name};
    return{status:'error',errorType:e.message||'network_error',answer:[],resolver:resolver.name};
  }finally{
    clearTimeout(tid);
  }
}

// Order resolvers — proxy always tried first if healthy, then by health score
function orderedResolvers(){
  return RESOLVERS.slice().sort((a,b)=>{
    const ph=(resolverHealth[b.name]||0)+(b.priority||0)*10;
    const ah=(resolverHealth[a.name]||0)+(a.priority||0)*10;
    return ph-ah;
  });
}

// Race resolvers; first non-failure wins
async function hedgedQuery(resolvers,name,type,timeoutMs){
  if(resolvers.length===1)return querySingleResolver(resolvers[0],name,type,timeoutMs);
  return new Promise(resolve=>{
    let settled=false;let pending=resolvers.length;let lastResult=null;
    resolvers.forEach(r=>{
      querySingleResolver(r,name,type,timeoutMs).then(res=>{
        pending--;
        if(!settled&&(res.status==='ok'||res.status==='nxdomain')){
          settled=true;
          resolverHealth[res.resolver]=Math.min((resolverHealth[res.resolver]||0)+1,5);
          resolve(res);return;
        }
        if(res.resolver)resolverHealth[res.resolver]=Math.max((resolverHealth[res.resolver]||0)-1,-3);
        lastResult=res;
        if(pending===0&&!settled){settled=true;resolve(lastResult);}
      });
    });
  });
}

// Detect total network-layer failure (corporate proxy, TLS interception, ad-blocker)
function isNetworkLayerFail(r){
  if(!r)return false;
  if(r.status==='timeout')return true;
  if(r.errorType&&(r.errorType==='network_error'||r.errorType.includes('Failed to fetch')||r.errorType.includes('NetworkError')))return true;
  return false;
}

// Track whether the proxy ever succeeded this run — if it did, network isn't blocked
let proxyEverSucceeded=false;
let networkFailCount=0;
let totalLookupCount=0;

// Main entry — proxy first, then hedge across direct DoH
async function dnsLookup(name,type){
  totalLookupCount++;
  const ordered=orderedResolvers();
  const proxy=ordered.find(r=>r.name==='Proxy');
  const directs=ordered.filter(r=>r.name!=='Proxy');

  // 1. Try the proxy alone first (it's our reliable path through corporate networks)
  if(proxy&&(resolverHealth.Proxy||0)>-2){
    const proxyResult=await querySingleResolver(proxy,name,type,DNS_TIMEOUT);
    if(proxyResult.status==='ok'||proxyResult.status==='nxdomain'){
      resolverHealth.Proxy=Math.min((resolverHealth.Proxy||0)+1,5);
      proxyEverSucceeded=true;
      return proxyResult;
    }
    // 400 Bad Request from proxy = client error (e.g. bad domain name) — don't penalise
    if(proxyResult.errorType!=='http_400'){
      resolverHealth.Proxy=Math.max((resolverHealth.Proxy||0)-1,-3);
    }
  }

  // 2. Fall back to hedging direct DoH (top 2 in parallel)
  let lastResult=null;
  for(let attempt=0;attempt<DNS_RETRIES;attempt++){
    const result=await hedgedQuery(directs.slice(0,2),name,type,DNS_TIMEOUT);
    if(result.status==='ok'||result.status==='nxdomain')return result;
    lastResult=result;
    if(attempt===DNS_RETRIES-1&&directs.length>2){
      const fallback=await querySingleResolver(directs[2],name,type,DNS_TIMEOUT);
      if(fallback.status==='ok'||fallback.status==='nxdomain')return fallback;
      lastResult=fallback;
    }
    if(attempt<DNS_RETRIES-1)await new Promise(r=>setTimeout(r,DNS_RETRY_DELAY+Math.random()*200));
  }

  // 3. Track network-layer failures (used to decide whether to show the blocked banner)
  if(isNetworkLayerFail(lastResult))networkFailCount++;

  return lastResult||{status:'error',errorType:'all_resolvers_failed',answer:[]};
}
function normTXT(d){return d.replace(/"\s+"/g,'').replace(/^"|"$/g,'').trim();}
function lookupFailed(r){return r.status==='timeout'||r.status==='error'||r.status==='servfail';}
async function countSPFLookups(domain,depth=0,visited=new Set()){
  if(depth>10||visited.has(domain))return 0;
  // Skip SPF macro-containing names (RFC 7208 §7) — they contain {d}, {i}, %{...}, etc.
  // and can't be resolved as literal DNS names.
  if(/[{}%]/.test(domain))return 0;
  visited.add(domain);
  const res=await dnsLookup(domain,'TXT');
  if(res.status!=='ok')return 0;
  const spf=res.answer.map(a=>normTXT(a.data)).find(d=>d.startsWith('v=spf1'));
  if(!spf)return 0;
  let count=0;
  for(const t of spf.split(/\s+/)){
    if(/^[+-~?]?(include|a|mx|ptr|exists):/.test(t))count++;
    if(t.startsWith('include:')){
      const target=t.split(':')[1];
      if(target&&!/[{}%]/.test(target))count+=await countSPFLookups(target,depth+1,visited);
    }
    if(t.startsWith('redirect=')){
      count++;
      const target=t.split('=')[1];
      if(target&&!/[{}%]/.test(target))count+=await countSPFLookups(target,depth+1,visited);
    }
  }
  return count;
}
async function resolveDKIM(sel,domain,depth=0,visited=new Set()){
  if(depth>5)return{status:'error',errorType:'CNAME chain too deep',answer:[]};
  const host=depth===0?`${sel}._domainkey.${domain}`:domain;
  if(visited.has(host))return{status:'error',errorType:'CNAME loop',answer:[]};
  visited.add(host);
  const t=await dnsLookup(host,'TXT');
  if(t.status==='ok'&&t.answer.length){
    // If we got a CNAME mixed with TXT, follow CNAME chain
    const txts=t.answer.filter(a=>a.type===16);
    if(txts.length)return{...t,answer:txts};
  }
  const c=await dnsLookup(host,'CNAME');
  if(c.status==='ok'&&c.answer.length){
    const target=c.answer[0].data.replace(/\.$/,'');
    return resolveDKIM(null,target,depth+1,visited);
  }
  return t;
}
async function forwardConfirm(hostname,ip){const res=await dnsLookup(hostname.replace(/\.$/,''),isIPv6(ip)?'AAAA':'A');return res.status==='ok'&&res.answer.some(a=>a.data===ip);}
// Public DNSBLs queryable via DoH. MXToolbox isn't a real DNSBL (it's a tool).
// SORBS shut down in June 2024 — removed. URIBL/SURBL public-tier rate-limits
// browser-origin queries heavily — we keep them but expect occasional timeouts.
// `validCodes` lists the actual response codes that mean "listed" — anything
// else (especially 127.0.0.1 = refused, 127.255.255.x = rate-limited) is NOT
// a real listing and must be treated as clean to avoid false positives.
const IP_LISTS=[
  {name:'Spamhaus ZEN',host:'zen.spamhaus.org',validCodes:['127.0.0.2','127.0.0.3','127.0.0.4','127.0.0.9','127.0.0.10','127.0.0.11']},
  {name:'Barracuda',host:'b.barracudacentral.org',validCodes:['127.0.0.2']},
  {name:'SpamCop',host:'bl.spamcop.net',validCodes:['127.0.0.2']},
  {name:'Spamhaus PBL',host:'pbl.spamhaus.org',validCodes:['127.0.0.10','127.0.0.11']},
  {name:'UCEPROTECT-1',host:'dnsbl-1.uceprotect.net',validCodes:['127.0.0.2']}
];
const DOM_LISTS=[
  {name:'URIBL',host:'multi.uribl.com',validCodes:['127.0.0.2','127.0.0.4','127.0.0.8']},
  {name:'SURBL',host:'multi.surbl.org',validCodes:['127.0.0.2','127.0.0.4','127.0.0.8','127.0.0.16','127.0.0.32','127.0.0.64']},
  {name:'DBL Spamhaus',host:'dbl.spamhaus.org',validCodes:['127.0.1.2','127.0.1.4','127.0.1.5','127.0.1.6']}
];

// Codes that explicitly mean "your query was refused / you're rate-limited"
// — never a real listing. We log these as 'refused' (treated as clean).
function isRefusedCode(code){
  if(!code)return false;
  if(code==='127.0.0.1')return true;                  // generic refusal on many DNSBLs
  if(code.startsWith('127.255.'))return true;         // URIBL/SURBL rate-limit responses
  return false;
}
async function checkIPBlacklists(ip){
  const rev=isIPv6(ip)?reverseIPv6(ip):reverseIPv4(ip);
  return Promise.all(IP_LISTS.map(async l=>{
    const r=await dnsLookup(`${rev}.${l.host}`,'A');
    if(lookupFailed(r))return{name:l.name,result:'timeout'};
    if(r.status==='nxdomain'||!r.answer.length)return{name:l.name,result:'clean'};
    const codes=r.answer.map(a=>a.data);
    // Refused/rate-limited codes are NOT real listings
    if(codes.every(isRefusedCode))return{name:l.name,result:'refused',code:codes[0]};
    // Only flag as listed if at least one response matches a known valid code
    const listed=codes.some(c=>l.validCodes.includes(c));
    return{name:l.name,result:listed?'listed':'clean',code:codes[0]};
  }));
}
async function checkDomainBlacklists(domain){
  return Promise.all(DOM_LISTS.map(async l=>{
    const r=await dnsLookup(`${domain}.${l.host}`,'A');
    if(lookupFailed(r))return{name:l.name,result:'timeout'};
    if(r.status==='nxdomain'||!r.answer.length)return{name:l.name,result:'clean'};
    const codes=r.answer.map(a=>a.data);
    if(codes.every(isRefusedCode))return{name:l.name,result:'refused',code:codes[0]};
    const listed=codes.some(c=>l.validCodes.includes(c));
    return{name:l.name,result:listed?'listed':'clean',code:codes[0]};
  }));
}
function orgDomain(d){const p=d.split('.');return p.length<=2?d:p.slice(-2).join('.');}

function streamLog(msg,state='running'){
  const log=document.getElementById('streamLog');
  const entry=document.createElement('div');entry.className='stream-entry';
  const dot=document.createElement('div');dot.className=`stream-dot dot-${state}`;
  const txt=document.createElement('span');txt.textContent=msg;
  entry.appendChild(dot);entry.appendChild(txt);log.appendChild(entry);log.scrollTop=log.scrollHeight;
  return{resolve:(s)=>{dot.className=`stream-dot dot-${s}`;dot.style.animation='none';}};
}

function sevMeta(s){return({critical:{cls:'critical',ci:'ci-critical',cb:'cb-critical',icon:'✕',label:'Critical'},important:{cls:'important',ci:'ci-important',cb:'cb-important',icon:'!',label:'Important'},pass:{cls:'pass',ci:'ci-pass',cb:'cb-pass',icon:'✓',label:'Pass'},info:{cls:'info',ci:'ci-info',cb:'cb-info',icon:'i',label:'Info'},timeout:{cls:'timeout',ci:'ci-timeout',cb:'cb-timeout',icon:'~',label:'Timeout'}}[s])||{cls:'info',ci:'ci-info',cb:'cb-info',icon:'i',label:'Info'};}

function makeCard(name,sev,value,desc,khKey,fixKey){
  const m=sevMeta(sev);
  const card=document.createElement('div');card.className=`check-card card-${m.cls}`;card._severity=sev;
  const main=document.createElement('div');main.className='card-main';
  const icon=document.createElement('div');icon.className=`card-icon ${m.ci}`;icon.textContent=m.icon;
  const body=document.createElement('div');body.className='card-body';
  const top=document.createElement('div');top.className='card-top';
  const nm=document.createElement('span');nm.className='card-name';nm.textContent=name;
  const badge=document.createElement('span');badge.className=`card-badge ${m.cb}`;badge.textContent=m.label;
  top.appendChild(nm);top.appendChild(badge);
  const d=document.createElement('div');d.className='card-desc';d.textContent=desc||'';
  body.appendChild(top);body.appendChild(d);
  if(value){const v=document.createElement('div');v.className='card-value';v.textContent=value;body.appendChild(v);}
  if(khKey||fixKey){
    const actions=document.createElement('div');actions.className='card-actions';
    const eb=document.createElement('button');eb.className='card-btn';eb.textContent='Details';actions.appendChild(eb);body.appendChild(actions);
    const expand=document.createElement('div');expand.className='card-expand';
    const tabs=document.createElement('div');tabs.className='expand-tabs';
    const panes=document.createElement('div');let first=true;
    const addTab=(label,content)=>{const tb=document.createElement('button');tb.className='expand-tab'+(first?' active':'');tb.textContent=label;const pane=document.createElement('div');pane.className='expand-pane'+(first?' active':'');pane.appendChild(content);tabs.appendChild(tb);panes.appendChild(pane);first=false;tb.addEventListener('click',()=>{tabs.querySelectorAll('.expand-tab').forEach(t=>t.classList.remove('active'));panes.querySelectorAll('.expand-pane').forEach(p=>p.classList.remove('active'));tb.classList.add('active');pane.classList.add('active');});};
    if(khKey){const kh=document.createElement('div');kh.className='knowhow-box';const lbl=document.createElement('div');lbl.className='knowhow-lbl';lbl.textContent='What is this?';const txt=document.createElement('p');txt.textContent=KNOW_HOW[khKey]||'';kh.appendChild(lbl);kh.appendChild(txt);addTab('Explain',kh);}
    if(fixKey&&FIX_DATA[fixKey]){const fd=FIX_DATA[fixKey];const fb=document.createElement('div');fb.className='fix-box';const st=document.createElement('div');st.className='fix-step';st.textContent=fd.steps;fb.appendChild(st);if(fd.record&&!fd.record.startsWith('Contact')&&!fd.record.startsWith('Admin')){const rw=document.createElement('div');rw.className='fix-record';const pre=document.createElement('pre');pre.textContent=fd.record;const cp=document.createElement('button');cp.className='copy-btn';cp.textContent='Copy';cp.onclick=()=>{navigator.clipboard.writeText(fd.record).then(()=>{cp.textContent='Copied!';setTimeout(()=>cp.textContent='Copy',2000);});};rw.appendChild(pre);rw.appendChild(cp);fb.appendChild(rw);}if(fd.providers){const pl=document.createElement('div');pl.className='fix-step';pl.style.marginTop='0.75rem';const s=document.createElement('strong');s.textContent='Provider-specific:';pl.appendChild(s);fb.appendChild(pl);const pills=document.createElement('div');pills.className='provider-pills';const contents=document.createElement('div');Object.entries(fd.providers).forEach(([pn,pd])=>{const pill=document.createElement('button');pill.className='provider-pill';pill.textContent=pn;const pc=document.createElement('div');pc.className='provider-content';const pw=document.createElement('div');pw.className='fix-record';const pp=document.createElement('pre');pp.textContent=pd.record;const pcp=document.createElement('button');pcp.className='copy-btn';pcp.textContent='Copy';pcp.onclick=()=>{navigator.clipboard.writeText(pd.record).then(()=>{pcp.textContent='Copied!';setTimeout(()=>pcp.textContent='Copy',2000);});};pw.appendChild(pp);pw.appendChild(pcp);pc.appendChild(pw);if(pd.note){const n=document.createElement('div');n.style.cssText='font-size:11px;color:var(--text-3);margin-top:5px';n.textContent=pd.note;pc.appendChild(n);}pill.addEventListener('click',()=>{pills.querySelectorAll('.provider-pill').forEach(p=>p.classList.remove('active'));contents.querySelectorAll('.provider-content').forEach(c=>c.classList.remove('active'));if(pill.classList.contains('active')){pill.classList.remove('active');}else{pill.classList.add('active');pc.classList.add('active');}});pills.appendChild(pill);contents.appendChild(pc);});fb.appendChild(pills);fb.appendChild(contents);}addTab('How to fix',fb);}
    expand.appendChild(tabs);expand.appendChild(panes);card.appendChild(expand);
    eb.addEventListener('click',()=>{const o=expand.classList.toggle('open');eb.textContent=o?'Close':'Details';});
  }
  main.appendChild(icon);main.appendChild(body);card.insertBefore(main,card.firstChild);
  return card;
}

const statusGroups=[];let activeFilter=null;
function buildTallyCell(key,num,label,cls){
  const cell=document.createElement('a');cell.className=`tally-cell tc-${cls}`;cell.href='#';
  cell.innerHTML=`<div class="tally-num">${num}</div><div class="tally-lbl">${label}</div><span class="tally-arrow">jump</span>`;
  if(!num)cell.style.opacity='0.3';
  cell.addEventListener('click',e=>{e.preventDefault();const grp=statusGroups.find(g=>g.status===key);if(grp){grp.el.scrollIntoView({behavior:'smooth',block:'start'});grp.el.querySelectorAll('.check-card').forEach(c=>{c.classList.remove('jumped');void c.offsetWidth;c.classList.add('jumped');});}const all=document.querySelectorAll('.tally-cell');if(activeFilter===key){all.forEach(c=>c.classList.remove('dimmed','highlighted'));activeFilter=null;}else{activeFilter=key;all.forEach(c=>{c.classList.toggle('dimmed',c!==cell);c.classList.toggle('highlighted',c===cell);});}});
  return cell;
}
function renderSection(title,cards,container){
  const crit=cards.filter(c=>c._severity==='critical').length;const imp=cards.filter(c=>c._severity==='important').length;const pass=cards.filter(c=>c._severity==='pass').length;const parts=[];if(crit)parts.push(`${crit} critical`);if(imp)parts.push(`${imp} important`);if(pass)parts.push(`${pass} passed`);
  const sec=document.createElement('div');sec.className='result-section';
  const hdr=document.createElement('div');hdr.className='section-hdr';
  const lbl=document.createElement('span');lbl.className='section-lbl';lbl.textContent=title;
  const sum=document.createElement('span');sum.className='section-sum';sum.textContent=parts.join(' · ');
  hdr.appendChild(lbl);hdr.appendChild(sum);
  const list=document.createElement('div');list.className='cards-list';cards.forEach(c=>list.appendChild(c));
  sec.appendChild(hdr);sec.appendChild(list);container.appendChild(sec);
}
function buildReadiness(checks){
  const wrap=document.createElement('div');wrap.className='readiness';
  const t=document.createElement('div');t.className='readiness-title';t.textContent='Readiness Checklist';wrap.appendChild(t);
  const grid=document.createElement('div');grid.className='readiness-grid';
  checks.forEach(c=>{const item=document.createElement('div');item.className='ri';const dot=document.createElement('div');dot.className=`ri-dot ${c.status}`;dot.textContent=c.status==='pass'?'✓':c.status==='fail'?'✕':c.status==='warn'?'!':'?';const lbl=document.createElement('span');lbl.textContent=c.label;item.appendChild(dot);item.appendChild(lbl);grid.appendChild(item);});
  wrap.appendChild(grid);return wrap;
}

let currentRunId=0;
function setLoading(on){
  document.getElementById('runBtn').disabled=on;
  document.getElementById('btnLabel').textContent=on?'Auditing…':'Run audit';
  document.getElementById('spinner').style.display=on?'inline-block':'none';
  document.getElementById('streamWrap').style.display=on?'block':'none';
  if(!on)setTimeout(()=>{document.getElementById('streamWrap').style.display='none';},1000);
}

function resetApp(){
  document.getElementById('auditWrap').classList.remove('at-top');
  document.getElementById('auditResults').innerHTML='';
  document.getElementById('audit-results-outer').style.display='none';
  document.getElementById('errBox').style.display='none';
  document.getElementById('streamLog').innerHTML='';
  document.getElementById('domain').value='';
  document.getElementById('dkimSel').value='';
  document.getElementById('ip').value='';
  document.getElementById('returnPath').value='';
  statusGroups.length=0;activeFilter=null;
  document.querySelectorAll('.panel').forEach(p=>{p.classList.remove('active');p.style.display='none';});
  document.querySelectorAll('.nav-tab').forEach(t=>t.classList.remove('active'));
  document.getElementById('panel-audit').classList.add('active');
  document.getElementById('panel-audit').style.display='flex';
  document.getElementById('tab-audit').classList.add('active');
}

async function runAudit(){
  const runId=++currentRunId;
  // Reset per-run network-health counters
  proxyEverSucceeded=false;networkFailCount=0;totalLookupCount=0;adBlockerSuspected=false;
  document.getElementById('errBox').style.display='none';
  const resultsEl=document.getElementById('auditResults');
  resultsEl.innerHTML='';document.getElementById('audit-results-outer').style.display='none';
  document.getElementById('streamLog').innerHTML='';
  statusGroups.length=0;activeFilter=null;
  const domain=normalizeDomain(document.getElementById('domain').value);
  const ip=normalizeIP(document.getElementById('ip').value);
  const sel=(document.getElementById('dkimSel').value||'').trim();
  const rpDomain=normalizeDomain(document.getElementById('returnPath').value);
  if(!domain&&!ip){const b=document.getElementById('errBox');b.textContent='Please enter at least a domain or IP address.';b.style.display='block';return;}
  if(ip&&!isIPv4(ip)&&!isIPv6(ip)){const b=document.getElementById('errBox');b.textContent=`"${esc(ip)}" doesn't look like a valid IP address.`;b.style.display='block';return;}
  document.getElementById('auditWrap').classList.add('at-top');
  setLoading(true);
  let critCount=0,impCount=0,passCount=0,infoCount=0;
  const criticals=[];const readinessChecks=[];
  function tally(sev,label){if(sev==='critical'){critCount++;if(label)criticals.push(label);}else if(sev==='important')impCount++;else if(sev==='pass')passCount++;else infoCount++;}
  const allSections=[];
  try{const[domSections,ipSection]=await Promise.all([domain?auditDomain(domain,sel,rpDomain,tally,readinessChecks,runId):Promise.resolve([]),ip?auditIP(ip,tally,readinessChecks):Promise.resolve(null)]);allSections.push(...domSections);if(ipSection)allSections.push(ipSection);}
  catch(e){setLoading(false);const b=document.getElementById('errBox');b.textContent='Error: '+e.message;b.style.display='block';return;}
  if(runId!==currentRunId){setLoading(false);return;}
  setLoading(false);
  // Show "network blocked" banner only if:
  //   - the proxy NEVER succeeded this run (so we couldn't bypass corp networks), AND
  //   - more than half of all lookups failed at the network layer
  // This avoids flashing the scary banner when the audit actually succeeded.
  const networkFailRate=totalLookupCount?networkFailCount/totalLookupCount:0;
  if(!proxyEverSucceeded&&networkFailRate>0.5){
    const b=document.getElementById('errBox');
    b.innerHTML='<strong>DNS queries are being blocked on your network.</strong> This usually means a corporate proxy, VPN, or browser extension is blocking DNS-over-HTTPS. Common causes: enterprise TLS inspection (Zscaler, Palo Alto, Netskope), browser extensions (uBlock, AdGuard), or strict network firewalls. Try a personal network, or contact your IT team if this is a work device.';
    b.style.display='block';
  }
  const total=critCount+impCount+passCount;const score=total?Math.round((passCount/total)*100):0;
  const scoreColor=score>=80?'var(--green)':score>=55?'var(--amber)':'var(--red)';
  const scoreLabel=score>=80?'Looking good':score>=55?'Needs attention':'Critical issues';
  const scoreSub=score>=80?'Your email setup is in solid shape.':score>=55?'Some issues could be affecting inbox placement.':'These may be blocking delivery right now.';
  const frag=document.createDocumentFragment();
  const hero=document.createElement('div');hero.className='score-hero';
  const top=document.createElement('div');top.className='score-top';
  const ringWrap=document.createElement('div');ringWrap.className='score-ring-wrap';
  ringWrap.innerHTML=`<svg width="72" height="72" viewBox="0 0 72 72"><circle class="score-ring-bg" cx="36" cy="36" r="30" fill="none" stroke-width="5"/><circle class="score-ring-fill" id="scoreArc" cx="36" cy="36" r="30" fill="none" stroke-width="5"/></svg><div class="score-num" style="color:${scoreColor}">${score}%</div>`;
  const scoreText=document.createElement('div');scoreText.className='score-text';scoreText.innerHTML=`<h2 style="color:${scoreColor}">${esc(scoreLabel)}</h2><p>${esc(scoreSub)}</p>`;
  top.appendChild(ringWrap);top.appendChild(scoreText);hero.appendChild(top);
  const tally4=document.createElement('div');tally4.className='tally-row';
  tally4.appendChild(buildTallyCell('critical',critCount,'Critical','critical'));
  tally4.appendChild(buildTallyCell('important',impCount,'Important','important'));
  tally4.appendChild(buildTallyCell('pass',passCount,'Passed','pass'));
  tally4.appendChild(buildTallyCell('info',infoCount,'Info','info'));
  hero.appendChild(tally4);
  if(readinessChecks.length)hero.appendChild(buildReadiness(readinessChecks));
  frag.appendChild(hero);
  if(criticals.length){const banner=document.createElement('div');banner.className='critical-banner';const h=document.createElement('h3');h.textContent=`${criticals.length} critical issue${criticals.length>1?'s':''} need immediate attention`;const ul=document.createElement('ul');ul.className='critical-list';criticals.forEach(c=>{const li=document.createElement('li');li.textContent=c;ul.appendChild(li);});banner.appendChild(h);banner.appendChild(ul);frag.appendChild(banner);}
  const sw=document.createElement('div');
  const bySev={critical:[],important:[],pass:[],info:[]};
  allSections.forEach(s=>{s.cards.forEach(c=>{const k=c._severity;if(bySev[k])bySev[k].push(c);});renderSection(s.title,s.cards,sw);});
  ['critical','important','pass','info'].forEach(st=>{const cards=bySev[st];if(!cards.length)return;const anchor=document.createElement('div');anchor.id=`group-${st}`;anchor.style.scrollMarginTop='12px';cards[0].parentNode?.insertBefore(anchor,cards[0]);statusGroups.push({status:st,el:anchor});});
  frag.appendChild(sw);
  const note=document.createElement('div');note.className='results-note';note.textContent='Checks run via Reachable\'s proxy with fallback to Cloudflare, Google and NextDNS. Nothing is stored. Also check Google Postmaster Tools and your ESP dashboard for full coverage.';
  frag.appendChild(note);
  resultsEl.appendChild(frag);document.getElementById('audit-results-outer').style.display='block';
  setTimeout(()=>{const arc=document.getElementById('scoreArc');if(arc){const offset=188-Math.round((score/100)*188);arc.style.stroke=scoreColor;arc.style.strokeDashoffset=offset;}},100);
}

async function auditDomain(domain,sel,rpDomain,tally,readiness,runId){
  const sections=[];
  const s1=streamLog(`Checking SPF on ${domain}...`);const s2=streamLog('Checking DMARC policy...');const s3=streamLog(sel?`Verifying DKIM selector "${sel}"...`:'DKIM: no selector provided');const s4=streamLog('Checking MX, BIMI, MTA-STS...');const s5=streamLog('Querying domain blacklists...');
  const[spfRes,dmarcRes,dmarcOrgRes,mxRes,bimiRes,mtaRes,dkimRes,rpSpfRes,domBL]=await Promise.all([dnsLookup(domain,'TXT'),dnsLookup(`_dmarc.${domain}`,'TXT'),dnsLookup(`_dmarc.${orgDomain(domain)}`,'TXT'),dnsLookup(domain,'MX'),dnsLookup(`default._bimi.${domain}`,'TXT'),dnsLookup(`_mta-sts.${domain}`,'TXT'),sel?resolveDKIM(sel,domain):Promise.resolve(null),rpDomain&&rpDomain!==domain?dnsLookup(rpDomain,'TXT'):Promise.resolve(null),checkDomainBlacklists(domain)]);
  const authCards=[];
  if(lookupFailed(spfRes)){s1.resolve('info');authCards.push(makeCard('SPF record','timeout','',`DNS lookup failed (${spfRes.errorType}).`,'spf'));readiness.push({label:'SPF configured',status:'fail'});}
  else{const recs=spfRes.answer.map(a=>normTXT(a.data)).filter(d=>d.startsWith('v=spf1'));if(!recs.length){s1.resolve('fail');tally('critical','No SPF record on '+domain);authCards.push(makeCard('SPF record','critical','No record found',`No SPF TXT record for ${domain}. Any server can send as you right now.`,'spf','spf_missing'));readiness.push({label:'SPF configured',status:'fail'});}else if(recs.length>1){s1.resolve('fail');tally('critical','Multiple SPF records on '+domain);authCards.push(makeCard('SPF record','critical',recs.join(' | '),'Multiple SPF records. Only one is allowed.','spf'));readiness.push({label:'SPF configured',status:'warn'});}else{const spf=recs[0];let sev='pass',desc='SPF record found. ';if(spf.includes('+all')){sev='critical';tally('critical','SPF uses +all');desc+='+all allows any server to send as you. Critical misconfiguration.';}else if(spf.includes('?all')){sev='important';tally('important');desc+='?all does not reject unauthorised senders. Use ~all or -all.';}else if(spf.includes('~all')){tally('pass');desc+='~all (softfail) flags unauthorised senders.';}else if(spf.includes('-all')){tally('pass');desc+='-all rejects unauthorised senders. Strongest setting.';}else{sev='important';tally('important');desc+='No all mechanism. SPF result is undefined for unknown senders.';}s1.resolve(sev==='pass'?'done':sev==='critical'?'fail':'warn');const c=makeCard('SPF record',sev,spf,desc,'spf');authCards.push(c);readiness.push({label:'SPF configured',status:sev==='pass'?'pass':sev==='critical'?'fail':'warn'});countSPFLookups(domain).then(n=>{if(runId!==currentRunId)return;const d=c.querySelector('.card-desc');if(!d)return;if(n>10)d.textContent+=` Also: ${n} DNS lookups — exceeds the limit of 10.`;else if(n>8)d.textContent+=` Approaching the 10-lookup limit (~${n} detected).`;});}}
  const dmTXTs=dmarcRes.status==='ok'?dmarcRes.answer.map(a=>normTXT(a.data)).filter(d=>d.startsWith('v=DMARC1')):[];const orgTXTs=dmarcOrgRes.status==='ok'?dmarcOrgRes.answer.map(a=>normTXT(a.data)).filter(d=>d.startsWith('v=DMARC1')):[];const dmRec=dmTXTs[0]||orgTXTs[0]||null;const usedOrg=!dmTXTs.length&&orgTXTs.length>0;
  if(lookupFailed(dmarcRes)){s2.resolve('info');authCards.push(makeCard('DMARC record','timeout','',`Lookup failed (${dmarcRes.errorType}).`,'dmarc'));readiness.push({label:'DMARC enforced',status:'fail'});}else if(!dmRec){s2.resolve('fail');tally('critical','No DMARC record');authCards.push(makeCard('DMARC record','critical','No record found',`No DMARC record at _dmarc.${domain}. Spoofing is unchecked.`,'dmarc','dmarc_missing'));readiness.push({label:'DMARC enforced',status:'fail'});}else if(dmTXTs.length>1){s2.resolve('fail');tally('critical','Multiple DMARC records');authCards.push(makeCard('DMARC record','critical','Multiple records','Only one DMARC record allowed.','dmarc'));readiness.push({label:'DMARC enforced',status:'warn'});}else{const p=(dmRec.match(/\bp=(\w+)/)||[])[1]||'none';const sp=(dmRec.match(/\bsp=(\w+)/)||[])[1];const pct=(dmRec.match(/\bpct=(\d+)/)||[])[1];const rua=dmRec.includes('rua=');const fo=(dmRec.match(/\bfo=([^;]+)/)||[])[1];const sev=p==='reject'||p==='quarantine'?'pass':'important';let desc=`Policy: p=${p}. `;if(p==='none')desc+='Monitoring only.';else if(p==='quarantine')desc+='Failing emails go to spam.';else desc+='Strictest setting.';if(sp)desc+=` sp=${sp}.`;if(pct&&pct!=='100')desc+=` Only ${pct}% subject to policy.`;if(!rua)desc+=` No rua= — you will not receive authentication reports.`;if(fo)desc+=` fo=${fo}.`;if(usedOrg)desc+=` (Inherited from org domain.)`;tally(sev);s2.resolve(sev==='pass'?'done':'warn');authCards.push(makeCard('DMARC record',sev,dmRec,desc,'dmarc'));readiness.push({label:'DMARC enforced',status:p==='reject'||p==='quarantine'?'pass':'warn'});}
  if(!sel){s3.resolve('info');authCards.push(makeCard('DKIM record','info','No selector provided','Enter your DKIM selector above to check this.','dkim'));readiness.push({label:'DKIM signed',status:'info'});}else if(!dkimRes||lookupFailed(dkimRes)){s3.resolve('info');authCards.push(makeCard('DKIM record','timeout',`${sel}._domainkey.${domain}`,`Lookup failed.`,'dkim'));readiness.push({label:'DKIM signed',status:'fail'});}else{const dkRecs=dkimRes.answer.map(a=>normTXT(a.data)).filter(d=>d.includes('p='));if(!dkRecs.length){s3.resolve('fail');tally('critical',`No DKIM record for selector "${sel}"`);authCards.push(makeCard('DKIM record','critical',`${sel}._domainkey.${domain}`,'No DKIM record found.','dkim','dkim_missing'));readiness.push({label:'DKIM signed',status:'fail'});}else{const dk=dkRecs[0];const pm=dk.match(/\bp=([A-Za-z0-9+/=]+)/);const revoked=!pm||!pm[1];let keyBits='unknown';if(pm&&pm[1]){const b=Math.floor(pm[1].length*3/4);keyBits=b>=256?'2048-bit':b>=128?'1024-bit':'<1024-bit (weak)';}const sev=revoked?'critical':'pass';const desc=revoked?'Key is empty or revoked. DKIM signing is disabled.':`Public key found. Estimated size: ${keyBits}.${keyBits.includes('1024')||keyBits.includes('<')?' Consider upgrading to 2048-bit.':''}`;tally(sev);s3.resolve(sev==='pass'?'done':'fail');authCards.push(makeCard('DKIM record',sev,`${sel}._domainkey.${domain}`,desc,'dkim'));readiness.push({label:'DKIM signed',status:sev});}}
  s4.resolve('done');sections.push({title:'Email authentication',cards:authCards});
  const dnsCards=[];if(!lookupFailed(mxRes)){const mx=mxRes.answer.filter(a=>a.type===15);if(!mx.length){tally('important');dnsCards.push(makeCard('MX records','important','No MX records','No MX records found. Replies bounce and your domain looks misconfigured.','mx'));}else{tally('pass');dnsCards.push(makeCard('MX records','pass',mx.sort((a,b)=>parseInt(a.data)-parseInt(b.data)).map(r=>r.data).join(', '),`${mx.length} MX record(s) found.`,'mx'));}}
  const bimiRec=bimiRes.status==='ok'?bimiRes.answer.map(a=>normTXT(a.data)).find(d=>d.includes('v=BIMI1')):null;if(bimiRec){tally('pass');dnsCards.push(makeCard('BIMI','pass',bimiRec,'BIMI configured. Logo can appear in Gmail, Yahoo and Apple Mail.','bimi'));readiness.push({label:'BIMI configured',status:'pass'});}else{dnsCards.push(makeCard('BIMI','info','Not configured','No BIMI record. Requires a strong DMARC policy first.','bimi'));readiness.push({label:'BIMI configured',status:'info'});}
  const mtaRec=mtaRes.status==='ok'?mtaRes.answer.map(a=>normTXT(a.data)).find(d=>d.includes('v=STSv1')):null;if(mtaRec){tally('pass');dnsCards.push(makeCard('MTA-STS','pass',mtaRec,'MTA-STS enforces TLS for inbound email.','tls'));readiness.push({label:'TLS enforced',status:'pass'});}else{dnsCards.push(makeCard('MTA-STS','info','Not configured','No MTA-STS policy found.','tls'));readiness.push({label:'TLS enforced',status:'info'});}
  sections.push({title:'DNS infrastructure',cards:dnsCards});
  if(rpDomain&&rpDomain!==domain&&rpSpfRes){const rpCards=[];if(lookupFailed(rpSpfRes)){rpCards.push(makeCard('Return-path SPF','timeout','',`Lookup failed for ${rpDomain}.`,'spf'));}else{const rp=rpSpfRes.answer.map(a=>normTXT(a.data)).find(d=>d.startsWith('v=spf1'));if(!rp){tally('important');rpCards.push(makeCard('Return-path SPF','important','No SPF on bounce domain',`${rpDomain} has no SPF. SPF alignment via envelope sender will fail.`,'spf'));}else{tally('pass');rpCards.push(makeCard('Return-path SPF','pass',rp,`SPF found on ${rpDomain}.`,'spf'));}}sections.push({title:'Return-path / bounce domain',cards:rpCards});}
  s5.resolve('done');const domBLCards=[];domBL.forEach(r=>{if(r.result==='timeout'){domBLCards.push(makeCard(r.name,'timeout','','Lookup timed out.','blacklist'));}else if(r.result==='refused'){domBLCards.push(makeCard(r.name,'info',r.code||'',`${r.name} refused the query (rate-limited or restricted to paying customers). Treating as clean.`,'blacklist'));}else if(r.result==='listed'){tally('critical',`Domain listed on ${r.name}`);domBLCards.push(makeCard(r.name,'critical',r.code||'',`${domain} is listed on ${r.name} (code ${r.code}). Fix the root cause before requesting removal.`,'blacklist'));}else{tally('pass');domBLCards.push(makeCard(r.name,'pass','',`Not listed on ${r.name}.`,'blacklist'));}});
  sections.push({title:'Domain blacklists',cards:domBLCards});return sections;
}

async function auditIP(ip,tally,readiness){
  const ipCards=[];const s1=streamLog(`Checking reverse DNS for ${ip}...`);const s2=streamLog('Querying IP blacklists...');
  const ptrZone=isIPv6(ip)?`${reverseIPv6(ip)}.ip6.arpa`:`${reverseIPv4(ip)}.in-addr.arpa`;
  const[ptrRes,blRes]=await Promise.all([dnsLookup(ptrZone,'PTR'),checkIPBlacklists(ip)]);
  if(lookupFailed(ptrRes)){s1.resolve('info');ipCards.push(makeCard('Reverse DNS (PTR)','timeout',ptrZone,'Lookup timed out.','rdns'));}else{const ptrs=ptrRes.answer.filter(a=>a.type===12);if(!ptrs.length){s1.resolve('fail');tally('critical',`No PTR record for ${ip}`);ipCards.push(makeCard('Reverse DNS (PTR)','critical',ptrZone,`No PTR for ${ip}. Missing rDNS is a strong spam signal.`,'rdns'));readiness.push({label:'rDNS configured',status:'fail'});}else{const confirms=await Promise.all(ptrs.map(async p=>({hostname:p.data.replace(/\.$/,''),confirmed:await forwardConfirm(p.data.replace(/\.$/,''),ip)})));const all=confirms.every(r=>r.confirmed);const any=confirms.some(r=>r.confirmed);const sev=all?'pass':any?'important':'critical';const val=confirms.map(r=>`${r.hostname} (${r.confirmed?'forward-confirmed':'not confirmed'})`).join(', ');const desc=all?'PTR found and forward-confirmed.':any?`PTR found but not all hostnames forward-confirm back to ${ip}.`:`PTR exists but does not forward-confirm.`;tally(sev);s1.resolve(sev==='pass'?'done':sev==='critical'?'fail':'warn');ipCards.push(makeCard('Reverse DNS (PTR)',sev,val,desc,'rdns'));readiness.push({label:'rDNS configured',status:sev==='pass'?'pass':'fail'});}}
  s2.resolve('done');blRes.forEach(r=>{if(r.result==='timeout'){ipCards.push(makeCard(r.name,'timeout','','Lookup timed out.','blacklist'));}else if(r.result==='refused'){ipCards.push(makeCard(r.name,'info',r.code||'',`${r.name} refused the query (rate-limited or restricted). Treating as clean.`,'blacklist'));}else if(r.result==='listed'){tally('critical',`IP listed on ${r.name}`);ipCards.push(makeCard(r.name,'critical',r.code||'',`${ip} is listed on ${r.name} (code ${r.code}).`,'blacklist'));}else{tally('pass');ipCards.push(makeCard(r.name,'pass','',`Not listed on ${r.name}.`,'blacklist'));}});
  return{title:`IP checks (${ip})`,cards:ipCards};
}

// Header analyzer
let hdrSetup=false;
function setupHeaderAnalyzer(){
  if(hdrSetup)return;hdrSetup=true;
  const hdrDrop=document.getElementById('hdrDropZone');
  const hdrFileInput=document.getElementById('hdrFileInput');
  if(!hdrDrop||!hdrFileInput)return;
  hdrDrop.addEventListener('dragover',e=>{e.preventDefault();hdrDrop.classList.add('dragover');});
  hdrDrop.addEventListener('dragleave',()=>hdrDrop.classList.remove('dragover'));
  hdrDrop.addEventListener('drop',e=>{e.preventDefault();hdrDrop.classList.remove('dragover');const f=e.dataTransfer.files[0];if(f)loadHdrFile(f);});
  hdrFileInput.addEventListener('change',()=>{if(hdrFileInput.files[0])loadHdrFile(hdrFileInput.files[0]);});
}
function loadHdrFile(f){const reader=new FileReader();reader.onload=e=>{document.getElementById('headerInput').value=e.target.result;document.getElementById('hdrFileName').textContent='Loaded: '+f.name;};reader.readAsText(f);}
function clearHeaders(){document.getElementById('headerInput').value='';document.getElementById('hdrResults').innerHTML='';document.getElementById('hdrResultsWrap').style.display='none';document.getElementById('hdrFileName').textContent='';document.getElementById('hdrFileInput').value='';}

function analyzeHeaders(){
  const rawInput=document.getElementById('headerInput').value.trim();if(!rawInput)return;
  document.getElementById('headerWrap').classList.add('at-top');
  const out=document.getElementById('hdrResults');out.innerHTML='';
  const wrap=document.getElementById('hdrResultsWrap');wrap.style.display='none';
  // RFC 5322: unfold continuation lines (lines beginning with whitespace are part of the previous header)
  const raw=rawInput.replace(/\r\n/g,'\n').replace(/\n[ \t]+/g,' ');
  const frag=document.createDocumentFragment();
  const get=(name)=>{const m=raw.match(new RegExp(`^${name}:\\s*(.+)$`,'im'));return m?m[1].trim():null;};
  const getAll=(name)=>{const re=new RegExp(`^${name}:\\s*(.+)$`,'gim');const res=[];let m;while((m=re.exec(raw))!==null)res.push(m[1].trim());return res;};
  const authRes=get('Authentication-Results');
  const spfR=authRes?(authRes.match(/spf=(\w+)/i)||[])[1]:null;
  const dkimR=authRes?(authRes.match(/dkim=(\w+)/i)||[])[1]:null;
  const dmarcR=authRes?(authRes.match(/dmarc=(\w+)/i)||[])[1]:null;
  const arcR=get('ARC-Authentication-Results');
  function mkCard(title,icon,rows){const card=document.createElement('div');card.className='result-card';const t=document.createElement('div');t.className='result-card-title';t.innerHTML=`<span>${icon}</span>${title}`;card.appendChild(t);rows.forEach(r=>card.appendChild(r));return card;}
  const authRows=[{k:'SPF',v:spfR},{k:'DKIM',v:dkimR},{k:'DMARC',v:dmarcR},{k:'ARC',v:arcR?'present':'not found'}].map(({k,v})=>{const row=document.createElement('div');row.className='auth-row';const nm=document.createElement('span');nm.className='auth-name';nm.textContent=k;const badge=document.createElement('span');const val=(v||'').toLowerCase();badge.className=`auth-badge ${val==='pass'?'ab-pass':val==='fail'||val==='none'?'ab-fail':'ab-neutral'}`;badge.textContent=v||'not found';row.appendChild(nm);row.appendChild(badge);return row;});
  frag.appendChild(mkCard('Authentication Results','🔐',authRows));
  const fields=[{k:'From',v:get('From')},{k:'Reply-To',v:get('Reply-To')},{k:'Return-Path',v:get('Return-Path')},{k:'Message-ID',v:get('Message-ID')},{k:'Subject',v:get('Subject')},{k:'Date',v:get('Date')},{k:'X-Mailer',v:get('X-Mailer')||get('X-Sender')},{k:'Content-Type',v:get('Content-Type')}].filter(f=>f.v);
  if(fields.length){const hdrRows=fields.map(({k,v})=>{const row=document.createElement('div');row.className='hdr-row';const key=document.createElement('span');key.className='hdr-key';key.textContent=k;const val=document.createElement('span');val.className='hdr-val';val.textContent=v;row.appendChild(key);row.appendChild(val);return row;});frag.appendChild(mkCard('Key Headers','📋',hdrRows));}
  const received=getAll('Received');
  if(received.length){const routeRows=received.slice().reverse().map((r,i)=>{const step=document.createElement('div');step.className='route-step';const num=document.createElement('div');num.className='route-num';num.textContent=i+1;const txt=document.createElement('span');txt.textContent=r.replace(/\s+/g,' ').slice(0,140)+(r.length>140?'…':'');step.appendChild(num);step.appendChild(txt);return step;});frag.appendChild(mkCard(`Routing Path (${received.length} hops)`,'🛤',routeRows));}
  const signals=[];const xSpam=get('X-Spam-Status')||get('X-Spam-Flag');if(xSpam)signals.push({icon:xSpam.toLowerCase().includes('yes')?'⚠':'✓',text:'Spam flag: '+xSpam});const xScore=get('X-Spam-Score');if(xScore)signals.push({icon:parseFloat(xScore)>5?'⚠':'✓',text:'Spam score: '+xScore});const prec=get('Precedence');if(prec)signals.push({icon:'ℹ',text:'Precedence: '+prec});if(get('List-Id')||get('List-Unsubscribe'))signals.push({icon:'ℹ',text:'Bulk/list sender detected'});if(!spfR||spfR.toLowerCase()!=='pass')signals.push({icon:'⚠',text:'SPF did not pass in transit'});if(!dkimR||dkimR.toLowerCase()!=='pass')signals.push({icon:'⚠',text:'DKIM did not pass in transit'});if(!dmarcR||dmarcR.toLowerCase()!=='pass')signals.push({icon:'⚠',text:'DMARC did not pass in transit'});
  if(signals.length){const sigRows=signals.map(s=>{const row=document.createElement('div');row.className='signal-row';const icon=document.createElement('span');icon.className='signal-icon';icon.textContent=s.icon;const txt=document.createElement('span');txt.textContent=s.text;row.appendChild(icon);row.appendChild(txt);return row;});frag.appendChild(mkCard('Signals and Flags','🚩',sigRows));}
  out.appendChild(frag);wrap.style.display='block';
}

function runSimulator(){
  const type=document.getElementById('simType').value;const record=(document.getElementById('simRecord').value||'').trim();
  const wrap=document.getElementById('simResultsWrap');const out=document.getElementById('simResults');out.innerHTML='';wrap.style.display='none';if(!record)return;
  document.getElementById('simWrap').classList.add('at-top');
  const rows=[];const findings=[];
  if(type==='spf'){
    if(!record.startsWith('v=spf1'))findings.push({cls:'critical',msg:'Record does not start with v=spf1. Not a valid SPF record.'});
    const tokens=record.split(/\s+/);const n=tokens.filter(t=>/^[+-~?]?(include:|a:|mx:|ptr:|exists:)/.test(t)).length;const hasAll=tokens.find(t=>/^[+-~?]?all$/.test(t))||'';
    rows.push({k:'Estimated DNS lookups',v:`${n} of 10 allowed`,cls:n>10?'bad':n>8?'warn':'good'});rows.push({k:'All mechanism',v:hasAll||'missing',cls:hasAll?(/^[-~]all$/.test(hasAll)?'good':'warn'):'bad'});rows.push({k:'Include count',v:tokens.filter(t=>t.startsWith('include:')).length+' found',cls:'good'});
    if(n>10)findings.push({cls:'critical',msg:`${n} DNS lookups exceed the 10-lookup limit. This causes a permerror.`});else if(n>8)findings.push({cls:'warn',msg:`${n} lookups is close to the limit.`});
    if(!hasAll)findings.push({cls:'critical',msg:'No all mechanism. SPF result is undefined for unknown senders.'});if(hasAll==='+all')findings.push({cls:'critical',msg:'+all permits any server to send as you. Remove immediately.'});if(hasAll==='?all')findings.push({cls:'warn',msg:'?all is neutral. Use ~all or -all.'});
    if(!findings.length)findings.push({cls:'ok',msg:'This SPF record looks safe to publish.'});
  }else{
    if(!record.startsWith('v=DMARC1'))findings.push({cls:'critical',msg:'Record does not start with v=DMARC1. Not a valid DMARC record.'});
    const p=(record.match(/\bp=(\w+)/)||[])[1];const sp=(record.match(/\bsp=(\w+)/)||[])[1];const pct=(record.match(/\bpct=(\d+)/)||[])[1];const rua=record.includes('rua=');const ruf=record.includes('ruf=');
    rows.push({k:'Policy (p=)',v:p||'missing',cls:p==='reject'||p==='quarantine'?'good':p==='none'?'warn':'bad'});rows.push({k:'Subdomain policy (sp=)',v:sp||'inherits from p=',cls:'good'});rows.push({k:'Percentage (pct=)',v:pct?pct+'%':'100% (default)',cls:pct&&parseInt(pct)<100?'warn':'good'});rows.push({k:'Aggregate reports (rua=)',v:rua?'configured':'missing',cls:rua?'good':'warn'});rows.push({k:'Forensic reports (ruf=)',v:ruf?'configured':'not set',cls:'good'});
    if(!p)findings.push({cls:'critical',msg:'No p= tag. Not a valid DMARC record.'});else if(p==='none')findings.push({cls:'warn',msg:'p=none means monitoring only. Failing emails still reach inboxes.'});if(!rua)findings.push({cls:'warn',msg:'No rua= tag. You will not receive DMARC aggregate reports.'});if(pct&&parseInt(pct)<100)findings.push({cls:'warn',msg:`pct=${pct} means only ${pct}% of failing mail is subject to your policy.`});
    if(!findings.length)findings.push({cls:'ok',msg:'This DMARC record looks reasonable.'});
  }
  const frag=document.createDocumentFragment();
  const rc=document.createElement('div');rc.className='result-card';
  rows.forEach(r=>{const row=document.createElement('div');row.className='sim-row';const k=document.createElement('span');k.className='sim-key';k.textContent=r.k;const v=document.createElement('span');v.className=`sim-val ${r.cls||''}`;v.textContent=r.v;row.appendChild(k);row.appendChild(v);rc.appendChild(row);});frag.appendChild(rc);
  const fc=document.createElement('div');fc.className='result-card';const ft=document.createElement('div');ft.className='result-card-title';ft.innerHTML='<span>🔍</span>Findings';fc.appendChild(ft);
  const fl=document.createElement('div');fl.className='sim-findings';findings.forEach(f=>{const item=document.createElement('div');item.className=`sim-finding ${f.cls}`;const icon=document.createElement('span');icon.className='sf-icon';icon.textContent=f.cls==='critical'?'✕':f.cls==='warn'?'!':'✓';const txt=document.createElement('span');txt.textContent=f.msg;item.appendChild(icon);item.appendChild(txt);fl.appendChild(item);});fc.appendChild(fl);frag.appendChild(fc);
  out.appendChild(frag);wrap.style.display='block';
}

function switchTab(name,btn){
  document.querySelectorAll('.panel').forEach(p=>{p.classList.remove('active');p.style.display='none';});
  document.querySelectorAll('.nav-tab').forEach(t=>t.classList.remove('active'));
  const target=document.getElementById('panel-'+name);
  if(target){target.classList.add('active');target.style.display='flex';}
  btn.classList.add('active');
  if(name==='header')setupHeaderAnalyzer();
}

document.addEventListener('keydown',e=>{if(e.key==='Escape'){document.getElementById('bugModal').classList.remove('open');}});

// Enter-to-submit on the audit form inputs
['domain','dkimSel','ip','returnPath'].forEach(id=>{
  const el=document.getElementById(id);
  if(el)el.addEventListener('keydown',e=>{if(e.key==='Enter'&&!document.getElementById('runBtn').disabled){e.preventDefault();runAudit();}});
});
