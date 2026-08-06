// urlscope — client-side heuristic phishing link analyzer
// Everything runs locally in the browser. No requests are sent anywhere.

const urlInput   = document.getElementById('urlInput');
const scanBtn    = document.getElementById('scanBtn');
const statusChip = document.getElementById('statusChip');
const report     = document.getElementById('report');
const verdictText = document.getElementById('verdictText');
const gaugeScore = document.getElementById('gaugeScore');
const gaugeFill  = document.getElementById('gaugeFill');
const targetValue = document.getElementById('targetValue');
const findingsBody = document.getElementById('findingsBody');

const SHORTENERS = ['bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','is.gd','buff.ly','rebrand.ly','cutt.ly','shorte.st','tiny.cc'];
const SUSPICIOUS_TLDS = ['zip','xyz','top','click','country','work','gq','tk','cf','ml','support','info','loan'];
const SUSPICIOUS_KEYWORDS = ['login','verify','secure','account','update','confirm','signin','password','billing','webscr','wallet','unlock','recover'];
const BRAND_HINTS = ['paypal','google','microsoft','apple','amazon','netflix','facebook','instagram','bank','chase','wellsfargo','icici','sbi','hdfc'];

function normalizeUrl(raw){
  let s = raw.trim();
  if(!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(s)){
    s = 'http://' + s;
  }
  return s;
}

function isIpHost(host){
  const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
  const hex = /^0x[0-9a-f]+$/i;
  return ipv4.test(host) || hex.test(host);
}

function countSubdomains(hostname){
  const parts = hostname.split('.');
  return Math.max(0, parts.length - 2);
}

function domainHasBrandMismatch(hostname, path){
  const lowerHost = hostname.toLowerCase();
  const full = (hostname + path).toLowerCase();
  const mentionsBrand = BRAND_HINTS.some(b => full.includes(b));
  const brandIsRootDomain = BRAND_HINTS.some(b => lowerHost === b + '.com' || lowerHost.endsWith('.' + b + '.com'));
  return mentionsBrand && !brandIsRootDomain;
}

function runChecks(rawUrl){
  const normalized = normalizeUrl(rawUrl);
  let parsed;
  try{
    parsed = new URL(normalized);
  }catch(e){
    return null;
  }

  const hostname = parsed.hostname;
  const path = parsed.pathname + parsed.search;
  const fullString = rawUrl.trim();
  const findings = [];
  let score = 0;

  if(parsed.protocol !== 'https:'){
    findings.push({ name:'Transport security', detail:'Connection is not HTTPS — credentials could travel in plain text.', flag:true });
    score += 10;
  } else {
    findings.push({ name:'Transport security', detail:'Uses HTTPS.', flag:false });
  }

  if(isIpHost(hostname)){
    findings.push({ name:'Hostname type', detail:`Raw IP address (${hostname}) used instead of a domain name.`, flag:true });
    score += 25;
  } else {
    findings.push({ name:'Hostname type', detail:'Standard domain name, no raw IP.', flag:false });
  }

  if(fullString.includes('@')){
    findings.push({ name:'"@" redirection trick', detail:'Everything before "@" is ignored by browsers — classic disguise trick.', flag:true });
    score += 20;
  } else {
    findings.push({ name:'"@" redirection trick', detail:'No "@" symbol present.', flag:false });
  }

  const isShortener = SHORTENERS.some(s => hostname === s || hostname.endsWith('.' + s));
  if(isShortener){
    findings.push({ name:'Link shortener', detail:`${hostname} masks the real destination.`, flag:true });
    score += 15;
  } else {
    findings.push({ name:'Link shortener', detail:'Not a known shortener domain.', flag:false });
  }

  if(hostname.includes('xn--')){
    findings.push({ name:'Punycode / homograph', detail:'Encoded international characters can visually impersonate real brands.', flag:true });
    score += 20;
  } else {
    findings.push({ name:'Punycode / homograph', detail:'No punycode encoding detected.', flag:false });
  }

  const subCount = countSubdomains(hostname);
  if(subCount >= 3){
    findings.push({ name:'Subdomain depth', detail:`${subCount} subdomain labels — often used to bury the real domain.`, flag:true });
    score += 15;
  } else {
    findings.push({ name:'Subdomain depth', detail:'Normal subdomain structure.', flag:false });
  }

  if(fullString.length > 75){
    findings.push({ name:'URL length', detail:`${fullString.length} characters — unusually long links often hide redirects or tokens.`, flag:true });
    score += 10;
  } else {
    findings.push({ name:'URL length', detail:`${fullString.length} characters — within normal range.`, flag:false });
  }

  const hyphenCount = (hostname.match(/-/g) || []).length;
  if(hyphenCount >= 2){
    findings.push({ name:'Domain hyphenation', detail:`${hyphenCount} hyphens in domain — common in lookalike domains (e.g. secure-login-verify.com).`, flag:true });
    score += 10;
  } else {
    findings.push({ name:'Domain hyphenation', detail:'Normal hyphen usage.', flag:false });
  }

  const kwHit = SUSPICIOUS_KEYWORDS.some(k => path.toLowerCase().includes(k) || hostname.toLowerCase().includes(k));
  const brandMismatch = domainHasBrandMismatch(hostname, path);
  if(brandMismatch){
    findings.push({ name:'Brand impersonation cue', detail:'Mentions a well-known brand but the domain doesn\'t belong to it.', flag:true });
    score += 20;
  } else if(kwHit){
    findings.push({ name:'Credential-bait wording', detail:'Contains login/verify/account-style wording often used in bait links.', flag:true });
    score += 8;
  } else {
    findings.push({ name:'Brand & keyword check', detail:'No brand impersonation or bait wording detected.', flag:false });
  }

  const tld = hostname.split('.').pop().toLowerCase();
  if(SUSPICIOUS_TLDS.includes(tld)){
    findings.push({ name:'Top-level domain', detail:`.${tld} is a low-cost TLD frequently abused for throwaway phishing sites.`, flag:true });
    score += 10;
  } else {
    findings.push({ name:'Top-level domain', detail:`.${tld} — no elevated abuse signal.`, flag:false });
  }

  score = Math.min(100, score);

  let verdict, verdictClass;
  if(score < 25){ verdict = 'LOW RISK'; verdictClass = 'safe'; }
  else if(score < 55){ verdict = 'USE CAUTION'; verdictClass = 'caution'; }
  else { verdict = 'HIGH RISK'; verdictClass = 'danger'; }

  return { hostname: parsed.href, findings, score, verdict, verdictClass };
}

function renderReport(result){
  report.hidden = false;

  verdictText.textContent = result.verdict;
  verdictText.className = 'verdict-value ' + result.verdictClass;

  gaugeScore.textContent = result.score;
  const offset = 157 - (157 * result.score / 100);
  gaugeFill.style.strokeDashoffset = offset;
  gaugeFill.style.stroke = result.verdictClass === 'safe' ? 'var(--cyan)'
                          : result.verdictClass === 'caution' ? 'var(--amber)'
                          : 'var(--red)';

  targetValue.textContent = result.hostname;

  findingsBody.innerHTML = '';
  result.findings.forEach((f, i) => {
    const row = document.createElement('div');
    row.className = 'finding-row ' + (f.flag ? 'flag' : 'pass');
    row.innerHTML = `
      <span class="idx">${String(i+1).padStart(2,'0')}</span>
      <span class="check-name">${f.name}<span class="check-detail">${f.detail}</span></span>
      <span class="result ${f.flag ? 'flag' : 'pass'}">${f.flag ? 'FLAGGED' : 'CLEAR'}</span>
      <span class="signal-bars"><span></span><span></span><span></span></span>
    `;
    findingsBody.appendChild(row);
  });

  statusChip.className = 'status-chip ' + (result.verdictClass === 'safe' ? 'safe' : 'danger');
  statusChip.innerHTML = `<span class="dot"></span> ${result.verdict}`;
}

function runScan(){
  const raw = urlInput.value.trim();
  if(!raw){
    urlInput.focus();
    return;
  }

  scanBtn.classList.add('scanning');
  statusChip.className = 'status-chip scanning';
  statusChip.innerHTML = '<span class="dot"></span> SCANNING';

  setTimeout(() => {
    const result = runChecks(raw);
    scanBtn.classList.remove('scanning');

    if(!result){
      statusChip.className = 'status-chip danger';
      statusChip.innerHTML = '<span class="dot"></span> INVALID URL';
      report.hidden = true;
      return;
    }
    renderReport(result);
  }, 550);
}

scanBtn.addEventListener('click', runScan);
urlInput.addEventListener('keydown', (e) => {
  if(e.key === 'Enter') runScan();
});