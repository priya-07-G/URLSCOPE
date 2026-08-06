/* =========================================================
   BREACHSCAN — client-side simulated breach exposure checker
   Everything runs locally against the bundled BREACH_DATASET.
   No network requests, nothing is stored or transmitted.
   ========================================================= */

const els = {
  queryInput: document.getElementById('queryInput'),
  checkBtn: document.getElementById('checkBtn'),
  resultBlock: document.getElementById('resultBlock'),
  resultSummary: document.getElementById('resultSummary'),
  breachList: document.getElementById('breachList'),
  pwInput: document.getElementById('pwInput'),
  strengthBar: document.getElementById('strengthBar'),
  strengthLabel: document.getElementById('strengthLabel'),
  crackTime: document.getElementById('crackTime'),
  pwChecklist: document.getElementById('pwChecklist'),
};

/* ---------- breach lookup ---------- */
function checkBreaches(query) {
  const q = query.trim().toLowerCase();
  if (!q) return [];
  return BREACH_DATASET.filter(b =>
    b.identifiers.some(id => id.toLowerCase() === q)
  );
}

function renderResults(query) {
  const matches = checkBreaches(query);
  els.resultBlock.hidden = false;

  if (matches.length === 0) {
    els.resultSummary.className = 'result-summary clean';
    els.resultSummary.textContent = `no matches found for "${query}" in the simulated dataset — clean.`;
    els.breachList.innerHTML = '';
    return;
  }

  els.resultSummary.className = 'result-summary exposed';
  els.resultSummary.textContent = `found in ${matches.length} simulated breach${matches.length > 1 ? 'es' : ''} — review below.`;

  els.breachList.innerHTML = matches.map(b => `
    <div class="breach-card">
      <div class="breach-card-head">
        <strong>${b.name}</strong>
        <span class="severity-tag severity-${b.severity}">${b.severity}</span>
      </div>
      <div class="breach-meta">${b.date} · ${b.records} records affected</div>
      <div class="exposed-tags">
        ${b.exposed.map(e => `<span class="exposed-tag">${e}</span>`).join('')}
      </div>
    </div>
  `).join('');
}

els.checkBtn.addEventListener('click', () => {
  if (els.queryInput.value.trim()) renderResults(els.queryInput.value);
});

els.queryInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && els.queryInput.value.trim()) renderResults(els.queryInput.value);
});

document.querySelectorAll('.hint-example').forEach(el => {
  el.addEventListener('click', () => {
    els.queryInput.value = el.dataset.fill;
    renderResults(el.dataset.fill);
  });
});

/* ---------- password strength ---------- */
function analyzePassword(pw) {
  const checks = {
    length: pw.length >= 8,
    upper: /[A-Z]/.test(pw),
    lower: /[a-z]/.test(pw),
    number: /[0-9]/.test(pw),
    symbol: /[^A-Za-z0-9]/.test(pw),
    common: pw.length > 0 && !COMMON_PASSWORDS.includes(pw.toLowerCase()),
  };

  const passed = Object.values(checks).filter(Boolean).length;
  const score = pw.length === 0 ? 0 : passed / 6;

  // rough entropy estimate for crack-time display (illustrative, not cryptographic)
  let poolSize = 0;
  if (checks.lower) poolSize += 26;
  if (checks.upper) poolSize += 26;
  if (checks.number) poolSize += 10;
  if (checks.symbol) poolSize += 32;
  poolSize = poolSize || 1;

  const entropy = pw.length * Math.log2(poolSize);
  const guesses = Math.pow(2, entropy);
  const guessesPerSecond = 1e10; // rough offline-attack estimate
  const seconds = guesses / guessesPerSecond;

  return { checks, score, seconds, isCommon: !checks.common && pw.length > 0 };
}

function formatCrackTime(seconds) {
  if (seconds < 1) return 'instantly';
  const units = [
    ['centuries', 60 * 60 * 24 * 365 * 100],
    ['years', 60 * 60 * 24 * 365],
    ['days', 60 * 60 * 24],
    ['hours', 60 * 60],
    ['minutes', 60],
    ['seconds', 1],
  ];
  for (const [label, unitSeconds] of units) {
    if (seconds >= unitSeconds) {
      const val = seconds / unitSeconds;
      return `~${val > 999 ? '999+' : Math.round(val)} ${label}`;
    }
  }
  return 'instantly';
}

function renderPasswordStrength() {
  const pw = els.pwInput.value;
  const { checks, score, seconds, isCommon } = analyzePassword(pw);

  const pct = Math.round(score * 100);
  els.strengthBar.style.width = pct + '%';

  let color = '#ff5c5c', label = 'very weak';
  if (isCommon) {
    color = '#ff5c5c'; label = 'common password — avoid';
  } else if (score >= 1) {
    color = '#5eead4'; label = 'strong';
  } else if (score >= 0.66) {
    color = '#f5b942'; label = 'moderate';
  } else if (score >= 0.33) {
    color = '#ff8c42'; label = 'weak';
  }

  els.strengthBar.style.background = color;
  els.strengthLabel.textContent = pw ? label : '—';
  els.crackTime.textContent = pw
    ? (isCommon ? 'found in common password lists' : `est. crack time: ${formatCrackTime(seconds)}`)
    : 'enter a password above';

  Object.keys(checks).forEach(key => {
    const li = els.pwChecklist.querySelector(`[data-check="${key}"]`);
    li.classList.toggle('pass', checks[key] && pw.length > 0);
  });
}

els.pwInput.addEventListener('input', renderPasswordStrength);