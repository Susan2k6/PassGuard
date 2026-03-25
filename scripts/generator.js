// ─── PassGuard Generator ─────────────────────────────────────────────────────

const UPPERCASE  = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const LOWERCASE  = 'abcdefghijklmnopqrstuvwxyz';
const NUMBERS    = '0123456789';
const SYMBOLS    = '!@#$%^&*()_+-=[]{}|;:,.<>?';
const AMBIGUOUS  = /[0Ol1I]/g;

const sessionHistory = []; // passwords generated this session

// ── Entropy / strength helpers ────────────────────────────────────────────────

function calcPoolSize(upper, lower, nums, syms, noAmbiguous) {
  let size = 0;
  if (upper) size += noAmbiguous ? UPPERCASE.replace(AMBIGUOUS,'').length : UPPERCASE.length;
  if (lower) size += noAmbiguous ? LOWERCASE.replace(AMBIGUOUS,'').length : LOWERCASE.length;
  if (nums)  size += noAmbiguous ? NUMBERS.replace(AMBIGUOUS,'').length   : NUMBERS.length;
  if (syms)  size += SYMBOLS.length;
  return size;
}

function entropyBits(length, poolSize) {
  return poolSize > 0 ? Math.floor(length * Math.log2(poolSize)) : 0;
}

function strengthFromEntropy(bits) {
  if (bits >= 80) return 'strong';
  if (bits >= 50) return 'medium';
  return 'weak';
}

function crackTimeLabel(bits) {
  // At 10B guesses/second (fast offline attack)
  const combos = Math.pow(2, bits);
  const seconds = combos / 1e10;
  if (seconds < 1)       return '< 1 second';
  if (seconds < 60)      return `${Math.round(seconds)} seconds`;
  if (seconds < 3600)    return `${Math.round(seconds/60)} minutes`;
  if (seconds < 86400)   return `${Math.round(seconds/3600)} hours`;
  if (seconds < 2.6e6)   return `${Math.round(seconds/86400)} days`;
  if (seconds < 3.15e7)  return `${Math.round(seconds/2.6e6)} months`;
  if (seconds < 3.15e9)  return `${Math.round(seconds/3.15e7)} years`;
  if (seconds < 3.15e12) return `${Math.round(seconds/3.15e9).toLocaleString()} thousand years`;
  return 'Centuries+';
}

// ── Generate ──────────────────────────────────────────────────────────────────

function buildPool(upper, lower, nums, syms, noAmbig) {
  let pool = '';
  if (upper) pool += UPPERCASE;
  if (lower) pool += LOWERCASE;
  if (nums)  pool += NUMBERS;
  if (syms)  pool += SYMBOLS;
  if (noAmbig) pool = pool.replace(AMBIGUOUS, '');
  return pool;
}

function generatePassword() {
  const length     = parseInt(document.getElementById('passwordLength').value);
  const upper      = document.getElementById('includeUppercase').checked;
  const lower      = document.getElementById('includeLowercase').checked;
  const nums       = document.getElementById('includeNumbers').checked;
  const syms       = document.getElementById('includeSymbols').checked;
  const noAmbig    = document.getElementById('excludeAmbiguous').checked;

  const pool = buildPool(upper, lower, nums, syms, noAmbig);
  if (!pool) {
    alert('Please select at least one character type.');
    return null;
  }

  // Use crypto if available for better randomness
  let password = '';
  if (window.crypto && window.crypto.getRandomValues) {
    const arr = new Uint32Array(length);
    window.crypto.getRandomValues(arr);
    for (let i = 0; i < length; i++) {
      password += pool[arr[i] % pool.length];
    }
  } else {
    for (let i = 0; i < length; i++) {
      password += pool[Math.floor(Math.random() * pool.length)];
    }
  }

  // Entropy & strength
  const poolSize = calcPoolSize(upper, lower, nums, syms, noAmbig);
  const bits     = entropyBits(length, poolSize);
  const strength = strengthFromEntropy(bits);

  return { password, bits, strength };
}

// ── UI updaters ───────────────────────────────────────────────────────────────

function showResult({ password, bits, strength }) {
  const colMap = { weak: '#ef4444', medium: '#f59e0b', strong: '#22c55e' };
  const pctMap = { weak: 30, medium: 62, strong: 100 };
  const labelMap = { weak: 'Weak', medium: 'Medium', strong: 'Strong' };

  document.getElementById('generatedPassword').textContent = password;
  document.getElementById('entropyChip').textContent  = `${bits} bits`;
  document.getElementById('crackChip').textContent    = crackTimeLabel(bits);
  document.getElementById('miniStrengthFill').style.width      = `${pctMap[strength]}%`;
  document.getElementById('miniStrengthFill').style.background = colMap[strength];
  document.getElementById('miniStrengthLabel').textContent     = labelMap[strength];
  document.getElementById('miniStrengthLabel').style.color     = colMap[strength];

  document.getElementById('passwordResult').classList.add('show');
}

function addToHistory({ password, strength }) {
  sessionHistory.unshift({ password, strength });
  if (sessionHistory.length > 8) sessionHistory.pop();
  renderHistory();
}

function renderHistory() {
  const container = document.getElementById('historyList');
  if (sessionHistory.length === 0) {
    container.innerHTML = '<div class="empty-history">No passwords generated yet.<br>Hit Generate to get started!</div>';
    return;
  }
    container.innerHTML = sessionHistory.map((item, idx) => `
    <div class="history-item">
      <div style="flex:1;min-width:0;">
        ${item.app ? `<div style="font-size:.75rem;font-weight:700;color:#6366f1;margin-bottom:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${item.app}</div>` : ''}
        <span class="history-pw">${item.password}</span>
      </div>
      <span class="history-badge ${item.strength}">${item.strength}</span>
      <button class="history-copy" onclick="copyHistoryItem(${idx})" title="Copy"><i data-lucide="clipboard"></i></button>
    </div>
  `).join('');
  lucide.createIcons();
}

// ── Quick Modes ───────────────────────────────────────────────────────────────

const MODES = {
  custom:   null, // user-controlled
  pin:      { length: 6,  upper: false, lower: false, nums: true,  syms: false },
  memorable:{ length: 16, upper: true,  lower: true,  nums: true,  syms: false },
  maxsec:   { length: 32, upper: true,  lower: true,  nums: true,  syms: true  },
};

document.getElementById('modeRow').addEventListener('click', function(e) {
  const pill = e.target.closest('.mode-pill');
  if (!pill) return;
  const mode = pill.dataset.mode;

  document.querySelectorAll('.mode-pill').forEach(p => p.classList.remove('active'));
  pill.classList.add('active');

  if (mode !== 'custom' && MODES[mode]) {
    const m = MODES[mode];
    document.getElementById('passwordLength').value         = m.length;
    document.getElementById('lengthValue').textContent      = m.length;
    document.getElementById('includeUppercase').checked     = m.upper;
    document.getElementById('includeLowercase').checked     = m.lower;
    document.getElementById('includeNumbers').checked       = m.nums;
    document.getElementById('includeSymbols').checked       = m.syms;
  }
});

// ── Slider ────────────────────────────────────────────────────────────────────

document.getElementById('passwordLength').addEventListener('input', function() {
  document.getElementById('lengthValue').textContent = this.value;
  // Reset to custom mode
  document.querySelectorAll('.mode-pill').forEach(p => p.classList.remove('active'));
  document.querySelector('[data-mode="custom"]').classList.add('active');
});

// ── Generate button ───────────────────────────────────────────────────────────

function doGenerate() {
  const result = generatePassword();
  if (!result) return;
  showResult(result);
  const app = document.getElementById('appName').value.trim();
  addToHistory({ ...result, app });
}

document.getElementById('generateBtn').addEventListener('click', doGenerate);
document.getElementById('refreshBtn').addEventListener('click', doGenerate);

// ── Copy ──────────────────────────────────────────────────────────────────────

document.getElementById('copyBtn').addEventListener('click', function() {
  const pw = document.getElementById('generatedPassword').textContent;
  navigator.clipboard.writeText(pw).then(() => {
    const orig = this.innerHTML;
    this.innerHTML = '<i data-lucide="check"></i><span>Copied!</span>';
    lucide.createIcons();
    setTimeout(() => { this.innerHTML = orig; lucide.createIcons(); }, 1600);
  });
});

function copyHistoryItem(idx) {
  const { password } = sessionHistory[idx];
  navigator.clipboard.writeText(password).then(() => {
    const btns = document.querySelectorAll('.history-copy');
    if (btns[idx]) {
      const orig = btns[idx].innerHTML;
      btns[idx].innerHTML = '<i data-lucide="check"></i>';
      lucide.createIcons();
      setTimeout(() => { btns[idx].innerHTML = orig; lucide.createIcons(); }, 1200);
    }
  });
}
window.copyHistoryItem = copyHistoryItem;

// ── Save to vault ─────────────────────────────────────────────────────────────

document.getElementById('saveBtn').addEventListener('click', async function () {
  const appName  = document.getElementById('appName').value.trim();
  const password = document.getElementById('generatedPassword').textContent;

  if (!appName) {
    document.getElementById('appName').focus();
    document.getElementById('appName').style.borderColor = '#ef4444';
    setTimeout(() => { document.getElementById('appName').style.borderColor = ''; }, 2000);
    alert('Please enter an application name first!');
    return;
  }

  const token = sessionStorage.getItem('pg_token');
  if (!token) { window.location.href = 'login.html'; return; }

  const strength = strengthFromEntropy(entropyBits(
    password.length,
    calcPoolSize(
      document.getElementById('includeUppercase').checked,
      document.getElementById('includeLowercase').checked,
      document.getElementById('includeNumbers').checked,
      document.getElementById('includeSymbols').checked,
      document.getElementById('excludeAmbiguous').checked
    )
  ));

  try {
    const res = await fetch('/api/vault', {
      method:  'POST',
      headers: {
        'Content-Type':  'application/json',
        'Authorization': `Bearer ${token}`,
      },
      body: JSON.stringify({ app: appName, username: '', password, strength }),
    });

    if (res.status === 401) {
      sessionStorage.clear();
      window.location.href = 'login.html';
      return;
    }

    const data = await res.json();
    if (!res.ok) { alert(data.error || 'Failed to save to vault.'); return; }

    this.innerHTML = '<i data-lucide="check"></i><span>Saved!</span>';
    lucide.createIcons();
    setTimeout(() => {
      this.innerHTML = '<i data-lucide="save"></i><span>Save to Vault</span>';
      lucide.createIcons();
    }, 1800);
    document.getElementById('appName').value = '';

  } catch (err) {
    console.error('Save to vault error:', err);
    alert('Network error. Could not save to vault.');
  }
});

