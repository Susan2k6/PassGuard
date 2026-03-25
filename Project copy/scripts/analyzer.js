// ─── PassGuard Analyzer ───────────────────────────────────────────────────────

const inputEl     = document.getElementById('passwordInput');
const toggleEyeEl = document.getElementById('toggleEye');
const meterFill   = document.getElementById('meterFill');
const resultsEl   = document.getElementById('resultsSection');

// ── Toggle Visibility ─────────────────────────────────────────────────────────

toggleEyeEl.addEventListener('click', () => {
  const isPassword = inputEl.type === 'password';
  inputEl.type = isPassword ? 'text' : 'password';
  toggleEyeEl.innerHTML = isPassword
    ? '<i data-lucide="eye-off"></i>'
    : '<i data-lucide="eye"></i>';
  lucide.createIcons();
});

// ── Entropy / crack time ──────────────────────────────────────────────────────

function calcEntropy(password) {
  let pool = 0;
  if (/[a-z]/.test(password)) pool += 26;
  if (/[A-Z]/.test(password)) pool += 26;
  if (/[0-9]/.test(password)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(password)) pool += 32;
  return pool > 0 ? Math.floor(password.length * Math.log2(pool)) : 0;
}

function crackTimeLabel(bits) {
  const seconds = Math.pow(2, bits) / 1e10;
  if (seconds < 1)        return '< 1 second';
  if (seconds < 60)       return `~${Math.round(seconds)} seconds`;
  if (seconds < 3600)     return `~${Math.round(seconds / 60)} minutes`;
  if (seconds < 86400)    return `~${Math.round(seconds / 3600)} hours`;
  if (seconds < 2.628e6)  return `~${Math.round(seconds / 86400)} days`;
  if (seconds < 3.154e7)  return `~${Math.round(seconds / 2.628e6)} months`;
  if (seconds < 3.154e9)  return `~${Math.round(seconds / 3.154e7)} years`;
  if (seconds < 3.154e12) return `~${(seconds / 3.154e9).toFixed(0).toLocaleString()}K years`;
  return 'Centuries+';
}

// ── Main analyze ──────────────────────────────────────────────────────────────

inputEl.addEventListener('input', function () {
  const pw = this.value;
  if (!pw) {
    meterFill.style.width = '0%';
    meterFill.style.background = '#e5e7eb';
    resultsEl.classList.remove('visible');
    return;
  }
  resultsEl.classList.add('visible');
  analyzePassword(pw);
});

function analyzePassword(pw) {
  const bits = calcEntropy(pw);

  // ── Counts ──
  const upperCount = (pw.match(/[A-Z]/g) || []).length;
  const lowerCount = (pw.match(/[a-z]/g) || []).length;
  const numCount   = (pw.match(/[0-9]/g) || []).length;
  const symCount   = (pw.match(/[^a-zA-Z0-9]/g) || []).length;

  // ── Score ──
  let score = 0;
  if (pw.length >= 16) score += 3;
  else if (pw.length >= 12) score += 2;
  else if (pw.length >= 8)  score += 1;
  if (upperCount > 0) score++;
  if (lowerCount > 0) score++;
  if (numCount   > 0) score++;
  if (symCount   > 0) score += 2;
  if (/(.)\\1{2,}/.test(pw)) score -= 1;
  if (/^[0-9]+$/.test(pw))   score -= 2;
  if (/^[a-zA-Z]+$/.test(pw)) score -= 1;

  const WEAK_WORDS = ['password','12345678','qwerty','admin','letmein','welcome','monkey','dragon','baseball','abc123'];
  if (WEAK_WORDS.some(w => pw.toLowerCase().includes(w))) score -= 3;

  score = Math.max(0, score);
  const maxScore = 8;
  const pct = Math.min(100, Math.round((score / maxScore) * 100));

  let level, color, label;
  if (pct >= 75) { level = 'strong'; color = '#22c55e'; label = 'Strong'; }
  else if (pct >= 45) { level = 'medium'; color = '#f59e0b'; label = 'Fair'; }
  else { level = 'weak'; color = '#ef4444'; label = 'Weak'; }

  // ── Meter ──
  meterFill.style.width      = `${pct}%`;
  meterFill.style.background = color;

  // ── Score pill ──
  const scorePill = document.getElementById('scorePill');
  scorePill.textContent  = label;
  scorePill.className    = `score-pill ${level}`;

  // ── Crack time + entropy ──
  document.getElementById('crackChip').textContent    = crackTimeLabel(bits);
  document.getElementById('entropyChip').textContent  = `${bits} bits`;

  // ── Breakdown ──
  function setBd(id, countId, count) {
    document.getElementById(countId).textContent = count;
    document.getElementById(id).className = `breakdown-item ${count > 0 ? 'has' : 'missing'}`;
  }
  setBd('bdUpper', 'bdUpperCount', upperCount);
  setBd('bdLower', 'bdLowerCount', lowerCount);
  setBd('bdNum',   'bdNumCount',   numCount);
  setBd('bdSym',   'bdSymCount',   symCount);

  // ── Security checks ──
  const checks = [
    { ok: pw.length >= 12,  msg: `Length: ${pw.length} characters ${pw.length >= 12 ? '✓' : '(need 12+)'}` },
    { ok: upperCount > 0,   msg: 'Contains uppercase letters' },
    { ok: lowerCount > 0,   msg: 'Contains lowercase letters' },
    { ok: numCount > 0,     msg: 'Contains numbers' },
    { ok: symCount > 0,     msg: 'Contains special symbols' },
    { ok: pw.length >= 16,  msg: `Optimal length (16+): ${pw.length >= 16 ? 'Yes ✓' : 'No'}` },
    { ok: !/((.)\2{2,})/.test(pw), msg: 'No repeated characters (aaa, 111…)' },
    { ok: !WEAK_WORDS.some(w => pw.toLowerCase().includes(w)), msg: 'No common dictionary words' },
  ];

  const checksList = document.getElementById('checksList');
  checksList.innerHTML = checks.map(c => `
    <div class="check-row ${c.ok ? 'pass' : 'fail'}">
      <span class="check-icon">${c.ok ? '<i data-lucide="check-circle-2"></i>' : '<i data-lucide="x-circle"></i>'}</span>
      <span>${c.msg}</span>
    </div>
  `).join('');
  lucide.createIcons();

  // ── Pattern detection ──
  const patterns = [];
  if (/(.)\1{2,}/.test(pw))   patterns.push('Repeated chars');
  if (/012|123|234|345|456|567|678|789|890/.test(pw)) patterns.push('Sequential numbers');
  if (/abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz/i.test(pw)) patterns.push('Sequential letters');
  if (/qwerty|asdf|zxcv/i.test(pw)) patterns.push('Keyboard pattern');
  if (/^[0-9]+$/.test(pw)) patterns.push('Numbers only');
  if (/^[a-zA-Z]+$/.test(pw)) patterns.push('Letters only');
  if (WEAK_WORDS.some(w => pw.toLowerCase().includes(w))) patterns.push('Common word');

  const patternsCard = document.getElementById('patternsCard');
  const patternTags  = document.getElementById('patternTags');
  if (patterns.length > 0) {
    patternTags.innerHTML = patterns.map(p => `<span class="pattern-tag"><i data-lucide="triangle-alert"></i> ${p}</span>`).join('');
    patternsCard.style.display = 'block';
    lucide.createIcons();
  } else {
    patternsCard.style.display = 'none';
  }

  // ── Suggestions ──
  const suggestions = [];
  if (level === 'strong') {
    suggestions.push({ good: true, icon: 'party-popper', text: 'Excellent! This password meets all strong security standards.' });
  }
  if (pw.length < 12) suggestions.push({ good: false, icon: 'ruler', text: 'Increase length to at least 12 characters.' });
  if (upperCount === 0) suggestions.push({ good: false, icon: 'arrow-up-a-z', text: 'Add uppercase letters (A–Z).' });
  if (lowerCount === 0) suggestions.push({ good: false, icon: 'arrow-down-a-z', text: 'Add lowercase letters (a–z).' });
  if (numCount === 0)   suggestions.push({ good: false, icon: 'hash', text: 'Add numbers (0–9).' });
  if (symCount === 0)   suggestions.push({ good: false, icon: 'asterisk', text: 'Add special symbols (!@#$%…).' });
  if (patterns.includes('Repeated chars'))    suggestions.push({ good: false, icon: 'repeat', text: 'Avoid repeating characters (aaa, 111).' });
  if (patterns.includes('Common word'))       suggestions.push({ good: false, icon: 'book-open', text: 'Remove common dictionary words.' });
  if (patterns.includes('Sequential numbers')) suggestions.push({ good: false, icon: 'hash', text: 'Avoid sequential number patterns (123, 456).' });
  if (patterns.includes('Keyboard pattern'))  suggestions.push({ good: false, icon: 'keyboard', text: 'Avoid keyboard patterns like "qwerty".' });
  if (pw.length >= 12 && level !== 'strong') suggestions.push({ good: false, icon: 'shuffle', text: 'Use a random mix instead of patterns. Try the Password Generator!' });

  const suggestionList = document.getElementById('suggestionList');
  suggestionList.innerHTML = suggestions.map(s => `
    <div class="suggestion-item ${s.good ? 'good' : ''}">
      <span class="suggestion-icon"><i data-lucide="${s.icon}"></i></span>
      <span class="suggestion-text">${s.text}</span>
    </div>
  `).join('') || '<div class="suggestion-item good"><span class="suggestion-icon"><i data-lucide="check-circle-2"></i></span><span class="suggestion-text">No issues found!</span></div>';
  lucide.createIcons();
}
