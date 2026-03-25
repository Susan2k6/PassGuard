// ─── PassGuard Vault (API-backed) ─────────────────────────────────────────────
// Replaces all localStorage logic with fetch() calls to /api/vault.
// Encryption is done server-side (AES-256-CBC). The frontend never sees
// the cipher-text — it receives decrypted passwords from the API.

const VAULT_KEY = 'passwords'; // kept for legacy key name compatibility
const EXPIRY_DAYS = 90;
const API_BASE = '/api/vault';

// ── Module-level cache — populated by refresh() ───────────────────────────────
// Allows togglePassword() to reveal values without an extra fetch.
let _vaultCache = [];

// ── API helpers ───────────────────────────────────────────────────────────────

function _token() {
  return sessionStorage.getItem('pg_token');
}

function _authHeaders() {
  return {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${_token()}`,
  };
}

async function _apiCall(method, path = '', body = null) {
  const res = await fetch(API_BASE + path, {
    method,
    headers: _authHeaders(),
    body: body ? JSON.stringify(body) : undefined,
  });

  // Token expired or invalid → send back to login
  if (res.status === 401) {
    sessionStorage.clear();
    window.location.href = 'login.html';
    return null;
  }
  return res;
}

// ── Date / expiry helpers ─────────────────────────────────────────────────────

function ageInDays(dateStr) {
  return Math.floor((Date.now() - new Date(dateStr).getTime()) / 86_400_000);
}

function expiryStatus(dateStr) {
  const age = ageInDays(dateStr);
  if (age >= EXPIRY_DAYS) return 'expired';
  if (age >= EXPIRY_DAYS - 15) return 'soon';
  return 'ok';
}

function expiryLabel(dateStr) {
  const age = ageInDays(dateStr);
  const remaining = EXPIRY_DAYS - age;
  if (age >= EXPIRY_DAYS) return `Expired ${age - EXPIRY_DAYS + 1}d ago`;
  if (remaining <= 15) return `Expires in ${remaining}d`;
  return `${remaining}d remaining`;
}

function formatDate(dateStr) {
  return new Date(dateStr).toLocaleDateString('en-IN', {
    day: '2-digit', month: 'short', year: 'numeric',
  });
}

function escapeHtml(text) {
  const d = document.createElement('div');
  d.textContent = text;
  return d.innerHTML;
}

// ── Toast notification ───────────────────────────────────────────────────

let _toastTimer = null;
function showToast(msg, durationMs = 3000) {
  const el = document.getElementById('vaultToast');
  if (!el) return;
  el.textContent = msg;
  el.classList.add('show');
  clearTimeout(_toastTimer);
  _toastTimer = setTimeout(() => el.classList.remove('show'), durationMs);
}

// ── Strength helper (client-side, for modal preview) ─────────────────────────

function analyzeStrength(password) {
  let score = 0;
  if (password.length >= 12) score += 2;
  else if (password.length >= 8) score += 1;
  if (/[a-z]/.test(password)) score++;
  if (/[A-Z]/.test(password)) score++;
  if (/[0-9]/.test(password)) score++;
  if (/[^a-zA-Z0-9]/.test(password)) score++;
  if (score >= 5) return 'strong';
  if (score >= 3) return 'medium';
  return 'weak';
}

// ── Reuse detection ───────────────────────────────────────────────────────────

function getReuseMap(list) {
  const map = {};
  list.forEach(item => {
    if (!map[item.password]) map[item.password] = [];
    map[item.password].push(item.app);
  });
  return map;
}

// ── Stats bar ─────────────────────────────────────────────────────────────────

function updateStats(list, reuseMap) {
  const expired = list.filter(p => expiryStatus(p.createdAt) === 'expired').length;
  const soon = list.filter(p => expiryStatus(p.createdAt) === 'soon').length;
  const reused = list.filter(p => reuseMap[p.password]?.length > 1).length;
  const strong = list.filter(p => p.strength === 'strong').length;

  document.getElementById('statTotal').textContent = list.length;
  document.getElementById('statExpired').textContent = expired;
  document.getElementById('statSoon').textContent = soon;
  document.getElementById('statReused').textContent = reused;
  document.getElementById('statStrong').textContent = strong;
}

// ── Alert banners ─────────────────────────────────────────────────────────────

function updateBanners(list, reuseMap) {
  const needsAction = list.filter(p => expiryStatus(p.createdAt) !== 'ok');
  const expiryBanner = document.getElementById('expiryBanner');
  const expiryList = document.getElementById('expiryBannerList');

  if (needsAction.length > 0) {
    expiryList.innerHTML = needsAction.map(p => {
      const icon = expiryStatus(p.createdAt) === 'expired'
        ? '<i data-lucide="circle-alert"></i>'
        : '<i data-lucide="clock-alert"></i>';
      return `<div class="alert-item">${icon} <strong>${escapeHtml(p.app)}</strong> — ${expiryLabel(p.createdAt)}</div>`;
    }).join('');
    expiryBanner.classList.add('show');
    lucide.createIcons();
  } else {
    expiryBanner.classList.remove('show');
  }

  const reusedGroups = Object.entries(reuseMap).filter(([, apps]) => apps.length > 1);
  const reuseBanner = document.getElementById('reuseBanner');
  const reuseList = document.getElementById('reuseBannerList');

  if (reusedGroups.length > 0) {
    reuseList.innerHTML = reusedGroups.map(([, apps]) =>
      `<div class="alert-item"><i data-lucide="repeat-2"></i> Same password used for: <strong>${apps.map(escapeHtml).join(', ')}</strong></div>`
    ).join('');
    reuseBanner.classList.add('show');
    lucide.createIcons();
  } else {
    reuseBanner.classList.remove('show');
  }
}

// ── Strength preview (modal) ──────────────────────────────────────────────────

function previewStrength(value) {
  const fill = document.getElementById('strengthFill');
  const label = document.getElementById('strengthLabel');
  if (!value) { fill.style.width = '0'; label.textContent = ''; return; }
  const s = analyzeStrength(value);
  const map = {
    weak: ['30%', '#ef4444', 'Weak'],
    medium: ['65%', '#f59e0b', 'Medium'],
    strong: ['100%', '#22c55e', 'Strong'],
  };
  fill.style.width = map[s][0];
  fill.style.background = map[s][1];
  label.textContent = map[s][2];
  label.style.color = map[s][1];
}
window.previewStrength = previewStrength;

// ── List view ─────────────────────────────────────────────────────────────────

function renderList(list, reuseMap, query = '') {
  const grid = document.getElementById('passwordGrid');
  const empty = document.getElementById('emptyState');

  let filtered = list;
  if (query) {
    const q = query.toLowerCase();
    filtered = list.filter(p =>
      p.app.toLowerCase().includes(q) ||
      (p.username && p.username.toLowerCase().includes(q)) ||
      (p.url && p.url.toLowerCase().includes(q))
    );
  }

  if (filtered.length === 0) {
    grid.innerHTML = '';
    empty.style.display = 'block';
    return;
  }
  empty.style.display = 'none';

  const order = { expired: 0, soon: 1, ok: 2 };
  filtered = [...filtered].sort((a, b) => {
    const sa = order[expiryStatus(a.createdAt)];
    const sb = order[expiryStatus(b.createdAt)];
    if (sa !== sb) return sa - sb;
    return new Date(b.createdAt) - new Date(a.createdAt);
  });

  grid.innerHTML = '';
  filtered.forEach(item => grid.appendChild(createCard(item, reuseMap)));
}

function createCard(item, reuseMap) {
  const status = expiryStatus(item.createdAt);
  const isReused = reuseMap[item.password]?.length > 1;
  const letter = item.app.charAt(0).toUpperCase();

  // Normalise URL: ensure it has a scheme so window.open works
  const rawUrl = (item.url || '').trim();
  const hasUrl = rawUrl.length > 0;
  const safeUrl = hasUrl && !/^https?:\/\//i.test(rawUrl) ? 'https://' + rawUrl : rawUrl;
  const shortUrl = rawUrl.replace(/^https?:\/\//i, '').replace(/\/$/, '');

  const card = document.createElement('div');
  card.className = `pw-card${status === 'expired' ? ' expired' : status === 'soon' ? ' expiring-soon' : ''}`;
  card.innerHTML = `
    <div class="pw-card-header">
      <div class="pw-app-icon">${letter}</div>
      <div class="pw-app-info">
        <div class="pw-app-name">${escapeHtml(item.app)}</div>
        ${item.username ? `<div class="pw-username"><i data-lucide="user"></i> ${escapeHtml(item.username)}</div>` : ''}
        ${hasUrl ? `<a class="pw-url-link" href="${escapeHtml(safeUrl)}" target="_blank" rel="noopener"><i data-lucide="link"></i> ${escapeHtml(shortUrl)}</a>` : ''}
      </div>
      <div class="pw-card-actions">
        <button class="icon-btn" onclick="togglePassword('${item.id}')" title="Show/Hide"><i data-lucide="eye"></i></button>
        <button class="icon-btn" onclick="copyPassword('${item.id}')"   title="Copy password"><i data-lucide="clipboard"></i></button>
        <button class="icon-btn" onclick="deletePassword('${item.id}')" title="Delete"><i data-lucide="trash-2"></i></button>
      </div>
    </div>

    <div class="pw-field">
      <span class="pw-field-val" id="pw-${item.id}">••••••••</span>
      <span class="badge badge-${item.strength}">${item.strength.charAt(0).toUpperCase() + item.strength.slice(1)}</span>
    </div>

    ${hasUrl ? `
    <div>
      <button class="launch-btn" onclick="launchAndFill('${item.id}')">
        <i data-lucide="rocket"></i> Launch &amp; Autofill
      </button>
    </div>` : ''}

    <div class="pw-footer">
      <span class="pw-date"><i data-lucide="calendar"></i> Added ${formatDate(item.createdAt)}</span>
      <div style="display:flex;gap:6px;flex-wrap:wrap;justify-content:flex-end;">
        ${isReused ? `<span class="reuse-tag"><i data-lucide="repeat-2"></i> Reused</span>` : ''}
        <span class="expiry-tag ${status}">${expiryLabel(item.createdAt)}</span>
      </div>
    </div>
  `;
  lucide.createIcons({ el: card });
  return card;
}

// ── Timeline view ─────────────────────────────────────────────────────────────

function renderTimeline(list) {
  const container = document.getElementById('timelineContainer');
  const emptyTl = document.getElementById('emptyTimeline');

  if (list.length === 0) {
    container.innerHTML = '';
    emptyTl.style.display = 'block';
    return;
  }
  emptyTl.style.display = 'none';

  const sorted = [...list].sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  const groups = {};
  sorted.forEach(item => {
    const key = new Date(item.createdAt).toLocaleDateString('en-IN', { month: 'long', year: 'numeric' });
    if (!groups[key]) groups[key] = [];
    groups[key].push(item);
  });

  container.innerHTML = '';
  Object.entries(groups).forEach(([label, items]) => {
    const groupEl = document.createElement('div');
    groupEl.className = 'tl-group';
    groupEl.innerHTML = `<div class="tl-date-label"><i data-lucide="calendar"></i> ${label}</div>`;

    items.forEach(item => {
      const status = expiryStatus(item.createdAt);
      const dotClass = status === 'expired' ? 'tl-dot-expired' : status === 'soon' ? 'tl-dot-soon' : '';
      const time = new Date(item.createdAt).toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit' });
      const letter = item.app.charAt(0).toUpperCase();

      const tlItem = document.createElement('div');
      tlItem.className = `tl-item ${dotClass}`;
      tlItem.innerHTML = `
        <div class="tl-icon">${letter}</div>
        <div class="tl-content">
          <div class="tl-app">${escapeHtml(item.app)}</div>
          <div class="tl-meta">
            ${item.username ? `<i data-lucide="user"></i> ${escapeHtml(item.username)} &bull; ` : ''}
            <span class="badge badge-${item.strength}" style="font-size:.7rem;padding:2px 8px;">${item.strength}</span>
            &bull; <span class="expiry-tag ${status}" style="font-size:.7rem;padding:2px 8px;">${expiryLabel(item.createdAt)}</span>
          </div>
        </div>
        <div class="tl-right">
          <div class="tl-time">${formatDate(item.createdAt)}</div>
          <div class="tl-time" style="margin-top:2px;">${time}</div>
        </div>
      `;
      lucide.createIcons({ el: tlItem });
      groupEl.appendChild(tlItem);
    });

    container.appendChild(groupEl);
  });
}

// ── Full refresh (fetches from API) ───────────────────────────────────────────

async function refresh(query = '') {
  const res = await _apiCall('GET');
  if (!res) return; // redirected to login

  if (!res.ok) {
    console.error('Failed to load vault entries.');
    return;
  }

  const list = await res.json();
  _vaultCache = list;           // cache for togglePassword
  const reuseMap = getReuseMap(list);

  updateStats(list, reuseMap);
  updateBanners(list, reuseMap);
  renderList(list, reuseMap, query);
  renderTimeline(list);
}

// ── Tab switching ─────────────────────────────────────────────────────────────

function switchTab(tab) {
  document.getElementById('listView').style.display = tab === 'list' ? 'block' : 'none';
  document.getElementById('timelineView').style.display = tab === 'timeline' ? 'block' : 'none';
  document.getElementById('tabList').classList.toggle('active', tab === 'list');
  document.getElementById('tabTimeline').classList.toggle('active', tab === 'timeline');
}
window.switchTab = switchTab;

// ── Password actions ──────────────────────────────────────────────────────────

function togglePassword(id) {
  const el = document.getElementById(`pw-${id}`);
  if (!el) return;
  if (el.textContent === '••••••••') {
    const entry = _vaultCache.find(p => p.id === id);
    if (entry) el.textContent = entry.password;
  } else {
    el.textContent = '••••••••';
  }
}

async function copyPassword(id) {
  const entry = _vaultCache.find(p => p.id === id);
  if (!entry) return;

  await navigator.clipboard.writeText(entry.password);
  showToast('✅ Password copied to clipboard');

  const btns = document.querySelectorAll('.pw-card .icon-btn');
  btns.forEach(b => {
    if (b.getAttribute('onclick') === `copyPassword('${id}')`) {
      const orig = b.innerHTML;
      b.innerHTML = '<i data-lucide="check"></i>';
      lucide.createIcons();
      setTimeout(() => { b.innerHTML = orig; lucide.createIcons(); }, 1200);
    }
  });
}

async function deletePassword(id) {
  if (!confirm('Delete this password entry? This cannot be undone.')) return;

  const res = await _apiCall('DELETE', `/${id}`);
  if (!res) return;
  if (!res.ok) {
    const data = await res.json();
    alert(data.error || 'Failed to delete entry.');
    return;
  }
  refresh(document.getElementById('searchBox').value.trim());
}

/**
 * Copies credentials to clipboard FIRST (before window.open steals focus),
 * then opens the URL in a new tab, then shows a persistent banner so the
 * user can copy the password in a second step when they come back.
 */
async function launchAndFill(id) {
  const entry = _vaultCache.find(p => p.id === id);
  if (!entry || !entry.url) return;

  const rawUrl = entry.url.trim();
  const url = /^https?:\/\//i.test(rawUrl) ? rawUrl : 'https://' + rawUrl;

  try {
    if (entry.username) {
      // Step 1: copy username BEFORE opening the tab (clipboard requires focus)
      await navigator.clipboard.writeText(entry.username);
      // Step 2: open the site
      window.open(url, '_blank', 'noopener,noreferrer');
      // Step 3: show persistent banner so user can copy password when they return
      showFillBanner(entry);
    } else {
      // No username — just copy password then open
      await navigator.clipboard.writeText(entry.password);
      window.open(url, '_blank', 'noopener,noreferrer');
      showToast('🔑 Password copied — paste it into the password field');
    }
  } catch (err) {
    // Clipboard was blocked — fall back to showing the banner with manual copy
    window.open(url, '_blank', 'noopener,noreferrer');
    showFillBanner(entry);
  }
}

/**
 * Shows a persistent "autofill helper" banner at the bottom of the page
 * with one-click copy buttons for username and password.
 */
function showFillBanner(entry) {
  // Remove any existing banner
  document.getElementById('fillBanner')?.remove();

  const banner = document.createElement('div');
  banner.id = 'fillBanner';
  banner.style.cssText = `
    position:fixed; bottom:0; left:0; right:0; z-index:8999;
    background:#1e1b4b; color:#fff;
    padding:14px 24px; display:flex; align-items:center;
    gap:14px; flex-wrap:wrap; box-shadow:0 -4px 24px rgba(0,0,0,0.35);
    font-family:'Playfair Display',serif; font-size:0.88rem;
    animation: slideUp .3s ease;
  `;

  const style = document.createElement('style');
  style.textContent = `@keyframes slideUp { from{transform:translateY(100%)} to{transform:translateY(0)} }`;
  banner.appendChild(style);

  const label = document.createElement('span');
  label.style.cssText = 'flex:1; font-weight:600;';
  label.textContent = '🚀 Site opened — paste credentials in order:';
  banner.appendChild(label);

  function makeBtn(icon, text, value) {
    const btn = document.createElement('button');
    btn.style.cssText = `
      padding:8px 16px; border:none; border-radius:8px; cursor:pointer;
      font-weight:700; font-size:0.82rem; font-family:'Playfair Display',serif;
      background:linear-gradient(135deg,#6366f1,#8b5cf6); color:#fff;
      transition:transform .15s; white-space:nowrap;
    `;
    btn.innerHTML = `${icon} ${text}`;
    btn.onmouseover = () => btn.style.transform = 'translateY(-1px)';
    btn.onmouseout = () => btn.style.transform = '';
    btn.onclick = async () => {
      await navigator.clipboard.writeText(value);
      const orig = btn.innerHTML;
      btn.innerHTML = '✅ Copied!';
      setTimeout(() => { btn.innerHTML = orig; }, 1500);
    };
    return btn;
  }

  if (entry.username) banner.appendChild(makeBtn('👤', '1. Copy Username', entry.username));
  banner.appendChild(makeBtn('🔑', entry.username ? '2. Copy Password' : 'Copy Password', entry.password));

  const close = document.createElement('button');
  close.style.cssText = `
    background:rgba(255,255,255,0.1); border:none; color:#94a3b8;
    border-radius:8px; padding:8px 12px; cursor:pointer;
    font-size:0.82rem; font-family:'Playfair Display',serif;
  `;
  close.textContent = '✕ Dismiss';
  close.onclick = () => banner.remove();
  banner.appendChild(close);

  document.body.appendChild(banner);
}

window.togglePassword = togglePassword;
window.copyPassword = copyPassword;
window.deletePassword = deletePassword;
window.launchAndFill = launchAndFill;


// ── Instagram demo hint ───────────────────────────────────────────────────────

function checkInstagramDemo(value) {
  const hint = document.getElementById('demoHint');
  if (!hint) return;
  hint.classList.toggle('visible', value.trim().toLowerCase() === 'instagram');
}
window.checkInstagramDemo = checkInstagramDemo;

// ── Modal logic ───────────────────────────────────────────────────────────────

function openModal() { document.getElementById('addModal').classList.add('open'); }
function closeModal() {
  document.getElementById('addModal').classList.remove('open');
  document.getElementById('newApp').value = '';
  document.getElementById('newUsername').value = '';
  document.getElementById('newUrl').value = '';
  document.getElementById('newPassword').value = '';
  document.getElementById('modalError').style.display = 'none';
  const hint = document.getElementById('demoHint');
  if (hint) hint.classList.remove('visible');
  previewStrength('');
}

document.getElementById('addPasswordBtn').addEventListener('click', openModal);
document.getElementById('cancelBtn').addEventListener('click', closeModal);
document.getElementById('addModal').addEventListener('click', function (e) {
  if (e.target === this) closeModal();
});

document.getElementById('saveBtn').addEventListener('click', async function () {
  const app = document.getElementById('newApp').value.trim();
  const username = document.getElementById('newUsername').value.trim();
  const url = document.getElementById('newUrl').value.trim();
  const password = document.getElementById('newPassword').value;
  const errEl = document.getElementById('modalError');

  errEl.style.display = 'none';

  if (!app) {
    errEl.textContent = 'Please enter an application or website name.';
    errEl.style.display = 'block';
    return;
  }
  if (!password) {
    errEl.textContent = 'Please enter a password.';
    errEl.style.display = 'block';
    return;
  }

  // Warn if password is reused across sites
  const existing = _vaultCache;
  const reusedApps = existing.filter(p => p.password === password).map(p => p.app);
  if (reusedApps.length > 0) {
    const names = reusedApps.join(', ');
    if (!confirm(`This password is already used for: ${names}.\n\nReusing passwords is a security risk. Save anyway?`)) return;
  }

  const strength = analyzeStrength(password);

  const res = await _apiCall('POST', '', { app, username, url, password, strength });
  if (!res) return;

  const data = await res.json();
  if (!res.ok) {
    errEl.textContent = data.error || 'Failed to save password.';
    errEl.style.display = 'block';
    return;
  }

  closeModal();
  refresh(document.getElementById('searchBox').value.trim());
});

// ── Search ────────────────────────────────────────────────────────────────────

document.getElementById('searchBox').addEventListener('input', function () {
  refresh(this.value.trim());
});

// ── Init ──────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => refresh());
