// ─── PassGuard Dashboard (API-backed) ─────────────────────────────────────────

document.addEventListener('DOMContentLoaded', function () {
  updateDashboard();
});

async function updateDashboard() {
  const token = sessionStorage.getItem('pg_token');
  if (!token) return; // requireAuth() in HTML will redirect

  let passwords = [];

  try {
    const res = await fetch('/api/vault', {
      headers: {
        'Authorization': `Bearer ${token}`,
      },
    });

    if (res.status === 401) {
      sessionStorage.clear();
      window.location.href = 'login.html';
      return;
    }

    if (!res.ok) {
      console.error('Failed to fetch vault data for dashboard.');
      return;
    }

    passwords = await res.json();
  } catch (err) {
    console.error('Dashboard fetch error:', err);
    return;
  }

  // ── Calculate statistics ──
  const total  = passwords.length;
  const strong = passwords.filter(p => p.strength === 'strong').length;
  const medium = passwords.filter(p => p.strength === 'medium').length;
  const weak   = passwords.filter(p => p.strength === 'weak').length;

  // ── Update count displays ──
  document.getElementById('totalCount').textContent  = total;
  document.getElementById('strongCount').textContent = strong;
  document.getElementById('mediumCount').textContent = medium;
  document.getElementById('weakCount').textContent   = weak;

  // ── Calculate percentages ──
  const strongPercent = total > 0 ? Math.round((strong / total) * 100) : 0;
  const mediumPercent = total > 0 ? Math.round((medium / total) * 100) : 0;
  const weakPercent   = total > 0 ? Math.round((weak   / total) * 100) : 0;

  // ── Update strength overview bars ──
  document.getElementById('strongBar').style.width     = `${strongPercent}%`;
  document.getElementById('strongPercent').textContent = `${strongPercent}%`;

  document.getElementById('mediumBar').style.width     = `${mediumPercent}%`;
  document.getElementById('mediumPercent').textContent = `${mediumPercent}%`;

  document.getElementById('weakBar').style.width     = `${weakPercent}%`;
  document.getElementById('weakPercent').textContent = `${weakPercent}%`;

  // ── Display recent passwords (max 5) ──
  displayRecentPasswords(passwords);
}

function displayRecentPasswords(passwords) {
  const recentList = document.getElementById('recentList');
  recentList.innerHTML = '';

  if (passwords.length === 0) {
    recentList.innerHTML = '<p style="text-align:center;color:var(--muted);padding:20px;">No passwords saved yet.</p>';
    return;
  }

  const recent = passwords
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
    .slice(0, 5);

  recent.forEach(item => {
    const card       = document.createElement('div');
    card.className   = 'card';
    card.innerHTML   = `
      <div>
        <strong>${escapeHtml(item.app)}</strong>
        <div class="meta">${item.username ? escapeHtml(item.username) : 'No username'}</div>
      </div>
      <div class="meta">•••••••• <small>${item.strength.charAt(0).toUpperCase() + item.strength.slice(1)}</small></div>
    `;
    recentList.appendChild(card);
  });
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}
