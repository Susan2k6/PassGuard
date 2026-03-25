// ─── PassGuard Auth Module (API-backed) ────────────────────────────────────────
// JWT stored in sessionStorage (cleared when browser/tab is closed).
// Vault OTP flag stored in sessionStorage (cleared when browser closes).

// One-time migration: clear any stale tokens left in localStorage from old builds.
['pg_token', 'pg_name', 'pg_email'].forEach(k => localStorage.removeItem(k));

const API = '/api';

// ── Session helpers ───────────────────────────────────────────────────────────

function getToken() {
  return sessionStorage.getItem('pg_token');
}

function getSession() {
  const token = getToken();
  if (!token) return null;
  return {
    token,
    name: sessionStorage.getItem('pg_name') || '',
    email: sessionStorage.getItem('pg_email') || '',
  };
}

function _saveSession(token, name, email) {
  sessionStorage.setItem('pg_token', token);
  sessionStorage.setItem('pg_name', name);
  sessionStorage.setItem('pg_email', email);
  // Notify the PassGuard content script (passguard_sync.js) via CustomEvent.
  // This is the reliable way to communicate from a page script to the
  // extension content script running in the same tab.
  try {
    window.dispatchEvent(new CustomEvent('pg:login', { detail: { token, name, email } }));
  } catch (_) { }
  // Secondary fallback: direct chrome.runtime call (works on extension pages).
  try {
    chrome.runtime?.sendMessage(
      { type: 'SAVE_TOKEN', token, name, email },
      () => void chrome.runtime.lastError
    );
  } catch (_) { }
}

function _clearSession() {
  sessionStorage.removeItem('pg_token');
  sessionStorage.removeItem('pg_name');
  sessionStorage.removeItem('pg_email');
  sessionStorage.removeItem('pg_vault_verified');
  // Notify content script via CustomEvent
  try { window.dispatchEvent(new CustomEvent('pg:logout')); } catch (_) { }
  // Secondary fallback: direct chrome.runtime call
  try {
    chrome.runtime?.sendMessage(
      { type: 'CLEAR_TOKEN' },
      () => void chrome.runtime.lastError
    );
  } catch (_) { }
}

// ── Auth Guard ────────────────────────────────────────────────────────────────

function requireAuth() {
  if (!getToken()) {
    window.location.href = 'login.html';
  }
}

// ── Vault OTP helpers ─────────────────────────────────────────────────────────

function isVaultVerified() {
  return sessionStorage.getItem('pg_vault_verified') === 'true';
}

function setVaultVerified() {
  sessionStorage.setItem('pg_vault_verified', 'true');
}

/**
 * Sends an OTP to the current user's registered email.
 * @returns {Promise<{ok: boolean, maskedEmail?: string, error?: string}>}
 */
async function sendOtp() {
  try {
    const res = await fetch(`${API}/auth/send-otp`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${getToken()}`,
      },
    });
    const data = await res.json();
    if (!res.ok) return { ok: false, error: data.error || 'Failed to send OTP.' };
    return { ok: true, maskedEmail: data.maskedEmail };
  } catch {
    return { ok: false, error: 'Network error. Please check your connection.' };
  }
}

/**
 * Verifies the submitted OTP.
 * @param {string} otp  6-digit code
 * @returns {Promise<{ok: boolean, error?: string}>}
 */
async function verifyOtp(otp) {
  try {
    const res = await fetch(`${API}/auth/verify-otp`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${getToken()}`,
      },
      body: JSON.stringify({ otp }),
    });
    const data = await res.json();
    if (!res.ok) return { ok: false, error: data.error || 'Verification failed.' };
    setVaultVerified();
    return { ok: true };
  } catch {
    return { ok: false, error: 'Network error. Please check your connection.' };
  }
}


// ── API calls ─────────────────────────────────────────────────────────────────

/**
 * Registers a new account.
 * @returns {Promise<{ok: boolean, error?: string}>}
 */
async function signUp(name, email, password) {
  try {
    const res = await fetch(`${API}/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, email, password }),
    });
    const data = await res.json();
    if (!res.ok) return { ok: false, error: data.error || 'Registration failed.' };
    return { ok: true };
  } catch {
    return { ok: false, error: 'Network error. Please check your connection.' };
  }
}

/**
 * Logs in an existing user.
 * @returns {Promise<{ok: boolean, error?: string}>}
 */
async function login(email, password) {
  try {
    const res = await fetch(`${API}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });
    const data = await res.json();
    if (!res.ok) return { ok: false, error: data.error || 'Login failed.' };
    _saveSession(data.token, data.name, data.email);
    return { ok: true };
  } catch {
    return { ok: false, error: 'Network error. Please check your connection.' };
  }
}

/**
 * Logs out the current user and redirects to the login page.
 */
function logout() {
  _clearSession();
  window.location.href = 'login.html';
}

// ── Navbar injection ──────────────────────────────────────────────────────────

function updateNavbar() {
  const session = getSession();
  const navLinks = document.querySelector('.nav-links');
  if (!navLinks) return;

  // Remove any existing auth element to avoid double-injection
  const existing = navLinks.querySelector('.nav-auth');
  if (existing) existing.remove();

  if (!session) return;

  const authEl = document.createElement('span');
  authEl.className = 'nav-auth';
  authEl.innerHTML = `
    <span class="nav-user"><i data-lucide="user"></i> ${session.name.split(' ')[0]}</span>
    <button class="nav-logout-btn" onclick="logout()">Logout</button>
  `;
  navLinks.appendChild(authEl);
  if (window.lucide) lucide.createIcons();
}

document.addEventListener('DOMContentLoaded', updateNavbar);
