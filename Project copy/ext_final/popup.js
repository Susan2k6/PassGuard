const root = document.getElementById('root');

async function getActiveTab() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    return tab;
}

function renderLoading() {
    root.innerHTML = `
    <div class="state">
      <div class="state-icon">⏳</div>
      <div class="state-title">Loading…</div>
    </div>`;
}

function renderNotLoggedIn(msg) {
    root.innerHTML = `
    <div class="header">
      <div class="header-icon">🔐</div>
      <div><div class="header-title">PassGuard Autofill</div></div>
    </div>
    <div class="state">
      <div class="state-icon">🔒</div>
      <div class="state-title">Not logged in</div>
      <div class="state-sub">${msg || 'Log in to PassGuard to use autofill.'}</div>
      <button class="open-btn" id="openPassGuard">Open PassGuard & Login</button>
      <button class="open-btn" id="syncBtn"
        style="background:none;border:1.5px solid rgba(99,102,241,0.4);color:#818cf8;margin-top:8px">
        🔄 Sync Now
      </button>
    </div>`;

    document.getElementById('openPassGuard').onclick = () => {
        chrome.tabs.create({ url: 'http://localhost:5001/login.html' });
    };

    document.getElementById('syncBtn').onclick = async () => {
        renderLoading();
        const tab = await getActiveTab();
        const data = await chrome.runtime.sendMessage({ type: 'GET_CREDENTIALS', tabUrl: tab.url });
        if (data.status === 'not_logged_in') {
            renderNotLoggedIn('Still not logged in. Make sure you are logged in at localhost:5001 then click Sync Now.');
            return;
        }
        if (data.status === 'server_offline') { renderOffline(); return; }
        if (data.status === 'error') { renderError(data.message); return; }
        renderCredentials(data, tab);
    };
}

function renderOffline() {
    root.innerHTML = `
    <div class="header">
      <div class="header-icon">🔐</div>
      <div><div class="header-title">PassGuard Autofill</div></div>
    </div>
    <div class="state">
      <div class="state-icon">📡</div>
      <div class="state-title">Server offline</div>
      <div class="state-sub">Run <strong>npm start</strong> in your project folder then try again.</div>
    </div>`;
}

function renderError(msg) {
    root.innerHTML = `
    <div class="state">
      <div class="state-icon">⚠️</div>
      <div class="state-title">Error</div>
      <div class="state-sub">${msg}</div>
    </div>`;
}

function renderCredentials(data, tab) {
    let tabHost = '';
    try { tabHost = new URL(tab.url).hostname.replace(/^www\./, ''); } catch {}

    const matched = data.matched || [];
    const all = (data.all || []).filter(e => !matched.find(m => m.id === e.id));

    root.innerHTML = `
    <div class="header">
      <div class="header-icon">🔐</div>
      <div>
        <div class="header-title">PassGuard Autofill</div>
        <div class="header-sub">${data.name || ''}</div>
      </div>
      <div class="header-right">
        <button class="logout-btn" id="logoutBtn">Sign out</button>
      </div>
    </div>

    <div class="domain-pill">
      <span>🌐</span>
      <span class="domain-name">${tabHost || 'Unknown page'}</span>
    </div>

    ${matched.length > 0 ? `
      <div class="cred-list">${matched.map(e => credCardHtml(e)).join('')}</div>
    ` : `
      <div class="state" style="padding:20px">
        <div class="state-icon">🔍</div>
        <div class="state-title">No saved logins for this site</div>
        <div class="state-sub">No credentials match <strong>${tabHost}</strong>.</div>
      </div>
    `}

    ${all.length > 0 ? `
      <div class="divider"></div>
      <div class="all-section">
        <div class="all-label">All saved logins</div>
        <div>${all.map(e => credCardHtml(e)).join('')}</div>
      </div>
    ` : ''}`;

    document.getElementById('logoutBtn')?.addEventListener('click', () => {
        renderNotLoggedIn();
    });

    document.querySelectorAll('.fill-btn').forEach(btn => {
        btn.addEventListener('click', () => handleFill(btn, tab));
    });
}

function credCardHtml(entry) {
    const letter = (entry.app || '?').charAt(0).toUpperCase();
    return `
    <div class="cred-card">
      <div class="cred-top">
        <div class="cred-avatar">${letter}</div>
        <div class="cred-info">
          <div class="cred-app">${esc(entry.app)}</div>
          <div class="cred-user">${esc(entry.username || '—')}</div>
        </div>
      </div>
      <button class="fill-btn"
        data-username="${esc(entry.username || '')}"
        data-password="${esc(entry.password || '')}">
        🔑 Autofill
      </button>
    </div>`;
}

async function handleFill(btn, tab) {
    const username = btn.dataset.username;
    const password = btn.dataset.password;
    btn.textContent = 'Filling…';
    btn.disabled = true;

    try {
        const [result] = await chrome.scripting.executeScript({
            target: { tabId: tab.id },
            func: fillInPage,
            args: [username, password]
        });

        if (result?.result?.ok) {
            btn.textContent = '✅ Filled!';
            btn.classList.add('success');
        } else {
            btn.textContent = '⚠️ No form found';
            btn.classList.add('error');
        }
    } catch (e) {
        btn.textContent = '❌ Failed';
        btn.classList.add('error');
    }

    setTimeout(() => {
        btn.textContent = '🔑 Autofill';
        btn.disabled = false;
        btn.className = 'fill-btn';
    }, 2500);
}

function fillInPage(username, password) {
    function isVisible(el) {
        return !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length) &&
            getComputedStyle(el).visibility !== 'hidden' &&
            !el.disabled && el.type !== 'hidden';
    }
    function setVal(el, value) {
        const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')?.set;
        if (setter) setter.call(el, value);
        else el.value = value;
        el.dispatchEvent(new Event('input', { bubbles: true }));
        el.dispatchEvent(new Event('change', { bubbles: true }));
    }
    const inputs = [...document.querySelectorAll('input')].filter(isVisible);
    const pwField = inputs.find(i => i.type === 'password');
    const uField = inputs.find(i =>
        ['email', 'text', 'tel'].includes(i.type) &&
        /user|email|login|phone|account|name/i.test(i.name + i.id + i.placeholder + (i.autocomplete || ''))
    ) || inputs.find(i => ['email', 'text'].includes(i.type));

    let filled = 0;
    if (uField && username) { setVal(uField, username); filled++; }
    if (pwField && password) { setVal(pwField, password); filled++; }
    return { ok: filled > 0 };
}

function esc(str) {
    return String(str)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;')
        .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

(async () => {
    renderLoading();
    const tab = await getActiveTab();

    if (!tab?.url || tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://')) {
        renderError('PassGuard cannot autofill browser pages.');
        return;
    }

    const data = await chrome.runtime.sendMessage({ type: 'GET_CREDENTIALS', tabUrl: tab.url });

    if (data.status === 'not_logged_in') { renderNotLoggedIn(); return; }
    if (data.status === 'server_offline') { renderOffline(); return; }
    if (data.status === 'error') { renderError(data.message); return; }

    renderCredentials(data, tab);
})();
