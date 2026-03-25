const API = 'http://localhost:5001/api';
const PG_ORIGIN = 'http://localhost:5001';

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (msg.type === 'GET_CREDENTIALS') {
        getCredentials(msg.tabUrl).then(sendResponse);
        return true;
    }
});

// Read token directly from the PassGuard tab's localStorage
async function getTokenFromTab() {
    try {
        const allTabs = await chrome.tabs.query({});
        const pgTab = allTabs.find(t => t.url && t.url.startsWith(PG_ORIGIN));
        if (!pgTab) return null;

        const [result] = await chrome.scripting.executeScript({
            target: { tabId: pgTab.id },
            func: () => ({
                token: sessionStorage.getItem('pg_token'),
                name:  sessionStorage.getItem('pg_name') || '',
                email: sessionStorage.getItem('pg_email') || ''
            })
        });

        return result?.result?.token ? result.result : null;
    } catch (_) {
        return null;
    }
}

async function getCredentials(tabUrl) {
    // Always read fresh from the PassGuard tab — no caching issues
    const session = await getTokenFromTab();

    if (!session) return { status: 'not_logged_in' };

    let tabHost = '';
    try { tabHost = new URL(tabUrl).hostname.replace(/^www\./, ''); } catch {}

    try {
        const res = await fetch(`${API}/vault`, {
            headers: {
                'Authorization': `Bearer ${session.token}`,
                'Content-Type': 'application/json'
            }
        });

        if (res.status === 401) return { status: 'not_logged_in' };
        if (!res.ok) return { status: 'error', message: 'Failed to fetch vault.' };

        const all = await res.json();

        const matched = all.filter(entry => {
            if (!entry.url) return false;
            try {
                const raw = entry.url.startsWith('http') ? entry.url : 'https://' + entry.url;
                const entryHost = new URL(raw).hostname.replace(/^www\./, '');
                return (
                    entryHost === tabHost ||
                    tabHost.endsWith('.' + entryHost) ||
                    entryHost.endsWith('.' + tabHost)
                );
            } catch { return false; }
        });

        return { status: 'ok', matched, all, name: session.name, email: session.email };
    } catch {
        return { status: 'server_offline' };
    }
}
