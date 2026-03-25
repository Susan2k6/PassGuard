// ─── PassGuard Extension — Content Script ────────────────────────────────────
// Injected into every page. Listens for FILL_CREDENTIALS and injects values
// into the best-matching username + password fields.

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (msg.type === 'FILL_CREDENTIALS') {
        const result = fillCredentials(msg.username, msg.password);
        sendResponse(result);
    }
});

function fillCredentials(username, password) {
    // Find all visible input fields
    const inputs = [...document.querySelectorAll('input')].filter(isVisible);

    const passwordField = inputs.find(i => i.type === 'password');
    const usernameField = inputs.find(i =>
        ['email', 'text', 'tel'].includes(i.type) &&
        /user|email|login|phone|account|name/i.test(i.name + i.id + i.placeholder + i.autocomplete)
    ) || inputs.find(i => ['email', 'text'].includes(i.type)); // fallback: first text input

    let filled = 0;

    if (usernameField && username) {
        setNativeValue(usernameField, username);
        filled++;
    }
    if (passwordField && password) {
        setNativeValue(passwordField, password);
        filled++;
    }

    return { ok: filled > 0, filled };
}

// Fires both native input events and React synthetic events
function setNativeValue(el, value) {
    const nativeInputValueSetter = Object.getOwnPropertyDescriptor(
        window.HTMLInputElement.prototype, 'value'
    )?.set;

    if (nativeInputValueSetter) {
        nativeInputValueSetter.call(el, value);
    } else {
        el.value = value;
    }

    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
    el.focus();
}

function isVisible(el) {
    return !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length) &&
        getComputedStyle(el).visibility !== 'hidden' &&
        !el.disabled &&
        el.type !== 'hidden';
}
