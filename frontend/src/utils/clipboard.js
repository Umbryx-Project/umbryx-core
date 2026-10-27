// navigator.clipboard (the Clipboard API) only exists in a secure context —
// HTTPS, or http://localhost. Every airgap/on-prem install so far has been
// reached over plain HTTP via the server's real hostname/IP (same class of
// issue as the COOKIE_SECURE bug), where navigator.clipboard is undefined —
// so every copy button across the app silently (or, for call sites missing
// the `?.`, with a thrown TypeError) did nothing. This falls back to the
// legacy execCommand('copy') path, which still works without a secure
// context, whenever the modern API isn't available.
export function copyToClipboard(text) {
  if (text === undefined || text === null) return Promise.reject(new Error('Nothing to copy'));
  const str = String(text);

  if (navigator.clipboard && window.isSecureContext) {
    return navigator.clipboard.writeText(str);
  }

  return new Promise((resolve, reject) => {
    const el = document.createElement('textarea');
    el.value = str;
    el.setAttribute('readonly', '');
    el.style.position = 'fixed';
    el.style.opacity = '0';
    el.style.pointerEvents = 'none';
    document.body.appendChild(el);
    el.select();
    el.setSelectionRange(0, str.length);
    try {
      const ok = document.execCommand('copy');
      ok ? resolve() : reject(new Error('Copy command failed'));
    } catch (e) {
      reject(e);
    } finally {
      document.body.removeChild(el);
    }
  });
}
