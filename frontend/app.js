// Shared helpers. Loaded in <head> (after config.js) so every page can use them.
// NOTE: no Shopify keys, secrets or tokens ever live in the frontend.
const API_BASE = (window.API_BASE || '').replace(/\/$/, '');

// fetch() against the FastAPI backend; sends the session cookie.
function apiFetch(path, options = {}) {
  return fetch(API_BASE + path, { credentials: 'include', ...options });
}

// Full URL for browser navigations (e.g. the Shopify OAuth start).
function apiUrl(path) { return API_BASE + path; }

function esc(v) {
  const d = document.createElement('div');
  d.textContent = v == null ? '' : String(v);
  return d.innerHTML;
}

// Only allow http(s) links from backend/Shopify data.
function safeUrl(u) { return /^https?:\/\//i.test(u || '') ? u : ''; }

async function logout() {
  await apiFetch('/auth/logout', { method: 'POST' });
  window.location.href = 'login.html';
}
