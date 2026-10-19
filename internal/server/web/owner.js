'use strict';

const element = id => document.getElementById(id);
let csrfToken = '';
let ready = false;

async function request(path, data) {
  const headers = {};
  if (data !== undefined) {
    headers['Content-Type'] = 'application/json';
    if (csrfToken) headers['X-CSRF-Token'] = csrfToken;
  }
  const response = await fetch(path, {
    method: data === undefined ? 'GET' : 'POST',
    headers,
    body: data === undefined ? undefined : JSON.stringify(data),
    credentials: 'same-origin',
    cache: 'no-store',
  });
  if (!response.ok) {
    const error = new Error('The request could not be completed. Please try again.');
    error.status = response.status;
    throw error;
  }
  return response.json();
}

function showSignedOut() {
  csrfToken = '';
  element('owner-id').textContent = '';
  element('owner-panel').hidden = true;
  element('login-panel').hidden = false;
  element('login').disabled = !ready;
}

async function loadSession() {
  let session;
  try {
    session = await request('/v1/session');
  } catch (error) {
    if (error.status !== 401 && error.status !== 403) throw error;
    showSignedOut();
    return;
  }
  if (session.fixture !== false || session.owner_only !== true ||
      typeof session.user_id !== 'string' || !session.user_id ||
      typeof session.csrf_token !== 'string' || !session.csrf_token) {
    throw new Error('Owner sign-in is unavailable.');
  }
  csrfToken = session.csrf_token;
  element('owner-id').textContent = session.user_id;
  element('login-panel').hidden = true;
  element('owner-panel').hidden = false;
}

function action(id, work) {
  element(id).addEventListener('click', async () => {
    const button = element(id);
    button.disabled = true;
    element('status').textContent = '';
    try {
      await work();
    } catch (error) {
      element('status').textContent = error.message;
    } finally {
      button.disabled = id === 'login' ? !ready : false;
    }
  });
}

action('login', async () => {
  if (!ready) return;
  const result = await request('/auth/oidc/start', {});
  const destination = new URL(result.authorization_url);
  if (destination.protocol !== 'https:' || destination.username || destination.password) {
    throw new Error('Owner sign-in is unavailable.');
  }
  window.location.assign(destination.href);
});

action('logout', async () => {
  try {
    await request('/v1/session/logout', {});
  } catch (error) {
    if (error.status === 401 || error.status === 403) await loadSession();
    throw error;
  }
  showSignedOut();
  element('status').textContent = 'Signed out of Toolbox. Your Okta session may still be active.';
});

(async () => {
  try {
    const config = await request('/v1/auth/config');
    if (config.fixture !== false || config.owner_only !== true ||
        config.login_url !== '/auth/oidc/start') {
      throw new Error('Owner sign-in is unavailable.');
    }
    ready = true;
    await loadSession();
  } catch (error) {
    ready = false;
    element('login').disabled = true;
    element('status').textContent = 'Owner sign-in is unavailable. Reload to try again.';
  }
})();
