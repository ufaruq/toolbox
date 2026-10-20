'use strict';
const $ = id => document.getElementById(id);
let csrf = '', reviewed = null, reviewGeneration = 0, uiEpoch = 0, resultGeneration = 0, approvedFile = '';
let pickerReady = null;
const tool = 'google_drive.read_document.v1';
const approvalReturnKey = 'toolbox.approvalReturn';
const validApprovalPath = path => /^\/approve\/[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/i.test(path);
function restoreApprovalPath() {
 let path = '';
 try { path = sessionStorage.getItem(approvalReturnKey) || ''; sessionStorage.removeItem(approvalReturnKey); } catch (_) { return; }
 if (location.pathname === '/' && validApprovalPath(path)) history.replaceState(null, '', path);
}
async function request(path, data, agent = false, delegation = '') {
 const headers = {};
 if (data !== undefined) headers['Content-Type'] = 'application/json';
 if (agent) headers.Authorization = 'Bearer ' + $('agent-credential').value.trim();
 else if (data !== undefined) headers['X-CSRF-Token'] = csrf;
 if (delegation) headers['Toolbox-Delegation'] = delegation;
 const response = await fetch(path, {method: data === undefined ? 'GET' : 'POST', credentials: agent ? 'omit' : 'same-origin', headers, body: data === undefined ? undefined : JSON.stringify(data), cache: 'no-store'});
 const value = await response.json();
 if (!response.ok) { const error = new Error(value.error || 'Request failed'); error.status = response.status; throw error; }
 return value;
}
function action(id, work) {
 $(id).addEventListener('click', async () => {
  $(id).disabled = true; $('status').textContent = '';
  try { await work(); } catch (error) { $('status').textContent = error.message; if (id === 'connect' || id === 'pick') $('connection-status').textContent = error.message; }
  finally { $(id).disabled = id === 'approve' ? !reviewed : id === 'request' ? !$('file-id').value : false; }
 });
}
function invalidateReview() { reviewGeneration++; reviewed = null; $('approve').disabled = true; $('review-details').hidden = true; }
function clearDocument() { $('file-id').value = ''; $('selected-document').textContent = 'No document selected.'; $('request').disabled = true; invalidateReview(); }
function clearResult() { resultGeneration++; approvedFile = ''; $('grant-id').value = ''; $('document').textContent = ''; $('result-panel').hidden = true; }
function showSignedOut() {
 uiEpoch++; resultGeneration++; csrf = ''; approvedFile = ''; invalidateReview();
 $('callers-panel').hidden = true; $('caller-list').replaceChildren();
 $('workspace').hidden = true; $('login-panel').hidden = false; $('logout').hidden = true;
 $('agent-credential').value = ''; $('agent-id').textContent = ''; $('document').textContent = ''; $('audit-output').textContent = '';
 $('request-id').value = ''; $('grant-id').value = ''; $('result-panel').hidden = true; $('approval-panel').hidden = true;
 clearDocument();
}
async function loadConnections(preferred = '') {
 const epoch = uiEpoch, list = await request('/v1/connections');
 if (epoch !== uiEpoch) return;
 const previous = preferred || $('connection').value;
 const active = list.filter(c => c.status === 'active');
 $('connection').replaceChildren();
 for (const c of active) $('connection').add(new Option('Google account ' + c.account_subject + ' · ' + c.id.slice(0,8), c.id));
 if (active.some(c => c.id === previous)) $('connection').value = previous;
 const connected = active.length > 0;
 $('connected-settings').hidden = !connected; $('document-panel').hidden = !connected;
 $('connection-badge').textContent = connected ? 'Connected' : 'Not connected';
 $('connection-badge').classList.toggle('connected', connected);
 $('connect').textContent = connected ? 'Connect another account ↗' : 'Connect Google account ↗';
 const current = active.find(c => c.id === $('connection').value);
 $('connection-info').textContent = current ? 'Verified Google account subject: ' + current.account_subject + '\nConnection: ' + current.id : '';
}
async function signedIn() {
 const session = await request('/v1/session');
 if (session.fixture || session.owner_only) throw new Error('Live Workspace mode is unavailable.');
 csrf = session.csrf_token;
 restoreApprovalPath();
 $('login-panel').hidden = true; $('workspace').hidden = false; $('logout').hidden = false;
 const result = new URLSearchParams(location.hash.slice(1));
 await loadConnections(result.get('connection_id') || '');
 if (session.mcp) await loadCallers();
 if (result.has('connection')) {
  const messages = {connected: 'Connected to your Google account. Choose a document below.', cancelled: 'Google connection cancelled. You can try again.', failed: 'Google connection could not be completed. Check the configured scopes and consent, then reconnect.'};
  $('connection-status').textContent = messages[result.get('connection')] || '';
  history.replaceState(null, '', location.pathname);
 }
 if (location.pathname.startsWith('/approve/')) { $('request-id').value = location.pathname.split('/')[2]; $('approval-panel').hidden = false; }
}
action('login', async () => {
 const path = validApprovalPath(location.pathname) ? location.pathname : '';
 // Only a local request path survives the redirect. Credentials stay in memory,
 // and the server still authorizes the restored request independently.
 try { sessionStorage.removeItem(approvalReturnKey); if (path) sessionStorage.setItem(approvalReturnKey, path); }
 catch (_) { if (path) throw new Error('Enable tab storage to return to this approval request after sign-in.'); }
 const value = await request('/auth/oidc/start', {}); location.assign(value.authorization_url);
});
action('logout', async () => {
 try { await request('/v1/session/logout', {}); }
 catch (error) {
  if (error.status !== 403) throw error;
  try { await request('/v1/session'); } catch (current) { if (current.status === 403) { showSignedOut(); $('status').textContent = 'Your Toolbox session has ended.'; return; } throw current; }
  throw error;
 }
 showSignedOut(); $('status').textContent = 'Signed out of Toolbox. Your Okta session may still be active.';
});
action('connect', async () => { $('connection-status').textContent = 'Opening Google consent…'; const value = await request('/v1/connections/google/start', {}); location.assign(value.authorization_url); });
action('disconnect', async () => {
 const id = $('connection').value; if (!id) throw new Error('Choose a connected account.');
 await request('/v1/connections/' + encodeURIComponent(id) + '/disconnect', {});
 resultGeneration++;
 clearDocument(); $('result-panel').hidden = true; $('approval-panel').hidden = true; $('document').textContent = ''; approvedFile = '';
 await loadConnections(); $('connection-status').textContent = 'Account disconnected. All grants are blocked; Google cleanup is queued.';
});
function loadPicker() {
 if (!pickerReady) pickerReady = new Promise((resolve, reject) => {
  const script = document.createElement('script'); script.src = 'https://apis.google.com/js/api.js'; script.async = true;
  script.onerror = () => { pickerReady = null; script.remove(); reject(new Error('Google Picker could not load. Check your connection and try again.')); };
  script.onload = () => { gapi.load('picker', {callback: resolve, onerror: () => { pickerReady = null; reject(new Error('Google Picker is unavailable.')); }, timeout: 10000, ontimeout: () => { pickerReady = null; reject(new Error('Google Picker timed out.')); }}); };
  document.head.append(script);
 });
 return pickerReady;
}
action('pick', async () => {
 const connection = $('connection').value, epoch = uiEpoch;
 if (!connection) throw new Error('Connect a Google account first.');
 await loadPicker();
 const config = await request('/v1/workspace/config');
 const lease = await request('/v1/connections/' + encodeURIComponent(connection) + '/picker-token', {});
 if (epoch !== uiEpoch || connection !== $('connection').value) { lease.access_token = ''; return; }
 await new Promise((resolve, reject) => {
  let picker, timer;
  const close = () => { clearTimeout(timer); picker?.setVisible(false); picker?.dispose?.(); picker = null; resolve(); };
  const callback = data => {
   if (data.action === google.picker.Action.CANCEL) { close(); return; }
   if (data.action !== google.picker.Action.PICKED) return;
   const doc = data.docs?.[0];
   if (epoch === uiEpoch && connection === $('connection').value && doc && /^[A-Za-z0-9_-]{1,256}$/.test(doc.id) && doc.mimeType === 'application/vnd.google-apps.document') {
    invalidateReview(); $('file-id').value = doc.id; $('selected-document').textContent = doc.name || 'Selected Google Doc'; $('request').disabled = false;
   }
   close();
  };
  try {
   const view = new google.picker.View(google.picker.ViewId.DOCS); view.setMimeTypes('application/vnd.google-apps.document');
   picker = new google.picker.PickerBuilder().setDeveloperKey(config.picker_api_key).setAppId(config.project_number).setOAuthToken(lease.access_token).setOrigin(location.origin).addView(view).setCallback(callback).build();
   lease.access_token = '';
   timer = setTimeout(close, Math.max(0, Date.parse(lease.expires_at) - Date.now() - 30000));
   picker.setVisible(true);
  } catch (_) { lease.access_token = ''; clearTimeout(timer); picker?.dispose?.(); reject(new Error('Google Picker could not open. Check the API key and project settings.')); }
 });
});
async function createAgent() { const epoch = uiEpoch, a = await request('/v1/agents', {name: $('agent-name').value}); if (epoch !== uiEpoch) return; $('agent-credential').value = a.credential; $('agent-id').textContent = 'Agent: ' + a.agent_id; }
action('create-agent', async () => { await createAgent(); $('status').textContent = 'Test agent created. Save its credential now if you need it outside this tab.'; });
action('request', async () => {
 const file = $('file-id').value, epoch = uiEpoch;
 if (!file) throw new Error('Choose a document first.');
 if (!$('agent-credential').value) await createAgent();
 if (epoch !== uiEpoch) return;
 const q = await request('/v1/delegation-requests', {tool, file_id: file, duration_seconds: Number($('duration').value)}, true);
 if (epoch !== uiEpoch || file !== $('file-id').value) return;
 invalidateReview(); $('request-id').value = q.request_id; $('approval-panel').hidden = false; $('approval-status').textContent = 'Request pending. Review the verified document before approving.';
});
action('review', async () => {
 invalidateReview(); const requestId = $('request-id').value, connection = $('connection').value, generation = reviewGeneration;
 if (!requestId || !connection) throw new Error('Choose a connection and enter a request ID.');
 const q = await request('/v1/delegation-requests/' + encodeURIComponent(requestId) + '/review', {connection_id: connection});
 if (generation !== reviewGeneration || requestId !== $('request-id').value || connection !== $('connection').value) return;
 reviewed = q;
 $('review-details').textContent = 'Agent: ' + q.agent_name + '\nVerified agent ID: ' + q.agent_id + '\nVerified client: ' + (q.verified_client || 'Independent HTTP test credential') + '\nGoogle account: ' + q.account_subject + '\nDocument: ' + q.document_name + '\nDocument ID: ' + q.file_id + '\nExpires: ' + q.expires_at + '\n\n' + q.description + '\n\n' + q.provider_scope_notice;
 $('review-details').hidden = false; $('approve').disabled = false;
});
action('approve', async () => {
 if (!reviewed) throw new Error('Review the request first.');
 const snapshot = reviewed, epoch = uiEpoch, generation = reviewGeneration;
 const q = await request('/v1/delegation-requests/' + encodeURIComponent(snapshot.request_id) + '/approve', {connection_id: snapshot.connection_id, version: snapshot.version, digest: snapshot.digest});
 if (epoch !== uiEpoch || generation !== reviewGeneration || snapshot.connection_id !== $('connection').value || snapshot.request_id !== $('request-id').value) return;
 resultGeneration++; approvedFile = snapshot.file_id; $('grant-id').value = q.grant_id; invalidateReview();
 $('approval-status').textContent = 'Approved for this document only.'; $('result-panel').hidden = false; $('grant-badge').textContent = 'Approved'; $('document').textContent = 'The document has not been read yet.';
});
action('deny', async () => { await request('/v1/delegation-requests/' + encodeURIComponent($('request-id').value) + '/deny', {}); invalidateReview(); $('approval-status').textContent = 'Request denied. No document access was granted.'; });
action('read', async () => {
 const grant = $('grant-id').value, epoch = uiEpoch, generation = resultGeneration, file = approvedFile;
 const token = await request('/v1/delegation-tokens', {grant_id: grant}, true);
 const value = await request('/v1/tool-invocations', {tool, grant_id: grant, arguments: {file_id: file}}, true, token.delegation_token);
 if (epoch !== uiEpoch || generation !== resultGeneration || grant !== $('grant-id').value) return;
 $('document').textContent = value.content; $('status').textContent = 'Read ' + value.bytes + ' bytes from the approved Google Doc.';
});
action('revoke', async () => {
 const grant = $('grant-id').value, epoch = uiEpoch, generation = resultGeneration;
 await request('/v1/grants/' + encodeURIComponent(grant) + '/revoke', {});
 if (epoch !== uiEpoch || generation !== resultGeneration || grant !== $('grant-id').value) return;
 resultGeneration++; $('grant-badge').textContent = 'Revoked'; $('document').textContent = 'Access revoked. Previously returned text cannot be recalled.'; $('status').textContent = 'Further reads through this grant are blocked.';
});
action('audit', async () => { $('audit-output').textContent = JSON.stringify(await request('/v1/audit'), null, 2); });
$('connection').addEventListener('change', () => { clearDocument(); clearResult(); $('connection-info').textContent = 'Connection: ' + $('connection').value; });
$('request-id').addEventListener('input', () => { invalidateReview(); $('approval-panel').hidden = !$('request-id').value; });
$('file-id').addEventListener('input', () => { invalidateReview(); $('request').disabled = !$('file-id').value; $('selected-document').textContent = $('file-id').value ? 'Document ID entered manually; verify its name during review.' : 'No document selected.'; });
async function loadCallers() {
 const epoch = uiEpoch;
 const value = await request('/v1/callers');
 if (epoch !== uiEpoch) return;
 const previous = $('caller-client').value;
 $('caller-client').replaceChildren();
 for (const [id, label] of Object.entries(value.clients)) $('caller-client').add(new Option(label + ' · ' + id, id));
 if ([...$('caller-client').options].some(x => x.value === previous)) $('caller-client').value = previous;
 $('callers-panel').hidden = false;
 $('caller-list').replaceChildren();
 for (const profile of value.callers) {
  const row = document.createElement('div'), identity = document.createElement('p'), detail = document.createElement('p');
  identity.textContent = profile.label + ' · ' + (value.clients[profile.client_id] || profile.client_id);
  detail.textContent = 'Verified client: ' + profile.client_id + ' · Agent: ' + profile.agent_id + ' · ' + profile.status + ' · Expires: ' + profile.expires_at + ' · Tools: ' + (profile.tools.join(', ') || 'None');
  row.append(identity, detail);
  const disable = document.createElement('button'); disable.textContent = 'Disable'; disable.disabled = profile.status === 'disabled';
  const enable = document.createElement('button'); enable.textContent = 'Apply selected tools and duration';
  for (const [button, operation] of [[disable, 'disable'], [enable, 'enable']]) {
   button.addEventListener('click', async () => {
    button.disabled = true; $('status').textContent = '';
    try {
     await request('/v1/callers/' + profile.id + '/' + operation, operation === 'disable' ? {} : callerPermissions());
     if (epoch !== uiEpoch) return;
     invalidateReview(); clearResult(); await loadCallers();
     $('status').textContent = operation === 'disable' ? 'Caller disabled. Grants revoked and pending requests cancelled.' : 'Caller approval updated for all valid tokens of this app. New document approval is required.';
    } catch (error) { $('status').textContent = error.message; button.disabled = false; }
   });
   row.append(button);
  }
  $('caller-list').append(row);
 }
}
function callerPermissions() { return {tools: $('caller-tool').checked ? ['google_drive.read_document.v1'] : [], duration_seconds: Number($('caller-duration').value)}; }
action('create-caller', async () => { const epoch = uiEpoch; await request('/v1/callers', {client_id: $('caller-client').value, label: $('caller-label').value, ...callerPermissions()}); if (epoch !== uiEpoch) return; await loadCallers(); $('status').textContent = 'Caller approved. Each document still needs its own approval.'; });

signedIn().catch(error => { if (error.status === 403) showSignedOut(); else $('status').textContent = 'Could not load your session: ' + error.message; });
