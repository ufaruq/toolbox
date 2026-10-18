'use strict';
const $ = id => document.getElementById(id);
let csrf = '', reviewed = null, reviewGeneration = 0;
async function request(path, data, agent = false, delegation = '') {
 const headers = {};
 if (data !== undefined) headers['Content-Type'] = 'application/json';
 if (agent) headers.Authorization = 'Bearer ' + $('agent-credential').value.trim();
 else if (data !== undefined) headers['X-CSRF-Token'] = csrf;
 if (delegation) headers['Toolbox-Delegation'] = delegation;
 const response = await fetch(path, {method: data === undefined ? 'GET' : 'POST', headers, body: data === undefined ? undefined : JSON.stringify(data), cache: 'no-store'});
 const value = await response.json();
 if (!response.ok) throw new Error(value.error || 'Request failed');
 return value;
}
function action(id, work) { $(id).addEventListener('click', async () => { const button = $(id); button.disabled = true; $('status').textContent = ''; try { await work(); } catch (error) { $('status').textContent = error.message; } finally { button.disabled = id === 'approve' ? !reviewed : false; } }); }
function invalidateReview() { reviewGeneration++; reviewed = null; $('approve').disabled = true; $('review-details').hidden = true; }
async function loadConnections() { const list = await request('/v1/connections'); const previous = $('connection').value; $('connection').replaceChildren(new Option('Choose an active connection', '')); for (const item of list) { if(item.status === 'active') $('connection').add(new Option(item.account_subject + ' · ' + item.id, item.id)); } if ([...$('connection').options].some(x=>x.value===previous)) $('connection').value=previous; if (!previous && $('connection').options.length===2) $('connection').selectedIndex=1; $('connection-info').textContent = list.map(c=>c.status + ': ' + c.account_subject).join(' | '); }
async function signedIn() { const session = await request('/v1/session'); csrf=session.csrf_token; $('login-panel').hidden=true; $('workspace').hidden=false; $('fixture-notice').hidden=!session.fixture; await loadConnections(); if(location.pathname.startsWith('/approve/')) $('request-id').value=location.pathname.split('/')[2]; }
action('login', async()=>{ const session=await request('/fixture/login',{});csrf=session.csrf_token;await signedIn();$('status').textContent='Signed in to the local fixture.'; });
action('connect', async()=>{const value=await request('/v1/connections/google/start',{});location.assign(value.authorization_url);});
action('disconnect',async()=>{if(!$('connection').value)throw new Error('Choose a connection first.');await request('/v1/connections/'+$('connection').value+'/disconnect',{});invalidateReview();await loadConnections();$('status').textContent='Connection blocked. Cleanup is queued.';});
action('create-agent',async()=>{const a=await request('/v1/agents',{name:$('agent-name').value});$('agent-credential').value=a.credential;$('agent-id').textContent='Agent: '+a.agent_id;$('status').textContent='Agent created. Save its credential now; it will not be shown again.';});
action('request',async()=>{const q=await request('/v1/delegation-requests',{tool:'google_drive.read_document.v1',file_id:$('file-id').value,duration_seconds:Number($('duration').value)},true);$('request-id').value=q.request_id;invalidateReview();const a=document.createElement('a');a.href=q.approval_url;a.textContent='Open trusted approval page';$('approval-link').replaceChildren(a);$('status').textContent='Request pending. Owner approval is required.';});
action('review',async()=>{invalidateReview();const requestId=$('request-id').value,connectionId=$('connection').value,generation=reviewGeneration;const q=await request('/v1/delegation-requests/'+requestId+'/review',{connection_id:connectionId});if(generation!==reviewGeneration||requestId!==$('request-id').value||connectionId!==$('connection').value)return;reviewed=q;$('review-details').textContent='Agent: '+q.agent_name+'\nVerified agent ID: '+q.agent_id+'\nGoogle account subject: '+q.account_subject+'\nTool: '+q.tool+'\nDocument: '+q.document_name+' ('+q.file_id+')\nExpires: '+q.expires_at+'\n\n'+q.description+'\n\n'+q.provider_scope_notice;$('review-details').hidden=false;$('approve').disabled=false;});
action('approve',async()=>{if(!reviewed)throw new Error('Review the request first.');const q=await request('/v1/delegation-requests/'+reviewed.request_id+'/approve',{connection_id:reviewed.connection_id,version:reviewed.version,digest:reviewed.digest});$('grant-id').value=q.grant_id;invalidateReview();$('approval-status').textContent='Approved. Grant: '+q.grant_id;$('status').textContent='The exact document read is approved.';});
action('deny',async()=>{await request('/v1/delegation-requests/'+$('request-id').value+'/deny',{});invalidateReview();$('approval-status').textContent='Request denied.';});
action('read',async()=>{const token=await request('/v1/delegation-tokens',{grant_id:$('grant-id').value},true);const result=await request('/v1/tool-invocations',{tool:'google_drive.read_document.v1',grant_id:$('grant-id').value,arguments:{file_id:$('file-id').value}},true,token.delegation_token);$('document').textContent=result.content;$('status').textContent='Read '+result.bytes+' bytes. Content is untrusted data.';});
action('revoke',async()=>{await request('/v1/grants/'+$('grant-id').value+'/revoke',{});$('document').textContent='Grant revoked. Previously returned content cannot be recalled.';$('status').textContent='Grant revoked. Future dispatches will be denied.';});
action('audit',async()=>{$('audit-output').textContent=JSON.stringify(await request('/v1/audit'),null,2);});
$('connection').addEventListener('change',invalidateReview);$('request-id').addEventListener('input',invalidateReview);
signedIn().catch(()=>{});
