'use strict';
const $ = id => document.getElementById(id);
let csrf = '', reviewed = null, generation = 0;
async function api(path, data) {
 const response = await fetch(path, {method: data === undefined ? 'GET' : 'POST', credentials: 'same-origin', headers: data === undefined ? {} : {'Content-Type':'application/json','X-CSRF-Token':csrf}, body: data === undefined ? undefined : JSON.stringify(data)});
 const value = await response.json();
 if (!response.ok) { const error = new Error(value.error || 'Request failed'); error.status = response.status; throw error; }
 return value;
}
function invalidate() { generation++; reviewed = null; $('review').hidden = true; $('approve').disabled = $('deny').disabled = true; }
function action(button, fn) { button.addEventListener('click', async () => { button.disabled = true; try { await fn(); } catch (error) { $('status').textContent = error.message; } finally { if (button.isConnected && button !== $('approve') && button !== $('deny')) button.disabled = false; } }); }
function item(parent, title, detail) { const row = document.createElement('div'), heading = document.createElement('h3'), note = document.createElement('p'); heading.textContent = title; note.textContent = detail; note.className = 'hint'; row.append(heading,note); parent.append(row); return row; }
function button(row,label,fn) { const b = document.createElement('button'); b.textContent = label; b.className = 'outline'; row.append(b); action(b,fn); return b; }
function field(label,value) { const dt=document.createElement('dt'),dd=document.createElement('dd'); dt.textContent=label;dd.textContent=value;dd.className='mono';$('review-details').append(dt,dd); }
async function review(id) {
 invalidate(); const epoch=generation;
 const value=await api('/v1/github/requests/'+encodeURIComponent(id)+'/review',{});
 if(epoch!==generation)return;
 reviewed=value;const q=value.request,scope=q.Scope;
 $('review-title').textContent=value.repository;
 $('review-details').replaceChildren();
 for(const [label,text] of [['Agent',value.agent_name+' · '+q.AgentID],['Repository ID',value.repository_id],['Actions',scope.Actions.join(', ')],['Head / working branches',(scope.Branches||[]).join(', ')||'None'],['Base branches',(scope.BaseBranches||[]).join(', ')||'None'],['File paths',(scope.Paths||[]).join(', ')||'None'],['Pull requests',(scope.PullRequests||[]).join(', ')||'None'],['Approved revision',scope.ExpectedHead||'None'],['Expires',new Date(q.ExpiresAt).toLocaleString()],['Review valid until',new Date(q.ReviewExpiresAt).toLocaleString()]])field(label,text);
 $('write-notice').hidden=!scope.AllowUnconditionalWrites;
 $('pr-notice').hidden=!scope.Actions.some(x=>x.startsWith('prs.')&&x!=='prs.read');
 $('review').hidden=false;$('approve').disabled=$('deny').disabled=false;
 $('status').textContent='Review every field before approving. Paths ending in / include their descendants.';
}
async function load() {
 invalidate(); const epoch=generation;
 const state=await api('/v1/github/state');if(epoch!==generation)return;
 for(const id of ['connections','requests','grants'])$(id).replaceChildren();
 for(const c of state.connections){const row=item($('connections'),c.RepositoryOwner+'/'+c.RepositoryName,c.Status+' · Repository '+c.RepositoryID);if(c.Status==='active')button(row,'Disconnect',async()=>{await api('/v1/github/connections/'+encodeURIComponent(c.ID)+'/disconnect',{});await load();$('status').textContent='Disconnected. Repository grants are revoked.';});}
 const pending=state.requests.filter(q=>q.Status==='pending'&&Date.parse(q.ReviewExpiresAt)>Date.now()&&Date.parse(q.ExpiresAt)>Date.now());
 if(!pending.length)$('requests').textContent='No pending requests.';
 for(const q of pending){const row=item($('requests'),q.Scope.Actions.join(', '),'Agent '+q.AgentID+' · Expires '+new Date(q.ExpiresAt).toLocaleString());button(row,'Review scope',()=>review(q.ID));}
 if(!state.grants.length)$('grants').textContent='No repository grants yet.';
 for(const g of state.grants){const active=!g.RevokedAt&&Date.parse(g.ExpiresAt)>Date.now();const row=item($('grants'),g.Scope.Actions.join(', '),(active?'Active':g.RevokedAt?'Revoked':'Expired')+' · Repository '+g.RepositoryID+' · Agent '+g.AgentID+' · Expires '+new Date(g.ExpiresAt).toLocaleString());if(active)button(row,'Revoke access',async()=>{await api('/v1/github/grants/'+encodeURIComponent(g.ID)+'/revoke',{});await load();$('status').textContent='Access revoked.';});}
}
async function decide(approve) { const value=reviewed;if(!value)return;const id=value.request.ID,digest=value.digest;invalidate();await api('/v1/github/requests/'+encodeURIComponent(id)+(approve?'/approve':'/deny'),{digest});await load();$('status').textContent=approve?'Scope approved. The agent can poll for its grant.':'Request denied.'; }
action($('approve'),()=>decide(true));action($('deny'),()=>decide(false));
action($('connect'),async()=>{const id=Number($('repository').value);if(!Number.isSafeInteger(id)||id<=0)throw new Error('Select a repository.');await api('/v1/github/connections',{repository_id:id});await load();$('status').textContent='Repository connected. Agents still need your approval.';});
(async()=>{try{const session=await api('/v1/session');csrf=session.csrf_token;await load();const repos=await api('/v1/github/repositories');for(const r of repos)$('repository').add(new Option(r.Owner+'/'+r.Name,String(r.RepositoryID)));$('connect').disabled=!repos.length;$('github').hidden=false;$('status').textContent=repos.length?'Choose a repository or review an access request.':'No repositories are available for this Toolbox owner.';const id=location.pathname.startsWith('/github/approve/') ? location.pathname.slice('/github/approve/'.length) : '';if(id&&/^[a-f0-9-]{36}$/.test(id))await review(id);}catch(error){$('status').textContent=error.message;if(error.status===403)$('signed-out').hidden=false;}})();
