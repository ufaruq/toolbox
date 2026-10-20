#!/usr/bin/env python3
"""Hermetic Workspace UI acceptance. Google consent, Picker and Drive are synthetic."""
import os
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlsplit
from playwright.sync_api import sync_playwright, expect

PICKER = r"""
window.gapi={load:(_,options)=>options.callback()};
window.google={picker:{Action:{PICKED:'picked',CANCEL:'cancel'},ViewId:{DOCS:'docs'},View:class{setMimeTypes(){return this;}},PickerBuilder:class{
setDeveloperKey(){return this;} setAppId(){return this;} setOrigin(){return this;}
setOAuthToken(token){if(!token.startsWith('fixture-access-'))throw Error('Not a synthetic Picker credential');return this;}
addView(){return this;}setCallback(cb){this.callback=cb;return this;}
build(){const cb=this.callback;return{setVisible(visible){if(!visible)return;const button=document.createElement('button');button.id='synthetic-picker-select';button.textContent='Select synthetic Google Doc';button.onclick=()=>{button.remove();cb({action:'picked',docs:[{id:'doc-A',name:'Synthetic document A',mimeType:'application/vnd.google-apps.document'}]});};document.body.append(button);},dispose(){}};}
}}};
"""

def main():
    origin=os.environ['TOOLBOX_WORKSPACE_TEST_ORIGIN']
    idp=os.environ['TOOLBOX_WORKSPACE_TEST_IDP']
    artifacts=Path(tempfile.mkdtemp(prefix='workspace-',dir=os.environ.get('TOOLBOX_BROWSER_ARTIFACT_DIR','/tmp')))
    stage='initialization'
    errors=[]
    with sync_playwright() as p:
        browser=p.chromium.launch(headless=True,args=['--no-sandbox','--ignore-certificate-errors-spki-list='+os.environ['TOOLBOX_WORKSPACE_TEST_SPKI']])
        context=browser.new_context(viewport={'width':1200,'height':900})
        page=context.new_page()
        page.on('pageerror',lambda _:errors.append(True))
        def allow(route):
            url=route.request.url
            if url=='https://apis.google.com/js/api.js':
                route.fulfill(status=200,content_type='application/javascript',body=PICKER)
            elif url.startswith(origin+'/') or url.startswith(idp+'/'):
                route.continue_()
            else:
                errors.append(True);route.abort()
        context.route('**/*',allow)
        try:
            stage='owner login'
            page.goto(origin+'/')
            expect(page.locator('#login')).to_be_visible()
            page.locator('#login').click()
            expect(page.locator('#subject')).to_be_visible()
            page.locator('#subject').fill('workspace-owner')
            page.locator('#authorize').click()
            expect(page.locator('#workspace')).to_be_visible()
            expect(page.locator('#document-panel')).to_be_hidden()
            assert page.locator('#advanced').get_attribute('open') is None
            stage='Google connection'
            page.locator('#connect').click()
            expect(page.locator('#connected-settings')).to_be_visible()
            expect(page.locator('#connection-status')).to_contain_text('Connected')
            assert urlsplit(page.url).query==''
            expect(page.locator('#policy')).to_have_value('approve_exact_document_read')
            page.screenshot(path=str(artifacts/'connected.png'),full_page=True,animations="disabled")
            stage='Picker'
            page.locator('#pick').click()
            page.locator('#synthetic-picker-select').click()
            expect(page.locator('#selected-document')).to_contain_text('Synthetic document A')
            stage='failed review is visible beside approval controls'
            page.locator('#request').click()
            expect(page.locator('#approval-status')).to_contain_text('Request pending')
            closed_request=page.locator('#request-id').input_value()
            # Another owner tab closes the request while this tab still shows it
            # as pending. Keep the actual server rejection and UI error handling.
            assert page.evaluate("""async id => {
                const session=await (await fetch('/v1/session')).json();
                return (await fetch('/v1/delegation-requests/'+id+'/deny', {
                    method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':session.csrf_token},body:'{}'
                })).status;
            }""",closed_request)==200
            with page.expect_response(lambda response: urlsplit(response.url).path=='/v1/delegation-requests/'+closed_request+'/review') as failed_review:
                page.locator('#review').click()
            assert failed_review.value.status==403
            expect(page.locator('#approval-status')).to_contain_text('NOT_AUTHORIZED')
            expect(page.locator('#approval-status')).not_to_contain_text('Request pending')
            expect(page.locator('#review-details')).to_be_hidden()
            expect(page.locator('#approve')).to_be_disabled()
            stage='request and review'
            page.locator('#request').click()
            expect(page.locator('#request-id')).not_to_have_value(closed_request)
            expect(page.locator('#approval-panel')).to_be_visible()
            expect(page.locator('#approve')).to_be_disabled()
            page.locator('#review').click()
            expect(page.locator('#review-details')).to_contain_text('Fixture doc-A')
            expect(page.locator('#approve')).to_be_enabled()
            stage='approval and read'
            page.locator('#approve').click()
            expect(page.locator('#result-panel')).to_be_visible()
            page.locator('#read').click()
            expect(page.locator('#document')).to_contain_text('Synthetic document doc-A.')
            page.screenshot(path=str(artifacts/'approved-read.png'),full_page=True,animations="disabled",mask=[page.locator('#agent-credential')])
            # Exercise the real agent HTTP surface without browser owner cookies.
            credential=page.locator('#agent-credential').input_value()
            grant=page.locator('#grant-id').input_value()
            agent=p.request.new_context()
            headers={'Authorization':'Bearer '+credential,'Content-Type':'application/json'}
            stage='approval link survives owner login'
            pending=agent.post(origin+'/v1/delegation-requests',headers=headers,data={'tool':'google_drive.read_document.v1','file_id':'doc-A','duration_seconds':3600})
            assert pending.status==201
            pending=pending.json()
            other=browser.new_context(viewport={'width':1200,'height':900})
            other.route('**/*',allow)
            approval=other.new_page()
            approval.on('pageerror',lambda _:errors.append(True))
            approval.goto(pending['approval_url'])
            expect(approval.locator('#login')).to_be_visible()
            approval.locator('#login').click()
            expect(approval.locator('#subject')).to_be_visible()
            approval.locator('#subject').fill('workspace-owner')
            approval.locator('#authorize').click()
            expect(approval.locator('#workspace')).to_be_visible()
            expect(approval.locator('#approval-panel')).to_be_visible()
            expect(approval.locator('#request-id')).to_have_value(pending['request_id'])
            assert urlsplit(approval.url).path=='/approve/'+pending['request_id']
            approval.locator('#review').click()
            expect(approval.locator('#review-details')).to_contain_text('Fixture doc-A')
            expect(approval.locator('#approve')).to_be_enabled()
            approval.locator('#approve').click()
            expect(approval.locator('#result-panel')).to_be_visible()
            accepted=agent.get(origin+'/v1/delegation-requests/'+pending['request_id'],headers=headers)
            assert accepted.status==200 and accepted.json()['status']=='approved'
            assert approval.evaluate('Object.keys(localStorage).length+Object.keys(sessionStorage).length')==0
            stage='approval return rejects unsafe destinations'
            approval.goto(origin+'/')
            for destination in ['https://example.invalid/', '//example.invalid/', '/approve/not-a-request', '/approve/'+pending['request_id']+'?next=elsewhere']:
                approval.evaluate("path => sessionStorage.setItem('toolbox.approvalReturn',path)",destination)
                approval.reload()
                expect(approval.locator('#workspace')).to_be_visible()
                assert approval.url==origin+'/'
                expect(approval.locator('#request-id')).to_have_value('')
                assert approval.evaluate('sessionStorage.length')==0
            other.close()
            stage='delayed revoke cannot mark a newer grant revoked'
            held_revokes=[]
            def hold_revoke(route):
                response=route.fetch()
                assert response.status==200
                held_revokes.append((route,response))
                page.locator('#revoke').evaluate("button => button.dataset.held = 'true'")
            page.route(origin+'/v1/grants/'+grant+'/revoke',hold_revoke)
            page.locator('#revoke').click()
            expect(page.locator('#revoke')).to_have_attribute('data-held','true')
            page.locator('#request').click()
            expect(page.locator('#approval-status')).to_contain_text('Request pending')
            page.locator('#review').click()
            expect(page.locator('#approve')).to_be_enabled()
            page.locator('#approve').click()
            expect(page.locator('#grant-id')).not_to_have_value(grant)
            expect(page.locator('#grant-badge')).to_have_text('Approved')
            assert agent.post(origin+'/v1/delegation-tokens',headers=headers,data={'grant_id':grant}).status==403
            grant=page.locator('#grant-id').input_value()
            assert grant
            route,response=held_revokes.pop()
            route.fulfill(response=response)
            expect(page.locator('#revoke')).to_be_enabled()
            expect(page.locator('#grant-badge')).to_have_text('Approved')
            expect(page.locator('#document')).not_to_contain_text('Access revoked.')
            assert agent.post(origin+'/v1/delegation-tokens',headers=headers,data={'grant_id':grant}).status==200
            stage='deny different document'
            token=agent.post(origin+'/v1/delegation-tokens',headers=headers,data={'grant_id':grant}).json()['delegation_token']
            denied=agent.post(origin+'/v1/tool-invocations',headers={**headers,'Toolbox-Delegation':token},data={'tool':'google_drive.read_document.v1','grant_id':grant,'arguments':{'file_id':'doc-B'}})
            assert denied.status==403
            stage='delayed read after revocation'
            held=[]
            def hold_read(route):
                response=route.fetch()
                assert response.status==200
                held.append((route,response))
                page.locator('#read').evaluate("button => button.dataset.held = 'true'")
            page.route(origin+'/v1/tool-invocations',hold_read)
            page.locator('#read').click()
            expect(page.locator('#read')).to_have_attribute('data-held','true')
            stage='revocation'
            page.locator('#revoke').click()
            expect(page.locator('#grant-badge')).to_have_text('Revoked')
            route,response=held.pop()
            route.fulfill(response=response)
            expect(page.locator('#read')).to_be_enabled()
            expect(page.locator('#document')).to_contain_text('Access revoked.')
            assert agent.post(origin+'/v1/delegation-tokens',headers=headers,data={'grant_id':grant}).status==403
            stage='disconnect'
            page.locator('#connected-settings details summary').click()
            page.locator('#disconnect').click()
            expect(page.locator('#document-panel')).to_be_hidden()
            stage='delayed approval after account change'
            for _ in range(2):
                page.locator('#connect').click()
                expect(page.locator('#connected-settings')).to_be_visible()
                expect(page.locator('#connection-status')).to_contain_text('Connected')
            page.locator('#pick').click()
            page.locator('#synthetic-picker-select').click()
            page.locator('#request').click()
            expect(page.locator('#approval-panel')).to_be_visible()
            page.locator('#review').click()
            expect(page.locator('#approve')).to_be_enabled()
            held_approvals=[]
            def hold_approval(route):
                response=route.fetch()
                assert response.status==201
                held_approvals.append((route,response))
                page.locator('#approve').evaluate("button => button.dataset.held = 'true'")
            page.route(origin+'/v1/delegation-requests/*/approve',hold_approval)
            page.locator('#approve').click()
            expect(page.locator('#approve')).to_have_attribute('data-held','true')
            current=page.locator('#connection').input_value()
            connections=page.locator('#connection option').evaluate_all('options => options.map(o=>o.value)')
            page.locator('#connection').select_option(next(c for c in connections if c!=current))
            route,response=held_approvals.pop()
            route.fulfill(response=response)
            expect(page.locator('#approve')).to_be_disabled()
            expect(page.locator('#result-panel')).to_be_hidden()
            expect(page.locator('#grant-id')).to_have_value('')
            stage='no persisted credentials'
            assert page.evaluate('Object.keys(localStorage).length+Object.keys(sessionStorage).length')==0
            assert not errors
            page.screenshot(path=str(artifacts/'workspace.png'),full_page=True,animations="disabled",mask=[page.locator('#agent-credential')])
            stage='logout'
            page.locator('#logout').click()
            expect(page.locator('#login-panel')).to_be_visible()
            expect(page.locator('#workspace')).to_be_hidden()
            page.set_viewport_size({'width':390,'height':844})
            page.screenshot(path=str(artifacts/'mobile-signed-out.png'),full_page=True,animations="disabled")
            assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
            agent.dispose()
            print('PASS: synthetic Workspace consent, Picker, approval/read, different-document denial, revocation, disconnect, logout; artifacts='+str(artifacts))
        except Exception:
            page.screenshot(path=str(artifacts/'failure.png'),full_page=True,animations="disabled",mask=[page.locator('#agent-credential')])
            print('FAIL: synthetic Workspace stage='+stage+'; artifacts='+str(artifacts))
            return 1
        finally:
            browser.close()
    return 0

if __name__=='__main__': sys.exit(main())
