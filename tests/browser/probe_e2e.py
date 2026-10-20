#!/usr/bin/env python3
"""Verify the real local probe form can navigate to Google's fixed consent host."""
import sys
from urllib.parse import urlsplit
from playwright.sync_api import sync_playwright,expect

def main():
    origin=sys.argv[1]
    with sync_playwright() as p:
        browser=p.chromium.launch(headless=True,args=['--no-sandbox'])
        context=browser.new_context()
        page=context.new_page()
        page.set_default_timeout(5000)
        events=[]
        stage='initial page'
        page.on('response',lambda response:events.append((urlsplit(response.url).path,response.status)))
        def allow(route):
            if route.request.url.startswith('https://accounts.google.com/'):
                route.fulfill(status=200,content_type='text/html',body='<p id="synthetic-consent">Synthetic Google consent</p>')
            elif route.request.url.startswith(origin+'/'):
                # Fulfill the local redirect without letting route.continue_()
                # follow a redirect chain outside interception. Chromium still
                # handles the form's 303 and enforces the document's CSP.
                route.fulfill(response=route.fetch(max_redirects=0))
            else:
                route.abort()
        context.route('**/*',allow)
        try:
            page.goto(origin+'/')
            stage='start form'
            page.get_by_role('button',name='Continue with Google').click()
            expect(page.locator('#synthetic-consent')).to_be_visible()
        except Exception:
            print('FAIL: probe form could not reach controlled Google consent destination; stage='+stage+'; synthetic response statuses='+str(events))
            return 1
        finally:
            browser.close()
    return 0
if __name__=='__main__':sys.exit(main())
