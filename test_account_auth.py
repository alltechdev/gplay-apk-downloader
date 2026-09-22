#!/usr/bin/env python3
"""Tests for personal Google account ("burner account") authentication.

Runs a local mock of android.clients.google.com to prove the full flow
end-to-end for the module, the CLI (auth-account) and the web UI endpoint
(POST /api/auth/google), plus a live negative test against the real
Google endpoint that proves the request format is accepted (Google
answers BadAuthentication for a bogus token instead of a format error
like MissingDroidguard).

Usage:  .venv/bin/python test_account_auth.py
        GPLAY_SKIP_LIVE=1 .venv/bin/python test_account_auth.py  # offline
"""

import json
import os
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs

os.environ['PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION'] = 'python'

REPO = Path(__file__).parent
PYTHON = str(REPO / '.venv' / 'bin' / 'python')

MOCK_AAS = 'aas_et/MOCKAASTOKEN0123456789'
MOCK_AC2DM = 'mock_ac2dm_token'
MOCK_PLAY = 'mock_play_auth_token'
MOCK_ANDROID_ID = 0x1122334455667788
MOCK_CCT = 'mock-checkin-consistency-token'
MOCK_DCT = 'mock-device-config-token'
MOCK_DFE = 'mock-dfe-cookie'


class MockGoogle(BaseHTTPRequestHandler):
    """Minimal mock of android.clients.google.com auth/checkin/upload."""

    def log_message(self, *a):
        pass

    def _send(self, body, content_type='text/plain'):
        self.send_response(200)
        self.send_header('Content-Type', content_type)
        self.end_headers()
        self.wfile.write(body if isinstance(body, bytes) else body.encode())

    def do_GET(self):
        if self.path == '/fdfe/toc':
            from gpapi import googleplay_pb2
            wrapper = googleplay_pb2.ResponseWrapper()
            wrapper.payload.tocResponse.cookie = MOCK_DFE
            self._send(wrapper.SerializeToString(), 'application/x-protobuf')
        elif self.path == '/login.html':
            # Simulates the post-sign-in EmbeddedSetup page: oauth_token
            # cookie present, email in the data-profile-identifier div.
            self._send(
                '<html><body>'
                '<div data-profile-identifier data-email="scraped@example.com">signed in</div>'
                '<script>document.cookie = "oauth_token=oauth2_4/BROWSERTEST; path=/";</script>'
                '</body></html>',
                'text/html')
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        raw = self.rfile.read(length)

        if self.path == '/auth':
            params = {k: v[0] for k, v in parse_qs(raw.decode()).items()}
            service = params.get('service', '')
            token = params.get('Token', '')
            if service == 'ac2dm' and params.get('add_account') == '1':
                # oauth_token -> AAS exchange (Aurora AC2DMTask format)
                assert params.get('droidguard_results') == 'null', 'missing droidguard_results'
                assert params.get('ACCESS_TOKEN') == '1'
                if token.startswith('oauth2_4/'):
                    self._send(f"Token={MOCK_AAS}\nEmail={params.get('Email')}\nservices=mail")
                else:
                    self._send('Error=BadAuthentication')
            elif service == 'ac2dm':
                # AAS -> ac2dm token
                self._send(f'Auth={MOCK_AC2DM}' if token == MOCK_AAS else 'Error=BadAuthentication')
            elif service == 'oauth2:https://www.googleapis.com/auth/googleplay':
                assert params.get('androidId'), 'play token exchange must include androidId'
                self._send(f'Auth={MOCK_PLAY}' if token == MOCK_AAS else 'Error=BadAuthentication')
            else:
                self._send(f'Error=UnknownService:{service}')

        elif self.path == '/checkin':
            from gpapi import googleplay_pb2
            resp = googleplay_pb2.AndroidCheckinResponse()
            resp.androidId = MOCK_ANDROID_ID
            resp.securityToken = 0x99887766
            resp.deviceCheckinConsistencyToken = MOCK_CCT
            self._send(resp.SerializeToString(), 'application/x-protobuf')

        elif self.path == '/fdfe/uploadDeviceConfig':
            from gpapi import googleplay_pb2
            wrapper = googleplay_pb2.ResponseWrapper()
            wrapper.payload.uploadDeviceConfigResponse.uploadDeviceConfigToken = MOCK_DCT
            self._send(wrapper.SerializeToString(), 'application/x-protobuf')

        else:
            self.send_response(404)
            self.end_headers()


def start_mock():
    server = HTTPServer(('127.0.0.1', 0), MockGoogle)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f'http://127.0.0.1:{server.server_port}/'


PASS = []
FAIL = []


def check(name, cond, detail=''):
    if cond:
        PASS.append(name)
        print(f'  PASS: {name}')
    else:
        FAIL.append(name)
        print(f'  FAIL: {name} {detail}')


def test_module(base):
    print('\n[1] Module flow (oauth_token -> AAS -> full auth dict) against mock Google')
    os.environ['GPLAY_ACCOUNT_AUTH_BASE'] = base
    sys.path.insert(0, str(REPO))
    import account_auth
    # Re-apply base in case account_auth was imported earlier with another value
    account_auth.AUTH_BASE = base
    account_auth.AUTH_URL = base + 'auth'

    logs = []
    aas = account_auth.exchange_oauth_token('burner@example.com', 'oauth2_4/FAKE', log=logs.append)
    check('oauth_token exchanged for AAS token', aas == MOCK_AAS, repr(aas))

    auth = account_auth.build_auth_data('burner@example.com', aas, log=logs.append)
    check('authToken is Play token', auth['authToken'] == MOCK_PLAY)
    check('gsfId is hex android id', auth['gsfId'] == '{0:x}'.format(MOCK_ANDROID_ID), auth['gsfId'])
    check('checkin consistency token present', auth['deviceCheckInConsistencyToken'] == MOCK_CCT)
    check('device config token present', auth['deviceConfigToken'] == MOCK_DCT)
    check('userAgentString present', 'Android-Finsky' in auth['deviceInfoProvider']['userAgentString'])
    check('aasToken stored for renewal', auth['aasToken'] == MOCK_AAS)
    check('dfeCookie captured from toc', auth['dfeCookie'] == MOCK_DFE)
    check('flow logged step by step', sum('Step' in l for l in logs) >= 8, logs)

    # The dict must satisfy the existing header builders (CLI + server)
    import importlib.util
    spec = importlib.util.spec_from_file_location('gplay_downloader', REPO / 'gplay-downloader.py')
    gd = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gd)
    headers = gd.get_auth_headers(auth)
    check('CLI get_auth_headers accepts auth dict',
          headers['Authorization'] == f'Bearer {MOCK_PLAY}' and headers['X-DFE-Device-Id'] == auth['gsfId'])
    return auth


def test_cli(base):
    print('\n[2] CLI: ./gplay-downloader.py auth-account against mock Google')
    with tempfile.TemporaryDirectory() as home:
        env = dict(os.environ, HOME=home, GPLAY_ACCOUNT_AUTH_BASE=base)
        proc = subprocess.run(
            [PYTHON, str(REPO / 'gplay-downloader.py'), 'auth-account',
             '--email', 'burner@example.com', '--oauth-token', 'oauth2_4/FAKE'],
            capture_output=True, text=True, env=env, cwd=REPO, timeout=60)
        print('  --- CLI output ---')
        for line in proc.stdout.splitlines():
            print('  |', line)
        check('CLI exits 0', proc.returncode == 0, proc.stderr[-400:])
        check('CLI logs the flow', 'Play auth token OK' in proc.stdout and 'ARMv7 auth saved' in proc.stdout)
        auth_file = Path(home) / '.gplay-auth.json'
        check('CLI wrote auth file', auth_file.exists())
        if auth_file.exists():
            saved = json.loads(auth_file.read_text())
            check('saved auth has Play token + gsfId',
                  saved.get('authToken') == MOCK_PLAY and saved.get('gsfId'))
        armv7_file = Path(home) / '.gplay-auth-armv7.json'
        check('CLI wrote ARMv7 auth file too', armv7_file.exists())
        if armv7_file.exists():
            v7 = json.loads(armv7_file.read_text())
            check('ARMv7 auth registered its own device',
                  v7.get('gsfId') and 'armeabi-v7a' in v7['deviceInfoProvider']['userAgentString'])

        # No-token invocation should print instructions, not crash
        proc2 = subprocess.run(
            [PYTHON, str(REPO / 'gplay-downloader.py'), 'auth-account', '--email', 'x@y.z'],
            capture_output=True, text=True, env=env, cwd=REPO, timeout=60)
        check('CLI without token prints how-to and exits 1',
              proc2.returncode == 1 and 'EmbeddedSetup' in proc2.stdout)


def test_webui(base):
    print('\n[3] Web UI: POST /api/auth/google (flask test client) against mock Google')
    home = tempfile.mkdtemp()
    os.environ['HOME'] = home
    os.environ['GPLAY_ACCOUNT_AUTH_BASE'] = base
    os.environ.setdefault('DISABLE_APP_PAGES', '1')

    import importlib
    import account_auth
    importlib.reload(account_auth)
    import server as srv
    importlib.reload(srv)
    srv.test_auth_token = lambda auth, strict=False: True  # skip live Play validation here

    client = srv.app.test_client()

    # Bad request
    r = client.post('/api/auth/google', json={'email': 'a@b.c'})
    check('missing token -> 400', r.status_code == 400)

    # Full flow with AAS token
    r = client.post('/api/auth/google', json={'email': 'burner@example.com', 'aasToken': MOCK_AAS})
    body = r.get_data(as_text=True)
    events = [json.loads(l[6:]) for l in body.splitlines() if l.startswith('data: ')]
    print('  --- SSE events ---')
    for e in events:
        print('  |', e.get('type'), '-', e.get('message', e.get('email', '')))
    types = [e['type'] for e in events]
    check('webui streams progress events', types.count('progress') >= 5, types)
    check('webui ends with success', types[-1] == 'success')
    check('success reports email + aasToken',
          events[-1].get('email') == 'burner@example.com' and events[-1].get('aasToken') == MOCK_AAS)

    saved = json.loads((Path(home) / '.gplay-auth.json').read_text())
    check('webui saved server auth cache', saved.get('authToken') == MOCK_PLAY)
    check('webui saved ARMv7 auth cache too', (Path(home) / '.gplay-auth-armv7.json').exists())

    r = client.get('/api/auth/status')
    st = r.get_json()
    check('auth status is authenticated after login', st.get('authenticated') is True)
    check('auth status reports personal account email',
          st.get('accountType') == 'personal' and st.get('email') == 'burner@example.com')

    # Stale-session auto-refresh: corrupt the cached Play token, refresh must
    # rebuild it from the stored AAS token without any sign-in
    stale = dict(saved); stale['authToken'] = 'stale_token'
    (Path(home) / '.gplay-auth.json').write_text(json.dumps(stale))
    refreshed = srv.refresh_personal_auth()
    check('stale session auto-refreshes from stored AAS token',
          refreshed and refreshed['authToken'] == MOCK_PLAY)
    check('refresh persisted to cache',
          json.loads((Path(home) / '.gplay-auth.json').read_text())['authToken'] == MOCK_PLAY)

    # Sign out
    r = client.post('/api/auth/google/logout')
    check('logout succeeds', r.status_code == 200 and r.get_json().get('success'))
    check('logout removed both auth caches',
          not (Path(home) / '.gplay-auth.json').exists()
          and not (Path(home) / '.gplay-auth-armv7.json').exists())
    st = client.get('/api/auth/status').get_json()
    check('status no longer authenticated after logout', st.get('authenticated') is False)

    # Bad token path surfaces Google's error
    r = client.post('/api/auth/google', json={'email': 'burner@example.com', 'aasToken': 'aas_et/WRONG'})
    body = r.get_data(as_text=True)
    check('webui surfaces BadAuthentication for wrong token', 'BadAuthentication' in body, body[:200])


def test_browser_capture(base):
    print('\n[4] Automatic browser capture (real headless Chrome + CDP) against mock login page')
    import account_auth
    browser = account_auth.find_browser()
    if not browser:
        print('  skipped (no Chromium-based browser installed)')
        return
    logs = []
    email, token = account_auth.capture_oauth_token_via_browser(
        log=logs.append, timeout=60, headless=True,
        url=base + 'login.html', cookie_domain='127.0.0.1', page_match='127.0.0.1')
    check('browser capture grabbed oauth_token cookie', token == 'oauth2_4/BROWSERTEST', repr(token))
    check('browser capture scraped account email', email == 'scraped@example.com', repr(email))
    check('browser capture logged its steps', any('Captured oauth_token' in l for l in logs), logs)

    # Captured values must drive the full flow end-to-end
    aas = account_auth.exchange_oauth_token(email, token, log=logs.append)
    auth = account_auth.build_auth_data(email, aas, log=logs.append)
    check('captured token completes full auth flow', auth['authToken'] == MOCK_PLAY)


def test_webui_browser_mode():
    print('\n[5] Web UI browser mode: POST /api/auth/google {"browser": true}')
    import server as srv
    import account_auth

    real_capture = account_auth.capture_oauth_token_via_browser
    real_find = account_auth.find_browser
    try:
        account_auth.find_browser = lambda: None
        client = srv.app.test_client()
        r = client.post('/api/auth/google', json={'browser': True})
        check('browser mode without a browser -> 400 with clear message',
              r.status_code == 400 and 'browser' in r.get_json()['error'].lower())

        account_auth.find_browser = lambda: '/usr/bin/google-chrome'
        account_auth.capture_oauth_token_via_browser = (
            lambda log, **kw: (log('Captured oauth_token cookie (oauth2_4/FAKE...)'),
                               ('scraped@example.com', 'oauth2_4/FAKE'))[1])
        r = client.post('/api/auth/google', json={'browser': True})
        body = r.get_data(as_text=True)
        events = [json.loads(l[6:]) for l in body.splitlines() if l.startswith('data: ')]
        check('browser mode streams and succeeds', events and events[-1]['type'] == 'success', body[:300])
        check('browser mode uses scraped email',
              events and events[-1].get('email') == 'scraped@example.com')

        # Retry must reuse the stored AAS token and never reopen the browser
        def _no_browser(**kw):
            raise AssertionError('browser reopened despite stored AAS token')
        account_auth.capture_oauth_token_via_browser = _no_browser
        r = client.post('/api/auth/google', json={'browser': True})
        body = r.get_data(as_text=True)
        events = [json.loads(l[6:]) for l in body.splitlines() if l.startswith('data: ')]
        check('retry reuses stored AAS token without browser',
              events and events[-1]['type'] == 'success'
              and any('previous sign-in' in e.get('message', '') for e in events), body[:300])
    finally:
        account_auth.capture_oauth_token_via_browser = real_capture
        account_auth.find_browser = real_find


def test_local_dispenser(base):
    print('\n[6] Local dispenser: per-arch tokens via ./gplay-downloader.py auth (issue #29)')
    import socket, subprocess as sp, time, re
    s = socket.socket(); s.bind(('127.0.0.1', 0)); port = s.getsockname()[1]; s.close()

    env = dict(os.environ, GPLAY_ACCOUNT_AUTH_BASE=base,
               GPLAY_DISPENSER_EMAIL='burner@example.com',
               GPLAY_DISPENSER_AAS_TOKEN=MOCK_AAS)
    disp = sp.Popen([PYTHON, str(REPO / 'local_dispenser.py'), str(port)],
                    env=env, cwd=REPO, stdout=sp.PIPE, stderr=sp.STDOUT, text=True)
    try:
        import requests as rq
        for _ in range(50):
            try:
                rq.get(f'http://127.0.0.1:{port}/', timeout=1); break
            except Exception:
                time.sleep(0.2)

        with tempfile.TemporaryDirectory() as home:
            cli_env = dict(os.environ, HOME=home, GPLAY_ACCOUNT_AUTH_BASE=base)
            proc = sp.run([PYTHON, str(REPO / 'gplay-downloader.py'), 'auth',
                           '-d', f'http://127.0.0.1:{port}'],
                          capture_output=True, text=True, env=cli_env, cwd=REPO, timeout=120)
            check('dispenser auth exits 0', proc.returncode == 0, proc.stdout[-300:] + proc.stderr[-200:])
            arm64 = Path(home) / '.gplay-auth.json'
            armv7 = Path(home) / '.gplay-auth-armv7.json'
            check('dispenser auth wrote both arch files', arm64.exists() and armv7.exists())
            if arm64.exists() and armv7.exists():
                a64 = json.loads(arm64.read_text()); a7 = json.loads(armv7.read_text())
                ua64 = a64['deviceInfoProvider']['userAgentString']
                ua7 = a7['deviceInfoProvider']['userAgentString']
                abis64 = re.search(r'supportedAbis=([^)]*)', ua64).group(1)
                abis7 = re.search(r'supportedAbis=([^)]*)', ua7).group(1)
                check('ARM64 token registered an arm64 device', 'arm64-v8a' in abis64, abis64)
                check('ARMv7 token registered an armv7-only device',
                      'armeabi-v7a' in abis7 and 'arm64' not in abis7, abis7)
                check('dispensed tokens do not leak the AAS token',
                      'aasToken' not in a64 and 'aasToken' not in a7)
    finally:
        disp.terminate()


def test_live_negative():
    print('\n[7] LIVE negative test against real android.clients.google.com')
    if os.environ.get('GPLAY_SKIP_LIVE'):
        print('  skipped (GPLAY_SKIP_LIVE set)')
        return
    import importlib
    os.environ['GPLAY_ACCOUNT_AUTH_BASE'] = 'https://android.clients.google.com/'
    import account_auth
    importlib.reload(account_auth)
    try:
        account_auth.exchange_oauth_token('burner@example.com', 'oauth2_4/bogus_probe')
        check('live oauth exchange rejects bogus token', False, 'unexpectedly succeeded')
    except account_auth.AccountAuthError as e:
        # BadAuthentication proves the request format is accepted and only
        # the token is rejected (a format problem would say MissingDroidguard etc.)
        check('live oauth exchange: format accepted, bogus token rejected',
              'BadAuthentication' in str(e), str(e))
    try:
        account_auth._exchange_aas_token('burner@example.com', 'aas_et/bogus_probe',
                                         'oauth2:https://www.googleapis.com/auth/googleplay',
                                         gsf_id_hex='3913f6bf9013e79b',
                                         app='com.android.vending',
                                         header_app='com.google.android.gms')
        check('live play-token exchange rejects bogus token', False, 'unexpectedly succeeded')
    except account_auth.AccountAuthError as e:
        check('live play-token exchange: format accepted, bogus token rejected',
              'BadAuthentication' in str(e), str(e))


def main():
    server, base = start_mock()
    try:
        test_module(base)
        test_cli(base)
        test_webui(base)
        test_browser_capture(base)
        test_webui_browser_mode()
        test_local_dispenser(base)
        test_live_negative()
    finally:
        server.shutdown()

    print(f'\n{len(PASS)} passed, {len(FAIL)} failed')
    return 1 if FAIL else 0


if __name__ == '__main__':
    sys.exit(main())
