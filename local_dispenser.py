#!/usr/bin/env python3
"""
Self-hosted token dispenser backed by your own (burner) Google account.

Speaks the same protocol as the AuroraOSS token dispenser: POST an Aurora
device profile (JSON body) and receive dispenser-format AuthData JSON.
Each request builds a Play session registered for the *posted* profile, so
tokens are architecture-correct (see issue #29).

Credentials come from, in order:
  1. GPLAY_DISPENSER_EMAIL + GPLAY_DISPENSER_AAS_TOKEN env vars
  2. an existing personal login in ~/.gplay-auth.json
     (created by `./gplay-downloader.py auth-account`)

Usage:
    python3 local_dispenser.py [port]        # default port 8765

Then point clients at it:
    DISPENSER_URL=http://127.0.0.1:8765 ./start-server.sh
    ./gplay-downloader.py auth -d http://127.0.0.1:8765

The dispensed JSON never includes the AAS token or checkin internals, so
exposing this service does not hand out your account's long-lived token.
Rate-limit or firewall it if you expose it beyond localhost.
"""

import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

os.environ.setdefault('PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION', 'python')

import account_auth

# Fields handed to dispenser clients. Everything else (aasToken, email is
# kept, ac2dm internals are not) stays server-side.
DISPENSED_FIELDS = (
    'email', 'authToken', 'gsfId', 'deviceCheckInConsistencyToken',
    'deviceConfigToken', 'dfeCookie', 'deviceInfoProvider',
)


def load_credentials():
    email = os.environ.get('GPLAY_DISPENSER_EMAIL', '').strip()
    aas = os.environ.get('GPLAY_DISPENSER_AAS_TOKEN', '').strip()
    if email and aas:
        return email, aas
    auth_file = Path.home() / '.gplay-auth.json'
    if auth_file.exists():
        try:
            data = json.loads(auth_file.read_text())
            if data.get('email') and data.get('aasToken'):
                return data['email'], data['aasToken']
        except Exception:
            pass
    print('Error: no credentials. Set GPLAY_DISPENSER_EMAIL/GPLAY_DISPENSER_AAS_TOKEN '
          "or run './gplay-downloader.py auth-account' first.")
    sys.exit(1)


EMAIL, AAS_TOKEN = None, None
_cache = {}          # profile name -> dispensed auth dict
_cache_lock = threading.Lock()


class DispenserHandler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        print(f'[dispenser] {fmt % args}')

    def _reply(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._reply(200, {'status': 'ok', 'service': 'gplay local dispenser'})

    def do_POST(self):
        try:
            length = int(self.headers.get('Content-Length', 0))
            profile = json.loads(self.rfile.read(length) or b'{}')
        except Exception:
            self._reply(400, {'error': 'body must be an Aurora device profile (JSON)'})
            return
        if not isinstance(profile, dict) or not profile.get('Build.FINGERPRINT'):
            self._reply(400, {'error': 'body must be an Aurora device profile (JSON)'})
            return

        name = profile.get('UserReadableName', 'unnamed profile')
        with _cache_lock:
            cached = _cache.get(name)
        if cached:
            print(f'[dispenser] serving cached token for {name}')
            self._reply(200, cached)
            return

        try:
            print(f'[dispenser] building session for profile: {name}')
            auth = account_auth.build_auth_data(EMAIL, AAS_TOKEN, device=profile,
                                                log=lambda m: print(f'[dispenser]   {m}'))
        except account_auth.AccountAuthError as e:
            self._reply(500, {'error': str(e)})
            return

        dispensed = {k: auth[k] for k in DISPENSED_FIELDS if k in auth}
        with _cache_lock:
            _cache[name] = dispensed
        self._reply(200, dispensed)


def main():
    global EMAIL, AAS_TOKEN
    EMAIL, AAS_TOKEN = load_credentials()
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8765
    host = os.environ.get('GPLAY_DISPENSER_HOST', '127.0.0.1')
    server = ThreadingHTTPServer((host, port), DispenserHandler)
    print(f'Local dispenser for {EMAIL} on http://{host}:{port}')
    print('Point clients at it with DISPENSER_URL or ./gplay-downloader.py auth -d <url>')
    server.serve_forever()


if __name__ == '__main__':
    main()
