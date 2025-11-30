#!/usr/bin/env python3
"""
GPlay Downloader - Local Python Server
Downloads APKs from Google Play Store with direct browser downloads
Uses gpapi for proper protobuf parsing
"""

import os
# Fix protobuf compatibility issue with gpapi
os.environ['PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION'] = 'python'

import json
import base64
import re
import logging
from flask import Flask, request, jsonify, send_file, Response
from flask_cors import CORS
import requests
import cloudscraper

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# Import gpapi protobuf
try:
    from gpapi import googleplay_pb2
    HAS_GPAPI = True
except (ImportError, TypeError) as e:
    HAS_GPAPI = False
    print(f"Warning: gpapi not available ({e}). Using fallback parser.")

DISPENSER_URL = 'https://auroraoss.com/api/auth'
FDFE_URL = 'https://android.clients.google.com/fdfe'
PURCHASE_URL = f'{FDFE_URL}/purchase'
DELIVERY_URL = f'{FDFE_URL}/delivery'
DETAILS_URL = f'{FDFE_URL}/details'

# Server-side auth cache files (per architecture)
from pathlib import Path
AUTH_CACHE_DIR = Path.home()
AUTH_CACHE_FILES = {
    'arm64-v8a': AUTH_CACHE_DIR / '.gplay-auth.json',  # Default for backward compat
    'armeabi-v7a': AUTH_CACHE_DIR / '.gplay-auth-armv7.json',
}

# Device profile for ARM64 (modern 64-bit phones)
DEVICE_ARM64 = {
    'UserReadableName': 'Google Pixel 7a',
    'Build.HARDWARE': 'lynx',
    'Build.RADIO': 'unknown',
    'Build.FINGERPRINT': 'google/lynx/lynx:14/UQ1A.231205.015/11084887:user/release-keys',
    'Build.BRAND': 'google',
    'Build.DEVICE': 'lynx',
    'Build.VERSION.SDK_INT': '34',
    'Build.VERSION.RELEASE': '14',
    'Build.MODEL': 'Pixel 7a',
    'Build.MANUFACTURER': 'Google',
    'Build.PRODUCT': 'lynx',
    'Build.ID': 'UQ1A.231205.015',
    'Build.BOOTLOADER': 'lynx-1.0-9716681',
    'TouchScreen': '3',
    'Keyboard': '1',
    'Navigation': '1',
    'ScreenLayout': '2',
    'HasHardKeyboard': 'false',
    'HasFiveWayNavigation': 'false',
    'Screen.Density': '420',
    'Screen.Width': '1080',
    'Screen.Height': '2400',
    'Platforms': 'arm64-v8a,armeabi-v7a,armeabi',
    'Features': 'android.hardware.sensor.proximity,android.hardware.touchscreen,android.hardware.wifi,android.hardware.camera,android.hardware.bluetooth',
    'Locales': 'en_US,en_GB',
    'SharedLibraries': 'android.ext.shared,org.apache.http.legacy',
    'GL.Version': '196610',
    'GL.Extensions': 'GL_OES_EGL_image',
    'Client': 'android-google',
    'GSF.version': '223616055',
    'Vending.version': '84122900',
    'Vending.versionString': '41.2.29-23 [0] [PR] 639844241',
    'Roaming': 'mobile-notroaming',
    'TimeZone': 'America/New_York',
    'CellOperator': '310',
    'SimOperator': '38',
}

# Device profile for ARMv7 (older 32-bit phones) - Samsung Galaxy J7
DEVICE_ARMV7 = {
    'UserReadableName': 'Samsung Galaxy J7',
    'Build.HARDWARE': 'samsungexynos7870',
    'Build.RADIO': 'unknown',
    'Build.FINGERPRINT': 'samsung/j7xeltexx/j7xelte:8.1.0/M1AJQ/J710FXXU6CSH1:user/release-keys',
    'Build.BRAND': 'samsung',
    'Build.DEVICE': 'j7xelte',
    'Build.VERSION.SDK_INT': '27',
    'Build.VERSION.RELEASE': '8.1.0',
    'Build.MODEL': 'SM-J710F',
    'Build.MANUFACTURER': 'samsung',
    'Build.PRODUCT': 'j7xeltexx',
    'Build.ID': 'M1AJQ',
    'Build.BOOTLOADER': 'J710FXXU6CSH1',
    'TouchScreen': '3',
    'Keyboard': '1',
    'Navigation': '1',
    'ScreenLayout': '2',
    'HasHardKeyboard': 'false',
    'HasFiveWayNavigation': 'false',
    'Screen.Density': '320',
    'Screen.Width': '720',
    'Screen.Height': '1280',
    'Platforms': 'armeabi-v7a,armeabi',
    'Features': 'android.hardware.sensor.proximity,android.hardware.touchscreen,android.hardware.wifi,android.hardware.camera,android.hardware.bluetooth',
    'Locales': 'en_US,en_GB',
    'SharedLibraries': 'android.ext.shared,org.apache.http.legacy',
    'GL.Version': '196609',
    'GL.Extensions': 'GL_OES_EGL_image',
    'Client': 'android-google',
    'GSF.version': '203615037',
    'Vending.version': '82041300',
    'Vending.versionString': '20.4.13-all [0] [PR] 312295870',
    'Roaming': 'mobile-notroaming',
    'TimeZone': 'America/New_York',
    'CellOperator': '310',
    'SimOperator': '38',
}

# Default for backward compatibility
DEFAULT_DEVICE = DEVICE_ARM64

SUPPORTED_ARCHS = ['arm64-v8a', 'armeabi-v7a']


def get_device_config(arch='arm64-v8a'):
    """Get device config for a specific architecture."""
    if arch == 'armeabi-v7a':
        return DEVICE_ARMV7.copy()
    return DEVICE_ARM64.copy()


def merge_apks(base_apk_bytes, split_apks_bytes_list):
    """Merge base APK with split APKs into a single installable APK.

    Uses APKEditor (REAndroid) for proper resource merging.

    Args:
        base_apk_bytes: Bytes of the base APK
        split_apks_bytes_list: List of (name, bytes) tuples for split APKs

    Returns:
        Bytes of the merged APK (unsigned)
    """
    import zipfile
    import io
    import subprocess
    import tempfile
    import shutil

    logger.info(f"merge_apks called with base ({len(base_apk_bytes)} bytes) and {len(split_apks_bytes_list)} splits")

    # Try APKEditor first (best results)
    apkeditor_jar = os.path.join(os.path.dirname(__file__), 'APKEditor.jar')
    if os.path.exists(apkeditor_jar):
        try:
            return merge_apks_with_apkeditor(base_apk_bytes, split_apks_bytes_list, apkeditor_jar)
        except Exception as e:
            logger.error(f"APKEditor merge failed: {e}, falling back to simple merge")
    else:
        logger.warning("APKEditor.jar not found, using simple merge")

    return merge_apks_simple(base_apk_bytes, split_apks_bytes_list)


def merge_apks_with_apkeditor(base_apk_bytes, split_apks_bytes_list, apkeditor_jar):
    """Use APKEditor to merge split APKs properly."""
    import subprocess
    import tempfile
    import shutil

    work_dir = tempfile.mkdtemp(prefix='apk_merge_')

    try:
        # Write base APK
        base_path = os.path.join(work_dir, 'base.apk')
        with open(base_path, 'wb') as f:
            f.write(base_apk_bytes)

        # Write split APKs
        for i, (name, data) in enumerate(split_apks_bytes_list):
            split_path = os.path.join(work_dir, f'split{i}.apk')
            with open(split_path, 'wb') as f:
                f.write(data)

        # Run APKEditor merge
        output_path = os.path.join(work_dir, 'merged.apk')
        result = subprocess.run(
            ['java', '-jar', apkeditor_jar, 'm', '-i', work_dir, '-o', output_path],
            capture_output=True, text=True, timeout=300
        )

        if result.returncode != 0:
            logger.error(f"APKEditor failed: {result.stderr}")
            raise Exception(f"APKEditor failed: {result.stderr}")

        if not os.path.exists(output_path):
            raise Exception("APKEditor did not produce output file")

        with open(output_path, 'rb') as f:
            merged_bytes = f.read()

        logger.info(f"APKEditor merge successful: {len(merged_bytes)} bytes")
        return merged_bytes

    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


def should_skip_meta_inf(name):
    """Skip signature files but keep META-INF/services and other important content."""
    if not name.startswith('META-INF/'):
        return False
    # Skip signature files
    if name.endswith(('.SF', '.RSA', '.DSA', '.EC', '.MF')):
        return True
    if name == 'META-INF/MANIFEST.MF':
        return True
    # Keep everything else (services, kotlin_module, version files, etc.)
    return False


def merge_apks_simple(base_apk_bytes, split_apks_bytes_list):
    """Simple merge without manifest patching."""
    import zipfile
    import io

    merged_files = {}

    with zipfile.ZipFile(io.BytesIO(base_apk_bytes), 'r') as base_zip:
        for name in base_zip.namelist():
            if should_skip_meta_inf(name):
                continue
            merged_files[name] = base_zip.read(name)

    for split_name, split_bytes in split_apks_bytes_list:
        with zipfile.ZipFile(io.BytesIO(split_bytes), 'r') as split_zip:
            for name in split_zip.namelist():
                if should_skip_meta_inf(name):
                    continue
                if name == 'AndroidManifest.xml':
                    continue
                if name.startswith('lib/') or name not in merged_files:
                    merged_files[name] = split_zip.read(name)

    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as merged_zip:
        for name, data in sorted(merged_files.items()):
            merged_zip.writestr(name, data)

    return output.getvalue()


def sign_apk(apk_bytes):
    """Sign an APK using apksigner with debug keystore.

    Returns signed APK bytes, or original bytes if signing fails.
    """
    import subprocess
    import tempfile
    import shutil

    keystore = Path.home() / '.android' / 'debug.keystore'
    if not keystore.exists():
        logger.warning("Debug keystore not found, returning unsigned APK")
        return apk_bytes

    # Check if apksigner is available
    if not shutil.which('apksigner'):
        logger.warning("apksigner not found, returning unsigned APK")
        return apk_bytes

    try:
        with tempfile.NamedTemporaryFile(suffix='.apk', delete=False) as tmp_in:
            tmp_in.write(apk_bytes)
            tmp_in_path = tmp_in.name

        tmp_out_path = tmp_in_path + '.signed'

        # Sign with apksigner using debug keystore
        cmd = [
            'apksigner', 'sign',
            '--ks', str(keystore),
            '--ks-pass', 'pass:android',
            '--key-pass', 'pass:android',
            '--out', tmp_out_path,
            tmp_in_path
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        if result.returncode == 0 and os.path.exists(tmp_out_path):
            with open(tmp_out_path, 'rb') as f:
                signed_bytes = f.read()
            logger.info("APK signed successfully")
            return signed_bytes
        else:
            logger.warning(f"apksigner failed: {result.stderr}")
            return apk_bytes

    except Exception as e:
        logger.error(f"APK signing failed: {e}")
        return apk_bytes
    finally:
        # Cleanup temp files
        for path in [tmp_in_path, tmp_out_path]:
            try:
                os.unlink(path)
            except:
                pass


def format_size(bytes_size):
    if not bytes_size:
        return 'Unknown'
    units = ['B', 'KB', 'MB', 'GB']
    i = 0
    size = float(bytes_size)
    while size >= 1024 and i < len(units) - 1:
        size /= 1024
        i += 1
    return f'{size:.2f} {units[i]}'


def get_cached_auth(arch='arm64-v8a'):
    """Load cached auth from server-side auth file for specific architecture."""
    cache_file = AUTH_CACHE_FILES.get(arch, AUTH_CACHE_FILES['arm64-v8a'])
    if cache_file.exists():
        try:
            with open(cache_file) as f:
                auth = json.load(f)
            if auth.get('authToken') and auth.get('gsfId'):
                logger.info(f"Using cached auth token for {arch}")
                return auth
        except Exception as e:
            logger.warning(f"Failed to load cached auth for {arch}: {e}")
    return None


def save_cached_auth(auth_data, arch='arm64-v8a'):
    """Save auth data to server-side cache file for specific architecture."""
    cache_file = AUTH_CACHE_FILES.get(arch, AUTH_CACHE_FILES['arm64-v8a'])
    try:
        cache_file.write_text(json.dumps(auth_data, indent=2))
        logger.info(f"Auth saved to: {cache_file}")
        return True
    except Exception as e:
        logger.error(f"Failed to save auth: {e}")
        return False


def test_auth_token(auth, strict=False):
    """Test if an auth token works by making a simple API request.

    Args:
        auth: Auth data dict
        strict: If True, test against a stricter app (Chase) that requires better tokens
    """
    try:
        headers = get_auth_headers(auth)
        headers['Accept'] = 'application/x-protobuf'

        # Use a stricter test app - banking apps like Chase require better tokens
        # than simple apps like YouTube. If strict=True or default, use Chase.
        test_app = 'com.chase.sig.android' if strict else 'com.google.android.youtube'

        resp = requests.get(f'{DETAILS_URL}?doc={test_app}', headers=headers, timeout=10)
        if resp.status_code == 200:
            wrapper = googleplay_pb2.ResponseWrapper()
            wrapper.ParseFromString(resp.content)
            # Check if we got valid version info (not 0)
            vc = wrapper.payload.detailsResponse.docV2.details.appDetails.versionCode
            if vc > 0:
                logger.info(f"Auth token validated ({test_app} versionCode={vc})")
                return True
            else:
                logger.warning(f"Auth test returned versionCode=0 for {test_app}")
        else:
            logger.warning(f"Auth token test failed: status={resp.status_code}")
        return False
    except Exception as e:
        logger.warning(f"Auth token test error: {e}")
        return False


def get_auth_from_request():
    # Always prefer cached CLI auth since AuroraOSS dispenser tokens have limited permissions
    cached = get_cached_auth()
    if cached:
        return cached

    # Fall back to request auth if no cached auth available
    auth_header = request.headers.get('Authorization', '')
    if auth_header:
        try:
            token = auth_header.replace('Bearer ', '')
            auth_data = json.loads(base64.b64decode(token).decode('utf-8'))
            if auth_data.get('authToken'):
                return auth_data
        except:
            pass
    return None


def get_auth_headers(auth):
    device_info = auth.get('deviceInfoProvider', {})
    return {
        'Authorization': f"Bearer {auth.get('authToken', '')}",
        'User-Agent': device_info.get('userAgentString', 'Android-Finsky/41.2.29-23'),
        'X-DFE-Device-Id': auth.get('gsfId', ''),
        'Accept-Language': 'en-US',
        'X-DFE-Encoded-Targets': 'CAESN/qigQYC2AMBFfUbyA7SM5Ij/CvfBoIDgxXrBPsDlQUdMfOLAfoFrwEHgAcBrQYhoA0cGt4MKK0Y2gI',
        'X-DFE-Client-Id': 'am-android-google',
        'X-DFE-Network-Type': '4',
        'X-DFE-Content-Filters': '',
        'X-Limit-Ad-Tracking-Enabled': 'false',
        'X-DFE-Cookie': auth.get('dfeCookie', ''),
        'X-DFE-No-Prefetch': 'true',
    }


def get_download_info(pkg, auth):
    """Get download info using proper protobuf parsing."""
    if not HAS_GPAPI:
        return {'error': 'gpapi library not installed'}

    headers = {
        **get_auth_headers(auth),
        'Content-Type': 'application/x-protobuf',
        'Accept': 'application/x-protobuf',
    }

    # Step 1: Get app details
    details_resp = requests.get(f'{DETAILS_URL}?doc={pkg}', headers=headers, timeout=30)
    if details_resp.status_code != 200:
        return {'error': f'Failed to get app details: {details_resp.status_code}'}

    # Parse details response with protobuf
    try:
        details_wrapper = googleplay_pb2.ResponseWrapper()
        details_wrapper.ParseFromString(details_resp.content)

        if not details_wrapper.payload.detailsResponse.docV2.docid:
            return {'error': 'App not found or not available'}

        app = details_wrapper.payload.detailsResponse.docV2
        version_code = app.details.appDetails.versionCode
        version_string = app.details.appDetails.versionString
        title = app.title

        logger.info(f"Details for {pkg}: title={title}, versionCode={version_code}, versionString={version_string}")

        # If version_code is 0, try to get it from offer
        if version_code == 0 and app.offer:
            for offer in app.offer:
                if offer.offerType == 1:  # Free app offer
                    # Check if there's version info in the offer
                    logger.debug(f"Offer details: micros={offer.micros}, formattedAmount={offer.formattedAmount}")

    except Exception as e:
        return {'error': f'Failed to parse app details: {str(e)}'}

    # Step 2: Purchase (acquire free app)
    purchase_headers = {**headers, 'Content-Type': 'application/x-www-form-urlencoded'}
    purchase_data = f'doc={pkg}&ot=1&vc={version_code}'

    try:
        logger.info(f"Attempting purchase for {pkg} (vc={version_code})")
        purchase_resp = requests.post(PURCHASE_URL, headers=purchase_headers, data=purchase_data, timeout=30)
        logger.info(f"Purchase response status: {purchase_resp.status_code}")
        if purchase_resp.status_code not in [200, 204]:
            logger.warning(f"Purchase returned non-success status: {purchase_resp.status_code}")
            logger.debug(f"Purchase response content: {purchase_resp.content[:500]}")
    except Exception as e:
        logger.error(f"Purchase request failed: {type(e).__name__}: {e}")
        # Continue anyway - app might already be "purchased" or free

    # Step 3: Get delivery URL
    logger.info(f"Requesting delivery URL for {pkg}")
    delivery_resp = requests.get(
        f'{DELIVERY_URL}?doc={pkg}&ot=1&vc={version_code}',
        headers=headers,
        timeout=30
    )

    logger.info(f"Delivery response status: {delivery_resp.status_code}")
    if delivery_resp.status_code != 200:
        logger.error(f"Delivery failed with status {delivery_resp.status_code}")
        logger.debug(f"Delivery response: {delivery_resp.content[:500]}")
        return {'error': f'Failed to get download URL: {delivery_resp.status_code}'}

    # Parse delivery response with protobuf
    try:
        delivery_wrapper = googleplay_pb2.ResponseWrapper()
        delivery_wrapper.ParseFromString(delivery_resp.content)

        delivery_data = delivery_wrapper.payload.deliveryResponse.appDeliveryData

        if not delivery_data.downloadUrl:
            logger.error(f"No downloadUrl in delivery response for {pkg}")
            logger.debug(f"Delivery data fields: downloadSize={delivery_data.downloadSize}, splits={len(delivery_data.split)}")
            return {'error': 'No download URL available. App may require purchase or is region-restricted.'}

        download_url = delivery_data.downloadUrl
        download_size = delivery_data.downloadSize

        # Get cookies
        cookies = []
        for cookie in delivery_data.downloadAuthCookie:
            cookies.append({'name': cookie.name, 'value': cookie.value})

        # Get split APKs
        splits = []
        for i, split in enumerate(delivery_data.split):
            if split.downloadUrl:
                splits.append({
                    'name': split.name or f'split{i}',
                    'downloadUrl': split.downloadUrl,
                })

        return {
            'docid': pkg,
            'title': title,
            'versionCode': version_code,
            'versionString': version_string,
            'downloadUrl': download_url,
            'downloadSize': download_size,
            'cookies': cookies,
            'splits': splits,
            'filename': f'{pkg}-{version_code}.apk'
        }

    except Exception as e:
        return {'error': f'Failed to parse delivery data: {str(e)}'}


# Routes
@app.route('/')
def index():
    return send_file('index.html')


@app.route('/api/auth', methods=['POST'])
def auth():
    # First check if we have a valid cached token - use strict validation (Chase test)
    cached = get_cached_auth()
    if cached and test_auth_token(cached, strict=True):
        logger.info("Using existing valid cached token (passed Chase test)")
        return jsonify({'success': True, 'authData': cached, 'cached': True})

    # If we have a cached token that at least works for simple apps, use it
    # but warn that some apps may not work
    if cached and test_auth_token(cached, strict=False):
        logger.warning("Cached token works for simple apps (may have limited functionality)")
        return jsonify({'success': True, 'authData': cached, 'cached': True, 'warning': 'Token may not work for all apps'})

    return jsonify({'error': 'No valid cached token. Use the streaming auth endpoint.'}), 400


@app.route('/api/auth/stream', methods=['GET'])
def auth_stream():
    """SSE endpoint that tries unlimited tokens and streams progress to the frontend."""
    def generate():
        import time

        # First check if we have a valid cached token
        cached = get_cached_auth()
        if cached and test_auth_token(cached, strict=True):
            logger.info("Using existing valid cached token (passed Chase test)")
            yield f"data: {json.dumps({'type': 'success', 'authData': cached, 'cached': True, 'attempt': 0})}\n\n"
            return

        attempt = 0
        while True:
            attempt += 1

            # Send progress update
            yield f"data: {json.dumps({'type': 'progress', 'attempt': attempt, 'message': f'Trying token #{attempt}...'})}\n\n"

            try:
                scraper = cloudscraper.create_scraper()
                response = scraper.post(
                    DISPENSER_URL,
                    headers={
                        'User-Agent': 'com.aurora.store-4.6.1-70',
                        'Content-Type': 'application/json',
                    },
                    json=DEFAULT_DEVICE,
                    timeout=30
                )

                if not response.ok:
                    logger.warning(f"Dispenser returned {response.status_code}, attempt {attempt}")
                    yield f"data: {json.dumps({'type': 'progress', 'attempt': attempt, 'message': f'Token #{attempt} - dispenser error ({response.status_code})'})}\n\n"
                    time.sleep(1)  # Brief delay before retry
                    continue

                auth_data = response.json()

                # Send validation progress
                yield f"data: {json.dumps({'type': 'progress', 'attempt': attempt, 'message': f'Token #{attempt} - validating...'})}\n\n"

                # Test with strict validation (Chase) - this ensures token works for all apps
                if test_auth_token(auth_data, strict=True):
                    # Save the working token
                    save_cached_auth(auth_data)
                    logger.info(f"Token #{attempt} validated with Chase and saved")
                    yield f"data: {json.dumps({'type': 'success', 'authData': auth_data, 'cached': False, 'attempt': attempt})}\n\n"
                    return
                else:
                    logger.warning(f"Token #{attempt} failed Chase validation")
                    yield f"data: {json.dumps({'type': 'progress', 'attempt': attempt, 'message': f'Token #{attempt} - failed validation, retrying...'})}\n\n"

            except Exception as e:
                logger.warning(f"Auth attempt {attempt} failed: {e}")
                yield f"data: {json.dumps({'type': 'progress', 'attempt': attempt, 'message': f'Token #{attempt} - error: {str(e)[:50]}'})}\n\n"

            time.sleep(0.5)  # Brief delay between attempts

    return Response(
        generate(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'X-Accel-Buffering': 'no',  # Disable nginx buffering
        }
    )


@app.route('/api/auth/status')
def auth_status():
    auth = get_auth_from_request()
    return jsonify({'authenticated': bool(auth and auth.get('authToken'))})


@app.route('/api/search')
def search():
    query = request.args.get('q', '')
    if not query:
        return jsonify({'error': 'Query required'}), 400

    try:
        scraper = cloudscraper.create_scraper()
        response = scraper.get(
            f'https://play.google.com/store/search?q={query}&c=apps',
            timeout=30
        )
        html = response.text

        results = []
        seen = set()

        def decode_html(text):
            return text.replace('&amp;', '&').replace('&#39;', "'").replace('&quot;', '"')

        def decode_json(text):
            return text.replace('\\u0026', '&').replace("\\u0027", "'").replace('\\u003d', '=')

        def upgrade_icon(url):
            url = re.sub(r'=s\d+', '=s128', url)
            url = re.sub(r'=w\d+', '=s128', url)
            return url

        # Method 1: Try HTML patterns first (some pages use these)
        # Featured app (class="vWM94c" for title)
        featured = re.search(
            r'href="/store/apps/details\?id=([^"&]+)"[^>]*>.*?'
            r'<img[^>]*src="(https://play-lh\.googleusercontent\.com/[^"]+)"[^>]*>.*?'
            r'<div class="vWM94c">([^<]+)</div>',
            html, re.DOTALL
        )
        if featured:
            pkg, icon, title = featured.groups()
            if pkg not in seen:
                seen.add(pkg)
                results.append({
                    'package': pkg,
                    'title': decode_html(title),
                    'icon': upgrade_icon(icon)
                })

        # Related apps (class="Epkrse" for title)
        for match in re.finditer(
            r'href="/store/apps/details\?id=([^"&]+)"[^>]*>.*?'
            r'<img[^>]*src="(https://play-lh\.googleusercontent\.com/[^"=]+=[sw]\d+[^"]*)"[^>]*>.*?'
            r'class="Epkrse\s*">([^<]+)</div>',
            html, re.DOTALL
        ):
            pkg, icon, title = match.groups()
            if pkg not in seen and len(results) < 10:
                seen.add(pkg)
                results.append({
                    'package': pkg,
                    'title': decode_html(title),
                    'icon': upgrade_icon(icon)
                })

        # Method 2: If HTML patterns didn't work, try embedded JSON data
        if len(results) < 3:
            # Find packages in JSON format: [["com.package.name",7],[null,2,...
            packages = re.findall(r'\[\["(com\.[a-zA-Z0-9_.]+)",7\],\[null,2', html)
            for pkg in packages:
                if pkg in seen or len(results) >= 10:
                    continue

                # Find title: package...],..."Title",[rating
                title_pattern = rf'\[\["{re.escape(pkg)}",7\].*?\],"([^"]+)",\["[0-9.]+",\s*[0-9.]+'
                title_match = re.search(title_pattern, html)

                # Find icon right after package: [["pkg",7],[null,2,null/[size],[null,null,"URL"]
                icon_pattern = rf'\[\["{re.escape(pkg)}",7\],\[null,2,(?:null|\[[0-9]+,[0-9]+\]),\[null,null,"(https://play-lh\.googleusercontent\.com/[^"]+)"\]'
                icon_match = re.search(icon_pattern, html)

                if title_match:
                    seen.add(pkg)
                    title = decode_json(title_match.group(1))
                    icon = None
                    if icon_match:
                        icon = decode_json(icon_match.group(1))
                        icon = upgrade_icon(icon)
                    results.append({
                        'package': pkg,
                        'title': title,
                        'icon': icon
                    })

        return jsonify({'results': results[:5]})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/info/<path:pkg>')
def info(pkg):
    try:
        scraper = cloudscraper.create_scraper()
        response = scraper.get(
            f'https://play.google.com/store/apps/details?id={pkg}&hl=en',
            timeout=30
        )

        if response.status_code == 404:
            return jsonify({'error': 'App not found'}), 404

        html = response.text

        title_match = re.search(r'<h1[^>]*>([^<]+)</h1>', html)
        dev_match = re.search(r'<a[^>]*href="/store/apps/developer[^"]*"[^>]*>([^<]+)</a>', html)

        return jsonify({
            'package': pkg,
            'title': title_match.group(1) if title_match else pkg,
            'developer': dev_match.group(1) if dev_match else 'Unknown',
            'playStoreUrl': f'https://play.google.com/store/apps/details?id={pkg}'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/download-info/<path:pkg>')
def download_info(pkg):
    auth = get_auth_from_request()
    if not auth:
        return jsonify({'error': 'Not authenticated'}), 401

    try:
        info = get_download_info(pkg, auth)
        if 'error' in info:
            return jsonify(info), 400

        return jsonify({
            'success': True,
            'filename': info['filename'],
            'title': info['title'],
            'version': info['versionString'],
            'versionCode': info['versionCode'],
            'size': format_size(info['downloadSize']),
            'downloadUrl': info['downloadUrl'],
            'cookies': info['cookies'],
            'splits': [{
                'filename': f"{pkg}-{info['versionCode']}-{s['name']}.apk",
                'name': s['name'],
                'downloadUrl': s['downloadUrl']
            } for s in info['splits']]
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/download-info-stream/<path:pkg>')
def download_info_stream(pkg):
    """SSE endpoint that tries unlimited tokens until download URL is obtained."""
    import time

    # Get architecture from query parameter
    arch = request.args.get('arch', 'arm64-v8a')
    if arch not in SUPPORTED_ARCHS:
        arch = 'arm64-v8a'
    device_config = get_device_config(arch)

    def generate():
        attempt = 0

        # Try cached token for this architecture
        cached = get_cached_auth(arch)
        if cached:
            yield f"data: {json.dumps({'type': 'progress', 'attempt': 0, 'message': 'Trying cached token...'})}\n\n"
            try:
                info = get_download_info(pkg, cached)
                if 'error' not in info:
                    logger.info(f"Cached token worked for {pkg}")
                    result = {
                        'type': 'success',
                        'attempt': 0,
                        'filename': info['filename'],
                        'title': info['title'],
                        'version': info['versionString'],
                        'versionCode': info['versionCode'],
                        'size': format_size(info['downloadSize']),
                        'downloadUrl': info['downloadUrl'],
                        'cookies': info['cookies'],
                        'splits': [{
                            'filename': f"{pkg}-{info['versionCode']}-{s['name']}.apk",
                            'name': s['name'],
                            'downloadUrl': s['downloadUrl']
                        } for s in info['splits']]
                    }
                    yield f"data: {json.dumps(result)}\n\n"
                    return
                else:
                    yield f"data: {json.dumps({'type': 'progress', 'attempt': 0, 'message': 'Cached token failed, trying new tokens...'})}\n\n"
            except Exception as e:
                yield f"data: {json.dumps({'type': 'progress', 'attempt': 0, 'message': f'Cached token error: {str(e)[:30]}'})}\n\n"

        while True:
            attempt += 1

            yield f"data: {json.dumps({'type': 'progress', 'attempt': attempt, 'message': f'Trying token #{attempt}...'})}\n\n"

            try:
                # Get a fresh token from dispenser with arch-specific config
                scraper = cloudscraper.create_scraper()
                response = scraper.post(
                    DISPENSER_URL,
                    headers={
                        'User-Agent': 'com.aurora.store-4.6.1-70',
                        'Content-Type': 'application/json',
                    },
                    json=device_config,
                    timeout=30
                )

                if not response.ok:
                    logger.warning(f"Dispenser returned {response.status_code}, attempt {attempt}")
                    yield f"data: {json.dumps({'type': 'progress', 'attempt': attempt, 'message': f'Token #{attempt} - dispenser error ({response.status_code})'})}\n\n"
                    time.sleep(1)
                    continue

                auth_data = response.json()

                yield f"data: {json.dumps({'type': 'progress', 'attempt': attempt, 'message': f'Token #{attempt} - getting download info...'})}\n\n"

                # Try to get download info with this token
                info = get_download_info(pkg, auth_data)

                if 'error' in info:
                    error_msg = info['error'][:50]
                    logger.warning(f"Token #{attempt} failed for {pkg}: {info['error']}")
                    yield f"data: {json.dumps({'type': 'progress', 'attempt': attempt, 'message': f'Token #{attempt} - {error_msg}'})}\n\n"
                    time.sleep(0.5)
                    continue

                # Success! Save the working token for this arch and return info
                save_cached_auth(auth_data, arch)
                logger.info(f"Token #{attempt} worked for {pkg}")

                result = {
                    'type': 'success',
                    'attempt': attempt,
                    'filename': info['filename'],
                    'title': info['title'],
                    'version': info['versionString'],
                    'versionCode': info['versionCode'],
                    'size': format_size(info['downloadSize']),
                    'downloadUrl': info['downloadUrl'],
                    'cookies': info['cookies'],
                    'splits': [{
                        'filename': f"{pkg}-{info['versionCode']}-{s['name']}.apk",
                        'name': s['name'],
                        'downloadUrl': s['downloadUrl']
                    } for s in info['splits']]
                }
                yield f"data: {json.dumps(result)}\n\n"
                return

            except Exception as e:
                logger.warning(f"Download info attempt {attempt} failed: {e}")
                yield f"data: {json.dumps({'type': 'progress', 'attempt': attempt, 'message': f'Token #{attempt} - error: {str(e)[:50]}'})}\n\n"

            time.sleep(0.5)

    return Response(
        generate(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'X-Accel-Buffering': 'no',
        }
    )


@app.route('/download/<path:pkg>')
@app.route('/download/<path:pkg>/<int:split_index>')
def download(pkg, split_index=None):
    """Proxy download for when direct download fails."""
    auth = get_auth_from_request()
    if not auth:
        return jsonify({'error': 'Not authenticated'}), 401

    try:
        info = get_download_info(pkg, auth)
        if 'error' in info:
            return jsonify(info), 400

        if split_index is not None and info['splits'] and split_index < len(info['splits']):
            url = info['splits'][split_index]['downloadUrl']
            filename = f"{pkg}-{info['versionCode']}-{info['splits'][split_index]['name']}.apk"
        else:
            url = info['downloadUrl']
            filename = info['filename']

        # Build cookie header
        cookie_header = '; '.join([f"{c['name']}={c['value']}" for c in info.get('cookies', [])])
        headers = {'Cookie': cookie_header} if cookie_header else {}

        # Stream the download
        resp = requests.get(url, headers=headers, stream=True, timeout=60)

        def generate():
            for chunk in resp.iter_content(chunk_size=8192):
                yield chunk

        return Response(
            generate(),
            content_type='application/vnd.android.package-archive',
            headers={'Content-Disposition': f'attachment; filename="{filename}"'}
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500


import tempfile
import uuid

# Store temp merged APKs
TEMP_APKS = {}


@app.route('/api/download-merged-stream/<path:pkg>')
def download_merged_stream(pkg):
    """SSE endpoint that downloads, merges, signs APKs with progress updates."""
    import time

    arch = request.args.get('arch', 'arm64-v8a')
    if arch not in SUPPORTED_ARCHS:
        arch = 'arm64-v8a'
    device_config = get_device_config(arch)

    def generate():
        # Try to get a working token
        yield f"data: {json.dumps({'type': 'progress', 'step': 'auth', 'message': 'Getting auth token...'})}\n\n"

        auth_data = None
        info = None

        # Try cached token for this architecture
        cached = get_cached_auth(arch)
        if cached:
            try:
                info = get_download_info(pkg, cached)
                if 'error' not in info:
                    auth_data = cached
            except:
                pass

        if not auth_data:
            for attempt in range(50):
                yield f"data: {json.dumps({'type': 'progress', 'step': 'auth', 'message': f'Trying token #{attempt+1}...'})}\n\n"
                try:
                    scraper = cloudscraper.create_scraper()
                    response = scraper.post(
                        DISPENSER_URL,
                        headers={
                            'User-Agent': 'com.aurora.store-4.6.1-70',
                            'Content-Type': 'application/json',
                        },
                        json=device_config,
                        timeout=30
                    )

                    if not response.ok:
                        time.sleep(1)
                        continue

                    auth_data = response.json()
                    info = get_download_info(pkg, auth_data)

                    if 'error' not in info:
                        save_cached_auth(auth_data, arch)
                        break
                    else:
                        auth_data = None
                        time.sleep(0.5)

                except Exception as e:
                    time.sleep(0.5)

        if not info or 'error' in info:
            yield f"data: {json.dumps({'type': 'error', 'message': 'Failed to get download info'})}\n\n"
            return

        splits = info.get('splits', [])
        total_files = 1 + len(splits)

        yield f"data: {json.dumps({'type': 'progress', 'step': 'download', 'message': f'Downloading APK...', 'current': 1, 'total': total_files})}\n\n"

        cookie_header = '; '.join([f"{c['name']}={c['value']}" for c in info.get('cookies', [])])
        headers = {'Cookie': cookie_header} if cookie_header else {}

        try:
            base_resp = requests.get(info['downloadUrl'], headers=headers, timeout=120)
            if not base_resp.ok:
                yield f"data: {json.dumps({'type': 'error', 'message': 'Failed to download base APK'})}\n\n"
                return
            base_apk = base_resp.content

            # If no splits, return original APK without merging/signing
            if not splits:
                file_id = str(uuid.uuid4())
                TEMP_APKS[file_id] = {
                    'data': base_apk,
                    'filename': info['filename'],
                    'created': time.time()
                }
                yield f"data: {json.dumps({'type': 'success', 'download_id': file_id, 'filename': info['filename'], 'original': True})}\n\n"
                return

            # Download splits
            splits_data = []
            for i, split in enumerate(splits):
                split_name = split['name']
                yield f"data: {json.dumps({'type': 'progress', 'step': 'download', 'message': f'Downloading {split_name} ({i+2}/{total_files})...', 'current': i+2, 'total': total_files})}\n\n"
                split_resp = requests.get(split['downloadUrl'], headers=headers, timeout=120)
                if not split_resp.ok:
                    yield f"data: {json.dumps({'type': 'error', 'message': f'Failed to download {split_name}'})}\n\n"
                    return
                splits_data.append((split_name, split_resp.content))

            yield f"data: {json.dumps({'type': 'progress', 'step': 'merge', 'message': 'Merging APKs...'})}\n\n"
            merged_apk = merge_apks(base_apk, splits_data)

            yield f"data: {json.dumps({'type': 'progress', 'step': 'sign', 'message': 'Signing APK...'})}\n\n"
            signed_apk = sign_apk(merged_apk)

            # Save to temp storage
            file_id = str(uuid.uuid4())
            TEMP_APKS[file_id] = {
                'data': signed_apk,
                'filename': f"{pkg}-{info['versionCode']}-merged.apk",
                'created': time.time()
            }

            yield f"data: {json.dumps({'type': 'success', 'download_id': file_id, 'filename': TEMP_APKS[file_id]['filename']})}\n\n"

        except Exception as e:
            yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"

    return Response(
        generate(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'X-Accel-Buffering': 'no',
        }
    )


@app.route('/api/download-temp/<file_id>')
def download_temp(file_id):
    """Download a temporary merged APK."""
    if file_id not in TEMP_APKS:
        return jsonify({'error': 'File not found or expired'}), 404

    apk_data = TEMP_APKS[file_id]
    # Clean up after download
    del TEMP_APKS[file_id]

    return Response(
        apk_data['data'],
        content_type='application/vnd.android.package-archive',
        headers={'Content-Disposition': f'attachment; filename="{apk_data["filename"]}"'}
    )


@app.route('/api/download-merged/<path:pkg>')
def download_merged(pkg):
    """Download and merge all APKs into a single installable APK (non-streaming fallback)."""
    import time

    # Get architecture from query parameter
    arch = request.args.get('arch', 'arm64-v8a')
    if arch not in SUPPORTED_ARCHS:
        arch = 'arm64-v8a'
    device_config = get_device_config(arch)

    # Try to get a working token and download info
    auth_data = None
    info = None

    # Try cached token for this architecture
    cached = get_cached_auth(arch)
    if cached:
        try:
            info = get_download_info(pkg, cached)
            if 'error' not in info:
                auth_data = cached
        except:
            pass

    # If cached didn't work, try new tokens
    if not auth_data:
        for attempt in range(100):  # Limit attempts for non-streaming endpoint
            try:
                scraper = cloudscraper.create_scraper()
                response = scraper.post(
                    DISPENSER_URL,
                    headers={
                        'User-Agent': 'com.aurora.store-4.6.1-70',
                        'Content-Type': 'application/json',
                    },
                    json=device_config,
                    timeout=30
                )

                if not response.ok:
                    time.sleep(1)
                    continue

                auth_data = response.json()
                info = get_download_info(pkg, auth_data)

                if 'error' not in info:
                    save_cached_auth(auth_data, arch)
                    break
                else:
                    auth_data = None
                    time.sleep(0.5)

            except Exception as e:
                logger.warning(f"Merge download attempt {attempt} failed: {e}")
                time.sleep(0.5)

    if not info or 'error' in info:
        return jsonify({'error': 'Failed to get download info after multiple attempts'}), 500

    # Build cookie header for downloads
    cookie_header = '; '.join([f"{c['name']}={c['value']}" for c in info.get('cookies', [])])
    headers = {'Cookie': cookie_header} if cookie_header else {}

    try:
        # Download base APK
        logger.info(f"Downloading base APK for {pkg}")
        base_resp = requests.get(info['downloadUrl'], headers=headers, timeout=120)
        if not base_resp.ok:
            return jsonify({'error': f'Failed to download base APK: {base_resp.status_code}'}), 500
        base_apk = base_resp.content

        # If no splits, just return base APK
        if not info['splits']:
            return Response(
                base_apk,
                content_type='application/vnd.android.package-archive',
                headers={'Content-Disposition': f'attachment; filename="{info["filename"]}"'}
            )

        # Download all splits
        splits_data = []
        for split in info['splits']:
            logger.info(f"Downloading split: {split['name']}")
            split_resp = requests.get(split['downloadUrl'], headers=headers, timeout=120)
            if not split_resp.ok:
                return jsonify({'error': f'Failed to download split {split["name"]}: {split_resp.status_code}'}), 500
            splits_data.append((split['name'], split_resp.content))

        # Merge APKs
        logger.info(f"Merging {len(splits_data) + 1} APKs")
        merged_apk = merge_apks(base_apk, splits_data)

        # Sign the merged APK
        logger.info("Signing merged APK")
        signed_apk = sign_apk(merged_apk)

        merged_filename = f"{pkg}-{info['versionCode']}-merged.apk"
        return Response(
            signed_apk,
            content_type='application/vnd.android.package-archive',
            headers={'Content-Disposition': f'attachment; filename="{merged_filename}"'}
        )

    except Exception as e:
        logger.error(f"Merge download failed: {e}")
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    print('Starting GPlay Downloader on http://localhost:5000')
    print(f'gpapi available: {HAS_GPAPI}')
    app.run(host='0.0.0.0', port=5000, debug=True)
