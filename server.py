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
import threading
import time as time_module
import random
from flask import Flask, request, jsonify, send_file, Response

# Use gevent for parallel downloads (compatible with gunicorn gevent workers)
try:
    from gevent.pool import Pool as GeventPool
    HAS_GEVENT = True
except ImportError:
    HAS_GEVENT = False
from flask_cors import CORS
import requests
import cloudscraper

# Thread-local scraper instances (thread-safe for concurrent requests)
_scraper_local = threading.local()


def get_scraper():
    """Get a thread-local cloudscraper instance."""
    if not hasattr(_scraper_local, 'scraper'):
        _scraper_local.scraper = cloudscraper.create_scraper()
    return _scraper_local.scraper


# Configure logging (INFO in production, DEBUG via env)
_log_level = os.environ.get('LOG_LEVEL', 'INFO').upper()
logging.basicConfig(level=getattr(logging, _log_level, logging.INFO), format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__, static_folder='public', static_url_path='')
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024  # 1MB max request body

from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

_cors_origins = os.environ.get('CORS_ORIGINS', '')
if _cors_origins:
    CORS(app, origins=_cors_origins.split(','))


@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    csp = '; '.join([
        "default-src 'self'",
        f"script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net{_ANALYTICS_ORIGIN}",
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
        "font-src 'self' https://fonts.gstatic.com",
        "img-src 'self' data: https://play-lh.googleusercontent.com",
        f"connect-src 'self' https://*.google.com https://*.googleapis.com https://*.googleusercontent.com https://*.ggpht.com{_ANALYTICS_ORIGIN}",
        "frame-src 'self'",
        "object-src 'none'",
        "base-uri 'self'",
        "form-action 'self'",
        "worker-src 'self' blob:",
    ])
    response.headers['Content-Security-Policy'] = csp
    return response


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
from contextlib import contextmanager
import fcntl

AUTH_CACHE_DIR = Path.home()
AUTH_CACHE_FILES = {
    'arm64-v8a': AUTH_CACHE_DIR / '.gplay-auth.json',  # Default for backward compat
    'armeabi-v7a': AUTH_CACHE_DIR / '.gplay-auth-armv7.json',
}


@contextmanager
def file_lock(file_path, exclusive=True):
    """Context manager for file locking (prevents race conditions)."""
    lock_path = Path(str(file_path) + '.lock')
    lock_fd = None
    try:
        lock_fd = open(lock_path, 'w')
        fcntl.flock(lock_fd, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        yield
    finally:
        if lock_fd:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            lock_fd.close()

# Import device profiles from centralized module
from device_profiles import (
    ARM64_PROFILES, ARMV7_PROFILES,
    DEFAULT_ARM64_PROFILE, DEFAULT_ARMV7_PROFILE,
    get_profile, get_all_profiles, get_priority_profiles,
)

# Legacy aliases for backward compatibility
DEVICE_ARM64 = DEFAULT_ARM64_PROFILE
DEVICE_ARMV7 = DEFAULT_ARMV7_PROFILE
DEFAULT_DEVICE = DEVICE_ARM64

SUPPORTED_ARCHS = ['arm64-v8a', 'armeabi-v7a']


def get_device_config(arch='arm64-v8a', profile_index=0):
    """Get device config for a specific architecture.

    Args:
        arch: 'arm64-v8a' or 'armeabi-v7a'
        profile_index: Index into the profile list (for fallback rotation)

    Returns:
        Device profile dict
    """
    if arch == 'armeabi-v7a':
        profiles = ARMV7_PROFILES
    else:
        profiles = ARM64_PROFILES

    # Use modulo to wrap around if index exceeds list length
    idx = profile_index % len(profiles)
    return profiles[idx][1].copy()


def get_priority_device_configs(arch='arm64-v8a'):
    """Get priority-ordered list of device profiles for an architecture.

    Returns profiles sorted by reliability (best first), with remaining
    profiles appended after.

    Args:
        arch: 'arm64-v8a' or 'armeabi-v7a'

    Returns:
        List of (profile_key, profile_dict) tuples
    """
    internal_arch = 'armv7' if arch == 'armeabi-v7a' else 'arm64'
    return get_priority_profiles(internal_arch)


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

    tmp_in_path = None
    tmp_out_path = None
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
            except Exception:
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


def sanitize_filename(name):
    """Sanitize a filename for use in Content-Disposition headers."""
    name = name.replace('/', '_').replace('\\', '_').replace('\0', '')
    name = re.sub(r'[\r\n"]', '', name)
    name = os.path.basename(name)
    return name or 'download.apk'


# Valid Android package name: segments of [a-zA-Z][a-zA-Z0-9_]* separated by dots, max 255 chars
_PKG_RE = re.compile(r'^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$')


def validate_package_name(pkg):
    """Return True if pkg is a valid Android package name."""
    return bool(pkg and len(pkg) <= 255 and _PKG_RE.match(pkg))


def _require_valid_pkg(pkg):
    """Return a 400 JSON response if pkg is invalid, else None."""
    if not validate_package_name(pkg):
        return jsonify({'error': 'Invalid package name'}), 400
    return None


def get_cached_auth(arch='arm64-v8a'):
    """Load cached auth from server-side auth file for specific architecture (thread-safe)."""
    cache_file = AUTH_CACHE_FILES.get(arch, AUTH_CACHE_FILES['arm64-v8a'])
    if not cache_file.exists():
        return None

    try:
        with file_lock(cache_file, exclusive=False):  # Shared lock for reads
            with open(cache_file) as f:
                auth = json.load(f)
        if auth.get('authToken') and auth.get('gsfId'):
            logger.info(f"Using cached auth token for {arch}")
            return auth
    except Exception as e:
        logger.warning(f"Failed to load cached auth for {arch}: {e}")
    return None


def save_cached_auth(auth_data, arch='arm64-v8a'):
    """Save auth data to server-side cache file for specific architecture (thread-safe, atomic)."""
    cache_file = AUTH_CACHE_FILES.get(arch, AUTH_CACHE_FILES['arm64-v8a'])
    tmp_file = cache_file.with_suffix('.tmp')

    try:
        with file_lock(cache_file, exclusive=True):  # Exclusive lock for writes
            # Write to temp file first (atomic write pattern)
            tmp_file.write_text(json.dumps(auth_data, indent=2))
            os.chmod(str(tmp_file), 0o600)  # Restrict permissions before rename
            # Atomic rename
            tmp_file.replace(cache_file)
        logger.info(f"Auth saved to: {cache_file}")
        return True
    except Exception as e:
        logger.error(f"Failed to save auth: {e}")
        # Clean up temp file if it exists
        if tmp_file.exists():
            try:
                tmp_file.unlink()
            except Exception:
                pass
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


def get_auth_from_request(arch='arm64-v8a'):
    # Always prefer cached CLI auth since AuroraOSS dispenser tokens have limited permissions
    cached = get_cached_auth(arch)
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
        except Exception:
            pass
    return None


def get_auth_headers(auth, accept_language='en-US'):
    """
    Build headers for Google Play API requests.
    Enhanced with additional headers from Aurora Store for better compatibility.
    """
    device_info = auth.get('deviceInfoProvider', {})
    locale = accept_language.replace('-', '_')

    headers = {
        'Authorization': f"Bearer {auth.get('authToken', '')}",
        'User-Agent': device_info.get('userAgentString', 'Android-Finsky/41.2.29-23 [0] [PR] 639844241 (api=3,versionCode=84122900,sdk=34,device=lynx,hardware=lynx,product=lynx,platformVersionRelease=14,model=Pixel%207a,buildId=UQ1A.231205.015,isWideScreen=0,supportedAbis=arm64-v8a;armeabi-v7a;armeabi)'),
        'X-DFE-Device-Id': auth.get('gsfId', ''),
        'Accept-Language': accept_language,
        'X-DFE-Encoded-Targets': 'CAESN/qigQYC2AMBFfUbyA7SM5Ij/CvfBoIDgxXrBPsDlQUdMfOLAfoFrwEHgAcBrQYhoA0cGt4MKK0Y2gI',
        'X-DFE-Phenotype': 'H4sIAAAAAAAAAB3OO3KjMAAA0KRNuWXukBkBQkAJ2MhgAZb5u2GCwQZbCH_EJ77QHmgvtDtbv-Z9_H63zXXU0NVPB1odlyGy7751Q3CitlPDvFd8lxhz3tpNmz7P92CFw73zdHU2Ie0Ad2kmR8lxhiErTFLt3RPGfJQHSDy7Clw10bg8kqf2owLokN4SecJTLoSwBnzQSd652_MOf2d1vKBNVedzg4ciPoLz2mQ8efGAgYeLou-l-PXn_7Sna1MfhHuySxt-4esulEDp8Sbq54CPPKjpANW-lkU2IZ0F92LBI-ukCKSptqeq1eXU96LD9nZfhKHdtjSWwJqUm_2r6pMHOxk01saVanmNopjX3YxQafC4iC6T55aRbC8nTI98AF_kItIQAJb5EQxnKTO7TZDWnr01HVPxelb9A2OWX6poidMWl16K54kcu_jhXw-JSBQkVcD_fPsLSZu6joIBAAA',
        'X-DFE-Client-Id': 'am-android-google',
        'X-DFE-Network-Type': '4',
        'X-DFE-Content-Filters': '',
        'X-Limit-Ad-Tracking-Enabled': 'false',
        'X-Ad-Id': '',
        'X-DFE-UserLanguages': locale,
        'X-DFE-Request-Params': 'timeoutMs=4000',
        'X-DFE-Cookie': auth.get('dfeCookie', ''),
        'X-DFE-No-Prefetch': 'true',
    }

    # Add optional tokens if available in auth data
    if auth.get('deviceCheckInConsistencyToken'):
        headers['X-DFE-Device-Checkin-Consistency-Token'] = auth['deviceCheckInConsistencyToken']
    if auth.get('deviceConfigToken'):
        headers['X-DFE-Device-Config-Token'] = auth['deviceConfigToken']
    if device_info.get('mccMnc'):
        headers['X-DFE-MCCMNC'] = device_info['mccMnc']

    return headers


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
    details_resp = requests.get(f'{DETAILS_URL}?doc={pkg}', headers=headers, timeout=(5, 15))
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
        purchase_resp = requests.post(PURCHASE_URL, headers=purchase_headers, data=purchase_data, timeout=(5, 15))
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
        timeout=(5, 15)
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


SITE_URL = os.environ.get('SITE_URL', '').rstrip('/')
UMAMI_SCRIPT = os.environ.get('UMAMI_SCRIPT', '')
_ANALYTICS_ORIGIN = ''
if UMAMI_SCRIPT:
    _m = re.search(r'src="(https?://[^"/]+)', UMAMI_SCRIPT)
    if _m:
        _ANALYTICS_ORIGIN = ' ' + _m.group(1)


# Routes
@app.route('/')
def index():
    with open(os.path.join(app.static_folder, 'index.html'), 'r') as f:
        html = f.read()
    if SITE_URL:
        html = html.replace('__SITE_URL__', SITE_URL)
    else:
        # Strip SEO tags that need a domain
        import re
        html = re.sub(r'<link rel="canonical"[^>]*>\n?', '', html)
        html = re.sub(r'<meta property="og:url"[^>]*>\n?', '', html)
        html = re.sub(r'<meta property="og:image"[^>]*>\n?', '', html)
        html = re.sub(r'<meta name="twitter:image"[^>]*>\n?', '', html)
    if UMAMI_SCRIPT:
        html = html.replace('</head>', f'  {UMAMI_SCRIPT}\n</head>')
    return Response(html, content_type='text/html')


_DISABLE_APP_PAGES = os.environ.get('DISABLE_APP_PAGES', '') == '1'

if not _DISABLE_APP_PAGES:
    @app.route('/apps')
    @app.route('/apps/')
    def apps_browse():
        from app_pages import render_browse_page
        html = render_browse_page()
        if UMAMI_SCRIPT:
            html = html.replace('</head>', f'  {UMAMI_SCRIPT}\n</head>')
        return Response(html, content_type='text/html')

    @app.route('/app/<path:pkg>')
    def app_page(pkg):
        if not re.match(r'^[a-zA-Z][a-zA-Z0-9_.]*$', pkg):
            return Response('Invalid package name', status=400, content_type='text/plain')
        from app_pages import render_app_page
        html = render_app_page(pkg)
        if not html:
            return Response('App not found. <a href="/">Try searching for it</a>.', status=404, content_type='text/html')
        if UMAMI_SCRIPT:
            html = html.replace('</head>', f'  {UMAMI_SCRIPT}\n</head>')
        return Response(html, content_type='text/html')


@app.route('/robots.txt')
def robots():
    with open(os.path.join(app.static_folder, 'robots.txt'), 'r') as f:
        txt = f.read()
    if SITE_URL:
        txt = txt.replace('__SITE_URL__', SITE_URL)
    else:
        txt = txt.replace('Sitemap: __SITE_URL__/sitemap.xml\n', '')
    return Response(txt, content_type='text/plain')


@app.route('/sitemap.xml')
def sitemap():
    if not SITE_URL:
        return Response('', status=404)
    with open(os.path.join(app.static_folder, 'sitemap.xml'), 'r') as f:
        xml = f.read().replace('__SITE_URL__', SITE_URL)
    # Inject cached app pages into sitemap
    if not _DISABLE_APP_PAGES:
        try:
            from app_pages import _load_meta
            meta = _load_meta()
            app_urls = ''.join(
                f'  <url><loc>{SITE_URL}/app/{pkg}</loc><changefreq>monthly</changefreq><priority>0.8</priority></url>\n'
                for pkg in meta
            )
            if app_urls:
                xml = xml.replace('</urlset>', app_urls + '</urlset>')
        except Exception:
            pass
    return Response(xml, content_type='application/xml')


@app.route('/health')
def health_check():
    """Health check endpoint for monitoring and load balancers."""
    import psutil

    try:
        # Check disk space for temp storage
        disk = psutil.disk_usage(str(TEMP_APK_DIR))
        disk_ok = disk.percent < 90

        # Check memory
        mem = psutil.virtual_memory()
        mem_ok = mem.percent < 90

        # Count active temp files
        with TEMP_APK_LOCK:
            temp_count = len(TEMP_APK_REGISTRY)
            temp_size = sum(m.get('size', 0) for m in TEMP_APK_REGISTRY.values())

        # Get semaphore availability
        download_slots = download_semaphore._value
        merge_slots = merge_semaphore._value

        status = {
            'status': 'healthy' if (disk_ok and mem_ok) else 'degraded',
            'gpapi_available': HAS_GPAPI,
            'temp_files': temp_count,
            'temp_size_mb': round(temp_size / 1024 / 1024, 2),
            'disk_percent': disk.percent,
            'memory_percent': mem.percent,
            'download_slots_available': download_slots,
            'download_slots_max': MAX_CONCURRENT_DOWNLOADS,
            'merge_slots_available': merge_slots,
            'merge_slots_max': MAX_CONCURRENT_MERGES,
        }

        code = 200 if status['status'] == 'healthy' else 503
        return jsonify(status), code

    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({
            'status': 'error',
            'error': 'Health check failed'
        }), 500


@app.route('/api/stats')
def stats():
    """Return download count for the UI."""
    return jsonify({'downloads': get_download_count()})


# Per-worker rate limit cache; with ProxyFix, request.remote_addr is now the
# real client IP (via Cloudflare's X-Forwarded-For). Each gunicorn worker
# tracks independently; worst case is N workers allow N increments in 10s.
_last_increment = {}

@app.route('/api/stats/increment', methods=['POST'])
def stats_increment():
    """Increment download counter (for client-side installs like ADB)."""
    ip = request.remote_addr
    now = time_module.time()
    if ip in _last_increment and now - _last_increment[ip] < 10:
        return jsonify({'downloads': get_download_count()}), 429
    _last_increment[ip] = now
    # Periodic cleanup: remove stale entries to prevent unbounded growth
    if len(_last_increment) > 1000:
        stale = [k for k, v in _last_increment.items() if now - v > 60]
        for k in stale:
            del _last_increment[k]
    count = increment_download_count()
    return jsonify({'downloads': count})


@app.route('/api/auth', methods=['POST'])
def auth():
    # First check if we have a valid cached token - use strict validation (Chase test)
    cached = get_cached_auth()
    if cached and test_auth_token(cached, strict=True):
        logger.info("Using existing valid cached token (passed Chase test)")
        return jsonify({'success': True, 'authenticated': True, 'cached': True})

    # If we have a cached token that at least works for simple apps, use it
    # but warn that some apps may not work
    if cached and test_auth_token(cached, strict=False):
        logger.warning("Cached token works for simple apps (may have limited functionality)")
        return jsonify({'success': True, 'authenticated': True, 'cached': True, 'warning': 'Token may not work for all apps'})

    return jsonify({'error': 'No valid cached token. Use the streaming auth endpoint.'}), 400


@app.route('/api/auth/stream', methods=['GET'])
def auth_stream():
    """SSE endpoint that tries tokens with timeout protection."""
    def generate():
        start_time = time_module.time()

        # First check if we have a valid cached token
        cached = get_cached_auth()
        if cached and test_auth_token(cached, strict=True):
            logger.info("Using existing valid cached token (passed Chase test)")
            yield f"data: {json.dumps({'type': 'success', 'authenticated': True, 'cached': True, 'attempt': 0})}\n\n"
            return

        attempt = 0
        # Get priority-ordered profiles for rotation
        profiles = get_priority_device_configs('arm64-v8a')
        profile_count = len(profiles)
        max_attempts = profile_count * MAX_PROFILE_CYCLES

        while True:
            # Check timeout
            if time_module.time() - start_time > SSE_MAX_DURATION:
                yield f"data: {json.dumps({'type': 'error', 'message': 'Timeout - please try again'})}\n\n"
                return

            attempt += 1

            if attempt > max_attempts:
                yield f"data: {json.dumps({'type': 'error', 'message': f'Failed after trying all {profile_count} profiles {MAX_PROFILE_CYCLES} times'})}\n\n"
                return

            # Rotate through profiles
            profile_key, profile = profiles[(attempt - 1) % profile_count]
            profile_name = profile.get('UserReadableName', profile_key)

            # Send progress update
            yield f"data: {json.dumps({'type': 'progress', 'attempt': attempt, 'message': f'Trying token #{attempt} ({profile_name})...'})}\n\n"

            scraper = None
            try:
                scraper = cloudscraper.create_scraper()  # Fresh scraper each attempt
                response = scraper.post(
                    DISPENSER_URL,
                    headers={
                        'User-Agent': 'com.aurora.store-4.6.1-70',
                        'Content-Type': 'application/json',
                    },
                    json=profile,
                    timeout=(5, 30)
                )

                if not response.ok:
                    logger.warning(f"Dispenser returned {response.status_code}, attempt {attempt} ({profile_name})")
                    yield f"data: {json.dumps({'type': 'progress', 'attempt': attempt, 'message': f'Token #{attempt} ({profile_name}) - dispenser error ({response.status_code})'})}\n\n"
                    time_module.sleep(1)
                    continue

                auth_data = response.json()

                # Send validation progress
                yield f"data: {json.dumps({'type': 'progress', 'attempt': attempt, 'message': f'Token #{attempt} ({profile_name}) - validating...'})}\n\n"

                # Test with strict validation (Chase) - this ensures token works for all apps
                if test_auth_token(auth_data, strict=True):
                    # Save the working token
                    save_cached_auth(auth_data)
                    logger.info(f"Token #{attempt} ({profile_name}) validated with Chase and saved")
                    yield f"data: {json.dumps({'type': 'success', 'authenticated': True, 'cached': False, 'attempt': attempt})}\n\n"
                    return
                else:
                    logger.warning(f"Token #{attempt} ({profile_name}) failed Chase validation")
                    yield f"data: {json.dumps({'type': 'progress', 'attempt': attempt, 'message': f'Token #{attempt} ({profile_name}) - failed validation, retrying...'})}\n\n"

            except requests.exceptions.ConnectionError as e:
                logger.warning(f"Connection error on auth attempt {attempt}: {e}")
                yield f"data: {json.dumps({'type': 'progress', 'attempt': attempt, 'message': f'Token #{attempt} - retrying connection...'})}\n\n"
                time_module.sleep(get_backoff_delay(attempt, base=2.0))
            except requests.exceptions.Timeout as e:
                logger.warning(f"Timeout on auth attempt {attempt}: {e}")
                yield f"data: {json.dumps({'type': 'progress', 'attempt': attempt, 'message': f'Token #{attempt} - request timeout, retrying...'})}\n\n"
                time_module.sleep(get_backoff_delay(attempt))
            except Exception as e:
                logger.warning(f"Auth attempt {attempt} failed: {e}")
                yield f"data: {json.dumps({'type': 'progress', 'attempt': attempt, 'message': f'Token #{attempt} - retrying...'})}\n\n"
                time_module.sleep(get_backoff_delay(attempt, base=0.5))
            finally:
                if scraper:
                    scraper.close()

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


_search_rate = {}  # {ip: [timestamps]}
SEARCH_RATE_LIMIT = 10  # max searches per minute per IP
SEARCH_RATE_WINDOW = 60  # seconds

@app.route('/api/search')
def search():
    query = request.args.get('q', '')
    if not query:
        return jsonify({'error': 'Query required'}), 400
    if len(query) > 200:
        return jsonify({'error': 'Query too long (max 200 characters)'}), 400

    # Per-IP search rate limit
    ip = request.remote_addr
    now = time_module.time()
    timestamps = [t for t in _search_rate.get(ip, []) if now - t < SEARCH_RATE_WINDOW]
    if len(timestamps) >= SEARCH_RATE_LIMIT:
        return jsonify({'error': 'Too many searches, please wait'}), 429
    timestamps.append(now)
    _search_rate[ip] = timestamps
    # Periodic cleanup
    if len(_search_rate) > 5000:
        stale_ips = [k for k, v in _search_rate.items() if not any(now - t < SEARCH_RATE_WINDOW for t in v)]
        for k in stale_ips:
            del _search_rate[k]

    # Normalize query for better cache hits
    normalized_query = normalize_search_query(query)

    # Check cache first (6 hour TTL)
    cached_results = get_cached_search(normalized_query)
    if cached_results is not None:
        return jsonify({'results': cached_results, 'cached': True})

    try:
        response = get_scraper().get(
            'https://play.google.com/store/search',
            params={'q': query, 'c': 'apps'},
            timeout=(5, 10)
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

        final_results = results[:5]
        # Cache the results for future requests
        cache_search(normalized_query, final_results)
        return jsonify({'results': final_results})
    except Exception as e:
        logger.error(f"Search failed for '{query}': {e}")
        return jsonify({'error': 'Search failed, please try again'}), 500


@app.route('/api/info/<path:pkg>')
def info(pkg):
    err = _require_valid_pkg(pkg)
    if err:
        return err
    try:
        response = get_scraper().get(
            f'https://play.google.com/store/apps/details?id={pkg}&hl=en',
            timeout=(5, 30)
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
        logger.error(f"Info lookup failed for {pkg}: {e}")
        return jsonify({'error': 'Failed to get app info'}), 500


@app.route('/api/download-info/<path:pkg>')
def download_info(pkg):
    err = _require_valid_pkg(pkg)
    if err:
        return err
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
        logger.error(f"Download info failed for {pkg}: {e}")
        return jsonify({'error': 'Failed to get download info'}), 500


@app.route('/api/download-info-stream/<path:pkg>')
def download_info_stream(pkg):
    """SSE endpoint that tries tokens until download URL is obtained (with timeout protection)."""
    err = _require_valid_pkg(pkg)
    if err:
        return err

    # Get architecture from query parameter
    arch = request.args.get('arch', 'arm64-v8a')
    if arch not in SUPPORTED_ARCHS:
        arch = 'arm64-v8a'

    # Get priority-ordered profiles for this architecture
    profiles = get_priority_device_configs(arch)
    profile_count = len(profiles)

    def generate():
        start_time = time_module.time()
        attempt = 0
        max_attempts = profile_count * MAX_PROFILE_CYCLES

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
                    if not _DISABLE_APP_PAGES:
                        try:
                            from app_pages import on_download_success
                            on_download_success(pkg, info['title'])
                        except Exception:
                            pass
                    return
                else:
                    yield f"data: {json.dumps({'type': 'progress', 'attempt': 0, 'message': 'Cached token failed, trying new tokens...'})}\n\n"
            except Exception as e:
                logger.warning(f"Cached token error for {pkg}: {e}")
                yield f"data: {json.dumps({'type': 'progress', 'attempt': 0, 'message': 'Cached token error, trying new tokens...'})}\n\n"

        while True:
            # Check timeout
            if time_module.time() - start_time > SSE_MAX_DURATION:
                yield f"data: {json.dumps({'type': 'error', 'message': 'Timeout - please try again'})}\n\n"
                return

            attempt += 1

            if attempt > max_attempts:
                yield f"data: {json.dumps({'type': 'error', 'message': f'Failed after trying all {profile_count} profiles {MAX_PROFILE_CYCLES} times'})}\n\n"
                return

            # Rotate through profiles
            profile_key, profile = profiles[(attempt - 1) % profile_count]
            profile_name = profile.get('UserReadableName', profile_key)

            yield f"data: {json.dumps({'type': 'progress', 'attempt': attempt, 'message': f'Trying token #{attempt} ({profile_name})...'})}\n\n"

            scraper = None
            try:
                # Get a fresh token from dispenser with profile rotation
                scraper = cloudscraper.create_scraper()  # Fresh scraper each attempt
                response = scraper.post(
                    DISPENSER_URL,
                    headers={
                        'User-Agent': 'com.aurora.store-4.6.1-70',
                        'Content-Type': 'application/json',
                    },
                    json=profile,
                    timeout=(5, 30)
                )

                if not response.ok:
                    logger.warning(f"Dispenser returned {response.status_code}, attempt {attempt} ({profile_name})")
                    yield f"data: {json.dumps({'type': 'progress', 'attempt': attempt, 'message': f'Token #{attempt} ({profile_name}) - dispenser error ({response.status_code})'})}\n\n"
                    time_module.sleep(1)
                    continue

                auth_data = response.json()

                yield f"data: {json.dumps({'type': 'progress', 'attempt': attempt, 'message': f'Token #{attempt} ({profile_name}) - getting download info...'})}\n\n"

                # Try to get download info with this token
                info = get_download_info(pkg, auth_data)

                if 'error' in info:
                    error_msg = info['error'][:50]
                    logger.warning(f"Token #{attempt} ({profile_name}) failed for {pkg}: {info['error']}")
                    yield f"data: {json.dumps({'type': 'progress', 'attempt': attempt, 'message': f'Token #{attempt} ({profile_name}) - {error_msg}'})}\n\n"
                    time_module.sleep(0.5)
                    continue

                # Success! Save the working token for this arch and return info
                save_cached_auth(auth_data, arch)
                logger.info(f"Token #{attempt} ({profile_name}) worked for {pkg}")

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
                try:
                    from app_pages import on_download_success
                    on_download_success(pkg, info['title'])
                except Exception:
                    pass
                return

            except requests.exceptions.ConnectionError as e:
                logger.warning(f"Connection error on attempt {attempt}: {e}")
                yield f"data: {json.dumps({'type': 'progress', 'attempt': attempt, 'message': f'Token #{attempt} - retrying connection...'})}\n\n"
                time_module.sleep(get_backoff_delay(attempt, base=2.0))
            except requests.exceptions.Timeout as e:
                logger.warning(f"Timeout on attempt {attempt}: {e}")
                yield f"data: {json.dumps({'type': 'progress', 'attempt': attempt, 'message': f'Token #{attempt} - request timeout, retrying...'})}\n\n"
                time_module.sleep(get_backoff_delay(attempt))
            except Exception as e:
                logger.warning(f"Download info attempt {attempt} failed: {e}")
                yield f"data: {json.dumps({'type': 'progress', 'attempt': attempt, 'message': f'Token #{attempt} - retrying...'})}\n\n"
                time_module.sleep(get_backoff_delay(attempt, base=0.5))
            finally:
                if scraper:
                    scraper.close()

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
    err = _require_valid_pkg(pkg)
    if err:
        return err
    arch = request.args.get('arch', 'arm64-v8a')
    if arch not in SUPPORTED_ARCHS:
        arch = 'arm64-v8a'
    auth = get_auth_from_request(arch)
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
            headers={'Content-Disposition': f'attachment; filename="{sanitize_filename(filename)}"'}
        )
    except Exception as e:
        logger.error(f"Proxy download failed for {pkg}: {e}")
        return jsonify({'error': 'Download failed'}), 500


import tempfile
import uuid

# =============================================================================
# Download Counter (persistent, file-based)
# =============================================================================

DOWNLOAD_COUNTER_FILE = Path.home() / '.gplay-download-count'


def get_download_count():
    """Read the current download count."""
    try:
        with file_lock(DOWNLOAD_COUNTER_FILE, exclusive=False):
            return int(DOWNLOAD_COUNTER_FILE.read_text().strip())
    except Exception:
        return 0


def increment_download_count():
    """Atomically increment the download counter (safe across gunicorn workers)."""
    try:
        with file_lock(DOWNLOAD_COUNTER_FILE, exclusive=True):
            try:
                count = int(DOWNLOAD_COUNTER_FILE.read_text().strip()) + 1
            except Exception:
                count = 1
            DOWNLOAD_COUNTER_FILE.write_text(str(count))
            return count
    except Exception as e:
        logger.warning(f"Failed to update download counter: {e}")
        return get_download_count()


# =============================================================================
# Disk-Based Temporary APK Storage (Production-Ready)
# =============================================================================

# Configuration
TEMP_APK_DIR = Path(tempfile.gettempdir()) / 'gplay_apks'
TEMP_APK_TTL = 600  # 10 minutes
MAX_TEMP_STORAGE_MB = 2048  # 2GB max temp storage
TEMP_APK_DIR.mkdir(exist_ok=True)

# Per-worker registry for temp files (lightweight metadata only).
# Cross-worker access is handled by disk fallback in consume_temp_apk().
TEMP_APK_REGISTRY = {}  # {file_id: {'path': Path, 'filename': str, 'created': float, 'size': int}}
TEMP_APK_LOCK = threading.Lock()

# Concurrency limits (prevents resource exhaustion under high load)
MAX_CONCURRENT_DOWNLOADS = 10
MAX_CONCURRENT_MERGES = 3
DOWNLOAD_QUEUE_TIMEOUT = 30  # seconds to wait for a slot

download_semaphore = threading.Semaphore(MAX_CONCURRENT_DOWNLOADS)
merge_semaphore = threading.Semaphore(MAX_CONCURRENT_MERGES)

# SSE timeout protection (prevents infinite connection holding)
SSE_MAX_DURATION = 300  # 5 minutes max for any SSE stream
MAX_PROFILE_CYCLES = 3  # Max times to cycle through all profiles before giving up

# Per-worker search cache (reduces latency for repeated queries).
# Each gunicorn worker maintains its own cache; duplicate fetches across workers are acceptable.
SEARCH_CACHE = {}  # {query: (results, timestamp)}
SEARCH_CACHE_TTL = 21600  # 6 hours - search results rarely change
SEARCH_CACHE_LOCK = threading.Lock()


def normalize_search_query(query):
    """Normalize query for better cache hit rate."""
    # Lowercase, strip whitespace, collapse multiple spaces
    normalized = ' '.join(query.lower().split())
    return normalized


def get_cached_search(query):
    """Get cached search results if still valid."""
    with SEARCH_CACHE_LOCK:
        if query in SEARCH_CACHE:
            results, ts = SEARCH_CACHE[query]
            if time_module.time() - ts < SEARCH_CACHE_TTL:
                return results
            del SEARCH_CACHE[query]
    return None


def cache_search(query, results):
    """Cache search results with TTL."""
    now = time_module.time()
    with SEARCH_CACHE_LOCK:
        # Purge expired entries first
        expired = [k for k, (_, ts) in SEARCH_CACHE.items() if now - ts >= SEARCH_CACHE_TTL]
        for k in expired:
            del SEARCH_CACHE[k]
        # If still over limit, remove oldest entries
        if len(SEARCH_CACHE) > 1000:
            oldest = sorted(SEARCH_CACHE.items(), key=lambda x: x[1][1])[:100]
            for k, _ in oldest:
                del SEARCH_CACHE[k]
        SEARCH_CACHE[query] = (results, now)


def get_backoff_delay(attempt, base=1.0, max_delay=30.0):
    """Exponential backoff with jitter to prevent thundering herd."""
    delay = min(base * (2 ** min(attempt, 5)), max_delay)  # Cap exponent at 5
    jitter = delay * 0.2 * random.random()
    return delay + jitter


def download_splits_parallel(splits, headers, max_workers=4):
    """Download multiple splits in parallel for faster downloads.

    Uses gevent Pool when available (compatible with gunicorn gevent workers),
    falls back to sequential downloads otherwise.
    """
    if not splits:
        return []

    results = {}
    errors = []

    def download_one(split):
        try:
            resp = requests.get(split['downloadUrl'], headers=headers, timeout=(10, 120))
            resp.raise_for_status()
            content = resp.content
            if 'content-length' in resp.headers:
                expected = int(resp.headers['content-length'])
                if len(content) != expected:
                    raise ValueError(f"Size mismatch for {split['name']}: got {len(content)}, expected {expected}")
            return split['name'], content, None
        except Exception as e:
            return split['name'], None, str(e)

    if HAS_GEVENT:
        # Use gevent pool (greenlet-based, compatible with gevent workers)
        pool = GeventPool(size=min(max_workers, len(splits)))
        results_list = pool.map(download_one, splits)
        for name, content, error in results_list:
            if error:
                errors.append(f"{name}: {error}")
            else:
                results[name] = content
    else:
        # Fallback to sequential downloads
        for split in splits:
            name, content, error = download_one(split)
            if error:
                errors.append(f"{name}: {error}")
            else:
                results[name] = content

    if errors:
        raise ValueError(f"Failed to download splits: {'; '.join(errors)}")

    return [(s['name'], results[s['name']]) for s in splits]


def validate_download(response, name="file"):
    """Validate downloaded content matches Content-Length header."""
    content = response.content
    if 'content-length' in response.headers:
        expected = int(response.headers['content-length'])
        actual = len(content)
        if actual != expected:
            raise ValueError(f"Download size mismatch for {name}: got {actual}, expected {expected}")
    return content


def cleanup_temp_apks():
    """Background cleanup of expired temp APKs."""
    while True:
        try:
            now = time_module.time()
            expired = []

            with TEMP_APK_LOCK:
                for file_id, meta in list(TEMP_APK_REGISTRY.items()):
                    if now - meta['created'] > TEMP_APK_TTL:
                        expired.append(file_id)

                # Remove expired entries
                for file_id in expired:
                    meta = TEMP_APK_REGISTRY.pop(file_id, None)
                    if meta and meta['path'].exists():
                        try:
                            meta['path'].unlink()
                            logger.info(f"Cleaned up expired temp APK: {file_id}")
                        except Exception as e:
                            logger.warning(f"Failed to clean temp file: {e}")

            # Also clean orphaned files not in registry
            try:
                if TEMP_APK_DIR.exists():
                    for f in TEMP_APK_DIR.iterdir():
                        try:
                            if f.is_file() and f.stat().st_mtime < now - TEMP_APK_TTL:
                                f.unlink()
                                logger.debug(f"Cleaned orphaned temp file: {f.name}")
                        except Exception:
                            pass
            except Exception as e:
                logger.warning(f"Orphaned file cleanup error: {e}")

        except Exception as e:
            logger.error(f"Cleanup error: {e}")

        time_module.sleep(60)  # Run every minute


def save_temp_apk(apk_bytes, filename):
    """Save APK to disk and return file_id."""
    file_id = str(uuid.uuid4())
    file_path = TEMP_APK_DIR / f"{file_id}.apk"
    meta_path = TEMP_APK_DIR / f"{file_id}.meta"

    # Check storage limit
    with TEMP_APK_LOCK:
        total_size = sum(m.get('size', 0) for m in TEMP_APK_REGISTRY.values())
        if total_size + len(apk_bytes) > MAX_TEMP_STORAGE_MB * 1024 * 1024:
            raise MemoryError("Temp storage limit exceeded, try again later")

    # Write APK to disk
    with open(file_path, 'wb') as f:
        f.write(apk_bytes)

    # Write metadata file (for cross-worker access)
    with open(meta_path, 'w') as f:
        f.write(filename)

    with TEMP_APK_LOCK:
        TEMP_APK_REGISTRY[file_id] = {
            'path': file_path,
            'filename': filename,
            'created': time_module.time(),
            'size': len(apk_bytes)
        }

    logger.info(f"Saved temp APK: {file_id} ({len(apk_bytes)} bytes)")
    return file_id


def get_temp_apk(file_id):
    """Get temp APK metadata, or None if not found/expired."""
    with TEMP_APK_LOCK:
        meta = TEMP_APK_REGISTRY.get(file_id)
        if not meta:
            return None
        if time_module.time() - meta['created'] > TEMP_APK_TTL:
            # Expired
            TEMP_APK_REGISTRY.pop(file_id, None)
            if meta['path'].exists():
                try:
                    meta['path'].unlink()
                except Exception:
                    pass
            return None
        return meta.copy()


def _is_valid_file_id(file_id):
    """Validate file_id is a strict UUID to prevent path traversal."""
    try:
        uuid.UUID(file_id)
        return True
    except (ValueError, AttributeError):
        return False


def consume_temp_apk(file_id):
    """Get temp APK metadata for serving. Does NOT delete — cleanup thread handles that.

    With multiple gunicorn workers, the registry may not have the entry
    if a different worker saved the file. Fall back to disk check.
    Files persist until the cleanup thread removes them after TEMP_APK_TTL,
    allowing Cloudflare retries and Android download manager to complete.
    """
    if not _is_valid_file_id(file_id):
        return None

    with TEMP_APK_LOCK:
        meta = TEMP_APK_REGISTRY.get(file_id)
        if meta:
            if time_module.time() - meta['created'] > TEMP_APK_TTL:
                TEMP_APK_REGISTRY.pop(file_id, None)
                return None
            return meta.copy()

    # If not in registry (different worker saved it), check disk directly
    file_path = TEMP_APK_DIR / f"{file_id}.apk"
    meta_path = TEMP_APK_DIR / f"{file_id}.meta"
    # Defense-in-depth: verify path didn't escape temp dir
    if file_path.resolve().parent != TEMP_APK_DIR.resolve():
        logger.warning(f"Path traversal attempt blocked: {file_id}")
        return None
    if file_path.exists():
        # Check TTL on disk file
        try:
            mtime = file_path.stat().st_mtime
            if time_module.time() - mtime > TEMP_APK_TTL:
                return None
        except OSError:
            return None
        # Try to read original filename from metadata file
        filename = f"{file_id}.apk"
        if meta_path.exists():
            try:
                filename = meta_path.read_text().strip()
            except Exception:
                pass
        try:
            size = file_path.stat().st_size
        except OSError:
            return None
        meta = {
            'path': file_path,
            'filename': filename,
            'created': mtime,
            'size': size
        }
        return meta

    return None


# Start cleanup thread (daemon so it dies when main process exits)
_cleanup_thread = threading.Thread(target=cleanup_temp_apks, daemon=True)
_cleanup_thread.start()
logger.info(f"Temp APK storage initialized: {TEMP_APK_DIR}")

# Warm connection pool on worker startup (pre-establish TLS to Google Play)
def _warm_connection_pool():
    """Pre-establish connections to reduce first-request latency."""
    try:
        scraper = get_scraper()
        # HEAD request is faster than GET, just establishes connection
        scraper.head('https://play.google.com', timeout=(5, 5))
        logger.info("Connection pool warmed for play.google.com")
    except Exception as e:
        logger.debug(f"Connection warming failed (non-critical): {e}")

_warm_connection_pool()

# APKEditor.jar integrity check (warning-only)
APKEDITOR_EXPECTED_SHA256 = os.environ.get('APKEDITOR_SHA256', '')

def _verify_apkeditor():
    jar_path = os.path.join(os.path.dirname(__file__), 'APKEditor.jar')
    if not os.path.exists(jar_path):
        logger.warning("APKEditor.jar not found")
        return
    if not APKEDITOR_EXPECTED_SHA256:
        logger.info("APKEDITOR_SHA256 not set, skipping integrity check")
        return
    import hashlib
    h = hashlib.sha256()
    with open(jar_path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    actual = h.hexdigest()
    if actual != APKEDITOR_EXPECTED_SHA256:
        logger.warning(f"APKEditor.jar SHA256 mismatch! Expected {APKEDITOR_EXPECTED_SHA256}, got {actual}")
    else:
        logger.info("APKEditor.jar integrity verified")

_verify_apkeditor()


@app.route('/api/download-merged-stream/<path:pkg>')
def download_merged_stream(pkg):
    """SSE endpoint that downloads, merges, signs APKs with progress updates."""
    err = _require_valid_pkg(pkg)
    if err:
        return err

    arch = request.args.get('arch', 'arm64-v8a')
    if arch not in SUPPORTED_ARCHS:
        arch = 'arm64-v8a'

    # Get priority-ordered profiles for this architecture
    profiles = get_priority_device_configs(arch)
    profile_count = len(profiles)

    def generate():
        # Try to acquire a download slot (prevents resource exhaustion)
        if not download_semaphore.acquire(timeout=DOWNLOAD_QUEUE_TIMEOUT):
            yield f"data: {json.dumps({'type': 'error', 'message': 'Server busy, please try again later'})}\n\n"
            return

        try:
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
                except Exception:
                    pass

            if not auth_data:
                scraper = get_scraper()  # Reuse scraper across attempts
                max_attempts = profile_count * MAX_PROFILE_CYCLES
                for attempt in range(max_attempts):
                    # Rotate through profiles
                    profile_key, profile = profiles[attempt % profile_count]
                    profile_name = profile.get('UserReadableName', profile_key)

                    yield f"data: {json.dumps({'type': 'progress', 'step': 'auth', 'message': f'Trying token #{attempt+1} ({profile_name})...'})}\n\n"
                    try:
                        response = scraper.post(
                            DISPENSER_URL,
                            headers={
                                'User-Agent': 'com.aurora.store-4.6.1-70',
                                'Content-Type': 'application/json',
                            },
                            json=profile,
                            timeout=(5, 30)
                        )

                        if not response.ok:
                            time_module.sleep(get_backoff_delay(attempt))
                            continue

                        auth_data = response.json()
                        info = get_download_info(pkg, auth_data)

                        if 'error' not in info:
                            save_cached_auth(auth_data, arch)
                            logger.info(f"Token #{attempt+1} ({profile_name}) worked for {pkg}")
                            break
                        else:
                            auth_data = None
                            time_module.sleep(0.5)

                    except requests.exceptions.ConnectionError as e:
                        time_module.sleep(get_backoff_delay(attempt, base=2.0))
                    except requests.exceptions.Timeout as e:
                        time_module.sleep(get_backoff_delay(attempt))
                    except Exception as e:
                        time_module.sleep(get_backoff_delay(attempt, base=0.5))

            if not info or 'error' in info:
                yield f"data: {json.dumps({'type': 'error', 'message': 'Failed to get download info'})}\n\n"
                return

            splits = info.get('splits', [])
            total_files = 1 + len(splits)

            yield f"data: {json.dumps({'type': 'progress', 'step': 'download', 'message': f'Downloading APK...', 'current': 1, 'total': total_files})}\n\n"

            cookie_header = '; '.join([f"{c['name']}={c['value']}" for c in info.get('cookies', [])])
            headers = {'Cookie': cookie_header} if cookie_header else {}

            try:
                base_resp = requests.get(info['downloadUrl'], headers=headers, timeout=(10, 120))
                if not base_resp.ok:
                    yield f"data: {json.dumps({'type': 'error', 'message': 'Failed to download base APK'})}\n\n"
                    return
                base_apk = validate_download(base_resp, "base APK")

                # If no splits, return original APK without merging/signing
                if not splits:
                    try:
                        file_id = save_temp_apk(base_apk, info['filename'])
                        count = increment_download_count()
                        yield f"data: {json.dumps({'type': 'success', 'download_id': file_id, 'filename': info['filename'], 'original': True, 'downloads': count})}\n\n"
                    except MemoryError as e:
                        logger.warning(f"Temp storage error for {pkg}: {e}")
                        yield f"data: {json.dumps({'type': 'error', 'message': 'Server storage full, try again later'})}\n\n"
                    return

                # Download splits in parallel for faster downloads
                yield f"data: {json.dumps({'type': 'progress', 'step': 'download', 'message': f'Downloading {len(splits)} splits in parallel...', 'current': 2, 'total': total_files})}\n\n"
                try:
                    splits_data = download_splits_parallel(splits, headers)
                except Exception as e:
                    logger.error(f"Failed to download splits for {pkg}: {e}")
                    yield f"data: {json.dumps({'type': 'error', 'message': 'Failed to download split APKs'})}\n\n"
                    return

                # Acquire merge slot (limited to prevent CPU exhaustion)
                if not merge_semaphore.acquire(timeout=DOWNLOAD_QUEUE_TIMEOUT):
                    yield f"data: {json.dumps({'type': 'error', 'message': 'Merge queue full, try again later'})}\n\n"
                    return

                try:
                    yield f"data: {json.dumps({'type': 'progress', 'step': 'merge', 'message': 'Merging APKs...'})}\n\n"
                    merged_apk = merge_apks(base_apk, splits_data)

                    yield f"data: {json.dumps({'type': 'progress', 'step': 'sign', 'message': 'Signing APK...'})}\n\n"
                    signed_apk = sign_apk(merged_apk)

                    # Save to disk-based temp storage
                    merged_filename = f"{pkg}-{info['versionCode']}-merged.apk"
                    try:
                        file_id = save_temp_apk(signed_apk, merged_filename)
                        count = increment_download_count()
                        yield f"data: {json.dumps({'type': 'success', 'download_id': file_id, 'filename': merged_filename, 'downloads': count})}\n\n"
                    except MemoryError as e:
                        logger.warning(f"Temp storage error for {pkg}: {e}")
                        yield f"data: {json.dumps({'type': 'error', 'message': 'Server storage full, try again later'})}\n\n"
                finally:
                    merge_semaphore.release()

            except Exception as e:
                logger.error(f"Download/merge failed for {pkg}: {e}")
                yield f"data: {json.dumps({'type': 'error', 'message': 'Download failed, please try again'})}\n\n"

        finally:
            download_semaphore.release()

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
    """Download a temporary merged APK (streams from disk)."""
    if not _is_valid_file_id(file_id):
        return jsonify({'error': 'Invalid file ID'}), 400

    meta = consume_temp_apk(file_id)
    if not meta:
        return jsonify({'error': 'File not found or expired'}), 404

    def generate():
        """Stream file from disk. Cleanup is handled by the cleanup thread."""
        try:
            f = open(meta['path'], 'rb')
        except FileNotFoundError:
            return
        with f:
            while True:
                chunk = f.read(65536)  # 64KB chunks
                if not chunk:
                    break
                yield chunk

    return Response(
        generate(),
        content_type='application/vnd.android.package-archive',
        headers={
            'Content-Disposition': f'attachment; filename="{sanitize_filename(meta["filename"])}"',
            'Content-Length': str(meta['size'])
        }
    )


@app.route('/api/download-merged/<path:pkg>')
def download_merged(pkg):
    """Download and merge all APKs into a single installable APK (non-streaming fallback)."""
    err = _require_valid_pkg(pkg)
    if err:
        return err

    # Get architecture from query parameter
    arch = request.args.get('arch', 'arm64-v8a')
    if arch not in SUPPORTED_ARCHS:
        arch = 'arm64-v8a'
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
        except Exception:
            pass

    # If cached didn't work, try new tokens with profile rotation
    if not auth_data:
        profiles = get_priority_device_configs(arch)
        profile_count = len(profiles)
        max_attempts = profile_count * MAX_PROFILE_CYCLES
        scraper = get_scraper()  # Reuse scraper across attempts
        for attempt in range(max_attempts):
            profile_key, profile = profiles[attempt % profile_count]
            try:
                response = scraper.post(
                    DISPENSER_URL,
                    headers={
                        'User-Agent': 'com.aurora.store-4.6.1-70',
                        'Content-Type': 'application/json',
                    },
                    json=profile,
                    timeout=(5, 30)
                )

                if not response.ok:
                    time_module.sleep(get_backoff_delay(attempt))
                    continue

                auth_data = response.json()
                info = get_download_info(pkg, auth_data)

                if 'error' not in info:
                    save_cached_auth(auth_data, arch)
                    break
                else:
                    auth_data = None
                    time_module.sleep(get_backoff_delay(attempt, base=0.5))

            except requests.exceptions.ConnectionError as e:
                logger.warning(f"Connection error on attempt {attempt}: {e}")
                time_module.sleep(get_backoff_delay(attempt, base=2.0))
            except requests.exceptions.Timeout as e:
                logger.warning(f"Timeout on attempt {attempt}: {e}")
                time_module.sleep(get_backoff_delay(attempt))
            except Exception as e:
                logger.warning(f"Merge download attempt {attempt} failed: {e}")
                time_module.sleep(get_backoff_delay(attempt, base=0.5))

    if not info or 'error' in info:
        return jsonify({'error': 'Failed to get download info after multiple attempts'}), 500

    # Build cookie header for downloads
    cookie_header = '; '.join([f"{c['name']}={c['value']}" for c in info.get('cookies', [])])
    headers = {'Cookie': cookie_header} if cookie_header else {}

    try:
        # Download base APK with validation
        logger.info(f"Downloading base APK for {pkg}")
        base_resp = requests.get(info['downloadUrl'], headers=headers, timeout=(10, 120))
        if not base_resp.ok:
            return jsonify({'error': f'Failed to download base APK: {base_resp.status_code}'}), 500
        base_apk = validate_download(base_resp, "base APK")

        # If no splits, just return base APK
        if not info['splits']:
            return Response(
                base_apk,
                content_type='application/vnd.android.package-archive',
                headers={'Content-Disposition': f'attachment; filename="{sanitize_filename(info["filename"])}"'}
            )

        # Download all splits in parallel
        logger.info(f"Downloading {len(info['splits'])} splits in parallel")
        splits_data = download_splits_parallel(info['splits'], headers)

        # Acquire merge semaphore to limit concurrent merges
        if not merge_semaphore.acquire(timeout=DOWNLOAD_QUEUE_TIMEOUT):
            return jsonify({'error': 'Server busy, please try again'}), 503

        try:
            # Merge APKs
            logger.info(f"Merging {len(splits_data) + 1} APKs")
            merged_apk = merge_apks(base_apk, splits_data)

            # Sign the merged APK
            logger.info("Signing merged APK")
            signed_apk = sign_apk(merged_apk)
        finally:
            merge_semaphore.release()

        merged_filename = f"{pkg}-{info['versionCode']}-merged.apk"
        return Response(
            signed_apk,
            content_type='application/vnd.android.package-archive',
            headers={'Content-Disposition': f'attachment; filename="{sanitize_filename(merged_filename)}"'}
        )

    except Exception as e:
        logger.error(f"Merge download failed for {pkg}: {e}")
        return jsonify({'error': 'Download failed, please try again'}), 500


if __name__ == '__main__':

    debug = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    host = os.environ.get('HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', '5000'))

    print(f'Starting GPlay Downloader on http://{host}:{port}')
    print(f'gpapi available: {HAS_GPAPI}')
    print(f'Debug mode: {debug}')

    if debug:
        app.run(host=host, port=port, debug=True)
    else:
        print('For production, use: gunicorn -c gunicorn.conf.py server:app')
        app.run(host=host, port=port, debug=False, threaded=True)
