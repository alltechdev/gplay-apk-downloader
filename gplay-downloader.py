#!/usr/bin/env python3
"""
Google Play APK Downloader

A CLI tool to download APKs from Google Play Store using anonymous authentication.
Based on the same API that AuroraStore uses.

Usage:
    ./gplay-downloader.py auth                    # Authenticate (anonymous mode)
    ./gplay-downloader.py search "whatsapp"       # Search for apps
    ./gplay-downloader.py info com.whatsapp       # Get app info
    ./gplay-downloader.py download com.whatsapp   # Download APK
    ./gplay-downloader.py download com.app --merge --arch arm64  # Download merged APK

Requirements:
    pip install cloudscraper requests protobuf

Note: This uses anonymous authentication via AuroraOSS dispensers.
"""

import argparse
import json
import os
import sys
import subprocess
import tempfile
import shutil
from pathlib import Path
from urllib.parse import urlencode

try:
    import cloudscraper
except ImportError:
    print("Error: cloudscraper library not found. Install with: pip install cloudscraper")
    sys.exit(1)

try:
    import requests
except ImportError:
    print("Error: requests library not found. Install with: pip install requests")
    sys.exit(1)

# Default dispenser URLs for anonymous authentication
DISPENSER_URLS = [
    "https://auroraoss.com/api/auth",
]

# Google Play API endpoints
FDFE_URL = "https://android.clients.google.com/fdfe"
PURCHASE_URL = f"{FDFE_URL}/purchase"
DELIVERY_URL = f"{FDFE_URL}/delivery"
DETAILS_URL = f"{FDFE_URL}/details"
SEARCH_URL = f"{FDFE_URL}/search"

# Import device profiles from centralized module
from device_profiles import (
    ARM64_PROFILES, ARMV7_PROFILES,
    DEFAULT_ARM64_PROFILE, DEFAULT_ARMV7_PROFILE,
    get_profile, get_all_profiles, get_priority_profiles,
)

# Default device profile (Galaxy S25 Ultra - newest, works with banking apps)
DEFAULT_DEVICE = DEFAULT_ARM64_PROFILE

AUTH_FILE = Path.home() / ".gplay-auth.json"
SCRIPT_DIR = Path(__file__).parent

# Architecture mapping
ARCH_MAP = {
    'arm64': 'arm64-v8a',
    'arm64-v8a': 'arm64-v8a',
    'armv7': 'armeabi-v7a',
    'armeabi-v7a': 'armeabi-v7a',
    'arm': 'armeabi-v7a',
}


def merge_apks_with_apkeditor(base_path, split_paths, output_path):
    """Use APKEditor to merge split APKs."""
    apkeditor_jar = SCRIPT_DIR / 'APKEditor.jar'
    if not apkeditor_jar.exists():
        raise FileNotFoundError(f"APKEditor.jar not found at {apkeditor_jar}")

    work_dir = tempfile.mkdtemp(prefix='apk_merge_')
    try:
        # Copy base APK
        shutil.copy(base_path, os.path.join(work_dir, 'base.apk'))

        # Copy split APKs
        for i, split_path in enumerate(split_paths):
            shutil.copy(split_path, os.path.join(work_dir, f'split{i}.apk'))

        # Run APKEditor merge
        result = subprocess.run(
            ['java', '-jar', str(apkeditor_jar), 'm', '-i', work_dir, '-o', output_path],
            capture_output=True, text=True, timeout=300
        )

        if result.returncode != 0:
            raise Exception(f"APKEditor failed: {result.stderr}")

        return True
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


def sign_apk(apk_path):
    """Sign an APK using apksigner with debug keystore."""
    keystore = Path.home() / '.android' / 'debug.keystore'
    if not keystore.exists():
        print("Warning: Debug keystore not found, APK will be unsigned")
        return False

    if not shutil.which('apksigner'):
        print("Warning: apksigner not found, APK will be unsigned")
        return False

    signed_path = str(apk_path) + '.signed'
    cmd = [
        'apksigner', 'sign',
        '--ks', str(keystore),
        '--ks-pass', 'pass:android',
        '--key-pass', 'pass:android',
        '--out', signed_path,
        str(apk_path)
    ]

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

    if result.returncode == 0 and os.path.exists(signed_path):
        os.replace(signed_path, apk_path)
        return True
    else:
        print(f"Warning: Signing failed: {result.stderr}")
        return False


def format_size(size_bytes):
    """Format bytes to human readable size."""
    if not size_bytes:
        return "Unknown"
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.2f} TB"


def get_dispenser_auth(dispenser_url=None):
    """Get anonymous authentication from dispenser with profile fallback."""
    url = dispenser_url or DISPENSER_URLS[0]
    print(f"Authenticating via dispenser: {url}")

    # Use cloudscraper to bypass Cloudflare protection
    scraper = cloudscraper.create_scraper()

    headers = {
        'User-Agent': 'com.aurora.store-4.6.1-70',
        'Content-Type': 'application/json',
    }

    # Try priority-ordered profiles (most reliable first)
    priority_arm64 = get_priority_profiles('arm64')
    priority_armv7 = get_priority_profiles('armv7')
    all_profiles = priority_arm64 + priority_armv7

    for profile_name, profile in all_profiles:
        try:
            response = scraper.post(url, json=profile, headers=headers, timeout=30)
            if response.status_code == 200:
                data = response.json()
                if data.get('authToken'):
                    print(f"  Using profile: {profile.get('UserReadableName', profile_name)}")
                    return data
            # Profile rejected, try next
        except Exception as e:
            continue

    # If all profiles failed, print error
    print("Error: All profiles failed to authenticate")
    return None


def save_auth(auth_data):
    """Save authentication data to file."""
    AUTH_FILE.write_text(json.dumps(auth_data, indent=2))
    print(f"Auth saved to: {AUTH_FILE}")


def load_auth():
    """Load authentication data from file."""
    if not AUTH_FILE.exists():
        print(f"Error: Auth file not found: {AUTH_FILE}")
        print("Run 'gplay-downloader.py auth' first.")
        return None

    try:
        return json.loads(AUTH_FILE.read_text())
    except json.JSONDecodeError as e:
        print(f"Error: Invalid auth file: {e}")
        return None


def get_auth_headers(auth, accept_language='en-US'):
    """
    Build headers for Google Play API requests.
    Enhanced with additional headers from Aurora Store for better compatibility.
    """
    device_info = auth.get('deviceInfoProvider', {})
    locale = accept_language.replace('-', '_')

    headers = {
        'Authorization': f"Bearer {auth.get('authToken')}",
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


def api_request(auth, url, params=None, method='GET'):
    """Make a request to Google Play API."""
    headers = get_auth_headers(auth)

    try:
        if method == 'GET':
            response = requests.get(url, headers=headers, params=params, timeout=30)
        else:
            response = requests.post(url, headers=headers, data=params, timeout=30)

        return response
    except Exception as e:
        print(f"API request failed: {e}")
        return None


def cmd_auth(args):
    """Authenticate with Google Play."""
    auth_data = get_dispenser_auth(args.dispenser)

    if not auth_data:
        print("Authentication failed!")
        return 1

    email = auth_data.get('email', 'unknown')
    print(f"Got auth token for: {email}")

    save_auth(auth_data)
    print("Authentication successful!")
    return 0


def cmd_search(args):
    """Search for apps."""
    auth = load_auth()
    if not auth:
        return 1

    if not getattr(args, 'json', False):
        print(f"Searching for: {args.query}")

    result = {
        'success': False,
        'query': args.query,
        'results': [],
        'error': None
    }

    # Use web search as fallback (more reliable)
    try:
        scraper = cloudscraper.create_scraper()
        search_url = f"https://play.google.com/store/search?q={args.query}&c=apps"

        response = scraper.get(search_url, timeout=30)

        if response.status_code != 200:
            result['error'] = f"Search failed with status {response.status_code}"
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                print(result['error'])
            return 1

        # Parse basic info from HTML (limited but works without protobuf)
        import re

        # Find app links
        pattern = r'href="/store/apps/details\?id=([^"&]+)"[^>]*>([^<]*)</a>'
        matches = re.findall(pattern, response.text)

        if not matches:
            # Try alternative pattern
            pattern = r'data-docid="([^"]+)"'
            package_matches = re.findall(pattern, response.text)
            if package_matches:
                matches = [(pkg, pkg) for pkg in set(package_matches)]

        seen = set()
        count = 0
        for package, title in matches:
            if package not in seen and count < args.limit:
                seen.add(package)
                count += 1
                display_title = title.strip() if title.strip() else package
                result['results'].append({
                    'package': package,
                    'title': display_title
                })

        result['success'] = True

        if args.json:
            print(json.dumps(result, indent=2))
        else:
            if not result['results']:
                print("No results found (try 'gplay info <package>' directly)")
            else:
                for i, app in enumerate(result['results'], 1):
                    print(f"{i}. {app['title']}")
                    print(f"   Package: {app['package']}")
                    print()

        return 0
    except Exception as e:
        result['error'] = str(e)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"Search error: {e}")
        return 1


def cmd_info(args):
    """Get app details."""
    auth = load_auth()
    if not auth:
        return 1

    if not getattr(args, 'json', False):
        print(f"Fetching info for: {args.package}")

    result = {
        'success': False,
        'package': args.package,
        'title': None,
        'developer': None,
        'rating': None,
        'downloads': None,
        'play_store_url': f"https://play.google.com/store/apps/details?id={args.package}",
        'error': None
    }

    try:
        # Use web scraping for app details (more reliable)
        scraper = cloudscraper.create_scraper()
        url = f"https://play.google.com/store/apps/details?id={args.package}&hl=en"

        response = scraper.get(url, timeout=30)

        if response.status_code == 404:
            result['error'] = "App not found"
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                print("App not found.")
            return 1

        if response.status_code != 200:
            result['error'] = f"HTTP {response.status_code}"
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                print(f"Failed to fetch app info: {response.status_code}")
            return 1

        import re

        # Extract app info from HTML
        html = response.text

        # Title
        title_match = re.search(r'<h1[^>]*>([^<]+)</h1>', html)
        result['title'] = title_match.group(1) if title_match else args.package

        # Developer
        dev_match = re.search(r'<a[^>]*href="/store/apps/developer[^"]*"[^>]*>([^<]+)</a>', html)
        result['developer'] = dev_match.group(1) if dev_match else "Unknown"

        # Rating
        rating_match = re.search(r'(\d+\.\d+)\s*star', html, re.IGNORECASE)
        result['rating'] = rating_match.group(1) if rating_match else None

        # Downloads
        downloads_match = re.search(r'>(\d+[KMB+,\d]*)\s*downloads<', html, re.IGNORECASE)
        if not downloads_match:
            downloads_match = re.search(r'>([\d,]+\+?)\s*Downloads<', html)
        result['downloads'] = downloads_match.group(1) if downloads_match else None

        result['success'] = True

        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"Name: {result['title']}")
            print(f"Package: {args.package}")
            print(f"Developer: {result['developer']}")
            print(f"Rating: {result['rating'] or 'N/A'}")
            print(f"Downloads: {result['downloads'] or 'N/A'}")
            print()
            print(f"Play Store URL: {result['play_store_url']}")

        return 0
    except Exception as e:
        result['error'] = str(e)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"Error fetching info: {e}")
        return 1


def cmd_download(args):
    """Download APK."""
    # Pre-check ADB device if --install requested
    if getattr(args, 'install', False):
        if not _check_adb_device():
            return 1

    auth = load_auth()
    if not auth:
        return 1

    package = args.package
    arch = ARCH_MAP.get(args.arch, 'arm64-v8a') if args.arch else 'arm64-v8a'
    should_merge = args.merge

    print(f"Preparing to download: {package}")
    print(f"Architecture: {arch}")
    if should_merge:
        print("Will merge split APKs into single APK")

    try:
        from gpapi import googleplay_pb2

        headers = get_auth_headers(auth)
        headers['Content-Type'] = 'application/x-protobuf'
        headers['Accept'] = 'application/x-protobuf'

        # Step 1: Get app details via protobuf
        print("Getting app details...")
        details_url = f"{DETAILS_URL}?doc={package}"
        response = requests.get(details_url, headers=headers, timeout=30)

        if response.status_code != 200:
            print(f"Failed to get app details: {response.status_code}")
            print("The app might not be available in your region or device profile.")
            return 1

        # Parse details response
        details_response = googleplay_pb2.ResponseWrapper()
        details_response.ParseFromString(response.content)

        if not details_response.payload.detailsResponse.docV2.docid:
            print("App not found or not available.")
            return 1

        app = details_response.payload.detailsResponse.docV2
        version_code = args.version or app.details.appDetails.versionCode

        print(f"App: {app.title}")
        print(f"Version: {app.details.appDetails.versionString} ({version_code})")
        print()

        # Step 2: Purchase (acquire free app)
        print("Acquiring app...")
        purchase_headers = headers.copy()
        purchase_headers['Content-Type'] = 'application/x-www-form-urlencoded'

        purchase_data = f"doc={package}&ot=1&vc={version_code}"

        purchase_response = requests.post(
            PURCHASE_URL,
            headers=purchase_headers,
            data=purchase_data,
            timeout=30
        )

        if purchase_response.status_code not in [200, 204]:
            print(f"Failed to acquire app: {purchase_response.status_code}")
            # Try to continue anyway - might already be "purchased"

        # Step 3: Get delivery URL
        print("Getting download URL...")
        delivery_url = f"{DELIVERY_URL}?doc={package}&ot=1&vc={version_code}"
        delivery_response = requests.get(delivery_url, headers=headers, timeout=30)

        if delivery_response.status_code != 200:
            print(f"Failed to get download URL: {delivery_response.status_code}")
            return 1

        # Parse delivery response
        delivery_wrapper = googleplay_pb2.ResponseWrapper()
        delivery_wrapper.ParseFromString(delivery_response.content)

        delivery_data = delivery_wrapper.payload.deliveryResponse.appDeliveryData

        if not delivery_data.downloadUrl:
            print("No download URL available.")
            print("The app might require purchase or not be available for this device.")
            return 1

        download_url = delivery_data.downloadUrl
        download_size = delivery_data.downloadSize
        sha1 = delivery_data.sha1

        print(f"Download size: {format_size(download_size)}")

        # Create output directory
        output_dir = Path(args.output)
        output_dir.mkdir(parents=True, exist_ok=True)

        # Download main APK
        filename = f"{package}-{version_code}.apk"
        filepath = output_dir / filename

        print(f"Downloading: {filename}")

        # Download with cookies if provided
        download_headers = {}
        cookie_parts = [f"{cookie.name}={cookie.value}" for cookie in delivery_data.downloadAuthCookie]
        if cookie_parts:
            download_headers['Cookie'] = '; '.join(cookie_parts)

        dl_response = requests.get(download_url, headers=download_headers, stream=True, timeout=60)

        if dl_response.status_code != 200:
            print(f"Download failed: {dl_response.status_code}")
            return 1

        with open(filepath, 'wb') as f:
            downloaded = 0
            for chunk in dl_response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
                    downloaded += len(chunk)
                    if download_size > 0:
                        progress = (downloaded * 100) // download_size
                        print(f"\r  Progress: {progress}% ({format_size(downloaded)} / {format_size(download_size)})", end='')

        print()
        print(f"Saved: {filepath}")

        # Download split APKs if any
        split_files = []
        for i, split in enumerate(delivery_data.split):
            if split.downloadUrl:
                split_name = split.name if split.name else f"split{i}"
                split_filename = f"{package}-{version_code}-{split_name}.apk"
                split_filepath = output_dir / split_filename
                print(f"Downloading split: {split_filename}")

                split_response = requests.get(split.downloadUrl, stream=True, timeout=120)
                with open(split_filepath, 'wb') as f:
                    for chunk in split_response.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
                print(f"Saved: {split_filepath}")
                split_files.append(split_filepath)

        # Merge if requested and there are splits
        if should_merge and split_files:
            print()
            print("Merging APKs...")
            merged_filename = f"{package}-{version_code}-merged.apk"
            merged_filepath = output_dir / merged_filename

            try:
                merge_apks_with_apkeditor(filepath, split_files, str(merged_filepath))
                print(f"Merged: {merged_filepath}")

                print("Signing merged APK...")
                if sign_apk(merged_filepath):
                    print("APK signed successfully")

                # Clean up individual files
                print("Cleaning up split files...")
                os.remove(filepath)
                for sf in split_files:
                    os.remove(sf)

                print()
                print(f"Final APK: {merged_filepath}")
            except Exception as e:
                print(f"Merge failed: {e}")
                print("Individual APK files have been kept.")
        elif not split_files:
            print()
            print("No splits - APK has original signature")

        # Install to device via ADB if requested
        if getattr(args, 'install', False):
            import subprocess as sp
            try:
                sp.run(['adb', 'version'], capture_output=True, check=True)
            except (FileNotFoundError, sp.CalledProcessError):
                print("Error: adb not found. Install Android SDK platform-tools.")
                return 1

            if should_merge and split_files:
                # Merged APK was created, install that
                install_path = merged_filepath if merged_filepath.exists() else filepath
                print(f"Installing {install_path.name} to device...")
                result = sp.run(['adb', 'install', '-r', str(install_path)],
                                capture_output=True, text=True, timeout=300)
                if result.returncode == 0:
                    print("Installed successfully!")
                else:
                    print(f"Install failed: {result.stderr.strip() or result.stdout.strip()}")
                    return 1
            elif split_files:
                # Use install-multiple for split APKs (preserves original signatures)
                all_apks = [str(filepath)] + [str(sf) for sf in split_files]
                print(f"Installing {len(all_apks)} APKs to device (session install)...")
                result = sp.run(['adb', 'install-multiple', '-r'] + all_apks,
                                capture_output=True, text=True, timeout=300)
                if result.returncode == 0:
                    print("Installed successfully!")
                else:
                    print(f"Install failed: {result.stderr.strip() or result.stdout.strip()}")
                    return 1
            else:
                # Single APK, no splits
                print(f"Installing {filepath.name} to device...")
                result = sp.run(['adb', 'install', '-r', str(filepath)],
                                capture_output=True, text=True, timeout=300)
                if result.returncode == 0:
                    print("Installed successfully!")
                else:
                    print(f"Install failed: {result.stderr.strip() or result.stdout.strip()}")
                    return 1

        print()
        print("Download complete!")
        return 0

    except ImportError:
        print("Error: gpapi library required for downloads.")
        print("Install with: pip install gpapi")
        return 1
    except Exception as e:
        print(f"Download error: {e}")
        import traceback
        traceback.print_exc()
        return 1


def cmd_check_version(args):
    """Check app version without downloading (protobuf API with HTML fallback)."""
    auth = load_auth()
    if not auth:
        return 1

    package = args.package
    result = {
        'success': False,
        'package': package,
        'title': None,
        'version': None,
        'version_code': None,
        'error': None
    }

    # Try protobuf API with retries
    try:
        from gpapi import googleplay_pb2

        for attempt in range(3):
            if attempt > 0:
                print(f"Retry {attempt + 1}/3...", file=sys.stderr)
                import time
                time.sleep(2)

            headers = get_auth_headers(auth)
            headers['Content-Type'] = 'application/x-protobuf'
            headers['Accept'] = 'application/x-protobuf'

            response = requests.get(f"{DETAILS_URL}?doc={package}", headers=headers, timeout=30)

            if response.status_code == 404:
                result['error'] = f'App not found: {package}'
                break

            if response.status_code != 200:
                result['error'] = f'HTTP {response.status_code}'
                continue

            details_response = googleplay_pb2.ResponseWrapper()
            details_response.ParseFromString(response.content)

            if not details_response.payload.detailsResponse.docV2.docid:
                result['error'] = 'App not found or not available'
                continue

            app = details_response.payload.detailsResponse.docV2
            app_details = app.details.appDetails

            if app_details.versionCode and app_details.versionString:
                result['success'] = True
                result['title'] = app.title
                result['version'] = app_details.versionString
                result['version_code'] = app_details.versionCode
                break

    except ImportError:
        pass  # Fall through to HTML fallback

    # HTML fallback if protobuf failed
    if not result['success']:
        try:
            scraper = cloudscraper.create_scraper()
            url = f"https://play.google.com/store/apps/details?id={package}&hl=en&gl=US"
            response = scraper.get(url, timeout=30)

            if response.status_code == 404:
                result['error'] = f'App not found: {package}'
            elif response.status_code == 200:
                html = response.text
                import re

                # Extract title
                title_match = re.search(r'<h1[^>]*>([^<]+)</h1>', html)
                if title_match:
                    result['title'] = title_match.group(1).strip()

                # Extract version
                version_patterns = [
                    r'\[\[\["(\d+\.\d+[^"]*)"',
                    r'"softwareVersion"\s*:\s*"([^"]+)"',
                ]
                for pattern in version_patterns:
                    match = re.search(pattern, html)
                    if match:
                        ver = match.group(1).strip()
                        if re.match(r'^\d+\.', ver) and len(ver) < 50:
                            result['version'] = ver
                            result['success'] = True
                            break
        except Exception as e:
            result['error'] = str(e)

    # Output
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        if result['success']:
            print(f"Package: {package}")
            print(f"Title: {result['title']}")
            print(f"Version: {result['version']}")
            if result['version_code']:
                print(f"Version Code: {result['version_code']}")
        else:
            print(f"Error: {result.get('error', 'Unknown error')}")

    return 0 if result['success'] else 1


def cmd_list_splits(args):
    """List available splits for an app."""
    auth = load_auth()
    if not auth:
        return 1

    package = args.package
    result = {
        'success': False,
        'package': package,
        'title': None,
        'version': None,
        'version_code': None,
        'splits': [],
        'language_splits': [],
        'error': None
    }

    try:
        from gpapi import googleplay_pb2
        import re

        headers = get_auth_headers(auth)
        headers['Content-Type'] = 'application/x-protobuf'
        headers['Accept'] = 'application/x-protobuf'

        response = requests.get(f"{DETAILS_URL}?doc={package}", headers=headers, timeout=30)

        if response.status_code != 200:
            result['error'] = f'HTTP {response.status_code}'
        else:
            details_response = googleplay_pb2.ResponseWrapper()
            details_response.ParseFromString(response.content)

            if not details_response.payload.detailsResponse.docV2.docid:
                result['error'] = 'App not found'
            else:
                app = details_response.payload.detailsResponse.docV2
                app_details = app.details.appDetails

                result['title'] = app.title
                result['version'] = app_details.versionString
                result['version_code'] = app_details.versionCode

                # Extract splits from file list
                all_splits = set()
                for file_meta in app_details.file:
                    try:
                        if file_meta.splitId:
                            all_splits.add(file_meta.splitId)
                    except Exception:
                        pass  # Field may not exist

                # Also check dependencies.splitApks
                try:
                    if app_details.dependencies and app_details.dependencies.splitApks:
                        for split_name in app_details.dependencies.splitApks:
                            if split_name:
                                all_splits.add(split_name)
                except Exception:
                    pass  # Field may not exist

                result['splits'] = sorted(list(all_splits))

                # Filter for language splits
                lang_pattern = re.compile(r'^config\.([a-z]{2}(_[A-Z]{2})?)$')
                result['language_splits'] = [s for s in result['splits'] if lang_pattern.match(s)]
                result['success'] = True

    except ImportError:
        result['error'] = 'gpapi library required'
    except Exception as e:
        result['error'] = str(e)

    # Output
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        if result['success']:
            print(f"Package: {package}")
            print(f"Title: {result['title']}")
            print(f"Version: {result['version']} ({result['version_code']})")
            print(f"\nSplits ({len(result['splits'])}):")
            for s in result['splits']:
                print(f"  - {s}")
            if result['language_splits']:
                print(f"\nLanguage splits: {', '.join(result['language_splits'])}")
        else:
            print(f"Error: {result.get('error', 'Unknown error')}")

    return 0 if result['success'] else 1


def cmd_download_both_arch(args):
    """Download APK for both ARM64 and ARMv7 architectures."""
    import time

    package = args.package
    base_output = Path(args.output)
    results = {'arm64': None, 'armv7': None}

    for arch in ['arm64', 'armv7']:
        print(f"\n{'='*50}")
        print(f"Downloading for {arch.upper()}")
        print('='*50)

        # Create arch-specific output dir
        arch_output = base_output / arch
        arch_output.mkdir(parents=True, exist_ok=True)

        # Create a modified args object
        class ArchArgs:
            pass
        arch_args = ArchArgs()
        arch_args.package = package
        arch_args.output = str(arch_output)
        arch_args.version = args.version
        arch_args.arch = arch
        arch_args.merge = args.merge

        result = cmd_download(arch_args)
        results[arch] = result

        # Small delay between downloads
        if arch == 'arm64':
            time.sleep(2)

    # Summary
    print(f"\n{'='*50}")
    print("SUMMARY")
    print('='*50)
    for arch, result in results.items():
        status = "SUCCESS" if result == 0 else "FAILED"
        print(f"  {arch}: {status}")

    return 0 if all(r == 0 for r in results.values()) else 1


def cmd_download_all_locales(args):
    """Download APK with all language splits."""
    import time

    auth = load_auth()
    if not auth:
        return 1

    package = args.package
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Language headers to try
    LANGUAGE_HEADERS = [
        ('en', 'en-US,en;q=0.9'),
        ('he', 'he-IL,he;q=0.9,iw;q=0.8,en;q=0.7'),
        ('fr', 'fr-FR,fr;q=0.9,en;q=0.7'),
    ]

    # First do normal download
    print("Downloading base APK and default splits...")
    result = cmd_download(args)
    if result != 0:
        return result

    # Now try to get additional language splits
    try:
        from gpapi import googleplay_pb2
        import re

        # Get version code from details
        headers = get_auth_headers(auth)
        headers['Content-Type'] = 'application/x-protobuf'
        headers['Accept'] = 'application/x-protobuf'

        response = requests.get(f"{DETAILS_URL}?doc={package}", headers=headers, timeout=30)
        if response.status_code != 200:
            print("Could not get version info for additional splits")
            return 0

        details_response = googleplay_pb2.ResponseWrapper()
        details_response.ParseFromString(response.content)
        app = details_response.payload.detailsResponse.docV2
        version_code = app.details.appDetails.versionCode

        lang_pattern = re.compile(r'^config\.([a-z]{2}(_[A-Z]{2})?)$')
        downloaded_splits = set()

        # Check what we already have
        for f in output_dir.iterdir():
            if f.name.startswith(f"{package}.config.") and f.name.endswith('.apk'):
                split_name = f.name.replace(f"{package}.", '').replace('.apk', '')
                downloaded_splits.add(split_name)

        # Try each language
        for lang_code, accept_lang in LANGUAGE_HEADERS:
            expected = f"config.{lang_code}"
            if expected in downloaded_splits:
                print(f"Already have {expected}, skipping")
                continue

            print(f"\nFetching {expected} split...")
            time.sleep(2)

            try:
                lang_headers = get_auth_headers(auth, accept_language=accept_lang)
                lang_headers['Content-Type'] = 'application/x-protobuf'
                lang_headers['Accept'] = 'application/x-protobuf'

                delivery_url = f"{DELIVERY_URL}?doc={package}&ot=1&vc={version_code}"
                delivery_response = requests.get(delivery_url, headers=lang_headers, timeout=30)

                if delivery_response.status_code != 200:
                    print(f"  Failed: HTTP {delivery_response.status_code}")
                    continue

                delivery_wrapper = googleplay_pb2.ResponseWrapper()
                delivery_wrapper.ParseFromString(delivery_response.content)
                delivery_data = delivery_wrapper.payload.deliveryResponse.appDeliveryData

                # Look for language splits
                for split in delivery_data.split:
                    if lang_pattern.match(split.name) and split.name not in downloaded_splits:
                        split_filepath = output_dir / f"{package}.{split.name}.apk"

                        download_headers = {}
                        for cookie in delivery_data.downloadAuthCookie:
                            download_headers['Cookie'] = f"{cookie.name}={cookie.value}"

                        dl_response = requests.get(split.downloadUrl, headers=download_headers, stream=True, timeout=300)
                        if dl_response.status_code == 200:
                            with open(split_filepath, 'wb') as f:
                                for chunk in dl_response.iter_content(chunk_size=8192):
                                    if chunk:
                                        f.write(chunk)

                            if split_filepath.exists() and split_filepath.stat().st_size > 0:
                                downloaded_splits.add(split.name)
                                print(f"  Downloaded: {split.name}")

            except Exception as e:
                print(f"  Error: {e}")

        print(f"\nTotal language splits: {len([s for s in downloaded_splits if lang_pattern.match(s)])}")

    except ImportError:
        print("gpapi library required for language split downloads")

    return 0


def _check_adb_device():
    """Check adb is available and a device is connected. Returns True if ready."""
    import subprocess as sp
    try:
        sp.run(['adb', 'version'], capture_output=True, check=True)
    except (FileNotFoundError, sp.CalledProcessError):
        print("Error: adb not found. Install Android SDK platform-tools.")
        return False
    result = sp.run(['adb', 'devices'], capture_output=True, text=True, timeout=10)
    devices = [l for l in result.stdout.strip().split('\n')[1:] if l.strip() and 'device' in l]
    if not devices:
        print("Error: No ADB device connected.")
        return False
    return True


def cmd_backup(args):
    """Backup list of user-installed packages from connected ADB device."""
    import subprocess as sp
    import datetime

    if not _check_adb_device():
        return 1

    print("Reading user-installed packages from device...")
    try:
        result = sp.run(['adb', 'shell', 'pm', 'list', 'packages', '-3'],
                        capture_output=True, text=True, check=True, timeout=30)
    except sp.CalledProcessError as e:
        print(f"Error: {e.stderr.strip() or 'Failed to list packages'}")
        return 1
    except sp.TimeoutExpired:
        print("Error: ADB command timed out. Is device connected?")
        return 1

    packages = sorted(set(
        line.replace('package:', '').strip()
        for line in result.stdout.strip().split('\n')
        if line.strip()
    ))
    print(f"Found {len(packages)} user-installed packages")

    # Check Play Store availability
    auth = load_auth()
    results = []
    available_count = 0

    if auth:
        print("Checking availability on Google Play...")
        scraper = cloudscraper.create_scraper()
        for i, pkg in enumerate(packages):
            sys.stdout.write(f"\r  Checking {i + 1}/{len(packages)}: {pkg[:50]}{'...' if len(pkg) > 50 else ''}" + ' ' * 20)
            sys.stdout.flush()
            try:
                url = f"https://play.google.com/store/apps/details?id={pkg}&hl=en"
                resp = scraper.get(url, timeout=10)
                if resp.status_code == 200:
                    results.append({'package': pkg, 'available': True})
                    available_count += 1
                else:
                    results.append({'package': pkg, 'available': False})
            except Exception:
                results.append({'package': pkg, 'available': False})
        print(f"\r  Done: {available_count} available on Play Store, {len(packages) - available_count} not found" + ' ' * 30)
    else:
        print("Warning: No auth token — skipping Play Store availability check")
        results = [{'package': pkg, 'available': True} for pkg in packages]

    # Get device info
    try:
        model = sp.run(['adb', 'shell', 'getprop', 'ro.product.model'],
                        capture_output=True, text=True, timeout=10).stdout.strip()
    except Exception:
        model = 'Unknown'

    backup = {
        'device': model,
        'date': datetime.datetime.now().isoformat(),
        'packages': results
    }

    # Output
    output_file = args.output
    if output_file == '-':
        print(json.dumps(backup, indent=2))
    else:
        if output_file is None:
            output_file = f"app-backup-{datetime.date.today().isoformat()}.json"
        with open(output_file, 'w') as f:
            json.dump(backup, f, indent=2)
        print(f"\nBackup saved to: {output_file}")
        print(f"  {len(results)} packages total, {available_count} available on Play Store")

    return 0


def cmd_restore(args):
    """Restore apps from a backup JSON file."""
    # Pre-check ADB device if --install requested
    if getattr(args, 'install', False):
        if not _check_adb_device():
            return 1

    auth = load_auth()
    if not auth:
        return 1

    # Load backup
    try:
        with open(args.file) as f:
            backup = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error: {e}")
        return 1

    if not backup.get('packages'):
        print("Error: Invalid backup file (no packages)")
        return 1

    packages = [p for p in backup['packages'] if p.get('available', True)]
    if not packages:
        print("No available packages to restore")
        return 0

    print(f"Backup from: {backup.get('device', 'Unknown')} ({backup.get('date', 'Unknown date')})")
    print(f"Packages to restore: {len(packages)}")
    print()

    arch = ARCH_MAP.get(args.arch, 'arm64-v8a') if args.arch else 'arm64-v8a'
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    should_merge = args.merge

    succeeded = 0
    failed = 0

    class DownloadArgs:
        pass

    for i, pkg_info in enumerate(packages):
        pkg = pkg_info['package']
        print(f"[{i + 1}/{len(packages)}] {pkg}")

        dl_args = DownloadArgs()
        dl_args.package = pkg
        dl_args.arch = args.arch
        dl_args.output = str(output_dir)
        dl_args.merge = should_merge
        dl_args.version = None
        dl_args.both_arch = False
        dl_args.all_locales = False
        dl_args.install = getattr(args, 'install', False)
        dl_args.json = False

        try:
            result = cmd_download(dl_args)
            if result == 0:
                succeeded += 1
            else:
                failed += 1
                print(f"  Failed to download {pkg}")
        except Exception as e:
            failed += 1
            print(f"  Error: {e}")

        print()

    print(f"\nRestore complete: {succeeded} succeeded, {failed} failed")
    return 0 if failed == 0 else 1


def main():
    parser = argparse.ArgumentParser(
        description='Download APKs from Google Play Store',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s auth                              # Authenticate (anonymous)
  %(prog)s search "whatsapp"                 # Search for apps
  %(prog)s info com.whatsapp                 # Get app details
  %(prog)s check-version com.whatsapp        # Check version without downloading
  %(prog)s list-splits com.whatsapp          # List available splits
  %(prog)s download com.whatsapp             # Download APK (arm64)
  %(prog)s download com.app -a armv7         # Download for older phones
  %(prog)s download com.app -m               # Download and merge splits
  %(prog)s download com.app --both-arch      # Download ARM64 + ARMv7
  %(prog)s download com.app --all-locales    # Download all language splits
  %(prog)s download com.app -i              # Download and install to device via ADB
  %(prog)s restore backup.json -i           # Restore apps directly to device
  %(prog)s info com.whatsapp --json          # JSON output for scripting
        """
    )

    # Global --json flag
    parser.add_argument('--json', action='store_true',
                        help='Output results as JSON (for scripting)')

    subparsers = parser.add_subparsers(dest='command', required=True)

    # Auth command
    auth_parser = subparsers.add_parser('auth', help='Authenticate with Google Play')
    auth_parser.add_argument('-d', '--dispenser', help='Dispenser URL for anonymous auth')

    # Search command
    search_parser = subparsers.add_parser('search', help='Search for apps')
    search_parser.add_argument('query', help='Search query')
    search_parser.add_argument('-l', '--limit', type=int, default=10, help='Max results')
    search_parser.add_argument('--json', action='store_true', help='Output as JSON')

    # Info command
    info_parser = subparsers.add_parser('info', help='Get app details')
    info_parser.add_argument('package', help='Package name (e.g., com.whatsapp)')
    info_parser.add_argument('--json', action='store_true', help='Output as JSON')

    # Check-version command
    check_version_parser = subparsers.add_parser('check-version', help='Check app version (no download)')
    check_version_parser.add_argument('package', help='Package name (e.g., com.whatsapp)')
    check_version_parser.add_argument('--json', action='store_true', help='Output as JSON')

    # List-splits command
    list_splits_parser = subparsers.add_parser('list-splits', help='List available splits for an app')
    list_splits_parser.add_argument('package', help='Package name (e.g., com.whatsapp)')
    list_splits_parser.add_argument('--json', action='store_true', help='Output as JSON')

    # Download command
    download_parser = subparsers.add_parser('download', help='Download APK')
    download_parser.add_argument('package', help='Package name (e.g., com.whatsapp)')
    download_parser.add_argument('-o', '--output', default='.', help='Output directory')
    download_parser.add_argument('-v', '--version', type=int, help='Specific version code')
    download_parser.add_argument('-a', '--arch', choices=['arm64', 'armv7'], default='arm64',
                                help='Architecture: arm64 (default) or armv7')
    download_parser.add_argument('-m', '--merge', action='store_true',
                                help='Merge split APKs into single installable APK')
    download_parser.add_argument('--both-arch', action='store_true',
                                help='Download for both ARM64 and ARMv7')
    download_parser.add_argument('--all-locales', action='store_true',
                                help='Download all language splits (en, he, fr)')
    download_parser.add_argument('-i', '--install', action='store_true',
                                help='Install to connected ADB device after download')

    # Backup command
    backup_parser = subparsers.add_parser('backup', help='Backup list of installed apps from ADB device')
    backup_parser.add_argument('-o', '--output', default=None, help='Output file (default: app-backup-DATE.json, use - for stdout)')

    # Restore command
    restore_parser = subparsers.add_parser('restore', help='Restore apps from a backup file')
    restore_parser.add_argument('file', help='Backup JSON file')
    restore_parser.add_argument('-o', '--output', default='.', help='Output directory for downloaded APKs')
    restore_parser.add_argument('-a', '--arch', choices=['arm64', 'armv7'], default='arm64',
                                help='Architecture: arm64 (default) or armv7')
    restore_parser.add_argument('-m', '--merge', action='store_true',
                                help='Merge split APKs into single installable APK')
    restore_parser.add_argument('-i', '--install', action='store_true',
                                help='Install each app to connected ADB device')

    args = parser.parse_args()

    # Handle download subcommand variants
    if args.command == 'download':
        if args.both_arch:
            return cmd_download_both_arch(args)
        elif args.all_locales:
            return cmd_download_all_locales(args)

    commands = {
        'auth': cmd_auth,
        'search': cmd_search,
        'info': cmd_info,
        'download': cmd_download,
        'check-version': cmd_check_version,
        'list-splits': cmd_list_splits,
        'backup': cmd_backup,
        'restore': cmd_restore,
    }

    return commands[args.command](args)


if __name__ == '__main__':
    sys.exit(main())
