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

# Default device properties (Pixel 7a)
DEFAULT_DEVICE = {
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
    """Get anonymous authentication from dispenser."""
    url = dispenser_url or DISPENSER_URLS[0]
    print(f"Authenticating via dispenser: {url}")

    # Use cloudscraper to bypass Cloudflare protection
    scraper = cloudscraper.create_scraper()

    headers = {
        'User-Agent': 'com.aurora.store-4.6.1-70',
        'Content-Type': 'application/json',
    }

    try:
        response = scraper.post(url, json=DEFAULT_DEVICE, headers=headers, timeout=30)
        response.raise_for_status()
        data = response.json()
        return data
    except Exception as e:
        print(f"Error: Failed to authenticate: {e}")
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


def get_auth_headers(auth):
    """Build headers for Google Play API requests."""
    device_info = auth.get('deviceInfoProvider', {})

    return {
        'Authorization': f"Bearer {auth.get('authToken')}",
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

    print(f"Searching for: {args.query}")

    # Use web search as fallback (more reliable)
    try:
        scraper = cloudscraper.create_scraper()
        search_url = f"https://play.google.com/store/search?q={args.query}&c=apps"

        response = scraper.get(search_url, timeout=30)

        if response.status_code != 200:
            print(f"Search failed with status {response.status_code}")
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

        if not matches:
            print("No results found (try 'gplay info <package>' directly)")
            return 0

        seen = set()
        count = 0
        for package, title in matches:
            if package not in seen and count < args.limit:
                seen.add(package)
                count += 1
                display_title = title.strip() if title.strip() else package
                print(f"{count}. {display_title}")
                print(f"   Package: {package}")
                print()

        return 0
    except Exception as e:
        print(f"Search error: {e}")
        return 1


def cmd_info(args):
    """Get app details."""
    auth = load_auth()
    if not auth:
        return 1

    print(f"Fetching info for: {args.package}")

    try:
        # Use web scraping for app details (more reliable)
        scraper = cloudscraper.create_scraper()
        url = f"https://play.google.com/store/apps/details?id={args.package}&hl=en"

        response = scraper.get(url, timeout=30)

        if response.status_code == 404:
            print("App not found.")
            return 1

        if response.status_code != 200:
            print(f"Failed to fetch app info: {response.status_code}")
            return 1

        import re

        # Extract app info from HTML
        html = response.text

        # Title
        title_match = re.search(r'<h1[^>]*>([^<]+)</h1>', html)
        title = title_match.group(1) if title_match else args.package

        # Developer
        dev_match = re.search(r'<a[^>]*href="/store/apps/developer[^"]*"[^>]*>([^<]+)</a>', html)
        developer = dev_match.group(1) if dev_match else "Unknown"

        # Rating
        rating_match = re.search(r'(\d+\.\d+)\s*star', html, re.IGNORECASE)
        rating = rating_match.group(1) if rating_match else "N/A"

        # Downloads
        downloads_match = re.search(r'>(\d+[KMB+,\d]*)\s*downloads<', html, re.IGNORECASE)
        if not downloads_match:
            downloads_match = re.search(r'>([\d,]+\+?)\s*Downloads<', html)
        downloads = downloads_match.group(1) if downloads_match else "N/A"

        print(f"Name: {title}")
        print(f"Package: {args.package}")
        print(f"Developer: {developer}")
        print(f"Rating: {rating}")
        print(f"Downloads: {downloads}")
        print()
        print(f"Play Store URL: https://play.google.com/store/apps/details?id={args.package}")

        return 0
    except Exception as e:
        print(f"Error fetching info: {e}")
        return 1


def cmd_download(args):
    """Download APK."""
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
        for cookie in delivery_data.downloadAuthCookie:
            download_headers['Cookie'] = f"{cookie.name}={cookie.value}"

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


def main():
    parser = argparse.ArgumentParser(
        description='Download APKs from Google Play Store',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s auth                              # Authenticate (anonymous)
  %(prog)s search "whatsapp"                 # Search for apps
  %(prog)s info com.whatsapp                 # Get app details
  %(prog)s download com.whatsapp             # Download APK (arm64)
  %(prog)s download com.app -a armv7         # Download for older phones
  %(prog)s download com.app -m               # Download and merge splits
  %(prog)s download com.app -m -a armv7      # Merge for armv7
        """
    )

    subparsers = parser.add_subparsers(dest='command', required=True)

    # Auth command
    auth_parser = subparsers.add_parser('auth', help='Authenticate with Google Play')
    auth_parser.add_argument('-d', '--dispenser', help='Dispenser URL for anonymous auth')

    # Search command
    search_parser = subparsers.add_parser('search', help='Search for apps')
    search_parser.add_argument('query', help='Search query')
    search_parser.add_argument('-l', '--limit', type=int, default=10, help='Max results')

    # Info command
    info_parser = subparsers.add_parser('info', help='Get app details')
    info_parser.add_argument('package', help='Package name (e.g., com.whatsapp)')

    # Download command
    download_parser = subparsers.add_parser('download', help='Download APK')
    download_parser.add_argument('package', help='Package name (e.g., com.whatsapp)')
    download_parser.add_argument('-o', '--output', default='.', help='Output directory')
    download_parser.add_argument('-v', '--version', type=int, help='Specific version code')
    download_parser.add_argument('-a', '--arch', choices=['arm64', 'armv7'], default='arm64',
                                help='Architecture: arm64 (default) or armv7')
    download_parser.add_argument('-m', '--merge', action='store_true',
                                help='Merge split APKs into single installable APK')

    args = parser.parse_args()

    commands = {
        'auth': cmd_auth,
        'search': cmd_search,
        'info': cmd_info,
        'download': cmd_download,
    }

    return commands[args.command](args)


if __name__ == '__main__':
    sys.exit(main())
