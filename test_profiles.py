#!/usr/bin/env python3
"""Test all Aurora device profiles against restricted apps."""

import os
import sys
import json
import time
import cloudscraper
import requests

DISPENSER_URL = "https://auroraoss.com/api/auth"
DETAILS_URL = "https://android.clients.google.com/fdfe/details"
TEST_APPS = [
    "com.chase.sig.android",  # Chase - often restricted
    "com.google.android.youtube",  # YouTube - always works
]

# Load all profiles from local profiles/ directory
PROFILES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'profiles')

def load_profile(filepath):
    """Load a .properties file as dict."""
    profile = {}
    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, val = line.split('=', 1)
                profile[key] = val
    return profile

def get_auth(profile):
    """Get auth token using device profile."""
    scraper = cloudscraper.create_scraper()
    scraper.headers.update({'User-Agent': 'com.aurora.store-4.6.1-70'})

    try:
        response = scraper.post(DISPENSER_URL, json=profile, timeout=30)
        if response.status_code == 200:
            return response.json()
    except Exception as e:
        print(f"    Auth error: {e}")
    return None

def test_app(auth, package):
    """Test if we can get app details."""
    device_info = auth.get('deviceInfoProvider', {})
    headers = {
        'Authorization': f"Bearer {auth.get('authToken')}",
        'User-Agent': device_info.get('userAgentString', 'Android-Finsky/41.2.29-23'),
        'X-DFE-Device-Id': auth.get('gsfId', ''),
        'Accept-Language': 'en-US',
        'X-DFE-Encoded-Targets': 'CAESN/qigQYC2AMBFfUbyA7SM5Ij/CvfBoIDgxXrBPsDlQUdMfOLAfoFrwEHgAcBrQYhoA0cGt4MKK0Y2gI',
        'X-DFE-Client-Id': 'am-android-google',
        'Content-Type': 'application/x-protobuf',
    }

    try:
        response = requests.get(f"{DETAILS_URL}?doc={package}", headers=headers, timeout=30)
        return response.status_code
    except:
        return 0

def main():
    results = {}

    # Get all profile files
    profiles = sorted([f for f in os.listdir(PROFILES_DIR) if f.endswith('.properties')])

    print(f"Testing {len(profiles)} profiles against {len(TEST_APPS)} apps...\n")

    for profile_file in profiles:
        filepath = os.path.join(PROFILES_DIR, profile_file)
        profile = load_profile(filepath)
        name = profile.get('UserReadableName', profile_file)
        platforms = profile.get('Platforms', 'unknown')

        print(f"[{profile_file}] {name} ({platforms})")

        # Get auth
        auth = get_auth(profile)
        if not auth:
            print("    FAILED: Could not authenticate")
            results[profile_file] = {'name': name, 'auth': False}
            time.sleep(2)
            continue

        results[profile_file] = {'name': name, 'auth': True, 'apps': {}}

        # Test apps
        for app in TEST_APPS:
            status = test_app(auth, app)
            status_str = "OK" if status == 200 else f"FAIL({status})"
            print(f"    {app}: {status_str}")
            results[profile_file]['apps'][app] = status

        time.sleep(1)  # Rate limit

    # Summary
    print("\n" + "="*60)
    print("SUMMARY - Profiles that work with Chase:")
    print("="*60)

    working = []
    for pf, data in results.items():
        if data.get('auth') and data.get('apps', {}).get('com.chase.sig.android') == 200:
            working.append((pf, data['name']))

    if working:
        for pf, name in working:
            print(f"  ✓ {name} ({pf})")
    else:
        print("  None worked!")

    # Save results
    with open('profile_test_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\nFull results saved to profile_test_results.json")

if __name__ == '__main__':
    main()
