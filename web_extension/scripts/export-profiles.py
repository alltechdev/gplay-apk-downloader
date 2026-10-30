#!/usr/bin/env python3
"""Bundle the server's profiles and personal-account defaults without duplicating policy."""
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import device_profiles as devices


def export_profiles():
    profiles = []
    for arch in ('arm64', 'armv7'):
        for key, profile in devices.get_priority_profiles(arch):
            profiles.append({'key': key, 'arch': arch, 'profile': profile})
    def key_for(profile):
        return next(entry['key'] for entry in profiles if entry['profile'] == profile)
    return {
        'priority': devices.PRIORITY_ARM64 + devices.PRIORITY_ARMV7,
        'personalDefaults': {
            'arm64-v8a': key_for(devices.DEFAULT_ARM64_PROFILE),
            'armeabi-v7a': key_for(devices.NEWEST_ARMV7_PROFILE),
        },
        'profiles': profiles,
    }


if __name__ == '__main__':
    payload = json.dumps(export_profiles(), indent=2) + '\n'
    if '--stdout' in sys.argv:
        print(payload, end='')
    else:
        (ROOT / 'web_extension/src/profiles.json').write_text(payload)
