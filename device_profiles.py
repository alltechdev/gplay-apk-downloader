"""
Device profiles for Google Play API.
Loads full profiles from Aurora Store .properties files.
Falls back to built-in profile if profiles/ directory is missing.
"""

import os
from pathlib import Path

PROFILES_DIR = Path(__file__).parent / 'profiles'

# Fallback profile if no .properties files exist
FALLBACK_PROFILE = {
    'UserReadableName': 'Generic ARM64 Device',
    'Build.HARDWARE': 'qcom',
    'Build.RADIO': 'unknown',
    'Build.BOOTLOADER': 'unknown',
    'Build.FINGERPRINT': 'google/sunfish/sunfish:13/TQ3A.230805.001/10316531:user/release-keys',
    'Build.BRAND': 'google',
    'Build.DEVICE': 'sunfish',
    'Build.VERSION.SDK_INT': '33',
    'Build.VERSION.RELEASE': '13',
    'Build.MODEL': 'Pixel 4a',
    'Build.MANUFACTURER': 'Google',
    'Build.PRODUCT': 'sunfish',
    'Build.ID': 'TQ3A.230805.001',
    'Build.TYPE': 'user',
    'Build.TAGS': 'release-keys',
    'Build.SUPPORTED_ABIS': 'arm64-v8a,armeabi-v7a,armeabi',
    'Platforms': 'arm64-v8a,armeabi-v7a,armeabi',
    'Screen.Density': '440',
    'Screen.Width': '1080',
    'Screen.Height': '2340',
    'Locales': 'en-US',
    'SharedLibraries': 'android.ext.shared,android.test.base,android.test.mock,android.test.runner,com.android.future.usb.accessory,com.android.location.provider,com.android.media.remotedisplay,com.android.mediadrm.signer,com.android.nfc_extras,com.google.android.gms,com.google.android.maps,javax.obex,org.apache.http.legacy',
    'Features': 'android.hardware.audio.output,android.hardware.bluetooth,android.hardware.bluetooth_le,android.hardware.camera,android.hardware.camera.autofocus,android.hardware.camera.capability.manual_post_processing,android.hardware.camera.capability.manual_sensor,android.hardware.camera.capability.raw,android.hardware.camera.flash,android.hardware.camera.front,android.hardware.camera.level.full,android.hardware.faketouch,android.hardware.fingerprint,android.hardware.location,android.hardware.location.gps,android.hardware.location.network,android.hardware.microphone,android.hardware.nfc,android.hardware.nfc.hce,android.hardware.nfc.hcef,android.hardware.nfc.uicc,android.hardware.opengles.aep,android.hardware.ram.normal,android.hardware.screen.landscape,android.hardware.screen.portrait,android.hardware.sensor.accelerometer,android.hardware.sensor.barometer,android.hardware.sensor.compass,android.hardware.sensor.gyroscope,android.hardware.sensor.hifi_sensors,android.hardware.sensor.light,android.hardware.sensor.proximity,android.hardware.sensor.stepcounter,android.hardware.sensor.stepdetector,android.hardware.telephony,android.hardware.telephony.cdma,android.hardware.telephony.gsm,android.hardware.touchscreen,android.hardware.touchscreen.multitouch,android.hardware.touchscreen.multitouch.distinct,android.hardware.touchscreen.multitouch.jazzhand,android.hardware.usb.accessory,android.hardware.usb.host,android.hardware.vulkan.compute,android.hardware.vulkan.level,android.hardware.vulkan.version,android.hardware.wifi,android.hardware.wifi.direct,android.hardware.wifi.passpoint,android.software.app_widgets,android.software.autofill,android.software.backup,android.software.companion_device_setup,android.software.connectionservice,android.software.cts,android.software.device_admin,android.software.file_based_encryption,android.software.home_screen,android.software.input_methods,android.software.live_wallpaper,android.software.managed_users,android.software.midi,android.software.picture_in_picture,android.software.print,android.software.securely_removes_users,android.software.sip,android.software.sip.voip,android.software.voice_recognizers,android.software.webview',
    'GSF.version': '223616055',
    'Vending.version': '82151710',
    'Vending.versionString': '21.5.17-21 [0] [PR] 326734551',
    'Roaming': 'mobile-notroaming',
    'TimeZone': 'America/New_York',
    'CellOperator': '310260',
    'SimOperator': '310260',
    'Client': 'android-google',
    'GL.Version': '196610',
    'GL.Extensions': 'GL_OES_EGL_image,GL_OES_EGL_image_external,GL_OES_EGL_sync,GL_OES_vertex_half_float,GL_OES_framebuffer_object,GL_OES_rgb8_rgba8,GL_OES_compressed_ETC1_RGB8_texture,GL_EXT_texture_format_BGRA8888,GL_OES_texture_npot,GL_OES_packed_depth_stencil,GL_OES_depth24,GL_OES_depth_texture,GL_OES_texture_float,GL_OES_texture_half_float,GL_OES_element_index_uint,GL_OES_vertex_array_object',
}


def load_profile_from_file(filepath):
    """Load a .properties file as dict."""
    profile = {}
    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, val = line.split('=', 1)
                profile[key] = val
    return profile


def load_all_profiles():
    """Load all profiles from the profiles directory."""
    profiles = {}
    if not PROFILES_DIR.exists():
        return profiles

    for filepath in sorted(PROFILES_DIR.glob('*.properties')):
        profile = load_profile_from_file(filepath)
        name = profile.get('UserReadableName', filepath.stem)
        platforms = profile.get('Platforms', '')

        # Determine architecture
        if 'arm64-v8a' in platforms:
            arch = 'arm64'
        elif 'armeabi-v7a' in platforms:
            arch = 'armv7'
        elif 'x86' in platforms:
            arch = 'x86'
        else:
            arch = 'unknown'

        profiles[filepath.stem] = {
            'name': name,
            'arch': arch,
            'platforms': platforms,
            'profile': profile,
        }

    return profiles


# Load all profiles on module import
ALL_PROFILES = load_all_profiles()

# Separate by architecture
ARM64_PROFILES = [
    (key, data['profile'])
    for key, data in ALL_PROFILES.items()
    if data['arch'] == 'arm64'
]

ARMV7_PROFILES = [
    (key, data['profile'])
    for key, data in ALL_PROFILES.items()
    if data['arch'] == 'armv7'
]

X86_PROFILES = [
    (key, data['profile'])
    for key, data in ALL_PROFILES.items()
    if data['arch'] == 'x86'
]

# Named profile access
GALAXY_S25_ULTRA = ALL_PROFILES.get('B1', {}).get('profile', {})
NOTHING_PHONE_1 = ALL_PROFILES.get('VP', {}).get('profile', {})
REDMI_NOTE_12 = ALL_PROFILES.get('HE', {}).get('profile', {})
XIAOMI_MI_A1 = ALL_PROFILES.get('Fj', {}).get('profile', {})
HUAWEI_MATE_20 = ALL_PROFILES.get('p6', {}).get('profile', {})
REDMI_7 = ALL_PROFILES.get('Hb', {}).get('profile', {})
SAMSUNG_A13_5G = ALL_PROFILES.get('Gj', {}).get('profile', {})
REALME_5_PRO = ALL_PROFILES.get('IV', {}).get('profile', {})

# Priority-ordered profiles (based on testing with restricted apps like Chase)
# These are sorted by reliability with the Aurora dispenser
PRIORITY_ARM64 = ['Pv', 'D2', 'eV', 'iq', 'Fj', 'HE', 'VP', 'Hb', 'p6', 'B1']  # Pixel 9a first
PRIORITY_ARMV7 = ['XK', 'Gj', 'IV', 'Gb']  # Samsung J5 Prime first

def get_priority_profiles(arch='arm64'):
    """Get profiles sorted by priority (most reliable first)."""
    if arch == 'armv7':
        priority_list = PRIORITY_ARMV7
        all_profiles = ARMV7_PROFILES
    else:
        priority_list = PRIORITY_ARM64
        all_profiles = ARM64_PROFILES

    # Build ordered list
    result = []
    seen = set()

    # Add priority profiles first
    for key in priority_list:
        for pkey, profile in all_profiles:
            if pkey == key and pkey not in seen:
                result.append((pkey, profile))
                seen.add(pkey)
                break

    # Add remaining profiles
    for pkey, profile in all_profiles:
        if pkey not in seen:
            result.append((pkey, profile))
            seen.add(pkey)

    return result

# Default profiles
PIXEL_9A = ALL_PROFILES.get('Pv', {}).get('profile', {})
SAMSUNG_F34 = ALL_PROFILES.get('D2', {}).get('profile', {})
XPERIA_5 = ALL_PROFILES.get('eV', {}).get('profile', {})
OPPO_R17 = ALL_PROFILES.get('iq', {}).get('profile', {})
SAMSUNG_J5_PRIME = ALL_PROFILES.get('XK', {}).get('profile', {})

DEFAULT_ARM64_PROFILE = PIXEL_9A if PIXEL_9A else (ARM64_PROFILES[0][1] if ARM64_PROFILES else FALLBACK_PROFILE)
DEFAULT_ARMV7_PROFILE = SAMSUNG_J5_PRIME if SAMSUNG_J5_PRIME else (ARMV7_PROFILES[0][1] if ARMV7_PROFILES else FALLBACK_PROFILE)


def get_profile(arch='arm64', profile_name=None):
    """Get a device profile by architecture and optional name."""
    if arch == 'armv7':
        profiles = ARMV7_PROFILES
        default = DEFAULT_ARMV7_PROFILE
    else:
        profiles = ARM64_PROFILES
        default = DEFAULT_ARM64_PROFILE

    if profile_name:
        for name, profile in profiles:
            if name == profile_name:
                return profile

    return default


def get_all_profiles(arch='arm64'):
    """Get all profiles for an architecture."""
    if arch == 'armv7':
        return ARMV7_PROFILES
    return ARM64_PROFILES


def list_profiles():
    """Print all available profiles."""
    print("Available profiles:")
    print("\nARM64 (64-bit):")
    for key, profile in ARM64_PROFILES:
        print(f"  {key}: {profile.get('UserReadableName', 'Unknown')}")

    print("\nARMv7 (32-bit):")
    for key, profile in ARMV7_PROFILES:
        print(f"  {key}: {profile.get('UserReadableName', 'Unknown')}")

    if X86_PROFILES:
        print("\nx86:")
        for key, profile in X86_PROFILES:
            print(f"  {key}: {profile.get('UserReadableName', 'Unknown')}")


if __name__ == '__main__':
    list_profiles()
