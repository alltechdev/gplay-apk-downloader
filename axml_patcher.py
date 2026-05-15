"""
Minimal Android Binary XML (AXML) patcher.

Patches AndroidManifest.xml in merged APKs to add the
com.android.dynamic.apk.fused.modules meta-data tag, which tells
the Play Core AssetPackManager where to find fused asset packs.

Only activates when asset pack splits (e.g. obbassets) are present.
"""

import struct
import io
import zipfile
import os

# AXML chunk types
CHUNK_STRINGPOOL = 0x0001
CHUNK_RESOURCEIDS = 0x0180
CHUNK_START_ELEMENT = 0x0102
CHUNK_END_ELEMENT = 0x0103

# Android attribute resource IDs
RES_ANDROID_NAME = 0x01010003
RES_ANDROID_VALUE = 0x01010024

# Typed value: string
TYPE_STRING = 0x03

FUSED_MODULES_KEY = "com.android.dynamic.apk.fused.modules"


def get_asset_pack_split_names(split_names):
    """Return names of asset pack splits (anything not config.*)."""
    return [n for n in split_names if n and not n.startswith('config.')]


def _read_u16(data, off):
    return struct.unpack_from('<H', data, off)[0]


def _read_u32(data, off):
    return struct.unpack_from('<I', data, off)[0]


def _parse_string_pool(data, off):
    """Parse AXML string pool. Returns dict with pool metadata and strings."""
    header_size = _read_u16(data, off + 2)
    chunk_size = _read_u32(data, off + 4)
    string_count = _read_u32(data, off + 8)
    style_count = _read_u32(data, off + 12)
    flags = _read_u32(data, off + 16)
    strings_start = _read_u32(data, off + 20)
    styles_start = _read_u32(data, off + 24)
    is_utf8 = bool(flags & (1 << 8))

    offsets_base = off + header_size
    str_offsets = [_read_u32(data, offsets_base + i * 4) for i in range(string_count)]

    abs_str_start = off + strings_start
    strings = []
    for i in range(string_count):
        pos = abs_str_start + str_offsets[i]
        if is_utf8:
            # char length (1-2 bytes)
            b = data[pos]
            if b & 0x80:
                pos += 2
            else:
                pos += 1
            # byte length (1-2 bytes)
            b = data[pos]
            if b & 0x80:
                byte_len = ((b & 0x7F) << 8) | data[pos + 1]
                pos += 2
            else:
                byte_len = b
                pos += 1
            strings.append(data[pos:pos + byte_len].decode('utf-8', errors='replace'))
        else:
            char_len = _read_u16(data, pos)
            pos += 2
            strings.append(data[pos:pos + char_len * 2].decode('utf-16-le', errors='replace'))

    return {
        'offset': off,
        'chunk_size': chunk_size,
        'header_size': header_size,
        'string_count': string_count,
        'style_count': style_count,
        'flags': flags,
        'is_utf8': is_utf8,
        'strings_start': strings_start,
        'styles_start': styles_start,
        'strings': strings,
    }


def _encode_string(s, is_utf8):
    """Encode a single string for the AXML string pool."""
    if is_utf8:
        utf8 = s.encode('utf-8')
        char_len = len(s)
        byte_len = len(utf8)
        buf = bytearray()
        if char_len >= 0x80:
            buf.append((char_len >> 8) | 0x80)
            buf.append(char_len & 0xFF)
        else:
            buf.append(char_len)
        if byte_len >= 0x80:
            buf.append((byte_len >> 8) | 0x80)
            buf.append(byte_len & 0xFF)
        else:
            buf.append(byte_len)
        buf += utf8
        buf.append(0)
        return bytes(buf)
    else:
        utf16 = s.encode('utf-16-le')
        return struct.pack('<H', len(s)) + utf16 + b'\x00\x00'


def _build_string_pool(strings, style_count, flags):
    """Rebuild a complete string pool chunk from a list of strings."""
    is_utf8 = bool(flags & (1 << 8))
    header_size = 0x1C  # 28

    encoded = [_encode_string(s, is_utf8) for s in strings]

    # Build string data and offset table
    string_data = bytearray()
    offsets = bytearray()
    for e in encoded:
        offsets += struct.pack('<I', len(string_data))
        string_data += e

    # Style offset table (empty — manifests don't use styles)
    style_offsets = bytearray()

    strings_start = header_size + len(offsets) + len(style_offsets)

    chunk = bytearray()
    chunk += struct.pack('<H', CHUNK_STRINGPOOL)
    chunk += struct.pack('<H', header_size)
    chunk += struct.pack('<I', 0)  # size placeholder
    chunk += struct.pack('<I', len(strings))
    chunk += struct.pack('<I', style_count)
    chunk += struct.pack('<I', flags)
    chunk += struct.pack('<I', strings_start)
    chunk += struct.pack('<I', 0)  # styles_start
    chunk += offsets
    chunk += style_offsets
    chunk += string_data

    # Pad to 4-byte boundary
    while len(chunk) % 4:
        chunk.append(0)

    struct.pack_into('<I', chunk, 4, len(chunk))
    return bytes(chunk)


def _build_start_element(name_idx, android_ns_idx, name_attr_idx, value_attr_idx,
                         key_str_idx, val_str_idx):
    """Build a StartElement chunk for <meta-data android:name=... android:value=.../>."""
    attr_count = 2
    chunk_size = 36 + attr_count * 20  # 76

    chunk = bytearray()
    # ResXMLTree_node header (16 bytes)
    chunk += struct.pack('<H', CHUNK_START_ELEMENT)
    chunk += struct.pack('<H', 0x10)  # headerSize
    chunk += struct.pack('<I', chunk_size)
    chunk += struct.pack('<I', 0)  # lineNumber
    chunk += struct.pack('<I', 0xFFFFFFFF)  # comment

    # ResXMLTree_attrExt (20 bytes)
    chunk += struct.pack('<I', 0xFFFFFFFF)  # namespace (none for element)
    chunk += struct.pack('<I', name_idx)  # element name = "meta-data"
    chunk += struct.pack('<H', 0x14)  # attributeStart
    chunk += struct.pack('<H', 0x14)  # attributeSize
    chunk += struct.pack('<H', attr_count)
    chunk += struct.pack('<HHH', 0, 0, 0)  # idIndex, classIndex, styleIndex

    # Attribute 1: android:name (resId 0x01010003)
    chunk += struct.pack('<I', android_ns_idx)  # namespace
    chunk += struct.pack('<I', name_attr_idx)  # name
    chunk += struct.pack('<I', key_str_idx)  # rawValue
    chunk += struct.pack('<H', 8)  # value size
    chunk += struct.pack('<B', 0)  # res0
    chunk += struct.pack('<B', TYPE_STRING)
    chunk += struct.pack('<I', key_str_idx)  # data

    # Attribute 2: android:value (resId 0x01010024)
    chunk += struct.pack('<I', android_ns_idx)
    chunk += struct.pack('<I', value_attr_idx)
    chunk += struct.pack('<I', val_str_idx)
    chunk += struct.pack('<H', 8)
    chunk += struct.pack('<B', 0)
    chunk += struct.pack('<B', TYPE_STRING)
    chunk += struct.pack('<I', val_str_idx)

    return bytes(chunk)


def _build_end_element(name_idx):
    """Build an EndElement chunk for </meta-data>."""
    chunk = bytearray()
    chunk += struct.pack('<H', CHUNK_END_ELEMENT)
    chunk += struct.pack('<H', 0x10)
    chunk += struct.pack('<I', 24)
    chunk += struct.pack('<I', 0)  # lineNumber
    chunk += struct.pack('<I', 0xFFFFFFFF)  # comment
    chunk += struct.pack('<I', 0xFFFFFFFF)  # namespace
    chunk += struct.pack('<I', name_idx)
    return bytes(chunk)


def _find_string_idx(strings, value):
    """Find string index or return None."""
    try:
        return strings.index(value)
    except ValueError:
        return None


def patch_manifest_fused_modules(manifest_data, fused_value):
    """Patch binary AndroidManifest.xml to add fused modules meta-data.

    Adds <meta-data android:name="com.android.dynamic.apk.fused.modules"
                    android:value="<fused_value>"/>
    inside the <application> element.

    Returns patched bytes, or original bytes if already present or on error.
    """
    data = bytearray(manifest_data)

    # Validate AXML magic
    if len(data) < 8 or _read_u32(data, 0) != 0x00080003:
        return manifest_data

    # Parse string pool
    sp = _parse_string_pool(data, 8)
    strings = sp['strings']

    # Already patched?
    if FUSED_MODULES_KEY in strings:
        return manifest_data

    # Find required existing strings
    android_ns_idx = _find_string_idx(strings, "http://schemas.android.com/apk/res/android")
    meta_data_idx = _find_string_idx(strings, "meta-data")
    application_idx = _find_string_idx(strings, "application")

    if any(x is None for x in [android_ns_idx, meta_data_idx, application_idx]):
        return manifest_data

    # Find name/value attribute indices via resource ID table
    resid_start = 8 + sp['chunk_size']
    if _read_u16(data, resid_start) != CHUNK_RESOURCEIDS:
        return manifest_data

    resid_header = _read_u16(data, resid_start + 2)
    resid_chunk_size = _read_u32(data, resid_start + 4)
    resid_count = (resid_chunk_size - resid_header) // 4

    name_attr_idx = None
    value_attr_idx = None
    for i in range(resid_count):
        rid = _read_u32(data, resid_start + resid_header + i * 4)
        if rid == RES_ANDROID_NAME:
            name_attr_idx = i
        elif rid == RES_ANDROID_VALUE:
            value_attr_idx = i

    if name_attr_idx is None or value_attr_idx is None:
        return manifest_data

    # Add new strings at end of pool (does not shift existing indices)
    key_str_idx = len(strings)
    val_str_idx = len(strings) + 1
    new_strings = strings + [FUSED_MODULES_KEY, fused_value]

    # Rebuild string pool with new strings
    new_sp = _build_string_pool(new_strings, sp['style_count'], sp['flags'])

    # Build meta-data element chunks
    meta_start = _build_start_element(
        meta_data_idx, android_ns_idx, name_attr_idx, value_attr_idx,
        key_str_idx, val_str_idx)
    meta_end = _build_end_element(meta_data_idx)

    # Rebuild file: header + new string pool + rest of chunks (with insertion)
    result = bytearray()
    result += struct.pack('<I', 0x00080003)
    result += struct.pack('<I', 0)  # file size placeholder
    result += new_sp

    # Copy all chunks after original string pool, inserting before </application>
    pos = 8 + sp['chunk_size']
    inserted = False
    while pos + 8 <= len(data):
        chunk_type = _read_u16(data, pos)
        chunk_size = _read_u32(data, pos + 4)
        if chunk_size < 8 or pos + chunk_size > len(data):
            break

        # Insert before first </application> EndElement
        if not inserted and chunk_type == CHUNK_END_ELEMENT:
            el_name_idx = _read_u32(data, pos + 20)
            if el_name_idx == application_idx:
                result += meta_start
                result += meta_end
                inserted = True

        result += data[pos:pos + chunk_size]
        pos += chunk_size

    # Update file size
    struct.pack_into('<I', result, 4, len(result))

    return bytes(result)


def _zipalign(apk_path):
    """Run zipalign on an APK file in place. Required for Android R+ compatibility."""
    import subprocess
    import shutil
    aligned = apk_path + '.aligned'
    try:
        result = subprocess.run(
            ['zipalign', '-f', '-p', '4', apk_path, aligned],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode == 0 and os.path.exists(aligned):
            os.replace(aligned, apk_path)
    except Exception:
        if os.path.exists(aligned):
            os.remove(aligned)


def _rewrite_apk_with_manifest(apk_path, patched_manifest, out_path):
    """Rewrite APK replacing AndroidManifest.xml, preserving compression types."""
    with zipfile.ZipFile(apk_path, 'r') as zin:
        with zipfile.ZipFile(out_path, 'w') as zout:
            for item in zin.infolist():
                if item.filename == 'AndroidManifest.xml':
                    info = zipfile.ZipInfo(item.filename)
                    info.compress_type = item.compress_type
                    zout.writestr(info, patched_manifest)
                else:
                    zout.writestr(item, zin.read(item.filename))


def patch_apk_fused_modules(apk_path, fused_value):
    """Patch an APK file on disk to add fused modules meta-data.

    Returns True if patched, False if no change needed.
    """
    with zipfile.ZipFile(apk_path, 'r') as zin:
        manifest = zin.read('AndroidManifest.xml')

    patched = patch_manifest_fused_modules(manifest, fused_value)
    if patched == manifest:
        return False

    tmp = apk_path + '.fused_tmp'
    try:
        _rewrite_apk_with_manifest(apk_path, patched, tmp)
        os.replace(tmp, apk_path)
        _zipalign(apk_path)
        return True
    except Exception:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise


def patch_apk_bytes_fused_modules(apk_bytes, fused_value):
    """Patch APK bytes in memory. Returns patched bytes or original if no change."""
    import tempfile
    zin = zipfile.ZipFile(io.BytesIO(apk_bytes), 'r')
    manifest = zin.read('AndroidManifest.xml')

    patched = patch_manifest_fused_modules(manifest, fused_value)
    if patched == manifest:
        zin.close()
        return apk_bytes

    # Write to temp files so we can zipalign
    tmp_dir = tempfile.mkdtemp(prefix='fused_patch_')
    tmp_apk = os.path.join(tmp_dir, 'patched.apk')
    try:
        with zipfile.ZipFile(tmp_apk, 'w') as zout:
            for item in zin.infolist():
                if item.filename == 'AndroidManifest.xml':
                    info = zipfile.ZipInfo(item.filename)
                    info.compress_type = item.compress_type
                    zout.writestr(info, patched)
                else:
                    zout.writestr(item, zin.read(item.filename))
        zin.close()

        _zipalign(tmp_apk)

        with open(tmp_apk, 'rb') as f:
            return f.read()
    finally:
        import shutil
        shutil.rmtree(tmp_dir, ignore_errors=True)
