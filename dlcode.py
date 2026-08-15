#!/usr/bin/env python3
"""
Downloader Code APK Fetcher

Resolves AFTVnews "Downloader codes" (the short codes you type into the
Downloader app on Fire TV / Android TV, e.g. aftv.news/141733) and downloads
the APK they point at.

Usage:
    ./dlcode.py 141733                 # Resolve code and download the APK
    ./dlcode.py 141733 -o ~/apks       # Download into a specific directory
    ./dlcode.py resolve 141733         # Just print the destination URL
    ./dlcode.py 141733 --json          # Machine-readable output

Unlike gplay-downloader.py, this needs no auth and no dispenser: Downloader
codes are plain URL-shortener entries pointing at publicly hosted files.
"""

import argparse
import json
import os
import re
import sys
import zipfile
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

try:
    import requests
except ImportError:
    print("Error: requests library not found. Install with: pip install requests")
    sys.exit(1)

SHORTENER_URL = "https://aftv.news/{code}"
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"

# The code page sets its destination with a bare JS assignment.
DEST_RE = re.compile(r'window\.location\s*=\s*"([^"]+)"')
# An unknown code falls through to a Google search instead of 404ing.
NOT_FOUND_MARKER = "go.aftvnews.com/googlesearch/"

ZIP_MAGIC = b"PK\x03\x04"


def format_size(size_bytes):
    """Human-readable byte count."""
    if not size_bytes:
        return "unknown size"
    for unit in ("B", "KB", "MB", "GB"):
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}" if unit != "B" else f"{size_bytes} B"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


def normalize_code(code):
    """Accept '141733', 'aftv.news/141733', or a full URL."""
    code = code.strip()
    if "/" in code:
        code = code.rstrip("/").rsplit("/", 1)[-1]
    return code


def direct_download_url(url):
    """Rewrite known share-page URLs into their direct-download form.

    Many codes point at Dropbox/Drive share pages, which serve an HTML preview
    rather than the file unless nudged.
    """
    parts = urlparse(url)
    host = parts.netloc.lower()

    if "dropbox.com" in host:
        query = parse_qs(parts.query)
        query["dl"] = ["1"]  # dl=0 renders a preview page; dl=1 serves the file
        return urlunparse(parts._replace(query=urlencode(query, doseq=True)))

    if "drive.google.com" in host:
        file_id = None
        match = re.search(r"/file/d/([^/]+)", parts.path)
        if match:
            file_id = match.group(1)
        elif "id" in parse_qs(parts.query):
            file_id = parse_qs(parts.query)["id"][0]
        if file_id:
            return f"https://drive.google.com/uc?export=download&id={file_id}"

    return url


def resolve(code, session):
    """Resolve a Downloader code to its destination URL."""
    url = SHORTENER_URL.format(code=code)
    response = session.get(url, timeout=30, allow_redirects=True)
    response.raise_for_status()

    if NOT_FOUND_MARKER in response.url or NOT_FOUND_MARKER in response.text:
        raise LookupError(f"Code '{code}' is not registered (the shortener fell back to a search page).")

    match = DEST_RE.search(response.text)
    if not match:
        raise LookupError(
            f"Code '{code}' has no destination — it is unregistered, expired, or mistyped."
        )

    return match.group(1)


def filename_for(response, url, code):
    """Pick an output filename from Content-Disposition, then URL, then code."""
    disposition = response.headers.get("content-disposition", "")
    match = re.search(r'filename\*?=(?:UTF-8\'\')?"?([^";]+)"?', disposition)
    if match:
        name = match.group(1)
    else:
        name = os.path.basename(urlparse(url).path)

    name = os.path.basename(name).strip()
    if not name or not name.lower().endswith(".apk"):
        name = f"{name or code}.apk" if not name.lower().endswith(".apk") else name
    return name


def verify_apk(path):
    """Return (is_apk, detail). APKs are zips containing AndroidManifest.xml."""
    with open(path, "rb") as handle:
        magic = handle.read(4)
    if magic != ZIP_MAGIC:
        head = magic.decode("latin-1", "replace")
        if magic[:1] == b"<":
            return False, "server returned an HTML page, not an APK (the link may need a browser or has expired)"
        return False, f"not a zip archive (starts with {head!r})"

    try:
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
    except zipfile.BadZipFile:
        return False, "file is a corrupt zip archive"

    if "AndroidManifest.xml" not in names:
        return False, "zip archive has no AndroidManifest.xml (may be an XAPK/APKS bundle)"
    return True, "valid APK"


def download(url, out_dir, code, session, quiet=False):
    """Stream the destination URL to disk, returning the saved path."""
    target = direct_download_url(url)
    with session.get(target, stream=True, timeout=(10, 60), allow_redirects=True) as response:
        response.raise_for_status()

        total = int(response.headers.get("content-length") or 0)
        name = filename_for(response, response.url, code)
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / name

        if not quiet:
            print(f"Downloading: {name} ({format_size(total)})")

        downloaded = 0
        last_percent = -1
        show_progress = bool(total) and not quiet
        with open(path, "wb") as handle:
            for chunk in response.iter_content(chunk_size=65536):
                if not chunk:
                    continue
                handle.write(chunk)
                downloaded += len(chunk)
                if show_progress:
                    percent = int(downloaded * 100 / total)
                    if percent != last_percent:  # avoid a line per chunk when piped
                        last_percent = percent
                        print(f"\r  Progress: {percent}% ({format_size(downloaded)} / {format_size(total)})", end="", flush=True)
        if show_progress:
            print()

    return path


def make_session():
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    return session


def main():
    parser = argparse.ArgumentParser(
        description="Download APKs by AFTVnews Downloader code",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ./dlcode.py 141733                  # Resolve code and download the APK
  ./dlcode.py 141733 -o ~/apks        # Save into a specific directory
  ./dlcode.py resolve 141733          # Print the destination URL only
  ./dlcode.py 141733 --json           # JSON output for scripting
  ./dlcode.py 141733 --force          # Keep the file even if it isn't an APK
""",
    )
    parser.add_argument("code", help="Downloader code (e.g. 141733), or 'resolve' followed by a code")
    parser.add_argument("code2", nargs="?", help=argparse.SUPPRESS)
    parser.add_argument("-o", "--output", default=".", help="Output directory (default: current directory)")
    parser.add_argument("--json", action="store_true", help="Output result as JSON")
    parser.add_argument("--force", action="store_true", help="Keep the download even if it is not a valid APK")
    args = parser.parse_args()

    resolve_only = args.code == "resolve"
    code = normalize_code(args.code2 if resolve_only else args.code)
    if not code:
        parser.error("no code supplied")

    quiet = args.json
    session = make_session()

    try:
        destination = resolve(code, session)
    except LookupError as exc:
        message = str(exc)
        print(json.dumps({"code": code, "error": message}) if args.json else f"Error: {message}", file=sys.stderr)
        return 1
    except requests.RequestException as exc:
        message = f"Failed to reach the shortener: {exc}"
        print(json.dumps({"code": code, "error": message}) if args.json else f"Error: {message}", file=sys.stderr)
        return 1

    if resolve_only:
        print(json.dumps({"code": code, "url": destination}) if args.json else destination)
        return 0

    if not quiet:
        print(f"Code {code} -> {destination}")

    try:
        path = download(destination, Path(args.output).expanduser(), code, session, quiet=quiet)
    except requests.RequestException as exc:
        message = f"Download failed: {exc}"
        print(json.dumps({"code": code, "url": destination, "error": message}) if args.json else f"Error: {message}", file=sys.stderr)
        return 1

    is_apk, detail = verify_apk(path)
    if not is_apk and not args.force:
        path.unlink(missing_ok=True)
        message = f"Discarded download: {detail}. Re-run with --force to keep it."
        print(json.dumps({"code": code, "url": destination, "error": message}) if args.json else f"Error: {message}", file=sys.stderr)
        return 1

    size = path.stat().st_size
    if args.json:
        print(json.dumps({
            "code": code,
            "url": destination,
            "path": str(path.resolve()),
            "size": size,
            "valid_apk": is_apk,
            "detail": detail,
        }))
    else:
        print(f"Saved: {path}  ({format_size(size)}, {detail})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
