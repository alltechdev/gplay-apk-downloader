"""
Auto-generated SEO app pages.
Caches app metadata + icons on first download, serves templated pages.
"""

import html as htmlmod
import json
import os
import re
import logging
import threading
from pathlib import Path

import requests
import cloudscraper

logger = logging.getLogger(__name__)

APP_CACHE_DIR = Path(__file__).parent / 'public' / 'app'
ICONS_DIR = Path(__file__).parent / 'public' / 'icons'
META_FILE = APP_CACHE_DIR / '_meta.json'
TEMPLATE_FILE = APP_CACHE_DIR / '_template.html'

# Ensure dirs exist
APP_CACHE_DIR.mkdir(exist_ok=True)
ICONS_DIR.mkdir(exist_ok=True)

_meta_lock = threading.Lock()


def _load_meta():
    try:
        return json.loads(META_FILE.read_text())
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError:
        logger.exception("Failed to parse metadata cache %s", META_FILE)
        raise


def _save_meta(meta):
    tmp = META_FILE.with_suffix('.tmp')
    tmp.write_text(json.dumps(meta, indent=2))
    tmp.replace(META_FILE)


def get_app_meta(pkg):
    with _meta_lock:
        meta = _load_meta()
    return meta.get(pkg)


def cache_app(pkg, title, icon_url=None, description=''):
    """Cache app metadata and icon. Called after successful download."""
    with _meta_lock:
        meta = _load_meta()
        if pkg in meta and meta[pkg].get('title') and meta[pkg].get('description'):
            return  # already cached

    entry = {'title': title, 'package': pkg, 'description': description}

    # Download and cache icon outside the lock to avoid blocking reads
    if icon_url:
        try:
            icon_resp = requests.get(icon_url, timeout=10, stream=True)
            if icon_resp.status_code == 200:
                # Limit icon size to 1MB
                chunks = []
                size = 0
                for chunk in icon_resp.iter_content(8192):
                    size += len(chunk)
                    if size > 1_000_000:
                        break
                    chunks.append(chunk)
                if size <= 1_000_000:
                    ct = icon_resp.headers.get('content-type', '')
                    ext = 'webp' if 'webp' in ct else 'png' if 'png' in ct else 'jpg'
                    icon_path = ICONS_DIR / f'{pkg}.{ext}'
                    icon_path.write_bytes(b''.join(chunks))
                    entry['icon'] = f'/icons/{pkg}.{ext}'
        except Exception as e:
            logger.warning(f"Failed to cache icon for {pkg}: {e}")

    if 'icon' not in entry:
        entry['icon'] = ''

    with _meta_lock:
        meta = _load_meta()
        existing = meta.get(pkg, {})
        if existing.get('title') and existing.get('description'):
            return
        meta[pkg] = {**existing, **{k: v for k, v in entry.items() if v}}
        _save_meta(meta)
    logger.info(f"Cached app page data for {pkg}: {title}")


def enrich_from_play(pkg):
    """Fetch title, description, and icon URL from Play Store. Run in background."""
    result = {'icon_url': None, 'title': None, 'description': ''}
    scraper = cloudscraper.create_scraper()

    # Get details page for title + description
    try:
        resp = scraper.get(f'https://play.google.com/store/apps/details?id={pkg}&hl=en', timeout=15)
        if resp.status_code == 200:
            text = resp.text
            title_match = re.search(r'itemprop="name"[^>]*>([^<]+)<', text)
            if title_match:
                result['title'] = htmlmod.unescape(title_match.group(1).strip())
            # Real description from the description div
            desc_div = re.search(r'data-g-id="description"[^>]*>(.*?)</div>', text, re.DOTALL)
            if desc_div:
                desc_html = desc_div.group(1)
                # Convert <br> to newlines, then strip remaining tags
                desc_html = re.sub(r'<br\s*/?>', '\n', desc_html)
                clean = re.sub(r'<[^>]+>', '', desc_html).strip()
                result['description'] = htmlmod.unescape(clean)[:800]
    except Exception as e:
        logger.warning(f"Failed to get details for {pkg}: {e}")

    # Get icon from search
    try:
        resp = scraper.get(f'https://play.google.com/store/search?q={pkg}&c=apps', timeout=15)
        html = resp.text

        icon_pattern = rf'\[\["{re.escape(pkg)}",7\],\[null,2,(?:null|\[[0-9]+,[0-9]+\]),\[null,null,"(https://play-lh\.googleusercontent\.com/[^"]+)"\]'
        icon_match = re.search(icon_pattern, html)
        if icon_match:
            icon_url = icon_match.group(1).replace('\\u003d', '=').replace('\\u0026', '&')
            result['icon_url'] = re.sub(r'=s\d+', '=s256', icon_url)
        else:
            img_pattern = rf'id={re.escape(pkg)}.*?<img[^>]*src="(https://play-lh\.googleusercontent\.com/[^"]+)"'
            img_match = re.search(img_pattern, html, re.DOTALL)
            if img_match:
                result['icon_url'] = re.sub(r'=s\d+', '=s256', img_match.group(1))
    except Exception as e:
        logger.warning(f"Failed to get icon for {pkg}: {e}")

    return result


def render_app_page(pkg):
    """Render an app page from template + cached metadata."""
    meta = get_app_meta(pkg)
    if not meta:
        return None

    try:
        template = TEMPLATE_FILE.read_text()
    except FileNotFoundError:
        return None

    title = htmlmod.escape(meta.get('title', pkg))
    icon = htmlmod.escape(meta.get('icon', ''))
    pkg_escaped = htmlmod.escape(pkg)
    description = meta.get('description', '')
    # Escape then restore line breaks as <br>
    desc_safe = htmlmod.escape(description).replace('\n', '<br>')

    html = template.replace('__PKG__', pkg_escaped)
    html = html.replace('__TITLE__', title)
    html = html.replace('__ICON__', icon)
    html = html.replace('__DESCRIPTION__', desc_safe)
    html = html.replace('__DESCRIPTION_DISPLAY__', '' if description else 'display:none')
    return html


BROWSE_TEMPLATE_FILE = APP_CACHE_DIR / '_browse.html'

# Simple category guessing from package name
CATEGORY_MAP = {
    'game': 'Games', 'games': 'Games', 'play': 'Games',
    'camera': 'Photography', 'photo': 'Photography',
    'music': 'Music & Audio', 'audio': 'Music & Audio', 'radio': 'Music & Audio',
    'video': 'Video Players', 'tv': 'Video Players', 'player': 'Video Players', 'stream': 'Video Players', 'iptv': 'Video Players',
    'browser': 'Tools', 'launcher': 'Tools', 'keyboard': 'Tools', 'calculator': 'Tools', 'clock': 'Tools', 'file': 'Tools',
    'chat': 'Communication', 'messenger': 'Communication', 'whatsapp': 'Communication', 'telegram': 'Communication',
    'mail': 'Communication', 'sms': 'Communication',
    'map': 'Travel & Navigation', 'weather': 'Weather', 'fitness': 'Health & Fitness',
    'shop': 'Shopping', 'store': 'Shopping', 'pay': 'Finance', 'bank': 'Finance',
    'youtube': 'Video Players', 'netflix': 'Video Players', 'chrome': 'Tools',
}


def _guess_category(pkg, title):
    text = (pkg + ' ' + title).lower()
    for keyword, cat in CATEGORY_MAP.items():
        if keyword in text:
            return cat
    return 'Other'


def render_browse_page():
    """Render the app catalog/browse page."""
    with _meta_lock:
        meta = _load_meta()
    try:
        template = BROWSE_TEMPLATE_FILE.read_text()
    except FileNotFoundError:
        return '<html><body>Browse template not found</body></html>'

    # Group apps by category
    categories = {}
    for pkg, data in sorted(meta.items(), key=lambda x: x[1].get('title', '')):
        cat = _guess_category(pkg, data.get('title', ''))
        categories.setdefault(cat, []).append(data)

    # Build HTML
    app_count = len(meta)
    cards_html = ''
    for cat in sorted(categories.keys()):
        apps = categories[cat]
        cards_html += f'<div class="browse-category"><h2 class="browse-category-title">{cat}</h2><div class="browse-grid">'
        for app in apps:
            pkg = htmlmod.escape(app.get('package', ''))
            title = htmlmod.escape(app.get('title', pkg))
            icon = htmlmod.escape(app.get('icon', ''))
            icon_html = f'<img class="browse-icon" src="{icon}" alt="" loading="lazy" onerror="this.style.display=\'none\'">' if icon else '<div class="browse-icon-placeholder"></div>'
            cards_html += (
                f'<a class="browse-card" href="/app/{pkg}">'
                f'{icon_html}'
                f'<div class="browse-card-info">'
                f'<div class="browse-card-title">{title}</div>'
                f'<div class="browse-card-pkg">{pkg}</div>'
                f'</div></a>'
            )
        cards_html += '</div></div>'

    html = template.replace('__APP_COUNT__', str(app_count))
    html = html.replace('__CARDS__', cards_html)
    return html


def on_download_success(pkg, title, icon_url=None):
    """Hook called after a successful download. Caches metadata in background."""
    cached = get_app_meta(pkg)
    if cached and cached.get('title') and cached.get('description'):
        return

    def _bg():
        try:
            info = enrich_from_play(pkg)
            real_title = info.get('title') or title
            cache_app(pkg, real_title, info.get('icon_url') or icon_url, info.get('description', ''))
        except Exception as e:
            logger.error(f"Background enrichment failed for {pkg}: {e}")

    t = threading.Thread(target=_bg, daemon=True)
    t.start()
