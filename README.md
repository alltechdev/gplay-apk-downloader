# GPlay APK Downloader

Download APKs from Google Play Store. Automatically merges split APKs (App Bundles) into single installable APKs.

## Features

- Download any free app from Google Play
- Automatic split APK merging using [APKEditor](https://github.com/REAndroid/APKEditor)
- 23 device profiles with automatic rotation for reliable downloads
- Architecture support: ARM64 (modern phones) and ARMv7 (older phones)
- Modern dark web UI with real-time download progress and streaming activity log
- WebUSB ADB support — install APKs directly to a connected Android device from the browser (Chrome/Edge)
- Split APK direct install via ADB sessions — no merging needed, original signatures preserved
- Persistent download counter displayed in the UI
- ADB install from CLI — download and install directly to device via `adb`
- Backup & restore — export installed app list from device, batch restore later
- CLI tool with JSON output for scripting and automation
- Apps without splits preserve original signature
- Merged APKs are signed with debug keystore

---

## Installation

### Prerequisites

- Python 3.8+
- Java 17+ (for APKEditor)
- apksigner (for APK signing)

### Quick Install

```bash
git clone <repo-url> gplay-apk-downloader
cd gplay-apk-downloader
./setup.sh
```

### Manual Dependencies (Ubuntu/Debian)

```bash
sudo apt-get update
sudo apt-get install -y openjdk-17-jre-headless apksigner python3 python3-venv python3-pip curl
```

The setup script will:
1. Check for required system dependencies
2. Create Python virtual environment (`.venv/`)
3. Install Python packages from `requirements.txt`
4. Download APKEditor.jar
5. Create debug keystore for signing (`~/.android/debug.keystore`)
6. Generate wrapper scripts (`gplay`, `start-server.sh`)

---

## Web Interface

### Starting the Server

```bash
./start-server.sh             # Production mode (gunicorn + gevent)
./start-server.sh dev         # Development mode (Flask debug server)
PORT=8080 ./start-server.sh   # Use a custom port
```

If port 5000 is already in use, the script will prompt for an alternate port interactively. In non-interactive mode (e.g., systemd, cron), set the `PORT` env var instead.

**Production mode** (default):
- Gunicorn with gevent async workers (capped at 8 workers)
- Handles concurrent users with connection pooling
- Disk-based temp storage (2GB limit, 10min TTL)
- Configurable CORS and log level via environment variables
- Runs in background via `nohup`

**Development mode** (`dev`):
- Single-threaded Flask server with debug output
- Auto-reload on code changes
- Runs in foreground

Features:
- **Logging**: Outputs to `server.log` (rotated after 12 hours, old logs kept 7 days)
- **Health check**: `GET /health` for monitoring
- **Concurrency limits**: Max 10 concurrent downloads, 3 concurrent merges

### Using the Web UI

Open http://localhost:5000 in your browser.

1. **Enter package name** (e.g., `com.google.android.youtube`) or use the search box
2. **Select architecture**:
   - ARM64 - Modern phones (2016+)
   - ARMv7 - Older phones
3. **Choose merge option**:
   - Checked: Single installable APK (re-signed with debug key)
   - Unchecked: ZIP with base + split APKs (original signatures)
4. **Click Download** - real-time progress shows token attempts, download, merge, and signing steps
5. **Activity Log** - collapsible terminal-style panel streams all operations in real time (auto-opens on download)
6. **Install to Device** (optional) - connect an Android device via USB to install APKs directly from the browser

> **Signature Warning**: Merged APKs are re-signed with a debug key and will NOT receive automatic updates from Google Play. Apps without splits keep their original signature.

### WebUSB ADB (Chrome/Edge only)

Connect an Android device via USB to install APKs directly without downloading to your computer first.

**Requirements:**
- Chrome or Edge browser (WebUSB is not supported in Firefox/Safari)
- HTTPS or localhost
- USB debugging enabled on the Android device (Settings → Developer Options → USB Debugging)

**How it works:**
1. Plug in your Android device via USB
2. Click **Connect Device** in the web UI
3. Select your device in the browser's USB picker and tap **Allow** on the phone
4. After fetching download info, click **Install to Device**

For apps with split APKs, the tool uses Android's session-based install (`pm install-create`/`pm install-write`/`pm install-commit`) to install all splits directly — no merging needed, original signatures preserved. The merge checkbox is automatically disabled when a device is connected.

### View Logs / Stop Server

```bash
tail -f server.log              # View logs
kill $(lsof -ti:5000)           # Stop server
```

---

## Command Line Interface (CLI)

### First-Time Setup

Authenticate to get an anonymous token:

```bash
./gplay auth
./gplay auth -d https://custom-dispenser.example.com  # Use custom dispenser
```

Token is saved to `~/.gplay-auth.json` and shared between CLI and web server.

### Commands

#### Search for Apps

```bash
./gplay search "youtube"
./gplay search "file manager" -l 20    # Show up to 20 results
./gplay search "spotify" --json        # JSON output for scripting
```

#### Get App Info

```bash
./gplay info com.google.android.youtube
./gplay info com.whatsapp --json
```

#### Check App Version (without downloading)

```bash
./gplay check-version com.whatsapp
./gplay check-version com.whatsapp --json
```

Uses protobuf API with HTML fallback to get the version string and version code.

#### List Available Splits

```bash
./gplay list-splits com.whatsapp
./gplay list-splits com.whatsapp --json
```

Shows all available split APKs including language splits.

#### Download APK

```bash
# Basic download (ARM64 is default)
./gplay download com.google.android.youtube

# Download for ARM64 (modern phones)
./gplay download com.google.android.youtube -a arm64

# Download for ARMv7 (older phones)
./gplay download com.google.android.youtube -a armv7

# Download and merge splits into single APK
./gplay download com.google.android.youtube -m

# Merge for ARMv7
./gplay download com.google.android.youtube -m -a armv7

# Download for both architectures at once
./gplay download com.google.android.youtube --both-arch

# Download all language splits (en, he, fr)
./gplay download com.google.android.youtube --all-locales

# Download and install to connected device via ADB
./gplay download com.google.android.youtube -i

# Download, merge, and install
./gplay download com.google.android.youtube -m -i

# Custom output directory
./gplay download com.google.android.youtube -m -o ~/apks/

# Download specific version code
./gplay download com.google.android.youtube -v 1234567
```

> **ADB Install**: The `-i` flag installs directly to a connected device. For split APKs without `-m`, it uses `adb install-multiple` (session install, preserves original signatures). With `-m`, it installs the merged APK.

### CLI Options Reference

#### Global

| Option | Description |
|--------|-------------|
| `--json` | Output results as JSON (for scripting) |

#### `auth`

| Option | Description |
|--------|-------------|
| `-d`, `--dispenser` | Custom dispenser URL |

#### `search`

| Option | Default | Description |
|--------|---------|-------------|
| `query` | (required) | Search query |
| `-l`, `--limit` | 10 | Max results |
| `--json` | | JSON output |

#### `info`, `check-version`, `list-splits`

| Option | Description |
|--------|-------------|
| `package` | Package name (required) |
| `--json` | JSON output |

#### `download`

| Option | Default | Description |
|--------|---------|-------------|
| `package` | (required) | Package name |
| `-a`, `--arch` | `arm64` | Architecture: `arm64` or `armv7` |
| `-m`, `--merge` | off | Merge split APKs into single installable APK |
| `-o`, `--output` | `.` | Output directory |
| `-v`, `--version` | latest | Download specific version code |
| `-i`, `--install` | off | Install to connected ADB device after download |
| `--both-arch` | | Download for both ARM64 and ARMv7 |
| `--all-locales` | | Download all language splits (en, he, fr) |

### Scripting Examples

```bash
# Get version as JSON and parse with jq
./gplay check-version com.whatsapp --json | jq '.version'

# Search and get package names
./gplay search "banking" --json | jq -r '.results[].package'

# Download multiple apps
for pkg in com.whatsapp com.spotify.music; do
  ./gplay download "$pkg" -m
done
```

#### Backup App List

Back up the list of user-installed apps from a connected ADB device. Checks each package against Google Play for availability.

```bash
./gplay backup                            # Save to app-backup-DATE.json
./gplay backup -o my-apps.json            # Custom output file
./gplay backup -o -                       # Print to stdout
```

#### Restore Apps

Restore apps from a backup JSON file. Downloads each available package.

```bash
# Download all apps from backup
./gplay restore my-apps.json

# Download and install directly to device
./gplay restore my-apps.json -i

# Restore merged APKs for ARMv7
./gplay restore my-apps.json -m -a armv7

# Restore to specific directory
./gplay restore my-apps.json -o ~/apks/
```

#### `backup`

| Option | Default | Description |
|--------|---------|-------------|
| `-o`, `--output` | `app-backup-DATE.json` | Output file (`-` for stdout) |

#### `restore`

| Option | Default | Description |
|--------|---------|-------------|
| `file` | (required) | Backup JSON file |
| `-o`, `--output` | `.` | Output directory for downloaded APKs |
| `-a`, `--arch` | `arm64` | Architecture: `arm64` or `armv7` |
| `-m`, `--merge` | off | Merge split APKs into single APK |
| `-i`, `--install` | off | Install each app to connected ADB device |

### Web UI Backup & Restore

The web UI also supports backup and restore when an ADB device is connected:

1. **Backup**: Click **Backup App List** to read installed packages from the device and check Play Store availability
2. **Export**: Save the list as a JSON file for later use
3. **Import**: Load a previously exported backup JSON
4. **Restore**: Install selected apps back to the device, or download them if no device is connected

---

## API Endpoints

The web server exposes these REST and SSE endpoints:

### Core

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Web UI |
| `/health` | GET | Health check (system status, disk usage, worker info) |
| `/api/stats` | GET | Download counter (total APKs downloaded) |
| `/api/stats/increment` | POST | Increment download counter (rate-limited, for client-side installs) |

### Authentication

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/auth` | POST | Get/validate cached auth token |
| `/api/auth/stream` | GET | SSE: acquire token with profile rotation |
| `/api/auth/status` | GET | Check if authenticated |

### Search & Info

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/search?q=<query>` | GET | Search apps (cached 6 hours) |
| `/api/info/<package>` | GET | Get app details |

### Downloads

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/download-info/<package>` | GET | Get download URLs (requires auth header) |
| `/api/download-info-stream/<package>` | GET | SSE: get download info with auto token rotation |
| `/api/download-merged-stream/<package>` | GET | SSE: download + merge + sign with progress |
| `/api/download-merged/<package>` | GET | Non-streaming fallback for download + merge |
| `/api/download-temp/<id>` | GET | Download temporary merged APK (auto-cleanup) |
| `/download/<package>` | GET | Proxy download for base APK |
| `/download/<package>/<split_index>` | GET | Proxy download for specific split |

### Query Parameters

| Parameter | Values | Default | Used By |
|-----------|--------|---------|---------|
| `arch` | `arm64-v8a`, `armeabi-v7a` | `arm64-v8a` | download-info-stream, download-merged-stream |
| `q` | search string | (required) | search |

### Example API Usage

```bash
# Search
curl "http://localhost:5000/api/search?q=youtube"

# Get info
curl "http://localhost:5000/api/info/com.google.android.youtube"

# Download merged APK for ARM64 (streams progress via SSE)
curl "http://localhost:5000/api/download-merged-stream/com.google.android.youtube?arch=arm64-v8a"

# Download merged APK for ARMv7
curl "http://localhost:5000/api/download-merged-stream/com.google.android.youtube?arch=armeabi-v7a"

# Health check
curl "http://localhost:5000/health"
```

---

## Running as a Service

### systemd (Linux)

```bash
sudo tee /etc/systemd/system/gplay.service << EOF
[Unit]
Description=GPlay APK Downloader
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$(pwd)
Environment=CORS_ORIGINS=https://yourdomain.com
ExecStart=$(pwd)/.venv/bin/gunicorn --bind 0.0.0.0:5000 --workers 2 server:app
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable gplay
sudo systemctl start gplay
```

### Service Commands

```bash
sudo systemctl status gplay      # Check status
sudo systemctl restart gplay     # Restart
sudo systemctl stop gplay        # Stop
journalctl -u gplay -f           # View logs
```

---

## Device Profiles

The tool includes 23 device profiles from Aurora Store, used to authenticate with Google Play's anonymous token dispenser. Profiles are rotated automatically during token acquisition to maximize compatibility with restricted apps (e.g., banking apps like Chase).

### How It Works

- Profiles are stored in `profiles/*.properties` and loaded by `device_profiles.py`
- Each profile represents a real Android device (Pixel 9a, Galaxy S25 Ultra, Xperia 5, etc.)
- Profiles are sorted by reliability — the most reliable ones are tried first
- The server cycles through all profiles up to 3 times before giving up
- A built-in fallback profile (Pixel 4a) is used if the `profiles/` directory is missing

### Priority Order

**ARM64** (19 profiles): Pixel 9a, Samsung F34, Xperia 5, Oppo R17, and others
**ARMv7** (4 profiles): Samsung J5 Prime, Samsung A13 5G, Realme 5 Pro, BRAVIA VU2

### Testing Profiles

```bash
python3 test_profiles.py    # Test all profiles against restricted apps
```

### Listing Profiles

```bash
python3 device_profiles.py  # Print all available profiles
```

---

## How It Works

1. **Authentication**: Gets anonymous token from Aurora Store's dispenser, rotating through device profiles for reliability
2. **Details**: Fetches app metadata (version, size, splits) via Google Play's protobuf API
3. **Purchase**: "Purchases" the free app to get download authorization
4. **Download**: Fetches base APK + config splits from Google Play CDN
5. **Merge**: Combines splits using APKEditor (proper resource table merging)
6. **Sign**: Signs merged APK with debug keystore via apksigner
7. **Deliver**: Returns single installable APK

### Split APKs Explained

Modern Android apps use App Bundles which split into:
- **Base APK**: Core app code and resources
- **Config splits**: Device-specific resources (screen density, language, CPU architecture)

This tool merges them back into a universal APK that works on any device of the target architecture.

---

## File Structure

```
gplay-apk-downloader/
├── server.py            # Flask web server with SSE endpoints
├── gplay-downloader.py  # CLI tool
├── gplay                # CLI wrapper script (sources venv)
├── device_profiles.py   # Device profile loader and priority ordering
├── profiles/            # 23 Aurora Store device profiles (.properties)
├── test_profiles.py     # Profile testing utility
├── index.html           # Web UI
├── gunicorn.conf.py     # Gunicorn production config
├── start-server.sh      # Server startup script (dev/production)
├── setup.sh             # Installation script
├── requirements.txt     # Python dependencies
├── APKEditor.jar        # Split APK merger (downloaded by setup)
├── server.log           # Server logs (generated, auto-rotated)
└── .venv/               # Python virtual environment (generated)
```

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CORS_ORIGINS` | (same-origin only) | Comma-separated allowed origins (e.g., `https://yourdomain.com`). Unset = no cross-origin requests allowed |
| `LOG_LEVEL` | `INFO` | Logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |
| `PORT` | `5000` | Server port (used by `start-server.sh`) |

Set these in your systemd service file or shell environment.

### Server Limits (server.py)

| Setting | Value | Description |
|---------|-------|-------------|
| `MAX_CONCURRENT_DOWNLOADS` | 10 | Parallel download slots |
| `MAX_CONCURRENT_MERGES` | 3 | Parallel merge operations |
| `SSE_MAX_DURATION` | 300s (5 min) | Max time for any SSE stream |
| `MAX_PROFILE_CYCLES` | 3 | Max times to cycle through all profiles |
| `TEMP_APK_TTL` | 600s (10 min) | Temp file lifetime before cleanup |
| `MAX_TEMP_STORAGE_MB` | 2048 (2 GB) | Max disk space for temp APKs |
| `SEARCH_CACHE_TTL` | 21600s (6 hr) | Search result cache lifetime |
| `DOWNLOAD_QUEUE_TIMEOUT` | 30s | Wait time for a free download slot |

### Gunicorn Config (gunicorn.conf.py)

| Setting | Value | Description |
|---------|-------|-------------|
| `worker_class` | `gevent` | Async workers for SSE streaming |
| `workers` | min(CPU cores x 2 + 1, 8) | Automatic worker scaling (capped at 8) |
| `worker_connections` | 1000 | Max connections per worker |
| `timeout` | 300s | Request timeout |
| `keepalive` | 65s | Keep-alive for SSE connections |
| `bind` | `0.0.0.0:5000` | Default listen address |

### Auth Cache Files

| File | Description |
|------|-------------|
| `~/.gplay-auth.json` | ARM64 auth token cache |
| `~/.gplay-auth-armv7.json` | ARMv7 auth token cache |
| `~/.gplay-download-count` | Persistent download counter |

---

## Security

- **CORS**: Defaults to same-origin only (no cross-origin requests). Set `CORS_ORIGINS` to allow specific external domains
- **Input validation**: Package names are validated against Android naming rules; temp file IDs are validated as strict UUIDs
- **XSS protection**: All user-controlled data is escaped before DOM insertion, including single quotes in JS contexts
- **Auth tokens**: Server-side only — auth tokens are never sent to the frontend
- **Filename sanitization**: All Content-Disposition headers are sanitized against path traversal and header injection
- **Download counter**: Uses file-level locking for safe concurrent access across gunicorn workers
- **Logging**: Production defaults to `INFO` level — no auth tokens logged. Set `LOG_LEVEL=DEBUG` only for development
- **No authentication**: API endpoints are open by default. Use a reverse proxy (nginx) to add auth if needed
- **HTTPS**: Not built-in — deploy behind a reverse proxy with TLS termination

---

## Troubleshooting

### "Auth file not found"
Run `./gplay auth` first to get an authentication token.

### "APKEditor.jar not found"
Re-run `./setup.sh` to download APKEditor.

### Server won't start
Check if port 5000 is in use:
```bash
lsof -i:5000
kill $(lsof -ti:5000)  # Kill existing process
```
Or use a different port: `PORT=8080 ./start-server.sh`

### DNS errors on VPS
Some VPS providers block Google CDN. Try:
```bash
echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf
```

### Download fails repeatedly
The tool automatically rotates through device profiles when acquiring tokens. Some apps (especially banking apps) only work with specific profiles. If all profiles fail after 3 cycles, try again later — the dispenser may be rate-limited (HTTP 429).

### App returns versionCode=0
The token's device profile isn't compatible with this app. The server will automatically try the next profile in the rotation.

---

## License

MIT
