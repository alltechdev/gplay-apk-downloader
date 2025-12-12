# GPlay APK Downloader

Download APKs from Google Play Store. Automatically merges split APKs (App Bundles) into single installable APKs.

## Features

- Download any free app from Google Play
- Automatic split APK merging using [APKEditor](https://github.com/REAndroid/APKEditor)
- Architecture support: ARM64 (modern phones) and ARMv7 (older phones)
- Web UI with real-time download progress
- CLI tool for scripting and automation
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
git clone <repo-url> gplay-downloader
cd gplay-downloader
./setup.sh
```

### Manual Dependencies (Ubuntu/Debian)

```bash
sudo apt-get update
sudo apt-get install -y openjdk-17-jre-headless apksigner python3 python3-venv python3-pip curl
```

The setup script will:
1. Check for required dependencies
2. Create Python virtual environment
3. Install Python packages
4. Download APKEditor.jar
5. Create debug keystore for signing
6. Generate wrapper scripts

---

## Web Interface

### Starting the Server

```bash
./start-server.sh           # Production mode (gunicorn + gevent)
./start-server.sh dev       # Development mode (Flask debug server)
```

The server runs in the background on port 5000. Open http://localhost:5000 in your browser.

**Production mode** (default):
- Gunicorn with gevent async workers (CPU cores × 2 + 1)
- Handles 100+ concurrent users
- Disk-based temp storage (2GB limit, 10min TTL)
- Connection pooling and rate limiting

**Development mode**:
- Single-threaded Flask server with debug output
- Auto-reload on code changes

Features:
- **Kill existing**: Automatically kills any existing server on port 5000
- **Background**: Runs detached from terminal (survives terminal close)
- **Logging**: Outputs to `server.log` (auto-rotated after 12 hours)
- **Health check**: GET `/health` for monitoring

### Using the Web UI

1. **Enter package name** (e.g., `com.google.android.youtube`)
2. **Select architecture**:
   - ARM64 - Modern phones (2016+)
   - ARMv7 - Older phones
3. **Choose merge option**:
   - Checked: Single installable APK (re-signed)
   - Unchecked: ZIP with base + split APKs
4. **Click Download**

### Important Notes

> **Signature Warning**: Merged APKs are re-signed with a debug key and will NOT receive automatic updates from Google Play. Apps without splits keep their original signature.

### View Logs

```bash
tail -f server.log
```

### Stop Server

```bash
kill $(lsof -ti:5000)
```

---

## Command Line Interface (CLI)

### First-Time Setup

Authenticate to get an anonymous token:

```bash
./gplay auth
```

Token is saved to `~/.gplay-auth.json` and shared between CLI and web server.

### Commands

#### Search for Apps

```bash
./gplay search "youtube"
./gplay search "file manager" -l 20    # Show 20 results
```

#### Get App Info

```bash
./gplay info com.google.android.youtube
```

#### Download APK

```bash
# Basic download (ARM64 is default)
./gplay download com.google.android.youtube

# Explicit ARM64 (modern phones)
./gplay download com.google.android.youtube -a arm64

# ARMv7 (older phones)
./gplay download com.google.android.youtube -a armv7

# Download and merge splits into single APK
./gplay download com.google.android.youtube -m

# ARM64 merged
./gplay download com.google.android.youtube -m -a arm64

# ARMv7 merged
./gplay download com.google.android.youtube -m -a armv7

# Full example: merge, armv7, custom output dir
./gplay download com.google.android.youtube -m -a armv7 -o ~/apks/
```

### CLI Options

| Option | Description |
|--------|-------------|
| `-a`, `--arch` | Architecture: `arm64` (default) or `armv7` |
| `-m`, `--merge` | Merge split APKs into single installable APK |
| `-o`, `--output` | Output directory (default: current directory) |
| `-v`, `--version` | Download specific version code |

### Examples

```bash
# Download YouTube, merge splits, ARM64 (default)
./gplay download com.google.android.youtube -m

# Download YouTube, merge splits, explicit ARM64
./gplay download com.google.android.youtube -m -a arm64

# Download Instagram for older phone (ARMv7)
./gplay download com.instagram.android -m -a armv7

# Download to specific folder
./gplay download com.whatsapp -m -o ~/Downloads/

# Download without merge (keeps splits separate)
./gplay download com.google.android.youtube -a arm64

# Search and download
./gplay search "spotify"
./gplay download com.spotify.music -m -a arm64
```

---

## API Endpoints

The web server exposes these REST endpoints:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Web UI |
| `/health` | GET | Health check (returns system status) |
| `/api/search?q=<query>` | GET | Search apps |
| `/api/info/<package>` | GET | Get app details |
| `/api/download-info-stream/<package>` | GET | SSE stream for download info |
| `/api/download-merged-stream/<package>` | GET | SSE stream for merged download |
| `/api/download-temp/<id>` | GET | Download temporary merged APK |

### Query Parameters

- `arch`: Architecture (`arm64-v8a` or `armeabi-v7a`)

### Example API Usage

```bash
# Search
curl "http://localhost:5000/api/search?q=youtube"

# Get info
curl "http://localhost:5000/api/info/com.google.android.youtube"

# Download merged APK (streams progress via SSE)
curl "http://localhost:5000/api/download-merged-stream/com.google.android.youtube?arch=arm64-v8a"
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
ExecStart=$(pwd)/start-server.sh
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable gplay
sudo systemctl start gplay
```

### Service Commands

```bash
sudo systemctl status gplay    # Check status
sudo systemctl restart gplay   # Restart
sudo systemctl stop gplay      # Stop
journalctl -u gplay -f         # View logs
```

---

## How It Works

1. **Authentication**: Uses Aurora Store's anonymous token dispenser
2. **Download**: Fetches base APK + config splits from Google Play CDN
3. **Merge**: Combines splits using APKEditor (proper resource table merging)
4. **Sign**: Signs merged APK with debug keystore via apksigner
5. **Deliver**: Returns single installable APK

### Split APKs Explained

Modern Android apps use App Bundles which split into:
- **Base APK**: Core app code and resources
- **Config splits**: Device-specific resources (density, language, ABI)

This tool merges them back into a universal APK that works on any device.

---

## File Structure

```
gplay-downloader/
├── server.py           # Flask web server
├── gunicorn.conf.py    # Production server config
├── index.html          # Web UI
├── gplay-downloader.py # CLI tool
├── gplay               # CLI wrapper script
├── start-server.sh     # Server startup script
├── setup.sh            # Installation script
├── APKEditor.jar       # Split APK merger
├── requirements.txt    # Python dependencies
├── server.log          # Server logs (generated)
└── .venv/              # Python virtual environment (generated)
```

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

### DNS errors on VPS
Some VPS providers block Google CDN. Try:
```bash
# Use Google DNS
echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf
```

### Download fails repeatedly
Tokens from the dispenser have varying quality. The tool automatically retries with new tokens until success.

---

## License

MIT
