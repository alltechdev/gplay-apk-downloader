#!/bin/bash
# Setup script for gplay-downloader webapp
# Installs all dependencies and prepares the server

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"

echo "================================================"
echo "  GPlay APK Downloader - Server Setup"
echo "================================================"
echo ""

# Check system dependencies
echo "[1/6] Checking system dependencies..."

missing_deps=""

if ! command -v java &> /dev/null; then
    missing_deps="$missing_deps openjdk-17-jre-headless"
fi

if ! command -v apksigner &> /dev/null; then
    missing_deps="$missing_deps apksigner"
fi

if ! command -v python3 &> /dev/null; then
    missing_deps="$missing_deps python3 python3-venv python3-pip"
fi

if [ -n "$missing_deps" ]; then
    echo "Missing dependencies:$missing_deps"
    echo ""
    echo "Install with:"
    echo "  sudo apt-get update && sudo apt-get install -y$missing_deps"
    echo ""
    read -p "Install now? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        sudo apt-get update && sudo apt-get install -y $missing_deps
    else
        echo "Please install dependencies manually and re-run setup."
        exit 1
    fi
fi

echo "  - Java: $(java -version 2>&1 | head -1)"
echo "  - apksigner: $(which apksigner)"
echo "  - Python: $(python3 --version)"

# Create virtual environment
echo ""
echo "[2/6] Setting up Python virtual environment..."
if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv "$VENV_DIR"
    echo "  Created: $VENV_DIR"
else
    echo "  Already exists: $VENV_DIR"
fi

# Install Python dependencies
echo ""
echo "[3/6] Installing Python dependencies..."
source "$VENV_DIR/bin/activate"
pip install --upgrade pip -q
pip install -r "$SCRIPT_DIR/requirements.txt" -q
echo "  Installed: $(pip list --format=freeze | wc -l) packages"

# Download APKEditor if not present
echo ""
echo "[4/6] Setting up APKEditor..."
APKEDITOR_JAR="$SCRIPT_DIR/APKEditor.jar"
if [ ! -f "$APKEDITOR_JAR" ]; then
    echo "  Downloading APKEditor.jar..."
    curl -sL -o "$APKEDITOR_JAR" \
        "https://github.com/REAndroid/APKEditor/releases/download/V1.4.1/APKEditor-1.4.1.jar"
    echo "  Downloaded: $(ls -lh "$APKEDITOR_JAR" | awk '{print $5}')"
else
    echo "  Already exists: APKEditor.jar"
fi

# Create debug keystore for APK signing
echo ""
echo "[5/6] Setting up APK signing keystore..."
KEYSTORE_DIR="$HOME/.android"
KEYSTORE_FILE="$KEYSTORE_DIR/debug.keystore"
if [ ! -f "$KEYSTORE_FILE" ]; then
    mkdir -p "$KEYSTORE_DIR"
    keytool -genkey -v -keystore "$KEYSTORE_FILE" \
        -storepass android -alias androiddebugkey -keypass android \
        -keyalg RSA -keysize 2048 -validity 10000 \
        -dname "CN=Android Debug,O=Android,C=US" 2>/dev/null
    echo "  Created: $KEYSTORE_FILE"
else
    echo "  Already exists: $KEYSTORE_FILE"
fi

# Create wrapper scripts
echo ""
echo "[6/6] Creating wrapper scripts..."

# CLI wrapper
cat > "$SCRIPT_DIR/gplay" << 'EOF'
#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/.venv/bin/activate"
python3 "$SCRIPT_DIR/gplay-downloader.py" "$@"
EOF
chmod +x "$SCRIPT_DIR/gplay"

# Server wrapper
cat > "$SCRIPT_DIR/start-server.sh" << 'EOF'
#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_PORT=5000
PORT="${PORT:-$DEFAULT_PORT}"

# Prompt for a different port if the default is busy
check_port() {
    lsof -ti:"$1" >/dev/null 2>&1
}

if check_port "$PORT"; then
    echo "Port $PORT is already in use."
    while true; do
        read -p "Enter a port to start the server on (blank to cancel): " INPUT_PORT
        if [ -z "$INPUT_PORT" ]; then
            echo "Aborting start; no free port selected."
            exit 1
        fi
        if ! [[ "$INPUT_PORT" =~ ^[0-9]+$ ]]; then
            echo "Please enter a numeric port."
            continue
        fi
        PORT="$INPUT_PORT"
        if check_port "$PORT"; then
            echo "Port $PORT is also in use. Try another."
            continue
        fi
        break
    done
fi

source "$SCRIPT_DIR/.venv/bin/activate"
cd "$SCRIPT_DIR"

# Delete log if older than 12 hours
if [ -f server.log ]; then
    if [ $(find server.log -mmin +720 2>/dev/null | wc -l) -gt 0 ]; then
        echo "Rotating old log file..."
        rm -f server.log
    fi
fi

echo "Starting server in background on port $PORT..."
PORT="$PORT" nohup python3 server.py > server.log 2>&1 &
disown
echo "Server started (PID: $!)"
echo "Logs: tail -f $SCRIPT_DIR/server.log"
EOF
chmod +x "$SCRIPT_DIR/start-server.sh"

echo "  Created: gplay (CLI)"
echo "  Created: start-server.sh (Web server)"

echo ""
echo "================================================"
echo "  Setup Complete!"
echo "================================================"
echo ""
echo "Start the web server:"
echo "  cd $SCRIPT_DIR"
echo "  ./start-server.sh"
echo ""
echo "Then open: http://localhost:5000"
echo ""
echo "CLI usage:"
echo "  ./gplay auth              # Authenticate"
echo "  ./gplay search 'app'      # Search apps"
echo "  ./gplay download com.pkg  # Download APK"
echo ""
