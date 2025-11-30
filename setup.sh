#!/bin/bash
# Setup script for gplay-downloader

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"

echo "Setting up gplay-downloader..."

# Create virtual environment
if [ ! -d "$VENV_DIR" ]; then
    echo "Creating virtual environment..."
    python3 -m venv "$VENV_DIR"
fi

# Activate and install dependencies
echo "Installing dependencies..."
source "$VENV_DIR/bin/activate"
pip install --upgrade pip
pip install -r "$SCRIPT_DIR/requirements.txt"

# Create wrapper script
cat > "$SCRIPT_DIR/gplay" << 'EOF'
#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/.venv/bin/activate"
python3 "$SCRIPT_DIR/gplay-downloader.py" "$@"
EOF

chmod +x "$SCRIPT_DIR/gplay"

echo ""
echo "Setup complete!"
echo ""
echo "Usage:"
echo "  $SCRIPT_DIR/gplay auth              # Authenticate (anonymous)"
echo "  $SCRIPT_DIR/gplay search 'app name' # Search for apps"
echo "  $SCRIPT_DIR/gplay info com.package  # Get app info"
echo "  $SCRIPT_DIR/gplay download com.pkg  # Download APK"
echo ""
echo "Or add to your PATH:"
echo "  export PATH=\"\$PATH:$SCRIPT_DIR\""
