#!/usr/bin/env bash
# web_extension/scripts/install.sh
# Sets up the full test toolchain for the browser-extension port.
# Idempotent: safe to run repeatedly.
#
# Stages:
#   1. Confirm system tools (node, npm, python3, chromium-browser, chromedriver)
#   2. Create Python venv at web_extension/.venv (for parity tests vs. existing CLI)
#   3. Install Python deps into the venv
#   4. Install Node deps via npm (puppeteer-core, web-ext, protobufjs, ...)
#   5. Sanity-launch Chromium headless to confirm the E2E stage will work

set -euo pipefail

EXT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_DIR="$(cd "$EXT_DIR/.." && pwd)"
VENV_DIR="$EXT_DIR/.venv"
LOG_DIR="$EXT_DIR/tests/logs"

mkdir -p "$LOG_DIR"
LOG="$LOG_DIR/install-$(date -u +%Y%m%dT%H%M%SZ).log"
exec > >(tee -a "$LOG") 2>&1

echo "== web_extension install =="
echo "ext_dir : $EXT_DIR"
echo "venv    : $VENV_DIR"
echo "log     : $LOG"
echo

# --- Stage 1: tool probe ---
echo "[1/5] probing system tools"
need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "  MISSING: $1"
    return 1
  fi
  printf "  ok: %-20s %s\n" "$1" "$($1 --version 2>&1 | head -1)"
}
need node
need npm
need python3
need chromium-browser
need chromedriver || echo "  (chromedriver optional — only needed for selenium-backed tests)"
echo

# --- Stage 2: Python venv ---
echo "[2/5] python venv"
if [[ ! -d "$VENV_DIR" ]]; then
  python3 -m venv "$VENV_DIR"
  echo "  created $VENV_DIR"
else
  echo "  exists $VENV_DIR"
fi
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"
python -m pip install --upgrade pip wheel >/dev/null
echo "  python: $(python --version)"
echo "  pip   : $(pip --version)"
echo

# --- Stage 3: Python deps ---
echo "[3/5] python deps"
REQ="$EXT_DIR/scripts/requirements.txt"
if [[ -f "$REQ" ]]; then
  pip install -r "$REQ"
else
  echo "  (no $REQ yet — skipping)"
fi
# Parent CLI deps are installed lazily by tests/parity/setup.sh into a
# separate venv (.venv-legacy) to avoid protobuf version conflicts.
# See web_extension/tests/parity/README.md for details.
echo

# --- Stage 4: Node deps ---
echo "[4/5] node deps"
cd "$EXT_DIR"
if [[ ! -f package.json ]]; then
  echo "  ERROR: $EXT_DIR/package.json is missing — cannot install node deps."
  exit 1
fi
# Tell puppeteer-core not to download a bundled browser; we use system chromium.
export PUPPETEER_SKIP_DOWNLOAD=1
export PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=1
npm install --no-audit --no-fund
echo

# --- Stage 5: sanity launch ---
echo "[5/5] sanity-launch chromium headless"
CHROMIUM_BIN="$(command -v chromium-browser)"
echo "  binary: $CHROMIUM_BIN"
TMP_OUT="$(mktemp)"
if "$CHROMIUM_BIN" --headless=new --no-sandbox --disable-gpu --disable-dev-shm-usage \
    --dump-dom about:blank > "$TMP_OUT" 2>/dev/null; then
  if grep -q '<html' "$TMP_OUT"; then
    echo "  ok: chromium rendered about:blank"
  else
    echo "  WARN: chromium ran but produced no html"
    head -20 "$TMP_OUT"
  fi
else
  echo "  ERROR: chromium failed to launch"
  exit 1
fi
rm -f "$TMP_OUT"

echo
echo "== install complete =="
echo "Activate venv with: source $VENV_DIR/bin/activate"
echo "Run tests with:     (cd $EXT_DIR && npm test)"
