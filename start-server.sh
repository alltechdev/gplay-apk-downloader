#!/bin/bash
# Start the GPlay APK Downloader server
# Usage: ./start-server.sh [dev|production]
# Default: production

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODE="${1:-production}"
DEFAULT_PORT=5000
PORT="${PORT:-$DEFAULT_PORT}"

# Prompt for a different port if the default is busy
check_port() {
    lsof -ti:"$1" >/dev/null 2>&1
}

if check_port "$PORT"; then
    echo "Port $PORT is already in use."
    # Only prompt interactively if stdin is a terminal
    if [ -t 0 ]; then
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
    else
        echo "Non-interactive mode: set PORT env variable to use a different port."
        exit 1
    fi
fi

source "$SCRIPT_DIR/.venv/bin/activate"
cd "$SCRIPT_DIR"

# Log rotation - delete if older than 12 hours
if [ -f server.log ]; then
    if [ $(find server.log -mmin +720 2>/dev/null | wc -l) -gt 0 ]; then
        echo "Rotating old log file..."
        mv server.log "server.log.$(date +%Y%m%d_%H%M%S)"
        # Keep only last 7 days of logs
        find . -name 'server.log.*' -mtime +7 -delete 2>/dev/null
    fi
fi

if [ "$MODE" = "dev" ]; then
    echo "Starting in DEVELOPMENT mode (single-threaded, debug=True)..."
    PORT="$PORT" FLASK_DEBUG=true python3 server.py 2>&1 | tee server.log
else
    echo "Starting in PRODUCTION mode with gunicorn..."
    nohup gunicorn --bind "0.0.0.0:$PORT" -c gunicorn.conf.py server:app >> server.log 2>&1 &
    disown
    sleep 2
    NEW_PID=$(lsof -ti:"$PORT" 2>/dev/null)
    if [ -n "$NEW_PID" ]; then
        echo "Server started (PID: $NEW_PID) on port $PORT"
        echo "Logs: tail -f $SCRIPT_DIR/server.log"
    else
        echo "ERROR: Server failed to start. Check server.log for details."
        tail -20 server.log
        exit 1
    fi
fi
