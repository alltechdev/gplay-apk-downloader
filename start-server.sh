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
