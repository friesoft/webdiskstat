#!/bin/bash
set -e

# Setup default scan interval (24 hours = 86400 seconds)
INTERVAL=${SCAN_INTERVAL:-86400}

# Create nginx html dir if not exists
mkdir -p /usr/share/nginx/html

# Build GDU arguments
GDU_ARGS=("-o-")
if [ -n "$GDU_IGNORE_DIRS" ]; then
  echo "Setting GDU ignore directories: $GDU_IGNORE_DIRS"
  GDU_ARGS+=("-i" "$GDU_IGNORE_DIRS")
fi
if [ -n "$GDU_ADDITIONAL_ARGS" ]; then
  echo "Adding GDU additional arguments: $GDU_ADDITIONAL_ARGS"
  read -r -a additional_args <<< "$GDU_ADDITIONAL_ARGS"
  GDU_ARGS+=("${additional_args[@]}")
fi

# Function to run the periodic scan in the background
run_periodic_scans() {
  # Wait for Nginx to start
  sleep 3

  # Run initial scan if index.html doesn't exist or force scan is enabled
  if [ ! -f /usr/share/nginx/html/index.html ] || [ "${FORCE_INITIAL_SCAN:-false}" = "true" ]; then
    echo "[$(date)] Running initial disk scan on /scan..."
    if gdu "${GDU_ARGS[@]}" /scan | python3 /usr/local/bin/webdiskstat.py -o /usr/share/nginx/html/index.html; then
      echo "[$(date)] Initial scan completed successfully. HTML report generated."
    else
      echo "[$(date)] Error: Initial scan failed!"
    fi
  else
    echo "[$(date)] Existing index.html report found. Skipping initial scan."
  fi

  while true; do
    echo "[$(date)] Waiting for ${INTERVAL} seconds before next scan..."
    sleep "$INTERVAL"
    echo "[$(date)] Starting scheduled disk scan on /scan..."
    if gdu "${GDU_ARGS[@]}" /scan | python3 /usr/local/bin/webdiskstat.py -o /usr/share/nginx/html/index.html; then
      echo "[$(date)] Scheduled scan completed successfully. HTML report updated."
    else
      echo "[$(date)] Error: Scheduled scan failed!"
    fi
  done
}

# Run the periodic scans in the background
run_periodic_scans &
BG_PID=$!

# Handle shutdown signals
cleanup() {
  echo "Shutting down gracefully..."
  kill "$BG_PID" || true
  exit 0
}
trap cleanup SIGTERM SIGINT

# Start Nginx in the foreground
echo "Starting Nginx in foreground..."
nginx -g "daemon off;" &
NGINX_PID=$!

# Wait for Nginx
wait "$NGINX_PID"
