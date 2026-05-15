# Gunicorn configuration for production
# Usage: gunicorn -c gunicorn.conf.py server:app

import multiprocessing

# Worker configuration
# gevent provides async workers that handle SSE streaming well.
# Each worker holds its own in-memory caches (search results, temp APK registry,
# rate-limit tracker). With default settings, expect ~50-100MB per worker baseline
# plus up to ~2GB shared temp APK storage on disk.
worker_class = 'gevent'
workers = min(multiprocessing.cpu_count() * 2 + 1, 8)
worker_connections = 1000

# Timeout for long-running requests (APK downloads/merges can take time)
timeout = 300  # 5 minutes
graceful_timeout = 30

# Server socket
bind = '0.0.0.0:5000'

# Logging
accesslog = '-'
errorlog = '-'
loglevel = 'info'

# Process naming
proc_name = 'gplay-downloader'

# Security - request limits
limit_request_line = 4096
limit_request_fields = 100
limit_request_body = 1048576  # 1MB - matches Flask MAX_CONTENT_LENGTH

# Keep-alive for SSE connections
keepalive = 65
