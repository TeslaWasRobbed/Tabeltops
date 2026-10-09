"""Gunicorn configuration for the tabletop SIEM VM."""

import os


bind = os.getenv("TABLETOP_BIND", "0.0.0.0:5000")

# Timed Kusto ingestion is coordinated in-process. Keep one worker and use
# threads for concurrent facilitator and team requests.
workers = 1
worker_class = "gthread"
threads = int(os.getenv("TABLETOP_THREADS", "8"))

timeout = 30
graceful_timeout = 30
keepalive = 5

accesslog = "-"
errorlog = "-"
capture_output = True
loglevel = os.getenv("TABLETOP_LOG_LEVEL", "info")

proc_name = "tabletop-siem"
