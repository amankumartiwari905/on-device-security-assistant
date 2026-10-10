"""Configuration for the local Windows security agent."""

POLL_INTERVAL_SECONDS = 3
DNS_POLL_INTERVAL_SECONDS = 3
TASK_POLL_INTERVAL_SECONDS = 15
SERVICE_POLL_INTERVAL_SECONDS = 10
DATABASE_PATH = "security_events.db"
APP_NAME = "PhishGuard Local"

# Event Deduplication
DEDUP_WINDOW_SECONDS = 300  # 5-minute database deduplication window

# Retention Policy
RETENTION_DAYS = 30
MAX_DB_RECORDS = 50000
RETENTION_KEEP_HIGH_SEVERITY = True

# Offline Queue & Retry
SYNC_ENABLED = True
SYNC_INTERVAL_SECONDS = 10
SYNC_BATCH_SIZE = 50
SYNC_MAX_RETRIES = 5
BACKEND_API_URL = "http://127.0.0.1:8000/api/v1/events"

# Logging & Rotation
LOG_FILE_PATH = "logs/phishguard_agent.log"
LOG_MAX_BYTES = 5 * 1024 * 1024  # 5 MB per log file
LOG_BACKUP_COUNT = 3

# File Download Monitoring & Prevention Pipeline
WATCH_DOWNLOADS = True
DOWNLOAD_POLL_INTERVAL_SECONDS = 3
WATCHED_DOWNLOAD_DIRECTORIES: list[str] = []  # Empty defaults to user's Downloads & Desktop
PREVENTION_ENABLED = True
PREVENTION_MODE = "quarantine_and_terminate"  # "alert_only", "quarantine_file", "terminate_process", "quarantine_and_terminate"
PREVENTION_MIN_SCORE = 70  # Trigger prevention for High (>=70) and Critical (>=85)
QUARANTINE_DIR = "quarantine"
