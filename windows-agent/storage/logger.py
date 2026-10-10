"""Structured agent logging with size-bounded log rotation."""

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from config import LOG_FILE_PATH, LOG_MAX_BYTES, LOG_BACKUP_COUNT


def setup_logging(
    log_file: str | Path = LOG_FILE_PATH,
    max_bytes: int = LOG_MAX_BYTES,
    backup_count: int = LOG_BACKUP_COUNT,
    level: int = logging.INFO,
    console: bool = False,
) -> logging.Logger:
    """
    Configure size-bounded rotating file logging to prevent disk growth.

    Args:
        log_file: Path to log file.
        max_bytes: Maximum size of single log file before rotation (e.g. 5MB).
        backup_count: Maximum number of rotated log backup files to keep.
        level: Minimum log level.
        console: Whether to also attach a console stream handler.
    """
    log_path = Path(log_file)
    if log_path.parent and not log_path.parent.exists():
        log_path.parent.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("phishguard")
    logger.setLevel(level)

    # Clear existing handlers to avoid duplicates on re-configuration
    if logger.hasHandlers():
        logger.handlers.clear()

    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] [%(name)s:%(threadName)s] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )

    # 1. Rotating File Handler
    file_handler = RotatingFileHandler(
        filename=str(log_path),
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(level)
    logger.addHandler(file_handler)

    # 2. Optional Console Stream Handler
    if console:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        console_handler.setLevel(level)
        logger.addHandler(console_handler)

    return logger


def get_logger(name: str = "phishguard") -> logging.Logger:
    """Get a child or named logger under the phishguard namespace."""
    return logging.getLogger(name)

