import logging
from logging.handlers import RotatingFileHandler
import os
from core.settings import BASE_DIR
LOG_DIR = os.path.join(str(BASE_DIR), "logs")
SYSTEM_LOG_PATH = os.path.join(LOG_DIR, "system.log")
THREAT_LOG_PATH = os.path.join(LOG_DIR, "threats.log")
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR, exist_ok=True)
def create_rotating_logger(name, log_file, level=logging.INFO, max_bytes=5 * 1024 * 1024, backup_count=3):
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.propagate = False
    if not logger.handlers:
        file_handler = RotatingFileHandler(
            log_file, maxBytes=max_bytes, backupCount=backup_count, encoding="utf-8"
        )
        file_handler.setLevel(level)
        formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        console_handler = logging.StreamHandler()
        console_handler.setLevel(level)
        console_format = logging.Formatter("\033[1;36m%(asctime)s\033[0m | \033[1;33m%(levelname)s\033[0m | %(message)s")
        console_handler.setFormatter(console_format)
        logger.addHandler(console_handler)
    return logger
def clear_threat_log():
    """
    Safely closes the threat log handler, truncates the file, and re-adds the handler.
    This prevents race conditions with active logging.
    """
    for handler in list(threat_logger.handlers):
        if isinstance(handler, RotatingFileHandler):
            try:
                handler.close()
                threat_logger.removeHandler(handler)
                with open(THREAT_LOG_PATH, 'w') as f:
                    pass
                new_handler = RotatingFileHandler(
                    THREAT_LOG_PATH, maxBytes=handler.maxBytes, backupCount=handler.backupCount, encoding="utf-8"
                )
                new_handler.setLevel(handler.level)
                new_handler.setFormatter(handler.formatter)
                threat_logger.addHandler(new_handler)
                system_logger.info("Threat log has been cleared by the user.")
            except Exception as e:
                system_logger.error(f"Failed to clear threat log: {e}")
                if handler not in threat_logger.handlers:
                    threat_logger.addHandler(handler)
system_logger = create_rotating_logger("system_logger", SYSTEM_LOG_PATH)
threat_logger = create_rotating_logger("threat_logger", THREAT_LOG_PATH)
def get_logger(name="system"):
    if name == "threat":
        return threat_logger
    return system_logger