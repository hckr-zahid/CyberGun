import os
import json
from pathlib import Path
from core.SignalBus import emit_log
from core import settings
CONFIG_DIR = Path.home() / ".cybergun"
CONFIG_FILE_PATH = CONFIG_DIR / "config.json"
_config = {}
def _get_default_config() -> dict:
    """Constructs the default configuration dictionary with advanced options."""
    return {
        "scan_path": settings.DEFAULT_SCAN_PATH,
        "allowed_extensions": settings.ALLOWED_EXTENSIONS,
        "engines": {
            "enable_hash_scan": settings.ENABLE_HASH_SCAN,
            "enable_yara_scan": settings.ENABLE_YARA_SCAN,
            "enable_ml_scan": settings.ENABLE_ML_SCAN,
            "enable_signature_scan": settings.ENABLE_SIGNATURE_SCAN,
            "enable_string_scan": settings.ENABLE_STRING_SCAN,
            "enable_behavior_monitor": settings.ENABLE_BEHAVIOR_MONITOR,
            "enable_network_monitor": settings.ENABLE_NETWORK_MONITOR,
            "enable_deep_forensics": True,
            "enable_initial_boot_scan": False,
        },
        "thresholds": {
            "ml_confidence": settings.ML_CONFIDENCE_THRESHOLD,
            "thread_concurrency": 4,
            "auto_update_on_boot": True,
            "quarantine_auto_encrypt": True,
            "sound_alerts_enabled": True
        }
    }
def load_settings():
    """
    Loads settings from config.json. If the file doesn't exist or is corrupt,
    it creates one with default values.
    """
    global _config
    defaults = _get_default_config()
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        if CONFIG_FILE_PATH.exists():
            with open(CONFIG_FILE_PATH, 'r') as f:
                user_config = json.load(f)
            _config = defaults
            for k, v in user_config.items():
                if isinstance(v, dict) and k in _config and isinstance(_config[k], dict):
                    _config[k].update(v)
                else:
                    _config[k] = v
            emit_log(f"Configuration loaded successfully from {CONFIG_FILE_PATH}", "info")
        else:
            _config = defaults
            save_settings()
    except Exception as e:
        emit_log(f"Configuration load warning: {e}. Resetting to defaults.", "warning")
        _config = defaults
        save_settings()
def save_settings():
    """Saves the current in-memory configuration to config.json."""
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        with open(CONFIG_FILE_PATH, 'w') as f:
            json.dump(_config, f, indent=4)
    except Exception as e:
        emit_log(f"CRITICAL: Failed to save settings to {CONFIG_FILE_PATH}: {e}", "error")
def update_and_save_settings(new_settings: dict):
    """Updates live config and saves to disk."""
    global _config
    _config.update(new_settings)
    save_settings()
    emit_log("Application settings have been updated and saved.", "info")
def get_scan_path() -> str:
    return _config.get("scan_path", settings.DEFAULT_SCAN_PATH)
def get_allowed_extensions() -> list:
    return _config.get("allowed_extensions", [])
def get_ml_confidence_threshold() -> float:
    return _config.get("thresholds", {}).get("ml_confidence", 0.8)
def get_thread_concurrency() -> int:
    return _config.get("thresholds", {}).get("thread_concurrency", 4)
def is_auto_update_on_boot_enabled() -> bool:
    return _config.get("thresholds", {}).get("auto_update_on_boot", True)
def is_quarantine_encrypt_enabled() -> bool:
    return _config.get("thresholds", {}).get("quarantine_auto_encrypt", True)
def is_sound_alerts_enabled() -> bool:
    return _config.get("thresholds", {}).get("sound_alerts_enabled", True)
def is_initial_scan_enabled() -> bool:
    return _config.get("engines", {}).get("enable_initial_boot_scan", False)
def is_deep_forensics_enabled() -> bool:
    return _config.get("engines", {}).get("enable_deep_forensics", True)
def is_hash_scan_enabled() -> bool:
    return _config.get("engines", {}).get("enable_hash_scan", True)
def is_yara_scan_enabled() -> bool:
    return _config.get("engines", {}).get("enable_yara_scan", True)
def is_ml_scan_enabled() -> bool:
    return _config.get("engines", {}).get("enable_ml_scan", True)
def is_signature_scan_enabled() -> bool:
    return _config.get("engines", {}).get("enable_signature_scan", True)
def is_string_scan_enabled() -> bool:
    return _config.get("engines", {}).get("enable_string_scan", True)
def is_behavior_monitor_enabled() -> bool:
    return _config.get("engines", {}).get("enable_behavior_monitor", True)
def is_network_monitor_enabled() -> bool:
    return _config.get("engines", {}).get("enable_network_monitor", True)