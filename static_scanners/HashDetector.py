import hashlib
import os
from typing import Set, List, Dict, Optional
import gc 
from core.settings import HASH_DIR, ENABLE_HASH_SCAN
from core.SignalBus import emit_log, get_signal_bus
from core.database_manager import get_db_manager
class HashDetector:
    """
    High-performance hash scanner powered by the centralized SQLite Intelligence DB.
    Performs instantaneous O(1) lookups across millions of malware signatures.
    """
    def __init__(self):
        self.resources_loaded = False
        self.signal_bus = get_signal_bus()
        self.db_manager = None
    def load_resources(self) -> None:
        """Connects to the centralized SQLite Threat Intelligence DB."""
        if not ENABLE_HASH_SCAN or self.resources_loaded:
            return
        emit_log(f"[{self.__class__.__name__}] Connecting to SQLite Threat Intelligence Database...", "info")
        self.db_manager = get_db_manager()
        stats = self.db_manager.get_intel_stats()
        hash_count = stats.get('threat_hashes', 0)
        self.resources_loaded = True
        emit_log(f"[{self.__class__.__name__}] Active index: {hash_count:,} malware hashes loaded in SQLite.", "info")
    def unload_resources(self) -> None:
        """Unloads hash scanner resources."""
        if not self.resources_loaded:
            return
        emit_log(f"[{self.__class__.__name__}] Hash scanner resources unloaded.", "info")
        self.resources_loaded = False
        gc.collect()
    def _compute_hashes(self, file_path: str) -> Dict[str, str]:
        """Computes SHA256 and MD5 hashes of a file in streaming chunks."""
        sha256 = hashlib.sha256()
        md5 = hashlib.md5()
        try:
            with open(file_path, "rb") as f:
                while chunk := f.read(65536):
                    sha256.update(chunk)
                    md5.update(chunk)
            return {
                "sha256": sha256.hexdigest().lower(),
                "md5": md5.hexdigest().lower()
            }
        except (IOError, PermissionError) as e:
            emit_log(f"[{self.__class__.__name__}] Could not hash {file_path}: {e}", "error")
            return {}
    def scan(self, file_path: str) -> List[Dict]:
        """Scans a file against the SQLite threat database."""
        self.signal_bus.scan_progress_updated.emit({
            "layer": self.__class__.__name__,
            "message": f"Checking hash for {os.path.basename(file_path)}"
        })
        if not ENABLE_HASH_SCAN or not self.resources_loaded or not self.db_manager:
            return []
        hashes = self._compute_hashes(file_path)
        if not hashes:
            return []
        for h_type, h_val in hashes.items():
            match = self.db_manager.check_hash(h_val)
            if match:
                malware_name = match.get("malware_name", "KnownMalware.ThreatHash")
                severity = match.get("severity", "critical")
                emit_log(f"[{self.__class__.__name__}] THREAT MATCH: {file_path} -> {malware_name} ({h_val})", "warning")
                return [{
                    "source": self.__class__.__name__,
                    "type": "hash_match",
                    "description": f"File matches {malware_name} ({h_type.upper()}: {h_val})",
                    "severity": severity,
                    "malware_name": malware_name,
                    "matched_hash": h_val
                }]
        return []