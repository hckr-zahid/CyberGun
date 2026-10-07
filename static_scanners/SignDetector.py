import os
import csv
from typing import List, Dict
import gc
from core.settings import SIGNATURE_DIR, ENABLE_SIGNATURE_SCAN
from core.SignalBus import emit_log, get_signal_bus
class SignDetector:
    """A memory-safe byte signature scanner that loads signatures on demand."""
    def __init__(self):
        self.signatures: List[Dict] = []
        self.resources_loaded = False
        self.signal_bus = get_signal_bus()
    def load_resources(self) -> None:
        if not ENABLE_SIGNATURE_SCAN or self.resources_loaded:
            return
        emit_log(f"[{self.__class__.__name__}] Loading byte signatures...", "info")
        try:
            from core.database_manager import get_db_manager
            db_sigs = get_db_manager().get_all_signatures()
            if db_sigs:
                for s in db_sigs:
                    try:
                        mal_name = s.get("malware_name", "")
                        sev = s.get("severity", "medium").lower()
                        if sev in ['low', 'info'] or any(b in mal_name.lower() for b in ['magicbyte', 'magic.byte', 'doctype', 'file.header']):
                            continue
                        self.signatures.append({
                            "signature": s["hex_signature"],
                            "bytes": bytes.fromhex(s["hex_signature"]),
                            "malware_name": mal_name,
                            "severity": s.get("severity", "medium"),
                            "description": s.get("description", "")
                        })
                    except Exception:
                        continue
                self.resources_loaded = True
                emit_log(f"[{self.__class__.__name__}] Loaded {len(self.signatures)} actionable byte signatures from SQLite database.", "info")
                return
        except Exception as e:
            emit_log(f"[{self.__class__.__name__}] SQLite signature load warning: {e}. Falling back to CSV.", "warning")
        if not SIGNATURE_DIR.exists() or not SIGNATURE_DIR.is_dir():
            emit_log(f"[{self.__class__.__name__}] Signature directory not found: {SIGNATURE_DIR}", "error")
            return
        loaded_count = 0
        for filename in os.listdir(SIGNATURE_DIR):
            if filename.endswith(".csv"):
                filepath = os.path.join(SIGNATURE_DIR, filename)
                try:
                    with open(filepath, "r", newline='', encoding='utf-8', errors='ignore') as f:
                        reader = csv.DictReader(f)
                        for i, row in enumerate(reader):
                            try:
                                if 'signature' not in row or not row['signature']:
                                    emit_log(f"[{self.__class__.__name__}] Skipping row {i+2} in {filename}: 'signature' column is missing or empty.", "warning")
                                    continue
                                row['bytes'] = bytes.fromhex(row['signature'])
                                self.signatures.append(row)
                                loaded_count += 1
                            except (ValueError, TypeError):
                                emit_log(f"[{self.__class__.__name__}] Skipping invalid hex signature in {filename} at row {i+2}.", "warning")
                                continue
                            except KeyError as ke:
                                emit_log(f"[{self.__class__.__name__}] Skipping row {i+2} in {filename} due to missing column: {ke}", "warning")
                                continue
                except Exception as e:
                    emit_log(f"[{self.__class__.__name__}] Error reading {filename}: {e}", "error")
        self.resources_loaded = True
        emit_log(f"[{self.__class__.__name__}] Loaded {loaded_count} valid byte signatures.", "info")
    def unload_resources(self) -> None:
        if not self.resources_loaded:
            return
        emit_log(f"[{self.__class__.__name__}] Unloading byte signatures.", "info")
        self.signatures.clear()
        self.resources_loaded = False
        gc.collect()
    def scan(self, file_path: str) -> List[Dict]:
        self.signal_bus.scan_progress_updated.emit({
            "layer": self.__class__.__name__,
            "message": f"Searching for byte signatures in {os.path.basename(file_path)}"
        })
        if not ENABLE_SIGNATURE_SCAN or not self.signatures:
            return []
        ext = os.path.splitext(file_path)[1].lower()
        if ext in ['.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp', '.ico', '.svg', '.mp3', '.mp4', '.avi', '.wav']:
            return []
        try:
            with open(file_path, "rb") as f:
                content_chunk = f.read(2 * 1024 * 1024)
                if not content_chunk:
                    return []
                for sig in self.signatures:
                    sig_bytes = sig.get('bytes')
                    if not sig_bytes or len(sig_bytes) < 8:
                        continue
                    if sig_bytes in content_chunk:
                        return [{
                            "source": self.__class__.__name__,
                            "type": "signature",
                            "description": f"Malicious byte signature detected: {sig.get('malware_name', 'UnnamedSignature')}",
                            "severity": sig.get('severity', 'high'),
                            "malware_name": sig.get('malware_name', 'UnnamedSignature'),
                        }]
        except (IOError, PermissionError) as e:
            emit_log(f"[{self.__class__.__name__}] Could not scan {file_path}: {e}", "error")
        return []
        return []