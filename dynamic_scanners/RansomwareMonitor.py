import os
import threading
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from pathlib import Path
from core.SignalBus import emit_log, emit_behavior_threat
from core.QuarantineManager import QuarantineManager
import psutil
class CanaryHandler(FileSystemEventHandler):
    def __init__(self, canary_files):
        self.canary_files = canary_files
        self.quarantine_mgr = QuarantineManager()
    def on_modified(self, event):
        if event.src_path in self.canary_files:
            self.trigger_ransomware_alert(event.src_path, "modified")
    def on_deleted(self, event):
        if event.src_path in self.canary_files:
            self.trigger_ransomware_alert(event.src_path, "deleted")
    def trigger_ransomware_alert(self, path, action):
        emit_log(f"[RansomwareMonitor] 🚨 CANARY FILE {action.upper()}: {path}", "critical")
        threat_data = {
            "source": "RansomwareMonitor",
            "type": "ransomware_behavior",
            "description": f"Canary file {action}. Potential encryption in progress.",
            "severity": "critical",
            "mitre_id": "T1486"
        }
        emit_behavior_threat(threat_data)
class RansomwareMonitor:
    def __init__(self):
        self.observer = Observer()
        self.home_dir = Path.home()
        self.target_dirs = [
            self.home_dir / "Documents",
            self.home_dir / "Desktop",
            self.home_dir / "Downloads"
        ]
        self.canary_name = "sys_config_backup.ini"
        self.canary_paths = []
    def _deploy_canaries(self):
        """Creates hidden honeypot files."""
        for d in self.target_dirs:
            if d.exists():
                canary = d / self.canary_name
                try:
                    with open(canary, 'w') as f:
                        f.write("[System Configuration]\nDO_NOT_MODIFY=TRUE\nUUID=0000-0000")
                    if os.name == 'nt':
                        import ctypes
                        ctypes.windll.kernel32.SetFileAttributesW(str(canary), 0x02)
                    self.canary_paths.append(str(canary))
                except Exception as e:
                    emit_log(f"[RansomwareMonitor] Failed to deploy canary in {d}: {e}", "error")
    def start(self):
        self._deploy_canaries()
        event_handler = CanaryHandler(self.canary_paths)
        for d in self.target_dirs:
            if d.exists():
                self.observer.schedule(event_handler, str(d), recursive=False)
        try:
            self.observer.start()
            emit_log("[RansomwareMonitor] 🛡️ Canary files deployed and monitoring active.", "info")
        except Exception as e:
            emit_log(f"[RansomwareMonitor] Failed to start: {e}", "error")
    def stop(self):
        if self.observer.is_alive():
            self.observer.stop()
            self.observer.join()
        for p in self.canary_paths:
            try:
                if os.path.exists(p): os.remove(p)
            except: pass