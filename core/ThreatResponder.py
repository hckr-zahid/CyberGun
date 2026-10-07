import psutil
import os
import shutil
import time
from core.SignalBus import get_signal_bus, emit_log
from core.settings import QUARANTINE_DIR
from core.QuarantineManager import QuarantineManager
class ThreatResponder:
    """Listens for high-confidence threat signals and takes automated action."""
    def __init__(self):
        self.quarantine_manager = QuarantineManager()
        self.signal_bus = get_signal_bus()
        self.signal_bus.behavior_threat_detected.connect(self.handle_behavioral_threat)
        self.signal_bus.threat_detected.connect(self.handle_static_threat)
        emit_log("[ThreatResponder] Ready and listening for all threats.", "info")
    def handle_behavioral_threat(self, threat_data: dict):
        """Handles threats detected by the BehaviorMonitor."""
        pid = threat_data.get("pid")
        severity = threat_data.get("severity")
        description = threat_data.get("description", "No description")
        if not pid: return
        emit_log(f"[ThreatResponder] Received BEHAVIORAL threat signal: {description}", "critical")
        if severity == "high":
            try:
                p = psutil.Process(pid)
                exe_path = p.exe()
                p.kill()
                emit_log(f"[ThreatResponder] ACTION: Terminated malicious process {p.name()} (PID: {pid}).", "critical")
                if exe_path and os.path.exists(exe_path):
                    self.quarantine_manager.quarantine_file(exe_path)
            except psutil.NoSuchProcess:
                emit_log(f"[ThreatResponder] Process {pid} already terminated.", "info")
            except Exception as e:
                emit_log(f"[ThreatResponder] Failed to fully handle behavioral threat for PID {pid}: {e}", "error")
    def handle_static_threat(self, threat_data: dict):
        """Handles threats detected by the StaticEngine."""
        file_path = threat_data.get("file")
        severity = threat_data.get("severity")
        description = threat_data.get("description", "No description")
        if not file_path: return
        emit_log(f"[ThreatResponder] Received STATIC threat signal: {description}", "critical")
        if severity in ["high", "critical"]:
            emit_log(f"High severity static threat detected: {file_path}. Attempting to neutralize...", "warning")
            self.quarantine_manager.terminate_process_by_path(file_path)
            self.quarantine_manager.quarantine_file(file_path)