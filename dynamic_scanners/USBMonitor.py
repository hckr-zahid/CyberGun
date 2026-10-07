import sys
import threading
import time
from typing import Set, Optional
from core.SignalBus import get_signal_bus, emit_log, emit_dynamic_event
IS_WINDOWS = sys.platform == 'win32'
if IS_WINDOWS:
    try:
        import win32file
    except ImportError:
        IS_WINDOWS = False
        emit_log("WARNING: 'pywin32' is not installed. USBMonitor will be disabled.", "warning")
class USBMonitor:
    """A professional monitor that detects USB device connections on Windows."""
    def __init__(self):
        self._running = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.signal_bus = get_signal_bus()
    def _get_removable_drives(self) -> Set[str]:
        if not IS_WINDOWS: return set()
        drives = set()
        bitmask = win32file.GetLogicalDrives()
        for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            if bitmask & 1:
                drive = f"{letter}:\\"
                try:
                    if win32file.GetDriveType(drive) == win32file.DRIVE_REMOVABLE:
                        drives.add(drive)
                except Exception:
                    continue
            bitmask >>= 1
        return drives
    def _run_loop(self) -> None:
        """The main background loop, polls for drive changes."""
        emit_log("[USBMonitor] Started.", "info")
        drives_before = self._get_removable_drives()
        while not self._running.is_set():
            try:
                drives_after = self._get_removable_drives()
                added = drives_after - drives_before
                removed = drives_before - drives_after
                for drive in added:
                    emit_log(f"[USBMonitor] Removable device connected: {drive}", "info")
                    threat_data = {
                        "source": "USBMonitor", "type": "device_event", "device": drive,
                        "description": "Removable Device Detected", "severity": "medium",
                        "action_taken": "Scan Triggered",
                        "timestamp": time.time(),
                    }
                    self.signal_bus.usb_detected.emit(threat_data)
                    emit_dynamic_event({
                        "timestamp": threat_data["timestamp"],
                        "event": "External Hardware Detection",
                        "details": f"Removable drive connected: {drive}. Triggering scan.",
                        "type": "warning"
                    })
                for drive in removed:
                    emit_log(f"[USBMonitor] Removable device disconnected: {drive}", "info")
                    emit_dynamic_event({
                        "timestamp": time.time(),
                        "event": "External Hardware Detection",
                        "details": f"Removable drive disconnected: {drive}",
                        "type": "info"
                    })
                if added or removed:
                    drives_before = drives_after
            except Exception as e:
                emit_log(f"[USBMonitor] An error occurred in the monitoring loop: {e}", "error")
            self._running.wait(timeout=2.0)
        emit_log("[USBMonitor] Stopped.", "info")
    def start(self) -> None:
        if not IS_WINDOWS:
            emit_log("[USBMonitor] Disabled (not running on Windows or pywin32 missing).", "warning")
            return
        if self._thread and self._thread.is_alive(): return
        self._running.clear()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
    def stop(self) -> None:
        if not self._thread or not self._thread.is_alive(): return
        self._running.set()
        self._thread.join(timeout=3.0)
        self._thread = None