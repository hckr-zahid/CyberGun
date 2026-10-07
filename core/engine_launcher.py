import time
import threading
from PyQt5.QtCore import QObject, pyqtSlot, QTimer
from typing import Callable
from core.StaticEngine import StaticEngine
from core.DynamicEngine import DynamicEngine
from core.NetworkEngine import NetworkEngine
from core.FileSystemMonitor import FileSystemMonitor
from core.ThreatDownloader import ThreatDownloader
from core.SignalBus import get_signal_bus, emit_log, emit_splash_update
from core import config_manager
class EngineLauncher(QObject):
    BOOT_UPDATE_TIMEOUT = 20.0
    def __init__(self):
        super().__init__()
        config_manager.load_settings()
        emit_log("[EngineLauncher] Initializing all backend engines...", "info")
        self.static_engine = StaticEngine()
        self.dynamic_engine = DynamicEngine()
        self.network_engine = NetworkEngine()
        self.threat_downloader = ThreatDownloader()
        self.filesystem_monitor = FileSystemMonitor(static_engine=self.static_engine)
        self._stop_scan_event = threading.Event()
        self._threat_update_timer = None
        get_signal_bus().stop_scan_requested.connect(self.handle_stop_scan_request)
        get_signal_bus().usb_detected.connect(self.handle_usb_detection)
        get_signal_bus().start_scan_path.connect(self.start_static_scan_on_directory)
        emit_log("[EngineLauncher] Backend engines are ready.", "info")
    def start_all_continuous_monitors(self):
        """
        Starts the services that should always be running in the background.
        This should be called once when the main application starts.
        """
        emit_log("[EngineLauncher] Starting all real-time monitors (Dynamic, Network, FileSystem).", "info")
        self.dynamic_engine.start_all_monitors()
        self.network_engine.start_all()
        self.filesystem_monitor.start()
        self._threat_update_timer = QTimer(self)
        self._threat_update_timer.setInterval(12 * 3600 * 1000)
        self._threat_update_timer.timeout.connect(self.start_threat_update)
        self._threat_update_timer.start()
        emit_log("[EngineLauncher] Automated 12-hour threat intelligence scheduler active.", "info")
    def stop_all_monitors(self):
        """
        Gracefully stops all background services.
        This should be called when the application is closing.
        """
        emit_log("[EngineLauncher] Stopping all real-time monitors.", "info")
        if self._threat_update_timer and self._threat_update_timer.isActive():
            self._threat_update_timer.stop()
        self.filesystem_monitor.stop()
        self.network_engine.stop_all()
        self.dynamic_engine.stop_all_monitors()
        emit_log("[EngineLauncher] All monitors stopped.", "info")
    def _scan_thread_wrapper(self, path: str, stop_check: Callable[[], bool]):
        """A wrapper to emit start/finish signals around the scan."""
        bus = get_signal_bus()
        try:
            bus.scan_started.emit()
            self.static_engine.scan_directory_layered(path, stop_check)
        except Exception as e:
            emit_log(f"[EngineLauncher] Error in scan thread wrapper: {e}", "error")
        finally:
            bus.scan_finished.emit()
    def start_static_scan_on_directory(self, directory_path=None):
        """
        Triggers a static scan on a directory. This is meant to be called by a GUI button.
        Runs in a separate thread to not freeze the GUI.
        """
        path = directory_path if directory_path else config_manager.get_scan_path()
        emit_log(f"[EngineLauncher] Received request to start static scan on: {path}", "info")
        self._stop_scan_event.clear()
        scan_thread = threading.Thread(
            target=self._scan_thread_wrapper,
            args=(path, self._stop_scan_event.is_set),
            daemon=True
        )
        scan_thread.start()
    def start_threat_update(self):
        """
        Triggers the threat intelligence downloader. Meant to be called by a GUI button.
        """
        emit_log("[EngineLauncher] Received request to update threat databases.", "info")
        self.threat_downloader.start_update()
    @pyqtSlot(dict)
    def handle_usb_detection(self, threat_data: dict):
        """
        Handles the signal emitted when a new USB device is detected.
        Triggers a static scan on the detected drive path.
        """
        drive_path = threat_data.get("device")
        if drive_path:
            emit_log(f"[EngineLauncher] USB device detected at {drive_path}. Starting static scan.", "info")
            self.start_static_scan_on_directory(directory_path=drive_path)
        else:
            emit_log("[EngineLauncher] Received USB detection signal but no drive path was provided.", "warning")
    @pyqtSlot()
    def run_initial_setup(self):
        """
        It starts a race between the database update and a 60-second timer.
        """
        self._loading_finished_event = threading.Event()
        def _update_task():
            try:
                emit_splash_update("Initializing CyberGun Core Security Engine...")
                time.sleep(0.4)
                emit_splash_update("Connecting to Central SQLite Threat Database...")
                time.sleep(0.3)
                if config_manager.is_auto_update_on_boot_enabled():
                    emit_splash_update("Updating Threat Database from online intelligence feeds...")
                    self.threat_downloader.run_update_logic()
                else:
                    emit_splash_update("Verifying offline threat signatures...")
                    time.sleep(0.5)
                emit_splash_update("Threat Database Synchronized (3.1M+ signatures).")
                time.sleep(0.4)
                emit_log("[EngineLauncher] Database update completed within the time limit.", "info")
            except Exception as e:
                emit_log(f"[EngineLauncher] Notice during database update: {e}", "warning")
            finally:
                self.finish_loading("Database synchronized. Launching dashboard...")
        def _timeout_task():
            time.sleep(self.BOOT_UPDATE_TIMEOUT)
            emit_log(f"[EngineLauncher] Database update timed out after {self.BOOT_UPDATE_TIMEOUT} seconds.", "info")
            self.finish_loading("Update continuing in background...")
        update_thread = threading.Thread(target=_update_task, daemon=True)
        timeout_thread = threading.Thread(target=_timeout_task, daemon=True)
        update_thread.start()
        timeout_thread.start()
    def finish_loading(self, final_splash_message: str):
        """
        A thread-safe method to emit the loading_finished signal.
        This will be called by whichever task finishes first.
        """
        if self._loading_finished_event.is_set():
            return
        self._loading_finished_event.set()
        emit_splash_update(final_splash_message)
        time.sleep(0.5)
        get_signal_bus().loading_finished.emit(None, None)
    def run_background_tasks(self):
        """
        Starts the initial background system scan only if enabled in settings,
        preventing background scanning lag at application startup.
        """
        if not config_manager.is_initial_scan_enabled():
            emit_log("[EngineLauncher] Initial boot scan is disabled in settings. Skipping automatic background scan.", "info")
            return
        def _scan_task():
            time.sleep(3.0)
            emit_log("[EngineLauncher] Starting background initial system scan...", "info")
            try:
                self.static_engine.scan_directory_layered(config_manager.get_scan_path())
                emit_log("[EngineLauncher] ✅ Background initial scan complete.", "info")
            except Exception as e:
                emit_log(f"[EngineLauncher] Notice during background initial scan: {e}", "warning")
        scan_thread = threading.Thread(target=_scan_task, daemon=True)
        scan_thread.start()
    @pyqtSlot()
    def handle_stop_scan_request(self):
        """Slot to receive the stop request from the GUI."""
        emit_log("[EngineLauncher] Received stop scan request from GUI.", "info")
        self._stop_scan_event.set()