import threading
import time
import os
from queue import Queue, Empty
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from typing import Optional
from core import config_manager
from core.StaticEngine import StaticEngine
from core.SignalBus import emit_log, emit_dynamic_event
class FileSystemMonitor:
    """
    Monitors the filesystem for new or modified files and triggers on-demand scans.
    """
    def __init__(self, static_engine: StaticEngine):
        self.static_engine = static_engine
        self.scan_queue = Queue()
        self._running = threading.Event()
        self._observer: Optional[Observer] = None
        self._worker_thread: Optional[threading.Thread] = None
        self.recent_scans = {}
        self.recent_scan_lock = threading.Lock()
        self.RECENT_SCAN_COOLDOWN = 10
    def _worker_loop(self):
            """Worker thread that consumes file paths from the queue and scans them."""
            emit_log("[FileSystemMonitor] Worker thread started.", "info")
            while not self._running.is_set():
                try:
                    file_path = self.scan_queue.get(timeout=1)
                    emit_dynamic_event({
                        "timestamp": time.time(),
                        "event": "File System Activity",
                        "details": f"Detected change: {os.path.basename(file_path)}",
                        "type": "info"
                    })
                    emit_log(f"[FileSystemMonitor] New event detected. Scanning: {file_path}", "info")
                    self.static_engine.scan_file(file_path)
                    self.scan_queue.task_done()
                except Empty:
                    continue
                except Exception as e:
                    emit_log(f"[FileSystemMonitor] Error in worker thread: {e}", "error")
            emit_log("[FileSystemMonitor] Worker thread stopped.", "info")
    def start(self):
        if self._observer and self._observer.is_alive(): return
        scan_path = config_manager.get_scan_path()
        if not os.path.isdir(scan_path):
            emit_log(f"[FileSystemMonitor] Cannot start: Scan path '{scan_path}' is not a valid directory.", "error")
            return
        emit_log(f"[FileSystemMonitor] Starting to watch directory: {scan_path}", "info")
        event_handler = self._ScanEventHandler(self.scan_queue)
        self._observer = Observer()
        self._observer.schedule(event_handler, scan_path, recursive=True)
        self._observer.start()
        emit_log("[FileSystemMonitor] Real-time monitoring is now active.", "info")
    def stop(self):
        if not self._observer or not self._observer.is_alive():
            return
        emit_log("[FileSystemMonitor] Stopping...", "info")
        self._running.set()
        self._observer.stop()
        self._observer.join()
        if self._worker_thread:
            self._worker_thread.join()
        emit_log("[FileSystemMonitor] Real-time monitoring stopped.", "info")
    class _ScanEventHandler(FileSystemEventHandler):
        """Helper class to push file events into the queue."""
        def __init__(self, scan_queue: Queue):
            self.scan_queue = scan_queue
            super().__init__()
        def on_created(self, event):
            if not event.is_directory:
                self.scan_queue.put(event.src_path)
        def on_modified(self, event):
            if not event.is_directory:
                self.scan_queue.put(event.src_path)