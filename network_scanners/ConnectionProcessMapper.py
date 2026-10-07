import psutil
import threading
import time
from typing import Dict, Optional, Tuple
from core.SignalBus import emit_log
class ConnectionProcessMapper:
    """
    A thread-safe utility that periodically scans for active network connections
    and maps them to the process ID and name that created them.
    """
    def __init__(self, interval: float = 3.0):
        self.interval = interval
        self._running = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._connection_map: Dict[Tuple, Tuple] = {}
    def _build_map(self):
        """Scans system connections and builds the correlation map."""
        new_map = {}
        try:
            connections = psutil.net_connections(kind='inet')
            for conn in connections:
                if conn.status != psutil.CONN_ESTABLISHED or not conn.pid:
                    continue
                key = (
                    conn.laddr.ip if conn.laddr else '0.0.0.0',
                    conn.laddr.port if conn.laddr else 0,
                    conn.raddr.ip if conn.raddr else '0.0.0.0',
                    conn.raddr.port if conn.raddr else 0,
                )
                try:
                    process = psutil.Process(conn.pid)
                    new_map[key] = (conn.pid, process.name())
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            emit_log(f"[ConnMapper] Error building connection map: {e}", "error")
        with self._lock:
            self._connection_map = new_map
    def get_process_for_connection(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> Optional[str]:
        """Looks up a connection in the map and returns the process name."""
        key = (src_ip, src_port, dst_ip, dst_port)
        with self._lock:
            result = self._connection_map.get(key)
        return result[1] if result else None
    def _run_loop(self):
        """The main loop that periodically rebuilds the map."""
        emit_log("[ConnMapper] Started.", "info")
        while not self._running.is_set():
            self._build_map()
            self._running.wait(self.interval)
        emit_log("[ConnMapper] Stopped.", "info")
    def start(self):
        if self._thread and self.thread.is_alive(): return
        self._running.clear()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
    def stop(self):
        if not self._thread or not self._thread.is_alive(): return
        self._running.set()
        self._thread.join(timeout=self.interval + 1)