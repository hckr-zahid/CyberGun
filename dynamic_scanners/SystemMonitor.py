import threading
import time
import psutil
import traceback
from collections import deque
from typing import List, Dict, Any, Optional
from core.SignalBus import emit_log, emit_system_monitor_log, emit_system_snapshot
from core.settings import SYSTEM_MONITOR_INTERVAL, BEHAVIOR_SEQUENCE_MAXLEN
class SystemMonitor:
    """
    An advanced, thread-safe monitor that collects detailed system and process metadata.
    """
    def __init__(self, interval: float = SYSTEM_MONITOR_INTERVAL, maxlen: int = BEHAVIOR_SEQUENCE_MAXLEN):
        self.interval = float(interval)
        self.maxlen = int(maxlen)
        self._running = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.RLock()
        self._buffer: deque = deque(maxlen=self.maxlen)
        try:
            self._known_pids: set = {p.pid for p in psutil.process_iter(['pid'])}
        except Exception as e:
            self._known_pids = set()
            emit_log(f"[SystemMonitor] Could not perform initial PID scan: {e}", "warning")
    def _take_snapshot(self) -> None:
        """
        Takes a single, comprehensive snapshot of the system state, including detailed
        process metadata required for machine learning analysis.
        """
        try:
            ts = time.time()
            cpu_percent = psutil.cpu_percent(interval=None)
            mem_info = psutil.virtual_memory()
            disk_io = psutil.disk_io_counters()
            net_io = psutil.net_io_counters()
            process_attrs = [
                'pid', 'ppid', 'name', 'exe', 'cpu_percent', 'memory_percent',
                'username', 'status', 'num_threads', 'create_time', 'num_handles'
            ]
            all_procs_data = [p.info for p in psutil.process_iter(attrs=process_attrs, ad_value=None) if p.info['pid'] is not None]
            total_threads = sum(p['num_threads'] for p in all_procs_data if p['num_threads'])
            snapshot = {
                'ts': ts,
                'cpu_percent': cpu_percent,
                'mem_percent': mem_info.percent,
                'disk_io': {'read_bytes': disk_io.read_bytes, 'write_bytes': disk_io.write_bytes} if disk_io else None,
                'net_io': {'bytes_sent': net_io.bytes_sent, 'bytes_recv': net_io.bytes_recv} if net_io else None,
                'processes': all_procs_data, 
                'summary': {
                    'total_processes': len(all_procs_data),
                    'total_threads': total_threads
                }
            }
            with self._lock:
                self._buffer.append(snapshot)
            emit_system_snapshot(snapshot)
            emit_system_monitor_log(f"Snapshot: CPU {cpu_percent:.1f}%, Mem {mem_info.percent:.1f}%, Procs: {len(all_procs_data)}")
        except Exception as e:
            emit_log(f"[SystemMonitor] CRITICAL: Failed to take snapshot: {e}\n{traceback.format_exc()}", "error")
    def _run_loop(self) -> None:
        emit_log("[SystemMonitor] Background thread run_loop started.", "info")
        while not self._running.is_set():
            self._take_snapshot()
            self._running.wait(timeout=self.interval)
        emit_log("[SystemMonitor] Background thread run_loop finished.", "info")
    def start(self) -> None:
        if self._thread and self._thread.is_alive(): return
        self._running.clear()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
    def stop(self) -> None:
        if not self._thread or not self._thread.is_alive(): return
        self._running.set()
        self._thread.join(timeout=self.interval + 1)
        self._thread = None
    def get_recent_behavior_sequence(self, n: Optional[int] = None) -> List[Dict[str, Any]]:
        with self._lock:
            full_sequence = list(self._buffer)
        return full_sequence[-int(n):] if n is not None else full_sequence