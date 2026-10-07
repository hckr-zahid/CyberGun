import threading
import subprocess
import shutil
import os
import json
from queue import Queue, Full
from typing import Optional
from core.SignalBus import emit_log, emit_network_status
from core.settings import NETWORK_INTERFACE, ENABLE_NETWORK_MONITOR, TSHARK_CUSTOM_PATH
class TSharkSniffer:
    """
    A professional network sniffer that uses TShark to capture packets and outputs them as JSON
    for real-time processing.
    """
    def __init__(self, packet_queue: Queue):
        self.packet_queue = packet_queue
        self._process: Optional[subprocess.Popen] = None
        self._thread: Optional[threading.Thread] = None
        self.interface = NETWORK_INTERFACE
        self.tshark_executable_path = self._find_tshark()
        if not self.tshark_executable_path:
            self.enabled = False
            emit_log("[TSharkSniffer] CRITICAL: TShark executable could not be found.", "error")
            emit_log("[TSharkSniffer] Please install Wireshark and set TSHARK_CUSTOM_PATH in settings.py or add it to the system PATH.", "error")
        else:
            self.enabled = ENABLE_NETWORK_MONITOR
            emit_log(f"[TSharkSniffer] Found TShark at: {self.tshark_executable_path}", "info")
        if self.enabled:
            emit_log("[TSharkSniffer] TShark backend is enabled.", "info")
    def _find_tshark(self) -> Optional[str]:
        """Finds the TShark executable using a robust, three-tiered approach."""
        tshark_exe_in_custom_path = os.path.join(TSHARK_CUSTOM_PATH, "tshark.exe")
        if TSHARK_CUSTOM_PATH and os.path.exists(tshark_exe_in_custom_path):
            emit_log(f"[TSharkSniffer] Using custom TShark path from settings: {tshark_exe_in_custom_path}", "info")
            return tshark_exe_in_custom_path
        tshark_path_from_env = shutil.which("tshark")
        if tshark_path_from_env:
            emit_log(f"[TSharkSniffer] Found TShark in system PATH: {tshark_path_from_env}", "info")
            return tshark_path_from_env
        return None
    def _sniff_loop(self) -> None:
        """
        The main loop that runs TShark and reads its JSON output line by line.
        """
        emit_network_status(f"Starting TShark capture on interface: {self.interface}")
        try:
            command = [
                self.tshark_executable_path, 
                "-i", self.interface,
                "-l",
                "-T", "ek",
                "-e", "ip.src",
                "-e", "ip.dst",
                "-e", "tcp.dstport",
                "-e", "udp.dstport",
                "-e", "frame.protocols"
            ]
            self._process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
            )
            for line in iter(self._process.stdout.readline, ''):
                try:
                    packet_data = json.loads(line)
                    self.packet_queue.put(packet_data, block=False)
                except Full:
                    emit_log("[TSharkSniffer] Packet queue is full. Dropping packets.", "warning")
                except json.JSONDecodeError:
                    continue
        except FileNotFoundError:
             emit_log(f"[TSharkSniffer] CRITICAL: TShark executable not found at '{self.tshark_executable_path}'.", "error")
        except Exception as e:
            stderr_output = self._process.stderr.read() if self._process else ""
            emit_log(f"[TSharkSniffer] TShark process failed: {e}", "error")
            if stderr_output:
                emit_log(f"[TSharkSniffer] TShark Error Output: {stderr_output.strip()}", "error")
        finally:
            emit_network_status("TShark capture stopped.")
            emit_log("[TSharkSniffer] Sniffing loop has terminated.", "info")
    def start(self) -> None:
        if not self.enabled: return
        if self._thread and self._thread.is_alive(): return
        emit_log("[TSharkSniffer] Starting sniffing thread...", "info")
        self._thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._thread.start()
    def stop(self) -> None:
        if not self._thread or not self._thread.is_alive(): return
        emit_log("[TSharkSniffer] Stopping TShark process...", "info")
        if self._process:
            self._process.kill()
        self._thread.join(timeout=3.0)
        if self._thread.is_alive(): emit_log("[TSharkSniffer] Sniffer thread did not stop gracefully.", "warning")
        self._thread = None
        self._process = None