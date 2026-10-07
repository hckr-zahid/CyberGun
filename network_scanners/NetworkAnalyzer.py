import threading
import time
from queue import Queue, Empty
from typing import Set
from core.SignalBus import emit_log, emit_network_alert, emit_network_status, emit_block_request
from .ConnectionProcessMapper import ConnectionProcessMapper
class NetworkAnalyzer:
    """
    Analyzes network data using a provided blacklist and a connection-to-process mapper.
    """
    def __init__(self, packet_queue: Queue, blacklist: Set[str], conn_mapper: ConnectionProcessMapper, interval: float = 5.0):
        self._packet_queue = packet_queue
        self._running = threading.Event()
        self._thread: threading.Thread | None = None
        self.interval = interval
        self.blacklist = blacklist
        self.conn_mapper = conn_mapper
        emit_log(f"[NetworkAnalyzer] Initialized with a blacklist of {len(self.blacklist)} IPs.", "info")
        self._suppressed_alerts = {}
        self.alert_cooldown = 60.0
    def _analysis_loop(self) -> None:
        """The main analysis loop. Uses a blocking get() for high efficiency."""
        emit_log("[NetworkAnalyzer] Analysis loop started.", "info")
        packets_processed_since_last_log = 0
        while not self._running.is_set():
            try:
                packet_data = self._packet_queue.get(timeout=self.interval)
                self._analyze_packet(packet_data)
                packets_processed_since_last_log += 1
            except Empty:
                if packets_processed_since_last_log > 0:
                    emit_network_status(f"Analyzed {packets_processed_since_last_log} packets.")
                    packets_processed_since_last_log = 0
                else:
                    emit_network_status("Monitoring... (idle)")
                continue
            except Exception as e:
                emit_log(f"[NetworkAnalyzer] Error in analysis loop: {e}", "error")
        emit_log("[NetworkAnalyzer] Analysis loop stopped.", "info")
    def _analyze_packet(self, packet_data: dict) -> None:
        """
        Performs analysis on a single packet, finds the responsible process,
        and emits a comprehensive alert.
        """
        layers = packet_data.get("layers", {})
        dst_ip_list = layers.get("ip_dst")
        if not dst_ip_list: return
        dst_ip = dst_ip_list[0]
        if dst_ip in self.blacklist:
            current_time = time.time()
            if self._suppressed_alerts.get(dst_ip) and (current_time - self._suppressed_alerts.get(dst_ip)) < self.alert_cooldown:
                return
            self._suppressed_alerts[dst_ip] = current_time
            src_ip = layers.get("ip_src", ["N/A"])[0]
            proto_parts = layers.get("frame_protocols", [""])[0].split(":")
            proto = "TCP" if "tcp" in proto_parts else "UDP" if "udp" in proto_parts else "IP"
            if proto == "TCP":
                src_port = int(layers.get("tcp_srcport", [0])[0])
                dst_port = int(layers.get("tcp_dstport", [0])[0])
            elif proto == "UDP":
                src_port = int(layers.get("udp_srcport", [0])[0])
                dst_port = int(layers.get("udp_dstport", [0])[0])
            else:
                src_port, dst_port = 0, 0
            process_name = self.conn_mapper.get_process_for_connection(
                src_ip, src_port, dst_ip, dst_port
            ) or "Unknown"
            emit_network_alert({
                "timestamp": current_time,
                "source": "NetworkAnalyzer",
                "severity": "high",
                "threat_type": "Blacklisted IP",
                "description": f"Connection attempt to blacklisted IP: {dst_ip}",
                "protocol": proto,
                "port": str(dst_port),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "process_name": process_name,
                "action_taken": "Block Attempted"
            })
            emit_block_request(ip_address=dst_ip)
    def start(self) -> threading.Thread:
        self._running.clear()
        self._thread = threading.Thread(target=self._analysis_loop, daemon=True)
        self._thread.start()
        emit_log("[NetworkAnalyzer] Analyzer thread started.", "info")
        return self._thread
    def stop(self) -> None:
        emit_log("[NetworkAnalyzer] Stopping analyzer...", "info")
        self._running.set()