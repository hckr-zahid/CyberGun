import threading
from queue import Queue
from network_scanners.FirewallManager import FirewallManager
from network_scanners.TSharkSniffer import TSharkSniffer 
from network_scanners.NetworkAnalyzer import NetworkAnalyzer
from network_scanners.LiveNetworkThreatFetcher import LiveNetworkThreatFetcher
from network_scanners.ConnectionProcessMapper import ConnectionProcessMapper
from core.SignalBus import emit_log, get_signal_bus
from core.settings import SNIFFER_PACKET_QUEUE_MAXSIZE
from core import config_manager
class NetworkEngine:
    def __init__(self):
        emit_log("[NetworkEngine] Initializing...", "info")
        self.packet_queue: Queue = Queue(maxsize=SNIFFER_PACKET_QUEUE_MAXSIZE)
        self.threat_fetcher = LiveNetworkThreatFetcher()
        self.sniffer = TSharkSniffer(self.packet_queue)  
        self.conn_mapper = ConnectionProcessMapper()       
        self.analyzer = NetworkAnalyzer(
            packet_queue=self.packet_queue, 
            blacklist=self.threat_fetcher.blacklist_ips,
            conn_mapper=self.conn_mapper 
        )
        self.firewall_manager = FirewallManager()
        self.components = [self.conn_mapper, self.sniffer, self.analyzer]
        if not config_manager.is_network_monitor_enabled() or not self.sniffer.enabled:
            emit_log("[NetworkEngine] Network monitoring is disabled in settings or TShark is not available.", "info")
        else:
            bus = get_signal_bus()
            bus.block_request_emitted.connect(self._handle_block_request)
    def _handle_block_request(self, ip_address: str):
        self.firewall_manager.block_ip(ip_address)
    def start_all(self):
        if not config_manager.is_network_monitor_enabled() or not self.sniffer.enabled:
            return
        emit_log("[NetworkEngine] Starting all network monitoring components...", "info")
        for component in self.components:
            component.start()
        emit_log("[NetworkEngine] All network components are active.", "info")
    def stop_all(self):
        emit_log("[NetworkEngine] Stopping all network monitoring components...", "info")
        for component in self.components:
            component.stop()
        emit_log("[NetworkEngine] All network components have been stopped.", "info")