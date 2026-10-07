import threading
from dynamic_scanners.SystemMonitor import SystemMonitor
from dynamic_scanners.BehaviorMonitor import BehaviorMonitor
from dynamic_scanners.USBMonitor import USBMonitor
from dynamic_scanners.SandboxSim import SandboxSim
from core.ThreatResponder import ThreatResponder
from core.SignalBus import get_signal_bus, emit_log
from core import config_manager
class DynamicEngine:
    """
    The central engine that orchestrates all REAL-TIME dynamic scanning components.
    """
    def __init__(self):
        emit_log("[DynamicEngine] Initializing...", "info")
        self.system_monitor = SystemMonitor(interval=2.0)
        self.behavior_monitor = BehaviorMonitor(system_monitor=self.system_monitor, scan_interval=5.0)
        self.usb_monitor = USBMonitor()
        self.sandbox_sim = SandboxSim()
        self.threat_responder = ThreatResponder()
        self.monitors = [self.system_monitor, self.behavior_monitor, self.usb_monitor]
        signal_bus = get_signal_bus()
        signal_bus.start_dynamic_scan.connect(self.handle_dynamic_scan_request)
    def start_all_monitors(self):
        emit_log("[DynamicEngine] Starting all continuous monitors...", "info")
        for monitor in self.monitors:
            if isinstance(monitor, BehaviorMonitor) and not config_manager.is_behavior_monitor_enabled():
                emit_log("[DynamicEngine] Skipping BehaviorMonitor as it is disabled in settings.", "info")
                continue
            monitor.start()
    def stop_all_monitors(self):
        emit_log("[DynamicEngine] Stopping all continuous monitors...", "info")
        for monitor in self.monitors:
            monitor.stop()
    def handle_dynamic_scan_request(self, file_path: str):
        emit_log(f"[DynamicEngine] Dynamic scan request received for: {file_path}", "info")
        self.sandbox_sim.execute(file_path=file_path)