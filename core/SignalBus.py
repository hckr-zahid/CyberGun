from PyQt5.QtCore import QObject, pyqtSignal
from utils.logger import get_logger
import threading
_log = get_logger("system")
threat_log_lock = threading.Lock()
from PyQt5.QtCore import QObject, pyqtSignal
from utils.logger import get_logger
import threading
_log = get_logger("system")
threat_log_lock = threading.Lock()
class SignalBus(QObject):
    log_updated = pyqtSignal(str, str)
    threat_detected = pyqtSignal(dict)
    behavior_threat_detected = pyqtSignal(dict)
    splash_updated = pyqtSignal(str)
    system_status_updated = pyqtSignal(dict)
    system_snapshot_updated = pyqtSignal(dict)
    loading_step_completed = pyqtSignal(str)
    loading_finished = pyqtSignal(object, object)
    threat_update_status_changed = pyqtSignal(str, str, str)
    start_scan = pyqtSignal()
    start_scan_path = pyqtSignal(str)
    scan_started = pyqtSignal()
    scan_finished = pyqtSignal()
    scan_progress_updated = pyqtSignal(dict)
    start_dynamic_scan = pyqtSignal(str)
    export_logs = pyqtSignal()
    export_report = pyqtSignal()
    dashboard_ready = pyqtSignal()
    tray_notification = pyqtSignal(str, str, str)
    behavior_alert = pyqtSignal(dict)
    network_alert = pyqtSignal(dict)
    usb_detected = pyqtSignal(dict)
    network_status_updated = pyqtSignal(str)
    block_request_emitted = pyqtSignal(str)
    sandbox_alert = pyqtSignal(dict)
    sandbox_log = pyqtSignal(str)
    system_monitor_log = pyqtSignal(str)
    dynamic_event_logged = pyqtSignal(dict)
    stop_scan_requested = pyqtSignal(object)
    config_updated = pyqtSignal(dict)
    def __init__(self):
        super().__init__()
_signal_bus = SignalBus()
def get_signal_bus() -> SignalBus:
    return _signal_bus
def emit_log(message: str, level: str = "info"):
    signal_bus = get_signal_bus()
    try:
        signal_bus.log_updated.emit(message, level)
    except RuntimeError:
        pass
    if level == "info":
        _log.info(message)
    elif level == "error":
        _log.error(message)
    elif level == "warning":
        _log.warning(message)
    else:
        _log.debug(message)
def emit_threat(threat: dict):
    _signal_bus.threat_detected.emit(threat)
def emit_behavior_threat(threat_data: dict):
    _log.warning(f"[Behavior Threat] {threat_data}")
    _signal_bus.behavior_threat_detected.emit(threat_data)
def emit_status(status: dict):
    _signal_bus.system_status_updated.emit(status)
def emit_loading_step(step: str):
    _signal_bus.loading_step_completed.emit(step)
def emit_loading_finished():
    _signal_bus.loading_finished.emit()
def emit_splash_update(status: str):
    _signal_bus.splash_updated.emit(status)
def emit_start_dynamic_scan(file_path: str):
    _log.info(f"[SignalBus] Emitting dynamic scan for: {file_path}")
    _signal_bus.start_dynamic_scan.emit(file_path)
def emit_behavior_alert(data: dict):
    _log.warning(f"[Behavior Alert] {data}")
    _signal_bus.behavior_alert.emit(data)
def emit_usb_detected(info: dict): 
    _log.info(f"[USB] Detected: {info.get('device', 'N/A')}")
    _signal_bus.usb_detected.emit(info)
def emit_sandbox_alert(alert: dict):
    _log.warning(f"[Sandbox Alert] {alert}")
    _signal_bus.sandbox_alert.emit(alert)
def emit_sandbox_log(log: str):
    _signal_bus.sandbox_log.emit(log)
def emit_system_monitor_log(log: str):
    _signal_bus.system_monitor_log.emit(log)
def emit_system_snapshot(snapshot: dict):
    """Convenience function to emit the latest system health snapshot."""
    get_signal_bus().system_snapshot_updated.emit(snapshot)
def emit_behavior_log(msg):
    if isinstance(msg, str):
        emit_behavior_alert({'description': msg})
    else:
        emit_behavior_alert(msg)
def emit_dynamic_event(data: dict):
    """Convenience function to emit a noteworthy dynamic event."""
    get_signal_bus().dynamic_event_logged.emit(data)
def emit_network_status(message: str):
    """Convenience function to emit a network status/heartbeat message."""
    get_signal_bus().network_status_updated.emit(message)
def emit_network_alert(alert_data: dict):
    """Convenience function to emit a network threat alert."""
    description = alert_data.get('description', 'No description provided')
    _log.warning(f"[Network Alert] {description}")
    _signal_bus.network_alert.emit(alert_data)
def emit_block_request(ip_address: str):
    """Emitted when a malicious IP should be blocked by the firewall."""
    get_signal_bus().block_request_emitted.emit(ip_address)
def emit_threat_update_status(component: str, message: str, status: str):
    """Convenience function to emit a structured threat intelligence update status."""
    get_signal_bus().threat_update_status_changed.emit(component, message, status)
def emit_tray_notification(title: str, message: str, level: str = "info"):
    """Emits a desktop notification request for the system tray."""
    get_signal_bus().tray_notification.emit(title, message, level)