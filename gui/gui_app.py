import sys
import os
from PyQt5.QtWidgets import QApplication, QStackedWidget, QSystemTrayIcon, QMenu, QAction, QMessageBox
from PyQt5.QtCore import QTimer, pyqtSlot
from PyQt5.QtGui import QIcon
from gui.components.BootSplash import BootSplash
from gui.components.MainDashboard import MainDashboard
from core.SignalBus import get_signal_bus, emit_log
from core.settings import BASE_DIR
class GuiApp(QStackedWidget):
    """
    The main QStackedWidget that manages switching between the BootSplash and MainDashboard,
    plus System Tray background daemon and native desktop notifications.
    """
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CyberGun - Threat Mitigation Suite")
        self.setStyleSheet("background-color: #0b1016;")
        self.app_icon = QIcon()
        icon_paths = [
            os.path.join(str(BASE_DIR), "datasets", "icons", "icon.ico"),
            os.path.join(str(BASE_DIR), "datasets", "icons", "icon.png"),
            os.path.join(os.path.dirname(sys.executable), "datasets", "icons", "icon.ico"),
            os.path.join(os.path.dirname(sys.executable), "_internal", "datasets", "icons", "icon.ico"),
            os.path.join(os.path.dirname(sys.executable), "_internal", "datasets", "icons", "icon.png")
        ]
        for p in icon_paths:
            if os.path.exists(p):
                self.app_icon.addFile(p)
        if not self.app_icon.isNull():
            self.setWindowIcon(self.app_icon)
            QApplication.setWindowIcon(self.app_icon)
        else:
            emit_log(f"Application icon not found in standard paths", "warning")
        self.signal_bus = get_signal_bus()
        self.dashboard = None
        self._is_quitting = False
        self._setup_tray_icon()
        self.signal_bus.tray_notification.connect(self._handle_tray_notification)
        self.signal_bus.threat_detected.connect(self._handle_threat_detected)
        self.signal_bus.network_alert.connect(self._handle_network_alert)
        self.signal_bus.usb_detected.connect(self._handle_usb_detected)
        self.bootsplash = BootSplash()
        self.addWidget(self.bootsplash)
        self.setCurrentIndex(0)
        self.signal_bus.loading_finished.connect(self.initialize_dashboard)
        QTimer.singleShot(500, self.bootsplash.start_animation)
    def _setup_tray_icon(self):
        """Initializes the background System Tray icon and context menu."""
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return
        self.tray_icon = QSystemTrayIcon(self)
        if not self.app_icon.isNull():
            self.tray_icon.setIcon(self.app_icon)
        self.tray_icon.setToolTip("CyberGun Security Suite - Active Protection")
        tray_menu = QMenu()
        show_action = QAction("Open Dashboard", self)
        show_action.triggered.connect(self.restore_window)
        tray_menu.addAction(show_action)
        scan_action = QAction("Quick Scan", self)
        scan_action.triggered.connect(lambda: self.signal_bus.start_scan.emit())
        tray_menu.addAction(scan_action)
        report_action = QAction("Generate Incident Report", self)
        report_action.triggered.connect(lambda: self.signal_bus.export_report.emit())
        tray_menu.addAction(report_action)
        tray_menu.addSeparator()
        quit_action = QAction("Exit CyberGun", self)
        quit_action.triggered.connect(self.force_exit)
        tray_menu.addAction(quit_action)
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.activated.connect(self._on_tray_activated)
        self.tray_icon.show()
    def _on_tray_activated(self, reason):
        """Toggle dashboard on tray double-click or click."""
        if reason in (QSystemTrayIcon.Trigger, QSystemTrayIcon.DoubleClick):
            if self.isVisible():
                self.hide()
            else:
                self.restore_window()
    def restore_window(self):
        """Restores and focuses the main window from tray."""
        self.showNormal()
        self.activateWindow()
    def force_exit(self):
        """Completely terminates the application when selected from tray."""
        self._is_quitting = True
        QApplication.instance().quit()
    def closeEvent(self, event):
        """Minimizes to system tray instead of exiting when [X] is clicked."""
        if self._is_quitting:
            event.accept()
            return
        event.ignore()
        self.hide()
        if hasattr(self, 'tray_icon') and self.tray_icon.isVisible():
            self.tray_icon.showMessage(
                "CyberGun Active Guard",
                "CyberGun is continuing to protect your system in the background.",
                QSystemTrayIcon.Information,
                3000
            )
    @pyqtSlot(str, str, str)
    def _handle_tray_notification(self, title: str, message: str, level: str):
        if not hasattr(self, 'tray_icon') or not self.tray_icon.isVisible():
            return
        icon = QSystemTrayIcon.Information
        if level == "warning":
            icon = QSystemTrayIcon.Warning
        elif level == "critical":
            icon = QSystemTrayIcon.Critical
        self.tray_icon.showMessage(title, message, icon, 4000)
    @pyqtSlot(dict)
    def _handle_threat_detected(self, threat: dict):
        malware_name = threat.get("malware_name") or threat.get("description", "Malware")
        self._handle_tray_notification("Threat Neutralized", f"Threat mitigated: {malware_name}", "critical")
    @pyqtSlot(dict)
    def _handle_network_alert(self, alert_data: dict):
        desc = alert_data.get("description", "Suspicious traffic detected")
        self._handle_tray_notification("Network Guard Alert", desc, "warning")
    @pyqtSlot(dict)
    def _handle_usb_detected(self, info: dict):
        device = info.get("device", "USB Device")
        self._handle_tray_notification("Hardware Monitor", f"New device attached: {device}", "info")
    @pyqtSlot(object, object)
    def initialize_dashboard(self, static_engine, dynamic_engine):
        emit_log("[GuiApp] BootSplash finished. Initializing Main Dashboard...", "info")
        self.dashboard = MainDashboard()
        self.addWidget(self.dashboard)
        self.setCurrentIndex(1)
        self.removeWidget(self.bootsplash)
        self.bootsplash.deleteLater()
        emit_log("[GuiApp] Dashboard is now live.", "info")
        self.signal_bus.dashboard_ready.emit()
def run_gui():
    """
    The main entry point for starting the application.
    This function will be called by your top-level main.py.
    """
    app = QApplication(sys.argv)
    app.setApplicationName("CyberGun")
    app.setOrganizationName("CyberGun Security")
    icon_path = os.path.join(BASE_DIR, "datasets", "icons", "app_icon.png")
    if os.path.exists(icon_path):
        app.setWindowIcon(QIcon(icon_path))
    window = GuiApp()
    window.resize(1280, 800)
    window.show()
    sys.exit(app.exec_())