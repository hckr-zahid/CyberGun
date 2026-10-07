from datetime import datetime
import subprocess
import os
import threading
import time
import re
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTextEdit, QPushButton,
    QGridLayout, QFrame, QSizePolicy, QStackedWidget, QHeaderView,
    QTableWidget, QTableWidgetItem, QMessageBox,QGroupBox,QProgressBar,QAbstractItemView,
    QFileDialog, QDialog
)
from PyQt5.QtGui import QFont, QColor, QBrush, QTextCursor
from PyQt5.QtCore import Qt, pyqtSlot, QTimer
from gui.components.SystemStatusDashboard import SystemStatusDashboard 
from gui.components.ThreatUpdatePanel import ThreatUpdatePanel
from core.QuarantineManager import QuarantineManager
from core.SignalBus import get_signal_bus, emit_log
from core.settings import (
    DEFAULT_SCAN_PATH,
    SYSTEM_LOG_PATH, THREAT_LOG_PATH
)
from gui.components.ThreatLogViewer import ThreatLogViewer
from gui.components.BehaviorFeed import BehaviorFeed
from gui.components.NetworkFeed import NetworkFeed
from gui.components.ConfigWindow import ConfigWindow
from gui.components.QuarantineViewer import QuarantineViewer
from gui.components.ForensicInvestigator import ForensicInvestigatorDialog
class SandboxLogViewer(QDialog):
    """A simple modal dialog to display sandbox log content."""
    def __init__(self, log_content: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Sandbox Analysis Report")
        self.setMinimumSize(800, 600)
        self.setStyleSheet("""
            QDialog { background-color: #0a0f14; border: 1px solid #00ffc8; }
            QTextEdit { background-color: #0a0f14; color: #00ffc8; border: 1px solid #00aaff; }
            QPushButton { 
                background-color: #00aaff; color: #000; border: none; 
                padding: 8px 16px; font-weight: bold;
            }
            QPushButton:hover { background-color: #33ffff; }
        """)
        layout = QVBoxLayout(self)
        log_display = QTextEdit()
        log_display.setReadOnly(True)
        log_display.setFont(QFont("Consolas", 10))
        log_display.setText(log_content)
        layout.addWidget(log_display)
        close_button = QPushButton("CLOSE")
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        button_layout.addWidget(close_button)
        layout.addLayout(button_layout)
        close_button.clicked.connect(self.accept)
        self.setLayout(layout)
class MainDashboard(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.signal_bus = get_signal_bus()
        self.quarantine_manager = QuarantineManager()
        self.setAcceptDrops(True)
        self.setStyleSheet("""
            QWidget { 
                background-color: #0a0f14; 
                color: #e0e0e0; 
                font-family: 'Consolas', 'Lucida Console', monospace;
                font-size: 11pt;
            }
            QStackedWidget { border: none; }
            /* --- Header and Navigation --- */
            #top_header_frame { 
                background-color: #121820;
                border-bottom: 2px solid #00aaff; 
            }
            #top_header_frame QPushButton {
                background-color: transparent;
                border: 1px solid transparent;
                padding: 8px 12px;
                font-weight: bold;
                color: #a0a0a0;
            }
            #top_header_frame QPushButton:hover {
                background-color: #1c2430;
                color: #ffffff;
            }
            #top_header_frame QPushButton:checked {
                background-color: #00aaff;
                color: #000000;
                border-bottom: 2px solid #33ffff;
            }
            /* --- Action Buttons (Scan, Stop, etc.) --- */
            #action_button {
                background-color: #00aaff;
                color: #000;
                font-weight: bold;
                border-radius: 4px;
                padding: 6px 14px;
            }
            #action_button:hover { background-color: #33ffff; }
            #action_button:disabled { background-color: #505050; color: #a0a0a0; }
            /* --- GroupBox Styling --- */
            QGroupBox {
                font-size: 10pt;
                font-weight: bold;
                color: #00aaff;
                border: 1px solid #1c2430;
                border-radius: 5px;
                margin-top: 1ex;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 0 10px;
                background-color: #121820;
                border-radius: 5px;
            }
            /* --- Table Styling --- */
            QTableWidget {
                background-color: #121820;
                border: 1px solid #1c2430;
                gridline-color: #1c2430;
                alternate-background-color: #161e28;
            }
            QHeaderView::section {
                background-color: #1c2430;
                color: #00aaff;
                padding: 4px;
                border: 1px solid #121820;
                font-weight: bold;
            }
            QTableWidget::item { padding-left: 5px; }
            QTableWidget::item:selected { background-color: #00aaff; color: black; }
            /* --- Other Widgets --- */
            QProgressBar {
                border: 1px solid #1c2430;
                border-radius: 5px;
                text-align: center;
                color: #e0e0e0;
                background-color: #121820;
            }
            QProgressBar::chunk { background-color: #00aaff; }
            QTextEdit {
                background-color: #121820;
                border: 1px solid #1c2430;
            }
            QLabel#main_header_label {
                font-size: 18pt;
                font-weight: bold;
                color: #e0e0e0;
                padding: 5px;
            }
        """)
        self.setWindowTitle("CyberGun")
        self.setMinimumSize(1200, 800)
        self.main_layout = QVBoxLayout()
        self.setLayout(self.main_layout)
        self.header_frame = self._create_header()
        self.main_layout.addWidget(self.header_frame)
        self.stacked_widget = QStackedWidget()
        self.main_layout.addWidget(self.stacked_widget, 1)
        self.dashboard_widget = self.create_dashboard_view()
        self.system_status_widget = SystemStatusDashboard() 
        self.threat_logs_widget = ThreatLogViewer()
        self.behavior_feed_widget = BehaviorFeed()
        self.network_feed_widget = NetworkFeed()
        self.quarantine_widget = QuarantineViewer()
        self.config_widget = ConfigWindow()
        self.stacked_widget.addWidget(self.dashboard_widget)
        self.stacked_widget.addWidget(self.system_status_widget)
        self.stacked_widget.addWidget(self.threat_logs_widget)
        self.stacked_widget.addWidget(self.behavior_feed_widget)
        self.stacked_widget.addWidget(self.network_feed_widget)
        self.stacked_widget.addWidget(self.quarantine_widget)
        self.stacked_widget.addWidget(self.config_widget)
        self.connect_signals()   
    def _create_header(self):
        header_frame = QFrame()
        header_frame.setObjectName("top_header_frame")
        header_layout = QHBoxLayout(header_frame)
        header_layout.setContentsMargins(10, 0, 10, 0)
        title_label = QLabel("CyberGun")
        title_label.setObjectName("main_header_label")
        header_layout.addWidget(title_label)
        self.dashboard_btn = QPushButton("Dashboard"); self.dashboard_btn.setCheckable(True); self.dashboard_btn.setChecked(True)
        self.system_status_btn = QPushButton("System Status"); self.system_status_btn.setCheckable(True)
        self.threat_logs_btn = QPushButton("Threat Logs"); self.threat_logs_btn.setCheckable(True)
        self.behavior_feed_btn = QPushButton("Behavior Feed"); self.behavior_feed_btn.setCheckable(True)
        self.network_feed_btn = QPushButton("Network Feed"); self.network_feed_btn.setCheckable(True)
        self.quarantine_btn = QPushButton("Quarantine"); self.quarantine_btn.setCheckable(True)
        self.config_btn = QPushButton("Config"); self.config_btn.setCheckable(True)
        nav_buttons = [self.dashboard_btn, self.system_status_btn, self.threat_logs_btn, 
                       self.behavior_feed_btn, self.network_feed_btn, self.quarantine_btn, self.config_btn]
        for btn in nav_buttons:
            header_layout.addWidget(btn)
        header_layout.addStretch()
        self.scan_btn = QPushButton("SCAN"); self.scan_btn.setObjectName("action_button")
        self.stop_scan_btn = QPushButton("STOP"); self.stop_scan_btn.setObjectName("action_button")
        self.stop_scan_btn.setEnabled(False)
        self.update_db_btn = QPushButton("UPDATE DB"); self.update_db_btn.setObjectName("action_button")
        self.report_btn = QPushButton("REPORT"); self.report_btn.setObjectName("action_button")
        self.forensic_btn = QPushButton("🔬 FORENSICS"); self.forensic_btn.setObjectName("action_button")
        self.forensic_btn.setStyleSheet("color: #00ffc8; border: 1px solid #00ffc8; font-weight: bold;")
        self.forensic_btn.clicked.connect(self.open_forensic_investigator)
        header_layout.addWidget(self.scan_btn)
        header_layout.addWidget(self.stop_scan_btn)
        header_layout.addWidget(self.update_db_btn)
        header_layout.addWidget(self.report_btn)
        header_layout.addWidget(self.forensic_btn)
        return header_frame
    def create_dashboard_view(self):
        dashboard_view = QWidget()
        content_grid = QGridLayout(dashboard_view)
        threat_group = QGroupBox("Detected Threats")
        threat_layout = QVBoxLayout(threat_group)
        self.threat_table = QTableWidget()
        self.threat_table.setColumnCount(4)
        self.threat_table.setHorizontalHeaderLabels(["File", "Method", "Malware", "Severity"])
        self.threat_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.threat_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.threat_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.threat_table.verticalHeader().setVisible(False)
        self.threat_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.threat_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.threat_table.setAlternatingRowColors(True)
        threat_layout.addWidget(self.threat_table)
        threat_btn_layout = QHBoxLayout()
        self.btn_investigate_threat = QPushButton("🔬 Forensically Investigate Selected File")
        self.btn_investigate_threat.setStyleSheet("background-color: #1a2533; color: #00ffc8; border: 1px solid #00ffc8; font-weight: bold; padding: 6px 12px; border-radius: 4px;")
        self.btn_investigate_threat.clicked.connect(self.investigate_selected_threat)
        threat_btn_layout.addWidget(self.btn_investigate_threat)
        threat_layout.addLayout(threat_btn_layout)
        right_column_layout = QVBoxLayout()
        self.threat_update_panel = ThreatUpdatePanel()
        system_group = QGroupBox("System Health")
        system_layout = QVBoxLayout(system_group)
        cpu_layout = QHBoxLayout(); cpu_layout.addWidget(QLabel("CPU:"))
        self.summary_cpu_bar = QProgressBar(); cpu_layout.addWidget(self.summary_cpu_bar)
        mem_layout = QHBoxLayout(); mem_layout.addWidget(QLabel("MEM:"))
        self.summary_mem_bar = QProgressBar(); mem_layout.addWidget(self.summary_mem_bar)
        system_layout.addLayout(cpu_layout); system_layout.addLayout(mem_layout)
        self.summary_process_table = QTableWidget()
        self.summary_process_table.setColumnCount(3)
        self.summary_process_table.setHorizontalHeaderLabels(["Process", "CPU %", "Mem %"])
        self.summary_process_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.summary_process_table.verticalHeader().setVisible(False)
        self.summary_process_table.setMaximumHeight(150)
        self.summary_process_table.setAlternatingRowColors(True)
        system_layout.addWidget(self.summary_process_table)
        right_column_layout.addWidget(self.threat_update_panel)
        right_column_layout.addWidget(system_group)
        right_column_layout.addStretch()
        live_feed_group = QGroupBox("Live Event Feed")
        live_feed_layout = QVBoxLayout(live_feed_group)
        self.live_event_table = QTableWidget()
        self.live_event_table.setColumnCount(3)
        self.live_event_table.setHorizontalHeaderLabels(["Time", "Event", "Details"])
        self.live_event_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.live_event_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.live_event_table.verticalHeader().setVisible(False)
        self.live_event_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.live_event_table.setAlternatingRowColors(True)
        live_feed_layout.addWidget(self.live_event_table)
        content_grid.addWidget(threat_group, 0, 0, 2, 1)
        content_grid.addLayout(right_column_layout, 0, 1)
        content_grid.addWidget(live_feed_group, 1, 1)
        content_grid.setColumnStretch(0, 3)
        content_grid.setColumnStretch(1, 2)
        return dashboard_view
    def connect_signals(self):
        self.dashboard_btn.clicked.connect(lambda: self.switch_view(0, self.dashboard_btn))
        self.system_status_btn.clicked.connect(lambda: self.switch_view(1, self.system_status_btn))
        self.threat_logs_btn.clicked.connect(lambda: self.switch_view(2, self.threat_logs_btn))
        self.behavior_feed_btn.clicked.connect(lambda: self.switch_view(3, self.behavior_feed_btn))
        self.network_feed_btn.clicked.connect(lambda: self.switch_view(4, self.network_feed_btn))
        self.quarantine_btn.clicked.connect(lambda: self.switch_view(5, self.quarantine_btn))
        self.config_btn.clicked.connect(lambda: self.switch_view(6, self.config_btn))
        self.scan_btn.clicked.connect(self.handle_scan)
        self.stop_scan_btn.clicked.connect(self.handle_stop_scan)
        self.report_btn.clicked.connect(self.handle_generate_report)
        self.signal_bus.export_report.connect(self.handle_generate_report)
        self.signal_bus.export_logs.connect(self._handle_export_logs)
        self.signal_bus.sandbox_log.connect(self.show_sandbox_log)
        self.signal_bus.log_updated.connect(self.handle_log_update)
        self.signal_bus.threat_detected.connect(self.add_threat_to_feed)
        self.signal_bus.dynamic_event_logged.connect(self.add_live_event)
        self.signal_bus.network_status_updated.connect(self.update_network_status_log)
        self.signal_bus.behavior_threat_detected.connect(self.on_behavioral_threat)
        self.signal_bus.network_alert.connect(self.append_network_threat_log)
        self.signal_bus.system_snapshot_updated.connect(self.update_system_status_display)
        self.threat_table.cellClicked.connect(self.open_file_location)
        self.threat_table.cellDoubleClicked.connect(self.on_threat_double_clicked)
        self.signal_bus.threat_update_status_changed.connect(self.manage_update_button_state)
    def _set_ui_for_scanning(self, is_scanning: bool):
        """A single method to correctly set the UI state for scanning."""
        self.scan_btn.setEnabled(not is_scanning)
        self.stop_scan_btn.setEnabled(is_scanning)
    @pyqtSlot(str, str)
    def handle_log_update(self, message: str, level: str):
        if isinstance(self.threat_logs_widget, ThreatLogViewer):
            self.threat_logs_widget.append_log(message)
    @pyqtSlot()
    def handle_scan(self):
        emit_log("[GUI] User triggered static scan.", "info")
        self.signal_bus.start_scan.emit()
        self._set_ui_for_scanning(True)
        QTimer.singleShot(1000, lambda: self._set_ui_for_scanning(False))
    @pyqtSlot()
    def handle_stop_scan(self):
        emit_log("[GUI] 🛑 Scan stop requested by user (feature requires backend implementation).", "warning")
        self.signal_bus.stop_scan_requested.emit()
        self._set_ui_for_scanning(False)
    @pyqtSlot()
    def export_logs(self):
        """Emits the signal to request a log export."""
        emit_log("[GUI] User requested to export logs.", "info")
        self.signal_bus.export_logs.emit()
    @pyqtSlot()
    def _handle_export_logs(self):
        """Slot that handles the actual logic of exporting logs."""
        try:
            import shutil
            default_filename = f"CyberGun_Logs_{datetime.now().strftime('%Y-%m-%d')}.zip"
            filePath, _ = QFileDialog.getSaveFileName(self, "Export Logs", default_filename, "Zip Files (*.zip);;All Files (*)")
            if not filePath:
                emit_log("[GUI] Log export cancelled by user.", "info")
                return
            temp_dir = f"temp_log_export_{os.urandom(4).hex()}"
            os.makedirs(temp_dir, exist_ok=True)
            if os.path.exists(SYSTEM_LOG_PATH):
                shutil.copy(SYSTEM_LOG_PATH, os.path.join(temp_dir, "system.log"))
            if os.path.exists(THREAT_LOG_PATH):
                shutil.copy(THREAT_LOG_PATH, os.path.join(temp_dir, "threats.log"))
            archive_name = filePath.rsplit('.zip', 1)[0]
            shutil.make_archive(archive_name, 'zip', temp_dir)
            shutil.rmtree(temp_dir)
            emit_log(f"[GUI] ✅ Logs successfully exported to {filePath}", "info")
            QMessageBox.information(self, "Export Successful", f"Logs have been exported to:\n{filePath}")
        except Exception as e:
            emit_log(f"[GUI] ❌ Failed to export logs: {e}", "error")
            QMessageBox.critical(self, "Export Failed", f"An unexpected error occurred while exporting logs:\n{e}")
    @pyqtSlot()
    def handle_generate_report(self):
        """Generates and opens the HTML Incident Response & Threat Audit report."""
        from utils.report_generator import generate_incident_report
        import webbrowser
        try:
            default_name = f"CyberGun_Audit_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            filePath, _ = QFileDialog.getSaveFileName(self, "Export Incident Report", default_name, "HTML Files (*.html);;All Files (*)")
            if not filePath:
                return
            report_path = generate_incident_report(filePath)
            webbrowser.open(f"file://{os.path.abspath(report_path)}")
            QMessageBox.information(self, "Audit Report Exported", f"Forensic incident report successfully generated and opened:\n\n{report_path}")
        except Exception as e:
            emit_log(f"[GUI] Failed to generate incident report: {e}", "error")
            QMessageBox.critical(self, "Report Failed", f"Could not generate incident report:\n{e}")
    def dragEnterEvent(self, event):
        """Accepts file/folder drag events onto the dashboard."""
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            event.ignore()
    def dropEvent(self, event):
        """Executes targeted static scanning on any dropped file or directory."""
        urls = event.mimeData().urls()
        if urls:
            path = urls[0].toLocalFile()
            if os.path.exists(path):
                emit_log(f"[Dashboard] Drag-and-drop target accepted: {path}. Starting scan...", "info")
                self.signal_bus.start_scan_path.emit(path)
                event.acceptProposedAction()
    @pyqtSlot(dict)
    def add_threat_to_feed(self, threat_dict: dict):
        file_path = threat_dict.get("file", "N/A")
        source_method = threat_dict.get("source", "Unknown")
        malware_name = threat_dict.get("malware_name", "Unknown")
        severity = threat_dict.get("severity", "low").upper()
        action_result = threat_dict.get("action_taken", "Logged") 
        row_pos = self.threat_table.rowCount()
        self.threat_table.insertRow(row_pos)
        display_text = os.path.basename(file_path)
        item_file = QTableWidgetItem(display_text)
        item_file.setToolTip(file_path) 
        item_method = QTableWidgetItem(source_method)
        item_malware = QTableWidgetItem(malware_name)
        item_level = QTableWidgetItem(severity)
        color_map = {
            "LOW": QColor("#27AE60"), 
            "MEDIUM": QColor("#F39C12"), 
            "HIGH": QColor("#E74C3C"), 
            "CRITICAL": QColor("#C0392B")
        }
        text_color = color_map.get(severity, QColor("#E74C3C"))
        for item in [item_file, item_method, item_malware, item_level]:
            item.setForeground(QBrush(text_color))
        level_font = QFont(); level_font.setBold(True); item_level.setFont(level_font)
        self.threat_table.setItem(row_pos, 0, item_file)
        self.threat_table.setItem(row_pos, 1, item_method)
        self.threat_table.setItem(row_pos, 2, item_malware)
        self.threat_table.setItem(row_pos, 3, item_level)
        self.threat_table.resizeRowsToContents()
    @pyqtSlot(dict)
    def update_system_status_display(self, snapshot: dict):
        if not snapshot:
            return
        self.summary_cpu_bar.setValue(int(snapshot.get('cpu_percent', 0.0)))
        self.summary_mem_bar.setValue(int(snapshot.get('mem_percent', 0.0)))
        procs = sorted(snapshot.get('processes', []), key=lambda p: p.get('cpu_percent', 0), reverse=True)[:3]
        self.summary_process_table.setRowCount(0)
        for proc in procs:
            row_pos = self.summary_process_table.rowCount()
            self.summary_process_table.insertRow(row_pos)
            self.summary_process_table.setItem(row_pos, 0, QTableWidgetItem(proc.get('name', 'N/A')))
            self.summary_process_table.setItem(row_pos, 1, QTableWidgetItem(f"{proc.get('cpu_percent', 0.0):.1f}"))
            self.summary_process_table.setItem(row_pos, 2, QTableWidgetItem(f"{proc.get('memory_percent', 0.0):.1f}"))
    @pyqtSlot(dict)
    def add_live_event(self, event_data: dict):
        table = self.live_event_table
        row_position = table.rowCount()
        table.insertRow(row_position)
        if row_position > 100:
            table.removeRow(0)
        timestamp = event_data.get('timestamp', time.time())
        ts_str = datetime.fromtimestamp(timestamp).strftime('%H:%M:%S')
        event_str = event_data.get('event', 'Unknown Event')
        details_str = event_data.get('details', '')
        event_type = event_data.get('type', 'info')
        ts_item = QTableWidgetItem(ts_str)
        event_item = QTableWidgetItem(event_str)
        details_item = QTableWidgetItem(details_str)
        color = QColor("#00ffc8")
        if event_type == 'warning': color = QColor("#F39C12")
        elif event_type == 'alert': color = QColor("#E74C3C")
        for item in [ts_item, event_item, details_item]: item.setForeground(QBrush(color))
        table.setItem(row_position, 0, ts_item)
        table.setItem(row_position, 1, event_item)
        table.setItem(row_position, 2, details_item)
        table.scrollToBottom()
    @pyqtSlot(dict)
    def on_behavioral_threat(self, threat_data: dict):
        if isinstance(self.behavior_feed_widget, BehaviorFeed):
            self.behavior_feed_widget.add_threat_entry(threat_data)
    def switch_view(self, index, clicked_button):
        self.stacked_widget.setCurrentIndex(index)
        buttons = [self.dashboard_btn, self.system_status_btn, self.threat_logs_btn, 
                   self.behavior_feed_btn, self.network_feed_btn, self.quarantine_btn, self.config_btn]
        for button in buttons:
            button.setChecked(button is clicked_button)
        if index == 5:
            self.quarantine_widget.refresh_table()
    @pyqtSlot(dict)
    def append_network_threat_log(self, alert_data: dict):
        pass
    @pyqtSlot(int, int)
    def open_file_location(self, row: int, column: int):
        if column == 0:
            item = self.threat_table.item(row, 0)
            if item:
                file_path_text = item.toolTip()
                if not file_path_text: return
                if not os.path.exists(file_path_text):
                    QMessageBox.warning(self, "File Not Found", f"The file may have been moved, quarantined or no longer exists:\n{file_path_text}")
                else:
                    subprocess.Popen(["explorer", "/select,", os.path.normpath(file_path_text)])
    @pyqtSlot(str)
    def update_network_status_log(self, message: str):
        pass
    @pyqtSlot(str, str, str)
    def manage_update_button_state(self, component: str, message: str, status: str):
        if component == 'overall':
            if status == 'running':
                self.update_db_btn.setEnabled(False)
                self.update_db_btn.setText("UPDATING...")
            else:
                self.update_db_btn.setEnabled(True)
                self.update_db_btn.setText("UPDATE DB")
    @pyqtSlot(str)
    def show_sandbox_log(self, log_content: str):
        self.sandbox_viewer = SandboxLogViewer(log_content, self)
        self.sandbox_viewer.exec_()
    @pyqtSlot()
    def open_forensic_investigator(self):
        """Opens the Forensic Investigator and Reverse Engineering Studio."""
        dlg = ForensicInvestigatorDialog(parent=self)
        dlg.exec_()
    @pyqtSlot()
    def investigate_selected_threat(self):
        """Investigates the currently highlighted threat in the feed."""
        selected = self.threat_table.selectedItems()
        if not selected:
            self.open_forensic_investigator()
            return
        row = selected[0].row()
        item = self.threat_table.item(row, 0)
        if item:
            file_path = item.toolTip()
            if file_path and os.path.exists(file_path):
                dlg = ForensicInvestigatorDialog(file_path=file_path, parent=self)
                dlg.exec_()
            else:
                self.open_forensic_investigator()
    @pyqtSlot(int, int)
    def on_threat_double_clicked(self, row: int, column: int):
        """Double-clicking a detected threat opens deep forensic reverse engineering inspection."""
        item = self.threat_table.item(row, 0)
        if item:
            file_path = item.toolTip()
            if file_path and os.path.exists(file_path):
                dlg = ForensicInvestigatorDialog(file_path=file_path, parent=self)
                dlg.exec_()