import os
import psutil
from datetime import datetime
import time
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTableWidget,
    QTableWidgetItem, QHeaderView, QAbstractItemView, QPushButton,
    QLineEdit, QTabWidget, QMessageBox, QDialog, QTextEdit
)
from PyQt5.QtGui import QFont, QColor, QBrush
from PyQt5.QtCore import Qt, pyqtSlot, QTimer, QThread, pyqtSignal
from core.SignalBus import get_signal_bus, emit_log
class ProcessHunterWorker(QThread):
    """Background worker that collects process heuristics without blocking the GUI."""
    processes_ready = pyqtSignal(list)
    def run(self):
        processes = []
        for p in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info', 'exe', 'username']):
            try:
                info = p.info
                if not info['name']:
                    continue
                pid = info['pid']
                name = info['name']
                cpu = p.cpu_percent(interval=None)
                mem_mb = round(info['memory_info'].rss / (1024 * 1024), 1) if info['memory_info'] else 0.0
                exe = info['exe'] or "System / Protected"
                user = info['username'] or "SYSTEM"
                exe_lower = exe.lower()
                status = "Normal"
                color_hex = "#10b981"
                suspicious_paths = ['\\temp\\', '\\appdata\\local\\temp', '\\downloads\\', '\\users\\public\\']
                script_hosts = ['powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'certutil.exe']
                if any(sp in exe_lower for sp in suspicious_paths):
                    status = "⚠️ Executable in Temp/User Path"
                    color_hex = "#f59e0b"
                elif name.lower() in script_hosts:
                    status = "⚠️ Script Host Active"
                    color_hex = "#f59e0b"
                elif cpu > 70.0:
                    status = "⚠️ High CPU Spike (Potential Miner)"
                    color_hex = "#ef4444"
                processes.append({
                    "pid": pid, "name": name, "cpu": cpu, "mem_mb": mem_mb,
                    "status": status, "user": user, "exe": exe, "color_hex": color_hex
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        processes.sort(key=lambda x: (x['status'] == "Normal", -x['cpu']))
        self.processes_ready.emit(processes)
class ProcessForensicDialog(QDialog):
    """Popup modal showing detailed forensic information for a specific PID."""
    def __init__(self, pid: int, parent=None):
        super().__init__(parent)
        self.pid = pid
        self.setWindowTitle(f"Forensic Process Inspection - PID {pid}")
        self.resize(700, 500)
        self.setStyleSheet("""
            QDialog { background-color: #0b1016; color: #FFFFFF; font-family: Consolas; }
            QTextEdit { background-color: #121820; color: #00ffc8; border: 1px solid #1f2d3d; font-size: 12px; }
            QPushButton { background-color: #1a2533; color: #00ffc8; border: 1px solid #00aaff; padding: 6px 14px; font-weight: bold; border-radius: 4px; }
            QPushButton:hover { background-color: #00aaff; color: #000; }
        """)
        layout = QVBoxLayout(self)
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        layout.addWidget(self.log_text)
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        btn_close = QPushButton("CLOSE")
        btn_close.clicked.connect(self.accept)
        btn_layout.addWidget(btn_close)
        layout.addLayout(btn_layout)
        self._populate_forensic_data()
    def _populate_forensic_data(self):
        try:
            p = psutil.Process(self.pid)
            lines = [
                f"=== FORENSIC SNAPSHOT FOR PID: {self.pid} ===",
                f"Process Name      : {p.name()}",
                f"Executable Path   : {p.exe()}",
                f"Current Status    : {p.status()}",
                f"Command Line      : {' '.join(p.cmdline()) if p.cmdline() else 'N/A'}",
                f"Username          : {p.username()}",
                f"Created Timestamp : {datetime.fromtimestamp(p.create_time()).strftime('%Y-%m-%d %H:%M:%S')}",
                f"Parent PID        : {p.ppid()}",
                f"Thread Count      : {p.num_threads()}",
                f"Memory (RSS)      : {p.memory_info().rss / (1024*1024):.2f} MB",
                f"Memory (VMS)      : {p.memory_info().vms / (1024*1024):.2f} MB",
                "",
                "--- Open File Descriptors / Handles (Sample) ---"
            ]
            try:
                open_files = p.open_files()
                if open_files:
                    for f in open_files[:15]:
                        lines.append(f"  • {f.path}")
                else:
                    lines.append("  (No regular open files detected)")
            except Exception as fe:
                lines.append(f"  (Cannot read open files: {fe})")
            lines.append("")
            lines.append("--- Network Connections ---")
            try:
                conns = p.connections(kind='inet')
                if conns:
                    for c in conns:
                        l = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "N/A"
                        r = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "LISTEN"
                        lines.append(f"  • {c.type} {l} -> {r} ({c.status})")
                else:
                    lines.append("  (No active network sockets)")
            except Exception as ce:
                lines.append(f"  (Cannot read connections: {ce})")
            self.log_text.setText("\n".join(lines))
        except psutil.NoSuchProcess:
            self.log_text.setText(f"Process PID {self.pid} has already terminated.")
        except Exception as e:
            self.log_text.setText(f"Failed to gather forensic telemetry for PID {self.pid}: {e}")
class BehaviorFeed(QWidget):
    """
    Enhanced Process Behavior & Threat Hunter Panel with Threaded Enumeration.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet("background-color: #0b1016; color: #FFFFFF;")
        self._proc_worker = None
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(10)
        header_layout = QHBoxLayout()
        self.title = QLabel("🧠 Process Behavior & Threat Hunter")
        self.title.setFont(QFont("Consolas", 14, QFont.Bold))
        self.title.setStyleSheet("color: #00ffc8;")
        header_layout.addWidget(self.title)
        header_layout.addStretch()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Filter by PID or Process Name...")
        self.search_input.setStyleSheet("""
            QLineEdit {
                background-color: #131c26; color: #FFFFFF;
                border: 1px solid #1f2d3d; border-radius: 4px;
                padding: 4px 8px; font-family: Consolas; min-width: 220px;
            }
        """)
        self.search_input.textChanged.connect(self._filter_tables)
        header_layout.addWidget(self.search_input)
        self.btn_refresh = QPushButton("🔄 Refresh")
        self.btn_refresh.clicked.connect(self.refresh_process_list)
        header_layout.addWidget(self.btn_refresh)
        self.btn_kill = QPushButton("🛑 Terminate (Kill PID)")
        self.btn_kill.setStyleSheet("background-color: #3b1111; color: #ef4444; border: 1px solid #ef4444; font-weight: bold; border-radius: 4px; padding: 5px 12px;")
        self.btn_kill.clicked.connect(self._kill_selected_process)
        header_layout.addWidget(self.btn_kill)
        self.btn_inspect = QPushButton("🔍 Forensic Inspect")
        self.btn_inspect.setStyleSheet("background-color: #1a2533; color: #f59e0b; border: 1px solid #f59e0b; font-weight: bold; border-radius: 4px; padding: 5px 12px;")
        self.btn_inspect.clicked.connect(self._inspect_selected_process)
        header_layout.addWidget(self.btn_inspect)
        main_layout.addLayout(header_layout)
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane { border: 1px solid #1f2d3d; background-color: #0e1620; }
            QTabBar::tab {
                background-color: #131c26; color: #9ca3af;
                padding: 8px 16px; border: 1px solid #1f2d3d;
                border-bottom: none; font-family: Consolas; font-weight: bold;
            }
            QTabBar::tab:selected { background-color: #0e1620; color: #00ffc8; border-top: 2px solid #00ffc8; }
        """)
        self.threat_tab = QWidget()
        threat_layout = QVBoxLayout(self.threat_tab)
        threat_layout.setContentsMargins(5, 5, 5, 5)
        self.threat_table = QTableWidget()
        self.threat_table.setColumnCount(6)
        self.threat_table.setHorizontalHeaderLabels(["Time", "Process", "PID", "Behavioral Anomaly", "Severity", "Detection Source"])
        self._style_table(self.threat_table)
        threat_layout.addWidget(self.threat_table)
        self.tabs.addTab(self.threat_tab, "🚨 Real-Time Behavioral Alerts")
        self.hunter_tab = QWidget()
        hunter_layout = QVBoxLayout(self.hunter_tab)
        hunter_layout.setContentsMargins(5, 5, 5, 5)
        self.process_table = QTableWidget()
        self.process_table.setColumnCount(7)
        self.process_table.setHorizontalHeaderLabels(["PID", "Process Name", "CPU %", "RAM (MB)", "Behavior Status", "User", "Executable Path"])
        self._style_table(self.process_table)
        hunter_layout.addWidget(self.process_table)
        self.tabs.addTab(self.hunter_tab, "🎯 Live Process Threat Hunter")
        main_layout.addWidget(self.tabs)
        self.signal_bus = get_signal_bus()
        self.signal_bus.behavior_threat_detected.connect(self.add_behavioral_threat_entry)
        self.refresh_timer = QTimer(self)
        self.refresh_timer.timeout.connect(self.refresh_process_list)
        self.refresh_timer.start(8000)
        QTimer.singleShot(800, self.refresh_process_list)
    def _style_table(self, table: QTableWidget):
        table.horizontalHeader().setStretchLastSection(True)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setSelectionMode(QAbstractItemView.SingleSelection)
        table.verticalHeader().setVisible(False)
        table.setSortingEnabled(True)
        table.setStyleSheet("""
            QTableWidget {
                background-color: #0e1620; color: #d1d5db;
                gridline-color: #1f2d3d; border: 1px solid #1f2d3d;
                font-family: Consolas; font-size: 11px;
            }
            QHeaderView::section {
                background-color: #131c26; color: #00ffc8;
                font-weight: bold; padding: 6px; border: 1px solid #1f2d3d;
            }
            QTableWidget::item:selected {
                background-color: #1e3a5f; color: #00ffc8;
            }
        """)
    @pyqtSlot(dict)
    def add_behavioral_threat_entry(self, threat_data: dict):
        row = self.threat_table.rowCount()
        self.threat_table.insertRow(row)
        timestamp = threat_data.get('timestamp', time.time())
        ts_str = datetime.fromtimestamp(timestamp).strftime('%H:%M:%S')
        process_name = threat_data.get('process_name', 'N/A')
        pid = str(threat_data.get('pid', 'N/A'))
        description = threat_data.get('description', threat_data.get('anomaly', 'Suspicious activity detected'))
        severity = threat_data.get('severity', 'high').upper()
        model_details = threat_data.get('model', 'Behavior ML')
        ts_item = QTableWidgetItem(ts_str)
        process_item = QTableWidgetItem(process_name)
        pid_item = QTableWidgetItem(pid)
        desc_item = QTableWidgetItem(description)
        severity_item = QTableWidgetItem(severity)
        model_item = QTableWidgetItem(model_details)
        color = QColor("#ef4444") if severity.lower() == 'critical' else (QColor("#f59e0b") if severity.lower() == 'high' else QColor("#38bdf8"))
        for item in [ts_item, process_item, pid_item, desc_item, severity_item, model_item]:
            item.setForeground(QBrush(color))
        self.threat_table.setItem(row, 0, ts_item)
        self.threat_table.setItem(row, 1, process_item)
        self.threat_table.setItem(row, 2, pid_item)
        self.threat_table.setItem(row, 3, desc_item)
        self.threat_table.setItem(row, 4, severity_item)
        self.threat_table.setItem(row, 5, model_item)
        self.threat_table.scrollToBottom()
    def refresh_process_list(self):
        """Asynchronously spawns worker thread to inspect processes."""
        if not self.isVisible():
            return
        if self._proc_worker and self._proc_worker.isRunning():
            return
        self._proc_worker = ProcessHunterWorker()
        self._proc_worker.processes_ready.connect(self._on_processes_loaded)
        self._proc_worker.start()
    @pyqtSlot(list)
    def _on_processes_loaded(self, processes: list):
        """Non-blocking update of the QTableWidget."""
        self.process_table.setSortingEnabled(False)
        self.process_table.setRowCount(len(processes))
        for row, pr in enumerate(processes):
            item_pid = QTableWidgetItem(str(pr['pid']))
            item_name = QTableWidgetItem(pr['name'])
            item_cpu = QTableWidgetItem(f"{pr['cpu']:.1f}%")
            item_mem = QTableWidgetItem(f"{pr['mem_mb']} MB")
            item_status = QTableWidgetItem(pr['status'])
            item_user = QTableWidgetItem(str(pr['user']))
            item_exe = QTableWidgetItem(str(pr['exe']))
            color = QColor(pr.get('color_hex', "#10b981"))
            item_status.setForeground(QBrush(color))
            if pr['status'] != "Normal":
                item_name.setForeground(QBrush(color))
            self.process_table.setItem(row, 0, item_pid)
            self.process_table.setItem(row, 1, item_name)
            self.process_table.setItem(row, 2, item_cpu)
            self.process_table.setItem(row, 3, item_mem)
            self.process_table.setItem(row, 4, item_status)
            self.process_table.setItem(row, 5, item_user)
            self.process_table.setItem(row, 6, item_exe)
        self.process_table.setSortingEnabled(True)
    def _filter_tables(self, text: str):
        filter_text = text.strip().lower()
        for table in [self.threat_table, self.process_table]:
            for row in range(table.rowCount()):
                match = False
                for col in range(table.columnCount()):
                    item = table.item(row, col)
                    if item and filter_text in item.text().lower():
                        match = True
                        break
                table.setRowHidden(row, not match)
    def _kill_selected_process(self):
        current_table = self.threat_table if self.tabs.currentIndex() == 0 else self.process_table
        selected = current_table.selectedItems()
        if not selected:
            QMessageBox.warning(self, "No Selection", "Please select a process row to terminate.")
            return
        row = selected[0].row()
        pid_col = 2 if self.tabs.currentIndex() == 0 else 0
        name_col = 1
        pid_item = current_table.item(row, pid_col)
        name_item = current_table.item(row, name_col)
        if not pid_item:
            return
        try:
            pid = int(pid_item.text())
            name = name_item.text() if name_item else "Unknown"
        except ValueError:
            QMessageBox.warning(self, "Invalid PID", f"Could not parse PID: {pid_item.text()}")
            return
        confirm = QMessageBox.question(
            self, "Confirm Process Termination",
            f"Are you sure you want to terminate malicious process:\n\nPID: {pid} ({name})\n\nThis will instantly halt execution.",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        if confirm != QMessageBox.Yes:
            return
        try:
            p = psutil.Process(pid)
            p.kill()
            emit_log(f"[BehaviorFeed] 🛑 Terminated process PID {pid} ({name}).", "warning")
            QMessageBox.information(self, "Process Terminated", f"Successfully terminated PID {pid} ({name}).")
            self.refresh_process_list()
        except psutil.NoSuchProcess:
            QMessageBox.information(self, "Already Closed", f"Process PID {pid} has already terminated.")
        except psutil.AccessDenied:
            QMessageBox.critical(self, "Access Denied", f"Cannot terminate PID {pid}: Access Denied.\nPlease run CyberGun as Administrator.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to terminate PID {pid}: {e}")
    def _inspect_selected_process(self):
        current_table = self.threat_table if self.tabs.currentIndex() == 0 else self.process_table
        selected = current_table.selectedItems()
        if not selected:
            QMessageBox.warning(self, "No Selection", "Please select a process row to inspect.")
            return
        row = selected[0].row()
        pid_col = 2 if self.tabs.currentIndex() == 0 else 0
        pid_item = current_table.item(row, pid_col)
        if not pid_item: return
        try:
            pid = int(pid_item.text())
            dlg = ProcessForensicDialog(pid, self)
            dlg.exec_()
        except ValueError:
            QMessageBox.warning(self, "Invalid PID", f"Could not parse PID: {pid_item.text()}")