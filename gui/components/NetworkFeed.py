import psutil
from datetime import datetime
import time
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTableWidget,
    QTableWidgetItem, QHeaderView, QAbstractItemView, QPushButton,
    QLineEdit, QTabWidget, QMessageBox
)
from PyQt5.QtGui import QFont, QColor, QBrush
from PyQt5.QtCore import Qt, pyqtSlot, QTimer, QThread, pyqtSignal
from core.SignalBus import get_signal_bus, emit_log
from core.database_manager import get_db_manager
class SocketHunterWorker(QThread):
    """Background worker that inspects open network sockets and cross-checks SQLite intelligence."""
    sockets_ready = pyqtSignal(list)
    def __init__(self, db_manager):
        super().__init__()
        self.db = db_manager
    def run(self):
        connections = []
        try:
            net_conns = psutil.net_connections(kind='inet')
        except Exception:
            self.sockets_ready.emit([])
            return
        pid_name_map = {}
        for conn in net_conns:
            if not conn.raddr:
                continue
            pid = conn.pid or 0
            if pid not in pid_name_map:
                try:
                    p = psutil.Process(pid)
                    pid_name_map[pid] = p.name()
                except Exception:
                    pid_name_map[pid] = "System / Unknown"
            p_name = pid_name_map.get(pid, "Unknown")
            laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
            proto = "TCP" if conn.type == 1 else "UDP"
            status = conn.status
            remote_ip = conn.raddr.ip
            threat_eval = "Clean (Safe Connection)"
            color_hex = "#10b981"
            if remote_ip.startswith(('127.', '10.', '192.168.', '172.16.', '0.0.0.0', '::1')):
                threat_eval = "Local / Trusted Intranet"
                color_hex = "#6b7280"
            else:
                db_threat = self.db.check_ip(remote_ip)
                if db_threat:
                    threat_eval = f"🚨 THREAT: {db_threat.get('threat_type', 'Blacklist IP')} ({db_threat.get('severity', 'high').upper()})"
                    color_hex = "#ef4444"
            connections.append({
                "pid": pid, "name": p_name, "laddr": laddr, "raddr": raddr,
                "proto": proto, "state": status, "eval": threat_eval, "color_hex": color_hex
            })
        connections.sort(key=lambda x: (not x['eval'].startswith("🚨"), x['pid']))
        self.sockets_ready.emit(connections)
class NetworkFeed(QWidget):
    """
    Enhanced Real-Time Network Threat & Socket Monitor with QThread background processing.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet("background-color: #0b1016; color: #FFFFFF;")
        self.db = get_db_manager()
        self._sock_worker = None
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(10)
        header_layout = QHBoxLayout()
        self.title = QLabel("🌐 Live Network Threat & Socket Monitor")
        self.title.setFont(QFont("Consolas", 14, QFont.Bold))
        self.title.setStyleSheet("color: #00ffc8;")
        header_layout.addWidget(self.title)
        header_layout.addStretch()
        self.ip_lookup_input = QLineEdit()
        self.ip_lookup_input.setPlaceholderText("Lookup IP / Domain in DB...")
        self.ip_lookup_input.setStyleSheet("""
            QLineEdit {
                background-color: #131c26; color: #FFFFFF;
                border: 1px solid #1f2d3d; border-radius: 4px;
                padding: 4px 8px; font-family: Consolas; min-width: 200px;
            }
        """)
        header_layout.addWidget(self.ip_lookup_input)
        self.btn_lookup = QPushButton("🔎 Query Intel")
        self.btn_lookup.clicked.connect(self._lookup_ip_in_db)
        header_layout.addWidget(self.btn_lookup)
        self.btn_refresh = QPushButton("🔄 Refresh Sockets")
        self.btn_refresh.clicked.connect(self.refresh_active_sockets)
        header_layout.addWidget(self.btn_refresh)
        self.btn_kill = QPushButton("🛑 Terminate Socket Process")
        self.btn_kill.setStyleSheet("background-color: #3b1111; color: #ef4444; border: 1px solid #ef4444; font-weight: bold; border-radius: 4px; padding: 5px 12px;")
        self.btn_kill.clicked.connect(self._terminate_socket_process)
        header_layout.addWidget(self.btn_kill)
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
        self.threat_table.setColumnCount(7)
        self.threat_table.setHorizontalHeaderLabels(["Time", "Process", "Source IP", "Destination IP", "Port/Proto", "Threat Classification", "Action Taken"])
        self._style_table(self.threat_table)
        threat_layout.addWidget(self.threat_table)
        self.tabs.addTab(self.threat_tab, "🚨 Malicious Connection Alerts")
        self.sockets_tab = QWidget()
        sockets_layout = QVBoxLayout(self.sockets_tab)
        sockets_layout.setContentsMargins(5, 5, 5, 5)
        self.sockets_table = QTableWidget()
        self.sockets_table.setColumnCount(7)
        self.sockets_table.setHorizontalHeaderLabels(["PID", "Process Name", "Local Address", "Remote Address", "Proto", "State", "Reputation & Intelligence"])
        self._style_table(self.sockets_table)
        sockets_layout.addWidget(self.sockets_table)
        self.tabs.addTab(self.sockets_tab, "📡 Live Active Sockets (Inspector)")
        main_layout.addWidget(self.tabs)
        self.signal_bus = get_signal_bus()
        self.signal_bus.network_alert.connect(self.add_threat_alert)
        self.socket_timer = QTimer(self)
        self.socket_timer.timeout.connect(self.refresh_active_sockets)
        self.socket_timer.start(8000)
        QTimer.singleShot(900, self.refresh_active_sockets)
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
    def add_threat_alert(self, alert: dict):
        row = self.threat_table.rowCount()
        self.threat_table.insertRow(row)
        ts_str = datetime.fromtimestamp(alert.get('timestamp', time.time())).strftime('%H:%M:%S')
        process_name = alert.get('process_name', 'N/A')
        src_ip = alert.get('src_ip', 'N/A')
        dst_ip = alert.get('dst_ip', 'N/A')
        port_proto = f"{alert.get('port', 'N/A')}/{alert.get('protocol', 'N/A')}"
        threat_type = alert.get('threat_type', 'Blacklisted Endpoint')
        action = alert.get('action_taken', 'Blocked & Logged')
        item_ts = QTableWidgetItem(ts_str)
        item_process = QTableWidgetItem(process_name)
        item_src_ip = QTableWidgetItem(src_ip)
        item_dst_ip = QTableWidgetItem(dst_ip)
        item_port = QTableWidgetItem(port_proto)
        item_type = QTableWidgetItem(threat_type)
        item_action = QTableWidgetItem(action)
        red = QColor("#ef4444")
        for item in [item_ts, item_process, item_src_ip, item_dst_ip, item_port, item_type, item_action]:
            item.setForeground(QBrush(red))
        self.threat_table.setItem(row, 0, item_ts)
        self.threat_table.setItem(row, 1, item_process)
        self.threat_table.setItem(row, 2, item_src_ip)
        self.threat_table.setItem(row, 3, item_dst_ip)
        self.threat_table.setItem(row, 4, item_port)
        self.threat_table.setItem(row, 5, item_type)
        self.threat_table.setItem(row, 6, item_action)
        self.threat_table.scrollToBottom()
    def refresh_active_sockets(self):
        """Asynchronously spawns worker thread to inspect network sockets."""
        if not self.isVisible():
            return
        if self._sock_worker and self._sock_worker.isRunning():
            return
        self._sock_worker = SocketHunterWorker(self.db)
        self._sock_worker.sockets_ready.connect(self._on_sockets_loaded)
        self._sock_worker.start()
    @pyqtSlot(list)
    def _on_sockets_loaded(self, connections: list):
        """Non-blocking update of the sockets table."""
        self.sockets_table.setSortingEnabled(False)
        self.sockets_table.setRowCount(len(connections))
        for row, c in enumerate(connections):
            i_pid = QTableWidgetItem(str(c['pid']))
            i_name = QTableWidgetItem(c['name'])
            i_laddr = QTableWidgetItem(c['laddr'])
            i_raddr = QTableWidgetItem(c['raddr'])
            i_proto = QTableWidgetItem(c['proto'])
            i_state = QTableWidgetItem(c['state'])
            i_eval = QTableWidgetItem(c['eval'])
            color = QColor(c.get('color_hex', "#10b981"))
            i_eval.setForeground(QBrush(color))
            if c['eval'].startswith("🚨"):
                i_name.setForeground(QBrush(color))
                i_raddr.setForeground(QBrush(color))
            self.sockets_table.setItem(row, 0, i_pid)
            self.sockets_table.setItem(row, 1, i_name)
            self.sockets_table.setItem(row, 2, i_laddr)
            self.sockets_table.setItem(row, 3, i_raddr)
            self.sockets_table.setItem(row, 4, i_proto)
            self.sockets_table.setItem(row, 5, i_state)
            self.sockets_table.setItem(row, 6, i_eval)
        self.sockets_table.setSortingEnabled(True)
    def _lookup_ip_in_db(self):
        query = self.ip_lookup_input.text().strip()
        if not query:
            QMessageBox.information(self, "Input Required", "Enter an IP address or domain to query.")
            return
        res = self.db.check_ip(query)
        if res:
            msg = (
                f"🚨 THREAT FOUND IN DATABASE:\n\n"
                f"Target          : {res.get('ip_address')}\n"
                f"Threat Type     : {res.get('threat_type')}\n"
                f"Severity        : {res.get('severity', 'high').upper()}\n"
                f"Confidence Score: {res.get('confidence', 1.0)}\n"
                f"Data Source     : {res.get('source_feed', 'Local Intel')}\n"
                f"Description     : {res.get('description', 'Known malicious C2 / botnet')}"
            )
            QMessageBox.critical(self, "Reputation Alert: MALICIOUS", msg)
        else:
            QMessageBox.information(self, "Reputation Clean", f"✅ Target '{query}' was NOT found in the current intelligence database.\nNo known malicious history recorded.")
    def _terminate_socket_process(self):
        selected = self.sockets_table.selectedItems()
        if not selected:
            QMessageBox.warning(self, "No Selection", "Please select a connection row in the Sockets table to terminate its process.")
            return
        row = selected[0].row()
        pid_item = self.sockets_table.item(row, 0)
        name_item = self.sockets_table.item(row, 1)
        raddr_item = self.sockets_table.item(row, 3)
        if not pid_item: return
        try:
            pid = int(pid_item.text())
            name = name_item.text() if name_item else "Unknown"
            raddr = raddr_item.text() if raddr_item else "Unknown"
        except ValueError:
            QMessageBox.warning(self, "Invalid PID", "Could not parse process PID.")
            return
        confirm = QMessageBox.question(
            self, "Confirm Process Termination",
            f"Are you sure you want to terminate the process managing this socket?\n\nPID: {pid} ({name})\nRemote Address: {raddr}\n\nThis will immediately disconnect the socket.",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        if confirm != QMessageBox.Yes:
            return
        try:
            p = psutil.Process(pid)
            p.kill()
            emit_log(f"[NetworkFeed] 🛑 Terminated socket process PID {pid} ({name}).", "warning")
            QMessageBox.information(self, "Process Terminated", f"Successfully terminated PID {pid} ({name}).")
            self.refresh_active_sockets()
        except psutil.NoSuchProcess:
            QMessageBox.information(self, "Already Closed", "The process has already terminated.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to terminate PID {pid}: {e}")