from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QGridLayout, QLabel, QProgressBar,
    QTableWidget, QTableWidgetItem, QHeaderView, QGroupBox,
    QMenu, QMessageBox
)
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt, pyqtSlot, QPoint
import time
import psutil
import platform
import socket
from core.SignalBus import get_signal_bus
class SystemStatusDashboard(QWidget):
    """A detailed, interactive dashboard for real-time system monitoring."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.pid_row_map: dict[int, QTableWidgetItem] = {}
        self.previous_snapshot = None
        self.total_bytes_sent = 0
        self.total_bytes_recv = 0
        self.start_time = time.time()
        self.signal_bus = get_signal_bus()
        self.signal_bus.system_snapshot_updated.connect(self.update_data)
        top_layout = QGridLayout()
        main_layout = QVBoxLayout(self)
        main_layout.addLayout(top_layout)
        sys_info_group = self._create_system_info_panel()
        resource_group = self._create_resource_bars()
        disk_group = self._create_disk_io_panel()
        network_group = self._create_network_panel()
        self.process_group, self.process_table = self._create_process_table()
        top_layout.addWidget(sys_info_group, 0, 0)
        top_layout.addWidget(resource_group, 0, 1)
        top_layout.addWidget(disk_group, 1, 0)
        top_layout.addWidget(network_group, 1, 1)
        main_layout.addWidget(self.process_group)
    def _create_system_info_panel(self) -> QGroupBox:
        group_box = QGroupBox("System Information")
        layout = QGridLayout(group_box)
        total_ram_gb = psutil.virtual_memory().total / (1024**3)
        layout.addWidget(QLabel("Hostname:"), 0, 0)
        layout.addWidget(QLabel(f"{socket.gethostname()}"), 0, 1)
        layout.addWidget(QLabel("OS:"), 1, 0)
        layout.addWidget(QLabel(f"{platform.system()} {platform.release()}"), 1, 1)
        layout.addWidget(QLabel("CPU:"), 2, 0)
        layout.addWidget(QLabel(f"{psutil.cpu_count(logical=True)} Cores @ {psutil.cpu_freq().max:.0f} MHz"), 2, 1)
        layout.addWidget(QLabel("Memory:"), 3, 0)
        layout.addWidget(QLabel(f"{total_ram_gb:.2f} GB Total"), 3, 1)
        return group_box
    def _create_resource_bars(self) -> QGroupBox:
        group_box = QGroupBox("Live Resources")
        layout = QGridLayout(group_box)
        self.cpu_bar = QProgressBar()
        self.mem_bar = QProgressBar()
        layout.addWidget(QLabel("CPU Usage:"), 0, 0)
        layout.addWidget(self.cpu_bar, 0, 1)
        layout.addWidget(QLabel("Memory Usage:"), 1, 0)
        layout.addWidget(self.mem_bar, 1, 1)
        return group_box
    def _create_disk_io_panel(self) -> QGroupBox:
        group_box = QGroupBox("Disk I/O")
        layout = QGridLayout(group_box)
        self.disk_read_label = QLabel("Calculating...")
        self.disk_write_label = QLabel("Calculating...")
        layout.addWidget(QLabel("Read Speed:"), 0, 0)
        layout.addWidget(self.disk_read_label, 0, 1)
        layout.addWidget(QLabel("Write Speed:"), 1, 0)
        layout.addWidget(self.disk_write_label, 1, 1)
        return group_box
    def _create_network_panel(self) -> QGroupBox:
        group_box = QGroupBox("Network Traffic")
        layout = QGridLayout(group_box)
        self.upload_label = QLabel("Calculating...")
        self.download_label = QLabel("Calculating...")
        self.total_upload_label = QLabel("0 B")
        self.total_download_label = QLabel("0 B")
        layout.addWidget(QLabel("Upload Speed:"), 0, 0)
        layout.addWidget(self.upload_label, 0, 1)
        layout.addWidget(QLabel("Download Speed:"), 1, 0)
        layout.addWidget(self.download_label, 1, 1)
        layout.addWidget(QLabel("Total Sent:"), 2, 0)
        layout.addWidget(self.total_upload_label, 2, 1)
        layout.addWidget(QLabel("Total Received:"), 3, 0)
        layout.addWidget(self.total_download_label, 3, 1)
        return group_box
    def _create_process_table(self) -> tuple[QGroupBox, QTableWidget]:
        group_box = QGroupBox("Running Processes")
        group_box.setStyleSheet("""
            QGroupBox { font-family: Consolas, monospace; color: #00FF00; font-size: 14px; font-weight: bold;
                        border: 1px solid #00FF00; border-radius: 5px; margin-top: 1ex; }
            QGroupBox::title { subcontrol-origin: margin; subcontrol-position: top left; padding: 0 5px; }
        """)
        layout = QVBoxLayout(group_box)
        table = QTableWidget()
        table.setColumnCount(6)
        table.setHorizontalHeaderLabels(["PID", "Name", "User", "CPU %", "Memory %", "Threads"])
        table.setStyleSheet("""
            QTableWidget { background-color: #111; color: #00FF00; gridline-color: #333; border: 1px solid #00FF00;
                           font-family: Consolas, monospace; font-size: 12px; alternate-background-color: #1A1A1A; }
            QHeaderView::section { background-color: #333; color: #FF0000; padding: 5px; border: 1px solid #00FF00; font-weight: bold; }
            QTableWidget::item { border-bottom: 1px solid #333; padding-left: 5px; }
            QTableWidget::item:selected { background-color: #00FF00; color: #000000; }
        """)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        table.horizontalHeader().setStretchLastSection(True)
        table.verticalHeader().setVisible(False)
        table.setEditTriggers(QTableWidget.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectRows)
        table.setAlternatingRowColors(True)
        table.setSortingEnabled(True)
        table.setContextMenuPolicy(Qt.CustomContextMenu)
        table.customContextMenuRequested.connect(self._show_process_context_menu)
        layout.addWidget(table)
        return group_box, table
    def _format_speed(self, bytes_per_second: float) -> str:
        if bytes_per_second < 1024: return f"{bytes_per_second:.1f} B/s"
        elif bytes_per_second < 1024**2: return f"{bytes_per_second / 1024:.1f} KB/s"
        else: return f"{bytes_per_second / 1024**2:.1f} MB/s"
    def _format_bytes(self, total_bytes: int) -> str:
        if total_bytes < 1024: return f"{total_bytes} B"
        elif total_bytes < 1024**2: return f"{total_bytes / 1024:.2f} KB"
        elif total_bytes < 1024**3: return f"{total_bytes / 1024**2:.2f} MB"
        else: return f"{total_bytes / 1024**3:.2f} GB"
    @pyqtSlot(dict)
    def update_data(self, snapshot: dict):
        """
        Public slot to update all UI elements. Optimized to skip work when tab is not visible,
        and limit table updates to top 45 active processes to prevent any GUI lag.
        """
        if not snapshot or not self.isVisible():
            return
        self.cpu_bar.setValue(int(snapshot.get('cpu_percent', 0.0)))
        self.mem_bar.setValue(int(snapshot.get('mem_percent', 0.0)))
        summary = snapshot.get('summary', {})
        self.process_group.setTitle(
            f"Active Running Processes ({summary.get('total_processes', 'N/A')} Total, "
            f"{summary.get('total_threads', 'N/A')} Threads)"
        )
        if self.previous_snapshot:
            time_delta = snapshot.get('ts', 0) - self.previous_snapshot.get('ts', 0)
            if time_delta > 0:
                net_io = snapshot.get('net_io')
                prev_net_io = self.previous_snapshot.get('net_io')
                if net_io and prev_net_io:
                    sent_delta = net_io['bytes_sent'] - prev_net_io['bytes_sent']
                    recv_delta = net_io['bytes_recv'] - prev_net_io['bytes_recv']
                    self.upload_label.setText(self._format_speed(sent_delta / time_delta))
                    self.download_label.setText(self._format_speed(recv_delta / time_delta))
                    self.total_bytes_sent += sent_delta
                    self.total_bytes_recv += recv_delta
                    self.total_upload_label.setText(self._format_bytes(self.total_bytes_sent))
                    self.total_download_label.setText(self._format_bytes(self.total_bytes_recv))
                disk_io = snapshot.get('disk_io')
                prev_disk_io = self.previous_snapshot.get('disk_io')
                if disk_io and prev_disk_io:
                    read_speed = (disk_io['read_bytes'] - prev_disk_io['read_bytes']) / time_delta
                    write_speed = (disk_io['write_bytes'] - prev_disk_io['write_bytes']) / time_delta
                    self.disk_read_label.setText(self._format_speed(read_speed))
                    self.disk_write_label.setText(self._format_speed(write_speed))
        self.previous_snapshot = snapshot
        self.process_table.setSortingEnabled(False)
        all_procs = snapshot.get('processes', [])
        top_procs = sorted(all_procs, key=lambda p: (p.get('cpu_percent', 0.0) or 0.0) + (p.get('memory_percent', 0.0) or 0.0), reverse=True)[:45]
        new_procs_by_pid = {proc['pid']: proc for proc in top_procs if proc.get('pid') is not None}
        new_pids = set(new_procs_by_pid.keys())
        current_pids = set(self.pid_row_map.keys())
        pids_to_remove = current_pids - new_pids
        pids_to_add = new_pids - current_pids
        pids_to_update = current_pids.intersection(new_pids)
        for pid in pids_to_remove:
            pid_item = self.pid_row_map.pop(pid, None)
            if pid_item:
                self.process_table.removeRow(pid_item.row())
        for pid in pids_to_add:
            proc_data = new_procs_by_pid[pid]
            row_position = self.process_table.rowCount()
            self.process_table.insertRow(row_position)
            pid_item = QTableWidgetItem(str(proc_data.get('pid', '')))
            self.pid_row_map[pid] = pid_item
            self.process_table.setItem(row_position, 0, pid_item)
            self.process_table.setItem(row_position, 1, QTableWidgetItem(proc_data.get('name', '')))
            self.process_table.setItem(row_position, 2, QTableWidgetItem(proc_data.get('username', '')))
            self.process_table.setItem(row_position, 3, QTableWidgetItem(f"{proc_data.get('cpu_percent', 0.0):.1f}"))
            self.process_table.setItem(row_position, 4, QTableWidgetItem(f"{proc_data.get('memory_percent', 0.0):.1f}"))
            self.process_table.setItem(row_position, 5, QTableWidgetItem(str(proc_data.get('num_threads', ''))))
            self.process_table.item(row_position, 1).setToolTip(proc_data.get('exe', 'N/A'))
        for pid in pids_to_update:
            pid_item = self.pid_row_map.get(pid)
            if not pid_item: continue
            row = pid_item.row()
            proc_data = new_procs_by_pid[pid]
            self.process_table.item(row, 1).setText(proc_data.get('name', ''))
            self.process_table.item(row, 1).setToolTip(proc_data.get('exe', 'N/A'))
            self.process_table.item(row, 2).setText(proc_data.get('username', ''))
            self.process_table.item(row, 3).setText(f"{proc_data.get('cpu_percent', 0.0):.1f}")
            self.process_table.item(row, 4).setText(f"{proc_data.get('memory_percent', 0.0):.1f}")
            self.process_table.item(row, 5).setText(str(proc_data.get('num_threads', '')))
        self.process_table.setSortingEnabled(True)
    def _show_process_context_menu(self, pos: QPoint):
        item = self.process_table.itemAt(pos)
        if not item: return
        pid_item = self.process_table.item(item.row(), 0)
        if not pid_item: return
        try:
            pid = int(pid_item.text())
        except (ValueError, AttributeError):
            return
        menu = QMenu()
        kill_action = menu.addAction(f"Kill Process (PID: {pid})")
        action = menu.exec_(self.process_table.mapToGlobal(pos))
        if action == kill_action:
            self._kill_selected_process(pid)
    def _kill_selected_process(self, pid: int):
        try:
            p = psutil.Process(pid)
            p.kill()
            QMessageBox.information(self, "Process Killed", f"Successfully terminated process with PID: {pid}")
        except psutil.NoSuchProcess:
            QMessageBox.warning(self, "Error", f"Process with PID {pid} no longer exists.")
        except psutil.AccessDenied:
            QMessageBox.critical(self, "Access Denied", f"Could not kill process {pid}.\nRun CyberGun as an administrator.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"An unexpected error occurred: {e}")