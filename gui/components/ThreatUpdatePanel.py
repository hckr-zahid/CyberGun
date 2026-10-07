from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QGroupBox, QTableWidget, QTableWidgetItem,
    QHeaderView, QAbstractItemView
)
from PyQt5.QtGui import QFont, QColor, QBrush
from PyQt5.QtCore import pyqtSlot, Qt
from datetime import datetime
from core.SignalBus import get_signal_bus
class ThreatUpdatePanel(QWidget):
    """
    A professional panel that displays the real-time status of threat intelligence
    updates in a table that matches the main dashboard's theme.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet("background-color: black; color: #FFFFFF;")
        main_layout = QVBoxLayout(self)
        group_box = QGroupBox("Threat Database Status")
        group_box.setFont(QFont("Consolas", 12, QFont.Bold))
        group_box.setStyleSheet("""
            QGroupBox {
                border: 1px solid #FF0000;
                border-radius: 5px;
                color: #FF0000;
                margin-top: 10px; 
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                left: 10px;
                padding: 0 3px;
                background-color: #111;
            }
        """)
        main_layout.addWidget(group_box)
        group_box_layout = QVBoxLayout()
        group_box.setLayout(group_box_layout)
        self.status_table = QTableWidget()
        self.status_table.setColumnCount(3)
        self.status_table.setHorizontalHeaderLabels(["Component", "Status", "Last Updated"])
        self.status_table.verticalHeader().setVisible(False)
        self.status_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.status_table.setFocusPolicy(Qt.NoFocus)
        self.status_table.setSelectionMode(QAbstractItemView.NoSelection)
        self.status_table.setStyleSheet("""
            QTableWidget {
                background-color: #111;
                color: #FFFFFF;
                gridline-color: #333;
                border: 1px solid #FF0000;
            }
            QHeaderView::section {
                background-color: #222;
                color: #FF0000;
                font-weight: bold;
                padding: 4px;
                border: 1px solid #FF0000;
            }
            QTableWidget::item {
                padding-left: 5px;
            }
        """)
        header = self.status_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        group_box_layout.addWidget(self.status_table)
        self.populate_initial_state()
        self.signal_bus = get_signal_bus()
        self.signal_bus.threat_update_status_changed.connect(self.update_status)
    def populate_initial_state(self):
        """Creates the initial rows for each database component."""
        self.status_table.setRowCount(0)
        components = {
            "yara_rules": "YARA Rules",
            "hashes": "Malware Hashes",
            "bad_ips": "Blacklisted IPs",
            "domains": "C2 Threat Domains"
        }
        for key, display_name in components.items():
            row = self.status_table.rowCount()
            self.status_table.insertRow(row)
            name_item = QTableWidgetItem(display_name)
            name_item.setData(Qt.UserRole, key)
            status_item = QTableWidgetItem("➖ Pending...")
            status_item.setForeground(QBrush(QColor("#FFFFFF")))
            timestamp_item = QTableWidgetItem("N/A")
            self.status_table.setItem(row, 0, name_item)
            self.status_table.setItem(row, 1, status_item)
            self.status_table.setItem(row, 2, timestamp_item)
    @pyqtSlot(str, str, str)
    def update_status(self, component: str, message: str, status: str):
        """
        Finds the correct row in the table and updates its status and timestamp.
        """
        if component == 'overall':
            return
        for row in range(self.status_table.rowCount()):
            name_item = self.status_table.item(row, 0)
            if name_item and name_item.data(Qt.UserRole) == component:
                status_item = self.status_table.item(row, 1)
                timestamp_item = self.status_table.item(row, 2)
                if status == 'running':
                    style_color = QColor("#FFFFFF")
                    icon = "🔄"
                elif status == 'success':
                    style_color = QColor("#00FF00")
                    icon = "✅"
                    timestamp_item.setText(datetime.now().strftime('%H:%M:%S'))
                elif status == 'error':
                    style_color = QColor("#FF0000")
                    icon = "❌"
                else:
                    style_color = QColor("#FFFFFF")
                    icon = "➖"
                status_item.setText(f"{icon} {message}")
                status_item.setForeground(QBrush(style_color))
                if status in ['success', 'error']:
                    timestamp_item.setForeground(QBrush(style_color))
                else:
                    timestamp_item.setForeground(QBrush(QColor("#FFFFFF")))
                return