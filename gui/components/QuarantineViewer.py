from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem,
    QHeaderView, QPushButton, QHBoxLayout, QMessageBox, QLabel
)
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt, pyqtSlot
from datetime import datetime
from core.QuarantineManager import QuarantineManager
class QuarantineViewer(QWidget):
    """
    A UI component for viewing and managing quarantined files.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.quarantine_manager = QuarantineManager()
        self._init_ui()
        self.refresh_table()
    def _init_ui(self):
        """Initializes the user interface."""
        self.setStyleSheet("""
            QWidget { background-color: #000; color: #00FF00; }
            QTableWidget {
                background-color: #111;
                gridline-color: #333;
                border: 1px solid #00FF00;
                font-size: 12px;
            }
            QHeaderView::section {
                background-color: #222;
                color: #00FF00;
                font-weight: bold;
                padding: 4px;
            }
            QPushButton {
                background-color: #333;
                border: 1px solid #666;
                padding: 8px;
                min-width: 120px;
            }
            QPushButton:hover { background-color: #555; }
        """)
        main_layout = QVBoxLayout(self)
        title = QLabel("📦 Quarantine Zone")
        title.setFont(QFont("Consolas", 16, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(title)
        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Quarantined Filename", "Original Path", "Date Quarantined", "Size"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        main_layout.addWidget(self.table)
        button_layout = QHBoxLayout()
        restore_btn = QPushButton("Restore Selected")
        restore_btn.setStyleSheet("background-color: #005500;")
        restore_btn.clicked.connect(self.restore_selected)
        delete_btn = QPushButton("Delete Selected Permanently")
        delete_btn.setStyleSheet("background-color: #550000;")
        delete_btn.clicked.connect(self.delete_selected)
        refresh_btn = QPushButton("Refresh List")
        refresh_btn.clicked.connect(self.refresh_table)
        button_layout.addStretch()
        button_layout.addWidget(refresh_btn)
        button_layout.addWidget(restore_btn)
        button_layout.addWidget(delete_btn)
        button_layout.addStretch()
        main_layout.addLayout(button_layout)
    def _format_size(self, size_bytes: int) -> str:
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024**2:
            return f"{size_bytes / 1024:.2f} KB"
        else:
            return f"{size_bytes / 1024**2:.2f} MB"
    @pyqtSlot()
    def refresh_table(self):
        """Clears and re-populates the table with the latest quarantine data."""
        self.table.setRowCount(0)
        files = self.quarantine_manager.list_quarantined_files()
        for file_data in files:
            row_position = self.table.rowCount()
            self.table.insertRow(row_position)
            filename_item = QTableWidgetItem(file_data["filename"])
            filename_item.setData(Qt.UserRole, file_data["filename"])
            try:
                date_obj = datetime.fromisoformat(file_data["quarantine_date"])
                date_str = date_obj.strftime("%Y-%m-%d %H:%M:%S")
            except (ValueError, TypeError):
                date_str = "Unknown"
            self.table.setItem(row_position, 0, filename_item)
            self.table.setItem(row_position, 1, QTableWidgetItem(file_data["original_path"]))
            self.table.setItem(row_position, 2, QTableWidgetItem(date_str))
            self.table.setItem(row_position, 3, QTableWidgetItem(self._format_size(file_data["size_bytes"])))
    def _get_selected_filename(self) -> str | None:
        """Helper to get the unique filename from the selected row."""
        selected_items = self.table.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "No Selection", "Please select a file from the list.")
            return None
        return selected_items[0].data(Qt.UserRole)
    @pyqtSlot()
    def restore_selected(self):
        """Handler for the restore button."""
        filename = self._get_selected_filename()
        if not filename:
            return
        reply = QMessageBox.question(self, "Confirm Restore",
                                     f"Are you sure you want to restore this file?\n\n'{filename}'\n\n"
                                     "Restoring a malicious file can harm your system.",
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            if self.quarantine_manager.restore_quarantined_file(filename):
                QMessageBox.information(self, "Success", "File has been restored to its original location.")
                self.refresh_table()
            else:
                QMessageBox.critical(self, "Error", "Failed to restore the file. Check system logs for details.")
    @pyqtSlot()
    def delete_selected(self):
        """Handler for the delete button."""
        filename = self._get_selected_filename()
        if not filename:
            return
        reply = QMessageBox.question(self, "Confirm Deletion",
                                     f"Are you sure you want to permanently delete this file?\n\n'{filename}'\n\n"
                                     "This action cannot be undone.",
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            if self.quarantine_manager.delete_quarantined_file(filename):
                QMessageBox.information(self, "Success", "File has been permanently deleted.")
                self.refresh_table()
            else:
                QMessageBox.critical(self, "Error", "Failed to delete the file. Check system logs for details.")