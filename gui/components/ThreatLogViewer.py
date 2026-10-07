import os
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QTextEdit, QLabel, QPushButton, QHBoxLayout, QGroupBox
from PyQt5.QtGui import QFont, QTextCursor
from PyQt5.QtCore import Qt, QObject, QThread, pyqtSignal, pyqtSlot
from core.SignalBus import get_signal_bus
from utils.logger import clear_threat_log 
class LogLoader(QObject):
    log_content_loaded = pyqtSignal(str)
    def __init__(self, log_path: str):
        super().__init__()
        self.log_path = log_path
    @pyqtSlot()
    def run(self):
        """Reads the log file and emits the content."""
        content = f"⚠️ Log file not found at: {self.log_path}"
        if os.path.exists(self.log_path):
            try:
                with open(self.log_path, "r", encoding="utf-8") as f:
                    content = f.read()
                if not content.strip():
                    content = "✔️ No threats logged."
            except Exception as e:
                content = f"❌ Error reading log file: {e}"
        self.log_content_loaded.emit(content)
class ThreatLogViewer(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.log_path = os.path.join("logs", "threats.log")
        self.signal_bus = get_signal_bus()
        self.worker_thread = None
        self.loader = None
        self.setStyleSheet(""" ... """)
        main_layout = QVBoxLayout(self)
        log_group = QGroupBox("Threat Log Viewer")
        group_layout = QVBoxLayout(log_group)
        btn_layout = QHBoxLayout()
        self.reload_btn = QPushButton("🔄 Reload")
        self.reload_btn.clicked.connect(self.load_log_file)
        self.clear_btn = QPushButton("🧹 Clear Log")
        self.clear_btn.setObjectName("clear_button")
        self.clear_btn.clicked.connect(self.clear_log)
        btn_layout.addStretch()
        btn_layout.addWidget(self.reload_btn)
        btn_layout.addWidget(self.clear_btn)
        self.log_console = QTextEdit()
        self.log_console.setReadOnly(True)
        group_layout.addLayout(btn_layout)
        group_layout.addWidget(self.log_console)
        main_layout.addWidget(log_group)
        self.setLayout(main_layout)
        self.load_log_file()
    @pyqtSlot()
    def load_log_file(self):
        if self.worker_thread and self.worker_thread.isRunning():
            return
        self.reload_btn.setEnabled(False)
        self.reload_btn.setText("Loading...")
        self.log_console.setText("🔄 Loading log file...")
        self.worker_thread = QThread()
        self.loader = LogLoader(self.log_path)
        self.loader.moveToThread(self.worker_thread)
        self.loader.log_content_loaded.connect(self._on_log_loaded)
        self.worker_thread.started.connect(self.loader.run)
        self.loader.log_content_loaded.connect(self.worker_thread.quit)
        self.loader.log_content_loaded.connect(self.loader.deleteLater)
        self.worker_thread.finished.connect(self.worker_thread.deleteLater)
        self.worker_thread.finished.connect(self._on_worker_finished)
        self.worker_thread.start()
    @pyqtSlot(str)
    def _on_log_loaded(self, content: str):
        self.log_console.setText(content)
        self.log_console.moveCursor(QTextCursor.End)
        self.reload_btn.setEnabled(True)
        self.reload_btn.setText("🔄 Reload")
    @pyqtSlot()
    def _on_worker_finished(self):
        """
        This slot is called when the thread has finished.
        It clears the Python references to the QThread and worker objects,
        preventing any further attempts to access the deleted C++ objects.
        """
        self.worker_thread = None
        self.loader = None
    def append_log(self, log_entry: str, level: str = "info"):
        current_content = self.log_console.toPlainText()
        if "No threats logged yet." in current_content or "No threats logged." in current_content:
            self.log_console.setText(log_entry)
        else:
            self.log_console.append(log_entry)
        self.log_console.moveCursor(QTextCursor.End)
    @pyqtSlot()
    def clear_log(self):
        """
        Calls the thread-safe log clearing function and then reloads the view.
        """
        clear_threat_log()
        self.load_log_file()