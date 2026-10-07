from PyQt5.QtWidgets import QDialog, QVBoxLayout, QTextEdit, QPushButton, QHBoxLayout
from PyQt5.QtGui import QFont
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