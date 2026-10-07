from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QGridLayout, QLabel, QGroupBox, QMessageBox,
    QScrollArea
)
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt, pyqtSlot
from .attack_data import ATTACK_MATRIX_DATA
from gui.theme import COLOR_ACCENT_BLUE, COLOR_THREAT_HIGH
class ATTACKMatrixViewer(QWidget):
    """
    A UI component to visualize detected threats on the MITRE ATT&CK Matrix.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.technique_labels: dict[str, QLabel] = {}
        self._init_ui()
    def _init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        matrix_group = QGroupBox("🛡️ MITRE ATT&CK Matrix for Enterprise")
        group_layout = QVBoxLayout(matrix_group)
        main_layout.addWidget(matrix_group)
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setStyleSheet("QScrollArea { border: none; }")
        group_layout.addWidget(scroll_area)
        container_widget = QWidget()
        scroll_area.setWidget(container_widget)
        grid_layout = QGridLayout(container_widget)
        grid_layout.setSpacing(1)
        header_font = QFont(QFont().defaultFamily(), 10, QFont.Bold)
        for col, (tactic, techniques) in enumerate(ATTACK_MATRIX_DATA.items()):
            tactic_label = QLabel(tactic.replace(" ", "\n"))
            tactic_label.setFont(header_font)
            tactic_label.setAlignment(Qt.AlignCenter)
            tactic_label.setStyleSheet(f"background-color: #2c3e50; color: {COLOR_ACCENT_BLUE}; padding: 10px; border-radius: 4px;")
            grid_layout.addWidget(tactic_label, 0, col)
            for row, (tech_id, tech_name) in enumerate(techniques.items()):
                tech_label = QLabel(f"{tech_id}\n{tech_name}")
                tech_label.setWordWrap(True)
                tech_label.setAlignment(Qt.AlignCenter)
                tech_label.setToolTip(f"{tech_id}: {tech_name}\n\n(Tactic: {tactic})")
                tech_label.setStyleSheet("background-color: #1c2b3a; padding: 5px; border-radius: 2px;")
                tech_label.mousePressEvent = lambda event, tid=tech_id, tname=tech_name, tac=tactic: self._show_technique_details(tid, tname, tac)
                grid_layout.addWidget(tech_label, row + 1, col)
                self.technique_labels[tech_id] = tech_label
    def _show_technique_details(self, tech_id, tech_name, tactic):
        url = f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/"
        QMessageBox.information(self, f"Technique Details: {tech_id}",
                                f"<b>Name:</b> {tech_name}<br>"
                                f"<b>Tactic:</b> {tactic}<br><br>"
                                f"For more information, visit:<br><a href='{url}'>{url}</a>")
    @pyqtSlot(str)
    def highlight_technique(self, technique_id: str):
        """Finds and highlights a technique label in the matrix."""
        base_id = technique_id.split('.')[0]
        if base_id in self.technique_labels:
            label = self.technique_labels[base_id]
            label.setStyleSheet(f"background-color: {COLOR_THREAT_HIGH}; color: white; padding: 5px; border-radius: 2px; border: 1px solid white;")