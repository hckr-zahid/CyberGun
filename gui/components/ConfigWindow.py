import os
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QCheckBox, QDoubleSpinBox, QSpinBox, QPushButton,
    QHBoxLayout, QMessageBox, QGroupBox, QFormLayout, QLineEdit, QFileDialog,
    QListWidget, QAbstractItemView, QScrollArea
)
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt, pyqtSlot
from core.SignalBus import get_signal_bus
from core import config_manager
from core.settings import DEFAULT_SCAN_PATH
class ConfigWindow(QWidget):
    """
    Enhanced configuration panel exposing engine toggles, threading,
    forensic disassembly switches, and boot-update automation.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.signal_bus = get_signal_bus()
        self._init_ui()
        self.load_current_settings()
    def _init_ui(self):
        self.setStyleSheet("""
            QWidget { 
                background-color: #0a0f14; 
                color: #e0e0e0; 
                font-family: 'Consolas', 'Lucida Console', monospace;
            }
            QGroupBox {
                font-size: 11pt; font-weight: bold; color: #00aaff;
                border: 1px solid #1c2430; border-radius: 5px; margin-top: 1ex;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin; subcontrol-position: top left;
                padding: 0 10px; background-color: #121820; border-radius: 5px;
            }
            QLabel { font-size: 10pt; }
            QLineEdit, QDoubleSpinBox, QSpinBox, QListWidget {
                background-color: #121820; border: 1px solid #1c2430;
                padding: 5px; color: #e0e0e0; border-radius: 4px;
            }
            QLineEdit:focus, QDoubleSpinBox:focus, QSpinBox:focus, QListWidget:focus {
                border: 1px solid #00aaff;
            }
            QCheckBox { font-size: 10pt; spacing: 8px; }
            QCheckBox::indicator {
                width: 18px; height: 18px;
                background-color: #121820; border: 1px solid #1c2430;
                border-radius: 4px;
            }
            QCheckBox::indicator:checked {
                background-color: #00ffc8;
            }
            QPushButton {
                background-color: #1c2430; color: #e0e0e0;
                border: 1px solid #00aaff; padding: 6px 12px;
                font-weight: bold; border-radius: 4px;
            }
            QPushButton:hover { background-color: #00aaff; color: #000; }
            QPushButton#apply_button {
                background-color: #00ffc8; color: #000; font-size: 11pt;
            }
            QPushButton#apply_button:hover { background-color: #33ffff; }
            QPushButton#restore_button {
                background-color: transparent; border: 1px solid #E67E22; color: #E67E22;
            }
            QPushButton#restore_button:hover { background-color: #E67E22; color: #fff; }
        """)
        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(10, 10, 10, 10)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")
        container = QWidget()
        main_layout = QVBoxLayout(container)
        main_layout.setContentsMargins(15, 10, 15, 10)
        main_layout.setSpacing(12)
        scan_group = QGroupBox("Target Scan Directory")
        scan_layout = QFormLayout(scan_group)
        self.scan_path_edit = QLineEdit(); self.scan_path_edit.setReadOnly(True)
        browse_btn = QPushButton("Browse..."); browse_btn.clicked.connect(self._browse_scan_path)
        path_layout = QHBoxLayout(); path_layout.addWidget(self.scan_path_edit, 1); path_layout.addWidget(browse_btn)
        scan_layout.addRow(QLabel("Default Directory:"), path_layout)
        main_layout.addWidget(scan_group)
        engine_group = QGroupBox("Core Security & Detection Engines")
        engine_layout = QVBoxLayout(engine_group); engine_layout.setSpacing(8)
        self.hash_checkbox = QCheckBox("Hash-Based Detection (SHA256 / Abuse.ch SQLite Database)")
        self.yara_checkbox = QCheckBox("YARA Rule Matching Engine (libyara compiled rules)")
        self.ml_checkbox = QCheckBox("Machine Learning Threat Classifier (LightGBM static inference)")
        self.signature_checkbox = QCheckBox("Byte Signature Pattern Matcher (Entry point heuristic search)")
        self.string_checkbox = QCheckBox("Suspicious String & Obfuscation Scanner")
        self.behavior_checkbox = QCheckBox("Real-Time Behavioral Process Monitor")
        self.network_checkbox = QCheckBox("Live Network Socket & IP Blacklist Inspector")
        self.forensic_checkbox = QCheckBox("Deep Forensic Investigation & Disassembly Engine")
        for cb in [self.hash_checkbox, self.yara_checkbox, self.ml_checkbox, self.signature_checkbox,
                   self.string_checkbox, self.behavior_checkbox, self.network_checkbox, self.forensic_checkbox]:
            engine_layout.addWidget(cb)
        main_layout.addWidget(engine_group)
        perf_group = QGroupBox("Performance, Threading & Automation")
        perf_layout = QFormLayout(perf_group)
        perf_layout.setSpacing(8)
        self.boot_scan_checkbox = QCheckBox("Run Background Initial System Scan on Startup")
        perf_layout.addRow(self.boot_scan_checkbox)
        self.boot_update_checkbox = QCheckBox("Auto-Update Threat Intelligence Feeds on Boot")
        perf_layout.addRow(self.boot_update_checkbox)
        self.thread_spin = QSpinBox()
        self.thread_spin.setRange(1, 16)
        perf_layout.addRow(QLabel("Scanner Worker Threads:"), self.thread_spin)
        self.conf_spin = QDoubleSpinBox()
        self.conf_spin.setRange(0.1, 1.0)
        self.conf_spin.setSingleStep(0.05)
        perf_layout.addRow(QLabel("ML Confidence Threshold:"), self.conf_spin)
        self.quarantine_encrypt_checkbox = QCheckBox("Encrypt Quarantined Artifacts with AES Key")
        perf_layout.addRow(self.quarantine_encrypt_checkbox)
        self.sound_checkbox = QCheckBox("Enable Sound & Tray Notifications on Threat Alert")
        perf_layout.addRow(self.sound_checkbox)
        main_layout.addWidget(perf_group)
        file_type_group = QGroupBox("Target File Type Filter (Empty allows all formats)")
        file_type_layout = QHBoxLayout(file_type_group)
        self.extension_list = QListWidget()
        self.extension_list.setMaximumHeight(110)
        ext_controls_layout = QVBoxLayout()
        self.new_ext_edit = QLineEdit(); self.new_ext_edit.setPlaceholderText(".exe, .pdf, .dll")
        add_ext_btn = QPushButton("Add Extension"); add_ext_btn.clicked.connect(self._add_extension)
        remove_ext_btn = QPushButton("Remove Selected"); remove_ext_btn.clicked.connect(self._remove_extension)
        ext_controls_layout.addWidget(self.new_ext_edit)
        ext_controls_layout.addWidget(add_ext_btn)
        ext_controls_layout.addWidget(remove_ext_btn)
        file_type_layout.addWidget(self.extension_list, 2)
        file_type_layout.addLayout(ext_controls_layout, 1)
        main_layout.addWidget(file_type_group)
        scroll.setWidget(container)
        outer_layout.addWidget(scroll, 1)
        btn_layout = QHBoxLayout()
        restore_btn = QPushButton("Restore Defaults"); restore_btn.setObjectName("restore_button")
        restore_btn.clicked.connect(self.load_default_settings)
        apply_btn = QPushButton("Apply & Save Settings"); apply_btn.setObjectName("apply_button")
        apply_btn.clicked.connect(self.apply_settings)
        btn_layout.addStretch()
        btn_layout.addWidget(restore_btn)
        btn_layout.addWidget(apply_btn)
        outer_layout.addLayout(btn_layout)
    @pyqtSlot()
    def load_current_settings(self):
        """Loads all settings from central config_manager into UI."""
        self.scan_path_edit.setText(config_manager.get_scan_path())
        self.hash_checkbox.setChecked(config_manager.is_hash_scan_enabled())
        self.yara_checkbox.setChecked(config_manager.is_yara_scan_enabled())
        self.ml_checkbox.setChecked(config_manager.is_ml_scan_enabled())
        self.signature_checkbox.setChecked(config_manager.is_signature_scan_enabled())
        self.string_checkbox.setChecked(config_manager.is_string_scan_enabled())
        self.behavior_checkbox.setChecked(config_manager.is_behavior_monitor_enabled())
        self.network_checkbox.setChecked(config_manager.is_network_monitor_enabled())
        self.forensic_checkbox.setChecked(config_manager.is_deep_forensics_enabled())
        self.boot_scan_checkbox.setChecked(config_manager.is_initial_scan_enabled())
        self.boot_update_checkbox.setChecked(config_manager.is_auto_update_on_boot_enabled())
        self.quarantine_encrypt_checkbox.setChecked(config_manager.is_quarantine_encrypt_enabled())
        self.sound_checkbox.setChecked(config_manager.is_sound_alerts_enabled())
        self.thread_spin.setValue(config_manager.get_thread_concurrency())
        self.conf_spin.setValue(config_manager.get_ml_confidence_threshold())
        self.extension_list.clear()
        self.extension_list.addItems(config_manager.get_allowed_extensions())
    @pyqtSlot()
    def load_default_settings(self):
        """Loads hardcoded defaults into UI."""
        self.scan_path_edit.setText(DEFAULT_SCAN_PATH)
        for cb in [self.hash_checkbox, self.yara_checkbox, self.ml_checkbox, self.signature_checkbox,
                   self.string_checkbox, self.behavior_checkbox, self.network_checkbox,
                   self.forensic_checkbox, self.boot_update_checkbox, self.quarantine_encrypt_checkbox, self.sound_checkbox]:
            cb.setChecked(True)
        self.boot_scan_checkbox.setChecked(False)
        self.thread_spin.setValue(4)
        self.conf_spin.setValue(0.80)
        self.extension_list.clear()
    @pyqtSlot()
    def apply_settings(self):
        """Saves all UI controls to config.json."""
        extensions = [self.extension_list.item(i).text() for i in range(self.extension_list.count())]
        config = {
            "scan_path": self.scan_path_edit.text(),
            "allowed_extensions": extensions,
            "engines": {
                "enable_hash_scan": self.hash_checkbox.isChecked(),
                "enable_yara_scan": self.yara_checkbox.isChecked(),
                "enable_ml_scan": self.ml_checkbox.isChecked(),
                "enable_signature_scan": self.signature_checkbox.isChecked(),
                "enable_string_scan": self.string_checkbox.isChecked(),
                "enable_behavior_monitor": self.behavior_checkbox.isChecked(),
                "enable_network_monitor": self.network_checkbox.isChecked(),
                "enable_deep_forensics": self.forensic_checkbox.isChecked(),
                "enable_initial_boot_scan": self.boot_scan_checkbox.isChecked(),
            },
            "thresholds": {
                "ml_confidence": round(self.conf_spin.value(), 2),
                "thread_concurrency": self.thread_spin.value(),
                "auto_update_on_boot": self.boot_update_checkbox.isChecked(),
                "quarantine_auto_encrypt": self.quarantine_encrypt_checkbox.isChecked(),
                "sound_alerts_enabled": self.sound_checkbox.isChecked()
            }
        }
        config_manager.update_and_save_settings(config)
        self.signal_bus.config_updated.emit(config)
        QMessageBox.information(self, "Configuration Saved", "CyberGun settings updated successfully.")
    @pyqtSlot()
    def _browse_scan_path(self):
        directory = QFileDialog.getExistingDirectory(self, "Select Scan Directory", self.scan_path_edit.text())
        if directory:
            self.scan_path_edit.setText(directory)
    @pyqtSlot()
    def _add_extension(self):
        ext = self.new_ext_edit.text().strip().lower()
        if not ext: return
        if not ext.startswith("."): ext = "." + ext
        if len(ext) > 1 and not self.extension_list.findItems(ext, Qt.MatchExactly):
            self.extension_list.addItem(ext)
            self.new_ext_edit.clear()
    @pyqtSlot()
    def _remove_extension(self):
        for item in self.extension_list.selectedItems():
            self.extension_list.takeItem(self.extension_list.row(item))