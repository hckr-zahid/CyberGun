import os
import json
import time
from datetime import datetime
from PyQt5.QtWidgets import (
    QDialog, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTextEdit,
    QPushButton, QTabWidget, QTableWidget, QTableWidgetItem, QHeaderView,
    QProgressBar, QFileDialog, QMessageBox, QGroupBox, QSplitter,
    QAbstractItemView
)
from PyQt5.QtGui import QFont, QColor, QBrush, QIcon
from PyQt5.QtCore import Qt, pyqtSlot, QThread, pyqtSignal
from core.ForensicAnalyzer import ForensicAnalyzer
from core.SignalBus import emit_log
class ForensicWorker(QThread):
    """Background worker to analyze files without freezing the GUI."""
    analysis_completed = pyqtSignal(dict)
    analysis_failed = pyqtSignal(str)
    def __init__(self, file_path: str):
        super().__init__()
        self.file_path = file_path
    def run(self):
        try:
            analyzer = ForensicAnalyzer()
            result = analyzer.analyze_file(self.file_path)
            self.analysis_completed.emit(result)
        except Exception as e:
            self.analysis_failed.emit(str(e))
class ForensicInvestigatorDialog(QDialog):
    """
    Forensic Investigator & Reverse Engineering Deep-Dive Dialog.
    Provides structural analysis, exploit guarantee, malware architecture blueprint,
    and a step-by-step reverse engineering methodology for analysts.
    """
    def __init__(self, file_path: str = None, parent=None):
        super().__init__(parent)
        self.current_file_path = file_path
        self.analyzer = ForensicAnalyzer()
        self.last_analysis_result = None
        self.setWindowTitle("CyberGun - Forensic Investigator & Reverse Engineering Suite")
        self.resize(1150, 750)
        self.setMinimumSize(950, 600)
        self.setStyleSheet("""
            QDialog {
                background-color: #080d14;
                color: #e2e8f0;
                font-family: 'Consolas', 'Segoe UI', monospace;
            }
            QGroupBox {
                border: 1px solid #1e293b;
                border-radius: 6px;
                margin-top: 10px;
                padding-top: 10px;
                font-weight: bold;
                color: #00ffc8;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
                background-color: #080d14;
            }
            QTabWidget::pane {
                border: 1px solid #1e293b;
                background-color: #0b121d;
                border-radius: 4px;
            }
            QTabBar::tab {
                background-color: #0f172a;
                color: #94a3b8;
                padding: 8px 16px;
                border: 1px solid #1e293b;
                border-bottom: none;
                margin-right: 2px;
                font-weight: bold;
            }
            QTabBar::tab:selected {
                background-color: #0b121d;
                color: #00ffc8;
                border-top: 2px solid #00ffc8;
            }
            QTextEdit {
                background-color: #090e17;
                color: #38bdf8;
                border: 1px solid #1e293b;
                border-radius: 4px;
                padding: 8px;
                font-family: 'Consolas', monospace;
                font-size: 12px;
            }
            QTableWidget {
                background-color: #090e17;
                color: #cbd5e1;
                gridline-color: #1e293b;
                border: 1px solid #1e293b;
                border-radius: 4px;
                font-family: 'Consolas', monospace;
                font-size: 11px;
            }
            QHeaderView::section {
                background-color: #0f172a;
                color: #00ffc8;
                font-weight: bold;
                padding: 5px;
                border: 1px solid #1e293b;
            }
            QPushButton {
                background-color: #1e293b;
                color: #f8fafc;
                border: 1px solid #334155;
                padding: 6px 14px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #00aaff;
                color: #000000;
            }
        """)
        self._init_ui()
        if self.current_file_path and os.path.exists(self.current_file_path):
            self.start_investigation(self.current_file_path)
    def _init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(15, 15, 15, 15)
        main_layout.setSpacing(10)
        header_layout = QHBoxLayout()
        title_label = QLabel("🔬 CYBERGUN FORENSIC INVESTIGATOR & REVERSE ENGINEERING SUITE")
        title_label.setFont(QFont("Consolas", 13, QFont.Bold))
        title_label.setStyleSheet("color: #00ffc8;")
        header_layout.addWidget(title_label)
        header_layout.addStretch()
        self.btn_select_file = QPushButton("📂 Analyze New File")
        self.btn_select_file.clicked.connect(self._browse_new_file)
        header_layout.addWidget(self.btn_select_file)
        self.btn_export = QPushButton("📄 Export Forensic Report")
        self.btn_export.setStyleSheet("background-color: #0369a1; color: #fff;")
        self.btn_export.clicked.connect(self._export_report)
        header_layout.addWidget(self.btn_export)
        main_layout.addLayout(header_layout)
        self.overview_group = QGroupBox("Target Artifact Overview")
        overview_layout = QVBoxLayout(self.overview_group)
        self.lbl_file_path = QLabel("Target: None selected")
        self.lbl_file_path.setStyleSheet("color: #94a3b8; font-weight: bold;")
        overview_layout.addWidget(self.lbl_file_path)
        meta_layout = QHBoxLayout()
        self.lbl_file_type = QLabel("Type: -")
        self.lbl_file_size = QLabel("Size: -")
        self.lbl_entropy = QLabel("Entropy: -")
        self.lbl_sha256 = QLabel("SHA256: -")
        self.lbl_sha256.setStyleSheet("color: #38bdf8;")
        for lbl in [self.lbl_file_type, self.lbl_file_size, self.lbl_entropy, self.lbl_sha256]:
            lbl.setFont(QFont("Consolas", 10))
            meta_layout.addWidget(lbl)
        meta_layout.addStretch()
        overview_layout.addLayout(meta_layout)
        self.verdict_banner = QLabel("STATUS: AWAITING ARTIFACT SELECTION")
        self.verdict_banner.setFont(QFont("Consolas", 11, QFont.Bold))
        self.verdict_banner.setStyleSheet("""
            background-color: #1e293b; color: #94a3b8; padding: 8px 12px;
            border-radius: 4px; border: 1px solid #334155;
        """)
        self.verdict_banner.setWordWrap(True)
        overview_layout.addWidget(self.verdict_banner)
        main_layout.addWidget(self.overview_group)
        self.tabs = QTabWidget()
        self.tab_guarantee = QWidget()
        self._init_tab_guarantee()
        self.tabs.addTab(self.tab_guarantee, "🛡️ Guarantee & Proof")
        self.tab_blueprint = QWidget()
        self._init_tab_blueprint()
        self.tabs.addTab(self.tab_blueprint, "🏗️ Development Anatomy")
        self.tab_how_it_works = QWidget()
        self._init_tab_how_it_works()
        self.tabs.addTab(self.tab_how_it_works, "⚙️ Execution Lifecycle")
        self.tab_re_guide = QWidget()
        self._init_tab_re_guide()
        self.tabs.addTab(self.tab_re_guide, "🔬 Reverse Engineering Manual")
        self.tab_disassembly = QWidget()
        self._init_tab_disassembly()
        self.tabs.addTab(self.tab_disassembly, "📜 Disassembly & Streams")
        main_layout.addWidget(self.tabs, 1)
    def _init_tab_guarantee(self):
        layout = QVBoxLayout(self.tab_guarantee)
        layout.setContentsMargins(10, 10, 10, 10)
        lbl = QLabel("Forensic Proof of Malicious Intent / Guarantee Assessment:")
        lbl.setFont(QFont("Consolas", 11, QFont.Bold))
        lbl.setStyleSheet("color: #00ffc8;")
        layout.addWidget(lbl)
        self.txt_guarantee = QTextEdit()
        self.txt_guarantee.setReadOnly(True)
        layout.addWidget(self.txt_guarantee, 1)
        self.indicators_table = QTableWidget()
        self.indicators_table.setColumnCount(4)
        self.indicators_table.setHorizontalHeaderLabels(["Indicator / Tag", "Count", "Risk Level", "Forensic Meaning"])
        self.indicators_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.indicators_table.horizontalHeader().setStretchLastSection(True)
        self.indicators_table.verticalHeader().setVisible(False)
        self.indicators_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        layout.addWidget(self.indicators_table, 1)
    def _init_tab_blueprint(self):
        layout = QVBoxLayout(self.tab_blueprint)
        layout.setContentsMargins(10, 10, 10, 10)
        lbl = QLabel("How the Malware Was Developed & Engineered:")
        lbl.setFont(QFont("Consolas", 11, QFont.Bold))
        lbl.setStyleSheet("color: #00ffc8;")
        layout.addWidget(lbl)
        self.txt_blueprint = QTextEdit()
        self.txt_blueprint.setReadOnly(True)
        layout.addWidget(self.txt_blueprint)
    def _init_tab_how_it_works(self):
        layout = QVBoxLayout(self.tab_how_it_works)
        layout.setContentsMargins(10, 10, 10, 10)
        lbl = QLabel("Step-by-Step Execution Vector (How It Operates):")
        lbl.setFont(QFont("Consolas", 11, QFont.Bold))
        lbl.setStyleSheet("color: #00ffc8;")
        layout.addWidget(lbl)
        self.txt_how_it_works = QTextEdit()
        self.txt_how_it_works.setReadOnly(True)
        layout.addWidget(self.txt_how_it_works)
    def _init_tab_re_guide(self):
        layout = QVBoxLayout(self.tab_re_guide)
        layout.setContentsMargins(10, 10, 10, 10)
        lbl = QLabel("Standard Operating Procedure for Reverse Engineering This Threat:")
        lbl.setFont(QFont("Consolas", 11, QFont.Bold))
        lbl.setStyleSheet("color: #00ffc8;")
        layout.addWidget(lbl)
        self.re_table = QTableWidget()
        self.re_table.setColumnCount(3)
        self.re_table.setHorizontalHeaderLabels(["Phase", "Recommended Tools", "Procedure & Practical Commands"])
        self.re_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.re_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.re_table.horizontalHeader().setStretchLastSection(True)
        self.re_table.verticalHeader().setVisible(False)
        self.re_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.re_table.setWordWrap(True)
        layout.addWidget(self.re_table)
    def _init_tab_disassembly(self):
        layout = QVBoxLayout(self.tab_disassembly)
        layout.setContentsMargins(10, 10, 10, 10)
        lbl = QLabel("Decompressed Stream Contents / Disassembled Sections / APIs:")
        lbl.setFont(QFont("Consolas", 11, QFont.Bold))
        lbl.setStyleSheet("color: #00ffc8;")
        layout.addWidget(lbl)
        self.txt_disassembly = QTextEdit()
        self.txt_disassembly.setReadOnly(True)
        layout.addWidget(self.txt_disassembly)
    def start_investigation(self, file_path: str):
        """Spawns non-blocking worker thread to analyze the file."""
        self.current_file_path = file_path
        self.lbl_file_path.setText(f"Target: {file_path}")
        self.verdict_banner.setText("⏳ DEEP FORENSIC INVESTIGATION IN PROGRESS...")
        self.verdict_banner.setStyleSheet("background-color: #1e293b; color: #38bdf8; padding: 8px 12px; border-radius: 4px;")
        self.worker = ForensicWorker(file_path)
        self.worker.analysis_completed.connect(self._on_analysis_completed)
        self.worker.analysis_failed.connect(self._on_analysis_failed)
        self.worker.start()
    @pyqtSlot(dict)
    def _on_analysis_completed(self, result: dict):
        self.last_analysis_result = result
        meta = result.get("metadata", {})
        self.lbl_file_type.setText(f"Type: {result.get('file_type', 'Unknown')}")
        self.lbl_file_size.setText(f"Size: {meta.get('file_size', 0):,} bytes")
        self.lbl_entropy.setText(f"Entropy: {meta.get('overall_entropy', 0.0):.2f}/8.0")
        self.lbl_sha256.setText(f"SHA256: {meta.get('hashes', {}).get('sha256', 'N/A')}")
        is_mal = result.get("is_malicious", False)
        confidence = result.get("confidence", 0.0)
        if is_mal:
            color = "#ef4444"
            bg = "#3b1111"
            status_text = f"🚨 WEAPONIZED / MALICIOUS ARTIFACT CONFIRMED (Confidence: {int(confidence*100)}%)"
        else:
            color = "#10b981"
            bg = "#064e3b"
            status_text = f"✅ BENIGN / CLEAN ARTIFACT (Confidence: {int((1-confidence)*100)}%)"
        self.verdict_banner.setText(status_text)
        self.verdict_banner.setStyleSheet(f"background-color: {bg}; color: {color}; font-weight: bold; padding: 8px 12px; border-radius: 4px; border: 1px solid {color};")
        guarantee_text = result.get("guarantee_statement", "")
        self.txt_guarantee.setPlainText(guarantee_text)
        indicators = result.get("indicators", [])
        self.indicators_table.setRowCount(len(indicators))
        for r, ind in enumerate(indicators):
            item_tag = QTableWidgetItem(ind.get("tag", ""))
            item_count = QTableWidgetItem(str(ind.get("count", 0)))
            item_risk = QTableWidgetItem(ind.get("risk", "INFO"))
            item_desc = QTableWidgetItem(ind.get("description", ""))
            if ind.get("risk") == "HIGH":
                item_risk.setForeground(QBrush(QColor("#ef4444")))
            elif ind.get("risk") == "MEDIUM":
                item_risk.setForeground(QBrush(QColor("#f59e0b")))
            self.indicators_table.setItem(r, 0, item_tag)
            self.indicators_table.setItem(r, 1, item_count)
            self.indicators_table.setItem(r, 2, item_risk)
            self.indicators_table.setItem(r, 3, item_desc)
        dev = result.get("development_blueprint", {})
        blueprint_text = json.dumps(dev, indent=4)
        self.txt_blueprint.setPlainText(blueprint_text)
        how = result.get("how_it_works", [])
        self.txt_how_it_works.setPlainText("\n\n".join(how))
        re_guide = result.get("reverse_engineering_guide", [])
        self.re_table.setRowCount(len(re_guide))
        for r, step in enumerate(re_guide):
            self.re_table.setItem(r, 0, QTableWidgetItem(step.get("phase", "")))
            self.re_table.setItem(r, 1, QTableWidgetItem(step.get("tool", "")))
            self.re_table.setItem(r, 2, QTableWidgetItem(step.get("instructions", "")))
        self.re_table.resizeRowsToContents()
        disasm_parts = []
        if "decompressed_scripts" in result:
            for s in result["decompressed_scripts"]:
                disasm_parts.append(f"--- Extracted Stream {s.get('stream_index')} (Entropy: {s.get('entropy')}) ---")
                disasm_parts.append(f"Suspicious Indicators: {', '.join(s.get('findings', []))}")
                disasm_parts.append(f"Code Preview:\n{s.get('preview', '')}\n")
        elif "sections" in result:
            disasm_parts.append("--- PE Sections Analysis ---")
            for sec in result["sections"]:
                disasm_parts.append(f"Section {sec['name']}: VirtualSize={sec['virtual_size']} RawSize={sec['raw_size']} Entropy={sec['entropy']} [{sec['status']}]")
            disasm_parts.append("\n--- Suspicious API Imports ---")
            for api in result.get("suspicious_apis", []):
                disasm_parts.append(f"Category: {api['category']} (Risk: {api['risk']}) -> {', '.join(api['matched_apis'])}")
        elif "matched_keywords" in result:
            disasm_parts.append(f"Matched Indicators: {', '.join(result.get('matched_keywords', []))}")
        self.txt_disassembly.setPlainText("\n".join(disasm_parts) if disasm_parts else "No decompressed bytecode or raw streams extracted.")
    @pyqtSlot(str)
    def _on_analysis_failed(self, error: str):
        self.verdict_banner.setText(f"❌ FORENSIC ANALYSIS FAILED: {error}")
        self.verdict_banner.setStyleSheet("background-color: #3b1111; color: #ef4444; padding: 8px 12px; border-radius: 4px;")
        emit_log(f"[ForensicInvestigator] Analysis error on {self.current_file_path}: {error}", "error")
    def _browse_new_file(self):
        filePath, _ = QFileDialog.getOpenFileName(
            self, "Select Artifact for Deep Forensic Investigation", "",
            "All Files (*.*);;PDF Documents (*.pdf);;Executables (*.exe *.dll);;Scripts (*.ps1 *.bat *.vbs)"
        )
        if filePath:
            self.start_investigation(filePath)
    def _export_report(self):
        if not self.last_analysis_result:
            QMessageBox.warning(self, "No Analysis Available", "Please complete an analysis before exporting a forensic report.")
            return
        default_name = f"Forensic_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        save_path, _ = QFileDialog.getSaveFileName(self, "Save Forensic Investigation Report", default_name, "HTML Files (*.html)")
        if not save_path:
            return
        try:
            res = self.last_analysis_result
            meta = res.get("metadata", {})
            html = f"""<!DOCTYPE html>
<html>
<head>
<title>CyberGun Forensic Report - {meta.get('file_name')}</title>
<style>
body {{ background-color: #0f172a; color: #e2e8f0; font-family: 'Consolas', monospace; padding: 30px; }}
h1, h2, h3 {{ color: #00ffc8; }}
.badge {{ padding: 6px 12px; border-radius: 4px; font-weight: bold; display: inline-block; }}
.malicious {{ background-color: #ef4444; color: #fff; }}
.clean {{ background-color: #10b981; color: #000; }}
.card {{ background-color: #1e293b; border-radius: 8px; padding: 15px; margin-bottom: 20px; }}
pre {{ background-color: #0b121d; color: #38bdf8; padding: 10px; border-radius: 6px; overflow-x: auto; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
th, td {{ border: 1px solid #334155; padding: 8px; text-align: left; }}
th {{ background-color: #0b121d; color: #00ffc8; }}
</style>
</head>
<body>
<h1>🔬 CyberGun Forensic Investigation & Reverse Engineering Dossier</h1>
<p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
<div class="card">
    <h2>Target Metadata</h2>
    <p><b>File Name:</b> {meta.get('file_name')}</p>
    <p><b>File Path:</b> {meta.get('file_path')}</p>
    <p><b>File Size:</b> {meta.get('file_size')} bytes</p>
    <p><b>Entropy:</b> {meta.get('overall_entropy')}/8.0</p>
    <p><b>SHA256:</b> {meta.get('hashes', {{}}).get('sha256')}</p>
    <p><b>Verdict:</b> <span class="badge {'malicious' if res.get('is_malicious') else 'clean'}">{'CONFIRMED MALICIOUS' if res.get('is_malicious') else 'CLEAN BENIGN'}</span> (Confidence: {int(res.get('confidence', 0)*100)}%)</p>
</div>
<div class="card">
    <h2>Forensic Guarantee & Proof</h2>
    <p>{res.get('guarantee_statement')}</p>
</div>
<div class="card">
    <h2>Malware Development Blueprint (How It Was Built)</h2>
    <pre>{json.dumps(res.get('development_blueprint', {{}}), indent=2)}</pre>
</div>
<div class="card">
    <h2>Execution Lifecycle (How It Works)</h2>
    <ul>
        {''.join([f"<li>{step}</li>" for step in res.get('how_it_works', [])])}
    </ul>
</div>
<div class="card">
    <h2>Reverse Engineering Standard Operating Procedure</h2>
    <table>
        <tr><th>Phase</th><th>Tools</th><th>Procedure</th></tr>
        {''.join([f"<tr><td>{s.get('phase')}</td><td>{s.get('tool')}</td><td>{s.get('instructions')}</td></tr>" for s in res.get('reverse_engineering_guide', [])])}
    </table>
</div>
</body>
</html>"""
            with open(save_path, "w", encoding="utf-8") as f:
                f.write(html)
            QMessageBox.information(self, "Export Successful", f"Forensic report exported successfully to:\n{save_path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Failed", f"Could not export forensic report:\n{e}")
