from PyQt5.QtGui import QColor
COLOR_BACKGROUND = "#000000"
COLOR_BACKGROUND_LIGHT = "#121820"
COLOR_BACKGROUND_ACCENT = "#1c2430"
COLOR_TEXT_PRIMARY = "#e0e0e0"
COLOR_TEXT_SECONDARY = "#a0a0a0"
COLOR_ACCENT_BLUE = "#00aaff"
COLOR_ACCENT_BLUE_LIGHT = "#33ffff"
COLOR_ACCENT_ORANGE = "#E67E22"
COLOR_THREAT_CRITICAL = "#C0392B"
COLOR_THREAT_HIGH = "#E74C3C"
COLOR_THREAT_MEDIUM = "#F39C12"
COLOR_THREAT_LOW = "#27AE60"
COLOR_INFO = "#00ffc8"
FONT_FAMILY = "'Consolas', 'Lucida Console', monospace"
MASTER_STYLESHEET = f"""
    QWidget {{
        background-color: {COLOR_BACKGROUND};
        color: {COLOR_TEXT_PRIMARY};
        font-family: {FONT_FAMILY};
        font-size: 11pt;
    }}
    QStackedWidget {{
        border: none;
    }}
    /* --- GroupBox Styling --- */
    QGroupBox {{
        font-size: 11pt;
        font-weight: bold;
        color: {COLOR_ACCENT_BLUE};
        border: 1px solid {COLOR_BACKGROUND_ACCENT};
        border-radius: 5px;
        margin-top: 1ex;
    }}
    QGroupBox::title {{
        subcontrol-origin: margin;
        subcontrol-position: top left;
        padding: 0 10px;
        background-color: {COLOR_BACKGROUND_LIGHT};
        border-radius: 5px;
    }}
    /* --- Table Styling --- */
    QTableWidget {{
        background-color: {COLOR_BACKGROUND_LIGHT};
        border: 1px solid {COLOR_BACKGROUND_ACCENT};
        gridline-color: {COLOR_BACKGROUND_ACCENT};
        alternate-background-color: #161e28;
    }}
    QHeaderView::section {{
        background-color: {COLOR_BACKGROUND_ACCENT};
        color: {COLOR_ACCENT_BLUE};
        padding: 4px;
        border: 1px solid {COLOR_BACKGROUND_LIGHT};
        font-weight: bold;
    }}
    QTableWidget::item {{
        padding-left: 5px;
    }}
    QTableWidget::item:selected {{
        background-color: {COLOR_ACCENT_BLUE};
        color: black;
    }}
    /* --- Input Widgets --- */
    QLineEdit, QDoubleSpinBox, QListWidget, QTextEdit {{
        background-color: {COLOR_BACKGROUND_LIGHT};
        border: 1px solid {COLOR_BACKGROUND_ACCENT};
        padding: 5px;
        color: {COLOR_TEXT_PRIMARY};
        border-radius: 4px;
    }}
    QLineEdit:focus, QDoubleSpinBox:focus, QListWidget:focus, QTextEdit:focus {{
        border: 1px solid {COLOR_ACCENT_BLUE};
    }}
    QTextEdit {{
        color: {COLOR_INFO};
    }}
    /* --- Buttons --- */
    QPushButton {{
        background-color: {COLOR_BACKGROUND_ACCENT};
        color: {COLOR_TEXT_PRIMARY};
        border: 1px solid {COLOR_ACCENT_BLUE};
        padding: 6px 12px;
        font-weight: bold;
        border-radius: 4px;
    }}
    QPushButton:hover {{
        background-color: {COLOR_ACCENT_BLUE};
        color: #000;
    }}
    QPushButton:disabled {{
        background-color: #505050;
        color: {COLOR_TEXT_SECONDARY};
        border: 1px solid #505050;
    }}
    /* --- Progress Bar --- */
    QProgressBar {{
        border: 1px solid {COLOR_BACKGROUND_ACCENT};
        border-radius: 5px;
        text-align: center;
        color: {COLOR_TEXT_PRIMARY};
        background-color: {COLOR_BACKGROUND_LIGHT};
    }}
    QProgressBar::chunk {{
        background-color: {COLOR_ACCENT_BLUE};
    }}
    /* --- CheckBox --- */
    QCheckBox {{ font-size: 10pt; }}
    QCheckBox::indicator {{
        width: 18px; height: 18px;
        background-color: {COLOR_BACKGROUND_LIGHT};
        border: 1px solid {COLOR_BACKGROUND_ACCENT};
        border-radius: 4px;
    }}
    QCheckBox::indicator:checked {{
        background-color: {COLOR_ACCENT_BLUE};
        image: url(datasets/icons/logo.svg);
    }}
"""