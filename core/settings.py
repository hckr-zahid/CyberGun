import os
import sys
from pathlib import Path
import psutil
if getattr(sys, 'frozen', False):
    exe_dir = Path(sys.executable).resolve().parent
    if (exe_dir / "datasets").exists():
        BASE_DIR = exe_dir
    elif hasattr(sys, '_MEIPASS') and (Path(sys._MEIPASS) / "datasets").exists():
        BASE_DIR = Path(sys._MEIPASS)
    elif (exe_dir / "_internal" / "datasets").exists():
        BASE_DIR = exe_dir / "_internal"
    else:
        BASE_DIR = exe_dir
else:
    BASE_DIR = Path(__file__).resolve().parent.parent
HOME_DIR = Path.home()
DEFAULT_SCAN_PATH = str(HOME_DIR / "Downloads")
if not os.path.isdir(DEFAULT_SCAN_PATH):
    DEFAULT_SCAN_PATH = str(HOME_DIR)
HASH_DIR = BASE_DIR / "datasets" / "hashes"
YARA_RULES_DIR = BASE_DIR / "datasets" / "yara_rules"
SIGNATURE_DIR = BASE_DIR / "datasets" / "signatures"
NETWORK_BLACKLIST_PATH = BASE_DIR / "datasets" / "network"
STRING_SIGNATURES_PATH = BASE_DIR / "datasets" / "strings"
def _resolve_model_dir(subfolder: str) -> Path:
    candidates = [
        BASE_DIR / "models" / subfolder,
        BASE_DIR / "_internal" / "models" / subfolder,
        Path(__file__).resolve().parent.parent / "models" / subfolder
    ]
    if getattr(sys, 'frozen', False):
        exe_dir = Path(sys.executable).resolve().parent
        candidates.extend([
            exe_dir / "_internal" / "models" / subfolder,
            exe_dir / "models" / subfolder,
        ])
    for c in candidates:
        if c.exists() and c.is_dir():
            return c
    return BASE_DIR / "models" / subfolder
ML_MODEL_DIR = _resolve_model_dir("static_models")
BH_MODEL_DIR = _resolve_model_dir("behavior_models")
LOG_DIR = BASE_DIR / "logs"
THREAT_LOG_PATH = LOG_DIR / "threats.log"
SYSTEM_LOG_PATH = LOG_DIR / "system.log"
QUARANTINE_DIR = BASE_DIR / "quarantine"
try:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
except Exception:
    pass
ENABLE_HASH_SCAN = True
ENABLE_YARA_SCAN = True
ENABLE_ML_SCAN = True
ENABLE_SIGNATURE_SCAN = True
ENABLE_STRING_SCAN = True
ENABLE_BEHAVIOR_MONITOR = True
ENABLE_NETWORK_MONITOR = True
ALLOWED_EXTENSIONS = []
ML_CONFIDENCE_THRESHOLD = 0.8
def find_best_network_interface() -> str:
    """Finds the most likely active, non-loopback network interface."""
    try:
        stats = psutil.net_if_stats()
        addrs = psutil.net_if_addrs()
        for iface, iface_stats in stats.items():
            if iface_stats.isup and 'loopback' not in iface.lower() and iface in addrs:
                for addr in addrs[iface]:
                    if addr.family == psutil.AF_LINK:
                        return iface
    except Exception:
        pass
    return "Ethernet"
TSHARK_CUSTOM_PATH = r"C:\Program Files\Wireshark"
NETWORK_INTERFACE = find_best_network_interface()
NETWORK_ANALYZE_INTERVAL = 5.0
SNIFFER_PACKET_QUEUE_MAXSIZE = 8192
SYSTEM_MONITOR_INTERVAL = 2.0
BEHAVIOR_SEQUENCE_MAXLEN = 100
ENABLE_REMOTE_STRINGS = True
WINDOW_SIZE = (1280, 800)
GUI_THEME = "hacker"
SYSTEM_ROOT = os.environ.get('SystemRoot', 'C:\\Windows').lower()
PROGRAM_FILES = os.environ.get('ProgramFiles', 'C:\\Program Files').lower()
PROGRAM_FILES_X86 = os.environ.get('ProgramFiles(x86)', 'C:\\Program Files (x86)').lower()
USER_PROFILE = os.environ.get('UserProfile', '').lower()
KNOWN_GOOD_PROCESSES = {
    """'system': 'system',
    'smss.exe': os.path.join(SYSTEM_ROOT, 'system32'),
    'csrss.exe': os.path.join(SYSTEM_ROOT, 'system32'),
    'wininit.exe': os.path.join(SYSTEM_ROOT, 'system32'),
    'winlogon.exe': os.path.join(SYSTEM_ROOT, 'system32'),
    'lsass.exe': os.path.join(SYSTEM_ROOT, 'system32'),
    'services.exe': os.path.join(SYSTEM_ROOT, 'system32'),
    'svchost.exe': os.path.join(SYSTEM_ROOT, 'system32'),
    # --- User Interface and Shell Processes ---
    'explorer.exe': os.path.join(SYSTEM_ROOT, 'explorer.exe'),
    'dwm.exe': os.path.join(SYSTEM_ROOT, 'system32'),
    'sihost.exe': os.path.join(SYSTEM_ROOT, 'system32'),
    'ctfmon.exe': os.path.join(SYSTEM_ROOT, 'system32'),
    'conhost.exe': os.path.join(SYSTEM_ROOT, 'system32'),
    'runtimebroker.exe': os.path.join(SYSTEM_ROOT, 'system32'),
    'taskhostw.exe': os.path.join(SYSTEM_ROOT, 'system32'),
    'shellexperiencehost.exe': os.path.join(SYSTEM_ROOT, 'systemapps'),
    'applicationframehost.exe': os.path.join(SYSTEM_ROOT, 'system32'),
    'logonui.exe': os.path.join(SYSTEM_ROOT, 'system32'),
    # --- Common Windows Services & Drivers ---
    'spoolsv.exe': os.path.join(SYSTEM_ROOT, 'system32'),
    'wmiprvse.exe': os.path.join(SYSTEM_ROOT, 'wbem'),
    'audiodg.exe': os.path.join(SYSTEM_ROOT, 'system32'),
    'dllhost.exe': os.path.join(SYSTEM_ROOT, 'system32'),
    'fontdrvhost.exe': os.path.join(SYSTEM_ROOT, 'system32'),
    'smartscreen.exe': os.path.join(SYSTEM_ROOT, 'system32'),
    # --- Microsoft Defender (Built-in Antivirus) ---
    'msmpeng.exe': os.path.join(PROGRAM_FILES, 'windows defender'),
    'nissrv.exe': os.path.join(PROGRAM_FILES, 'windows defender'),
    'securityhealthservice.exe': os.path.join(SYSTEM_ROOT, 'system32'),
    # --- Microsoft Store & UWP Related ---
    'wsappx.exe': os.path.join(SYSTEM_ROOT, 'system32'),
    'winstore.app.exe': os.path.join(PROGRAM_FILES, 'windowsapps'),
    # --- Common Third-Party Applications (paths are defaults) ---
    'chrome.exe': os.path.join(PROGRAM_FILES, 'google\\chrome\\application'),
    'firefox.exe': os.path.join(PROGRAM_FILES, 'mozilla firefox'),
    'msedge.exe': os.path.join(PROGRAM_FILES_X86, 'microsoft\\edge\\application'),
    'winword.exe': os.path.join(PROGRAM_FILES, 'microsoft office\\root\\office'),
    'excel.exe': os.path.join(PROGRAM_FILES, 'microsoft office\\root\\office'),
    'powerpnt.exe': os.path.join(PROGRAM_FILES, 'microsoft office\\root\\office'),
    'outlook.exe': os.path.join(PROGRAM_FILES, 'microsoft office\\root\\office'),
    'onedrive.exe': os.path.join(USER_PROFILE, 'appdata\\local\\microsoft\\onedrive') if USER_PROFILE else '',
    # --- Common Developer Tools ---
    'code.exe': os.path.join(USER_PROFILE, 'appdata\\local\\programs\\microsoft vs code') if USER_PROFILE else '',"""
    'dockerd.exe': os.path.join(PROGRAM_FILES, 'docker\\docker\\resources\\bin'),
}
KNOWN_GOOD_PROCESSES = {k: v for k, v in KNOWN_GOOD_PROCESSES.items() if v}