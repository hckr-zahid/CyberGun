import os
import sys
if getattr(sys, 'frozen', False):
    exe_dir = os.path.dirname(sys.executable)
    internal_dir = os.path.join(exe_dir, '_internal')
    dll_dir = os.path.join(sys.prefix, 'DLLs')
    try:
        os.makedirs(dll_dir, exist_ok=True)
    except Exception:
        pass
    target_dll = os.path.join(dll_dir, 'libyara.dll')
    if not os.path.exists(target_dll):
        candidates = [
            os.path.join(internal_dir, 'libyara.dll'),
            os.path.join(internal_dir, 'DLLs', 'libyara.dll'),
            os.path.join(exe_dir, 'libyara.dll'),
            os.path.join(exe_dir, 'DLLs', 'libyara.dll'),
        ]
        for c in candidates:
            if os.path.exists(c):
                try:
                    import shutil
                    shutil.copy2(c, target_dll)
                    break
                except Exception:
                    pass
    for p in [
        dll_dir,
        os.path.join(internal_dir, 'DLLs'),
        os.path.join(exe_dir, 'DLLs'),
        internal_dir
    ]:
        if os.path.isdir(p):
            os.environ['PATH'] = p + os.pathsep + os.environ.get('PATH', '')
            if hasattr(os, 'add_dll_directory'):
                try:
                    os.add_dll_directory(p)
                except Exception:
                    pass
from PyQt5.QtWidgets import QApplication, QMessageBox
from PyQt5.QtCore import QThread, pyqtSlot
from PyQt5.QtGui import QIcon
from gui.gui_app import GuiApp
from core.engine_launcher import EngineLauncher
from core.SignalBus import get_signal_bus, emit_log
from core.settings import BASE_DIR
from utils.system_checks import is_admin
def main():
    """
    The main entry point for the CyberGun application.
    Initializes the GUI, the backend engines, and connects them.
    """
    try:
        os.chdir(str(BASE_DIR))
    except Exception:
        pass
    try:
        import ctypes
        app_id = 'cybergun.threat.mitigation.suite.1.0'
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(app_id)
    except Exception:
        pass
    from PyQt5.QtCore import Qt
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
    app = QApplication(sys.argv)
    icon_candidates = [
        os.path.join(str(BASE_DIR), "datasets", "icons", "icon.ico"),
        os.path.join(str(BASE_DIR), "datasets", "icons", "icon.png"),
        os.path.join(
            os.path.dirname(sys.executable),
            "datasets",
            "icons",
            "icon.ico"
        ),
        os.path.join(
            os.path.dirname(sys.executable),
            "_internal",
            "datasets",
            "icons",
            "icon.ico"
        ),
    ]
    app_icon = None
    for icon_path in icon_candidates:
        if os.path.exists(icon_path):
            app_icon = QIcon(icon_path)
            break
    if app_icon and not app_icon.isNull():
        app.setWindowIcon(app_icon)
    if not is_admin():
        warning_msg = (
            "CyberGun is running without administrator privileges.\n\n"
            "Key features will be disabled:\n"
            "• Automatic Firewall Blocking\n"
            "• Advanced API Tracing for Behavior Analysis\n"
            "• Termination of Protected Malicious Processes\n\n"
            "For full protection, please close the application "
            "and run it as an Administrator."
        )
        QMessageBox.warning(
            None,
            "Privilege Warning",
            warning_msg
        )
        emit_log(
            "[Main] Application started without administrator privileges. "
            "Functionality will be degraded.",
            "warning"
        )
    else:
        emit_log(
            "[Main] Application started with administrator privileges. "
            "Full functionality enabled.",
            "info"
        )
    engine_launcher = EngineLauncher()
    main_window = GuiApp()
    backend_thread = QThread()
    engine_launcher.moveToThread(backend_thread)
    backend_thread.started.connect(
        engine_launcher.run_initial_setup
    )
    @pyqtSlot()
    def on_dashboard_ready():
        """
        This slot is called ONLY after the dashboard UI is fully created
        and visible. It's now safe to start background processes and
        connect signals.
        """
        emit_log(
            "[Main] Dashboard is ready. Starting background services.",
            "info"
        )
        signal_bus = get_signal_bus()
        if main_window.dashboard:
            signal_bus.start_scan.connect(
                engine_launcher.start_static_scan_on_directory
            )
            signal_bus.start_scan_path.connect(
                engine_launcher.start_static_scan_on_directory
            )
            main_window.dashboard.update_db_btn.clicked.connect(
                engine_launcher.start_threat_update
            )
        engine_launcher.start_all_continuous_monitors()
        engine_launcher.run_background_tasks()
    get_signal_bus().dashboard_ready.connect(
        on_dashboard_ready
    )
    backend_thread.start()
    main_window.show()
    emit_log(
        "CyberGun Application Startup Complete.",
        "info"
    )
    app.aboutToQuit.connect(
        engine_launcher.stop_all_monitors
    )
    app.aboutToQuit.connect(
        backend_thread.quit
    )
    app.aboutToQuit.connect(
        backend_thread.wait
    )
    sys.exit(app.exec_())
if __name__ == "__main__":
    main()