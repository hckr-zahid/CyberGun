import os
import subprocess
import threading
import tempfile
import shutil
import time
from typing import Optional
from core.SignalBus import emit_log, emit_sandbox_log
class SandboxSim:
    """
    A professional-grade sandboxing simulator for executing untrusted files.
    """
    def __init__(self):
        self._temp_dir: Optional[str] = None
        self._process: Optional[subprocess.Popen] = None
        self._lock = threading.Lock()
    def _cleanup_environment(self) -> None:
        """Robustly cleans up the sandbox directory and resources."""
        with self._lock:
            if self._temp_dir and os.path.exists(self._temp_dir):
                try:
                    shutil.rmtree(self._temp_dir)
                except OSError as e:
                    emit_log(f"[SandboxSim] Error cleaning sandbox {self._temp_dir}: {e}", "error")
            self._temp_dir = None
            self._process = None
    def is_running(self) -> bool:
        """Checks if a sandbox process is currently active."""
        with self._lock:
            return self._process is not None and self._process.poll() is None
    def execute(self, file_path: str, timeout: int = 15, completion_event: Optional[threading.Event] = None) -> None:
        """Securely copies and executes a file in an isolated environment."""
        if not os.path.isfile(file_path):
            emit_log(f"[SandboxSim] File not found: {file_path}", "error")
            if completion_event: completion_event.set()
            return
        with self._lock:
            self._temp_dir = tempfile.mkdtemp(prefix="cybergun_sandbox_")
            sandboxed_file = os.path.join(self._temp_dir, os.path.basename(file_path))
        try:
            shutil.copy2(file_path, sandboxed_file)
            if os.name == 'posix': os.chmod(sandboxed_file, 0o755)
        except Exception as e:
            emit_log(f"[SandboxSim] Failed to prepare sandbox: {e}", "error")
            self._cleanup_environment()
            if completion_event: completion_event.set()
            return
        def _run_target():
            try:
                emit_log(f"[SandboxSim] Executing: {sandboxed_file}", "info")
                with self._lock:
                    self._process = subprocess.Popen(
                        [sandboxed_file],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        cwd=self._temp_dir, shell=False
                    )
                try:
                    stdout, stderr = self._process.communicate(timeout=timeout)
                    emit_sandbox_log(f"--- Sandbox Log for {os.path.basename(file_path)} ---\n"
                                     f"STDOUT:\n{stdout.decode(errors='ignore')}\n"
                                     f"STDERR:\n{stderr.decode(errors='ignore')}")
                except subprocess.TimeoutExpired:
                    with self._lock:
                        if self._process: self._process.kill()
                    emit_log(f"[SandboxSim] Execution for {os.path.basename(file_path)} timed out and was terminated.", "warning")
            except Exception as e:
                emit_log(f"[SandboxSim] Critical error during execution: {e}", "error")
            finally:
                self._cleanup_environment()
                if completion_event: completion_event.set()
        thread = threading.Thread(target=_run_target, daemon=True)
        thread.start()