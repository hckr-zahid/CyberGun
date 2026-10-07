import frida
import threading
from collections import defaultdict
from typing import Dict, List, Set
from core.SignalBus import emit_log
from utils.system_checks import is_admin
class ApiTraceManager:
    AGENT_SCRIPT = """
    send({ type: 'agent:log', payload: 'Frida agent injected and ready.' });
    const functionsToHook = {
        'ntdll.dll': ['LdrLoadDll', 'NtCreateFile', 'NtWriteVirtualMemory'],
        'kernel32.dll': ['CreateFileW', 'CreateProcessW', 'WriteFile', 'VirtualAllocEx', 'LoadLibraryA', 'LoadLibraryW'],
        'advapi32.dll': ['RegOpenKeyExW', 'RegCreateKeyExW', 'RegSetValueExW']
    };
    function hookFunction(moduleName, functionName) {
        try {
            const pointer = Module.findExportByName(moduleName, functionName);
            if (!pointer) { return; }
            Interceptor.attach(pointer, {
                onEnter: function (args) { send({ type: 'agent:api_call', payload: functionName }); }
            });
        } catch (err) { /* Silently ignore errors for non-existent functions */ }
    }
    for (const moduleName in functionsToHook) {
        functionsToHook[moduleName].forEach(functionName => { hookFunction(moduleName, functionName); });
    }
    """
    def __init__(self):
        self.sessions: Dict[int, frida.core.Session] = {}
        self.api_sequences: Dict[int, List[str]] = defaultdict(list)
        self.traced_pids: Set[int] = set()
        self._lock = threading.Lock()
        self.has_privileges = is_admin()
        if not self.has_privileges:
            emit_log("[ApiTraceManager] Running without administrator privileges. API tracing will be disabled.", "warning")
    def _on_message(self, pid: int, process_name: str):
        def wrapper(message, data):
            if message.get('type') == 'send':
                payload = message.get('payload', {})
                msg_type, payload_data = payload.get('type'), payload.get('payload')
                if msg_type == 'agent:api_call':
                    with self._lock: self.api_sequences[pid].append(payload_data)
        return wrapper
    def start_tracing(self, pid: int, process_name: str):
        if not self.has_privileges:
            return
        with self._lock:
            if pid in self.traced_pids: return
        thread = threading.Thread(target=self._attach_and_load, args=(pid, process_name), daemon=True)
        thread.start()
    def _attach_and_load(self, pid: int, process_name: str):
        try:
            session = frida.attach(pid)
            script = session.create_script(self.AGENT_SCRIPT)
            script.on('message', self._on_message(pid, process_name))
            script.load()
            with self._lock:
                self.sessions[pid] = session
                self.traced_pids.add(pid)
            emit_log(f"[ApiTraceManager] ✅ Successfully attached to PID: {pid} ({process_name})", "info")
        except frida.ProcessNotFoundError:
            emit_log(f"[ApiTraceManager] Process {pid} not found (likely terminated).", "info")
        except frida.PermissionDeniedError:
            emit_log(f"[ApiTraceManager] Permission denied for PID: {pid}. Cannot trace protected processes.", "warning")
        except Exception as e:
            emit_log(f"[ApiTraceManager] Failed to attach to PID {pid}: {e}", "error")
    def stop_tracing(self, pid: int):
        with self._lock:
            if pid not in self.traced_pids: return
            session = self.sessions.pop(pid, None)
            self.traced_pids.remove(pid)
        if session and not session.is_detached:
            try: session.detach()
            except Exception: pass
    def get_and_clear_sequence(self, pid: int) -> str:
        with self._lock:
            if pid not in self.api_sequences: return ""
            sequence_list = list(self.api_sequences[pid])
            self.api_sequences[pid].clear()
        return " ".join(sequence_list)