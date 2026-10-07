import os
import joblib
import threading
import time
import pandas as pd
import warnings
from pathlib import Path
from typing import List, Dict, Any, Optional, Set
import traceback
from dynamic_scanners.SystemMonitor import SystemMonitor
from dynamic_scanners.ApiTraceManager import ApiTraceManager
from core.SignalBus import emit_log, emit_behavior_threat
from core.settings import BH_MODEL_DIR, KNOWN_GOOD_PROCESSES
warnings.filterwarnings("ignore", category=UserWarning)
class ApiSequenceClassifier:
    def __init__(self):
        self.model_dir = Path(BH_MODEL_DIR) / "api_sequence_models"
        self.vectorizer_path = self.model_dir / "API_TfidfVectorizer.joblib"
        self.encoder_path = self.model_dir / "API_LabelEncoder.joblib"
        self.models: Dict[str, Any] = {}
        self.vectorizer = None
        self.label_encoder = None
        self.is_loaded = self._load_artifacts()
    def _load_artifacts(self) -> bool:
        try:
            if not self.model_dir.exists(): return False
            if not self.vectorizer_path.exists() or not self.encoder_path.exists(): return False
            self.vectorizer = joblib.load(self.vectorizer_path)
            self.label_encoder = joblib.load(self.encoder_path)
            for file_path in self.model_dir.glob("Model_API_*.joblib"):
                model_name = file_path.stem.replace("Model_API_", "")
                self.models[model_name] = joblib.load(file_path)
            return bool(self.models)
        except Exception as e:
            emit_log(f"[ApiClassifier] ❌ Critical error loading API artifacts: {e}", "error")
            return False
    def classify(self, api_string: str, pid: int, process_name: str) -> None:
        if not self.is_loaded or not api_string: return
        try:
            vectorized_sequence = self.vectorizer.transform([api_string])
            for model_name, model in self.models.items():
                prediction_idx = model.predict(vectorized_sequence)[0]
                prediction_label = self.label_encoder.inverse_transform([prediction_idx])[0]
                score = 0.99
                if hasattr(model, 'predict_proba'):
                    probabilities = model.predict_proba(vectorized_sequence)[0]
                    score = probabilities[prediction_idx]
                if score > 0.85:
                    description = f"Process '{process_name}' (PID: {pid}) identified as '{prediction_label}' by {model_name} (Score: {score:.2f})."
                    emit_behavior_threat({ "source": "ApiClassifier", "pid": pid, "process_name": process_name, "type": f"api_ml_{prediction_label.lower()}", "description": description, "severity": "high", "score": round(score, 4) })
                    break
        except Exception as e:
            emit_log(f"[ApiClassifier] Error during API sequence prediction for PID {pid}: {e}", "error")
class SystemStateClassifier:
    """Uses a model trained on psutil features to find suspicious system states."""
    def __init__(self):
        self.model_dir = Path(BH_MODEL_DIR) / "system_state_models"
        self.model_path = self.model_dir / "Model_RandomForest.joblib"
        self.scaler_path = self.model_dir / "Data_Scaler.joblib"
        self.feature_list_path = self.model_dir / "Selected_Feature_List.joblib"
        self.model: Optional[Any] = None
        self.scaler: Optional[Any] = None
        self.feature_columns: Optional[List[str]] = None
        self.is_loaded = self._load_artifacts()
        self.FORBIDDEN_PROCESSES = { "system", "registry", "smss.exe", "csrss.exe", "wininit.exe", 
                                     "services.exe", "lsass.exe", "winlogon.exe", "svchost.exe",
                                     "memory compression", "python.exe", "py.exe", "frida-helper-x86_64.exe" }
    def _load_artifacts(self) -> bool:
        """Loads the new, simplified set of model artifacts."""
        try:
            if not all([self.model_path.exists(), self.scaler_path.exists(), self.feature_list_path.exists()]):
                emit_log(f"[SysStateClassifier] Model, scaler, or feature list not found in {self.model_dir}. System state analysis disabled.", "warning")
                return False
            self.model = joblib.load(self.model_path)
            self.scaler = joblib.load(self.scaler_path)
            self.feature_columns = joblib.load(self.feature_list_path)
            emit_log("[SysStateClassifier] ✅ System state model, scaler, and feature list loaded.", "info")
            return True
        except Exception as e:
            emit_log(f"[SysStateClassifier] ❌ Critical error loading system state artifacts: {e}", "error")
            return False
    def _extract_features_from_snapshot(self, snapshot: Dict[str, Any]) -> Optional[pd.DataFrame]:
        """
        This is the live implementation and MUST BE IDENTICAL to the logic in
        `scripts/generate_training_features.py`.
        """
        processes = snapshot.get('processes')
        if not processes:
            return None
        proc_df = pd.DataFrame(processes)
        features = {}
        features['proc.count.total'] = len(proc_df)
        features['proc.count.running'] = len(proc_df[proc_df['status'] == 'running'])
        features['proc.count.sleeping'] = len(proc_df[proc_df['status'] == 'sleeping'])
        features['proc.count.zombie'] = len(proc_df[proc_df['status'] == 'zombie'])
        features['proc.count.unique_names'] = proc_df['name'].nunique()
        features['proc.avg.threads'] = proc_df['num_threads'].mean()
        features['proc.avg.handles'] = proc_df['num_handles'].mean()
        features['proc.avg.cpu_percent'] = proc_df['cpu_percent'].mean()
        features['proc.avg.mem_percent'] = proc_df['memory_percent'].mean()
        features['proc.count.unique_users'] = proc_df['username'].nunique()
        features['proc.count.null_user'] = proc_df['username'].isnull().sum()
        net_io = snapshot.get('net_io', {})
        features['net.count.connections'] = net_io.get('connections', 0)
        features['net.count.listening_ports'] = net_io.get('listening', 0)
        features['net.count.established'] = net_io.get('established', 0)
        features['net.count.unique_remote_ips'] = net_io.get('unique_remotes', 0)
        feature_row = pd.DataFrame([features], columns=self.feature_columns)
        feature_row.fillna(0, inplace=True)
        return feature_row
    def find_suspicious_candidates(self, sequence: List[Dict]) -> Set[int]:
        if not self.is_loaded or not sequence: return set()
        latest_snapshot = sequence[-1]
        feature_vector = self._extract_features_from_snapshot(latest_snapshot)
        if feature_vector is None: return set()
        scaled_vector = self.scaler.transform(feature_vector)
        suspicious_pids: Set[int] = set()
        try:
            prediction = self.model.predict(scaled_vector)[0]
            if prediction == 1:
                all_procs_df = pd.DataFrame(latest_snapshot.get('processes', []))
                if all_procs_df.empty: return set()
                potential_pids = set(all_procs_df['pid'])
                safe_pids = {pid for pid in potential_pids if all_procs_df[all_procs_df['pid'] == pid].iloc[0]['name'].lower() in self.FORBIDDEN_PROCESSES}
                final_pids = potential_pids - safe_pids
                suspicious_pids.update(final_pids)
                if final_pids:
                    emit_log(f"[SysStateClassifier] Model flagged system state as potentially malicious. Identifying {len(final_pids)} candidates for API tracing.", "warning")
        except Exception as e:
            emit_log(f"[SysStateClassifier] Prediction failed: {e}", "error")
        return suspicious_pids
class BehaviorMonitor:
    def __init__(self, system_monitor: SystemMonitor, scan_interval: float = 10.0):
        self.system_monitor = system_monitor
        self.scan_interval = scan_interval
        self._running = threading.Event()
        self._thread: Optional[threading.Thread] = None
        emit_log("[BehaviorMonitor] Initializing analysis pipeline...", "info")
        self.state_classifier = SystemStateClassifier()
        self.api_classifier = ApiSequenceClassifier()
        self.api_tracer = ApiTraceManager()
        self.process_map: Dict[int, str] = {}
        self.traced_pids: Set[int] = set()
    def _run_loop(self) -> None:
        emit_log("[BehaviorMonitor] Started continuous analysis pipeline.", "info")
        while not self._running.is_set():
            try:
                self._running.wait(self.scan_interval)
                sequence = self.system_monitor.get_recent_behavior_sequence()
                if not sequence: continue
                current_procs = {p['pid']: p['name'] for p in sequence[-1].get('processes', []) if p.get('pid')}
                self.process_map.update(current_procs)
                candidate_pids = self.state_classifier.find_suspicious_candidates(sequence)
                for pid in candidate_pids:
                    if pid in current_procs and pid not in self.traced_pids:
                        proc_name = current_procs.get(pid, "Unknown")
                        self.api_tracer.start_tracing(pid, proc_name)
                        self.traced_pids.add(pid)
                for pid in list(self.traced_pids):
                    if pid not in current_procs:
                        self.api_tracer.stop_tracing(pid)
                        self.traced_pids.remove(pid)
                        continue
                    api_string = self.api_tracer.get_and_clear_sequence(pid)
                    if api_string:
                        self.api_classifier.classify(api_string, pid, self.process_map.get(pid, "Unknown"))
            except Exception as e:
                emit_log(f"[BehaviorMonitor] CRITICAL ERROR IN MAIN LOOP: {e}\n{traceback.format_exc()}", "error")
        for pid in list(self.traced_pids): self.api_tracer.stop_tracing(pid)
    def start(self) -> None:
        if self._thread and self._thread.is_alive(): return
        self._running.clear()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
    def stop(self) -> None:
        if not self._thread or not self._thread.is_alive(): return
        self._running.set()
        self._thread.join(timeout=self.scan_interval + 2)