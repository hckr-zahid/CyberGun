import os
import sys
from pathlib import Path
import lightgbm as lgb
import thrember
from typing import List, Dict, Optional, Any
import struct
import gc
from core import config_manager
from core.settings import ML_MODEL_DIR, ENABLE_ML_SCAN, BASE_DIR
from core.SignalBus import emit_log, get_signal_bus
class MLDetector:
    """An ML-based scanner that loads models on demand for low memory usage."""
    def __init__(self):
        self._model_cache: Dict[str, Any] = {}
        self.resources_loaded = False
        self._model_mapping: Dict[str, str] = {
            "apk": "apk_model.lgbm",
            "dotnet": "dotnet_model.lgbm",
            "elf": "elf_model.lgbm",
            "pdf": "pdf_model.lgbm",
            "win64": "win64_model.lgbm",
            "win32": "win32_model.lgbm",
        }
        self.signal_bus = get_signal_bus()
    def load_resources(self) -> None:
        """Enables the model cache. Models are still loaded lazily upon first use."""
        if not ENABLE_ML_SCAN or self.resources_loaded:
            return
        emit_log(f"[{self.__class__.__name__}] ML Detector is now active. Models will be loaded on first use.", "info")
        self.resources_loaded = True
    def unload_resources(self) -> None:
        """Clears the ML model cache from memory."""
        if not self.resources_loaded:
            return
        emit_log(f"[{self.__class__.__name__}] Unloading ML model cache.", "info")
        self._model_cache.clear()
        self.resources_loaded = False
        gc.collect()
    def _infer_file_type(self, file_path: Path) -> str:
        ext = file_path.suffix.lower()
        if ext in ['.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp', '.ico', '.svg', '.mp3', '.mp4', '.avi', '.wav', '.txt', '.csv', '.log', '.json', '.xml', '.html']:
            return "unknown"
        try:
            with open(file_path, "rb") as f:
                header = f.read(8)
                if header.startswith(b'MZ'):
                    f.seek(0x3c)
                    pe_offset_bytes = f.read(4)
                    if not pe_offset_bytes: return 'unknown'
                    pe_offset = struct.unpack('<I', pe_offset_bytes)[0]
                    f.seek(pe_offset)
                    pe_header = f.read(6)
                    if not pe_header.startswith(b'PE\0\0'):
                        return 'unknown'
                    f.seek(pe_offset + 24) 
                    magic = f.read(2)
                    if magic == b'\x0b\x01': return 'win32'
                    elif magic == b'\x0b\x02': return 'win64'
                elif header.startswith(b'\x7fELF'): return 'elf'
                elif header.startswith(b'%PDF-') or ext == '.pdf': return 'pdf'
                elif header.startswith(b'PK\x03\x04') and ext == '.apk': return 'apk'
        except (IOError, PermissionError, struct.error):
            return "unknown"
        if ext in ['.exe', '.dll', '.sys']: return 'win64' 
        if ext == '.apk': return 'apk'
        if ext == '.pdf': return 'pdf'
        return "unknown"
    def _load_model(self, file_type: str) -> Optional[lgb.Booster]:
        if file_type in self._model_cache:
            return self._model_cache[file_type]
        model_filename = self._model_mapping.get(file_type)
        if not model_filename:
            return None
        candidates = [
            ML_MODEL_DIR / model_filename,
            Path(ML_MODEL_DIR) / model_filename,
            Path(BASE_DIR) / "models" / "static_models" / model_filename,
            Path(BASE_DIR) / "_internal" / "models" / "static_models" / model_filename,
            Path(os.path.dirname(sys.executable)) / "models" / "static_models" / model_filename,
            Path(os.path.dirname(sys.executable)) / "_internal" / "models" / "static_models" / model_filename,
        ]
        model_path = None
        for cand in candidates:
            if cand.exists():
                model_path = cand
                break
        if not model_path:
            emit_log(f"[{self.__class__.__name__}] Model '{model_filename}' not found for type '{file_type}'. Checked: {[str(c) for c in candidates[:3]]}", "warning")
            return None
        try:
            model = lgb.Booster(model_file=str(model_path))
            self._model_cache[file_type] = model
            emit_log(f"[{self.__class__.__name__}] Loaded and cached model: {model_filename} from {model_path}", "info")
            return model
        except Exception as e:
            emit_log(f"[{self.__class__.__name__}] Failed to load model {model_filename}: {e}", "error")
            return None
    def scan(self, file_path: str) -> List[Dict]:
        """Detects threats in a file using an ML model, which is loaded on demand."""
        self.signal_bus.scan_progress_updated.emit({
            "layer": self.__class__.__name__,
            "message": f"Running ML analysis on {os.path.basename(file_path)}"
        })
        if not ENABLE_ML_SCAN or not self.resources_loaded:
            return []
        path = Path(file_path)
        file_type = self._infer_file_type(path)
        if file_type == "unknown":
            return []
        model = self._load_model(file_type)
        if not model:
            emit_log(f"[{self.__class__.__name__}] Could not load a model for detected file type '{file_type}' on file {file_path}", "warning")
            return []
        try:
            with open(file_path, "rb") as f:
                file_data = f.read()
            if not file_data: return []
            score = thrember.predict_sample(model, file_data)
            if score >= config_manager.get_ml_confidence_threshold():
                return [{
                    "source": self.__class__.__name__,
                    "type": "ml_detection",
                    "description": f"ML model for '{file_type}' predicted malicious with score {score:.2f}",
                    "severity": "high",
                    "malware_name": f"ML.Malware.{file_type.capitalize()}",
                }]
        except Exception as e:
            emit_log(f"[{self.__class__.__name__}] Prediction failed for {file_path}: {e}", "error")
        return []