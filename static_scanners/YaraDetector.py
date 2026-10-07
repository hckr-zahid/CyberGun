import os
import yara
from typing import List, Dict, Optional
import gc
from pathlib import Path
from core.settings import YARA_RULES_DIR, ENABLE_YARA_SCAN
from core.SignalBus import emit_log, get_signal_bus
class YaraDetector:
    """A professional YARA scanner that validates each rule to silently skip problematic ones and compile only the valid rules."""
    def __init__(self):
        self.rules: Optional[yara.Rules] = None
        self.resources_loaded = False
        self.signal_bus = get_signal_bus()
    def load_resources(self) -> None:
        if not ENABLE_YARA_SCAN or self.resources_loaded:
            return
        emit_log(f"[{self.__class__.__name__}] Starting YARA rule validation...", "info")
        if not YARA_RULES_DIR.exists() or not YARA_RULES_DIR.is_dir():
            emit_log(f"[{self.__class__.__name__}] YARA rules directory not found: {YARA_RULES_DIR}", "error")
            return
        original_cwd = os.getcwd()
        try:
            os.chdir(YARA_RULES_DIR)
            rule_files = list(Path.cwd().glob("**/*.yar")) + list(Path.cwd().glob("**/*.yara"))
            total_files = len(rule_files)
            if total_files == 0:
                emit_log(f"[{self.__class__.__name__}] No YARA rule files found.", "warning")
                return
            valid_filepaths = {}
            for file_path in rule_files:
                try:
                    yara.compile(filepath=str(file_path))
                    namespace = os.path.relpath(file_path).replace(os.sep, "_")
                    valid_filepaths[namespace] = str(file_path.resolve())
                except yara.YaraSyntaxError:
                    continue
            valid_count = len(valid_filepaths)
            problematic_count = total_files - valid_count
            emit_log(f"[{self.__class__.__name__}] Validation complete. Total files: {total_files}, Valid: {valid_count}, Problematic (skipped): {problematic_count}", "info")
            if not valid_filepaths:
                emit_log(f"[{self.__class__.__name__}] ❌ No valid YARA rules could be compiled.", "error")
                return
            externals = {
                'filename': 's', 'filepath': 's', 'extension': 's',
                'filetype': 's', 'owner': 's', 'size': 'i'
            }
            self.rules = yara.compile(filepaths=valid_filepaths, externals=externals)
            self.resources_loaded = True
            emit_log(f"[{self.__class__.__name__}] ✅ Successfully compiled {valid_count} valid files into a single ruleset.", "info")
        except Exception as e:
            emit_log(f"[{self.__class__.__name__}] An unexpected critical error occurred during YARA compilation: {e}", "error")
            self.rules = None
        finally:
            os.chdir(original_cwd)
    def unload_resources(self) -> None:
        if not self.resources_loaded:
            return
        emit_log(f"[{self.__class__.__name__}] Unloading YARA rules.", "info")
        self.rules = None
        self.resources_loaded = False
        gc.collect()
    def scan(self, file_path: str) -> List[Dict]:
        """
        Scans a single file against the compiled YARA ruleset with robust error handling.
        """
        self.signal_bus.scan_progress_updated.emit({
            "layer": self.__class__.__name__,
            "message": f"Applying YARA rules to {os.path.basename(file_path)}"
        })
        if not ENABLE_YARA_SCAN or not self.rules:
            return []
        all_matches = []
        try:
            filename = os.path.basename(file_path)
            try:
                owner = Path(file_path).owner()
            except Exception:
                owner = "N/A"
            externals = {
                'filename': filename,
                'filepath': file_path,
                'extension': os.path.splitext(filename)[1],
                'owner': owner,
                'size': os.path.getsize(file_path)
            }
            matches = self.rules.match(filepath=file_path, externals=externals)
            for match in matches:
                if hasattr(match, 'meta'):
                    description = match.meta.get('description', f"YARA rule match: {match.rule}")
                    severity = match.meta.get("severity", "high")
                    malware_name = match.meta.get("malware_family", match.rule)
                else:
                    rule_name = str(match)
                    description = f"YARA rule match: {rule_name}"
                    severity = "high"
                    malware_name = rule_name
                all_matches.append({
                    "source": self.__class__.__name__,
                    "type": "yara_rule",
                    "description": description,
                    "severity": severity,
                    "malware_name": malware_name,
                })
        except yara.YaraSyntaxError as e:
            if "Could not open file" not in str(e) and "Zero length file" not in str(e):
                emit_log(f"[{self.__class__.__name__}] YARA scan error on {os.path.basename(file_path)}: {e}", "warning")
        except (IOError, PermissionError):
             pass
        except Exception as e:
            emit_log(f"[{self.__class__.__name__}] An unhandled error occurred scanning {os.path.basename(file_path)}: {e}", "error")
        return all_matches