import os
from pathlib import Path
import concurrent.futures
from typing import List, Optional, Callable, Dict
import time
from static_scanners.HashDetector import HashDetector
from static_scanners.YaraDetector import YaraDetector
from static_scanners.MLDetector import MLDetector
from static_scanners.StringDetector import StringDetector
from static_scanners.SignDetector import SignDetector
from core.SignalBus import emit_log, emit_threat, get_signal_bus
from core import config_manager 
class StaticEngine:
    """
    Manages static scanners with on-demand resource loading for memory efficiency.
    """
    def __init__(self):
        emit_log("[StaticEngine] Initializing...", "info")
        self.scanners = [
           HashDetector(),
            YaraDetector(),
            SignDetector(),
            StringDetector(),
            MLDetector()
        ]
        emit_log(f"[StaticEngine] {len(self.scanners)} scanners are ready in a low-memory state.", "info")
    def scan_file(self, file_path: str) -> List[Dict]:
        """
        Scans a single file with all available static scanners.
        Loads and unloads resources for each scanner to keep memory usage minimal.
        """
        all_findings = []
        if not os.path.isfile(file_path):
            return []
        for scanner in self.scanners:
            try:
                scanner.load_resources()
                results = scanner.scan(file_path)
                if results and isinstance(results, list):
                    for res in results:
                        res['file'] = file_path
                    all_findings.extend(results)
            except Exception as e:
                emit_log(f"[{scanner.__class__.__name__}] Unhandled error scanning {file_path}: {e}", "error")
            finally:
                scanner.unload_resources()
        return all_findings
    def scan_directory(self, directory_path: str, stop_check_callback: Optional[Callable[[], bool]] = None) -> List[Dict]:
        """
        Scans a directory concurrently. For performance, it loads each scanner's
        resources once for the entire batch of files.
        """
        total_threats = []
        files_to_scan = self._collect_files(directory_path, stop_check_callback)
        if not files_to_scan:
            return []
        emit_log(f"[StaticEngine] Beginning concurrent scan of {len(files_to_scan)} files.", "info")
        for scanner in self.scanners:
            if stop_check_callback and stop_check_callback():
                emit_log("[StaticEngine] Scan aborted by user.", "warning")
                break
            try:
                scanner.load_resources()
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future_to_file = {executor.submit(scanner.scan, file): file for file in files_to_scan}
                    for future in concurrent.futures.as_completed(future_to_file):
                        if stop_check_callback and stop_check_callback():
                            executor.shutdown(wait=False, cancel_futures=True)
                            break
                        try:
                            findings = future.result()
                            if findings:
                                for finding in findings:
                                    finding['file'] = future_to_file[future]
                                    emit_threat(finding)
                                total_threats.extend(findings)
                        except Exception as e:
                            emit_log(f"[StaticEngine] Error processing result for {future_to_file[future]}: {e}", "error")
            finally:
                scanner.unload_resources() 
        emit_log(f"[StaticEngine] Scan complete. Total threats found: {len(total_threats)}", "info")
        return total_threats
    def scan_directory_layered(self, directory_path: str, stop_check_callback: Optional[Callable[[], bool]] = None) -> List[Dict]:
        """
        Performs a memory-efficient, sequential scan of a directory.
        It scans all files with one layer at a time to prevent race conditions.
        """
        all_threats = []
        files_to_scan = self._collect_files(directory_path, stop_check_callback)
        if not files_to_scan:
            return []
        emit_log(f"[StaticEngine] Beginning LAYERED scan of {len(files_to_scan)} files.", "info")
        flagged_files = set()
        bus = get_signal_bus()
        total_files = len(files_to_scan)
        for scanner in self.scanners:
            scanner_name = scanner.__class__.__name__
            if (scanner_name == 'HashDetector' and not config_manager.is_hash_scan_enabled()) or \
               (scanner_name == 'YaraDetector' and not config_manager.is_yara_scan_enabled()) or \
               (scanner_name == 'MLDetector' and not config_manager.is_ml_scan_enabled()) or \
               (scanner_name == 'SignDetector' and not config_manager.is_signature_scan_enabled()) or \
               (scanner_name == 'StringDetector' and not config_manager.is_string_scan_enabled()):
                emit_log(f"--- Skipping Layer: {scanner_name} (disabled in settings) ---", "info")
                continue
            if stop_check_callback and stop_check_callback():
                emit_log("[StaticEngine] Layered scan aborted by user.", "warning")
                break
            emit_log(f"--- Starting Layer: {scanner.__class__.__name__} ---", "info")
            try:
                scanner.load_resources()
                last_progress_emit = 0.0
                for i, file_path in enumerate(files_to_scan):
                    if stop_check_callback and stop_check_callback():
                        break
                    now = time.time()
                    if (now - last_progress_emit) >= 0.20 or i == total_files - 1 or i % 20 == 0:
                        last_progress_emit = now
                        progress_percent = int(((i + 1) / total_files) * 100)
                        bus.scan_progress_updated.emit({
                            "layer": scanner_name,
                            "progress": progress_percent,
                            "message": f"Scanning ({i+1}/{total_files}): {os.path.basename(file_path)}"
                        })
                    if file_path in flagged_files:
                        continue
                    findings = scanner.scan(file_path)
                    if findings:
                        for finding in findings:
                            finding['file'] = file_path
                            emit_threat(finding) 
                            all_threats.append(finding)
                            flagged_files.add(file_path)
                        continue
            except Exception as e:
                emit_log(f"[{scanner.__class__.__name__}] A critical error occurred during its layer: {e}", "error")
            finally:
                scanner.unload_resources()
        emit_log(f"[StaticEngine] Layered scan complete. Total threats found: {len(all_threats)}", "info")
        return all_threats
    def _collect_files(self, directory_path: str, stop_check_callback: Optional[Callable[[], bool]] = None) -> List[str]:
        """Helper function to recursively collect files to be scanned."""
        files_to_scan = []
        if not os.path.isdir(directory_path):
            emit_log(f"[StaticEngine] Directory not found: {directory_path}", "error")
            return []
        allowed_extensions = config_manager.get_allowed_extensions()
        emit_log(f"[StaticEngine] Collecting files from: {directory_path}", "info")
        if allowed_extensions:
            emit_log(f"[StaticEngine] Filtering for extensions: {', '.join(allowed_extensions)}", "info")
        for root, _, files in os.walk(directory_path):
            if stop_check_callback and stop_check_callback(): break
            for file in files:
                if stop_check_callback and stop_check_callback(): break
                if allowed_extensions and not any(file.lower().endswith(ext) for ext in allowed_extensions):
                    continue
                files_to_scan.append(str(Path(root) / file))
        return files_to_scan