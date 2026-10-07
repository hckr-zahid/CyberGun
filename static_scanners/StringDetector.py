import re
import csv
import os
import gc
from typing import List, Dict
from core.settings import ENABLE_STRING_SCAN, STRING_SIGNATURES_PATH
from core.SignalBus import emit_log, get_signal_bus
class StringDetector:
    """
    A powerful and memory-safe scanner that searches for suspicious strings and regex patterns.
    """
    def __init__(self):
        self.rules: List[Dict] = []
        self.resources_loaded = False
        self.rule_file_path = os.path.join("datasets", "strings", "string_rules.csv")
        self.signal_bus = get_signal_bus()
    def load_resources(self) -> None:
        if not ENABLE_STRING_SCAN or self.resources_loaded:
            return
        try:
            from core.database_manager import get_db_manager
            db_rules = get_db_manager().get_all_string_rules()
            if db_rules:
                for row in db_rules:
                    rule_type = str(row.get('rule_type', 'string')).lower()
                    pattern = row.get('pattern', '')
                    if not pattern:
                        continue
                    rule = {
                        'type': rule_type,
                        'pattern': pattern,
                        'description': row.get('description', ''),
                        'severity': row.get('severity', 'medium')
                    }
                    if rule_type == 'regex':
                        try:
                            rule['compiled'] = re.compile(pattern.encode('utf-8', 'ignore'))
                        except re.error as e:
                            emit_log(f"[{self.__class__.__name__}] Invalid regex pattern skipped: '{pattern}' ({e})", "warning")
                            continue
                    self.rules.append(rule)
                self.resources_loaded = True
                emit_log(f"[{self.__class__.__name__}] Loaded {len(self.rules)} string/regex rules from SQLite database.", "info")
                return
        except Exception as db_err:
            emit_log(f"[{self.__class__.__name__}] SQLite string load fallback: {db_err}", "warning")
        emit_log(f"[{self.__class__.__name__}] Loading string and regex rules from CSV: {self.rule_file_path}", "info")
        if not os.path.exists(self.rule_file_path):
            emit_log(f"[{self.__class__.__name__}] Rule file not found: {self.rule_file_path}", "warning")
            return
        try:
            with open(self.rule_file_path, newline='', encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if not all(key in row for key in ['type', 'pattern', 'description']):
                        continue
                    rule = {
                        'type': row['type'].lower(),
                        'pattern': row['pattern'],
                        'description': row['description'],
                        'severity': row.get('severity', 'medium')
                    }
                    if rule['type'] == 'regex':
                        try:
                            rule['compiled'] = re.compile(row['pattern'].encode('utf-8', 'ignore'))
                        except re.error as e:
                            emit_log(f"[{self.__class__.__name__}] Invalid regex pattern skipped: '{row['pattern']}' ({e})", "warning")
                            continue
                    self.rules.append(rule)
            self.resources_loaded = True
            emit_log(f"[{self.__class__.__name__}] Loaded {len(self.rules)} string/regex rules from CSV.", "info")
        except Exception as e:
            emit_log(f"[{self.__class__.__name__}] Failed loading string rules from CSV: {e}", "error")
    def unload_resources(self) -> None:
        """Clears all loaded rules from memory."""
        if not self.resources_loaded:
            return
        emit_log(f"[{self.__class__.__name__}] Unloading string/regex rules.", "info")
        self.rules.clear()
        self.resources_loaded = False
        gc.collect()
    def scan(self, file_path: str) -> List[Dict]:
        """
        Scans a file for suspicious strings and regex patterns in a memory-safe way.
        """
        self.signal_bus.scan_progress_updated.emit({
            "layer": self.__class__.__name__,
            "message": f"Analyzing strings in {os.path.basename(file_path)}"
        })
        if not ENABLE_STRING_SCAN or not self.rules:
            return []
        findings = []
        try:
            with open(file_path, "rb") as f:
                content_chunk = f.read(4 * 1024 * 1024)
                if not content_chunk:
                    return []
                for rule in self.rules:
                    found = False
                    match_text = ""
                    if rule['type'] == 'string':
                        if rule['pattern'].encode('utf-8', 'ignore').lower() in content_chunk.lower():
                            found = True
                            match_text = rule['pattern']
                    elif rule['type'] == 'regex':
                        match = rule['compiled'].search(content_chunk)
                        if match:
                            found = True
                            match_text = match.group(0).decode('utf-8', 'ignore')
                    if found:
                        findings.append({
                            "source": self.__class__.__name__,
                            "type": "suspicious_pattern",
                            "description": f"{rule['description']} (Match: '{match_text}')",
                            "severity": rule['severity'],
                            "malware_name": f"Suspicious.{rule['severity'].capitalize()}",
                        })
                        if rule['severity'] in ['high', 'critical']:
                            return findings
        except (IOError, PermissionError) as e:
            emit_log(f"[{self.__class__.__name__}] Could not scan {file_path}: {e}", "error")
        return findings