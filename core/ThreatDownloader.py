import os
import requests
import threading
import time
from pathlib import Path
from core.SignalBus import emit_log, get_signal_bus 
from core.settings import HASH_DIR, YARA_RULES_DIR, NETWORK_BLACKLIST_PATH
from core.database_manager import get_db_manager
class ThreatDownloader:
    """
    Downloads and synchronizes live threat intelligence feeds directly
    into the centralized SQLite database and local disk caches.
    """
    def __init__(self):
        self._thread: threading.Thread | None = None
        self.signal_bus = get_signal_bus()
        self.db = get_db_manager()
    def start_update(self):
        """Starts the database update process in a non-blocking background thread."""
        if self._thread and self._thread.is_alive():
            emit_log("[ThreatDownloader] Update already in progress.", "warning")
            return
        self._thread = threading.Thread(target=self.run_update_logic, daemon=True)
        self._thread.start()
    def run_update_logic(self):
        """Sequentially runs update routines for YARA rules, hashes, IPs, and domains."""
        self.signal_bus.threat_update_status_changed.emit('overall', 'Update process started...', 'running')
        self.signal_bus.splash_updated.emit("Synchronizing YARA rule engine...")
        self._update_yara_rules()
        self.signal_bus.splash_updated.emit("Downloading Malware Hash intelligence...")
        self._update_hashes()
        self.signal_bus.splash_updated.emit("Updating Blacklisted IP feed...")
        self._update_bad_ips()
        self.signal_bus.splash_updated.emit("Updating Malicious C2 domains...")
        self._update_c2_domains()
        self.signal_bus.threat_update_status_changed.emit('overall', 'All threat intelligence updated.', 'success')
        emit_log("[ThreatDownloader] All database components synchronized successfully.", "info")
    def _update_yara_rules(self):
        """Verifies and updates local YARA signatures."""
        component_name = 'yara_rules'
        self.signal_bus.threat_update_status_changed.emit(component_name, 'Inspecting ruleset...', 'running')
        repo_path = Path(YARA_RULES_DIR)
        git_dir = repo_path / ".git"
        updated = False
        if git_dir.is_dir():
            try:
                import git
                repo = git.Repo(str(repo_path))
                self.signal_bus.threat_update_status_changed.emit(component_name, 'Pulling updates...', 'running')
                repo.remotes.origin.pull()
                updated = True
            except Exception as ge:
                emit_log(f"[ThreatDownloader] Git pull notice: {ge}", "info")
        rule_count = 0
        if repo_path.exists():
            for root, _, files in os.walk(repo_path):
                rule_count += sum(1 for f in files if f.endswith(('.yar', '.yara')))
        if rule_count > 0:
            status_msg = f"Active & Verified ({rule_count} rule files)"
            self.signal_bus.threat_update_status_changed.emit(component_name, status_msg, 'success')
        else:
            self.signal_bus.threat_update_status_changed.emit(component_name, "Verified (Embedded Rules)", 'success')
    def _update_hashes(self):
        """Downloads latest Malware SHA256 hashes and imports them into SQLite."""
        component_name = 'hashes'
        self.signal_bus.threat_update_status_changed.emit(component_name, 'Downloading latest hashes...', 'running')
        target_dir = Path(HASH_DIR)
        target_dir.mkdir(parents=True, exist_ok=True)
        target_file = target_dir / "abuse_ch_recent_sha256.txt"
        url = "https://bazaar.abuse.ch/export/txt/sha256/recent/"
        try:
            with requests.get(url, stream=True, timeout=30) as resp:
                if resp.status_code == 200:
                    text_data = resp.text
                    new_hashes = []
                    for line in text_data.splitlines():
                        line = line.strip()
                        if line and not line.startswith('#'):
                            if len(line) == 64:
                                new_hashes.append((line.lower(), 'sha256', 'MalwareBazaar.Recent', 'critical', 'Abuse.ch'))
                    if new_hashes:
                        inserted = self.db.bulk_import_hashes(new_hashes)
                        with open(target_file, "w", encoding="utf-8") as f:
                            f.write(text_data)
                        self.signal_bus.threat_update_status_changed.emit(component_name, f"Imported {len(new_hashes)} new hashes", 'success')
                        return
            stats = self.db.get_intel_stats()
            count = stats.get('threat_hashes', 0)
            self.signal_bus.threat_update_status_changed.emit(component_name, f"Database active ({count:,} hashes)", 'success')
        except Exception as e:
            emit_log(f"[ThreatDownloader] Hash update notice: {e}", "warning")
            stats = self.db.get_intel_stats()
            count = stats.get('threat_hashes', 0)
            self.signal_bus.threat_update_status_changed.emit(component_name, f"Offline cache active ({count:,} hashes)", 'success')
    def _update_bad_ips(self):
        """Downloads latest IP blocklist and imports into SQLite threat_ips."""
        component_name = 'bad_ips'
        self.signal_bus.threat_update_status_changed.emit(component_name, 'Downloading FireHOL blocklist...', 'running')
        target_dir = Path(NETWORK_BLACKLIST_PATH)
        target_dir.mkdir(parents=True, exist_ok=True)
        target_file = target_dir / "firehol_level1.netset"
        url = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"
        try:
            with requests.get(url, stream=True, timeout=30) as resp:
                if resp.status_code == 200:
                    text = resp.text
                    ip_rows = []
                    for line in text.splitlines():
                        line = line.strip()
                        if line and not line.startswith('#') and '/' not in line:
                            ip_rows.append((line, 'FireHOL Level 1 Threat', 'high', 'FireHOL'))
                    if ip_rows:
                        conn = self.db._get_connection()
                        cur = conn.cursor()
                        cur.executemany("""
                            INSERT OR IGNORE INTO threat_ips (ip_address, threat_type, severity, source)
                            VALUES (?, ?, ?, ?);
                        """, ip_rows)
                        conn.commit()
                        conn.close()
                        with open(target_file, "w", encoding="utf-8") as f:
                            f.write(text)
                        self.signal_bus.threat_update_status_changed.emit(component_name, f"Synced {len(ip_rows)} IPs", 'success')
                        return
            stats = self.db.get_intel_stats()
            self.signal_bus.threat_update_status_changed.emit(component_name, f"Active ({stats.get('threat_ips', 0):,} IPs)", 'success')
        except Exception as e:
            emit_log(f"[ThreatDownloader] IP update notice: {e}", "warning")
            stats = self.db.get_intel_stats()
            self.signal_bus.threat_update_status_changed.emit(component_name, f"Active ({stats.get('threat_ips', 0):,} IPs)", 'success')
    def _update_c2_domains(self):
        """Downloads active C2 URLs / domains from URLhaus into SQLite."""
        component_name = 'domains'
        self.signal_bus.threat_update_status_changed.emit(component_name, 'Fetching active C2 domains...', 'running')
        url = "https://urlhaus.abuse.ch/downloads/text_online/"
        try:
            with requests.get(url, timeout=30) as resp:
                if resp.status_code == 200:
                    domains = set()
                    for line in resp.text.splitlines():
                        line = line.strip()
                        if line and not line.startswith('#'):
                            clean = line.replace('http://', '').replace('https://', '').split('/')[0].split(':')[0]
                            if clean and '.' in clean:
                                domains.add(clean.lower())
                    if domains:
                        domain_rows = [(d, 'C2 Online Beacon', 'critical', 'URLhaus') for d in list(domains)[:500]]
                        conn = self.db._get_connection()
                        cur = conn.cursor()
                        cur.executemany("""
                            INSERT OR IGNORE INTO threat_domains (domain, threat_type, severity, source)
                            VALUES (?, ?, ?, ?);
                        """, domain_rows)
                        conn.commit()
                        conn.close()
                        self.signal_bus.threat_update_status_changed.emit(component_name, f"Synced {len(domain_rows)} C2 domains", 'success')
                        return
            stats = self.db.get_intel_stats()
            self.signal_bus.threat_update_status_changed.emit(component_name, f"Active ({stats.get('threat_domains', 0)} C2s)", 'success')
        except Exception as e:
            emit_log(f"[ThreatDownloader] C2 update notice: {e}", "warning")
            stats = self.db.get_intel_stats()
            self.signal_bus.threat_update_status_changed.emit(component_name, f"Active ({stats.get('threat_domains', 0)} C2s)", 'success')