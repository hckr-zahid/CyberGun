import os
import sys
import sqlite3
import csv
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set
from datetime import datetime
from core.settings import BASE_DIR, HASH_DIR, SIGNATURE_DIR, STRING_SIGNATURES_PATH, NETWORK_BLACKLIST_PATH
from core.SignalBus import emit_log
def _resolve_db_path() -> Path:
    primary = Path(BASE_DIR) / "datasets" / "cybergun_intel.db"
    if primary.exists():
        return primary
    if getattr(sys, 'frozen', False):
        exe_dir = Path(sys.executable).resolve().parent
        for cand in [exe_dir / "_internal" / "datasets" / "cybergun_intel.db", exe_dir / "datasets" / "cybergun_intel.db"]:
            if cand.exists():
                return cand
    return primary
DB_PATH = _resolve_db_path()
class DatabaseManager:
    """
    Centralized SQLite Intelligence Database for CyberGun.
    Stores and fast-queries:
    - Malware Hashes (SHA256, MD5, SHA1)
    - Blacklisted IP Addresses
    - Phishing Emails & Malicious Sender Domains
    - Malicious C2 & Phishing Domains
    - Byte Signatures
    - Suspicious Command & API Strings
    - Incident & Quarantine Scan History
    """
    _instance = None
    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(DatabaseManager, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    def __init__(self, db_path: Optional[Path] = None):
        if self._initialized:
            return
        self.db_path = db_path if db_path else _resolve_db_path()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_database()
        self._seed_initial_data_if_empty()
        self._initialized = True
    def _get_connection(self) -> sqlite3.Connection:
        """Returns a thread-safe connection configured for high performance."""
        conn = sqlite3.connect(str(self.db_path), timeout=30.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("PRAGMA journal_mode = WAL;")
        cur.execute("PRAGMA synchronous = NORMAL;")
        cur.execute("PRAGMA cache_size = -64000;")
        return conn
    def _init_database(self):
        """Creates the unified tables and indexes if they do not exist."""
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS threat_hashes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hash TEXT UNIQUE NOT NULL,
                hash_type TEXT DEFAULT 'sha256',
                malware_name TEXT DEFAULT 'KnownMalware.ThreatHash',
                severity TEXT DEFAULT 'critical',
                source TEXT DEFAULT 'Abuse.ch/MalwareBazaar',
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_threat_hashes_hash ON threat_hashes(hash);")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS threat_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                threat_type TEXT DEFAULT 'Blacklisted IP',
                severity TEXT DEFAULT 'critical',
                source TEXT DEFAULT 'FireHOL/Ipsum',
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_threat_ips_ip ON threat_ips(ip_address);")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS threat_emails (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email_or_domain TEXT UNIQUE NOT NULL,
                threat_type TEXT DEFAULT 'Phishing / Malicious Sender',
                severity TEXT DEFAULT 'high',
                source TEXT DEFAULT 'PhishTank/Spamhaus',
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_threat_emails_addr ON threat_emails(email_or_domain);")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS threat_domains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT UNIQUE NOT NULL,
                threat_type TEXT DEFAULT 'Malicious C2 Domain',
                severity TEXT DEFAULT 'critical',
                source TEXT DEFAULT 'URLhaus/Abuse.ch',
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_threat_domains_domain ON threat_domains(domain);")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS threat_signatures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hex_signature TEXT UNIQUE NOT NULL,
                malware_name TEXT NOT NULL,
                severity TEXT DEFAULT 'medium',
                description TEXT DEFAULT '',
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_threat_signatures_hex ON threat_signatures(hex_signature);")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS threat_strings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_type TEXT DEFAULT 'string',
                pattern TEXT UNIQUE NOT NULL,
                description TEXT NOT NULL,
                severity TEXT DEFAULT 'medium',
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_threat_strings_pattern ON threat_strings(pattern);")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                target_path TEXT,
                threat_type TEXT,
                threat_name TEXT,
                severity TEXT,
                action_taken TEXT,
                details TEXT
            );
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_scan_history_timestamp ON scan_history(timestamp);")
        conn.commit()
        conn.close()
    def _seed_initial_data_if_empty(self):
        """Populates initial signatures, strings, emails, domains, and core indicators if empty."""
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM threat_signatures;")
        if cur.fetchone()[0] == 0:
            sig_csv = Path(SIGNATURE_DIR) / "signatures.csv"
            if sig_csv.exists():
                try:
                    with open(sig_csv, "r", encoding="utf-8", errors="ignore") as f:
                        reader = csv.DictReader(f)
                        rows = []
                        for r in reader:
                            sig = r.get("signature", "").strip().lower()
                            if sig:
                                rows.append((sig, r.get("malware_name", "Malware"), r.get("severity", "medium"), ""))
                        cur.executemany("""
                            INSERT OR IGNORE INTO threat_signatures (hex_signature, malware_name, severity, description)
                            VALUES (?, ?, ?, ?);
                        """, rows)
                    emit_log(f"[DatabaseManager] Seeded {len(rows)} byte signatures into SQLite.", "info")
                except Exception as e:
                    emit_log(f"[DatabaseManager] Failed to seed signatures: {e}", "warning")
        cur.execute("SELECT COUNT(*) FROM threat_strings;")
        if cur.fetchone()[0] == 0:
            str_csv = Path(STRING_SIGNATURES_PATH) / "string_rules.csv"
            if str_csv.exists():
                try:
                    with open(str_csv, "r", encoding="utf-8", errors="ignore") as f:
                        reader = csv.DictReader(f)
                        rows = []
                        for r in reader:
                            pat = r.get("pattern", "").strip()
                            if pat:
                                rows.append((r.get("type", "string").lower(), pat, r.get("description", ""), r.get("severity", "medium")))
                        cur.executemany("""
                            INSERT OR IGNORE INTO threat_strings (rule_type, pattern, description, severity)
                            VALUES (?, ?, ?, ?);
                        """, rows)
                    emit_log(f"[DatabaseManager] Seeded {len(rows)} string rules into SQLite.", "info")
                except Exception as e:
                    emit_log(f"[DatabaseManager] Failed to seed strings: {e}", "warning")
        cur.execute("SELECT COUNT(*) FROM threat_emails;")
        if cur.fetchone()[0] == 0:
            seed_emails = [
                ("phishing@account-verification-alert.com", "Credential Harvesting", "critical", "Spamhaus"),
                ("billing@irs-tax-refund.org", "Tax Impersonation Phishing", "critical", "PhishTank"),
                ("security@apple-id-verify.co", "Brand Impersonation Phishing", "critical", "Spamhaus"),
                ("support@microsoft-security-alert.net", "Tech Support Scam", "high", "Custom"),
                ("admin@crypto-airdrop-claim.com", "Crypto Drainer Scam", "critical", "PhishTank"),
                ("service@paypal-dispute-resolution.cc", "Financial Phishing", "critical", "PhishTank"),
                ("payroll@internal-hr-notification.info", "BEC / Wire Fraud", "critical", "Custom"),
                ("update@windows-defender-patch.biz", "Malware Delivery Lure", "critical", "Custom"),
                ("invoice@quickbooks-overdue-notice.top", "Trojan Dropper Phishing", "high", "PhishTank"),
                ("helpdesk@secure-vpn-authenticator.xyz", "VPN Credential Stealer", "critical", "Custom"),
            ]
            cur.executemany("""
                INSERT OR IGNORE INTO threat_emails (email_or_domain, threat_type, severity, source)
                VALUES (?, ?, ?, ?);
            """, seed_emails)
            emit_log(f"[DatabaseManager] Seeded {len(seed_emails)} phishing email indicators into SQLite.", "info")
        cur.execute("SELECT COUNT(*) FROM threat_domains;")
        if cur.fetchone()[0] == 0:
            seed_domains = [
                ("c2-server-beacon.top", "CobaltStrike Beacon C2", "critical", "URLhaus"),
                ("malware-traffic-analysis.xyz", "Trojan Command & Control", "critical", "URLhaus"),
                ("ransomware-pay-portal.onion.pet", "Ransomware Payment Portal", "critical", "Abuse.ch"),
                ("dns-exfiltration-tunnel.biz", "DNS Tunneling Exfiltration", "high", "Custom"),
                ("stealer-logs-upload.space", "InfoStealer Drop Site", "critical", "URLhaus"),
                ("dynamic-dns-updater.duckdns.org", "Dynamic DNS Evasion", "medium", "Custom"),
                ("ddos-botnet-controller.cc", "Mirai / Botnet Controller", "critical", "Abuse.ch"),
            ]
            cur.executemany("""
                INSERT OR IGNORE INTO threat_domains (domain, threat_type, severity, source)
                VALUES (?, ?, ?, ?);
            """, seed_domains)
            emit_log(f"[DatabaseManager] Seeded {len(seed_domains)} malicious domains into SQLite.", "info")
        cur.execute("SELECT COUNT(*) FROM threat_ips;")
        if cur.fetchone()[0] == 0:
            ip_files = [Path(NETWORK_BLACKLIST_PATH) / "blacklist_ips.txt", Path(NETWORK_BLACKLIST_PATH) / "firehol_level1.netset"]
            ip_rows = []
            for ip_file in ip_files:
                if ip_file.exists():
                    try:
                        with open(ip_file, "r", encoding="utf-8", errors="ignore") as f:
                            for line in f:
                                line = line.strip()
                                if line and not line.startswith('#') and not line.startswith(';'):
                                    ip = line.split('/')[0].strip()
                                    if ip:
                                        ip_rows.append((ip, "Firewall Blacklist", "critical", ip_file.name))
                    except Exception:
                        pass
            if ip_rows:
                unique_ips = list({r[0]: r for r in ip_rows}.values())[:100000]
                cur.executemany("""
                    INSERT OR IGNORE INTO threat_ips (ip_address, threat_type, severity, source)
                    VALUES (?, ?, ?, ?);
                """, unique_ips)
                emit_log(f"[DatabaseManager] Seeded {len(unique_ips)} blacklisted IPs into SQLite.", "info")
        conn.commit()
        conn.close()
    def check_hash(self, hash_value: str) -> Optional[Dict]:
        """Checks if a SHA256, MD5, or SHA1 hash exists in the threat database."""
        if not hash_value:
            return None
        hash_clean = hash_value.strip().lower()
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("SELECT hash, hash_type, malware_name, severity, source FROM threat_hashes WHERE hash = ? LIMIT 1;", (hash_clean,))
        row = cur.fetchone()
        conn.close()
        if row:
            return dict(row)
        return None
    def check_ip(self, ip_address: str) -> Optional[Dict]:
        """Checks if an IP address exists in the blacklisted IP database."""
        if not ip_address:
            return None
        ip_clean = ip_address.strip()
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("SELECT ip_address, threat_type, severity, source FROM threat_ips WHERE ip_address = ? LIMIT 1;", (ip_clean,))
        row = cur.fetchone()
        conn.close()
        if row:
            return dict(row)
        return None
    def check_email(self, email_or_domain: str) -> Optional[Dict]:
        """Checks if an email or sender domain is a known phishing threat."""
        if not email_or_domain:
            return None
        clean_target = email_or_domain.strip().lower()
        domain_part = clean_target.split('@')[-1] if '@' in clean_target else clean_target
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT email_or_domain, threat_type, severity, source 
            FROM threat_emails 
            WHERE email_or_domain = ? OR email_or_domain = ? 
            LIMIT 1;
        """, (clean_target, domain_part))
        row = cur.fetchone()
        conn.close()
        if row:
            return dict(row)
        return None
    def check_domain(self, domain: str) -> Optional[Dict]:
        """Checks if a domain is a known malicious or C2 endpoint."""
        if not domain:
            return None
        domain_clean = domain.strip().lower()
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("SELECT domain, threat_type, severity, source FROM threat_domains WHERE domain = ? LIMIT 1;", (domain_clean,))
        row = cur.fetchone()
        conn.close()
        if row:
            return dict(row)
        return None
    def get_all_signatures(self) -> List[Dict]:
        """Retrieves all byte signatures from SQLite for static scanning."""
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("SELECT hex_signature, malware_name, severity, description FROM threat_signatures;")
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return rows
    def get_all_string_rules(self) -> List[Dict]:
        """Retrieves all string and regex rules from SQLite."""
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("SELECT rule_type, pattern, description, severity FROM threat_strings;")
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return rows
    def record_incident(self, target_path: str, threat_type: str, threat_name: str, 
                        severity: str = "critical", action_taken: str = "Quarantined", details: str = ""):
        """Records a detected incident in the scan history audit log."""
        try:
            conn = self._get_connection()
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO scan_history (target_path, threat_type, threat_name, severity, action_taken, details)
                VALUES (?, ?, ?, ?, ?, ?);
            """, (str(target_path), str(threat_type), str(threat_name), str(severity), str(action_taken), str(details)))
            conn.commit()
            conn.close()
        except Exception as e:
            emit_log(f"[DatabaseManager] Failed to record incident: {e}", "warning")
    def get_scan_history(self, limit: int = 100) -> List[Dict]:
        """Returns the recent scan and quarantine incidents."""
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT id, timestamp, target_path, threat_type, threat_name, severity, action_taken, details
            FROM scan_history
            ORDER BY id DESC
            LIMIT ?;
        """, (limit,))
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return rows
    def add_threat_hash(self, hash_val: str, hash_type: str = "sha256", malware_name: str = "KnownMalware", 
                        severity: str = "critical", source: str = "UserAdded") -> bool:
        """Adds a threat hash to the database."""
        try:
            conn = self._get_connection()
            cur = conn.cursor()
            cur.execute("""
                INSERT OR IGNORE INTO threat_hashes (hash, hash_type, malware_name, severity, source)
                VALUES (?, ?, ?, ?, ?);
            """, (hash_val.strip().lower(), hash_type.lower(), malware_name, severity, source))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            emit_log(f"[DatabaseManager] Failed to add hash: {e}", "error")
            return False
    def add_blacklisted_ip(self, ip_address: str, threat_type: str = "Blacklisted IP", 
                           severity: str = "critical", source: str = "UserAdded") -> bool:
        """Adds a blacklisted IP address to the database."""
        try:
            conn = self._get_connection()
            cur = conn.cursor()
            cur.execute("""
                INSERT OR IGNORE INTO threat_ips (ip_address, threat_type, severity, source)
                VALUES (?, ?, ?, ?);
            """, (ip_address.strip(), threat_type, severity, source))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            emit_log(f"[DatabaseManager] Failed to add IP: {e}", "error")
            return False
    def add_threat_email(self, email_or_domain: str, threat_type: str = "Phishing Sender", 
                         severity: str = "high", source: str = "UserAdded") -> bool:
        """Adds a phishing email address or sender domain to the database."""
        try:
            conn = self._get_connection()
            cur = conn.cursor()
            cur.execute("""
                INSERT OR IGNORE INTO threat_emails (email_or_domain, threat_type, severity, source)
                VALUES (?, ?, ?, ?);
            """, (email_or_domain.strip().lower(), threat_type, severity, source))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            emit_log(f"[DatabaseManager] Failed to add email indicator: {e}", "error")
            return False
    def add_threat_domain(self, domain: str, threat_type: str = "C2 Domain", 
                          severity: str = "critical", source: str = "UserAdded") -> bool:
        """Adds a malicious domain to the database."""
        try:
            conn = self._get_connection()
            cur = conn.cursor()
            cur.execute("""
                INSERT OR IGNORE INTO threat_domains (domain, threat_type, severity, source)
                VALUES (?, ?, ?, ?);
            """, (domain.strip().lower(), threat_type, severity, source))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            emit_log(f"[DatabaseManager] Failed to add domain: {e}", "error")
            return False
    def bulk_import_hashes(self, hash_list: List[Tuple[str, str, str, str, str]]) -> int:
        """Fast bulk insertion of hashes using transactions."""
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("PRAGMA synchronous = OFF;")
        cur.executemany("""
            INSERT OR IGNORE INTO threat_hashes (hash, hash_type, malware_name, severity, source)
            VALUES (?, ?, ?, ?, ?);
        """, hash_list)
        inserted = conn.total_changes
        conn.commit()
        conn.close()
        return inserted
    def get_intel_stats(self) -> Dict[str, int]:
        """Returns statistics for all threat intelligence tables."""
        conn = self._get_connection()
        cur = conn.cursor()
        stats = {}
        for table in ["threat_hashes", "threat_ips", "threat_emails", "threat_domains", "threat_signatures", "threat_strings", "scan_history"]:
            try:
                cur.execute(f"SELECT COUNT(*) FROM {table};")
                stats[table] = cur.fetchone()[0]
            except Exception:
                stats[table] = 0
        conn.close()
        return stats
def get_db_manager() -> DatabaseManager:
    """Returns the singleton instance of the DatabaseManager."""
    return DatabaseManager()
