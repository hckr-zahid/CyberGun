import os
from typing import Set
from core.SignalBus import emit_log
from core.settings import NETWORK_BLACKLIST_PATH
class LiveNetworkThreatFetcher:
    """
    Loads and manages the IP blacklist from all files within a specified directory.
    This class serves as the single source of truth for threat intelligence.
    """
    def __init__(self):
        self.blacklist_ips: Set[str] = self._load_blacklist_from_directory()
    def _load_blacklist_from_directory(self) -> Set[str]:
        """Loads unique, non-commented IP addresses from all files in the blacklist directory."""
        ips = set()
        if not os.path.isdir(NETWORK_BLACKLIST_PATH):
            emit_log(f"[LiveNetworkThreatFetcher] ⚠️ Blacklist path is not a directory: {NETWORK_BLACKLIST_PATH}", "warning")
            if os.path.isfile(NETWORK_BLACKLIST_PATH):
                 emit_log(f"[LiveNetworkThreatFetcher] Attempting to load as a single file for backward compatibility...", "info")
                 try:
                    with open(NETWORK_BLACKLIST_PATH, 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            ip = line.strip()
                            if ip and not ip.startswith('#'):
                                ips.add(ip)
                 except Exception as e:
                    emit_log(f"[LiveNetworkThreatFetcher] ❌ Failed to load single blacklist file: {e}", "error")
            return ips
        try:
            for filename in os.listdir(NETWORK_BLACKLIST_PATH):
                filepath = os.path.join(NETWORK_BLACKLIST_PATH, filename)
                if os.path.isfile(filepath):
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            ip = line.strip()
                            if ip and not ip.startswith('#'):
                                ips.add(ip)
            emit_log(f"[LiveNetworkThreatFetcher] ✅ Loaded {len(ips)} unique IPs into the blacklist.", "info")
        except Exception as e:
            emit_log(f"[LiveNetworkThreatFetcher] ❌ Failed to load IP blacklist from directory: {e}", "error")
        return ips
    def is_ip_malicious(self, ip_address: str) -> bool:
        """Checks if the given IP address is in the loaded blacklist or SQLite database."""
        if not ip_address:
            return False
        if ip_address in self.blacklist_ips:
            return True
        try:
            from core.database_manager import get_db_manager
            res = get_db_manager().check_ip(ip_address)
            if res:
                return True
        except Exception:
            pass
        return False
    def get_ip_threat_info(self, ip_address: str):
        """Returns threat metadata dictionary for an IP address if found in SQLite or blacklist."""
        if not ip_address:
            return None
        try:
            from core.database_manager import get_db_manager
            db_res = get_db_manager().check_ip(ip_address)
            if db_res:
                return db_res
        except Exception:
            pass
        if ip_address in self.blacklist_ips:
            return {
                "ip_address": ip_address,
                "threat_type": "Blacklisted Network IP",
                "severity": "high",
                "source": "Local Blacklist"
            }
        return None