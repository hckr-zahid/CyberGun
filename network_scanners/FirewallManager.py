import subprocess
from typing import Set
from core.SignalBus import emit_log
from utils.system_checks import is_admin
class FirewallManager:
    """
    Manages blocking and unblocking IP addresses using the Windows Defender Firewall.
    """
    def __init__(self):
        self._blocked_ips: Set[str] = set()
        self.has_privileges = is_admin()
        if self.has_privileges:
            emit_log("[FirewallManager] Initialized with Administrator privileges.", "info")
        else:
            emit_log("[FirewallManager] WARNING: Initialized WITHOUT Administrator privileges. Firewall blocking is disabled.", "warning")
    def block_ip(self, ip_address: str) -> None:
        """
        Adds a new outbound firewall rule to block a specific IP address.
        """
        if not self.has_privileges:
            emit_log(f"[FirewallManager] Cannot block IP {ip_address}: Lack of administrator privileges.", "warning")
            return
        if ip_address in self._blocked_ips:
            return
        rule_name = f"CyberGun-Block-{ip_address}"
        emit_log(f"[FirewallManager] ATTEMPTING TO BLOCK IP: {ip_address} with rule: '{rule_name}'", "warning")
        try:
            command = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f'name="{rule_name}"',
                "dir=out",
                "action=block",
                f"remoteip={ip_address}"
            ]
            creation_flags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
            subprocess.run(
                command, 
                check=True, 
                capture_output=True, 
                text=True,
                creationflags=creation_flags
            )
            self._blocked_ips.add(ip_address)
            emit_log(f"[FirewallManager] ✅ Successfully BLOCKED outbound traffic to {ip_address}.", "critical")
        except FileNotFoundError:
            emit_log("[FirewallManager] ❌ CRITICAL: 'netsh' command not found. Cannot manage firewall.", "error")
        except subprocess.CalledProcessError as e:
            error_message = e.stderr.strip() if e.stderr else e.stdout.strip()
            emit_log(f"[FirewallManager] ❌ FAILED to block {ip_address}. Reason: {error_message}", "error")
        except Exception as e:
            emit_log(f"[FirewallManager] ❌ An unexpected error occurred while blocking {ip_address}: {e}", "error")
    def unblock_ip(self, ip_address: str):
        if not self.has_privileges:
            return
        if ip_address not in self._blocked_ips:
            return
        rule_name = f"CyberGun-Block-{ip_address}"
        try:
            creation_flags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
            command = ["netsh", "advfirewall", "firewall", "delete", "rule", f'name="{rule_name}"']
            subprocess.run(command, check=True, capture_output=True, text=True, creationflags=creation_flags)
            self._blocked_ips.remove(ip_address)
            emit_log(f"[FirewallManager] Unblocked {ip_address}.", "info")
        except Exception as e:
            emit_log(f"[FirewallManager] Failed to unblock {ip_address}: {e}", "error")