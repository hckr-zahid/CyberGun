import os
import shutil
import json
from pathlib import Path
import psutil
from datetime import datetime
from core.settings import QUARANTINE_DIR
from core.SignalBus import emit_log
VAULT_MAGIC_HEADER = b"CYBERGUN_VAULT_V1\x00\xff"
VAULT_KEY = b"CyberGunThreatMitigationSecureVaultKey2026!"
def _obfuscate_stream(input_path: Path, output_path: Path):
    """Encrypts/obfuscates a malicious file to neutralize its payload."""
    key_len = len(VAULT_KEY)
    with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
        f_out.write(VAULT_MAGIC_HEADER)
        i = 0
        while True:
            chunk = f_in.read(65536)
            if not chunk:
                break
            obf_chunk = bytearray(chunk)
            for j in range(len(obf_chunk)):
                obf_chunk[j] ^= VAULT_KEY[(i + j) % key_len]
            i += len(chunk)
            f_out.write(obf_chunk)
def _deobfuscate_stream(input_path: Path, output_path: Path):
    """Restores an obfuscated quarantined file back to its original bytes."""
    key_len = len(VAULT_KEY)
    with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
        header = f_in.read(len(VAULT_MAGIC_HEADER))
        if header != VAULT_MAGIC_HEADER:
            f_in.seek(0)
            shutil.copyfileobj(f_in, f_out)
            return
        i = 0
        while True:
            chunk = f_in.read(65536)
            if not chunk:
                break
            deobf_chunk = bytearray(chunk)
            for j in range(len(deobf_chunk)):
                deobf_chunk[j] ^= VAULT_KEY[(i + j) % key_len]
            i += len(chunk)
            f_out.write(deobf_chunk)
class QuarantineManager:
    """
    Handles the safe neutralization of threats, including process termination
    and encrypted file isolation, with restore and delete capabilities.
    """
    def __init__(self):
        self.quarantine_path = Path(QUARANTINE_DIR)
        self.manifest_path = self.quarantine_path / "quarantine_manifest.json"
        self._ensure_quarantine_dir_exists()
        self.manifest = self._load_manifest()
    def _ensure_quarantine_dir_exists(self):
        """Creates the quarantine directory if it doesn't exist."""
        try:
            self.quarantine_path.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            emit_log(f"[QuarantineManager] CRITICAL: Could not create quarantine directory at {self.quarantine_path}: {e}", "error")
            raise
    def _load_manifest(self) -> dict:
        """Loads the quarantine manifest file."""
        if not self.manifest_path.exists():
            return {}
        try:
            with open(self.manifest_path, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            emit_log(f"[QuarantineManager] Could not read or decode manifest file. A new one will be created.", "warning")
            return {}
    def _save_manifest(self):
        """Saves the current state of the manifest to the JSON file."""
        try:
            with open(self.manifest_path, 'w') as f:
                json.dump(self.manifest, f, indent=4)
        except IOError:
            emit_log(f"[QuarantineManager] CRITICAL: Could not save manifest file.", "error")
    def terminate_process_by_path(self, file_path: str) -> bool:
        """Finds and terminates a running process by its executable file path."""
        target_path = os.path.normcase(os.path.abspath(file_path))
        process_terminated = False
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                if proc.info['exe'] and os.path.normcase(os.path.abspath(proc.info['exe'])) == target_path:
                    emit_log(f"[QuarantineManager] Found running malicious process {proc.info['name']} (PID: {proc.info['pid']}). Terminating...", "warning")
                    p = psutil.Process(proc.info['pid'])
                    p.kill()
                    emit_log(f"[QuarantineManager] Process PID {proc.info['pid']} terminated successfully.", "info")
                    process_terminated = True
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception as e:
                emit_log(f"[QuarantineManager] Error while trying to terminate process for {file_path}: {e}", "error")
        return process_terminated
    def quarantine_file(self, file_path: str) -> bool:
        """Encrypts and isolates a file in the quarantine directory and records it in the manifest."""
        source = Path(file_path)
        if not source.exists() or not source.is_file():
            emit_log(f"[QuarantineManager] File to quarantine does not exist: {file_path}", "warning")
            return False
        try:
            import hashlib
            hasher = hashlib.sha256()
            with open(source, "rb") as f:
                while chunk := f.read(65536):
                    hasher.update(chunk)
            sha256_hash = hasher.hexdigest()
            unique_id = os.urandom(8).hex()
            destination_filename = f"{source.name}.{unique_id}.quarantined"
            destination = self.quarantine_path / destination_filename
            _obfuscate_stream(source, destination)
            try:
                os.remove(source)
            except Exception as e:
                emit_log(f"[QuarantineManager] Warning: Could not remove source file after vaulting: {e}", "warning")
            self.manifest[destination_filename] = {
                "original_path": str(source.resolve()),
                "quarantine_date": datetime.utcnow().isoformat(),
                "sha256": sha256_hash,
                "encrypted": True
            }
            self._save_manifest()
            try:
                from core.database_manager import get_db_manager
                get_db_manager().record_incident(
                    target_path=str(source.resolve()),
                    threat_type="Malware Infection",
                    threat_name=source.name,
                    severity="critical",
                    action_taken="Vault Encrypted",
                    details=f"SHA256: {sha256_hash}"
                )
            except Exception as dbe:
                emit_log(f"[QuarantineManager] Failed to record incident in DB: {dbe}", "warning")
            emit_log(f"[QuarantineManager] Quarantined & Vault-Encrypted: {source.name} (SHA256: {sha256_hash[:12]}...)", "info")
            return True
        except Exception as e:
            emit_log(f"[QuarantineManager] An unexpected error occurred during quarantine of {file_path}: {e}", "error")
        return False
    def list_quarantined_files(self) -> list:
        """Returns a list of dictionaries of quarantined files for UI display."""
        file_list = []
        self.manifest = self._load_manifest()
        for filename, data in self.manifest.items():
            file_path = self.quarantine_path / filename
            file_list.append({
                "filename": filename,
                "original_path": data.get("original_path", "Unknown"),
                "quarantine_date": data.get("quarantine_date", "Unknown"),
                "sha256": data.get("sha256", "N/A"),
                "size_bytes": file_path.stat().st_size if file_path.exists() else 0
            })
        return file_list
    def restore_quarantined_file(self, filename: str) -> bool:
        """Restores and decrypts a quarantined file to its original location."""
        if filename not in self.manifest:
            emit_log(f"[QuarantineManager] Cannot restore '{filename}': Not found in manifest.", "error")
            return False
        quarantined_file_path = self.quarantine_path / filename
        original_path_str = self.manifest[filename]["original_path"]
        original_path = Path(original_path_str)
        try:
            original_path.parent.mkdir(parents=True, exist_ok=True)
            _deobfuscate_stream(quarantined_file_path, original_path)
            try:
                os.remove(quarantined_file_path)
            except Exception:
                pass
            del self.manifest[filename]
            self._save_manifest()
            try:
                from core.database_manager import get_db_manager
                get_db_manager().record_incident(
                    target_path=original_path_str,
                    threat_type="Quarantine Restore",
                    threat_name=filename,
                    severity="low",
                    action_taken="Restored",
                    details="Restored to original location by user"
                )
            except Exception:
                pass
            emit_log(f"[QuarantineManager] Successfully restored and decrypted '{filename}' to '{original_path_str}'.", "info")
            return True
        except Exception as e:
            emit_log(f"[QuarantineManager] FAILED to restore '{filename}': {e}", "error")
            return False
    def delete_quarantined_file(self, filename: str) -> bool:
        """Permanently deletes a file from quarantine."""
        if filename not in self.manifest:
            emit_log(f"[QuarantineManager] Cannot delete '{filename}': Not found in manifest.", "error")
            return False
        quarantined_file_path = self.quarantine_path / filename
        try:
            if quarantined_file_path.exists():
                os.remove(quarantined_file_path)
            del self.manifest[filename]
            self._save_manifest()
            try:
                from core.database_manager import get_db_manager
                get_db_manager().record_incident(
                    target_path=filename,
                    threat_type="Quarantine Purge",
                    threat_name=filename,
                    severity="info",
                    action_taken="Permanently Deleted",
                    details="Purged from quarantine vault"
                )
            except Exception:
                pass
            emit_log(f"[QuarantineManager] Permanently deleted quarantined file '{filename}'.", "warning")
            return True
        except Exception as e:
            emit_log(f"[QuarantineManager] FAILED to delete '{filename}': {e}", "error")
            return False