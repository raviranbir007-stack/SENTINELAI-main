"""
Enhanced Quarantine Workflow Manager
Provides robust quarantine and restore operations with state tracking
"""

import json
import logging
import os
import shutil
import subprocess
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Callable
from enum import Enum

logger = logging.getLogger(__name__)


class QuarantineState(Enum):
    ACTIVE = "active"
    RESTORING = "restoring"
    RESTORED = "restored"
    FAILED = "failed"


class QuarantineAction(Enum):
    QUARANTINE_FILE = "quarantine_file"
    QUARANTINE_PROCESS = "quarantine_process"
    QUARANTINE_NETWORK = "quarantine_network"
    RESTORE_FILE = "restore_file"
    RESTORE_PROCESS = "restore_process"
    RESTORE_NETWORK = "restore_network"


class QuarantineWorkflowManager:
    """Enhanced quarantine workflow with robust state management and restore capabilities"""

    def __init__(self, quarantine_base_dir: Optional[Path] = None):
        self.quarantine_base_dir = quarantine_base_dir or Path.home() / ".sentinelai_quarantine"
        self.quarantine_base_dir.mkdir(parents=True, exist_ok=True)

        # Core directories
        self.files_dir = self.quarantine_base_dir / "files"
        self.metadata_dir = self.quarantine_base_dir / "metadata"
        self.backup_dir = self.quarantine_base_dir / "backups"

        for dir_path in [self.files_dir, self.metadata_dir, self.backup_dir]:
            dir_path.mkdir(parents=True, exist_ok=True)

        # State tracking
        self._active_quarantines: Dict[str, Dict] = {}
        self._restore_operations: Dict[str, Dict] = {}

        # Callbacks
        self._quarantine_callbacks: List[Callable] = []
        self._restore_callbacks: List[Callable] = []

        # Load existing state
        self._load_state()

    def _load_state(self):
        """Load existing quarantine state from disk"""
        state_file = self.quarantine_base_dir / "quarantine_state.json"
        if state_file.exists():
            try:
                with open(state_file, 'r', encoding='utf-8') as f:
                    state_data = json.load(f)
                    self._active_quarantines = state_data.get("active_quarantines", {})
                    self._restore_operations = state_data.get("restore_operations", {})
                logger.info(f"Loaded quarantine state with {len(self._active_quarantines)} active quarantines")
            except Exception as e:
                logger.error(f"Failed to load quarantine state: {e}")

    def _save_state(self):
        """Save current quarantine state to disk"""
        state_file = self.quarantine_base_dir / "quarantine_state.json"
        try:
            state_data = {
                "active_quarantines": self._active_quarantines,
                "restore_operations": self._restore_operations,
                "last_updated": datetime.now().isoformat()
            }
            with open(state_file, 'w', encoding='utf-8') as f:
                json.dump(state_data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"Failed to save quarantine state: {e}")

    def add_quarantine_callback(self, callback: Callable):
        """Add callback to be called when quarantine operations occur"""
        self._quarantine_callbacks.append(callback)

    def add_restore_callback(self, callback: Callable):
        """Add callback to be called when restore operations occur"""
        self._restore_callbacks.append(callback)

    def quarantine_file(self, file_path: Path, reason: str, threat_data: Optional[Dict] = None,
                       auto_quarantine: bool = False) -> Tuple[bool, str, Optional[str]]:
        """
        Quarantine a file with full state tracking

        Returns:
            Tuple of (success, message, quarantine_id)
        """
        try:
            if not file_path.exists():
                return False, f"File does not exist: {file_path}", None

            if not file_path.is_file():
                return False, f"Path is not a file: {file_path}", None

            # Generate quarantine ID
            quarantine_id = f"file_{int(time.time())}_{hash(str(file_path)) % 10000}"

            # Create quarantine paths
            quarantine_file_path = self.files_dir / f"{quarantine_id}_{file_path.name}"
            metadata_path = self.metadata_dir / f"{quarantine_id}.json"

            # Move file to quarantine
            shutil.move(str(file_path), str(quarantine_file_path))

            # Create metadata
            metadata = {
                "quarantine_id": quarantine_id,
                "original_path": str(file_path),
                "quarantine_path": str(quarantine_file_path),
                "filename": file_path.name,
                "reason": reason,
                "threat_data": threat_data or {},
                "auto_quarantine": auto_quarantine,
                "quarantined_at": datetime.now().isoformat(),
                "state": QuarantineState.ACTIVE.value,
                "file_size": quarantine_file_path.stat().st_size if quarantine_file_path.exists() else 0,
                "file_hash": self._calculate_file_hash(quarantine_file_path) if quarantine_file_path.exists() else None
            }

            # Save metadata
            with open(metadata_path, 'w', encoding='utf-8') as f:
                json.dump(metadata, f, indent=2, ensure_ascii=False)

            # Update state
            self._active_quarantines[quarantine_id] = metadata
            self._save_state()

            # Call callbacks
            for callback in self._quarantine_callbacks:
                try:
                    callback(quarantine_id, metadata)
                except Exception as e:
                    logger.error(f"Quarantine callback failed: {e}")

            logger.info(f"File quarantined: {file_path} -> {quarantine_file_path} (ID: {quarantine_id})")
            return True, f"File quarantined successfully (ID: {quarantine_id})", quarantine_id

        except Exception as e:
            logger.error(f"Failed to quarantine file {file_path}: {e}")
            return False, f"Quarantine failed: {str(e)}", None

    def restore_file(self, quarantine_id: str, target_path: Optional[Path] = None,
                    admin_override: bool = False) -> Tuple[bool, str]:
        """
        Restore a quarantined file

        Returns:
            Tuple of (success, message)
        """
        try:
            if quarantine_id not in self._active_quarantines:
                return False, f"Quarantine ID not found: {quarantine_id}"

            metadata = self._active_quarantines[quarantine_id]
            quarantine_path = Path(metadata["quarantine_path"])
            original_path = Path(metadata["original_path"])

            # Determine restore target
            if target_path:
                restore_path = target_path
            else:
                restore_path = original_path

            # Check if target directory exists
            if not restore_path.parent.exists():
                restore_path.parent.mkdir(parents=True, exist_ok=True)

            # Check for conflicts
            if restore_path.exists() and not admin_override:
                return False, f"Target path already exists: {restore_path}. Use admin_override=True to overwrite."

            # Create backup if target exists
            if restore_path.exists():
                backup_path = self.backup_dir / f"restore_backup_{int(time.time())}_{restore_path.name}"
                shutil.move(str(restore_path), str(backup_path))
                metadata["restore_backup"] = str(backup_path)

            # Restore file
            shutil.copy2(str(quarantine_path), str(restore_path))

            # Update metadata
            metadata["state"] = QuarantineState.RESTORED.value
            metadata["restored_at"] = datetime.now().isoformat()
            metadata["restored_to"] = str(restore_path)
            metadata["admin_override"] = admin_override

            # Save updated metadata
            metadata_path = self.metadata_dir / f"{quarantine_id}.json"
            with open(metadata_path, 'w', encoding='utf-8') as f:
                json.dump(metadata, f, indent=2, ensure_ascii=False)

            # Update state
            del self._active_quarantines[quarantine_id]
            self._restore_operations[quarantine_id] = metadata
            self._save_state()

            # Call callbacks
            for callback in self._restore_callbacks:
                try:
                    callback(quarantine_id, metadata)
                except Exception as e:
                    logger.error(f"Restore callback failed: {e}")

            logger.info(f"File restored: {quarantine_path} -> {restore_path} (ID: {quarantine_id})")
            return True, f"File restored successfully to {restore_path}"

        except Exception as e:
            logger.error(f"Failed to restore file {quarantine_id}: {e}")
            return False, f"Restore failed: {str(e)}"

    def quarantine_process(self, pid: int, reason: str, threat_data: Optional[Dict] = None) -> Tuple[bool, str, Optional[str]]:
        """
        Quarantine a process (suspend/terminate with state preservation)

        Returns:
            Tuple of (success, message, quarantine_id)
        """
        try:
            import psutil

            if not psutil.pid_exists(pid):
                return False, f"Process {pid} does not exist", None

            proc = psutil.Process(pid)

            # Generate quarantine ID
            quarantine_id = f"process_{int(time.time())}_{pid}"

            # Suspend process
            try:
                proc.suspend()
                suspended = True
            except Exception:
                suspended = False
                logger.warning(f"Could not suspend process {pid}, terminating instead")

            # Terminate process if suspend failed
            if not suspended:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except psutil.TimeoutExpired:
                    proc.kill()

            # Create metadata
            metadata = {
                "quarantine_id": quarantine_id,
                "pid": pid,
                "process_name": proc.name(),
                "process_cmdline": proc.cmdline(),
                "process_cwd": str(proc.cwd()) if proc.cwd() else None,
                "reason": reason,
                "threat_data": threat_data or {},
                "quarantined_at": datetime.now().isoformat(),
                "state": QuarantineState.ACTIVE.value,
                "process_suspended": suspended,
                "process_terminated": not suspended
            }

            # Save metadata
            metadata_path = self.metadata_dir / f"{quarantine_id}.json"
            with open(metadata_path, 'w', encoding='utf-8') as f:
                json.dump(metadata, f, indent=2, ensure_ascii=False)

            # Update state
            self._active_quarantines[quarantine_id] = metadata
            self._save_state()

            # Call callbacks
            for callback in self._quarantine_callbacks:
                try:
                    callback(quarantine_id, metadata)
                except Exception as e:
                    logger.error(f"Quarantine callback failed: {e}")

            action = "suspended" if suspended else "terminated"
            logger.info(f"Process quarantined: PID {pid} ({action}) - ID: {quarantine_id}")
            return True, f"Process {action} successfully (ID: {quarantine_id})", quarantine_id

        except Exception as e:
            logger.error(f"Failed to quarantine process {pid}: {e}")
            return False, f"Process quarantine failed: {str(e)}", None

    def get_quarantine_inventory(self) -> Dict:
        """Get comprehensive quarantine inventory"""
        inventory = {
            "active": {},
            "restored": {},
            "failed": {},
            "summary": {
                "total_active": 0,
                "total_restored": 0,
                "total_failed": 0,
                "by_type": {},
                "by_reason": {}
            }
        }

        # Process all metadata files
        for metadata_file in self.metadata_dir.glob("*.json"):
            try:
                with open(metadata_file, 'r', encoding='utf-8') as f:
                    metadata = json.load(f)

                quarantine_id = metadata["quarantine_id"]
                state = metadata.get("state", QuarantineState.ACTIVE.value)

                if state == QuarantineState.ACTIVE.value:
                    inventory["active"][quarantine_id] = metadata
                    inventory["summary"]["total_active"] += 1
                elif state == QuarantineState.RESTORED.value:
                    inventory["restored"][quarantine_id] = metadata
                    inventory["summary"]["total_restored"] += 1
                elif state == QuarantineState.FAILED.value:
                    inventory["failed"][quarantine_id] = metadata
                    inventory["summary"]["total_failed"] += 1

                # Update type summary
                q_type = quarantine_id.split("_")[0]
                inventory["summary"]["by_type"][q_type] = inventory["summary"]["by_type"].get(q_type, 0) + 1

                # Update reason summary
                reason = metadata.get("reason", "unknown")
                inventory["summary"]["by_reason"][reason] = inventory["summary"]["by_reason"].get(reason, 0) + 1

            except Exception as e:
                logger.error(f"Failed to read quarantine metadata {metadata_file}: {e}")

        return inventory

    def cleanup_expired_quarantines(self, max_age_days: int = 30) -> int:
        """Clean up old quarantined items"""
        cutoff_date = datetime.now() - timedelta(days=max_age_days)
        cleaned_count = 0

        for quarantine_id, metadata in list(self._active_quarantines.items()):
            quarantined_at = datetime.fromisoformat(metadata["quarantined_at"])
            if quarantined_at < cutoff_date:
                try:
                    # Remove quarantined file
                    quarantine_path = Path(metadata["quarantine_path"])
                    if quarantine_path.exists():
                        quarantine_path.unlink()

                    # Remove metadata
                    metadata_path = self.metadata_dir / f"{quarantine_id}.json"
                    if metadata_path.exists():
                        metadata_path.unlink()

                    # Remove from state
                    del self._active_quarantines[quarantine_id]
                    cleaned_count += 1

                except Exception as e:
                    logger.error(f"Failed to cleanup quarantine {quarantine_id}: {e}")

        if cleaned_count > 0:
            self._save_state()
            logger.info(f"Cleaned up {cleaned_count} expired quarantines")

        return cleaned_count

    def _calculate_file_hash(self, file_path: Path) -> Optional[str]:
        """Calculate SHA256 hash of a file"""
        try:
            import hashlib
            sha256 = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception:
            return None

    def get_quarantine_stats(self) -> Dict:
        """Get quarantine statistics"""
        inventory = self.get_quarantine_inventory()
        return {
            "total_quarantines": len(inventory["active"]) + len(inventory["restored"]) + len(inventory["failed"]),
            "active_quarantines": len(inventory["active"]),
            "restored_quarantines": len(inventory["restored"]),
            "failed_quarantines": len(inventory["failed"]),
            "storage_used_mb": self._calculate_storage_used() / (1024 * 1024),
            "oldest_quarantine_days": self._get_oldest_quarantine_days()
        }

    def _calculate_storage_used(self) -> int:
        """Calculate total storage used by quarantine"""
        total_size = 0
        for path in [self.files_dir, self.metadata_dir, self.backup_dir]:
            if path.exists():
                total_size += sum(f.stat().st_size for f in path.rglob("*") if f.is_file())
        return total_size

    def _get_oldest_quarantine_days(self) -> Optional[int]:
        """Get age of oldest quarantine in days"""
        oldest_date = None
        for metadata in self._active_quarantines.values():
            q_date = datetime.fromisoformat(metadata["quarantined_at"])
            if oldest_date is None or q_date < oldest_date:
                oldest_date = q_date

        if oldest_date:
            return (datetime.now() - oldest_date).days
        return None


# Global quarantine manager instance
quarantine_manager = QuarantineWorkflowManager()