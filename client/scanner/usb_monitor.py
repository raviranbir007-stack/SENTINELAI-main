"""
USB / Removable-Media Monitor
Detects every USB / storage device insertion and removal in real-time.
On Linux it uses pyudev; on Windows it uses WMI; on macOS it polls /Volumes.

Capabilities
------------
* Real-time hot-plug detection (insert / remove events)
* Device fingerprinting  (vendor, model, serial, bus path)
* Auto-scan of mounted volume for malware (file hash → VirusTotal)
* Entropy-based detection of suspicious files (packed / encrypted)
* AutoRun / Autoplay script detection (autorun.inf, .bat, .ps1 …)
* Write-block enforcement (optional – marks volume read-only on Linux)
* Suspicious file-type blocking (.exe, .dll, .ps1, .vbs, .bat on USB)
* Full event log with risk rating sent via callback
"""

import hashlib
import importlib
import json
import logging
import math
import os
import platform
import re
import shutil
import sqlite3
import subprocess
import threading
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set

logger = logging.getLogger("USBMonitor")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _entropy(data: bytes) -> float:
    """Shannon entropy of a byte sequence (0‥8)."""
    if not data:
        return 0.0
    freq: Dict[int, int] = defaultdict(int)
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values() if c)


def _file_entropy(path: str, sample: int = 65536) -> float:
    """Return entropy of up to *sample* bytes from *path*."""
    try:
        with open(path, "rb") as fh:
            return _entropy(fh.read(sample))
    except Exception:
        return 0.0


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
    except Exception:
        return ""
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Suspicious patterns
# ---------------------------------------------------------------------------

AUTORUN_NAMES = {"autorun.inf", "autoplay.inf", ".autorun"}

DANGEROUS_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js",
    ".jse", ".wsf", ".wsh", ".msi", ".scr", ".pif", ".com", ".hta",
    ".cpl", ".reg", ".lnk", ".inf",
}

SUSPICIOUS_NAMES = {
    "autorun", "setup", "install", "update", "patch", "helper",
    "loader", "dropper", "payload", "exploit", "hack", "crack",
    "keygen", "activator", "bypass",
}

MAX_SCAN_FILES = 500          # never scan more than this many files per volume
MAX_FILE_SIZE_BYTES = 100 * 1024 * 1024   # skip files > 100 MB
HIGH_ENTROPY_THRESHOLD = 7.2  # packed / encrypted indicator


# ---------------------------------------------------------------------------
# Platform helpers
# ---------------------------------------------------------------------------

def _get_block_devices_linux() -> List[Dict]:
    """Return mounted removable block devices via lsblk."""
    try:
        out = subprocess.check_output(
            ["lsblk", "-J", "-o", "NAME,HOTPLUG,MOUNTPOINT,VENDOR,MODEL,SERIAL,SIZE,TYPE"],
            timeout=10, text=True, stderr=subprocess.DEVNULL
        )
        data = json.loads(out)
        devices = []
        for bd in data.get("blockdevices", []):
            _flatten(bd, devices)
        return [d for d in devices if d.get("hotplug") == "1" and d.get("mountpoint")]
    except Exception:
        return []


def _flatten(node: Dict, result: List):
    result.append(node)
    for child in node.get("children", []):
        _flatten(child, result)


def _make_readonly_linux(mountpoint: str) -> bool:
    """Remount a filesystem read-only (requires root)."""
    try:
        subprocess.run(
            ["mount", "-o", "remount,ro", mountpoint],
            timeout=5, check=True, capture_output=True
        )
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class USBMonitor:
    """Real-time USB / removable-media monitor with auto-scan."""

    def __init__(
        self,
        callback: Optional[Callable[[Dict], None]] = None,
        threat_analyzer=None,
        db_path: str = "activity_logs.db",
        enforce_write_block: bool = False,
        block_dangerous_files: bool = True,
    ):
        self.callback = callback
        self.threat_analyzer = threat_analyzer
        self.db_path = db_path
        self.enforce_write_block = enforce_write_block
        self.block_dangerous_files = block_dangerous_files
        self.running = False
        self._thread: Optional[threading.Thread] = None
        self._scan_threads: List[threading.Thread] = []

        # Tracks currently known devices: serial/path → device dict
        self._known_devices: Dict[str, Dict] = {}
        self._lock = threading.Lock()

        self._init_db()
        self._platform = platform.system()

    # ------------------------------------------------------------------
    # DB
    # ------------------------------------------------------------------

    def _init_db(self):
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute("""
                CREATE TABLE IF NOT EXISTS usb_events (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type  TEXT NOT NULL,
                    device_id   TEXT,
                    vendor      TEXT,
                    model       TEXT,
                    serial      TEXT,
                    mountpoint  TEXT,
                    size        TEXT,
                    risk_level  TEXT DEFAULT 'UNKNOWN',
                    details     TEXT,
                    timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS usb_file_scans (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id    TEXT,
                    file_path    TEXT,
                    file_hash    TEXT,
                    file_size    INTEGER,
                    entropy      REAL,
                    extension    TEXT,
                    risk_level   TEXT DEFAULT 'UNKNOWN',
                    vt_verdict   TEXT,
                    timestamp    DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"USB DB init failed: {e}")

    def _log_event(self, event_type: str, device: Dict, risk: str = "INFO", details: str = ""):
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute("""
                INSERT INTO usb_events
                    (event_type, device_id, vendor, model, serial, mountpoint, size, risk_level, details)
                VALUES (?,?,?,?,?,?,?,?,?)
            """, (
                event_type,
                device.get("name", ""),
                device.get("vendor", ""),
                device.get("model", ""),
                device.get("serial", ""),
                device.get("mountpoint", ""),
                device.get("size", ""),
                risk,
                details,
            ))
            conn.commit()
            conn.close()
        except Exception:
            pass

    def _log_file_scan(self, device_id: str, path: str, fhash: str,
                        size: int, ent: float, ext: str, risk: str, verdict: str):
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute("""
                INSERT INTO usb_file_scans
                    (device_id, file_path, file_hash, file_size, entropy, extension, risk_level, vt_verdict)
                VALUES (?,?,?,?,?,?,?,?)
            """, (device_id, path, fhash, size, ent, ext, risk, verdict))
            conn.commit()
            conn.close()
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self):
        if self.running:
            return
        self.running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True, name="USBMonitor")
        self._thread.start()
        logger.debug("USB monitor started")

    def stop(self):
        self.running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("USB Monitor stopped")

    # ------------------------------------------------------------------
    # Monitor loop
    # ------------------------------------------------------------------

    def _monitor_loop(self):
        """Poll for device changes; prefer udev events on Linux."""
        if self._platform == "Linux":
            self._run_udev()
        elif self._platform == "Windows":
            self._run_wmi()
        else:
            self._run_poll()

    # ---- Linux udev ----

    def _run_udev(self):
        try:
            pyudev = importlib.import_module("pyudev")
            context = pyudev.Context()
            monitor = pyudev.Monitor.from_netlink(context)
            monitor.filter_by(subsystem="block")
            # Do an initial snapshot
            self._snapshot_linux()
            for action, device in monitor:
                if not self.running:
                    break
                if action == "add":
                    time.sleep(1.5)  # wait for mount
                    self._on_insert_linux(device)
                elif action == "remove":
                    self._on_remove_linux(device)
        except ImportError:
            logger.warning("pyudev not installed – falling back to polling")
            self._run_poll()
        except Exception as e:
            logger.error(f"udev monitor error: {e}")
            self._run_poll()

    def _snapshot_linux(self):
        for dev in _get_block_devices_linux():
            key = dev.get("serial") or dev.get("name", "")
            with self._lock:
                self._known_devices[key] = dev

    def _on_insert_linux(self, udev_device):
        devs = _get_block_devices_linux()
        known_keys = set(self._known_devices.keys())
        for dev in devs:
            key = dev.get("serial") or dev.get("name", "")
            if key not in known_keys:
                with self._lock:
                    self._known_devices[key] = dev
                self._handle_insert(dev)

    def _on_remove_linux(self, udev_device):
        sys_name = udev_device.sys_name
        with self._lock:
            gone = [k for k, v in self._known_devices.items()
                    if sys_name in v.get("name", "")]
        for key in gone:
            dev = self._known_devices.pop(key, {})
            self._handle_remove(dev)

    # ---- Windows WMI ----

    def _run_wmi(self):
        try:
            wmi = importlib.import_module("wmi")
            c = wmi.WMI()
            watcher = c.Win32_VolumeChangeEvent.watch_for("creation")
            self._snapshot_windows(c)
            while self.running:
                try:
                    event = watcher(timeout_ms=2000)
                    if event:
                        time.sleep(1.5)
                        self._snapshot_windows(c)
                except Exception:
                    pass
        except ImportError:
            logger.warning("wmi not installed – falling back to polling")
            self._run_poll()

    def _snapshot_windows(self, c):
        try:
            for disk in c.Win32_DiskDrive():
                for part in disk.associators("Win32_DiskDriveToDiskPartition"):
                    for logical in part.associators("Win32_LogicalDiskToPartition"):
                        if logical.DriveType == 2:   # removable
                            dev = {
                                "name": logical.DeviceID,
                                "vendor": disk.Manufacturer or "",
                                "model": disk.Model or "",
                                "serial": disk.SerialNumber or "",
                                "mountpoint": logical.DeviceID + "\\",
                                "size": str(disk.Size or ""),
                            }
                            key = dev["serial"] or dev["name"]
                            with self._lock:
                                if key not in self._known_devices:
                                    self._known_devices[key] = dev
                                    self._handle_insert(dev)
        except Exception as e:
            logger.debug(f"WMI snapshot: {e}")

    # ---- Generic polling fallback ----

    def _run_poll(self):
        """Poll mounted volumes every 3 seconds."""
        prev: Set[str] = set()
        while self.running:
            try:
                current = self._get_removable_mounts()
                inserted = current - prev
                removed = prev - current
                for mp in inserted:
                    dev = {"name": mp, "vendor": "", "model": "", "serial": "",
                           "mountpoint": mp, "size": ""}
                    with self._lock:
                        self._known_devices[mp] = dev
                    self._handle_insert(dev)
                for mp in removed:
                    dev = self._known_devices.pop(mp, {"name": mp, "mountpoint": mp})
                    self._handle_remove(dev)
                prev = current
            except Exception as e:
                logger.debug(f"Poll error: {e}")
            time.sleep(3)

    def _get_removable_mounts(self) -> Set[str]:
        mounts: Set[str] = set()
        try:
            import psutil
            for part in psutil.disk_partitions():
                if "removable" in part.opts or part.fstype in ("vfat", "exfat", "ntfs"):
                    if part.mountpoint and os.path.ismount(part.mountpoint):
                        mounts.add(part.mountpoint)
        except Exception:
            pass
        return mounts

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def _handle_insert(self, device: Dict):
        mp = device.get("mountpoint", "")
        label = f"{device.get('vendor','')} {device.get('model','')}".strip() or mp
        logger.warning(f"🔌 USB INSERTED: {label}  →  {mp}")

        # Write-block enforcement
        if self.enforce_write_block and self._platform == "Linux" and mp:
            _make_readonly_linux(mp)
            logger.info(f"🔒 Write-blocked: {mp}")

        event = {
            "type": "usb_insert",
            "device": device,
            "mountpoint": mp,
            "label": label,
            "timestamp": datetime.now().isoformat(),
            "risk": "INFO",
        }

        # Check for AutoRun files immediately
        autorun_risk = self._check_autorun(mp)
        if autorun_risk:
            event["risk"] = "CRITICAL"
            event["autorun_detected"] = True
            logger.critical(f"🚨 AUTORUN DETECTED on USB: {mp}")

        self._log_event("INSERT", device, event["risk"])

        if self.callback:
            self.callback(event)

        # Start background volume scan
        t = threading.Thread(
            target=self._scan_volume,
            args=(device,),
            daemon=True,
            name=f"USB-Scan-{mp}",
        )
        t.start()
        self._scan_threads.append(t)

    def _handle_remove(self, device: Dict):
        mp = device.get("mountpoint", device.get("name", ""))
        logger.info(f"🔌 USB REMOVED: {mp}")
        self._log_event("REMOVE", device, "INFO")
        if self.callback:
            self.callback({
                "type": "usb_remove",
                "device": device,
                "mountpoint": mp,
                "timestamp": datetime.now().isoformat(),
                "risk": "INFO",
            })

    # ------------------------------------------------------------------
    # AutoRun detection
    # ------------------------------------------------------------------

    def _check_autorun(self, mountpoint: str) -> bool:
        if not mountpoint:
            return False
        for name in AUTORUN_NAMES:
            p = Path(mountpoint) / name
            if p.exists():
                return True
        return False

    # ------------------------------------------------------------------
    # Volume scanner
    # ------------------------------------------------------------------

    def _scan_volume(self, device: Dict):
        mp = device.get("mountpoint", "")
        if not mp or not os.path.isdir(mp):
            return

        device_id = device.get("serial") or device.get("name", mp)
        logger.info(f"🔍 Scanning USB volume: {mp}")

        scanned = 0
        threats: List[Dict] = []

        for root, _dirs, files in os.walk(mp):
            if not self.running:
                break
            for fname in files:
                if scanned >= MAX_SCAN_FILES:
                    break
                fpath = os.path.join(root, fname)
                try:
                    result = self._scan_file(fpath, device_id)
                    scanned += 1
                    if result and result["risk"] in ("HIGH", "CRITICAL"):
                        threats.append(result)
                        if self.block_dangerous_files:
                            self._quarantine_file(fpath, result)
                except Exception:
                    pass

        risk_summary = "CLEAN"
        if threats:
            max_risk = max(
                ("CRITICAL", "HIGH", "MEDIUM", "LOW", "CLEAN").index(t["risk"])
                for t in threats
            )
            risk_summary = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "CLEAN")[max_risk]

        logger.info(f"✅ USB scan done: {mp}  files={scanned}  threats={len(threats)}  risk={risk_summary}")

        if self.callback:
            self.callback({
                "type": "usb_scan_complete",
                "device": device,
                "mountpoint": mp,
                "files_scanned": scanned,
                "threats_found": len(threats),
                "risk": risk_summary,
                "threats": threats[:20],   # cap payload
                "timestamp": datetime.now().isoformat(),
            })

    def _scan_file(self, fpath: str, device_id: str) -> Optional[Dict]:
        try:
            stat = os.stat(fpath)
            size = stat.st_size
            if size > MAX_FILE_SIZE_BYTES:
                return None

            ext = Path(fpath).suffix.lower()
            name_lower = Path(fpath).stem.lower()
            ent = _file_entropy(fpath)
            fhash = _sha256(fpath)
            risk = "LOW"
            verdict = "UNKNOWN"

            # --- Rule 1: dangerous extension ---
            if ext in DANGEROUS_EXTENSIONS:
                risk = "HIGH"
                verdict = "DANGEROUS_EXTENSION"

            # --- Rule 2: suspicious name ---
            if any(s in name_lower for s in SUSPICIOUS_NAMES):
                risk = max(risk, "HIGH", key=lambda r: ("LOW", "MEDIUM", "HIGH", "CRITICAL").index(r))
                verdict = "SUSPICIOUS_NAME"

            # --- Rule 3: high entropy (packed / encrypted) ---
            if ent >= HIGH_ENTROPY_THRESHOLD and size > 4096:
                if risk == "LOW":
                    risk = "MEDIUM"
                verdict = f"{verdict}+HIGH_ENTROPY({ent:.2f})" if verdict != "UNKNOWN" else f"HIGH_ENTROPY({ent:.2f})"

            # --- Rule 4: AutoRun file ---
            if Path(fpath).name.lower() in AUTORUN_NAMES:
                risk = "CRITICAL"
                verdict = "AUTORUN"

            # --- Rule 5: VirusTotal hash check (async – queue) ---
            if self.threat_analyzer and fhash and ext in DANGEROUS_EXTENSIONS:
                self.threat_analyzer.queue_scan("file", fhash, {"path": fpath, "device": device_id})

            self._log_file_scan(device_id, fpath, fhash, size, ent, ext, risk, verdict)

            if risk in ("HIGH", "CRITICAL"):
                logger.warning(f"⚠️  USB threat: {fpath}  risk={risk}  [{verdict}]")

            return {"path": fpath, "hash": fhash, "size": size, "entropy": ent,
                    "ext": ext, "risk": risk, "verdict": verdict}
        except Exception:
            return None

    def _quarantine_file(self, fpath: str, result: Dict):
        """Move dangerous file to quarantine folder."""
        try:
            q_dir = Path("quarantine") / "usb"
            q_dir.mkdir(parents=True, exist_ok=True)
            ts = datetime.now().strftime("%Y%m%d%H%M%S")
            dest = q_dir / f"{ts}_{Path(fpath).name}"
            shutil.move(fpath, dest)
            logger.critical(f"🔒 QUARANTINED USB file: {fpath} → {dest}")
            if self.callback:
                self.callback({
                    "type": "usb_file_quarantined",
                    "original_path": fpath,
                    "quarantine_path": str(dest),
                    "risk": result["risk"],
                    "verdict": result["verdict"],
                    "timestamp": datetime.now().isoformat(),
                })
        except Exception as e:
            logger.error(f"Quarantine failed for {fpath}: {e}")

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    def get_events_summary(self) -> Dict:
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute("SELECT COUNT(*) FROM usb_events WHERE event_type='INSERT'")
            inserts = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM usb_file_scans WHERE risk_level IN ('HIGH','CRITICAL')")
            threats = c.fetchone()[0]
            conn.close()
            return {"usb_inserts": inserts, "usb_threats": threats}
        except Exception:
            return {"usb_inserts": 0, "usb_threats": 0}
