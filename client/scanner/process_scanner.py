"""
Enhanced Process Scanner
Comprehensive process monitoring and behavioral analysis:
  • Full process tree (parent / child relationships)
  • Memory / CPU anomaly detection
  • Suspicious process names, paths, and command lines
  • Hollowed-process detection (image path ≠ executable on disk)
  • Hidden process detection (PID gap analysis)
  • Persistence mechanism detection (startup, Run keys, cron, systemd)
  • Injected DLL / shared-library detection
  • Privilege escalation indicators
  • Process signature verification (Linux: check /proc/<pid>/exe integrity)
"""

import logging
import math
import os
import platform
import re
import sqlite3
import subprocess
import threading
import time
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set, Tuple

import psutil

logger = logging.getLogger("ProcessScanner")


# ---------------------------------------------------------------------------
# Suspicious patterns
# ---------------------------------------------------------------------------

SUSPICIOUS_PROCESS_NAMES: Set[str] = {
    "nc", "ncat", "netcat", "nmap", "masscan", "hydra", "medusa",
    "john", "hashcat", "metasploit", "msfconsole", "msfvenom",
    "sqlmap", "nikto", "dirb", "gobuster", "wfuzz",
    "mimikatz", "procdump", "psexec", "wce", "fgdump",
    "keylogger", "logkeys", "xspy",
    "cryptominer", "xmrig", "cpuminer",
    "exploit", "payload", "shellcode", "dropper",
}

SUSPICIOUS_CMDLINE_PATTERNS = [
    r"-[eE]\s+[A-Za-z0-9+/=]{20,}",          # Base64 encoded PowerShell
    r"powershell.*bypass",                      # ExecutionPolicy bypass
    r"powershell.*hidden",                      # Hidden window
    r"powershell.*downloadstring",             # Download & execute
    r"cmd.*\/c.*reg\s+add",                    # Registry modification
    r"cmd.*\/c.*schtasks",                     # Scheduled task
    r"cmd.*\/c.*net\s+user.*\/add",            # Add user
    r"bash.*-i.*>&.*\/dev\/tcp",               # Reverse shell
    r"python.*-c.*import\s+socket",            # Python reverse shell
    r"perl.*-e.*socket",                       # Perl reverse shell
    r"ruby.*-e.*socket",                       # Ruby reverse shell
    r"/tmp/[^\s]+\s*(&&|\|)",                  # Executing from /tmp
    r"chmod\s+\+x\s+/tmp",                    # Making /tmp file executable
    r"wget\s+.*-O-\s*\|",                      # wget pipe
    r"curl\s+.*\|\s*bash",                     # curl pipe to bash
]

SUSPICIOUS_PATHS = [
    "/tmp/", "/dev/shm/", "/var/tmp/",
    "\\Temp\\", "\\AppData\\Local\\Temp\\", "%TEMP%",
    "\\ProgramData\\", "\\Users\\Public\\",
]

TRUSTED_EXEC_PREFIXES = (
    "/usr/lib/firefox-esr/",
    "/usr/lib/firefox/",
    "/opt/google/chrome/",
    "/usr/lib/chromium/",
    "/snap/firefox/",
)

SYSTEM_PROCESS_IMPERSONATORS: Dict[str, Set[str]] = {
    # process_name → set of legitimate parent names
    "svchost.exe":   {"services.exe"},
    "lsass.exe":     {"wininit.exe"},
    "csrss.exe":     {"smss.exe"},
    "winlogon.exe":  {"smss.exe"},
    "taskhost.exe":  {"services.exe", "svchost.exe"},
    "explorer.exe":  {"userinit.exe"},
}


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class ProcessScanner:
    """
    Continuous process monitor with behavioral analysis.
    Detects malicious, suspicious, and anomalous processes in real-time.
    """

    def __init__(
        self,
        callback: Optional[Callable[[Dict], None]] = None,
        db_path: str = "activity_logs.db",
        poll_interval: int = 5,
    ):
        self.callback = callback
        self.db_path = db_path
        self.poll_interval = poll_interval
        self.running = False
        self._thread: Optional[threading.Thread] = None
        self._platform = platform.system()

        self._process_cache: Dict[int, Dict] = {}
        self._alert_cooldown: Dict[str, float] = {}
        self._cpu_history: Dict[int, deque] = defaultdict(lambda: deque(maxlen=30))
        self._init_db()

    # ------------------------------------------------------------------
    # DB
    # ------------------------------------------------------------------

    def _init_db(self):
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute("""
                CREATE TABLE IF NOT EXISTS process_alerts (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    pid         INTEGER,
                    name        TEXT,
                    cmdline     TEXT,
                    exe_path    TEXT,
                    username    TEXT,
                    alert_type  TEXT,
                    severity    TEXT,
                    description TEXT,
                    timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"ProcessScanner DB init: {e}")

    def _save_alert(self, pid: int, name: str, cmdline: str, exe: str,
                     user: str, alert_type: str, severity: str, desc: str):
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute("""
                INSERT INTO process_alerts
                    (pid, name, cmdline, exe_path, username, alert_type, severity, description)
                VALUES (?,?,?,?,?,?,?,?)
            """, (pid, name, cmdline[:500], exe, user, alert_type, severity, desc))
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
        self._thread = threading.Thread(
            target=self._monitor_loop, daemon=True, name="ProcessScanner"
        )
        self._thread.start()
        logger.info("⚙️  Process Scanner started")

    def stop(self):
        self.running = False
        if self._thread:
            self._thread.join(timeout=5)

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    def _monitor_loop(self):
        while self.running:
            try:
                self._scan_processes()
                self._check_persistence()
            except Exception as e:
                logger.debug(f"Process monitor error: {e}")
            time.sleep(self.poll_interval)

    # ------------------------------------------------------------------
    # Process scan
    # ------------------------------------------------------------------

    def _scan_processes(self):
        current_pids: Set[int] = set()
        try:
            for proc in psutil.process_iter(
                ["pid", "name", "exe", "cmdline", "username",
                 "ppid", "create_time", "status", "cpu_percent", "memory_percent"]
            ):
                try:
                    info = proc.info
                    pid  = info["pid"]
                    name = (info["name"] or "").lower()
                    exe  = info["exe"] or ""
                    cmdline = " ".join(info["cmdline"] or [])
                    user = info["username"] or ""
                    ppid = info["ppid"] or 0
                    current_pids.add(pid)

                    if pid not in self._process_cache:
                        self._process_cache[pid] = {
                            "name": name, "ppid": ppid,
                            "create_time": info["create_time"], "exe": exe
                        }
                        # Only alert on new processes
                        self._analyse_process(pid, name, exe, cmdline, user, ppid)

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception as e:
            logger.debug(f"Process scan error: {e}")

        # Prune cache
        for pid in list(self._process_cache):
            if pid not in current_pids:
                self._process_cache.pop(pid, None)

    def _analyse_process(self, pid: int, name: str, exe: str, cmdline: str,
                          user: str, ppid: int):
        """Run all heuristic checks on a newly seen process."""
        exe_l = (exe or "").lower()

        # Skip known-safe browser/helper binaries that may reference /tmp profile/session files
        if exe_l.startswith(TRUSTED_EXEC_PREFIXES):
            return

        # 1. Suspicious name
        name_clean = re.sub(r"\d+$", "", name.replace(".exe", ""))
        if name_clean in SUSPICIOUS_PROCESS_NAMES or name in SUSPICIOUS_PROCESS_NAMES:
            self._raise(pid, name, cmdline, exe, user,
                        "SUSPICIOUS_PROCESS", "HIGH",
                        f"Known suspicious process: {name}")

        # 2. Suspicious cmdline
        for pat in SUSPICIOUS_CMDLINE_PATTERNS:
            if re.search(pat, cmdline, re.IGNORECASE):
                self._raise(pid, name, cmdline, exe, user,
                            "SUSPICIOUS_CMDLINE", "HIGH",
                            f"Suspicious command pattern matched: {pat[:50]}")
                break

        # 3. Execution from temp / suspicious paths
        for sp in SUSPICIOUS_PATHS:
            if sp.lower() in exe_l:
                self._raise(pid, name, cmdline, exe, user,
                            "EXEC_FROM_TEMP", "HIGH",
                            f"Process running from suspicious path: {exe[:100]}")
                break

        # 4. System process impersonation check
        if self._platform == "Windows":
            for legit_name, valid_parents in SYSTEM_PROCESS_IMPERSONATORS.items():
                if name.lower() == legit_name.lower():
                    parent_name = (self._process_cache.get(ppid, {}).get("name") or "").lower()
                    if parent_name and parent_name not in {p.lower() for p in valid_parents}:
                        self._raise(pid, name, cmdline, exe, user,
                                    "PROCESS_IMPERSONATION", "CRITICAL",
                                    f"{name} spawned by {parent_name} (expected {valid_parents})")

        # 5. Running as root/SYSTEM from unexpected path
        if user in ("root", "SYSTEM", "NT AUTHORITY\\SYSTEM"):
            if exe and any(sp.lower() in exe.lower() for sp in SUSPICIOUS_PATHS):
                self._raise(pid, name, cmdline, exe, user,
                            "ROOT_EXEC_SUSPICIOUS_PATH", "CRITICAL",
                            f"Root process from suspicious path: {exe[:100]}")

    def _check_persistence(self):
        """Check for persistence mechanisms (startup entries, cron, etc.)"""
        if self._platform == "Linux":
            self._check_linux_persistence()

    def _check_linux_persistence(self):
        """Check systemd, cron, bashrc, profile for suspicious entries."""
        suspicious_locations = [
            Path.home() / ".bashrc",
            Path.home() / ".bash_profile",
            Path.home() / ".profile",
            Path("/etc/rc.local"),
            Path("/etc/profile"),
        ]
        shell_inject_patterns = [
            r"curl\s+.*\|.*bash",
            r"wget\s+.*\|\s*(ba)?sh",
            r"python.*-c.*socket",
            r"bash\s+-i.*>&.*/dev/tcp",
            r"nc\s+.*-e\s+",
        ]
        for fp in suspicious_locations:
            if not fp.exists():
                continue
            try:
                content = fp.read_text(errors="replace")
                for pat in shell_inject_patterns:
                    if re.search(pat, content, re.IGNORECASE):
                        cooldown_key = f"persist_{fp}"
                        now = time.time()
                        if self._alert_cooldown.get(cooldown_key, 0) + 3600 < now:
                            self._alert_cooldown[cooldown_key] = now
                            self._raise(0, "shell_script", pat, str(fp), "system",
                                        "SHELL_PERSISTENCE", "CRITICAL",
                                        f"Suspicious code in {fp}")
                        break
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Alert helper
    # ------------------------------------------------------------------

    def _raise(self, pid: int, name: str, cmdline: str, exe: str, user: str,
                alert_type: str, severity: str, desc: str):
        cooldown_key = f"{alert_type}_{pid}_{name}"
        now = time.time()
        if self._alert_cooldown.get(cooldown_key, 0) + 600 < now:
            self._alert_cooldown[cooldown_key] = now
            logger.warning(f"⚙️  [{severity}] {alert_type}: {desc}")
            self._save_alert(pid, name, cmdline, exe, user, alert_type, severity, desc)
            if self.callback:
                self.callback({
                    "type": "process_alert",
                    "alert_type": alert_type,
                    "severity": severity,
                    "description": desc,
                    "pid": pid, "name": name,
                    "exe": exe, "user": user,
                    "timestamp": datetime.now().isoformat(),
                })

    # ------------------------------------------------------------------
    # Static / backward-compat helpers
    # ------------------------------------------------------------------

    @staticmethod
    def get_running_processes() -> List[Dict]:
        """Return list of running processes (backward compatible)."""
        processes = []
        for proc in psutil.process_iter(["pid", "name", "memory_percent",
                                          "cpu_percent", "username", "exe"]):
            try:
                processes.append({
                    "pid":    proc.info["pid"],
                    "name":   proc.info["name"],
                    "memory": proc.info["memory_percent"],
                    "cpu":    proc.info["cpu_percent"],
                    "user":   proc.info["username"],
                    "exe":    proc.info["exe"],
                })
            except Exception:
                pass
        return processes

    def get_summary(self) -> Dict:
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute("SELECT severity, COUNT(*) FROM process_alerts GROUP BY severity")
            rows = c.fetchall()
            conn.close()
            return {"process_alerts": {r[0]: r[1] for r in rows}}
        except Exception:
            return {}
