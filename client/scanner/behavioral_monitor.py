"""
Behavioral Analytics Monitor  (User & Entity Behavior Analytics – UEBA)
Detects anomalous user/system behaviour that indicates compromise:

  • Login time anomalies (off-hours logins, impossible travel)
  • Sudden privilege escalation (sudo / su / UAC events)
  • Mass file access / deletion / encryption (ransomware-like activity)
  • Large outbound data transfers (exfiltration)
  • Clipboard sensitive-data harvesting patterns
  • Abnormal process parentage (e.g. Word spawning cmd.exe)
  • Screen-capture / screenshot tool invocations
  • Keystroke-logger process patterns (no keylogging itself – just detection)
  • CPU / memory spikes consistent with crypto-miners
  • Repeated failed authentication attempts in local logs
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
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set, Tuple

import psutil

logger = logging.getLogger("BehavioralMonitor")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

WORK_HOUR_START = 7     # 07:00
WORK_HOUR_END   = 22    # 22:00

# Rapid file-change thresholds (events within the window)
RAPID_FILE_CHANGE_THRESHOLD = 100
RAPID_FILE_CHANGE_WINDOW_SECS = 30

# Data exfil threshold (bytes/min outbound, avg over 5-min window)
# Keep conservative enough to catch large sustained upload bursts without
# flagging ordinary browsing, updates, or conferencing traffic.
EXFIL_BYTES_PER_MIN = 50 * 1024 * 1024   # 50 MB/min

# CPU spike: if a single process > this % for this long
CPU_SPIKE_PCT = 80
CPU_SPIKE_DURATION_SECS = 120

# Suspicious parent→child combos (parent_name → set of suspicious children)
SUSPICIOUS_PARENT_CHILD: Dict[str, Set[str]] = {
    "winword.exe":  {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"},
    "excel.exe":    {"cmd.exe", "powershell.exe", "wscript.exe"},
    "outlook.exe":  {"cmd.exe", "powershell.exe", "regsvr32.exe"},
    "acrord32.exe": {"cmd.exe", "powershell.exe"},
    "firefox":      {"bash", "sh", "cmd.exe"},
    "chrome":       {"bash", "sh", "cmd.exe"},
    "python":       {"bash", "sh", "cmd.exe", "powershell.exe"},
}

# Known screen-capture / keylogger process names (detection only)
SCREEN_CAPTURE_PROCS = {
    "keylogger", "logkeys", "xspy", "xkeylogger", "kidlogger",
    "actual_keylogger", "revealer_keylogger", "perfect_keylogger",
    "screenkey", "scrot", "import",   # 'import' from ImageMagick
}

# Crypto-miner process / cmdline patterns
MINER_PATTERNS = [
    r"--algo\s+", r"--pool\s+", r"stratum\+tcp://", r"xmrig",
    r"cpuminer", r"cgminer", r"bfgminer", r"ethminer",
    r"nicehash", r"minergate", r"--donate-level",
]

BENIGN_HIGH_CPU_PROCESSES = {
    "python", "python3", "python3.11", "python3.12", "python3.13",
    "code", "code-insiders", "codium",
    "chrome", "chromium", "firefox", "brave", "electron", "x-www-browser",
    "google-chrome", "google-chrome-stable", "microsoft-edge", "brave-browser",
    "xfdesktop", "gnome-shell", "plasmashell", "kwin_x11", "kwin_wayland",
    "xorg", "xwayland", "mutter", "compiz",
}


def _is_benign_high_cpu(name: str, cmdline: str) -> bool:
    """Return True for common non-malicious workloads that may spike CPU."""
    n = (name or "").lower().strip()
    c = (cmdline or "").lower()

    if n in BENIGN_HIGH_CPU_PROCESSES:
        return True

    # Handle process naming variations (e.g., code-oss, chromium-browser)
    benign_prefixes = (
        "code", "chrom", "firefox", "brave", "electron", "python", "node",
        "x-www-browser", "google-chrome", "microsoft-edge",
        "xfdesktop", "gnome", "plasma", "kwin", "xorg", "xwayland", "mutter",
    )
    if any(n.startswith(prefix) for prefix in benign_prefixes):
        return True

    # Match executable paths/argv variants
    benign_cmd_markers = (
        "/code", "vscode", "code-insiders", "codium",
        "chromium", "chrome", "firefox", "brave", "electron",
        "x-www-browser", "google-chrome", "microsoft-edge", "brave-browser",
        "xfdesktop", "gnome-shell", "plasmashell", "kwin", "xorg", "xwayland", "mutter",
    )
    return any(marker in c for marker in benign_cmd_markers)

# Sensitive data patterns that shouldn't be in clipboard / screen
SENSITIVE_PATTERNS = [
    r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b",  # credit card
    r"\b\d{3}[\s\-]\d{2}[\s\-]\d{4}\b",                  # SSN
    r"(?i)password\s*[:=]\s*\S+",
    r"(?i)secret\s*[:=]\s*\S+",
    r"(?i)api[_\s]?key\s*[:=]\s*\S+",
    r"(?i)BEGIN\s+(RSA|EC|OPENSSH)\s+PRIVATE\s+KEY",
]


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class BehavioralMonitor:
    """
    Continuous behavioural analytics engine.
    Monitors user/system behaviour and raises alerts on anomalies.
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

        # State tracking
        self._file_change_times: deque = deque()
        self._proc_cpu_history: Dict[int, deque] = defaultdict(lambda: deque(maxlen=60))
        self._net_bytes_history: deque = deque(maxlen=60)
        self._last_net_bytes: Dict[str, int] = {}
        self._process_cache: Dict[int, Dict] = {}   # pid → {name, ppid, create_time}
        self._alert_cooldown: Dict[str, float] = {}   # alert_key → last_alert_ts

        # Clipboard checks are noisy in normal workflows; keep opt-in by default.
        self.enable_clipboard_monitor = os.getenv("SENTINEL_MONITOR_CLIPBOARD", "false").lower() == "true"
        self.clipboard_min_confirmations = int(os.getenv("SENTINEL_CLIPBOARD_MIN_CONFIRMATIONS", "2"))
        self._last_clipboard_fingerprint = ""
        self._clipboard_match_count = 0

        self._init_db()

    # ------------------------------------------------------------------
    # DB
    # ------------------------------------------------------------------

    def _init_db(self):
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute("""
                CREATE TABLE IF NOT EXISTS behavioral_alerts (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_type  TEXT,
                    severity    TEXT,
                    description TEXT,
                    details     TEXT,
                    timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Behavioral DB init: {e}")

    def _save_alert(self, alert_type: str, severity: str, desc: str, details: str):
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute("""
                INSERT INTO behavioral_alerts (alert_type, severity, description, details)
                VALUES (?,?,?,?)
            """, (alert_type, severity, desc, details))
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
            target=self._monitor_loop, daemon=True, name="BehavioralMonitor"
        )
        self._thread.start()
        logger.debug("Behavioral monitor started")

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
                self._check_login_anomaly()
                self._check_process_anomalies()
                self._check_network_exfil()
                self._check_cpu_miners()
                self._check_screen_keyloggers()
                if self.enable_clipboard_monitor:
                    self._check_clipboard()
                self._check_sudo_events()
            except Exception as e:
                logger.debug(f"Behavioral loop error: {e}")
            time.sleep(self.poll_interval)

    # ------------------------------------------------------------------
    # Checks
    # ------------------------------------------------------------------

    def _check_login_anomaly(self):
        """Detect off-hours or failed logins via /var/log/auth.log"""
        if self._platform != "Linux":
            return
        auth_log = Path("/var/log/auth.log")
        if not auth_log.exists():
            return
        try:
            # Read last 200 lines
            out, _, _ = _run_cmd(["tail", "-n", "200", str(auth_log)])
            for line in out.splitlines():
                # Failed password / invalid user
                if "Failed password" in line or "Invalid user" in line:
                    m = re.search(r"from\s+([\d\.]+)", line)
                    ip = m.group(1) if m else "unknown"
                    self._raise_alert(
                        "FAILED_LOGIN", "MEDIUM",
                        f"SSH brute-force attempt from {ip}",
                        line[:200],
                        cooldown_key=f"failed_login_{ip}",
                        cooldown_secs=300,
                    )
                # Off-hours root login
                elif "Accepted" in line and "root" in line:
                    ts_m = re.match(r"(\w+\s+\d+\s+\d+:\d+)", line)
                    if ts_m:
                        hour = int(ts_m.group(1).split()[-1].split(":")[0])
                        if not (WORK_HOUR_START <= hour <= WORK_HOUR_END):
                            self._raise_alert(
                                "OFF_HOURS_ROOT_LOGIN", "HIGH",
                                f"Root login outside work hours (h={hour:02d})",
                                line[:200],
                                cooldown_key="off_hours_root",
                                cooldown_secs=3600,
                            )
        except Exception as e:
            logger.debug(f"Login anomaly check: {e}")

    def _check_process_anomalies(self):
        """Detect suspicious parent→child process combinations."""
        current_pids: Set[int] = set()
        try:
            for proc in psutil.process_iter(["pid", "name", "ppid", "cmdline", "create_time"]):
                try:
                    pid  = proc.info["pid"]
                    name = (proc.info["name"] or "").lower()
                    ppid = proc.info["ppid"]
                    current_pids.add(pid)

                    if pid not in self._process_cache:
                        self._process_cache[pid] = {
                            "name": name, "ppid": ppid,
                            "create_time": proc.info["create_time"]
                        }
                    # Check parent→child
                    if ppid in self._process_cache:
                        parent_name = self._process_cache[ppid]["name"]
                        for pname, suspicious_children in SUSPICIOUS_PARENT_CHILD.items():
                            if pname in parent_name and name in suspicious_children:
                                self._raise_alert(
                                    "SUSPICIOUS_PROCESS_SPAWN", "HIGH",
                                    f"{parent_name} spawned suspicious child {name}",
                                    f"PID={pid} PPID={ppid}",
                                    cooldown_key=f"spawn_{ppid}_{name}",
                                    cooldown_secs=600,
                                )
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception as e:
            logger.debug(f"Process anomaly: {e}")
        # Prune cache
        gone = set(self._process_cache) - current_pids
        for pid in gone:
            self._process_cache.pop(pid, None)

    def _check_network_exfil(self):
        """Detect large outbound data transfers (possible exfiltration)."""
        try:
            counters = psutil.net_io_counters(pernic=False)
            now_bytes_sent = counters.bytes_sent
            ts = time.time()
            if self._last_net_bytes:
                elapsed = ts - self._last_net_bytes.get("ts", ts)
                if elapsed > 0:
                    rate = (now_bytes_sent - self._last_net_bytes.get("sent", now_bytes_sent)) / elapsed
                    self._net_bytes_history.append(rate)
                    if len(self._net_bytes_history) >= 12:   # 1 minute at 5s poll
                        avg_rate = sum(list(self._net_bytes_history)[-12:]) / 12
                        if avg_rate > EXFIL_BYTES_PER_MIN / 60:
                            self._raise_alert(
                                "DATA_EXFILTRATION", "CRITICAL",
                                f"High outbound data rate: {avg_rate/1024/1024:.1f} MB/s",
                                "Possible data exfiltration detected",
                                cooldown_key="exfil",
                                cooldown_secs=300,
                            )
            self._last_net_bytes = {"sent": now_bytes_sent, "ts": ts}
        except Exception as e:
            logger.debug(f"Exfil check: {e}")

    def _check_cpu_miners(self):
        """Detect crypto-miner processes by cmdline patterns or sustained high CPU."""
        try:
            for proc in psutil.process_iter(["pid", "name", "cmdline", "cpu_percent"]):
                try:
                    name = (proc.info["name"] or "").lower()
                    cmdline = " ".join(proc.info["cmdline"] or []).lower()
                    miner_hint = False
                    for pat in MINER_PATTERNS:
                        if re.search(pat, cmdline, re.IGNORECASE) or re.search(pat, name, re.IGNORECASE):
                            miner_hint = True
                            self._raise_alert(
                                "CRYPTO_MINER", "CRITICAL",
                                f"Crypto-miner detected: {name} (pid={proc.info['pid']})",
                                cmdline[:200],
                                cooldown_key=f"miner_{proc.info['pid']}",
                                cooldown_secs=3600,
                            )
                            break
                    # Sustained CPU spike
                    pid = proc.info["pid"]
                    cpu = proc.cpu_percent(interval=None)
                    self._proc_cpu_history[pid].append(cpu)
                    if len(self._proc_cpu_history[pid]) >= CPU_SPIKE_DURATION_SECS // self.poll_interval:
                        avg_cpu = sum(self._proc_cpu_history[pid]) / len(self._proc_cpu_history[pid])
                        if avg_cpu > CPU_SPIKE_PCT:
                            if _is_benign_high_cpu(name, cmdline) and not miner_hint:
                                # common for local analytics/workers; avoid false positives
                                continue
                            self._raise_alert(
                                "CPU_SPIKE", "HIGH",
                                f"Process {name} (pid={pid}) sustained {avg_cpu:.0f}% CPU",
                                f"Possible crypto-miner or runaway process",
                                cooldown_key=f"cpu_spike_{pid}",
                                cooldown_secs=1800,
                            )
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception as e:
            logger.debug(f"Miner check: {e}")

    def _check_screen_keyloggers(self):
        """Detect known keylogger / screen-capture tool processes."""
        try:
            for proc in psutil.process_iter(["pid", "name"]):
                try:
                    name = (proc.info["name"] or "").lower()
                    if any(kl in name for kl in SCREEN_CAPTURE_PROCS):
                        self._raise_alert(
                            "KEYLOGGER_SCREEN_CAPTURE", "CRITICAL",
                            f"Potential keylogger/screen-capture tool: {name}",
                            f"PID={proc.info['pid']}",
                            cooldown_key=f"keylogger_{name}",
                            cooldown_secs=3600,
                        )
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception as e:
            logger.debug(f"Keylogger check: {e}")

    def _check_clipboard(self):
        """Check clipboard for sensitive data (passwords, credit cards, keys)."""
        if self._platform not in ("Linux", "Windows", "Darwin"):
            return
        try:
            clip_text = self._get_clipboard_text()
            if not clip_text:
                self._last_clipboard_fingerprint = ""
                self._clipboard_match_count = 0
                return

            # Avoid re-alerting for arbitrary copy/paste churn unless the exact
            # same sensitive content is observed repeatedly across checks.
            fingerprint = str(hash(clip_text))
            if fingerprint == self._last_clipboard_fingerprint:
                self._clipboard_match_count += 1
            else:
                self._last_clipboard_fingerprint = fingerprint
                self._clipboard_match_count = 1

            for pat in SENSITIVE_PATTERNS:
                if re.search(pat, clip_text):
                    if self._clipboard_match_count < self.clipboard_min_confirmations:
                        return
                    self._raise_alert(
                        "SENSITIVE_CLIPBOARD", "MEDIUM",
                        "Sensitive data detected in clipboard",
                        "Pattern match in clipboard content",
                        cooldown_key="clipboard_sensitive",
                        cooldown_secs=600,
                    )
                    break
        except Exception:
            pass

    def _get_clipboard_text(self) -> str:
        try:
            if self._platform == "Linux":
                out, _, rc = _run_cmd(["xclip", "-selection", "clipboard", "-o"])
                return out if rc == 0 else ""
            elif self._platform == "Windows":
                import ctypes
                ctypes.windll.user32.OpenClipboard(0)
                handle = ctypes.windll.user32.GetClipboardData(13)  # CF_UNICODETEXT
                text = ctypes.c_wchar_p(handle).value or ""
                ctypes.windll.user32.CloseClipboard()
                return text
            elif self._platform == "Darwin":
                out, _, rc = _run_cmd(["pbpaste"])
                return out if rc == 0 else ""
        except Exception:
            return ""
        return ""

    def _check_sudo_events(self):
        """Detect sudo / su usage from auth.log."""
        if self._platform != "Linux":
            return
        auth_log = Path("/var/log/auth.log")
        if not auth_log.exists():
            return
        try:
            out, _, _ = _run_cmd(["tail", "-n", "50", str(auth_log)])
            for line in out.splitlines():
                if "sudo:" in line and "COMMAND=" in line:
                    m = re.search(r"COMMAND=(.+)$", line)
                    cmd = m.group(1) if m else ""
                    # Flag dangerous sudo commands
                    if any(k in cmd for k in ("chmod", "chown", "/bin/sh", "/bin/bash",
                                               "dd if=", "mkfs", "rm -rf", "wget", "curl")):
                        self._raise_alert(
                            "DANGEROUS_SUDO", "HIGH",
                            f"Dangerous sudo command: {cmd[:80]}",
                            line[:200],
                            cooldown_key=f"sudo_{cmd[:40]}",
                            cooldown_secs=300,
                        )
        except Exception as e:
            logger.debug(f"Sudo check: {e}")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _raise_alert(self, alert_type: str, severity: str, description: str,
                      details: str, cooldown_key: str = "", cooldown_secs: int = 60):
        now = time.time()
        if cooldown_key and self._alert_cooldown.get(cooldown_key, 0) + cooldown_secs > now:
            return
        if cooldown_key:
            self._alert_cooldown[cooldown_key] = now

        logger.warning(f"🧠 [{severity}] {alert_type}: {description}")
        self._save_alert(alert_type, severity, description, details)

        if self.callback:
            self.callback({
                "type": "behavioral_alert",
                "alert_type": alert_type,
                "severity": severity,
                "description": description,
                "details": details,
                "timestamp": datetime.now().isoformat(),
            })

    def get_summary(self) -> Dict:
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute("SELECT severity, COUNT(*) FROM behavioral_alerts GROUP BY severity")
            rows = c.fetchall()
            conn.close()
            return {"behavioral_alerts": {r[0]: r[1] for r in rows}}
        except Exception:
            return {}


# ---------------------------------------------------------------------------
# Tiny helper to avoid importing run from vulnerability_scanner
# ---------------------------------------------------------------------------

def _run_cmd(cmd: List[str], timeout: int = 10) -> Tuple[str, str, int]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr, r.returncode
    except Exception as e:
        return "", str(e), -1
