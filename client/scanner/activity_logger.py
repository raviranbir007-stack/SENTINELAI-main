"""
Activity Logger - Monitors user activity (websites, applications)
Logs all activities for analysis and prevention
"""

import logging
import os
import platform
import re
import sqlite3
import socket
import subprocess
import tempfile
import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from .minimal_cli import MinimalCLI
from .file_scanner import FileScanner

logger = logging.getLogger("ActivityLogger")
logger.setLevel(logging.WARNING)
cli = MinimalCLI()


class ActivityLogger:
    """Monitors and logs user activities (websites visited, applications used)"""

    def __init__(self, db_path: str = "activity_logs.db", callback=None, threat_analyzer=None, os_log_file: Optional[str] = None):
        self.db_path = db_path
        self.callback = callback
        self.threat_analyzer = threat_analyzer  # For background threat analysis
        self.running = False
        self.monitor_thread = None
        
        # Activity tracking
        self.website_history = []
        self.app_history = []
        self.current_apps = set()
        self.last_check_time = time.time()  # Track last check to only get NEW activities
        self.recent_files = {}  # file_path -> last_seen timestamp
        
        # OS log monitoring
        # allow tests or callers to specify a custom log file path
        self.os_log_file = os_log_file or self._detect_os_log_file()
        self._log_fp = None

        # Initialize database
        self._init_database()
        
        # Browser process names by platform
        self.BROWSER_PROCESSES = {
            'firefox', 'firefox.exe', 'firefox-bin',
            'chrome', 'chrome.exe', 'google-chrome',
            'chromium', 'chromium-browser',
            'opera', 'opera.exe',
            'brave', 'brave.exe', 'brave-browser',
            'edge', 'msedge.exe', 'microsoft-edge',
            'safari', 'Safari',
            'vivaldi', 'vivaldi.exe'
        }
        
        # Suspicious patterns
        self.SUSPICIOUS_KEYWORDS = [
            'hack', 'crack', 'exploit', 'malware', 'trojan',
            'ransomware', 'phishing', 'darkweb', 'tor',
            'anonymous', 'vpn-leak', 'password-dump',
            'credit-card', 'ccv', 'fullz', 'dump'
        ]
        
        self.RISKY_DOMAINS = [
            'pastebin.com', 'anonfiles.com', 'mega.nz',
            'tempmail.', 'guerrillamail.', '10minutemail.'
        ]

        self.TRUSTED_TELEMETRY_DOMAINS = {
            'ip-api.com',
            'ipapi.co',
            'ipify.org',
            'api.ipify.org',
            'ifconfig.me',
        }
        self._reverse_dns_cache = {}

        # Chrome/Chromium timestamp origin: microseconds since 1601-01-01
        self._chrome_epoch_offset = 11644473600  # seconds between 1601-01-01 and 1970-01-01

    def _init_database(self):
        """Initialize SQLite database for activity logs"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create websites table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS websites (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    title TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    browser TEXT,
                    risk_level TEXT DEFAULT 'UNKNOWN',
                    is_blocked BOOLEAN DEFAULT 0,
                    analysis TEXT
                )
            ''')
            
            # Create applications table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS applications (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    app_name TEXT NOT NULL,
                    app_path TEXT,
                    pid INTEGER,
                    start_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                    end_time DATETIME,
                    risk_level TEXT DEFAULT 'UNKNOWN',
                    is_blocked BOOLEAN DEFAULT 0,
                    analysis TEXT
                )
            ''')
            
            # Create network connections table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS network_connections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    app_name TEXT,
                    local_addr TEXT,
                    remote_addr TEXT,
                    remote_ip TEXT,
                    remote_port INTEGER,
                    status TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    risk_level TEXT DEFAULT 'UNKNOWN'
                )
            ''')
            
            # Create blocked activities table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS blocked_activities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    activity_type TEXT NOT NULL,
                    target TEXT NOT NULL,
                    reason TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    auto_blocked BOOLEAN DEFAULT 1
                )
            ''')

            # Create file events table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS file_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_path TEXT NOT NULL,
                    app_name TEXT,
                    pid INTEGER,
                    file_hash TEXT,
                    size INTEGER,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    risk_level TEXT DEFAULT 'UNKNOWN',
                    analysis TEXT
                )
            ''')
            
            # Create OS logs table (captures lines read from system log files)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS os_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    message TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Database init failed")

    def _detect_os_log_file(self) -> Optional[str]:
        """Determine an appropriate OS log file to monitor, if available."""
        system = platform.system()
        # prefer syslog on Linux
        if system == "Linux":
            candidates = [
                '/var/log/syslog',
                '/var/log/messages',
                '/var/log/auth.log',
                '/var/log/kern.log'
            ]
            for path in candidates:
                if Path(path).exists():
                    return path
        elif system == "Darwin":
            return '/var/log/system.log' if Path('/var/log/system.log').exists() else None
        # Windows doesn't have a flat file, leave for future implementation
        return None

    def _monitor_os_logs(self):
        """Read new lines from the OS log file and record them."""
        if not self.os_log_file:
            return
        try:
            # Open the file if needed
            if not hasattr(self, '_log_fp') or self._log_fp is None or self._log_fp.closed:
                self._log_fp = open(self.os_log_file, 'r', encoding='utf-8', errors='ignore')
                # seek to end so we only get new entries
                self._log_fp.seek(0, os.SEEK_END)
            # read any new lines
            line = self._log_fp.readline()
            if line:
                logger.debug(f"OS log: {line.strip()}")
                # store in database
                try:
                    conn = sqlite3.connect(self.db_path)
                    cursor = conn.cursor()
                    cursor.execute("INSERT INTO os_logs (message) VALUES (?)", (line.strip(),))
                    conn.commit()
                    conn.close()
                except Exception as db_e:
                    logger.error(f"Failed to write os log to db: {db_e}")
                if self.callback:
                    self.callback({
                        'type': 'os_log',
                        'message': line.strip(),
                        'timestamp': datetime.now().isoformat()
                    })
        except Exception as e:
            logger.error(f"Failed to read OS log: {e}")

    def start(self):
        """Start activity monitoring"""
        if not self.running:
            self.running = True
            self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.monitor_thread.start()

    def stop(self):
        """Stop activity monitoring"""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)

    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.running:
            try:
                # Monitor running applications
                self._monitor_applications()

                # Monitor opened files
                self._monitor_open_files()
                
                # Monitor network connections (for browser activity)
                self._monitor_network_connections()
                
                # Monitor browser history (platform-specific)
                self._monitor_browser_activity()
                
                # Monitor OS/system logs if available
                self._monitor_os_logs()
                
                # Update last check time
                self.last_check_time = time.time()
                
                time.sleep(2)  # Faster checks for more responsive detection
                
            except Exception as e:
                logger.debug(f"Monitor loop error")
                time.sleep(2)

    def _monitor_applications(self):
        """Monitor running applications (filtered to important ones only)"""
        try:
            import psutil
            
            current_processes = set()
            new_apps_detected = []
            
            # Kernel workers and system processes to ignore (reduce noise)
            IGNORE_PATTERNS = [
                'kworker', 'ksoftirqd', 'kthreadd', 'kdevtmpfs', 'kauditd',
                'khungtaskd', 'oom_reaper', 'kcompactd', 'ksmd', 'khugepaged',
                'kswapd', 'kdamond', 'kstrp', 'irq/', 'rcu_', 'migration/',
                'cpuhp/', 'idle_inject/', 'scsi_eh_', 'jbd2/', 'systemd-userwork',
                'pool_workqueue', 'kvfree', 'slub_', 'netns', 'mm_percpu',
                'inet_frag', 'kblockd', 'blkcg', 'kintegrityd', 'tpm_dev',
                'edac-poller', 'devfreq', 'quota_events', 'kthrotld', 'acpi_thermal',
                'mld', 'ipv6_addrconf', 'ata_sff', 'scsi_tmf', 'ttm', 'ext4-rsv',
                'rpciod', 'xprtiod', 'writeback', 'VBoxClient', 'VBoxService',
                'VBoxDRMClient', 'systemd-journald', 'systemd-udevd', 'systemd-userdbd',
                'systemd-logind', 'dbus-daemon', 'at-spi', 'gvfsd', 'wrapper-2.0',
                'xfconfd', 'polkitd', 'accounts-daemon', 'rtkit-daemon', 'upowerd',
                'colord', 'psimon', 'ModemManager', 'NetworkManager'
            ]
            
            # Important applications to always log
            IMPORTANT_APPS = [
                'firefox', 'chrome', 'chromium', 'brave', 'opera', 'edge',
                'nmap', 'masscan', 'hydra', 'metasploit', 'burp', 'wireshark',
                'tcpdump', 'sqlmap', 'nikto', 'netcat', 'nc', 'ssh', 'telnet',
                'python', 'bash', 'sh', 'zsh' # Only if executing scripts
            ]
            
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'create_time', 'username']):
                try:
                    pinfo = proc.info
                    proc_name = pinfo['name']
                    proc_id = f"{proc_name}_{pinfo['pid']}"
                    
                    # Skip if process should be ignored
                    should_ignore = any(pattern in proc_name for pattern in IGNORE_PATTERNS)
                    if should_ignore:
                        continue
                    
                    # Skip if PID < 1000 (usually system processes)
                    if pinfo['pid'] < 1000:
                        continue
                    
                    current_processes.add(proc_id)
                    
                    # New application started
                    if proc_id not in self.current_apps:
                        # Only log if it's important (security tools)
                        is_important = any(app in proc_name.lower() for app in IMPORTANT_APPS)
                        
                        # Only log important security-critical applications
                        if is_important:
                            app_info = {
                                'app_name': proc_name,
                                'app_path': pinfo.get('exe', 'Unknown'),
                                'pid': pinfo['pid'],
                                'start_time': datetime.fromtimestamp(pinfo['create_time'])
                            }
                            self._log_application(**app_info)
                            new_apps_detected.append(app_info)
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
                except Exception as e:
                    logger.debug(f"Error processing process: {e}")
                    continue
            
            # Callback for new apps
            if new_apps_detected and self.callback:
                for app in new_apps_detected:
                    self.callback({
                        'type': 'APPLICATION_STARTED',
                        'data': app,
                        'timestamp': datetime.now().isoformat()
                    })
            
            # Update current apps
            self.current_apps = current_processes
            
        except Exception as e:
            logger.debug(f"Monitor app error")

    def _monitor_network_connections(self):
        """Monitor network connections to detect web activity"""
        try:
            import psutil
            
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    try:
                        # Get process info
                        proc = psutil.Process(conn.pid) if conn.pid else None
                        proc_name = proc.name() if proc else 'Unknown'
                        
                        # Check if it's a browser
                        if proc_name.lower() in [b.lower() for b in self.BROWSER_PROCESSES]:
                            self._log_network_connection(
                                app_name=proc_name,
                                local_addr=f"{conn.laddr.ip}:{conn.laddr.port}",
                                remote_addr=f"{conn.raddr.ip}:{conn.raddr.port}",
                                remote_ip=conn.raddr.ip,
                                remote_port=conn.raddr.port,
                                status=conn.status
                            )
                            
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                        
        except Exception as e:
            logger.debug(f"Monitor network error")

    def _monitor_open_files(self):
        """Monitor file open events and queue hash scans"""
        try:
            import psutil

            now = time.time()
            # prune old entries to avoid growth
            self.recent_files = {
                path: ts for path, ts in self.recent_files.items() if now - ts < 600
            }

            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    files = proc.open_files()
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
                except Exception:
                    continue

                if not files:
                    continue

                for f in files:
                    file_path = f.path
                    if not file_path or not os.path.isfile(file_path):
                        continue

                    if file_path.startswith(('/proc', '/sys', '/dev')):
                        continue

                    # Avoid duplicate logging
                    last_seen = self.recent_files.get(file_path)
                    if last_seen and now - last_seen < 120:
                        continue

                    self.recent_files[file_path] = now
                    self._log_file_access(
                        file_path=file_path,
                        app_name=proc.info.get('name', 'Unknown'),
                        pid=proc.info.get('pid')
                    )

        except Exception:
            logger.debug("Monitor file error")

    def _monitor_browser_activity(self):
        """Monitor browser activity (platform-specific)"""
        system = platform.system()
        
        try:
            if system == "Linux":
                self._monitor_linux_browser()
            elif system == "Windows":
                self._monitor_windows_browser()
            elif system == "Darwin":  # macOS
                self._monitor_macos_browser()
                
        except Exception as e:
            logger.debug(f"Browser monitor error")

    def _monitor_linux_browser(self):
        """Monitor browser activity on Linux"""
        for engine, browser_name, history_path in self._discover_browser_targets("Linux"):
            if engine == "firefox":
                self._parse_firefox_history(history_path)
            elif engine == "chromium":
                self._parse_chrome_history(history_path, browser_name)

    def _get_active_user_home(self) -> Path:
        """Get the real user home when running with sudo/root"""
        try:
            if os.geteuid() == 0:
                sudo_user = os.environ.get("SUDO_USER") or os.environ.get("USER")
                if sudo_user and sudo_user != "root":
                    return Path("/home") / sudo_user
        except Exception:
            pass
        return Path.home()

    def _monitor_windows_browser(self):
        """Monitor browser activity on Windows"""
        for engine, browser_name, history_path in self._discover_browser_targets("Windows"):
            if engine == "firefox":
                self._parse_firefox_history(history_path)
            elif engine == "chromium":
                self._parse_chrome_history(history_path, browser_name)

    def _monitor_macos_browser(self):
        """Monitor browser activity on macOS"""
        for engine, browser_name, history_path in self._discover_browser_targets("Darwin"):
            if engine == "firefox":
                self._parse_firefox_history(history_path)
            elif engine == "chromium":
                self._parse_chrome_history(history_path, browser_name)
            elif engine == "safari":
                self._parse_safari_history(history_path)

    def _discover_browser_targets(self, system_name: str) -> List[Tuple[str, str, Path]]:
        """Discover browser history targets as tuples of (engine, browser_name, path)."""
        targets: List[Tuple[str, str, Path]] = []

        if system_name == "Linux":
            home = self._get_active_user_home()

            # Firefox-style profile directories
            firefox_dirs = [
                home / ".mozilla/firefox",
                home / "snap/firefox/common/.mozilla/firefox",
            ]
            for ff_dir in firefox_dirs:
                if ff_dir.exists():
                    targets.append(("firefox", "Firefox", ff_dir))

            chromium_roots = {
                "Chrome": [
                    home / ".config/google-chrome",
                    home / "snap/google-chrome/common/.config/google-chrome",
                ],
                "Chromium": [
                    home / ".config/chromium",
                    home / "snap/chromium/common/chromium",
                ],
                "Brave": [
                    home / ".config/BraveSoftware/Brave-Browser",
                ],
                "Edge": [
                    home / ".config/microsoft-edge",
                ],
                "Opera": [
                    home / ".config/opera",
                    home / ".config/opera-beta",
                    home / ".config/opera-developer",
                ],
                "Vivaldi": [
                    home / ".config/vivaldi",
                ],
                "Yandex": [
                    home / ".config/yandex-browser",
                ],
            }

            for browser_name, roots in chromium_roots.items():
                for root in roots:
                    for history_db in self._discover_chromium_history_files(root):
                        targets.append(("chromium", browser_name, history_db))

        elif system_name == "Windows":
            user_profile = os.environ.get('USERPROFILE', '')
            if not user_profile:
                return targets

            home = Path(user_profile)
            firefox_dirs = [
                home / "AppData/Roaming/Mozilla/Firefox/Profiles",
            ]
            for ff_dir in firefox_dirs:
                if ff_dir.exists():
                    targets.append(("firefox", "Firefox", ff_dir))

            chromium_roots = {
                "Chrome": [home / "AppData/Local/Google/Chrome/User Data"],
                "Edge": [home / "AppData/Local/Microsoft/Edge/User Data"],
                "Brave": [home / "AppData/Local/BraveSoftware/Brave-Browser/User Data"],
                "Chromium": [home / "AppData/Local/Chromium/User Data"],
                "Opera": [home / "AppData/Roaming/Opera Software/Opera Stable"],
                "OperaGX": [home / "AppData/Roaming/Opera Software/Opera GX Stable"],
                "Vivaldi": [home / "AppData/Local/Vivaldi/User Data"],
            }

            for browser_name, roots in chromium_roots.items():
                for root in roots:
                    for history_db in self._discover_chromium_history_files(root):
                        targets.append(("chromium", browser_name, history_db))

        elif system_name == "Darwin":
            home = Path.home()

            firefox_dirs = [home / "Library/Application Support/Firefox/Profiles"]
            for ff_dir in firefox_dirs:
                if ff_dir.exists():
                    targets.append(("firefox", "Firefox", ff_dir))

            safari_history = home / "Library/Safari/History.db"
            if safari_history.exists():
                targets.append(("safari", "Safari", safari_history))

            chromium_roots = {
                "Chrome": [home / "Library/Application Support/Google/Chrome"],
                "Chromium": [home / "Library/Application Support/Chromium"],
                "Edge": [home / "Library/Application Support/Microsoft Edge"],
                "Brave": [home / "Library/Application Support/BraveSoftware/Brave-Browser"],
                "Opera": [home / "Library/Application Support/com.operasoftware.Opera"],
                "Vivaldi": [home / "Library/Application Support/Vivaldi"],
                "Arc": [home / "Library/Application Support/Arc/User Data"],
            }

            for browser_name, roots in chromium_roots.items():
                for root in roots:
                    for history_db in self._discover_chromium_history_files(root):
                        targets.append(("chromium", browser_name, history_db))

        # Deduplicate
        deduped = []
        seen = set()
        for engine, browser_name, path in targets:
            key = (engine, browser_name, str(path))
            if key in seen:
                continue
            seen.add(key)
            deduped.append((engine, browser_name, path))

        return deduped

    def _discover_chromium_history_files(self, root: Path) -> List[Path]:
        """Discover Chromium-style history DB files for any available profile."""
        if not root.exists():
            return []

        history_files = []

        # Some roots may already point to a concrete History DB file
        if root.is_file() and root.name == "History":
            return [root]

        # Root could itself be a profile folder (e.g. Opera Stable)
        direct_history = root / "History"
        if direct_history.exists():
            history_files.append(direct_history)

        # Common Chromium profile naming conventions
        for child in root.iterdir():
            if not child.is_dir():
                continue
            name = child.name
            if name == "Default" or name.startswith("Profile ") or "Profile" in name or name.endswith(" Stable"):
                history_path = child / "History"
                if history_path.exists():
                    history_files.append(history_path)

        # Deduplicate while preserving order
        deduped = []
        seen = set()
        for path in history_files:
            key = str(path)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(path)

        return deduped

    def _parse_chrome_history(self, history_path: Path, browser_name: str = "Chrome/Chromium"):
        """Parse Chrome/Chromium history database"""
        try:
            # Copy database to avoid lock issues
            import shutil
            profile_tag = history_path.parent.name.replace(" ", "_")
            browser_tag = re.sub(r'[^a-zA-Z0-9_-]+', '_', browser_name.lower())
            temp_file = tempfile.NamedTemporaryFile(
                prefix=f"{browser_tag}_history_{os.getpid()}_{profile_tag}_",
                suffix=".db",
                delete=False,
            )
            temp_db = temp_file.name
            temp_file.close()
            shutil.copy2(history_path, temp_db)
            
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            
            # Get ONLY NEW URLs since last check (Chrome uses 1601 epoch in microseconds)
            last_check_microsec = self._chrome_time_from_unix(self.last_check_time)
            cursor.execute('''
                SELECT url, title, last_visit_time
                FROM urls
                WHERE last_visit_time > ?
                AND url LIKE 'http%'
                ORDER BY last_visit_time DESC
                LIMIT 50
            ''', (last_check_microsec,))
            
            rows = cursor.fetchall()
            # Fallback: if no rows, try last 5 minutes window (clock drift or epoch issues)
            if not rows:
                five_min_ago = time.time() - 300
                fallback_microsec = self._chrome_time_from_unix(five_min_ago)
                cursor.execute('''
                    SELECT url, title, last_visit_time
                    FROM urls
                    WHERE last_visit_time > ?
                    AND url LIKE 'http%'
                    ORDER BY last_visit_time DESC
                    LIMIT 50
                ''', (fallback_microsec,))
                rows = cursor.fetchall()

            for row in rows:
                url, title, visit_time = row
                self._log_website(url, title, browser_name)
            
            conn.close()
            os.remove(temp_db)
            
        except Exception as e:
            logger.debug(f"Chrome history parse error")

    def _chrome_time_from_unix(self, unix_time: float) -> int:
        """Convert Unix epoch seconds to Chrome/Chromium microseconds since 1601-01-01"""
        try:
            return int((unix_time + self._chrome_epoch_offset) * 1_000_000)
        except Exception:
            return 0

    def _parse_firefox_history(self, firefox_dir: Path):
        """Parse Firefox history database"""
        try:
            # Find default profile
            profiles = list(firefox_dir.glob("*.default*"))
            if not profiles:
                return

            for profile in profiles:
                history_db = profile / "places.sqlite"
                if not history_db.exists():
                    continue

                # Copy database to avoid lock issues
                import shutil
                profile_tag = profile.name.replace(" ", "_")
                temp_db = f"/tmp/firefox_history_{os.getpid()}_{profile_tag}.db"
                shutil.copy2(history_db, temp_db)

                conn = sqlite3.connect(temp_db)
                cursor = conn.cursor()

                # Get ONLY NEW URLs since last check
                last_check_microsec = int(self.last_check_time * 1000000)
                cursor.execute('''
                    SELECT url, title, last_visit_date
                    FROM moz_places
                    WHERE last_visit_date > ?
                    AND url LIKE 'http%'
                    ORDER BY last_visit_date DESC
                    LIMIT 50
                ''', (last_check_microsec,))

                for row in cursor.fetchall():
                    url, title, visit_time = row
                    self._log_website(url, title, 'Firefox')

                conn.close()
                os.remove(temp_db)
            
        except Exception as e:
            logger.debug(f"Firefox history parse error")

    def _parse_safari_history(self, history_path: Path):
        """Parse Safari history database"""
        try:
            import shutil
            temp_db = f"/tmp/safari_history_{os.getpid()}.db"
            shutil.copy2(history_path, temp_db)
            
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT url, title, visit_time
                FROM history_visits
                JOIN history_items ON history_visits.history_item = history_items.id
                WHERE visit_time > ?
                ORDER BY visit_time DESC
                LIMIT 100
            ''', (time.time() - 600,))
            
            for row in cursor.fetchall():
                url, title, visit_time = row
                self._log_website(url, title, 'Safari')
            
            conn.close()
            os.remove(temp_db)
            
        except Exception as e:
            logger.debug(f"Safari history parse error")

    def _log_website(self, url: str, title: Optional[str], browser: str):
        """Log website visit and queue for threat analysis"""
        try:
            if self._is_recently_logged('website', url):
                return
            parsed = urlparse(url)
            domain = parsed.netloc or parsed.path.split('/')[0]
            
            # Skip empty domains
            if not domain:
                return
            
            # Save to database
            try:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO websites (url, domain, title, browser)
                    VALUES (?, ?, ?, ?)
                ''', (url[:2048], domain[:255], title[:255] if title else None, browser))
                
                conn.commit()
                conn.close()
            except Exception as db_e:
                logger.debug(f"Website DB log failed")
                return
            
            # Queue for threat analysis
            if self.threat_analyzer:
                self.threat_analyzer.queue_scan(
                    artifact_type='url',
                    artifact_value=url,
                    metadata={'domain': domain, 'browser': browser}
                )
            
            # Log to console (one-line format)
            cli.prompt_website(domain)
            
        except Exception as e:
            logger.debug(f"Website log failed")

    def _log_file_access(self, file_path: str, app_name: str, pid: int):
        """Log file access and queue hash scan"""
        try:
            if self._is_recently_logged('file', file_path):
                return

            file_hash = None
            size = None
            risk_level = 'UNKNOWN'

            try:
                size = os.path.getsize(file_path)
                # Skip hashing very large files (>20MB)
                if size <= 20 * 1024 * 1024:
                    file_hash = FileScanner.calculate_hash(file_path)
            except Exception:
                pass

            # Save to database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO file_events (file_path, app_name, pid, file_hash, size, risk_level)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (file_path[:2048], app_name[:255] if app_name else None, pid, file_hash, size, risk_level))
            conn.commit()
            conn.close()

            # Queue hash for threat analysis if available
            if self.threat_analyzer and file_hash:
                self.threat_analyzer.queue_scan(
                    artifact_type='file',
                    artifact_value=file_hash,
                    metadata={'file_path': file_path, 'app': app_name}
                )

            # Notify
            if self.callback:
                self.callback({
                    'type': 'FILE_OPENED',
                    'file_path': file_path,
                    'app_name': app_name,
                    'pid': pid,
                    'timestamp': datetime.now().isoformat()
                })

        except Exception as e:
            logger.debug("File log failed")

    def _log_application(self, app_name: str, app_path: str, pid: int, start_time: datetime):
        """Log application usage"""
        try:
            # Check if already logged
            if self._is_recently_logged('app', f"{app_name}_{pid}"):
                return
            
            # Analyze risk
            risk_level = self._analyze_app_risk(app_name, app_path)
            
            # Save to database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO applications (app_name, app_path, pid, start_time, risk_level)
                VALUES (?, ?, ?, ?, ?)
            ''', (app_name, app_path, pid, start_time, risk_level))
            
            conn.commit()
            conn.close()
            
            # Log all applications
            if risk_level in ['HIGH', 'CRITICAL']:
                logger.warning(f"⚠️  Suspicious app started: {app_name} ({risk_level})")
            else:
                logger.info(f"📱 App started: {app_name}")
            
        except Exception as e:
            logger.error(f"Error logging application: {e}")

    def _log_network_connection(self, app_name: str, local_addr: str, 
                               remote_addr: str, remote_ip: str, 
                               remote_port: int, status: str):
        """Log network connection and queue for threat analysis"""
        try:
            # Save to database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO network_connections 
                (app_name, local_addr, remote_addr, remote_ip, remote_port, status)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (app_name, local_addr, remote_addr, remote_ip, remote_port, status))
            
            conn.commit()
            conn.close()

            remote_domain = self._reverse_lookup_domain(remote_ip)

            if self._is_trusted_telemetry_domain(remote_domain):
                return
            
            # Queue IP for threat analysis
            if self.threat_analyzer:
                self.threat_analyzer.queue_scan(
                    artifact_type='ip',
                    artifact_value=remote_ip,
                    metadata={'app': app_name, 'port': remote_port, 'remote_domain': remote_domain}
                )
            
        except Exception as e:
            logger.debug(f"Network log failed")

    def _reverse_lookup_domain(self, remote_ip: str) -> str:
        cached = self._reverse_dns_cache.get(remote_ip)
        if cached is not None:
            return cached
        try:
            host, *_ = socket.gethostbyaddr(remote_ip)
            normalized = str(host or '').strip().lower().rstrip('.')
        except Exception:
            normalized = ''
        self._reverse_dns_cache[remote_ip] = normalized
        return normalized

    def _is_trusted_telemetry_domain(self, domain: str) -> bool:
        normalized = str(domain or '').strip().lower().rstrip('.')
        if not normalized:
            return False
        return any(
            normalized == trusted or normalized.endswith(f'.{trusted}')
            for trusted in self.TRUSTED_TELEMETRY_DOMAINS
        )

    def _analyze_website_risk(self, url: str, domain: str) -> str:
        """Analyze website risk level"""
        url_lower = url.lower()
        domain_lower = domain.lower()
        
        # Check for suspicious keywords
        for keyword in self.SUSPICIOUS_KEYWORDS:
            if keyword in url_lower or keyword in domain_lower:
                return 'HIGH'
        
        # Check for risky domains
        for risky_domain in self.RISKY_DOMAINS:
            if risky_domain in domain_lower:
                return 'MEDIUM'
        
        # Check for HTTP (insecure)
        if url.startswith('http://'):
            return 'LOW'
        
        return 'SAFE'

    def _analyze_app_risk(self, app_name: str, app_path: str) -> str:
        """Analyze application risk level"""
        app_lower = app_name.lower()
        path_lower = app_path.lower() if app_path else ''
        
        # Check for suspicious app names
        for keyword in self.SUSPICIOUS_KEYWORDS:
            if keyword in app_lower or keyword in path_lower:
                return 'HIGH'
        
        # Check for system locations (usually safe)
        if any(loc in path_lower for loc in ['/usr/', '/bin/', 'c:\\windows\\', 'c:\\program files\\']):
            return 'SAFE'
        
        # Check for temporary/download locations (risky)
        if any(loc in path_lower for loc in ['/tmp/', '/temp/', 'downloads', 'desktop']):
            return 'MEDIUM'
        
        return 'UNKNOWN'

    def _analyze_connection_risk(self, remote_ip: str, remote_port: int) -> str:
        """Analyze network connection risk"""
        # Common malicious ports
        MALICIOUS_PORTS = [4444, 5555, 6666, 7777, 8888, 31337, 12345]
        
        if remote_port in MALICIOUS_PORTS:
            return 'HIGH'
        
        # Private IP ranges (usually safe)
        if remote_ip.startswith(('192.168.', '10.', '172.16.')):
            return 'SAFE'
        
        return 'UNKNOWN'

    def _is_recently_logged(self, activity_type: str, identifier: str, minutes: int = 2) -> bool:
        """Check if activity was recently logged (prevents duplicate prompts)"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cutoff_time = datetime.now() - timedelta(minutes=minutes)
            
            if activity_type == 'website':
                cursor.execute('''
                    SELECT COUNT(*) FROM websites 
                    WHERE url = ? AND timestamp > ?
                ''', (identifier, cutoff_time))
            elif activity_type == 'app':
                app_name, pid = identifier.split('_')
                cursor.execute('''
                    SELECT COUNT(*) FROM applications 
                    WHERE app_name = ? AND pid = ? AND start_time > ?
                ''', (app_name, pid, cutoff_time))
            elif activity_type == 'file':
                cursor.execute('''
                    SELECT COUNT(*) FROM file_events
                    WHERE file_path = ? AND timestamp > ?
                ''', (identifier, cutoff_time))
            
            count = cursor.fetchone()[0]
            conn.close()
            
            return count > 0
            
        except Exception as e:
            logger.debug(f"Error checking recent logs: {e}")
            return False

    def get_recent_activities(self, hours: int = 24) -> Dict:
        """Get recent activities"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cutoff_time = datetime.now() - timedelta(hours=hours)
            
            # Get websites
            cursor.execute('''
                SELECT url, domain, browser, risk_level, timestamp
                FROM websites
                WHERE timestamp > ?
                ORDER BY timestamp DESC
                LIMIT 100
            ''', (cutoff_time,))
            websites = cursor.fetchall()
            
            # Get applications
            cursor.execute('''
                SELECT app_name, app_path, risk_level, start_time
                FROM applications
                WHERE start_time > ?
                ORDER BY start_time DESC
                LIMIT 100
            ''', (cutoff_time,))
            applications = cursor.fetchall()
            
            # Get blocked activities
            cursor.execute('''
                SELECT activity_type, target, reason, timestamp
                FROM blocked_activities
                WHERE timestamp > ?
                ORDER BY timestamp DESC
            ''', (cutoff_time,))
            blocked = cursor.fetchall()
            
            conn.close()
            
            return {
                'websites': websites,
                'applications': applications,
                'blocked': blocked
            }
            
        except Exception as e:
            logger.error(f"Error getting recent activities: {e}")
            return {'websites': [], 'applications': [], 'blocked': []}

    def block_activity(self, activity_type: str, target: str, reason: str):
        """Block an activity"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO blocked_activities (activity_type, target, reason)
                VALUES (?, ?, ?)
            ''', (activity_type, target, reason))
            
            conn.commit()
            conn.close()
            
            logger.warning(f"Blocked {activity_type}: {target} - {reason}")
            
        except Exception as e:
            logger.error(f"Error blocking activity: {e}")
