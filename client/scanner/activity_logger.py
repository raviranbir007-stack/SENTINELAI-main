"""
Activity Logger - Monitors user activity (websites, applications)
Logs all activities for analysis and prevention
"""

import logging
import os
import platform
import re
import sqlite3
import subprocess
import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger("ActivityLogger")


class ActivityLogger:
    """Monitors and logs user activities (websites visited, applications used)"""

    def __init__(self, db_path: str = "activity_logs.db", callback=None):
        self.db_path = db_path
        self.callback = callback
        self.running = False
        self.monitor_thread = None
        
        # Activity tracking
        self.website_history = []
        self.app_history = []
        self.current_apps = set()
        self.last_check_time = time.time()  # Track last check to only get NEW activities
        
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
            
            conn.commit()
            conn.close()
            logger.info("Activity logging database initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")

    def start(self):
        """Start activity monitoring"""
        if not self.running:
            self.running = True
            self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.monitor_thread.start()
            logger.info("📊 Activity Logger started")

    def stop(self):
        """Stop activity monitoring"""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        logger.info("Activity Logger stopped")

    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.running:
            try:
                # Monitor running applications
                self._monitor_applications()
                
                # Monitor network connections (for browser activity)
                self._monitor_network_connections()
                
                # Monitor browser history (platform-specific)
                self._monitor_browser_activity()
                
                # Update last check time
                self.last_check_time = time.time()
                
                time.sleep(10)  # Check every 10 seconds - balanced monitoring
                
            except Exception as e:
                logger.error(f"Error in activity monitoring loop: {e}")
                time.sleep(10)

    def _monitor_applications(self):
        """Monitor running applications"""
        try:
            import psutil
            
            current_processes = set()
            
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'create_time']):
                try:
                    pinfo = proc.info
                    proc_name = pinfo['name']
                    proc_id = f"{proc_name}_{pinfo['pid']}"
                    
                    current_processes.add(proc_id)
                    
                    # New application started
                    if proc_id not in self.current_apps:
                        self._log_application(
                            app_name=proc_name,
                            app_path=pinfo.get('exe', 'Unknown'),
                            pid=pinfo['pid'],
                            start_time=datetime.fromtimestamp(pinfo['create_time'])
                        )
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Update current apps
            self.current_apps = current_processes
            
        except Exception as e:
            logger.error(f"Error monitoring applications: {e}")

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
            logger.error(f"Error monitoring network connections: {e}")

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
            logger.error(f"Error monitoring browser activity: {e}")

    def _monitor_linux_browser(self):
        """Monitor browser activity on Linux"""
        # Check Firefox history
        firefox_history = Path.home() / ".mozilla/firefox"
        if firefox_history.exists():
            self._parse_firefox_history(firefox_history)
        
        # Check Chrome history
        chrome_history = Path.home() / ".config/google-chrome/Default/History"
        if chrome_history.exists():
            self._parse_chrome_history(chrome_history)
        
        # Check Chromium history
        chromium_history = Path.home() / ".config/chromium/Default/History"
        if chromium_history.exists():
            self._parse_chrome_history(chromium_history)

    def _monitor_windows_browser(self):
        """Monitor browser activity on Windows"""
        user_profile = os.environ.get('USERPROFILE', '')
        
        # Chrome history
        chrome_path = Path(user_profile) / "AppData/Local/Google/Chrome/User Data/Default/History"
        if chrome_path.exists():
            self._parse_chrome_history(chrome_path)
        
        # Edge history
        edge_path = Path(user_profile) / "AppData/Local/Microsoft/Edge/User Data/Default/History"
        if edge_path.exists():
            self._parse_chrome_history(edge_path)

    def _monitor_macos_browser(self):
        """Monitor browser activity on macOS"""
        home = Path.home()
        
        # Safari history
        safari_history = home / "Library/Safari/History.db"
        if safari_history.exists():
            self._parse_safari_history(safari_history)
        
        # Chrome history
        chrome_history = home / "Library/Application Support/Google/Chrome/Default/History"
        if chrome_history.exists():
            self._parse_chrome_history(chrome_history)

    def _parse_chrome_history(self, history_path: Path):
        """Parse Chrome/Chromium history database"""
        try:
            # Copy database to avoid lock issues
            import shutil
            temp_db = f"/tmp/chrome_history_{os.getpid()}.db"
            shutil.copy2(history_path, temp_db)
            
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            
            # Get ONLY NEW URLs since last check (not last 10 minutes!)
            last_check_microsec = int(self.last_check_time * 1000000)
            cursor.execute('''
                SELECT url, title, last_visit_time
                FROM urls
                WHERE last_visit_time > ?
                ORDER BY last_visit_time DESC
                LIMIT 50
            ''', (last_check_microsec,))
            
            for row in cursor.fetchall():
                url, title, visit_time = row
                self._log_website(url, title, 'Chrome/Chromium')
            
            conn.close()
            os.remove(temp_db)
            
        except Exception as e:
            logger.debug(f"Error parsing Chrome history: {e}")

    def _parse_firefox_history(self, firefox_dir: Path):
        """Parse Firefox history database"""
        try:
            # Find default profile
            profiles = list(firefox_dir.glob("*.default*"))
            if not profiles:
                return
            
            history_db = profiles[0] / "places.sqlite"
            if not history_db.exists():
                return
            
            # Copy database to avoid lock issues
            import shutil
            temp_db = f"/tmp/firefox_history_{os.getpid()}.db"
            shutil.copy2(history_db, temp_db)
            
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            
            # Get ONLY NEW URLs since last check
            last_check_microsec = int(self.last_check_time * 1000000)
            cursor.execute('''
                SELECT url, title, last_visit_date
                FROM moz_places
                WHERE last_visit_date > ?
                ORDER BY last_visit_date DESC
                LIMIT 50
            ''', (last_check_microsec,))
            
            for row in cursor.fetchall():
                url, title, visit_time = row
                self._log_website(url, title, 'Firefox')
            
            conn.close()
            os.remove(temp_db)
            
        except Exception as e:
            logger.debug(f"Error parsing Firefox history: {e}")

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
            logger.debug(f"Error parsing Safari history: {e}")

    def _log_website(self, url: str, title: Optional[str], browser: str):
        """Log website visit"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc or parsed.path.split('/')[0]
            
            # Check if already logged recently (avoid duplicates)
            if self._is_recently_logged('website', url):
                return
            
            # Analyze risk
            risk_level = self._analyze_website_risk(url, domain)
            
            # Save to database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO websites (url, domain, title, browser, risk_level)
                VALUES (?, ?, ?, ?, ?)
            ''', (url, domain, title, browser, risk_level))
            
            conn.commit()
            conn.close()
            
            # Notify if callback is set
            if self.callback and risk_level in ['HIGH', 'CRITICAL']:
                self.callback({
                    'type': 'RISKY_WEBSITE',
                    'url': url,
                    'domain': domain,
                    'risk_level': risk_level,
                    'browser': browser,
                    'timestamp': datetime.now()
                })
            
            # Log all activities with appropriate level
            if risk_level in ['HIGH', 'CRITICAL']:
                logger.warning(f"⚠️  Risky website: {domain} [{browser}] - {risk_level}")
            else:
                logger.info(f"🌐 Website visited: {domain} [{browser}]")
            
        except Exception as e:
            logger.error(f"Error logging website: {e}")

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
        """Log network connection"""
        try:
            # Analyze risk
            risk_level = self._analyze_connection_risk(remote_ip, remote_port)
            
            # Save to database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO network_connections 
                (app_name, local_addr, remote_addr, remote_ip, remote_port, status, risk_level)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (app_name, local_addr, remote_addr, remote_ip, remote_port, status, risk_level))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.debug(f"Error logging network connection: {e}")

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
