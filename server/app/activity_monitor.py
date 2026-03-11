"""
Real-time Activity Monitor - Integrated with Server
Tracks all user activities and displays in server terminal
"""

import asyncio
import ipaddress
import sqlite3
import psutil
import shutil
import os
import logging
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any
from urllib.parse import urlparse

from app.services.virus_total import VirusTotalService
from app.services.abuseipdb import AbuseIPDBService
from app.services.urlscan import URLScanService
from app.services.shodan import ShodanService
from app.services.hybrid_analysis import HybridAnalysisService
from app.gemini_integration import get_gemini_client

logger = logging.getLogger(__name__)

class ActivityMonitor:
    """Real-time activity monitoring with AI analysis"""
    
    def __init__(self):
        # determine which HOME to monitor (handle sudo)
        real_user = os.getenv('SUDO_USER') or os.getenv('USER')
        if real_user and os.geteuid() == 0:
            # running as root via sudo, monitor the invoking user's home
            self.user_home = Path('/home') / real_user
            if not self.user_home.exists():
                # fallback to root home
                self.user_home = Path.home()
        else:
            self.user_home = Path.home()
        logger.info(f"ActivityMonitor will use home directory: {self.user_home}")

        self.db_path = Path(__file__).parent.parent.parent / "client" / "activity_logs.db"
        self.running = False
        self.blocked_domains = set()
        self.blocked_ips = set()
        
        # Initialize threat intelligence services
        self.vt_service = VirusTotalService()
        self.abuseipdb_service = AbuseIPDBService()
        self.urlscan_service = URLScanService()
        self.shodan_service = ShodanService()
        self.hybrid_service = HybridAnalysisService()
        
        # Browser history paths - Support ALL major browsers with comprehensive paths
        self.firefox_paths = [
            self.user_home / ".mozilla" / "firefox",
            self.user_home / "snap" / "firefox" / "common" / ".mozilla" / "firefox",
            Path("/usr/lib/firefox"),  # System Firefox
            Path("/usr/lib/firefox-esr"),  # Firefox ESR
        ]
        
        # Chrome-based browsers - Comprehensive path list
        self.chrome_based_browsers = {
            'Chrome': [
                self.user_home / ".config" / "google-chrome" / "Default" / "History",
                self.user_home / ".config" / "google-chrome" / "Profile 1" / "History",
                self.user_home / "snap" / "google-chrome" / "common" / ".config" / "google-chrome" / "Default" / "History",
            ],
            'Chromium': [
                self.user_home / ".config" / "chromium" / "Default" / "History",
                self.user_home / ".config" / "chromium" / "Profile 1" / "History",
                self.user_home / "snap" / "chromium" / "common" / ".config" / "chromium" / "Default" / "History",
            ],
            'Brave': [
                self.user_home / ".config" / "BraveSoftware" / "Brave-Browser" / "Default" / "History",
                self.user_home / ".config" / "BraveSoftware" / "Brave-Browser" / "Profile 1" / "History",
            ],
            'Edge': [
                self.user_home / ".config" / "microsoft-edge" / "Default" / "History",
                self.user_home / ".config" / "microsoft-edge" / "Profile 1" / "History",
            ],
            'Opera': [
                self.user_home / ".config" / "opera" / "Default" / "History",
                self.user_home / ".config" / "opera" / "Profile 1" / "History",
            ],
            'Vivaldi': [
                self.user_home / ".config" / "vivaldi" / "Default" / "History",
                self.user_home / ".config" / "vivaldi" / "Profile 1" / "History",
            ],
        }
        
        self.monitoring_cycle = 0
        
        # Last seen tracking with timestamps
        self.last_websites = {}  # url: timestamp
        self.last_processes = set()
        self.last_connections = set()
        self.website_cache_duration = 3600  # 1 hour - don't re-analyze same URL for 1 hour
        
        # Initialize BEFORE first check to capture everything
        self.last_browser_check_time = (datetime.now().timestamp() - 600)  # Start from 10 minutes ago to catch recent activity
        
        self._init_database()
        # Limit concurrent external API scans to reduce lag
        self._analysis_semaphore = asyncio.Semaphore(2)
        self._pending_tasks = set()

    def _copy_sqlite_db(self, source_db: Path, target_db: Path) -> None:
        """Copy SQLite DB with WAL/SHM if present to avoid missing recent writes."""
        shutil.copy2(source_db, target_db)

        wal_src = Path(f"{source_db}-wal")
        shm_src = Path(f"{source_db}-shm")
        wal_dst = Path(f"{target_db}-wal")
        shm_dst = Path(f"{target_db}-shm")

        if wal_src.exists():
            shutil.copy2(wal_src, wal_dst)
        if shm_src.exists():
            shutil.copy2(shm_src, shm_dst)

    def _cleanup_sqlite_temp(self, target_db: Path) -> None:
        """Remove temp SQLite DB and any WAL/SHM companions."""
        for suffix in ("", "-wal", "-shm"):
            temp_path = Path(f"{target_db}{suffix}")
            if temp_path.exists():
                try:
                    temp_path.unlink()
                except Exception:
                    pass
    
    def _init_database(self):
        """Initialize activity database"""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Websites table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS websites (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                domain TEXT NOT NULL,
                title TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                browser TEXT,
                risk_level TEXT DEFAULT 'ANALYZING',
                is_blocked BOOLEAN DEFAULT 0,
                analysis TEXT,
                vt_result TEXT,
                abuseipdb_result TEXT,
                urlscan_result TEXT,
                gemini_result TEXT
            )
        ''')
        
        # Applications table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS applications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                app_name TEXT NOT NULL,
                app_path TEXT,
                pid INTEGER,
                start_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                risk_level TEXT DEFAULT 'ANALYZING',
                is_blocked BOOLEAN DEFAULT 0,
                analysis TEXT
            )
        ''')
        
        # Network connections table
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
                risk_level TEXT DEFAULT 'ANALYZING',
                is_blocked BOOLEAN DEFAULT 0,
                analysis TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        try:
            parsed = urlparse(url)
            return parsed.netloc or parsed.path.split('/')[0]
        except:
            return url

    def _normalize_url_key(self, url: str) -> str:
        """Normalize URL to reduce duplicate detections (strip query/fragment)."""
        try:
            parsed = urlparse(url)
            if parsed.netloc:
                # Use scheme + netloc + path without query/fragment
                path = parsed.path or "/"
                return f"{parsed.scheme}://{parsed.netloc}{path}"
            return url
        except Exception:
            return url

    def _is_localhost_domain(self, domain: str) -> bool:
        """Check if domain is localhost or loopback."""
        if not domain:
            return False

        host = domain.split(":")[0]

        if host in {"localhost", "127.0.0.1", "0.0.0.0", "::1"}:
            return True

        if host.startswith("127."):
            return True

        try:
            ip = ipaddress.ip_address(host)
            return ip.is_loopback
        except Exception:
            return False
    
    async def _analyze_url(self, url: str, domain: str) -> Dict[str, Any]:
        """Analyze URL using 5 APIs + Gemini AI"""
        # Temporarily reduce logging to hide API keys
        import logging
        original_level = logging.getLogger('httpx').level
        logging.getLogger('httpx').setLevel(logging.WARNING)
        
        results = {
            'risk_level': 'SAFE',
            'threats': [],
            'vt_result': 'N/A',
            'abuseipdb_result': 'N/A',
            'urlscan_result': 'N/A',
            'gemini_result': 'N/A'
        }
        
        # VirusTotal URL check
        try:
            vt_result = await self.vt_service.scan_url(url)
            if vt_result and not vt_result.get('error'):
                # Parse the VirusTotal response
                stats = vt_result.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                if stats:
                    malicious = stats.get('malicious', 0)
                    suspicious = stats.get('suspicious', 0)
                    
                    if malicious > 0:
                        results['threats'].append(f'VirusTotal: {malicious} vendors flagged as malicious')
                        results['risk_level'] = 'CRITICAL'
                    elif suspicious > 0:
                        results['threats'].append(f'VirusTotal: {suspicious} vendors flagged as suspicious')
                        if results['risk_level'] == 'SAFE':
                            results['risk_level'] = 'MEDIUM'
                    
                    results['vt_result'] = f"Malicious: {malicious}, Suspicious: {suspicious}, Clean: {stats.get('harmless', 0)}"
                else:
                    results['vt_result'] = 'Scanned'
            else:
                error_msg = vt_result.get('error', 'Unknown error')
                if 'not configured' in error_msg:
                    results['vt_result'] = 'No API key'
                else:
                    results['vt_result'] = 'Error'
        except Exception as e:
            logger.debug(f"VirusTotal: {e}")
            results['vt_result'] = 'Error'
        
        # URLScan.io check
        try:
            urlscan_result = await self.urlscan_service.scan_url(url)
            if urlscan_result and not urlscan_result.get('error'):
                # URLScan returns submission info
                results['urlscan_result'] = 'Submitted for scan'
            else:
                error_msg = urlscan_result.get('error', '')
                if 'not configured' in error_msg:
                    results['urlscan_result'] = 'No API key'
                elif 'blocked' in str(error_msg).lower():
                    results['urlscan_result'] = 'Blocked by URLScan'
                else:
                    results['urlscan_result'] = 'Error'
        except Exception as e:
            logger.debug(f"URLScan: {e}")
            results['urlscan_result'] = 'Error'
        
        # AbuseIPDB check for domain IP
        try:
            import socket
            ip = socket.gethostbyname(domain)
            
            # Skip local/private IPs
            if ip.startswith(('127.', '192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.')):
                results['abuseipdb_result'] = 'Local IP (skipped)'
            else:
                # Use async AbuseIPDB check
                abuse_result = await self.abuseipdb_service.check_ip(ip)
                if abuse_result and not abuse_result.get('error'):
                    data = abuse_result.get('data', {})
                    score = data.get('abuseConfidenceScore', 0)
                    
                    if score > 75:
                        results['threats'].append(f'AbuseIPDB: High risk ({score}%)')
                        results['risk_level'] = 'CRITICAL' if score > 90 else 'HIGH'
                    elif score > 25:
                        results['threats'].append(f'AbuseIPDB: Moderate risk ({score}%)')
                        if results['risk_level'] == 'SAFE':
                            results['risk_level'] = 'MEDIUM'
                    
                    results['abuseipdb_result'] = f"Score: {score}%, Reports: {data.get('totalReports', 0)}"
                else:
                    error_msg = abuse_result.get('error', '')
                    if 'not configured' in error_msg:
                        results['abuseipdb_result'] = 'No API key'
                    else:
                        results['abuseipdb_result'] = 'Error'
        except socket.gaierror:
            results['abuseipdb_result'] = 'DNS lookup failed'
        except Exception as e:
            logger.debug(f"AbuseIPDB: {e}")
            results['abuseipdb_result'] = 'Error'
        
        # Gemini AI analysis
        try:
            gemini_client = get_gemini_client()
            if gemini_client.is_available():
                # Check if it's localhost first
                is_localhost = domain in ['127.0.0.1', 'localhost'] or domain.startswith('127.')
                
                if is_localhost:
                    results['gemini_result'] = 'Localhost - Safe'
                else:
                    gemini_prompt = f"Analyze this URL for security threats: {url}\nProvide risk assessment (SAFE/LOW/MEDIUM/HIGH/CRITICAL) and brief explanation."
                    gemini_response = await gemini_client.analyze_with_gemini(gemini_prompt)
                    if gemini_response.get('success'):
                        gemini_text = gemini_response.get('response', '')
                        if 'HIGH' in gemini_text or 'CRITICAL' in gemini_text:
                            results['threats'].append('Gemini AI: Threat detected')
                            if 'CRITICAL' in gemini_text:
                                results['risk_level'] = 'CRITICAL'
                            elif results['risk_level'] == 'SAFE':
                                results['risk_level'] = 'HIGH'
                        results['gemini_result'] = gemini_text[:100] if gemini_text else 'N/A'
                    else:
                        results['gemini_result'] = 'Analysis unavailable'
            else:
                results['gemini_result'] = 'Service unavailable'
        except Exception as e:
            logger.debug(f"Gemini: {e}")
            results['gemini_result'] = 'Error'
        
        # Restore logging level
        logging.getLogger('httpx').setLevel(original_level)
        
        return results
    
    async def _analyze_ip(self, ip: str) -> Dict[str, Any]:
        """Analyze IP using threat intelligence"""
        results = {
            'risk_level': 'SAFE',
            'threats': []
        }
        
        # Skip analysis for common safe IPs
        if ip.startswith(('127.', '192.168.', '10.', '172.16.')):
            return results
        
        # AbuseIPDB check - skip for now to avoid async issues
        # Will be enabled once API keys are configured
        try:
            # Disabled to prevent coroutine warnings
            pass
        except Exception as e:
            logger.debug(f"AbuseIPDB check skipped: {e}")
        
        # Shodan check - skip for now
        try:
            # Disabled to prevent errors
            pass
        except Exception as e:
            logger.debug(f"Shodan check skipped: {e}")
        
        return results
    
    def _block_domain(self, domain: str):
        """Block domain - logs blocking action (requires root for /etc/hosts)"""
        try:
            # Note: Modifying /etc/hosts requires root privileges
            # For production, run server with appropriate permissions or use alternative blocking
            self.blocked_domains.add(domain)
            logger.warning(f"⚠️  BLOCKED: {domain} (logged - system-level blocking requires root)")
            if os.geteuid() != 0:
                print("   ⚠️  Note: Run with sudo to enable /etc/hosts blocking")
        except Exception as e:
            logger.error(f"Failed to block domain: {e}")
    
    def _block_ip(self, ip: str):
        """Block IP - logs blocking action (requires root for iptables)"""
        try:
            # Note: iptables requires root privileges
            self.blocked_ips.add(ip)
            logger.warning(f"⚠️  BLOCKED IP: {ip} (logged - iptables requires root)")
            if os.geteuid() != 0:
                print("   ⚠️  Note: Run with sudo to enable iptables blocking")
        except Exception as e:
            logger.error(f"Failed to block IP: {e}")
    
    async def _monitor_browser_activity(self):
        """Monitor browser history for new visits - ALL BROWSERS"""
        new_visits = []
        seen_keys = set()
        current_time = datetime.now().timestamp()
        
        # Clean old cached URLs (older than 1 hour)
        old_urls = [url for url, ts in self.last_websites.items() 
                    if current_time - ts > self.website_cache_duration]
        for url in old_urls:
            del self.last_websites[url]
        
        # Show cache status every 3600 cycles (1 hour) instead of 1800
        if self.monitoring_cycle % 3600 == 0 and self.monitoring_cycle > 0:
            logger.debug(f"Hourly Summary: {len(self.last_websites)} URLs tracked")
        
        # Calculate time since last check (in microseconds for browser databases)
        time_since_last_check = int(self.last_browser_check_time * 1000000)
        
        # Check Firefox
        firefox_profiles_found = 0
        for firefox_path in self.firefox_paths:
            if not firefox_path.exists():
                continue
            
            profiles = list(firefox_path.glob("*.default*"))
            firefox_profiles_found += len(profiles)
            
            # Log once on startup
            if self.monitoring_cycle == 1 and len(profiles) > 0:
                logger.debug(f"Found {len(profiles)} Firefox profile(s)")
            
            for profile_dir in profiles:
                history_db = profile_dir / "places.sqlite"
                if not history_db.exists():
                    continue
                
                temp_db = Path(f"/tmp/firefox_temp_{os.getpid()}.db")
                try:
                    # Copy database to avoid lock
                    self._copy_sqlite_db(history_db, temp_db)
                    conn = sqlite3.connect(temp_db)
                    cursor = conn.cursor()
                    
                    # Get ONLY NEW visits since last check
                    cursor.execute('''
                        SELECT url, title, datetime(last_visit_date/1000000, 'unixepoch', 'localtime'),
                               last_visit_date, visit_count
                        FROM moz_places
                        WHERE last_visit_date > ?
                        AND url NOT LIKE 'about:%'
                        AND url NOT LIKE 'moz-extension:%'
                        AND url NOT LIKE 'file:%'
                        AND url NOT LIKE 'chrome:%'
                        AND url NOT LIKE 'edge:%'
                        AND (url LIKE 'http://%' OR url LIKE 'https://%')
                        ORDER BY last_visit_date DESC
                        LIMIT 50
                    ''', (time_since_last_check,))
                    
                    results = cursor.fetchall()
                    
                    # Log only if we found something
                    if results:
                        logger.debug(f"Firefox: Found {len(results)} new URLs")
                    
                    for row in results:
                        url, title, visit_time, timestamp, visit_count = row
                        domain = self._extract_domain(url) if url else ""
                        if domain and self._is_localhost_domain(domain):
                            continue
                        # Check if URL was recently processed (normalized)
                        if url:
                            url_key = self._normalize_url_key(url)
                        else:
                            url_key = None

                        if url_key and (url_key in self.last_websites or url_key in seen_keys):
                            continue

                        if url and url_key:
                            new_visits.append({
                                'url': url,
                                'url_key': url_key,
                                'title': title or 'Untitled',
                                'browser': 'Firefox',
                                'time': visit_time,
                                'visit_count': visit_count
                            })
                            self.last_websites[url_key] = current_time
                            seen_keys.add(url_key)
                            # Show detection immediately
                            print(f"\n🌐 [DETECTED] {url}", flush=True)
                            print(f"   📦 Browser: Firefox | 📝 Title: {title or 'Untitled'}", flush=True)
                            logger.info(f"🌐 NEW VISIT: {url} (Firefox)")
                    
                    conn.close()
                    self._cleanup_sqlite_temp(temp_db)
                except Exception as e:
                    logger.error(f"❌ Firefox error: {e}")
                    self._cleanup_sqlite_temp(temp_db)
        
        # Check ALL Chrome-based browsers
        for browser_name, chrome_paths in self.chrome_based_browsers.items():
            # Try all possible paths for this browser
            for chrome_db in chrome_paths:
                if not chrome_db.exists():
                    continue
                
                temp_db = Path(f"/tmp/{browser_name.lower()}_temp_{os.getpid()}.db")
                try:
                    self._copy_sqlite_db(chrome_db, temp_db)
                    conn = sqlite3.connect(temp_db)
                    cursor = conn.cursor()
                    
                    # Chrome uses different timestamp format (microseconds since 1601)
                    # Calculate timestamp for last check
                    chrome_timestamp = int((self.last_browser_check_time + 11644473600) * 1000000)
                    
                    # Get ONLY NEW visits since last check
                    cursor.execute('''
                        SELECT url, title, datetime((last_visit_time/1000000)-11644473600, 'unixepoch', 'localtime'),
                               last_visit_time, visit_count
                        FROM urls
                        WHERE last_visit_time > ?
                        AND url NOT LIKE 'chrome:%'
                        AND url NOT LIKE 'chrome-extension:%'
                        AND url NOT LIKE 'edge:%'
                        AND url NOT LIKE 'brave:%'
                        AND url NOT LIKE 'opera:%'
                        AND url NOT LIKE 'vivaldi:%'
                        AND url NOT LIKE 'file:%'
                        AND url NOT LIKE 'about:%'
                        AND (url LIKE 'http://%' OR url LIKE 'https://%')
                        ORDER BY last_visit_time DESC
                        LIMIT 50
                    ''', (chrome_timestamp,))
                    
                    results = cursor.fetchall()
                    
                    # Log only if we found something
                    if results:
                        logger.debug(f"{browser_name}: Found {len(results)} new URLs")
                    
                    for row in results:
                        url, title, visit_time, timestamp, visit_count = row
                        domain = self._extract_domain(url) if url else ""
                        if domain and self._is_localhost_domain(domain):
                            continue
                        url_key = self._normalize_url_key(url) if url else None
                        if url_key and (url_key in self.last_websites or url_key in seen_keys):
                            continue

                        if url and url_key:
                            new_visits.append({
                                'url': url,
                                'url_key': url_key,
                                'title': title or 'Untitled',
                                'browser': browser_name,
                                'time': visit_time,
                                'visit_count': visit_count
                            })
                            self.last_websites[url_key] = current_time
                            seen_keys.add(url_key)
                            # Show detection immediately
                            print(f"\n🌐 [DETECTED] {url}", flush=True)
                            print(f"   📦 Browser: {browser_name} | 📝 Title: {title or 'Untitled'}", flush=True)
                            logger.info(f"🌐 NEW VISIT: {url} ({browser_name})")
                    
                    conn.close()
                    self._cleanup_sqlite_temp(temp_db)
                    break  # Found one working path, skip others for this browser
                except Exception as e:
                    logger.debug(f"{browser_name}: {e}")
                    self._cleanup_sqlite_temp(temp_db)
        
        # Fallback: also monitor browser network connections for URLs
        fallback_visits = await self._monitor_browser_connections()
        if fallback_visits:
            logger.info(f"Network fallback discovered {len(fallback_visits)} URLs")
        new_visits.extend(fallback_visits)
        
        return new_visits
    
    async def _monitor_browser_connections(self):
        """Fallback: Monitor browser processes and their network connections"""
        new_visits = []
        browser_processes = ['firefox', 'firefox-esr', 'chrome', 'chromium', 'brave', 
                           'brave-browser', 'microsoft-edge', 'opera', 'vivaldi']
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'connections']):
                try:
                    proc_name = proc.info['name'].lower() if proc.info['name'] else ''
                    
                    # Check if this is a browser process
                    if any(browser in proc_name for browser in browser_processes):
                        connections = proc.info.get('connections', [])
                        if not connections:
                            continue
                        
                        for conn in connections:
                            if conn.status == 'ESTABLISHED' and conn.raddr:
                                ip = conn.raddr.ip
                                port = conn.raddr.port
                                
                                # Standard web ports
                                if port in [80, 443, 8080, 8443]:
                                    # Create pseudo-URL from connection
                                    protocol = 'https' if port in [443, 8443] else 'http'
                                    url = f"{protocol}://{ip}"

                                    if self._is_localhost_domain(ip):
                                        continue
                                    
                                    url_key = self._normalize_url_key(url)
                                    if url_key in self.last_websites or url_key in seen_keys:
                                        continue

                                    if url_key:
                                        new_visits.append({
                                            'url': url,
                                            'url_key': url_key,
                                            'title': f'Connection to {ip}',
                                            'browser': proc_name.capitalize(),
                                            'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                                        })
                                        self.last_websites[url_key] = datetime.now().timestamp()
                                        seen_keys.add(url_key)
                                        logger.info(f"🌐 NEW VISIT (network): {url} ({proc_name.capitalize()})")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            logger.debug(f"Browser connection monitoring: {e}")
        
        return new_visits
    
    async def _monitor_applications(self):
        """Monitor new application launches"""
        new_apps = []
        
        # System processes to ignore
        IGNORE_PROCESSES = {
            'kworker', 'systemd', 'dbus', 'at-spi', 'gvfs', 'xfce', 'wrapper',
            'upowerd', 'polkit', 'colord', 'agent', 'udisks', 'obex', 'xdg-',
            'fusermount', 'pcscd', 'chrome_crashpad', 'pet', 'code', 'zsh', 'crashhelper'
        }
        
        try:
            current_processes = set()
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    pinfo = proc.info
                    pid = pinfo['pid']
                    name = pinfo['name']
                    exe = pinfo['exe']
                    
                    # Skip system processes
                    if any(ignored in name.lower() for ignored in IGNORE_PROCESSES):
                        continue
                    
                    # Skip kernel workers
                    if name.startswith('k') and 'worker' in name:
                        continue
                    
                    proc_id = f"{name}:{exe}"
                    current_processes.add(proc_id)
                    
                    if proc_id not in self.last_processes:
                        # Log important user applications (browsers, editors, terminals, etc.)
                        important_apps = ['firefox', 'chrome', 'chromium', 'brave', 'opera', 'vivaldi',
                                        'code', 'sublime', 'vim', 'nano', 'gedit', 'kate',
                                        'terminal', 'gnome-terminal', 'konsole', 'xterm',
                                        'vlc', 'mpv', 'gimp', 'inkscape', 'libreoffice',
                                        'thunderbird', 'evolution', 'discord', 'slack', 'telegram']
                        
                        if any(app in name.lower() for app in important_apps):
                            new_apps.append({
                                'name': name,
                                'path': exe or 'N/A',
                                'pid': pid
                            })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            self.last_processes = current_processes
        except Exception as e:
            logger.error(f"Application monitoring error: {e}")
        
        return new_apps
    
    async def _monitor_network_connections(self):
        """Monitor new network connections"""
        new_connections = []
        
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    remote_ip = conn.raddr.ip
                    remote_port = conn.raddr.port
                    
                    conn_id = f"{remote_ip}:{remote_port}"
                    
                    if conn_id not in self.last_connections:
                        try:
                            proc = psutil.Process(conn.pid) if conn.pid else None
                            app_name = proc.name() if proc else 'Unknown'
                        except:
                            app_name = 'Unknown'
                        
                        new_connections.append({
                            'app_name': app_name,
                            'remote_ip': remote_ip,
                            'remote_port': remote_port,
                            'status': conn.status
                        })
                        self.last_connections.add(conn_id)
        except Exception as e:
            logger.error(f"Network monitoring error: {e}")
        
        return new_connections
    
    async def _process_website(self, visit: Dict[str, Any]):
        """Process and analyze website visit"""
        url = visit['url']
        url_key = visit.get('url_key') or self._normalize_url_key(url)
        domain = self._extract_domain(url)
        
        # Skip analysis for localhost
        is_localhost = self._is_localhost_domain(domain)
        
        # Minimal display (keep console clean)
        logger.debug(f"Website visit detected: {url} (domain: {domain}) from {visit['browser']}")
        
        if is_localhost:
            # Quick path for localhost - no need for full analysis
            return
        
        # Analyze with AI
        analysis = await self._analyze_url(url_key, domain)
        
        risk_level = analysis['risk_level']
        is_blocked = risk_level in ['HIGH', 'CRITICAL']
        
        logger.debug(f"Analysis complete for {domain} - risk={risk_level}")

        # Single-line prompt for user
        if is_blocked:
            print(f"🚫 [ACTION REQUIRED] {domain} blocked ({risk_level}). Document and monitor for recurrence.", flush=True)
            self._block_domain(domain)
        elif risk_level in ['MEDIUM']:
            print(f"🟡 [REVIEW] {domain} needs monitoring and documentation (risk: {risk_level})", flush=True)
        else:
            print(f"✅ [SAFE] {domain} is safe to access", flush=True)
        
        # Save to database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO websites (url, domain, title, browser, risk_level, is_blocked, 
                                 vt_result, abuseipdb_result, urlscan_result, gemini_result, analysis)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (url, domain, visit.get('title'), visit['browser'], risk_level, is_blocked,
              analysis['vt_result'], analysis['abuseipdb_result'], analysis['urlscan_result'],
              analysis['gemini_result'], ', '.join(analysis['threats'])))
        conn.commit()
        conn.close()
        
        # Keep console output minimal
    
    async def _process_application(self, app: Dict[str, Any]):
        """Process new application launch"""
        # Only log, don't print spam
        logger.debug(f"📱 App started: {app['name']} (PID: {app['pid']})")
        
        # Save to database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO applications (app_name, app_path, pid, risk_level)
            VALUES (?, ?, ?, ?)
        ''', (app['name'], app['path'], app['pid'], 'SAFE'))
        conn.commit()
        conn.close()
    
    async def _process_connection(self, conn: Dict[str, Any]):
        """Process network connection"""
        # Quick risk check
        analysis = await self._analyze_ip(conn['remote_ip'])
        risk_level = analysis['risk_level']
        is_blocked = risk_level in ['HIGH', 'CRITICAL']
        
        # Only display if HIGH/CRITICAL threat
        if risk_level in ['HIGH', 'CRITICAL']:
            print(f"🚫 [NETWORK] {conn['remote_ip']}:{conn['remote_port']} via {conn['app_name']} blocked ({risk_level})", flush=True)
            self._block_ip(conn['remote_ip'])
        
        # Save to database (only if threat detected)
        if is_blocked:
            db_conn = sqlite3.connect(self.db_path)
            cursor = db_conn.cursor()
            cursor.execute('''
                INSERT INTO network_connections (app_name, remote_ip, remote_port, status, risk_level, is_blocked, analysis)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (conn['app_name'], conn['remote_ip'], conn['remote_port'], 
                  conn['status'], risk_level, is_blocked, ', '.join(analysis['threats'])))
            db_conn.commit()
            db_conn.close()
    
    async def start(self):
        """Start monitoring"""
        self.running = True
        
        logger.info("MONITOR started | browser+apps+network")
        
        # Detect installed browsers
        installed_browsers = []
        
        # Check Firefox
        for ff_path in self.firefox_paths:
            if ff_path.exists():
                profiles = list(ff_path.glob("*.default*"))
                if profiles:
                    for profile in profiles:
                        if (profile / "places.sqlite").exists():
                            installed_browsers.append("Firefox")
                            break
                    break
        
        # Check Chrome-based browsers
        for browser_name, paths in self.chrome_based_browsers.items():
            for path in paths:
                if path.exists():
                    installed_browsers.append(browser_name)
                    break
        
        if installed_browsers:
            logger.info(f"MONITOR browsers | {', '.join(set(installed_browsers))}")
        else:
            logger.info("MONITOR browsers | none detected yet")
        
        print("✅ Monitoring active", flush=True)
        
        # Show browser setup on first cycle
        await asyncio.sleep(1)
        logger.debug("Starting continuous monitoring...")
        
        while self.running:
            try:
                self.monitoring_cycle += 1
                
                # Monitor browser activity
                visits = await self._monitor_browser_activity()
                
                # Update last check time AFTER processing
                self.last_browser_check_time = datetime.now().timestamp()
                
                if visits:
                    print(f"🔍 Scanning {len(visits)} new website(s)", flush=True)
                for visit in visits:
                    task = asyncio.create_task(self._process_website_with_semaphore(visit))
                    self._pending_tasks.add(task)
                    task.add_done_callback(self._pending_tasks.discard)
                
                # Monitor applications
                apps = await self._monitor_applications()
                for app in apps:
                    await self._process_application(app)
                
                # Monitor connections
                connections = await self._monitor_network_connections()
                for conn in connections:
                    await self._process_connection(conn)
                
                await asyncio.sleep(1)  # Check every 1 second for immediate detection
                
            except Exception as e:
                logger.error(f"❌ Monitoring error: {e}")
                await asyncio.sleep(5)
    
    async def stop(self):
        """Stop monitoring"""
        self.running = False
        print("🛑 Activity monitor stopped", flush=True)

    async def _process_website_with_semaphore(self, visit: Dict[str, Any]):
        """Limit concurrent website analyses to avoid lag."""
        async with self._analysis_semaphore:
            await self._process_website(visit)

# Global monitor instance
activity_monitor = ActivityMonitor()
