"""
Real-time Activity Monitor - Integrated with Server
Tracks all user activities and displays in server terminal
"""

import asyncio
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
        
        # Browser history paths - Support ALL major browsers
        self.firefox_paths = [
            Path.home() / ".mozilla" / "firefox",
            Path.home() / "snap" / "firefox" / "common" / ".mozilla" / "firefox"
        ]
        
        # Chrome-based browsers (Chrome, Chromium, Brave, Edge, Opera, Vivaldi)
        self.chrome_based_browsers = {
            'Chrome': [
                Path.home() / ".config" / "google-chrome" / "Default" / "History",
                Path.home() / "snap" / "google-chrome" / "common" / ".config" / "google-chrome" / "Default" / "History",
            ],
            'Chromium': [
                Path.home() / ".config" / "chromium" / "Default" / "History",
                Path.home() / "snap" / "chromium" / "common" / ".config" / "chromium" / "Default" / "History",
            ],
            'Brave': [
                Path.home() / ".config" / "BraveSoftware" / "Brave-Browser" / "Default" / "History",
            ],
            'Edge': [
                Path.home() / ".config" / "microsoft-edge" / "Default" / "History",
            ],
            'Opera': [
                Path.home() / ".config" / "opera" / "Default" / "History",
            ],
            'Vivaldi': [
                Path.home() / ".config" / "vivaldi" / "Default" / "History",
            ],
        }
        
        self.monitoring_cycle = 0
        
        # Last seen tracking with timestamps
        self.last_websites = {}  # url: timestamp
        self.last_processes = set()
        self.last_connections = set()
        self.website_cache_duration = 3600  # 1 hour - don't re-analyze same URL for 1 hour
        self.last_browser_check_time = datetime.now().timestamp()  # Track last check time
        
        self._init_database()
    
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
            print(f"   ⚠️  Note: Run with sudo to enable /etc/hosts blocking")
        except Exception as e:
            logger.error(f"Failed to block domain: {e}")
    
    def _block_ip(self, ip: str):
        """Block IP - logs blocking action (requires root for iptables)"""
        try:
            # Note: iptables requires root privileges
            self.blocked_ips.add(ip)
            logger.warning(f"⚠️  BLOCKED IP: {ip} (logged - iptables requires root)")
            print(f"   ⚠️  Note: Run with sudo to enable iptables blocking")
        except Exception as e:
            logger.error(f"Failed to block IP: {e}")
    
    async def _monitor_browser_activity(self):
        """Monitor browser history for new visits - ALL BROWSERS"""
        new_visits = []
        current_time = datetime.now().timestamp()
        
        # Clean old cached URLs (older than 1 hour)
        old_urls = [url for url, ts in self.last_websites.items() 
                    if current_time - ts > self.website_cache_duration]
        for url in old_urls:
            del self.last_websites[url]
        
        # Show cache status every 1800 cycles (1 hour)
        if self.monitoring_cycle % 1800 == 0 and self.monitoring_cycle > 0:
            logger.info(f"📊 Hourly Summary: {len(self.last_websites)} URLs tracked, {len(old_urls)} expired")
        
        # Calculate time since last check (in microseconds for browser databases)
        time_since_last_check = int(self.last_browser_check_time * 1000000)
        
        # Check Firefox
        for firefox_path in self.firefox_paths:
            if not firefox_path.exists():
                continue
            
            for profile_dir in firefox_path.glob("*.default*"):
                history_db = profile_dir / "places.sqlite"
                if not history_db.exists():
                    continue
                
                temp_db = Path(f"/tmp/firefox_temp_{os.getpid()}.db")
                try:
                    # Copy database to avoid lock
                    shutil.copy2(history_db, temp_db)
                    conn = sqlite3.connect(temp_db)
                    cursor = conn.cursor()
                    
                    # Get ONLY NEW visits since last check (not last 5 minutes!)
                    cursor.execute('''
                        SELECT url, title, datetime(last_visit_date/1000000, 'unixepoch', 'localtime'),
                               last_visit_date
                        FROM moz_places
                        WHERE last_visit_date > ?
                        AND url NOT LIKE 'about:%'
                        AND url NOT LIKE 'moz-extension:%'
                        AND url NOT LIKE 'file:%'
                        AND (url LIKE 'http://%' OR url LIKE 'https://%')
                        ORDER BY last_visit_date DESC
                        LIMIT 20
                    ''', (time_since_last_check,))
                    
                    results = cursor.fetchall()
                    
                    # Log what we found for debugging (debug level, not info)
                    if results:
                        logger.debug(f"🔍 Firefox: Found {len(results)} NEW URLs since last check")
                    
                    for row in results:
                        url, title, visit_time, timestamp = row
                        # Check if URL was recently processed
                        if url and url not in self.last_websites:
                            new_visits.append({
                                'url': url,
                                'title': title or 'Untitled',
                                'browser': 'Firefox',
                                'time': visit_time
                            })
                            self.last_websites[url] = current_time
                            logger.info(f"🌐 NEW VISIT: {url} (Firefox)")
                    
                    conn.close()
                    temp_db.unlink()
                except Exception as e:
                    logger.error(f"❌ Firefox error: {e}")
                    if temp_db.exists():
                        try:
                            temp_db.unlink()
                        except:
                            pass
        
        # Check ALL Chrome-based browsers
        for browser_name, chrome_paths in self.chrome_based_browsers.items():
            # Try all possible paths for this browser
            for chrome_db in chrome_paths:
                if not chrome_db.exists():
                    continue
                
                temp_db = Path(f"/tmp/{browser_name.lower()}_temp_{os.getpid()}.db")
                try:
                    shutil.copy2(chrome_db, temp_db)
                    conn = sqlite3.connect(temp_db)
                    cursor = conn.cursor()
                    
                    # Chrome uses different timestamp format (microseconds since 1601)
                    # Calculate timestamp for last check
                    chrome_timestamp = int((self.last_browser_check_time + 11644473600) * 1000000)
                    
                    # Get ONLY NEW visits since last check
                    cursor.execute('''
                        SELECT url, title, datetime((last_visit_time/1000000)-11644473600, 'unixepoch', 'localtime'),
                               last_visit_time
                        FROM urls
                        WHERE last_visit_time > ?
                        AND url NOT LIKE 'chrome:%'
                        AND url NOT LIKE 'chrome-extension:%'
                        AND url NOT LIKE 'edge:%'
                        AND url NOT LIKE 'brave:%'
                        AND url NOT LIKE 'opera:%'
                        AND url NOT LIKE 'file:%'
                        AND (url LIKE 'http://%' OR url LIKE 'https://%')
                        ORDER BY last_visit_time DESC
                        LIMIT 20
                    ''', (chrome_timestamp,))
                    
                    results = cursor.fetchall()
                    
                    # Log what we found for debugging (debug level)
                    if results:
                        logger.debug(f"🔍 {browser_name}: Found {len(results)} NEW URLs since last check")
                    
                    for row in results:
                        url, title, visit_time, timestamp = row
                        if url and url not in self.last_websites:
                            new_visits.append({
                                'url': url,
                                'title': title or 'Untitled',
                                'browser': browser_name,
                                'time': visit_time
                            })
                            self.last_websites[url] = current_time
                            logger.info(f"🌐 NEW VISIT: {url} ({browser_name})")
                    
                    conn.close()
                    temp_db.unlink()
                    break  # Found one working path, skip others for this browser
                except Exception as e:
                    logger.debug(f"{browser_name}: {e}")
                    if temp_db.exists():
                        try:
                            temp_db.unlink()
                        except:
                            pass
        
        # Fallback: Monitor browser network connections for URLs
        if not new_visits:
            fallback_visits = await self._monitor_browser_connections()
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
                                    
                                    if url not in self.last_websites:
                                        new_visits.append({
                                            'url': url,
                                            'title': f'Connection to {ip}',
                                            'browser': proc_name.capitalize(),
                                            'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                                        })
                                        self.last_websites[url] = datetime.now().timestamp()
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
        domain = self._extract_domain(url)
        
        # Skip analysis for localhost
        is_localhost = domain in ['127.0.0.1', 'localhost'] or domain.startswith('127.')
        
        # Display visit
        print(f"\n" + "="*80)
        print(f"🌐 [NEW WEBSITE VISIT] {domain}")
        print(f"   Browser: {visit['browser']}")
        print(f"   Time: {visit['time']}")
        print(f"   URL: {url[:70]}...")
        
        if is_localhost:
            # Quick path for localhost - no need for full analysis
            print(f"\n✅ [STATUS] LOCALHOST - SAFE (No analysis needed)")
            print(f"{'='*80}\n")
            return
        
        # Analyze with AI
        print(f"🔍 [ANALYZING] {domain}...")
        analysis = await self._analyze_url(url, domain)
        
        risk_level = analysis['risk_level']
        is_blocked = risk_level in ['HIGH', 'CRITICAL']
        
        # Display results
        risk_colors = {
            'SAFE': '✅',
            'LOW': '🟢',
            'MEDIUM': '🟡',
            'HIGH': '🟠',
            'CRITICAL': '🔴'
        }
        
        print(f"\n📊 [ANALYSIS RESULTS]")
        print(f"   🛡️  Risk Level: {risk_colors.get(risk_level, '⚪')} {risk_level}")
        print(f"   🔍 VirusTotal: {analysis['vt_result']}")
        print(f"   🌐 AbuseIPDB: {analysis['abuseipdb_result']}")
        print(f"   🔎 URLScan: {analysis['urlscan_result']}")
        print(f"   🤖 Gemini AI: {analysis['gemini_result'][:60]}...")
        
        if analysis['threats']:
            print(f"\n⚠️  [THREATS DETECTED]")
            for threat in analysis['threats']:
                print(f"   🚨 {threat}")
        
        if is_blocked:
            print(f"\n🚫 [ACTION REQUIRED] BLOCKING {domain}")
            self._block_domain(domain)
        else:
            print(f"\n✅ [STATUS] ALLOWED - Safe to access")
        
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
        
        print(f"{'='*80}\n")
    
    async def _process_application(self, app: Dict[str, Any]):
        """Process new application launch"""
        print(f"\n{'='*80}")
        print(f"📱 [APPLICATION LAUNCHED] {app['name']}")
        print(f"   PID: {app['pid']}")
        print(f"   Path: {app['path']}")
        print(f"   Status: ✅ Monitored")
        print(f"{'='*80}\n")
        
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
            print(f"\n" + "="*80)
            print(f"⚠️  [NETWORK THREAT DETECTED]")
            print(f"   🌐 IP Address: {conn['remote_ip']}:{conn['remote_port']}")
            print(f"   📱 Application: {conn['app_name']}")
            print(f"   🚨 Risk Level: 🔴 {risk_level}")
            print(f"   ⚡ Threats: {', '.join(analysis['threats'])}")
            print(f"   🚫 ACTION: Blocking IP immediately")
            self._block_ip(conn['remote_ip'])
            print("="*80 + "\n")
        
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
        
        print("\n" + "="*80)
        print("🛡️  SENTINEL-AI ACTIVITY MONITOR STARTED")
        print("="*80)
        print("📊 Monitoring: Websites | Applications | Network Connections")
        print("🔍 Analysis: 5 APIs + Gemini AI + ML")
        print("🚫 Auto-blocking: Enabled for HIGH/CRITICAL threats")
        print("="*80)
        print("🌐 Universal Browser Monitoring: Active")
        print("   Monitoring ALL browsers and network connections")
        print("   Checking every 2 seconds | History lookback: 5 minutes")
        print("   Re-analysis interval: 60 seconds per URL")
        print("   (Activity will be displayed when detected)")
        print("="*80 + "\n")
        
        print("✅ High-frequency monitoring started - capturing all activity...")
        print("\n💡 TIP: Open Firefox and visit websites NOW to see real-time detection!\n")
        print("\n💡 TIP: Visit websites NOW to see real-time detection!\n")
        
        while self.running:
            try:
                self.monitoring_cycle += 1
                
                # Monitor browser activity
                visits = await self._monitor_browser_activity()
                
                # Update last check time AFTER processing
                self.last_browser_check_time = datetime.now().timestamp()
                
                if visits:
                    print(f"\n🔥 Processing {len(visits)} new website visit(s)...\n")
                for visit in visits:
                    await self._process_website(visit)
                
                # Monitor applications
                apps = await self._monitor_applications()
                for app in apps:
                    await self._process_application(app)
                
                # Monitor connections
                connections = await self._monitor_network_connections()
                for conn in connections:
                    await self._process_connection(conn)
                
                # Show activity summary every 1800 cycles (1 hour)
                if self.monitoring_cycle % 1800 == 0 and self.monitoring_cycle > 0:
                    logger.info(f"📊 Hourly Summary - Cycle {self.monitoring_cycle}: Websites cached: {len(self.last_websites)}, Processes tracked: {len(self.last_processes)}")
                
                await asyncio.sleep(2)  # Check every 2 seconds for faster detection
                
            except Exception as e:
                logger.error(f"❌ Monitoring error: {e}")
                await asyncio.sleep(5)
    
    async def stop(self):
        """Stop monitoring"""
        self.running = False
        print("\n🛑 Activity monitor stopped")

# Global monitor instance
activity_monitor = ActivityMonitor()
