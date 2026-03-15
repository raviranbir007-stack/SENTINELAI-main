"""
Automatic Activity Monitor & Scanner
Continuously monitors system activity and automatically scans all detected artifacts
"""

import asyncio
import ipaddress
import logging
import os
import platform
import re
import sqlite3
import shutil
import tempfile
import time
from collections import deque
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Optional, Set
from urllib.parse import urlparse

from ..config import settings

try:
    import psutil
except ImportError:
    psutil = None

logger = logging.getLogger("AutoMonitor")


class AutomaticActivityMonitor:
    """
    Automatically monitors ALL system activity and scans detected artifacts
    - Monitors browser activity (URLs visited)
    - Monitors network connections (IPs contacted)
    - Monitors DNS queries (domains resolved)
    - Automatically scans everything detected
    - Shows brief terminal messages
    - Logs full details to database
    """
    
    def __init__(self, scan_callback=None, db_path: str = "activity_monitoring.db"):
        self.scan_callback = scan_callback
        self.db_path = db_path
        self.running = False
        self.enable_network_monitoring = str(
            os.getenv("SENTINEL_ENABLE_NETWORK_MONITORING", "true")
        ).strip().lower() not in {"0", "false", "no", "off"}
        self.network_scan_cooldown = max(
            60,
            int(os.getenv("SENTINEL_NETWORK_SCAN_COOLDOWN", "600") or 600),
        )
        self.network_poll_interval = max(
            5,
            int(os.getenv("SENTINEL_NETWORK_POLL_INTERVAL", "15") or 15),
        )
        self.monitored_remote_ports = {
            21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587,
            993, 995, 1433, 3306, 3389, 5432, 6379, 8080, 8443,
        }
        self.browser_process_markers = {
            'firefox', 'firefox-esr', 'chrome', 'chromium', 'brave',
            'brave-browser', 'microsoft-edge', 'edge', 'opera', 'vivaldi', 'arc'
        }
        self.last_network_scan_at = 0.0
        self.ip_last_seen: Dict[str, float] = {}
        
        # Track what we've already scanned to avoid duplicates
        self.scanned_urls: Set[str] = set()
        self.scanned_ips: Set[str] = set()
        self.scanned_domains: Set[str] = set()
        
        # Recent activity for deduplication
        self.recent_urls = deque(maxlen=1000)
        self.recent_ips = deque(maxlen=1000)
        self.recent_domains = deque(maxlen=1000)
        
        # Statistics
        self.stats = {
            'urls_detected': 0,
            'ips_detected': 0,
            'domains_detected': 0,
            'scans_performed': 0,
            'threats_found': 0,
            'start_time': None
        }

        # Chromium timestamp origin: microseconds since 1601-01-01
        self._chrome_epoch_offset = 11644473600
        
        # Whitelist common safe domains/IPs to reduce noise
        self.safe_domains = {
            'google.com', 'googleapis.com', 'gstatic.com',
            'microsoft.com', 'windows.com', 'office.com',
            'apple.com', 'icloud.com',
            'mozilla.org', 'firefox.com',
            'github.com', 'githubusercontent.com',
            'ubuntu.com', 'debian.org',
            'localhost', '127.0.0.1', '0.0.0.0'
        }
        
        logger.info("🤖 Automatic Activity Monitor initialized")
    
    def _is_safe_domain(self, domain: str) -> bool:
        """Check if domain is in safe list"""
        domain_lower = domain.lower()
        for safe in self.safe_domains:
            if domain_lower.endswith(safe):
                return True
        return False
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/local"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return (
                ip_obj.is_private
                or ip_obj.is_loopback
                or ip_obj.is_link_local
                or getattr(ip_obj, 'is_reserved', False)
                or getattr(ip_obj, 'is_unspecified', False)
                or getattr(ip_obj, 'is_multicast', False)
            )
        except Exception:
            pass
        return False

    def _get_process_name(self, pid: Optional[int]) -> str:
        """Best-effort process name lookup for network connections."""
        if not pid or not psutil:
            return "unknown"
        try:
            return (psutil.Process(pid).name() or "unknown").lower()
        except Exception:
            return "unknown"

    def _is_browser_process(self, process_name: str) -> bool:
        """Return True if process looks like a browser."""
        name = (process_name or "").lower()
        return any(marker in name for marker in self.browser_process_markers)
    
    def _get_hostname(self, ip: str) -> str:
        """Get hostname from IP address"""
        try:
            import socket
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname if hostname != ip else None
        except:
            return None

    def _build_allowlisted_result(self, artifact_type: str, value: str, reason: str) -> Dict:
        """Build a local SAFE result for allowlisted artifacts so monitoring stays informative."""
        return {
            "input": value,
            "input_type": artifact_type,
            "verdict": "clean",
            "confidence": 1.0,
            "summary": reason,
            "threat_indicators": [],
            "warnings": [],
            "recommendations": ["No action required."],
            "api_results": {
                "apis_called": [],
                "apis_expected": [],
                "api_status": {
                    "virustotal": {"name": "VirusTotal", "status": "allowlisted", "configured": bool(settings.VIRUSTOTAL_API_KEY), "applicable": artifact_type in {"url", "domain", "file_hash"}, "error": None},
                    "abuseipdb": {"name": "AbuseIPDB", "status": "allowlisted", "configured": bool(settings.ABUSEIPDB_API_KEY), "applicable": artifact_type == "ip", "error": None},
                    "shodan": {"name": "Shodan", "status": "allowlisted", "configured": bool(settings.SHODAN_API_KEY), "applicable": artifact_type == "ip", "error": None},
                    "urlscan": {"name": "URLScan.io", "status": "allowlisted", "configured": bool(settings.URLSCAN_API_KEY), "applicable": artifact_type in {"url", "domain"}, "error": None},
                    "hybrid_analysis": {"name": "Hybrid Analysis", "status": "allowlisted", "configured": bool(settings.HYBRIDANALYSIS_API_KEY), "applicable": artifact_type == "file_hash", "error": None},
                },
            },
            "forensic_metadata": {
                "corroboration_count": 0,
                "corroboration_threshold_met": False,
                "unique_sources": [],
                "apis_checked": 0,
                "total_apis_available": 0,
            },
        }

    def _get_recommended_action(self, result: Dict) -> str:
        """Return a concise operator action for terminal prompts."""
        recommendations = result.get("recommendations") or []
        if recommendations:
            return str(recommendations[0]).strip().rstrip(".") + "."

        verdict = str(result.get("verdict", "unknown")).lower()
        if verdict in {"clean", "safe", "unknown"}:
            return "No action required. Continue monitoring."
        if verdict == "suspicious":
            return "Review activity and keep the target under observation."
        if verdict in {"malicious", "critical"}:
            return "Block or quarantine immediately and investigate exposure."
        if verdict == "error":
            return "Retry scan and verify external API availability."
        return "Review scan details manually."

    def _log_website_activity(
        self,
        url: str,
        domain: str,
        title: str,
        browser_name: str,
        result: Optional[Dict] = None,
        scan_status: str = "completed",
    ):
        """Persist browser activity for dashboards and generated reports."""
        try:
            from .activity_database import activity_db

            result = result or {}
            forensic_metadata = result.get("forensic_metadata", {}) or {}
            verdict = str(result.get("verdict", "unknown")).lower()
            verdict_map = {
                "clean": "safe",
                "safe": "safe",
                "unknown": "unknown",
                "suspicious": "suspicious",
                "malicious": "malicious",
                "critical": "malicious",
            }

            activity_db.log_website(
                {
                    "url": url,
                    "domain": domain,
                    "title": title,
                    "browser": browser_name,
                    "risk_level": verdict_map.get(verdict, verdict).upper(),
                    "risk_score": round(float(result.get("confidence", 0.0)) * 100, 2),
                    "risk_factors": [item.get("indicator") for item in result.get("threat_indicators", []) if isinstance(item, dict)],
                    "scan_status": scan_status,
                    "scan_result": result,
                    "threat_verdict": verdict_map.get(verdict, verdict),
                    "corroboration_sources": forensic_metadata.get("unique_sources") or result.get("api_results", {}).get("apis_called", []),
                    "metadata": {
                        "auto_detected": True,
                        "recommended_action": self._get_recommended_action(result),
                    },
                }
            )
        except Exception as e:
            logger.debug(f"Unable to persist website activity for reporting: {e}")
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        try:
            parsed = urlparse(url)
            return parsed.netloc or parsed.path.split('/')[0]
        except:
            return url

    def _chrome_time_from_unix(self, unix_time: float) -> int:
        """Convert Unix timestamp to Chromium microseconds since 1601 epoch."""
        try:
            return int((unix_time + self._chrome_epoch_offset) * 1_000_000)
        except Exception:
            return 0

    def _discover_chromium_history_files(self, root: Path):
        """Find Chromium-style History DB files under a user-data root."""
        if not root.exists():
            return []

        found = []

        if root.is_file() and root.name == "History":
            return [root]

        direct = root / "History"
        if direct.exists():
            found.append(direct)

        try:
            for child in root.iterdir():
                if not child.is_dir():
                    continue
                if child.name == "Default" or child.name.startswith("Profile ") or "Profile" in child.name or child.name.endswith(" Stable"):
                    history = child / "History"
                    if history.exists():
                        found.append(history)
        except Exception:
            pass

        dedup = []
        seen = set()
        for path in found:
            key = str(path)
            if key in seen:
                continue
            seen.add(key)
            dedup.append(path)

        return dedup

    def _discover_browser_history_targets(self):
        """Return list of browser history targets as (engine, browser_name, path)."""
        targets = []
        system = platform.system()

        if system == "Linux":
            home = Path.home()
            firefox_roots = [
                home / ".mozilla/firefox",
                home / "snap/firefox/common/.mozilla/firefox",
            ]
            for ff in firefox_roots:
                if ff.exists():
                    targets.append(("firefox", "Firefox", ff))

            chromium_roots = {
                "Chrome": [home / ".config/google-chrome", home / "snap/google-chrome/common/.config/google-chrome"],
                "Chromium": [home / ".config/chromium", home / "snap/chromium/common/chromium"],
                "Brave": [home / ".config/BraveSoftware/Brave-Browser"],
                "Edge": [home / ".config/microsoft-edge"],
                "Opera": [home / ".config/opera", home / ".config/opera-beta", home / ".config/opera-developer"],
                "Vivaldi": [home / ".config/vivaldi"],
            }
            for browser_name, roots in chromium_roots.items():
                for root in roots:
                    for history in self._discover_chromium_history_files(root):
                        targets.append(("chromium", browser_name, history))

        elif system == "Windows":
            user_profile = os.environ.get('USERPROFILE', '')
            if user_profile:
                home = Path(user_profile)
                ff = home / "AppData/Roaming/Mozilla/Firefox/Profiles"
                if ff.exists():
                    targets.append(("firefox", "Firefox", ff))

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
                        for history in self._discover_chromium_history_files(root):
                            targets.append(("chromium", browser_name, history))

        elif system == "Darwin":
            home = Path.home()
            ff = home / "Library/Application Support/Firefox/Profiles"
            if ff.exists():
                targets.append(("firefox", "Firefox", ff))

            safari = home / "Library/Safari/History.db"
            if safari.exists():
                targets.append(("safari", "Safari", safari))

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
                    for history in self._discover_chromium_history_files(root):
                        targets.append(("chromium", browser_name, history))

        dedup = []
        seen = set()
        for engine, browser_name, path in targets:
            key = (engine, browser_name, str(path))
            if key in seen:
                continue
            seen.add(key)
            dedup.append((engine, browser_name, path))
        return dedup
    
    async def _scan_artifact(self, artifact_type: str, value: str, show_prompt: bool = True):
        """Scan an artifact and log results - minimal terminal output, full database logging"""
        try:
            if not self.scan_callback:
                return None
            
            # Get context info (hostname for IPs)
            context = ""
            if artifact_type == 'ip':
                hostname = self._get_hostname(value)
                if hostname:
                    context = f" → {hostname}"
            
            # Perform scan (results go to database)
            result = await self.scan_callback(artifact_type, value)
            self.stats['scans_performed'] += 1
            
            # Check verdict
            verdict = result.get('verdict', 'unknown')
            
            if verdict in ['malicious', 'suspicious', 'critical']:
                self.stats['threats_found'] += 1
            
            # Detailed terminal output (3–4 lines) for each activity.
            # For network monitoring we keep SAFE/UNKNOWN results quiet to avoid spam.
            if show_prompt or verdict in ['malicious', 'suspicious', 'critical', 'error']:
                self._print_activity_prompt(artifact_type, value, result, context=context)
            return result
            
        except Exception as e:
            logger.error(f"Error scanning {artifact_type} {value}: {e}")
            return {"verdict": "error", "error": str(e), "warnings": [str(e)]}

    def _print_activity_prompt(self, artifact_type: str, value: str, result: Dict, context: str = ""):
        """Print a concise 3–4 line activity prompt with API usage and verdict"""
        verdict_raw = str(result.get('verdict', 'unknown')).lower()
        confidence = result.get('confidence', 0.0)
        threats = result.get('threat_indicators') or []
        warnings = result.get('warnings') or []

        verdict_map = {
            'clean': 'SAFE',
            'safe': 'SAFE',
            'unknown': 'UNKNOWN',
            'suspicious': 'SUSPICIOUS',
            'malicious': 'MALICIOUS',
            'critical': 'MALICIOUS'
        }
        verdict_label = verdict_map.get(verdict_raw, verdict_raw.upper())

        api_results = result.get('api_results', {}) or {}
        api_status_map = api_results.get('api_status', {}) or {}
        api_status = []
        for api_key in ["virustotal", "abuseipdb", "shodan", "urlscan", "hybrid_analysis"]:
            api_meta = api_status_map.get(api_key, {})
            api_name = api_meta.get("name", api_key)
            status = str(api_meta.get("status", "unknown")).replace("_", " ")
            api_status.append(f"{api_name}({status})")

        action_text = self._get_recommended_action(result)

        # Build the prompt
        header_icon = "🌐" if artifact_type in ['url', 'domain'] else "🔌" if artifact_type == 'ip' else "📄"
        print(f"\n{header_icon} Activity Detected: {artifact_type.upper()} -> {value}{context}")
        print(f"🧪 APIs: {', '.join(api_status)}")
        print(f"✅ Verdict: {verdict_label} | Confidence: {confidence:.2f}")
        print(f"🛡️ Action: {action_text}")
        if threats or warnings:
            print(f"📝 Indicators: {len(threats)} | Warnings: {len(warnings)}")
    
    async def _monitor_file_access(self):
        """Monitor file access - for future implementation"""
        # TODO: Monitor file opens/downloads using inotify or similar
        # This will track files opened by user and scan them
        pass
    
    async def _monitor_browser_activity(self):
        """Monitor browser history for NEW URLs user actually visits"""
        try:
            for engine, browser_name, history_path in self._discover_browser_history_targets():
                try:
                    if engine == "chromium":
                        await self._read_chromium_history(browser_name, history_path)
                    elif engine == "firefox":
                        await self._read_firefox_history(browser_name, history_path)
                    elif engine == "safari":
                        await self._read_safari_history(browser_name, history_path)
                except Exception as e:
                    logger.debug(f"Error reading {browser_name} history: {e}")
            
        except Exception as e:
            logger.debug(f"Browser monitoring error: {e}")

    async def _read_chromium_history(self, browser_name: str, history_path: Path):
        """Read Chromium-based browser history and scan new URLs."""
        temp_file = tempfile.NamedTemporaryFile(prefix=f"{browser_name.lower()}_{os.getpid()}_", suffix=".db", delete=False)
        temp_db = temp_file.name
        temp_file.close()
        try:
            shutil.copy2(history_path, temp_db)
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()

            cutoff = self._chrome_time_from_unix(time.time() - 30)
            cursor.execute('''
                SELECT url, title, last_visit_time FROM urls
                WHERE last_visit_time > ?
                AND url LIKE 'http%'
                ORDER BY last_visit_time DESC
                LIMIT 20
            ''', (cutoff,))

            for url, title, _ in cursor.fetchall():
                await self._process_detected_url(url, title or 'Untitled', browser_name)

            conn.close()
        finally:
            try:
                os.remove(temp_db)
            except Exception:
                pass

    async def _read_firefox_history(self, browser_name: str, firefox_profiles_dir: Path):
        """Read Firefox profile history and scan new URLs."""
        profiles = list(firefox_profiles_dir.glob("*.default*"))
        for profile in profiles:
            history_db = profile / "places.sqlite"
            if not history_db.exists():
                continue

            temp_file = tempfile.NamedTemporaryFile(prefix=f"firefox_{os.getpid()}_", suffix=".db", delete=False)
            temp_db = temp_file.name
            temp_file.close()
            try:
                shutil.copy2(history_db, temp_db)
                conn = sqlite3.connect(temp_db)
                cursor = conn.cursor()

                cutoff = int((time.time() - 30) * 1_000_000)
                cursor.execute('''
                    SELECT url, title, last_visit_date FROM moz_places
                    WHERE last_visit_date > ?
                    AND url LIKE 'http%'
                    ORDER BY last_visit_date DESC
                    LIMIT 20
                ''', (cutoff,))

                for url, title, _ in cursor.fetchall():
                    await self._process_detected_url(url, title or 'Untitled', browser_name)

                conn.close()
            finally:
                try:
                    os.remove(temp_db)
                except Exception:
                    pass

    async def _read_safari_history(self, browser_name: str, safari_db_path: Path):
        """Read Safari history and scan new URLs."""
        temp_file = tempfile.NamedTemporaryFile(prefix=f"safari_{os.getpid()}_", suffix=".db", delete=False)
        temp_db = temp_file.name
        temp_file.close()
        try:
            shutil.copy2(safari_db_path, temp_db)
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()

            # Safari timestamps are seconds since 2001-01-01
            safari_epoch_offset = 978307200
            cutoff = (time.time() - 30) - safari_epoch_offset
            cursor.execute('''
                SELECT hi.url, hv.title, hv.visit_time
                FROM history_visits hv
                JOIN history_items hi ON hv.history_item = hi.id
                WHERE hv.visit_time > ?
                AND hi.url LIKE 'http%'
                ORDER BY hv.visit_time DESC
                LIMIT 20
            ''', (cutoff,))

            for url, title, _ in cursor.fetchall():
                await self._process_detected_url(url, title or 'Untitled', browser_name)

            conn.close()
        finally:
            try:
                os.remove(temp_db)
            except Exception:
                pass

    async def _process_detected_url(self, url: str, title: str, browser_name: str):
        """Apply dedup/filtering and trigger scans for newly detected URLs."""
        if url in self.scanned_urls:
            return

        self.recent_urls.append(url)
        domain = self._extract_domain(url)

        if self._is_safe_domain(domain):
            self.scanned_urls.add(url)
            self.stats['urls_detected'] += 1
            self.stats['scans_performed'] += 1
            safe_result = self._build_allowlisted_result(
                'url', url, f"Allowlisted domain '{domain}' recognized as trusted traffic."
            )
            print(f"\n🌐 [{browser_name}] Visited: {domain}")
            self._print_activity_prompt('url', url, safe_result)
            self._log_website_activity(url, domain, title, browser_name, safe_result, scan_status="allowlisted")
            return

        self.scanned_urls.add(url)
        self.stats['urls_detected'] += 1

        print(f"\n🌐 [{browser_name}] Visited: {domain}")
        result = await self._scan_artifact('url', url)
        self._log_website_activity(url, domain, title, browser_name, result, scan_status="completed")

        if domain not in self.scanned_domains and not self._is_safe_domain(domain):
            self.scanned_domains.add(domain)
            self.stats['domains_detected'] += 1
            asyncio.create_task(self._scan_artifact('domain', domain))
    
    async def _monitor_network_connections(self):
        """Monitor active network connections with low-noise public-IP scanning."""
        if not self.enable_network_monitoring or not psutil:
            return

        now = time.time()
        if now - self.last_network_scan_at < self.network_poll_interval:
            return
        self.last_network_scan_at = now

        seen_this_cycle = set()

        try:
            for conn in psutil.net_connections(kind='inet'):
                try:
                    if getattr(conn, 'status', '') != 'ESTABLISHED' or not getattr(conn, 'raddr', None):
                        continue

                    ip = conn.raddr.ip
                    port = conn.raddr.port
                    if not ip or self._is_private_ip(ip) or ip in seen_this_cycle:
                        continue

                    process_name = self._get_process_name(getattr(conn, 'pid', None))
                    if not self._is_browser_process(process_name) and port not in self.monitored_remote_ports:
                        continue

                    last_seen = self.ip_last_seen.get(ip, 0.0)
                    if now - last_seen < self.network_scan_cooldown:
                        continue

                    seen_this_cycle.add(ip)
                    self.ip_last_seen[ip] = now
                    self.scanned_ips.add(ip)
                    self.stats['ips_detected'] += 1

                    hostname = self._get_hostname(ip)
                    if hostname and self._is_safe_domain(hostname):
                        continue

                    result = await self._scan_artifact('ip', ip, show_prompt=False)
                    verdict = str((result or {}).get('verdict', 'unknown')).lower()
                    if verdict in {'malicious', 'suspicious', 'critical', 'error'}:
                        logger.warning(
                            "Network monitor flagged %s:%s via %s | verdict=%s",
                            ip,
                            port,
                            process_name,
                            verdict,
                        )
                except Exception:
                    continue
        except Exception as e:
            logger.debug(f"Network connection monitoring error: {e}")
    
    async def _monitoring_loop(self):
        """Main monitoring loop for browser activity plus optional network scanning."""
        mode = "active+passive" if self.enable_network_monitoring else "passive"
        logger.info("🔍 Monitoring user browser activity (%s mode)...", mode)
        
        while self.running:
            try:
                # Monitor browser activity (user visits)
                await self._monitor_browser_activity()
                await self._monitor_network_connections()
                
                # Check every 10 seconds for new browser visits / connection changes
                await asyncio.sleep(10)
                
            except Exception as e:
                logger.error(f"Monitoring loop error: {e}")
                await asyncio.sleep(10)
    
    async def start(self):
        """Start automatic monitoring"""
        if self.running:
            return
        
        self.running = True
        self.stats['start_time'] = datetime.utcnow()
        
        mode = "active+passive" if self.enable_network_monitoring else "passive"
        print(
            f"🤖 Auto monitor started | mode={mode} | ip_cooldown={self.network_scan_cooldown}s | auto_scan=on",
            flush=True,
        )
        
        # Start monitoring loop
        await self._monitoring_loop()
    
    def stop(self):
        """Stop monitoring"""
        self.running = False
        
        # Print summary
        if self.stats['start_time']:
            duration = datetime.utcnow() - self.stats['start_time']
            
            print(
                "📊 Auto monitor summary | duration=%s | urls=%s ips=%s domains=%s scans=%s threats=%s"
                % (
                    str(duration).split('.')[0],
                    self.stats['urls_detected'],
                    self.stats['ips_detected'],
                    self.stats['domains_detected'],
                    self.stats['scans_performed'],
                    self.stats['threats_found'],
                ),
                flush=True,
            )
    
    def get_stats(self) -> Dict:
        """Get current statistics"""
        return self.stats.copy()
