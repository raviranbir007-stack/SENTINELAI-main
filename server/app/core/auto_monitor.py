"""
Automatic Activity Monitor & Scanner
Continuously monitors system activity and automatically scans all detected artifacts
"""

import asyncio
import hashlib
import ipaddress
import json
import logging
import os
import platform
import re
import sqlite3
import shutil
import socket
import tempfile
import textwrap
import time
import urllib.request
from collections import deque
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Optional, Set
from urllib.parse import quote, urlparse

try:
    import pwd
except Exception:
    pwd = None

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
        self.scan_local_targets = str(
            os.getenv("SENTINEL_SCAN_LOCAL_TARGETS", "false")
        ).strip().lower() in {"1", "true", "yes", "on"}
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
        self._network_baseline_ready = False
        self.prompt_cooldown_seconds = max(
            300,
            int(os.getenv("SENTINEL_PROMPT_COOLDOWN", "900") or 900),
        )
        self.url_revisit_cooldown = max(
            10,
            int(os.getenv("SENTINEL_URL_REVISIT_COOLDOWN", "60") or 60),
        )
        self.browser_history_batch = max(
            200,
            int(os.getenv("SENTINEL_BROWSER_HISTORY_BATCH", "1000") or 1000),
        )
        self.download_poll_interval = max(
            10,
            int(os.getenv("SENTINEL_DOWNLOAD_POLL_INTERVAL", "15") or 15),
        )
        self.download_settle_seconds = max(
            5,
            int(os.getenv("SENTINEL_DOWNLOAD_SETTLE_SECONDS", "20") or 20),
        )
        self.download_max_file_size = max(
            1024 * 1024,
            int(os.getenv("SENTINEL_DOWNLOAD_MAX_FILE_SIZE", str(150 * 1024 * 1024)))
        )
        self._last_prompt_at: Dict[str, float] = {}
        self._trusted_recent_ips: Dict[str, float] = {}
        self._public_dns_cache: Dict[str, tuple[float, Optional[str]]] = {}
        self.trusted_infra_ips: Set[str] = {
            # Public DNS resolvers (high-volume benign traffic)
            '8.8.8.8', '8.8.4.4',
            '1.1.1.1', '1.0.0.1',
            '9.9.9.9', '149.112.112.112',
            '208.67.222.222', '208.67.220.220',
            '94.140.14.14', '94.140.15.15',
            # Common resolver IPv6 endpoints
            '2001:4860:4860::8888', '2001:4860:4860::8844',
            '2606:4700:4700::1111', '2606:4700:4700::1001',
            '2620:fe::fe', '2620:fe::9',
            # Known benign high-frequency cloud endpoint observed in baseline traffic
            '20.189.173.1',
        }
        
        # Track what we've already scanned to avoid duplicates
        self.scanned_urls: Set[str] = set()
        self.scanned_ips: Set[str] = set()
        self.scanned_domains: Set[str] = set()
        
        # Recent activity for deduplication
        self.recent_urls = deque(maxlen=1000)
        self.recent_ips = deque(maxlen=1000)
        self.recent_domains = deque(maxlen=1000)
        self.url_last_seen: Dict[str, float] = {}
        self.history_last_seen: Dict[str, int] = {}
        self.download_last_seen: Dict[str, tuple[int, int]] = {}
        self._browser_last_seen_count = 0
        self._browser_last_diag_at = 0.0
        
        # Statistics
        self.stats = {
            'urls_detected': 0,
            'ips_detected': 0,
            'domains_detected': 0,
            'downloads_detected': 0,
            'scans_performed': 0,
            'threats_found': 0,
            'start_time': None
        }

        # Chromium timestamp origin: microseconds since 1601-01-01
        self._chrome_epoch_offset = 11644473600
        
        # Whitelist common safe domains/IPs to reduce noise
        self.safe_domains = {
            # Google
            'google.com', 'googleapis.com', 'gstatic.com', 'googleusercontent.com',
            'googlevideo.com', 'youtube.com', 'ytimg.com', 'ggpht.com',
            # Microsoft
            'microsoft.com', 'windows.com', 'office.com', 'office365.com',
            'live.com', 'outlook.com', 'microsoftonline.com', 'azure.com',
            'azureedge.net', 'msocdn.com', 'skype.com', 'bing.com',
            # Apple
            'apple.com', 'icloud.com', 'mzstatic.com', 'aaplimg.com',
            # Amazon / AWS
            'amazon.com', 'amazonaws.com', 'cloudfront.net', 'awsstatic.com',
            # Mozilla / Firefox
            'mozilla.org', 'firefox.com', 'mozilla.net', 'mozgcp.net',
            # Meta
            'facebook.com', 'fbcdn.net', 'instagram.com', 'whatsapp.com',
            # Wikimedia / Wikipedia
            'wikipedia.org', 'wikimedia.org', 'mediawiki.org', 'wiktionary.org',
            'wikisource.org', 'wikidata.org', 'wikivoyage.org',
            # CDNs
            'cloudflare.com', 'cloudflare.net', 'cdn.cloudflare.com',
            'akamai.net', 'akamaihd.net', 'akamaiedge.net', 'akamaitechnologies.com',
            'fastly.net', 'fastlylb.net', 'fastly.com',
            'cdn.jsdelivr.net', 'jscdn.dev', 'jsdelivr.net',
            'bootstrapcdn.com', 'cloudinary.com', 'unpkg.com',
            # GitHub / Dev
            'github.com', 'githubusercontent.com', 'github.io', 'githubassets.com',
            'gitlab.com', 'gitlab.io',
            'stackoverflow.com', 'sstatic.net', 'stackexchange.com',
            'npmjs.com', 'pypi.org', 'python.org',
            'docker.com', 'docker.io',
            # Linux / OS updates
            'ubuntu.com', 'debian.org', 'fedoraproject.org', 'kernel.org',
            'archlinux.org', 'centos.org', 'redhat.com', 'suse.com',
            'linuxmint.com', 'kali.org',
            # Security / Threat Intel (these contact our own APIs)
            'virustotal.com', 'abuseipdb.com', 'shodan.io',
            'urlscan.io', 'hybrid-analysis.com',
            # Common news / productivity
            'nytimes.com', 'bbc.com', 'bbc.co.uk', 'reuters.com',
            'reddit.com', 'redd.it', 'redditmedia.com', 'redditstatic.com',
            'twitter.com', 'twimg.com', 'x.com',
            'linkedin.com', 'licdn.com',
            'slack.com', 'slack-edge.com', 'slackb.com',
            'zoom.us', 'zoomgov.com',
            'dropbox.com', 'dropboxstatic.com',
            # Local
            'localhost', '127.0.0.1', '0.0.0.0',
        }
        
        logger.info("🤖 Automatic Activity Monitor initialized")
    
    def _is_safe_domain(self, domain: str) -> bool:
        """Check if domain is in safe list"""
        domain_lower = (domain or "").strip().lower().rstrip('.')
        if ":" in domain_lower and not domain_lower.startswith('['):
            domain_lower = domain_lower.split(':', 1)[0]
        for safe in self.safe_domains:
            if domain_lower.endswith(safe):
                return True
        return False

    def _is_local_host(self, host: str) -> bool:
        """Return True for localhost/loopback names and addresses."""
        h = (host or "").strip().lower().rstrip('.')
        if not h:
            return False
        if h in {"localhost", "localhost.localdomain", "0.0.0.0", "::1", "127.0.0.1"}:
            return True
        if h.startswith("127."):
            return True
        try:
            ip_obj = ipaddress.ip_address(h)
            return ip_obj.is_loopback or ip_obj.is_private
        except Exception:
            return False

    def _is_local_artifact(self, artifact_type: str, value: str) -> bool:
        """Return True when artifact represents localhost/private target."""
        t = (artifact_type or "").strip().lower()
        v = (value or "").strip()
        if not v:
            return False

        if t == "ip":
            return self._is_private_ip(v)

        if t == "url":
            try:
                host = (urlparse(v).hostname or "").strip()
                return self._is_local_host(host)
            except Exception:
                return False

        if t == "domain":
            host = v.split(":", 1)[0].strip()
            return self._is_local_host(host)

        return False
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/local"""
        recent_ts = self._trusted_recent_ips.get(ip)
        if recent_ts and (time.time() - recent_ts) < 3600:
            return True
        if ip in self.trusted_infra_ips:
            return True
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
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname if hostname != ip else None
        except:
            return None

    def _resolve_public_ip_via_doh(self, domain: str) -> Optional[str]:
        """Resolve public A record via DNS-over-HTTPS, bypassing local hosts overrides."""
        host = (domain or "").strip().lower()
        if not host:
            return None

        now = time.time()
        cached = self._public_dns_cache.get(host)
        if cached and (now - cached[0]) < 300:
            return cached[1]

        try:
            url = f"https://cloudflare-dns.com/dns-query?name={quote(host)}&type=A"
            req = urllib.request.Request(
                url,
                headers={"accept": "application/dns-json", "user-agent": "sentinel-ai/monitor"},
            )
            with urllib.request.urlopen(req, timeout=2.5) as resp:
                payload = json.loads(resp.read().decode("utf-8", errors="ignore"))
            answers = payload.get("Answer") or []
            for ans in answers:
                data = str(ans.get("data") or "").strip()
                if not data:
                    continue
                try:
                    ip_obj = ipaddress.ip_address(data)
                    if not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local):
                        self._public_dns_cache[host] = (now, data)
                        return data
                except Exception:
                    continue
        except Exception:
            pass

        self._public_dns_cache[host] = (now, None)
        return None

    def _resolve_domain_ip(self, domain: str) -> Optional[str]:
        """Resolve a domain to a representative IP address (best effort)."""
        if not domain:
            return None
        try:
            ip_obj = ipaddress.ip_address(domain)
            return str(ip_obj)
        except Exception:
            pass

        host = (domain or "").split(":", 1)[0].strip().lower().rstrip('.')

        try:
            infos = socket.getaddrinfo(host, None)
            for info in infos:
                addr = info[4][0]
                if not addr:
                    continue
                # If a public host resolves locally (hosts file override), try public DNS fallback.
                if self._is_local_host(host) is False:
                    try:
                        ip_obj = ipaddress.ip_address(addr)
                        if ip_obj.is_loopback or ip_obj.is_private:
                            doh_ip = self._resolve_public_ip_via_doh(host)
                            if doh_ip:
                                return doh_ip
                            continue
                    except Exception:
                        pass
                return addr
        except Exception:
            return self._resolve_public_ip_via_doh(host)
        return None

    def _artifact_endpoint_details(self, artifact_type: str, value: str) -> tuple[Optional[str], Optional[str]]:
        """Return (hostname/domain, ip) context for URL/domain/IP prompts."""
        if artifact_type == 'ip':
            return self._get_hostname(value), value

        host = None
        if artifact_type == 'url':
            try:
                host = (urlparse(value).hostname or '').strip()
            except Exception:
                host = None
        elif artifact_type == 'domain':
            host = (value or '').strip()

        if not host:
            return None, None
        return host, self._resolve_domain_ip(host)

    def _build_allowlisted_result(self, artifact_type: str, value: str, reason: str) -> Dict:
        """Build a local SAFE result for allowlisted artifacts so monitoring stays informative."""
        return {
            "input": value,
            "input_type": artifact_type,
            "verdict": "clean",
            "confidence": 0.85,
            "summary": reason,
            "threat_indicators": [],
            "warnings": [],
            "recommendations": ["No action required."],
            "api_results": {
                "apis_called": [],
                "apis_expected": [],
                "api_status": {
                    "virustotal": {"name": "VirusTotal", "status": "not_applicable", "configured": bool(settings.VIRUSTOTAL_API_KEY), "applicable": artifact_type in {"url", "domain", "file_hash"}, "error": "Skipped: allowlisted target"},
                    "abuseipdb": {"name": "AbuseIPDB", "status": "not_applicable", "configured": bool(settings.ABUSEIPDB_API_KEY), "applicable": artifact_type == "ip", "error": "Skipped: allowlisted target"},
                    "shodan": {"name": "Shodan", "status": "not_applicable", "configured": bool(settings.SHODAN_API_KEY), "applicable": artifact_type == "ip", "error": "Skipped: allowlisted target"},
                    "urlscan": {"name": "URLScan.io", "status": "not_applicable", "configured": bool(settings.URLSCAN_API_KEY), "applicable": artifact_type in {"url", "domain"}, "error": "Skipped: allowlisted target"},
                    "hybrid_analysis": {"name": "Hybrid Analysis", "status": "not_applicable", "configured": bool(settings.HYBRIDANALYSIS_API_KEY), "applicable": artifact_type == "file_hash", "error": "Skipped: allowlisted target"},
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

        verdict = normalize_verdict(result)
        if verdict in {"clean", "safe", "unknown"}:
            return "No action required."
        if verdict == "suspicious":
            return "Need review."
        if verdict in {"malicious", "critical"}:
            return "Need action now."
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
        host_ip: Optional[str] = None,
    ):
        """Persist browser activity for dashboards and generated reports."""
        try:
            from .activity_database import activity_db

            result = result or {}
            forensic_metadata = result.get("forensic_metadata", {}) or {}
            
            # Extract verdict string, handling both enum and string types
            verdict_raw = result.get("verdict", "unknown")
            if hasattr(verdict_raw, "value"):  # Handle enum (e.g., ThreatLevel.CLEAN)
                verdict = verdict_raw.value.lower()
            elif hasattr(verdict_raw, "name"):  # Fallback to enum name
                verdict = verdict_raw.name.lower()
            else:
                verdict = str(verdict_raw).lower()
            
            verdict_map = {
                "clean": "safe",
                "safe": "safe",
                "unknown": "unknown",
                "suspicious": "suspicious",
                "malicious": "malicious",
                "critical": "malicious",
            }
            risk_level = verdict_map.get(verdict, verdict).upper()

            activity_db.log_website(
                {
                    "url": url,
                    "domain": domain,
                    "title": title,
                    "browser": browser_name,
                    "risk_level": risk_level,
                    "risk_score": round(float(result.get("confidence", 0.0)) * 100, 2),
                    "risk_factors": [item.get("indicator") for item in result.get("threat_indicators", []) if isinstance(item, dict)],
                    "scan_status": scan_status,
                    "scan_result": result,
                    "threat_verdict": verdict_map.get(verdict, verdict),
                    "corroboration_sources": forensic_metadata.get("unique_sources") or result.get("api_results", {}).get("apis_called", []),
                    "metadata": {
                        "auto_detected": True,
                        "browser": browser_name,
                        "host_ip": host_ip,
                        "recommended_action": self._get_recommended_action(result),
                    },
                }
            )

            # Sync counter so terminal monitor tracks sites correctly
            try:
                from .terminal_monitor import terminal_monitor
                terminal_monitor.log_website_activity(domain or url, risk_level)
            except Exception:
                pass

        except Exception as e:
            logger.debug(f"Unable to persist website activity for reporting: {e}")
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        try:
            parsed = urlparse(url)
            host = parsed.hostname or parsed.netloc or parsed.path.split('/')[0]
            return (host or "").strip().lower().rstrip('.')
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

            # Fallback: recursively discover additional profile layouts used by
            # browser variants/beta/dev channels.
            for history in root.rglob("History"):
                try:
                    if history.is_file():
                        found.append(history)
                except Exception:
                    continue
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

    def _guess_browser_label(self, path: Path, fallback: str = "Browser") -> str:
        """Best-effort browser label inference from a history DB path."""
        p = str(path).lower()
        mapping = [
            ("librewolf", "LibreWolf"),
            ("waterfox", "Waterfox"),
            ("firefox", "Firefox"),
            ("google-chrome", "Chrome"),
            ("chrome", "Chrome"),
            ("chromium", "Chromium"),
            ("brave", "Brave"),
            ("microsoft-edge", "Edge"),
            ("edge", "Edge"),
            ("opera", "Opera"),
            ("vivaldi", "Vivaldi"),
            ("arc", "Arc"),
            ("safari", "Safari"),
        ]
        for token, label in mapping:
            if token in p:
                return label
        return fallback

    def _discover_extra_history_targets(self, home: Path, system: str):
        """Discover additional browser history DBs from common and user-provided paths."""
        targets = []
        roots = []

        if system == "Linux":
            roots.extend([
                home / ".config",
                home / "snap",
                home / ".var/app",
            ])
        elif system == "Darwin":
            roots.extend([
                home / "Library/Application Support",
                home / "Library/Safari",
            ])
        elif system == "Windows":
            roots.extend([
                home / "AppData/Local",
                home / "AppData/Roaming",
            ])

        # Optional custom roots: colon-separated absolute paths.
        # Example: SENTINEL_BROWSER_HISTORY_PATHS="/mnt/profileA:/mnt/profileB"
        custom = os.getenv("SENTINEL_BROWSER_HISTORY_PATHS", "").strip()
        if custom:
            for item in custom.split(":" if system != "Windows" else ";"):
                item = item.strip()
                if not item:
                    continue
                try:
                    roots.append(Path(item).expanduser().resolve())
                except Exception:
                    continue

        for root in roots:
            if not root.exists():
                continue
            try:
                for db in root.rglob("places.sqlite"):
                    if db.is_file():
                        label = self._guess_browser_label(db, fallback="Firefox")
                        targets.append(("firefox", label, db))
                for db in root.rglob("History"):
                    if db.is_file():
                        label = self._guess_browser_label(db, fallback="Chromium")
                        targets.append(("chromium", label, db))
                for db in root.rglob("History.db"):
                    if db.is_file():
                        label = self._guess_browser_label(db, fallback="Safari")
                        engine = "safari" if label == "Safari" else "chromium"
                        targets.append((engine, label, db))
            except Exception:
                continue

        return targets

    def _discover_browser_history_targets(self):
        """Return list of browser history targets as (engine, browser_name, path)."""
        targets = []
        system = platform.system()
        home = self._monitor_home_dir()

        if system == "Linux":
            firefox_roots = [
                home / ".mozilla/firefox",
                home / "snap/firefox/common/.mozilla/firefox",
                home / ".var/app/org.mozilla.firefox/.mozilla/firefox",
                home / ".librewolf",
                home / ".waterfox",
            ]
            for ff in firefox_roots:
                if ff.exists():
                    label = "Firefox"
                    p = str(ff).lower()
                    if "librewolf" in p:
                        label = "LibreWolf"
                    elif "waterfox" in p:
                        label = "Waterfox"
                    targets.append(("firefox", label, ff))

            chromium_roots = {
                "Chrome": [
                    home / ".config/google-chrome",
                    home / "snap/google-chrome/common/.config/google-chrome",
                    home / ".config/google-chrome-beta",
                    home / ".config/google-chrome-unstable",
                ],
                "Chromium": [
                    home / ".config/chromium",
                    home / "snap/chromium/common/chromium",
                    home / ".var/app/org.chromium.Chromium/config/chromium",
                ],
                "Brave": [
                    home / ".config/BraveSoftware/Brave-Browser",
                    home / ".var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser",
                ],
                "Edge": [
                    home / ".config/microsoft-edge",
                    home / ".config/microsoft-edge-beta",
                    home / ".config/microsoft-edge-dev",
                ],
                "Opera": [
                    home / ".config/opera",
                    home / ".config/opera-beta",
                    home / ".config/opera-developer",
                    home / ".config/opera-gx",
                    home / ".var/app/com.opera.Opera/config/opera",
                ],
                "Vivaldi": [home / ".config/vivaldi"],
                "Arc": [home / ".config/Arc/User Data"],
            }
            for browser_name, roots in chromium_roots.items():
                for root in roots:
                    for history in self._discover_chromium_history_files(root):
                        targets.append(("chromium", browser_name, history))

        elif system == "Windows":
            if home:
                ff = home / "AppData/Roaming/Mozilla/Firefox/Profiles"
                if ff.exists():
                    targets.append(("firefox", "Firefox", ff))

                chromium_roots = {
                    "Chrome": [
                        home / "AppData/Local/Google/Chrome/User Data",
                        home / "AppData/Local/Google/Chrome Beta/User Data",
                        home / "AppData/Local/Google/Chrome SxS/User Data",
                    ],
                    "Edge": [
                        home / "AppData/Local/Microsoft/Edge/User Data",
                        home / "AppData/Local/Microsoft/Edge Beta/User Data",
                        home / "AppData/Local/Microsoft/Edge Dev/User Data",
                    ],
                    "Brave": [home / "AppData/Local/BraveSoftware/Brave-Browser/User Data"],
                    "Chromium": [home / "AppData/Local/Chromium/User Data"],
                    "Opera": [home / "AppData/Roaming/Opera Software/Opera Stable"],
                    "OperaGX": [home / "AppData/Roaming/Opera Software/Opera GX Stable"],
                    "Vivaldi": [home / "AppData/Local/Vivaldi/User Data"],
                    "Arc": [home / "AppData/Local/Arc/User Data"],
                }
                for browser_name, roots in chromium_roots.items():
                    for root in roots:
                        for history in self._discover_chromium_history_files(root):
                            targets.append(("chromium", browser_name, history))

        elif system == "Darwin":
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

        # Generic adaptive discovery to support browser variants/channels
        # beyond explicit path lists.
        targets.extend(self._discover_extra_history_targets(home, system))

        dedup = []
        seen = set()
        for engine, browser_name, path in targets:
            key = (engine, browser_name, str(path))
            if key in seen:
                continue
            seen.add(key)
            dedup.append((engine, browser_name, path))
        return dedup

    def _copy_sqlite_bundle(self, source_db: Path, temp_db_path: str) -> bool:
        """Copy SQLite DB plus WAL/SHM sidecars so recent browser visits are not missed."""
        try:
            shutil.copy2(source_db, temp_db_path)
            for suffix in ("-wal", "-shm"):
                src_side = Path(str(source_db) + suffix)
                dst_side = Path(str(temp_db_path) + suffix)
                try:
                    if src_side.exists():
                        shutil.copy2(src_side, dst_side)
                except Exception:
                    # Sidecars are best-effort; continue with main DB copy.
                    pass
            return True
        except Exception as exc:
            logger.debug(f"Failed to copy sqlite bundle {source_db}: {exc}")
            return False

    def _monitor_home_dir(self) -> Path:
        """Return the most likely desktop user home for browser history lookup."""
        explicit = os.getenv("SENTINEL_MONITOR_HOME", "").strip()
        if explicit:
            try:
                path = Path(explicit).expanduser().resolve()
                if path.exists():
                    return path
            except Exception:
                pass

        # If launched via sudo, prefer original user's home instead of /root.
        sudo_user = os.getenv("SUDO_USER", "").strip()
        if sudo_user and pwd is not None:
            try:
                sudo_home = Path(pwd.getpwnam(sudo_user).pw_dir)
                if sudo_home.exists():
                    return sudo_home
            except Exception:
                pass

        if platform.system() == "Windows":
            user_profile = os.getenv("USERPROFILE", "").strip()
            if user_profile:
                try:
                    p = Path(user_profile)
                    if p.exists():
                        return p
                except Exception:
                    pass

        return Path.home()

    def _download_directories(self) -> list[Path]:
        """Return existing download directories to watch for new files."""
        roots: list[Path] = []
        seen: set[str] = set()

        explicit = os.getenv("SENTINEL_DOWNLOAD_DIRS", "").strip()
        if explicit:
            for raw in explicit.split(os.pathsep):
                if not raw.strip():
                    continue
                try:
                    candidate = Path(raw).expanduser().resolve()
                    key = str(candidate)
                    if candidate.exists() and candidate.is_dir() and key not in seen:
                        roots.append(candidate)
                        seen.add(key)
                except Exception:
                    continue

        home = self._monitor_home_dir()
        for candidate in [home / "Downloads", home / "downloads"]:
            try:
                resolved = candidate.expanduser().resolve()
                key = str(resolved)
                if resolved.exists() and resolved.is_dir() and key not in seen:
                    roots.append(resolved)
                    seen.add(key)
            except Exception:
                continue

        return roots

    @staticmethod
    def _is_temporary_download(path: Path) -> bool:
        suffixes = {s.lower() for s in path.suffixes}
        return any(s in suffixes for s in {".crdownload", ".part", ".partial", ".tmp", ".download"})

    @staticmethod
    def _sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(chunk_size)
                if not chunk:
                    break
                digest.update(chunk)
        return digest.hexdigest()
    
    async def _scan_artifact(
        self,
        artifact_type: str,
        value: str,
        show_prompt: bool = True,
        prompt_context: str = "",
        use_external_apis: bool = False,
        metadata: Optional[Dict] = None,
    ):
        """Scan an artifact and log results - minimal terminal output, full database logging"""
        try:
            if not self.scan_callback:
                return None

            # Default: do not scan localhost/private artifacts unless explicitly enabled.
            if (not self.scan_local_targets) and self._is_local_artifact(artifact_type, value):
                return self._build_allowlisted_result(
                    artifact_type,
                    value,
                    "Localhost/private target skipped by default policy.",
                )
            
            # Get context info (hostname for IPs)
            context = ""
            if artifact_type == 'ip':
                hostname = self._get_hostname(value)
                if hostname:
                    context = f" → {hostname}"
                    # Skip scan if the IP resolves to a trusted domain
                    if self._is_safe_domain(hostname):
                        return self._build_allowlisted_result(
                            artifact_type, value,
                            f"IP resolves to trusted host '{hostname}' — no scan needed."
                        )

            # Perform scan (results go to database)
            try:
                result = await self.scan_callback(
                    artifact_type,
                    value,
                    use_external_apis=use_external_apis,
                    metadata=metadata or {},
                )
            except TypeError:
                result = await self.scan_callback(artifact_type, value)
            self.stats['scans_performed'] += 1
            
            # Check verdict — normalise enum string (e.g. ThreatLevel.SUSPICIOUS → 'suspicious')
            _raw = result.get('verdict', 'unknown')
            verdict = (getattr(_raw, 'value', None) or str(_raw)).lower().split('.')[-1]

            low_signal_suspicious = self._is_low_signal_suspicious(result, artifact_type)

            # Fully suppress noisy low-confidence single-source IP warnings
            # from automatic monitoring paths.
            if low_signal_suspicious:
                return result

            if verdict in ['malicious', 'suspicious', 'critical'] and not low_signal_suspicious:
                self.stats['threats_found'] += 1

            # Notify terminal monitor so scan/threat counters stay in sync
            try:
                from .terminal_monitor import terminal_monitor
                terminal_monitor.log_scan_activity(artifact_type, value, verdict)
            except Exception:
                pass

            # Detailed terminal output for each activity.
            # For network monitoring we keep SAFE/UNKNOWN results quiet to avoid spam.
            if self._should_emit_prompt(show_prompt, verdict, value, artifact_type, low_signal_suspicious):
                self._print_activity_prompt(artifact_type, value, result, context=f"{context}{prompt_context}")
            return result
            
        except Exception as e:
            logger.error(f"Error scanning {artifact_type} {value}: {e}")
            return {"verdict": "error", "error": str(e), "warnings": [str(e)]}

    def _print_activity_prompt(self, artifact_type: str, value: str, result: Dict, context: str = ""):
        """Print clean operator prompt in compact table format."""
        _v = result.get('verdict', 'unknown')
        # Handle Enum instances: ThreatLevel.SUSPICIOUS → 'suspicious'
        verdict_raw = (getattr(_v, 'value', None) or str(_v)).lower().split('.')[-1]
        confidence = result.get('confidence', 0.0)
        verdict_map = {
            'clean': 'SAFE',
            'safe': 'SAFE',
            'unknown': 'UNKNOWN',
            'suspicious': 'SUSPICIOUS',
            'malicious': 'MALICIOUS',
            'critical': 'MALICIOUS',
        }
        verdict_label = verdict_map.get(verdict_raw, verdict_raw.upper())

        action_text = self._get_recommended_action(result)

        type_labels = {'ip': 'IP', 'url': 'URL', 'domain': 'DOMAIN', 'file_hash': 'HASH'}
        type_label = type_labels.get(artifact_type, artifact_type.upper())
        endpoint_host, endpoint_ip = self._artifact_endpoint_details(artifact_type, value)
        conf_pct = f"{int(confidence * 100)}%"

        if endpoint_host and endpoint_ip:
            endpoint = f"{endpoint_host} [{endpoint_ip}]"
        else:
            endpoint = endpoint_host or endpoint_ip or value

        if artifact_type == 'url' and context and '[' in context:
            endpoint = f"{endpoint}{context}"

        title_emoji = "✅" if verdict_label == 'SAFE' else "⚠️" if verdict_label in {'SUSPICIOUS', 'UNKNOWN'} else "🚨"
        self._render_prompt_table(
            f"{title_emoji} LIVE ACTIVITY",
            [
                ("Type", type_label),
                ("Target", endpoint),
                ("Verdict", f"{verdict_label} ({conf_pct})"),
                ("Action", action_text),
            ],
        )

    @staticmethod
    def _render_prompt_table(title: str, rows: list[tuple]):
        """Render short activity box with auto word-wrap for readability."""
        width = max(84, min(132, shutil.get_terminal_size((110, 20)).columns))
        key_width = max((len(str(k)) for k, _ in rows), default=10)
        key_width = max(10, min(22, key_width + 1))
        val_width = max(24, width - key_width - 7)

        top = f"┌{'─' * (width - 2)}┐"
        mid = f"├{'─' * (width - 2)}┤"
        bottom = f"└{'─' * (width - 2)}┘"

        print(top, flush=True)
        print(f"│ {title[:width - 4]:<{width - 4}} │", flush=True)
        print(mid, flush=True)

        for key, value in rows:
            value_text = str(value if value is not None else '—')
            wrapped = textwrap.wrap(value_text, width=val_width) or ['—']
            for idx, line in enumerate(wrapped):
                left = str(key) if idx == 0 else ''
                print(f"│ {left:<{key_width}} │ {line:<{val_width}} │", flush=True)

        print(bottom, flush=True)

    def _is_low_signal_suspicious(self, result: Dict, artifact_type: str) -> bool:
        """Return True when suspicious verdict is low-confidence single-source noise."""
        _v = result.get('verdict', 'unknown')
        verdict = (getattr(_v, 'value', None) or str(_v)).lower().split('.')[-1]
        if verdict != 'suspicious' or artifact_type != 'ip':
            return False

        try:
            confidence = float(result.get('confidence', 0.0) or 0.0)
        except Exception:
            confidence = 0.0

        indicators = result.get('threat_indicators') or []
        warnings = result.get('warnings') or []
        summary_text = " ".join([
            str(result.get('summary', '') or ''),
            " ".join(str(w) for w in warnings),
            " ".join(str(r) for r in (result.get('recommendations') or [])),
        ]).lower()

        single_source_hint = (
            "single source" in summary_text
            or "low corroboration" in summary_text
            or "false positive" in summary_text
            or "limited corroboration" in summary_text
        )
        low_signal = len(indicators) <= 2 and len(warnings) <= 2
        return confidence <= 0.65 and low_signal and single_source_hint

    def _should_emit_prompt(
        self,
        show_prompt: bool,
        verdict: str,
        value: str,
        artifact_type: str,
        low_signal_suspicious: bool,
    ) -> bool:
        """Decide whether to print terminal prompt for this scan result."""
        if low_signal_suspicious and not show_prompt:
            return False

        should_show = show_prompt or verdict in ['malicious', 'suspicious', 'critical', 'error']
        if not should_show:
            return False

        key_value = value
        if artifact_type == 'url':
            try:
                key_value = value.lower() if show_prompt else (urlparse(value).hostname or value).lower()
            except Exception:
                key_value = value

        key = f"{artifact_type}:{key_value}:{verdict}"
        now = time.time()
        last = self._last_prompt_at.get(key, 0.0)
        cooldown = self.prompt_cooldown_seconds
        if artifact_type in {'url', 'domain'} and verdict in {'clean', 'safe', 'unknown'}:
            cooldown = 8 if artifact_type == 'url' and show_prompt else min(cooldown, 120)

        if (now - last) < cooldown:
            return False

        self._last_prompt_at[key] = now
        return True
    
    async def _monitor_file_access(self):
        """Monitor likely download folders and scan completed files by hash."""
        now = time.time()
        for root in self._download_directories():
            try:
                for entry in root.iterdir():
                    try:
                        if not entry.is_file():
                            continue
                        if self._is_temporary_download(entry):
                            continue

                        stat = entry.stat()
                        if stat.st_size <= 0 or stat.st_size > self.download_max_file_size:
                            continue
                        if (now - stat.st_mtime) < self.download_settle_seconds:
                            continue

                        file_key = str(entry.resolve())
                        fingerprint = (int(stat.st_mtime), int(stat.st_size))
                        if self.download_last_seen.get(file_key) == fingerprint:
                            continue

                        file_hash = await asyncio.to_thread(self._sha256_file, entry)
                        self.download_last_seen[file_key] = fingerprint
                        self.stats['downloads_detected'] += 1

                        await self._scan_artifact(
                            'file_hash',
                            file_hash,
                            show_prompt=True,
                            prompt_context=f" [download: {entry.name}]",
                            use_external_apis=True,
                            metadata={
                                'auto_detected': True,
                                'detection_source': 'download_monitor',
                                'download_path': file_key,
                                'file_name': entry.name,
                                'file_size': int(stat.st_size),
                                'download_directory': str(root),
                            },
                        )
                    except Exception as item_error:
                        logger.debug(f"Download monitoring item error for {entry}: {item_error}")
                        continue
            except Exception as e:
                logger.debug(f"Download monitoring error for {root}: {e}")
    
    async def _monitor_browser_activity(self):
        """Monitor browser history for NEW URLs user actually visits"""
        try:
            targets = self._discover_browser_history_targets()
            self._browser_last_seen_count = len(targets)
            now = time.time()
            if len(targets) == 0 and (now - self._browser_last_diag_at) > 60:
                self._render_prompt_table(
                    "ℹ️ LIVE ACTIVITY",
                    [
                        ("Type", "MONITOR"),
                        ("Target", "browser"),
                        ("Verdict", "IDLE"),
                        ("Action", "No history targets discovered"),
                    ],
                )
                self._browser_last_diag_at = now

            for engine, browser_name, history_path in targets:
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
        temp_file = tempfile.NamedTemporaryFile(
            prefix=f"{browser_name.lower()}_{os.getpid()}_",
            suffix=".db",
            delete=False,
        )
        temp_db = temp_file.name
        temp_file.close()
        try:
            if not self._copy_sqlite_bundle(history_path, temp_db):
                return
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()

            source_key = f"chromium:{browser_name}:{history_path}"
            default_cutoff = self._chrome_time_from_unix(time.time() - 120)
            cutoff = int(self.history_last_seen.get(source_key, default_cutoff) or default_cutoff)
            cursor.execute(
                """
                SELECT u.url, u.title, v.visit_time
                FROM visits v
                JOIN urls u ON v.url = u.id
                WHERE v.visit_time > ?
                  AND u.url LIKE 'http%'
                ORDER BY v.visit_time ASC
                LIMIT ?
                """,
                (cutoff, self.browser_history_batch),
            )

            max_seen = cutoff
            for url, title, visit_time in cursor.fetchall():
                try:
                    vt = int(visit_time or 0)
                except Exception:
                    vt = 0
                if vt <= cutoff:
                    continue
                max_seen = max(max_seen, vt)
                await self._process_detected_url(url, title or 'Untitled', browser_name)

            self.history_last_seen[source_key] = max_seen
            conn.close()
        finally:
            try:
                os.remove(temp_db)
            except Exception:
                pass

    async def _read_firefox_history(self, browser_name: str, firefox_target: Path):
        """Read Firefox-family history and scan new URLs."""
        history_dbs = []
        try:
            if firefox_target.is_file() and firefox_target.name == "places.sqlite":
                history_dbs = [firefox_target]
            elif (firefox_target / "places.sqlite").exists():
                history_dbs = [firefox_target / "places.sqlite"]
            else:
                for candidate in firefox_target.iterdir():
                    if not candidate.is_dir():
                        continue
                    db = candidate / "places.sqlite"
                    if db.exists():
                        history_dbs.append(db)
        except Exception:
            history_dbs = list(firefox_target.glob("*.default*/places.sqlite"))

        for history_db in history_dbs:
            if not history_db.exists():
                continue

            temp_file = tempfile.NamedTemporaryFile(prefix=f"firefox_{os.getpid()}_", suffix=".db", delete=False)
            temp_db = temp_file.name
            temp_file.close()
            try:
                if not self._copy_sqlite_bundle(history_db, temp_db):
                    continue
                conn = sqlite3.connect(temp_db)
                cursor = conn.cursor()

                source_key = f"firefox:{browser_name}:{history_db}"
                default_cutoff = int((time.time() - 120) * 1_000_000)
                cutoff = int(self.history_last_seen.get(source_key, default_cutoff) or default_cutoff)
                cursor.execute('''
                    SELECT p.url, p.title, hv.visit_date
                    FROM moz_historyvisits hv
                    JOIN moz_places p ON hv.place_id = p.id
                    WHERE hv.visit_date > ?
                    AND p.url LIKE 'http%'
                    ORDER BY hv.visit_date ASC
                    LIMIT ?
                ''', (cutoff, self.browser_history_batch))

                max_seen = cutoff
                for url, title, last_visit_date in cursor.fetchall():
                    try:
                        vt = int(last_visit_date or 0)
                    except Exception:
                        vt = 0
                    if vt <= cutoff:
                        continue
                    max_seen = max(max_seen, vt)
                    await self._process_detected_url(url, title or 'Untitled', browser_name)

                self.history_last_seen[source_key] = max_seen

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
            if not self._copy_sqlite_bundle(safari_db_path, temp_db):
                return
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()

            source_key = f"safari:{browser_name}:{safari_db_path}"
            # Safari timestamps are seconds since 2001-01-01
            safari_epoch_offset = 978307200
            default_cutoff = (time.time() - 120) - safari_epoch_offset
            cutoff = float(self.history_last_seen.get(source_key, int(default_cutoff)) or default_cutoff)
            cursor.execute('''
                SELECT hi.url, hv.title, hv.visit_time
                FROM history_visits hv
                JOIN history_items hi ON hv.history_item = hi.id
                WHERE hv.visit_time > ?
                AND hi.url LIKE 'http%'
                ORDER BY hv.visit_time ASC
                LIMIT ?
            ''', (cutoff, self.browser_history_batch))

            max_seen = int(cutoff)
            for url, title, visit_time in cursor.fetchall():
                try:
                    vt = int(float(visit_time or 0))
                except Exception:
                    vt = 0
                if vt <= cutoff:
                    continue
                max_seen = max(max_seen, vt)
                await self._process_detected_url(url, title or 'Untitled', browser_name)

            self.history_last_seen[source_key] = max_seen

            conn.close()
        finally:
            try:
                os.remove(temp_db)
            except Exception:
                pass

    async def _process_detected_url(self, url: str, title: str, browser_name: str):
        """Apply dedup/filtering and trigger scans for newly detected URLs."""
        now = time.time()
        last_seen = self.url_last_seen.get(url, 0.0)
        if now - last_seen < self.url_revisit_cooldown:
            return
        self.url_last_seen[url] = now

        self.recent_urls.append(url)
        domain = self._extract_domain(url)

        # Ignore local service URLs to avoid noisy localhost/domain prompts.
        if self._is_local_host(domain):
            return

        if self._is_safe_domain(domain):
            self.scanned_urls.add(url)
            self.stats['urls_detected'] += 1
            self.stats['scans_performed'] += 1
            resolved_ip = self._resolve_domain_ip(domain)
            if resolved_ip:
                self._trusted_recent_ips[resolved_ip] = time.time()
            safe_result = self._build_allowlisted_result(
                'url', url, f"Allowlisted domain '{domain}' recognized as trusted traffic."
            )
            if self._should_emit_prompt(True, 'clean', url, 'url', False):
                self._print_activity_prompt('url', url, safe_result, context=f" [{browser_name}]")
            self._log_website_activity(
                url,
                domain,
                title,
                browser_name,
                safe_result,
                scan_status="allowlisted",
                host_ip=resolved_ip,
            )
            return

        self.scanned_urls.add(url)
        self.stats['urls_detected'] += 1

        resolved_ip = self._resolve_domain_ip(domain) if domain else None
        result = await self._scan_artifact('url', url, show_prompt=True, prompt_context=f" [{browser_name}]")
        self._log_website_activity(
            url,
            domain,
            title,
            browser_name,
            result,
            scan_status="completed",
            host_ip=resolved_ip,
        )

        if domain:
            if resolved_ip and (self._is_safe_domain(domain) or normalize_verdict(result) in {"clean", "safe"}):
                self._trusted_recent_ips[resolved_ip] = time.time()

        if domain not in self.scanned_domains and not self._is_safe_domain(domain):
            self.scanned_domains.add(domain)
            self.stats['domains_detected'] += 1
            asyncio.create_task(self._scan_artifact('domain', domain, show_prompt=False))
    
    async def _monitor_network_connections(self):
        """Monitor active network connections with low-noise public-IP scanning."""
        if not self.enable_network_monitoring or not psutil:
            return

        now = time.time()
        if now - self.last_network_scan_at < self.network_poll_interval:
            return
        self.last_network_scan_at = now

        seen_this_cycle = set()

        # First cycle should establish a quiet baseline from already-open
        # connections, not treat them as newly suspicious startup activity.
        if not self._network_baseline_ready:
            try:
                for conn in psutil.net_connections(kind='inet'):
                    try:
                        if getattr(conn, 'status', '') != 'ESTABLISHED' or not getattr(conn, 'raddr', None):
                            continue
                        ip = conn.raddr.ip
                        if not ip or self._is_private_ip(ip):
                            continue
                        self.ip_last_seen[ip] = now
                    except Exception:
                        continue
            except Exception as e:
                logger.debug(f"Network baseline setup error: {e}")

            self._network_baseline_ready = True
            return

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

                    try:
                        from .terminal_monitor import terminal_monitor
                        terminal_monitor.log_connection_activity()
                    except Exception:
                        pass

                    hostname = self._get_hostname(ip)
                    if hostname and self._is_safe_domain(hostname):
                        continue

                    result = await self._scan_artifact('ip', ip, show_prompt=False)
                    vr = (result or {}).get('verdict', 'unknown')
                    verdict = (getattr(vr, 'value', None) or str(vr)).lower().split('.')[-1]
                    indicators = (result or {}).get('threat_indicators') or []
                    conf = float((result or {}).get('confidence', 0.0) or 0.0)
                    actionable_suspicious = verdict == 'suspicious' and conf >= 0.7 and len(indicators) >= 2
                    if verdict in {'malicious', 'critical', 'error'} or actionable_suspicious:
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
                await self._monitor_file_access()
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
        monitor_home = self._monitor_home_dir()
        browser_targets = self._discover_browser_history_targets()
        print(
            "",
            flush=True,
        )
        self._render_prompt_table(
            "🛡️ SENTINEL-AI MONITOR STARTED",
            [
                ("Mode", mode),
                ("Auto Scan", "ON"),
                ("IP Cooldown", f"{self.network_scan_cooldown}s"),
                ("Browser Source", str(monitor_home)),
                ("Targets", len(browser_targets)),
            ],
        )
        
        # Start monitoring loop
        await self._monitoring_loop()
    
    def stop(self):
        """Stop monitoring"""
        self.running = False
        
        # Print summary
        if self.stats['start_time']:
            duration = datetime.utcnow() - self.stats['start_time']
            
            duration_str = str(duration).split('.')[0]
            self._render_prompt_table(
                "◈ MONITOR SESSION END",
                [
                    ("Uptime", duration_str),
                    ("URLs", self.stats['urls_detected']),
                    ("IPs", self.stats['ips_detected']),
                    ("Scans", self.stats['scans_performed']),
                    ("Threats", self.stats['threats_found']),
                ],
            )
    
    def get_stats(self) -> Dict:
        """Get current statistics"""
        return self.stats.copy()


def normalize_verdict(result: Optional[Dict]) -> str:
    if not isinstance(result, dict):
        return "unknown"
    raw = result.get("verdict", "unknown")
    return (getattr(raw, "value", None) or str(raw)).lower().split('.')[-1]
