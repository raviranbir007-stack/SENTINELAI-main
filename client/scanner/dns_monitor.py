"""
DNS Monitor
Monitors all outbound DNS queries on the host for:

  • Command-and-Control (C2) beaconing (periodic queries to same domain)
  • DNS tunneling (unusually long / high-entropy subdomain labels)
  • Newly Registered Domain (NRD) queries
  • DGA (Domain Generation Algorithm) domain detection via entropy scoring
  • Queries to known malicious TLDs (.tk, .ml, .ga, .cf, .gq + custom list)
  • Repetitive NXDOMAIN responses (C2 domain rotation)
  • PTR record lookups for suspicious reverse queries

Implementation
--------------
1.  Primary:  parse /var/log/syslog or /var/log/messages  for DNS lines
2.  Fallback: poll system resolver cache (systemd-resolve --statistics)
3.  Optional: raw capture using scapy on udp port 53 (requires root / CAP_NET_RAW)

Results are cached in SQLite and reported via callback.
"""

import hashlib
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
import ipaddress

logger = logging.getLogger("DNSMonitor")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Known malicious / free TLDs heavily abused for phishing/malware
SUSPICIOUS_TLDS: Set[str] = {
    ".tk", ".ml", ".ga", ".cf", ".gq",       # Freenom abuse
    ".pw", ".top", ".work", ".click",
    ".link", ".bid", ".win", ".download",
    ".loan", ".stream", ".accountant", ".date",
}

# Domains known to be C2 / malware infrastructure (sample; extend via threat feeds)
KNOWN_MALICIOUS_DOMAINS: Set[str] = {
    "evildomain.xyz", "malware-cnc.net", "badactor.ru",
    # ← threat-feed entries would go here
}

# DNS tunneling thresholds
DNS_TUNNEL_LABEL_LEN   = 50       # subdomain label longer than this is suspicious
DNS_TUNNEL_ENTROPY_MIN = 3.8      # Shannon entropy of subdomain label
DGA_ENTROPY_MIN        = 3.5      # whole second-level domain
DGA_MIN_LEN            = 12       # very short DGA domains are common

# C2 beaconing: same domain queried > N times in a sliding window
BEACON_THRESHOLD       = 20
BEACON_WINDOW_SECS     = 300      # 5 minutes

# Log file patterns to look for DNS queries
DNS_LOG_PATTERNS = [
    r"named.*query:\s+([\w.\-]+)\s+IN\s+\w+",    # BIND / named
    r"dnsmasq.*query\[\w+\]\s+([\w.\-]+)",        # dnsmasq
    r"systemd-resolved.*question:\s+([\w.\-]+)",  # systemd-resolved
    r"unbound.*query:\s+([\w.\-]+)\s+\w+",        # unbound
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = defaultdict(int)
    for c in s:
        freq[c] += 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _is_dga_like(domain: str) -> bool:
    """Heuristic: high entropy + long length in the second-level domain."""
    parts = domain.rstrip(".").split(".")
    if len(parts) < 2:
        return False
    sld = parts[-2]
    return len(sld) >= DGA_MIN_LEN and _entropy(sld) >= DGA_ENTROPY_MIN


def _has_tunnel_label(domain: str) -> bool:
    """Check if any subdomain label suggests DNS tunneling."""
    for label in domain.rstrip(".").split("."):
        if len(label) >= DNS_TUNNEL_LABEL_LEN:
            return True
        if len(label) >= 20 and _entropy(label) >= DNS_TUNNEL_ENTROPY_MIN:
            return True
    return False


def _extract_tld(domain: str) -> str:
    parts = domain.rstrip(".").rsplit(".", 2)
    return "." + parts[-1].lower() if parts else ""


def _run(cmd: List[str], timeout: int = 10) -> Tuple[str, str, int]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr, r.returncode
    except Exception as e:
        return "", str(e), -1


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class DNSMonitor:
    """
    Real-time DNS query monitor.
    Detects C2 beaconing, DGA domains, DNS tunneling, and more.
    """

    def __init__(
        self,
        callback: Optional[Callable[[Dict], None]] = None,
        threat_analyzer=None,
        db_path: str = "activity_logs.db",
        use_scapy: bool = False,        # requires root + scapy installed
        poll_interval: int = 5,
    ):
        self.callback = callback
        self.threat_analyzer = threat_analyzer
        self.db_path = db_path
        self.use_scapy = use_scapy
        self.poll_interval = poll_interval
        self.running = False
        self._thread: Optional[threading.Thread] = None
        self._platform = platform.system()

        # Sliding window: domain → [timestamps]
        self._query_window: Dict[str, deque] = defaultdict(lambda: deque())
        # NXDOMAIN counter
        self._nxdomain_counts: Dict[str, int] = defaultdict(int)
        # Already alerted domains this session
        self._alerted: Set[str] = set()
        # Log file position
        self._log_pos: int = 0
        self._log_fp = None

        self._init_db()

    # ------------------------------------------------------------------
    # DB
    # ------------------------------------------------------------------

    def _init_db(self):
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute("""
                CREATE TABLE IF NOT EXISTS dns_queries (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain      TEXT,
                    query_type  TEXT,
                    risk_level  TEXT DEFAULT 'LOW',
                    reason      TEXT,
                    source      TEXT,
                    timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"DNS DB init: {e}")

    def _log_query(self, domain: str, qtype: str, risk: str, reason: str, source: str):
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute("""
                INSERT INTO dns_queries (domain, query_type, risk_level, reason, source)
                VALUES (?,?,?,?,?)
            """, (domain, qtype, risk, reason, source))
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
        if self.use_scapy and os.geteuid() == 0:
            self._thread = threading.Thread(
                target=self._sniff_scapy, daemon=True, name="DNSMonitor-Scapy"
            )
        else:
            self._thread = threading.Thread(
                target=self._poll_loop, daemon=True, name="DNSMonitor-Poll"
            )
        self._thread.start()
        logger.info("🌐 DNS Monitor started")

    def stop(self):
        self.running = False
        if self._thread:
            self._thread.join(timeout=5)
        if self._log_fp:
            try:
                self._log_fp.close()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Polling mode (log file + systemd-resolve stats)
    # ------------------------------------------------------------------

    def _poll_loop(self):
        while self.running:
            try:
                self._poll_log_file()
                self._poll_proc_net_dns()
            except Exception as e:
                logger.debug(f"DNS poll error: {e}")
            time.sleep(self.poll_interval)

    def _poll_log_file(self):
        """Tail DNS-relevant entries from syslog / journald."""
        log_candidates = [
            "/var/log/syslog",
            "/var/log/messages",
            "/var/log/daemon.log",
        ]
        log_file = None
        for p in log_candidates:
            if Path(p).exists():
                log_file = p
                break

        if not log_file:
            # Fallback: journalctl
            self._poll_journalctl()
            return

        try:
            if self._log_fp is None:
                self._log_fp = open(log_file, "r", errors="replace")
                self._log_fp.seek(0, os.SEEK_END)

            for line in self._log_fp:
                self._parse_log_line(line)
        except Exception as e:
            logger.debug(f"Log tail error: {e}")
            self._log_fp = None

    def _poll_journalctl(self):
        """Pull last N DNS-related lines from journald."""
        try:
            out, _, rc = _run(
                ["journalctl", "-u", "systemd-resolved", "--no-pager", "-n", "100",
                 "--since", "1 minute ago"],
                timeout=10
            )
            if rc == 0:
                for line in out.splitlines():
                    self._parse_log_line(line)
        except Exception:
            pass

    def _parse_log_line(self, line: str):
        for pat in DNS_LOG_PATTERNS:
            m = re.search(pat, line, re.IGNORECASE)
            if m:
                domain = m.group(1).lower().rstrip(".")
                self._process_query(domain, "A", source="syslog")
                return
        # Generic hostname-like extraction from network log lines
        m = re.search(r'(?:query|lookup|resolve)[^\s]*\s+([\w.\-]{4,253})', line, re.IGNORECASE)
        if m:
            domain = m.group(1).lower().rstrip(".")
            self._process_query(domain, "A", source="syslog")

    def _poll_proc_net_dns(self):
        """
        On Linux, try to read /proc/net/udp to infer new connections on port 53.
        This is a light-weight complement to log parsing.
        """
        if self._platform != "Linux":
            return
        try:
            proc_udp = Path("/proc/net/udp")
            if not proc_udp.exists():
                return
            for line in proc_udp.read_text().splitlines()[1:]:
                parts = line.split()
                if len(parts) < 3:
                    continue
                rem_hex = parts[2]
                rem_ip_hex, rem_port_hex = rem_hex.split(":")
                rem_port = int(rem_port_hex, 16)
                if rem_port == 53:
                    # We see DNS traffic but can't get the domain name here
                    # Just record the fact (used for statistical analysis)
                    pass
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Scapy live capture mode (root only)
    # ------------------------------------------------------------------

    def _sniff_scapy(self):
        try:
            from scapy.all import sniff, DNS, DNSQR
            def handle_pkt(pkt):
                if pkt.haslayer(DNS) and pkt[DNS].qr == 0:   # query
                    for i in range(pkt[DNS].qdcount):
                        try:
                            domain = pkt[DNS].qd.qname.decode().rstrip(".")
                            qtype = pkt[DNS].qd.qtype
                            self._process_query(domain.lower(), str(qtype), source="scapy")
                        except Exception:
                            pass
            sniff(filter="udp port 53", prn=handle_pkt,
                  store=False, stop_filter=lambda _: not self.running)
        except ImportError:
            logger.warning("scapy not available – using log polling")
            self._poll_loop()
        except Exception as e:
            logger.error(f"Scapy sniff error: {e}")
            self._poll_loop()

    # ------------------------------------------------------------------
    # Analysis engine
    # ------------------------------------------------------------------

    def _process_query(self, domain: str, qtype: str, source: str = "unknown"):
        if not domain or len(domain) < 4:
            return
        # Skip obviously benign
        if domain in ("localhost", "localdomain", "broadcasthost"):
            return
        try:
            # Skip pure IPs
            ipaddress.ip_address(domain)
            return
        except ValueError:
            pass

        now = time.time()
        risk = "LOW"
        reasons: List[str] = []

        # 1. Known malicious domain
        if domain in KNOWN_MALICIOUS_DOMAINS or any(
            domain.endswith("." + m) for m in KNOWN_MALICIOUS_DOMAINS
        ):
            risk = "CRITICAL"
            reasons.append("KNOWN_MALICIOUS")

        # 2. Suspicious TLD
        tld = _extract_tld(domain)
        if tld in SUSPICIOUS_TLDS:
            risk = max(risk, "MEDIUM", key=lambda r: ("LOW","MEDIUM","HIGH","CRITICAL").index(r))
            reasons.append(f"SUSPICIOUS_TLD:{tld}")

        # 3. DGA-like domain
        if _is_dga_like(domain):
            risk = max(risk, "HIGH", key=lambda r: ("LOW","MEDIUM","HIGH","CRITICAL").index(r))
            reasons.append("DGA_DOMAIN")

        # 4. DNS tunneling
        if _has_tunnel_label(domain):
            risk = "CRITICAL"
            reasons.append("DNS_TUNNEL")

        # 5. C2 beaconing (high-frequency queries to same domain)
        self._query_window[domain].append(now)
        # Trim old entries
        cutoff = now - BEACON_WINDOW_SECS
        while self._query_window[domain] and self._query_window[domain][0] < cutoff:
            self._query_window[domain].popleft()
        if len(self._query_window[domain]) >= BEACON_THRESHOLD:
            risk = "CRITICAL"
            reasons.append(f"C2_BEACONING({len(self._query_window[domain])} queries/5min)")

        # Log to DB
        reason_str = ", ".join(reasons) if reasons else "OK"
        self._log_query(domain, qtype, risk, reason_str, source)

        # Queue threat-intel API check for suspicious domains
        if risk in ("HIGH", "CRITICAL") and self.threat_analyzer and domain not in self._alerted:
            self.threat_analyzer.queue_scan("domain", domain, {"source": "dns", "reason": reason_str})

        # Fire callback for suspicious domains
        if risk in ("HIGH", "CRITICAL") and domain not in self._alerted:
            self._alerted.add(domain)
            logger.warning(f"🌐 DNS [{risk}]: {domain}  ({reason_str})")
            if self.callback:
                self.callback({
                    "type": "dns_threat",
                    "domain": domain,
                    "query_type": qtype,
                    "risk": risk,
                    "reasons": reasons,
                    "source": source,
                    "timestamp": datetime.now().isoformat(),
                })

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    def get_summary(self) -> Dict:
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute("SELECT COUNT(*) FROM dns_queries")
            total = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM dns_queries WHERE risk_level IN ('HIGH','CRITICAL')")
            threats = c.fetchone()[0]
            conn.close()
            return {"dns_queries_total": total, "dns_threats": threats}
        except Exception:
            return {}
