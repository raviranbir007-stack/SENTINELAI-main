"""
Email Threat Monitor
Monitors local email clients and IMAP/POP3 mailboxes for:
  • Phishing links (checked via VirusTotal / URLScan / IPQualityScore)
  • Malicious attachments (VirusTotal hash / HybridAnalysis)
  • Spoofed sender domains (SPF/DKIM-like heuristics)
  • Suspicious keywords (credential harvesting, urgent wire-transfer, etc.)
  • Executable / macro-enabled attachments (.exe, .doc with macros, .xlsm …)

Supports
--------
* Thunderbird profile  (local Mbox / Maildir parsing)
* Generic IMAP polling  (any provider)
* Generic POP3 polling
* Watching a local mailbox file / directory
"""

import email
import email.policy
import hashlib
import imaplib
import logging
import math
import os
import poplib
import re
import sqlite3
import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta
from email import message_from_bytes, message_from_string
from email.header import decode_header
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger("EmailMonitor")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DANGEROUS_ATTACHMENT_EXTS = {
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js",
    ".jse", ".wsf", ".wsh", ".msi", ".scr", ".pif", ".com", ".hta",
    ".cpl", ".reg", ".lnk", ".inf", ".jar", ".docm", ".xlsm",
    ".pptm", ".dotm", ".xltm", ".xlam", ".ppam",
}

PHISHING_KEYWORDS = [
    r"verify\s+your\s+account",
    r"click\s+here\s+to\s+confirm",
    r"your\s+account\s+will\s+be\s+suspended",
    r"update\s+your\s+payment",
    r"wire\s+transfer",
    r"urgent\s+action\s+required",
    r"password\s+expired",
    r"login\s+immediately",
    r"validate\s+your\s+identity",
    r"billing\s+information\s+required",
    r"you\s+have\s+won",
    r"claim\s+your\s+prize",
    r"crypt(?:o|currency)\s+wallet",
    r"unusual\s+sign[\-\s]in\s+activity",
    r"two[\-\s]factor\s+authentication\s+bypass",
]

URL_PATTERN = re.compile(
    r"https?://[^\s\"'<>\]\)\}]+", re.IGNORECASE
)

SPOOFED_DOMAINS = {
    "paypa1.com", "g00gle.com", "amaz0n.com", "micros0ft.com",
    "appl€.com", "faceb00k.com", "linkedln.com",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _decode_header_str(raw: str) -> str:
    parts = []
    for fragment, enc in decode_header(raw or ""):
        if isinstance(fragment, bytes):
            parts.append(fragment.decode(enc or "utf-8", errors="replace"))
        else:
            parts.append(fragment)
    return "".join(parts)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _extract_urls(text: str) -> List[str]:
    return URL_PATTERN.findall(text)


def _extract_domain(addr: str) -> str:
    m = re.search(r"@([\w.\-]+)", addr or "")
    return m.group(1).lower() if m else ""


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class EmailMonitor:
    """
    Monitors email sources for threats and fires a *callback* for each
    suspicious message or attachment.
    """

    def __init__(
        self,
        callback: Optional[Callable[[Dict], None]] = None,
        threat_analyzer=None,
        db_path: str = "activity_logs.db",
        imap_host: str = "",
        imap_port: int = 993,
        imap_user: str = "",
        imap_pass: str = "",
        pop3_host: str = "",
        pop3_port: int = 995,
        pop3_user: str = "",
        pop3_pass: str = "",
        scan_local_thunderbird: bool = True,
        poll_interval: int = 60,
    ):
        self.callback = callback
        self.threat_analyzer = threat_analyzer
        self.db_path = db_path
        self.imap_config = dict(host=imap_host, port=imap_port,
                                user=imap_user, password=imap_pass)
        self.pop3_config = dict(host=pop3_host, port=pop3_port,
                                user=pop3_user, password=pop3_pass)
        self.scan_local_thunderbird = scan_local_thunderbird
        self.poll_interval = poll_interval
        self.running = False
        self._thread: Optional[threading.Thread] = None
        self._seen_msg_ids: set = set()
        self._init_db()

    # ------------------------------------------------------------------
    # DB
    # ------------------------------------------------------------------

    def _init_db(self):
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute("""
                CREATE TABLE IF NOT EXISTS email_threats (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    message_id      TEXT,
                    sender          TEXT,
                    subject         TEXT,
                    threat_type     TEXT,
                    risk_level      TEXT DEFAULT 'UNKNOWN',
                    details         TEXT,
                    timestamp       DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Email DB init: {e}")

    def _log_threat(self, msg_id: str, sender: str, subject: str,
                     threat: str, risk: str, details: str):
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute("""
                INSERT INTO email_threats
                    (message_id, sender, subject, threat_type, risk_level, details)
                VALUES (?,?,?,?,?,?)
            """, (msg_id, sender, subject, threat, risk, details))
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
            target=self._monitor_loop, daemon=True, name="EmailMonitor"
        )
        self._thread.start()
        logger.info("📧 Email Monitor started")

    def stop(self):
        self.running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("Email Monitor stopped")

    # ------------------------------------------------------------------
    # Monitor loop
    # ------------------------------------------------------------------

    def _monitor_loop(self):
        while self.running:
            try:
                if self.scan_local_thunderbird:
                    self._scan_thunderbird()
                if self.imap_config["host"]:
                    self._poll_imap()
                if self.pop3_config["host"]:
                    self._poll_pop3()
            except Exception as e:
                logger.error(f"Email monitor loop error: {e}")
            time.sleep(self.poll_interval)

    # ------------------------------------------------------------------
    # Thunderbird local scan
    # ------------------------------------------------------------------

    def _thunderbird_profiles(self) -> List[Path]:
        paths: List[Path] = []
        candidates = [
            Path.home() / ".thunderbird",
            Path.home() / "AppData" / "Roaming" / "Thunderbird" / "Profiles",
            Path.home() / "Library" / "Thunderbird" / "Profiles",
        ]
        for base in candidates:
            if base.exists():
                for p in base.iterdir():
                    if p.is_dir():
                        paths.append(p)
        return paths

    def _scan_thunderbird(self):
        for profile in self._thunderbird_profiles():
            mail_root = profile / "Mail"
            imap_root = profile / "ImapMail"
            for root_dir in (mail_root, imap_root):
                if root_dir.exists():
                    self._scan_mbox_dir(root_dir)

    def _scan_mbox_dir(self, root: Path):
        for fpath in root.rglob("*"):
            if fpath.suffix in (".msf", ".dat") or fpath.is_dir():
                continue
            try:
                text = fpath.read_bytes()
                if text.startswith(b"From ") or b"Content-Type:" in text[:4096]:
                    self._parse_mbox(text, source=str(fpath))
            except Exception:
                pass

    def _parse_mbox(self, raw: bytes, source: str = "local"):
        """Parse an mbox file and analyse each message."""
        text = raw.decode("utf-8", errors="replace")
        parts = re.split(r"\nFrom ", text)
        for part in parts:
            try:
                msg = message_from_string("From " + part if not part.startswith("From ") else part)
                self._analyse_message(msg, source=source)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # IMAP polling
    # ------------------------------------------------------------------

    def _poll_imap(self):
        try:
            cfg = self.imap_config
            conn = imaplib.IMAP4_SSL(cfg["host"], cfg["port"])
            conn.login(cfg["user"], cfg["password"])
            conn.select("INBOX")
            _, data = conn.search(None, "UNSEEN")
            for uid in (data[0] or b"").split():
                _, msg_data = conn.fetch(uid, "(RFC822)")
                if msg_data and msg_data[0]:
                    raw = msg_data[0][1]
                    msg = message_from_bytes(raw, policy=email.policy.default)
                    self._analyse_message(msg, source="imap")
            conn.logout()
        except Exception as e:
            logger.debug(f"IMAP poll error: {e}")

    # ------------------------------------------------------------------
    # POP3 polling
    # ------------------------------------------------------------------

    def _poll_pop3(self):
        try:
            cfg = self.pop3_config
            conn = poplib.POP3_SSL(cfg["host"], cfg["port"])
            conn.user(cfg["user"])
            conn.pass_(cfg["password"])
            count, _ = conn.stat()
            for i in range(max(1, count - 9), count + 1):    # last 10
                raw_lines = conn.retr(i)[1]
                raw = b"\r\n".join(raw_lines)
                msg = message_from_bytes(raw, policy=email.policy.default)
                self._analyse_message(msg, source="pop3")
            conn.quit()
        except Exception as e:
            logger.debug(f"POP3 poll error: {e}")

    # ------------------------------------------------------------------
    # Message analysis engine
    # ------------------------------------------------------------------

    def _analyse_message(self, msg, source: str = "unknown"):
        try:
            msg_id = msg.get("Message-ID", "") or str(hash(msg.get("Subject", "")))
            if msg_id in self._seen_msg_ids:
                return
            self._seen_msg_ids.add(msg_id)

            sender_raw = msg.get("From", "")
            sender = _decode_header_str(sender_raw)
            subject = _decode_header_str(msg.get("Subject", "(no subject)"))
            date_str = msg.get("Date", "")

            # Collect body text
            body = self._get_body(msg)

            # ---- Threat checks ----
            threats: List[Dict] = []

            # 1. Phishing keyword detection
            phishing_hits = self._check_phishing_keywords(body)
            if phishing_hits:
                threats.append({
                    "type": "PHISHING_KEYWORDS",
                    "risk": "HIGH",
                    "details": f"Matched: {', '.join(phishing_hits[:5])}",
                })

            # 2. URL extraction + threat analysis
            urls = _extract_urls(body)
            for url in urls[:20]:           # limit API calls
                domain = urlparse(url).netloc.lower()
                if domain in SPOOFED_DOMAINS:
                    threats.append({
                        "type": "SPOOFED_DOMAIN",
                        "risk": "CRITICAL",
                        "details": f"Known spoofed domain: {domain}",
                    })
                if self.threat_analyzer:
                    self.threat_analyzer.queue_scan("url", url,
                                                     {"source": "email", "sender": sender})

            # 3. Attachment analysis
            for att_threat in self._check_attachments(msg, msg_id, sender):
                threats.append(att_threat)

            # 4. Sender domain spoofing
            domain_threat = self._check_sender_domain(sender)
            if domain_threat:
                threats.append(domain_threat)

            # 5. Header anomalies (Reply-To mismatch etc.)
            header_threat = self._check_header_anomalies(msg)
            if header_threat:
                threats.append(header_threat)

            # --- Report ---
            if threats:
                max_risk = self._max_risk([t["risk"] for t in threats])
                logger.warning(
                    f"📧 Email threat [{max_risk}]: from={sender}  subj={subject[:60]}  "
                    f"threats={[t['type'] for t in threats]}"
                )
                for t in threats:
                    self._log_threat(msg_id, sender, subject,
                                     t["type"], t["risk"], t["details"])

                if self.callback:
                    self.callback({
                        "type": "email_threat",
                        "message_id": msg_id,
                        "sender": sender,
                        "subject": subject,
                        "date": date_str,
                        "source": source,
                        "threats": threats,
                        "risk": max_risk,
                        "urls_found": len(urls),
                        "timestamp": datetime.now().isoformat(),
                    })

        except Exception as e:
            logger.debug(f"Message analysis error: {e}")

    # ------------------------------------------------------------------
    # Sub-checks
    # ------------------------------------------------------------------

    def _get_body(self, msg) -> str:
        parts = []
        if msg.is_multipart():
            for part in msg.walk():
                ct = part.get_content_type()
                if ct in ("text/plain", "text/html"):
                    try:
                        payload = part.get_payload(decode=True) or b""
                        parts.append(payload.decode("utf-8", errors="replace"))
                    except Exception:
                        pass
        else:
            try:
                payload = msg.get_payload(decode=True) or b""
                parts.append(payload.decode("utf-8", errors="replace"))
            except Exception:
                pass
        return " ".join(parts)

    def _check_phishing_keywords(self, body: str) -> List[str]:
        hits = []
        bl = body.lower()
        for pat in PHISHING_KEYWORDS:
            if re.search(pat, bl):
                hits.append(pat)
        return hits

    def _check_attachments(self, msg, msg_id: str, sender: str) -> List[Dict]:
        threats = []
        if not msg.is_multipart():
            return threats
        for part in msg.walk():
            filename = part.get_filename()
            if not filename:
                continue
            filename = _decode_header_str(filename)
            ext = Path(filename).suffix.lower()
            if ext in DANGEROUS_ATTACHMENT_EXTS:
                payload = part.get_payload(decode=True) or b""
                fhash = _sha256_bytes(payload)
                threats.append({
                    "type": "DANGEROUS_ATTACHMENT",
                    "risk": "HIGH",
                    "details": f"File: {filename}  hash={fhash[:16]}…",
                })
                # Queue VirusTotal hash check
                if self.threat_analyzer and fhash:
                    self.threat_analyzer.queue_scan(
                        "file", fhash,
                        {"filename": filename, "source": "email_attachment", "sender": sender}
                    )
            # Macro-enabled Office docs
            elif ext in (".doc", ".xls", ".ppt"):
                payload = part.get_payload(decode=True) or b""
                if b"macros" in payload[:8192].lower() or b"VBA" in payload[:8192]:
                    threats.append({
                        "type": "MACRO_ATTACHMENT",
                        "risk": "HIGH",
                        "details": f"Possible macro: {filename}",
                    })
        return threats

    def _check_sender_domain(self, sender: str) -> Optional[Dict]:
        domain = _extract_domain(sender)
        if not domain:
            return None
        if domain in SPOOFED_DOMAINS:
            return {"type": "SPOOFED_SENDER", "risk": "CRITICAL",
                    "details": f"Known spoofed domain: {domain}"}
        # Lookalike detection: letter substitutions
        for legit in ("paypal", "google", "amazon", "microsoft", "apple", "facebook", "linkedin"):
            similarity = self._leet_similarity(domain.split(".")[0], legit)
            if similarity >= 0.8 and domain.split(".")[0] != legit:
                return {"type": "LOOKALIKE_DOMAIN", "risk": "HIGH",
                        "details": f"Domain '{domain}' looks like '{legit}'"}
        return None

    def _check_header_anomalies(self, msg) -> Optional[Dict]:
        from_addr = msg.get("From", "")
        reply_to = msg.get("Reply-To", "")
        return_path = msg.get("Return-Path", "")
        if reply_to and from_addr:
            from_domain = _extract_domain(from_addr)
            reply_domain = _extract_domain(reply_to)
            if from_domain and reply_domain and from_domain != reply_domain:
                return {"type": "REPLY_TO_MISMATCH", "risk": "MEDIUM",
                        "details": f"From={from_domain}  Reply-To={reply_domain}"}
        return None

    @staticmethod
    def _leet_similarity(a: str, b: str) -> float:
        """Rough Jaccard-like similarity ignoring leet substitutions."""
        leet = str.maketrans("013457@$!", "oieastagsi")
        a2 = a.translate(leet)
        b2 = b.translate(leet)
        set_a = set(a2)
        set_b = set(b2)
        if not set_a or not set_b:
            return 0.0
        return len(set_a & set_b) / len(set_a | set_b)

    @staticmethod
    def _max_risk(risks: List[str]) -> str:
        order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        best = "LOW"
        for r in risks:
            if r in order and order.index(r) > order.index(best):
                best = r
        return best

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    def get_summary(self) -> Dict:
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute("SELECT COUNT(*) FROM email_threats")
            total = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM email_threats WHERE risk_level='CRITICAL'")
            critical = c.fetchone()[0]
            conn.close()
            return {"total_email_threats": total, "critical": critical}
        except Exception:
            return {"total_email_threats": 0, "critical": 0}
