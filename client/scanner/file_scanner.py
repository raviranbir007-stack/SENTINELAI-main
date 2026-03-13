"""
Enhanced File Scanner
Full malware detection engine with:
  • SHA-256 + MD5 hashing
  • Shannon entropy analysis (packed / encrypted detection)
  • YARA-like byte-pattern signature matching
  • Dangerous file extension & magic-byte verification
  • Suspicious string extraction (URLs, IPs, registry keys, commands)
  • PE header parsing (Windows executables on any OS)
  • Script obfuscation detection (PowerShell, VBS, JS)
  • VirusTotal file hash look-up via ThreatAnalyzer queue
  • Quarantine support
"""

import hashlib
import logging
import math
import os
import re
import shutil
import struct
import sqlite3
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("FileScanner")


# ---------------------------------------------------------------------------
# Byte-pattern signatures  (YARA-like)
# ---------------------------------------------------------------------------

BYTE_SIGNATURES: List[Tuple[str, bytes, str, str]] = [
    # (name, pattern, description, severity)
    ("EICAR",       b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
                    "EICAR AV test file", "HIGH"),
    ("MZ_PE",       b"MZ",              "Windows PE executable header", "INFO"),
    ("ELF",         b"\x7fELF",         "Linux ELF executable",        "INFO"),
    ("JAVA_CLASS",  b"\xca\xfe\xba\xbe","Java class file",             "MEDIUM"),
    ("SHELLCODE_NOP", b"\x90\x90\x90\x90\x90\x90\x90\x90", "NOP sled (shellcode)", "HIGH"),
    ("REVERSE_SHELL", b"/bin/sh\x00-i",  "Reverse-shell string",       "CRITICAL"),
    ("MSFVENOM",    b"msfvenom",         "Metasploit payload marker",  "CRITICAL"),
    ("XOR_DECODE",  b"xor eax",          "XOR decode stub (shellcode)","HIGH"),
]

REGEX_SIGNATURES: List[Tuple[str, str, str]] = [
    ("POWERSHELL_ENCODED", r"powershell.*-enc",          "HIGH"),
    ("WGET_SH",            r"wget\s+.*\|\s*(ba)?sh",     "HIGH"),
    ("CURL_SH",            r"curl\s+.*\|\s*(ba)?bash",   "HIGH"),
    ("BASE64_BLOB",        r"base64\s+--?decode",        "MEDIUM"),
    ("NET_USER_ADD",       r"net\s+user.*\/add",         "HIGH"),
    ("SCHTASK_CREATE",     r"schtasks.*\/create",        "HIGH"),
    ("CREATEREMOTETHREAD", r"CreateRemoteThread",        "CRITICAL"),
    ("VIRTUALALLOC",       r"VirtualAlloc",              "HIGH"),
    ("WSCRIPT_SHELL",      r"WScript\.Shell",            "HIGH"),
    ("OBFUSCATED_EVAL",    r"eval\s*\(\s*(?:unescape|base64|gzip|rot13)", "HIGH"),
]

MAGIC_BYTES: Dict[bytes, Tuple[str, bool]] = {
    b"MZ":               ("Windows PE",           False),
    b"\x7fELF":          ("Linux ELF",            False),
    b"\xca\xfe\xba\xbe": ("Java class",           True),
    b"#!/":              ("Script file",           False),
    b"PK\x03\x04":       ("ZIP archive",           False),
    b"Rar!":             ("RAR archive",           False),
    b"\x1f\x8b":         ("GZIP compressed",       False),
    b"\xd0\xcf\x11\xe0": ("OLE2 (Office/macro)",  True),
    b"%PDF":             ("PDF document",          False),
}

DANGEROUS_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js",
    ".jse", ".wsf", ".wsh", ".msi", ".scr", ".pif", ".com", ".hta",
    ".cpl", ".reg", ".lnk", ".inf", ".jar", ".docm", ".xlsm",
    ".pptm", ".dotm", ".xltm", ".xlam", ".ppam", ".gadget",
}

HIGH_ENTROPY_THRESHOLD   = 7.2
MEDIUM_ENTROPY_THRESHOLD = 6.5
MAX_FILE_SIZE            = 500 * 1024 * 1024   # 500 MB

SUSPICIOUS_STRING_PATTERNS = [
    r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
    r"/etc/passwd", r"/etc/shadow",
    r"cmd\.exe", r"powershell",
    r"\\AppData\\Roaming",
    r"CreateRemoteThread", r"VirtualAlloc", r"WriteProcessMemory",
    r"ShellExecute", r"WScript\.Shell",
    r"eval\s*\(", r"exec\s*\(",
    r"base64_decode", r"gzinflate", r"str_rot13",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq: Dict[int, int] = defaultdict(int)
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values() if c)


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
    except Exception:
        return ""
    return h.hexdigest()


def _md5(path: str) -> str:
    h = hashlib.md5()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
    except Exception:
        return ""
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class FileScanner:
    """Enhanced malware-oriented file scanner."""

    def __init__(self, threat_analyzer=None, db_path: str = "activity_logs.db",
                 quarantine_dir: str = "quarantine/files"):
        self.threat_analyzer = threat_analyzer
        self.db_path = db_path
        self.quarantine_dir = Path(quarantine_dir)
        self._init_db()

    def _init_db(self):
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute("""
                CREATE TABLE IF NOT EXISTS file_scan_results (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_path     TEXT,
                    sha256        TEXT,
                    md5           TEXT,
                    size          INTEGER,
                    entropy       REAL,
                    extension     TEXT,
                    magic_type    TEXT,
                    risk_level    TEXT DEFAULT 'UNKNOWN',
                    signatures    TEXT,
                    suspicious_strings TEXT,
                    quarantined   INTEGER DEFAULT 0,
                    timestamp     DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"FileScanner DB init: {e}")

    @staticmethod
    def calculate_hash(filepath: str) -> str:
        """Backward-compatible SHA-256 hash."""
        return _sha256(filepath)

    def scan_file(self, filepath: str) -> Dict:
        """Full analysis of a single file."""
        result: Dict = {
            "filepath": filepath, "sha256": "", "md5": "", "size": 0,
            "entropy": 0.0, "extension": "", "magic_type": "", "risk_level": "UNKNOWN",
            "signatures": [], "suspicious_strings": [], "quarantined": False, "error": None,
        }
        try:
            p = Path(filepath)
            if not p.exists():
                result["error"] = "File not found"
                return result
            if p.stat().st_size > MAX_FILE_SIZE:
                result["error"] = "File too large"
                return result

            result["size"]      = p.stat().st_size
            result["extension"] = p.suffix.lower()
            result["sha256"]    = _sha256(filepath)
            result["md5"]       = _md5(filepath)
            # Also expose as "hash" for backward compat
            result["hash"]      = result["sha256"]

            with open(filepath, "rb") as fh:
                sample = fh.read(min(result["size"], 1 * 1024 * 1024))

            result["entropy"]   = _entropy(sample)
            result["magic_type"] = self._identify_magic(sample)
            result["signatures"] = self._match_signatures(sample)
            result["suspicious_strings"] = self._extract_suspicious_strings(sample)

            pe_info = self._analyse_pe(sample)
            if pe_info:
                result["pe_info"] = pe_info
                if pe_info.get("suspicious"):
                    result["signatures"].append("PE_ANOMALY")

            result["risk_level"] = self._score_risk(result)

            if self.threat_analyzer and result["sha256"] and \
               result["extension"] in DANGEROUS_EXTENSIONS:
                self.threat_analyzer.queue_scan(
                    "file", result["sha256"],
                    {"path": filepath, "size": result["size"]}
                )

            self._save_result(result)
            logger.info(
                f"📂 Scan: {p.name}  size={result['size']}  "
                f"entropy={result['entropy']:.2f}  risk={result['risk_level']}"
            )
        except Exception as e:
            result["error"] = str(e)
            logger.error(f"FileScanner error on {filepath}: {e}")
        return result

    def scan_directory(self, dirpath: str, recursive: bool = True,
                       max_files: int = 1000) -> List[Dict]:
        results = []
        count = 0
        walk = Path(dirpath).rglob("*") if recursive else Path(dirpath).iterdir()
        for fp in walk:
            if count >= max_files:
                break
            if fp.is_file():
                results.append(self.scan_file(str(fp)))
                count += 1
        return results

    def quarantine(self, filepath: str, reason: str = "") -> bool:
        try:
            self.quarantine_dir.mkdir(parents=True, exist_ok=True)
            ts = datetime.now().strftime("%Y%m%d%H%M%S")
            dest = self.quarantine_dir / f"{ts}_{Path(filepath).name}"
            shutil.move(filepath, dest)
            logger.critical(f"🔒 QUARANTINED: {filepath} → {dest}  reason={reason}")
            return True
        except Exception as e:
            logger.error(f"Quarantine failed for {filepath}: {e}")
            return False

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _identify_magic(self, data: bytes) -> str:
        for magic, (desc, _) in MAGIC_BYTES.items():
            if data[:len(magic)] == magic:
                return desc
        return "Unknown"

    def _match_signatures(self, data: bytes) -> List[str]:
        matched = []
        text = data.decode("latin-1", errors="replace")
        for name, pattern, _, _ in BYTE_SIGNATURES:
            try:
                if isinstance(pattern, bytes) and pattern in data:
                    matched.append(name)
            except Exception:
                pass
        for name, pattern, _ in REGEX_SIGNATURES:
            try:
                if re.search(pattern, text, re.IGNORECASE):
                    matched.append(name)
            except Exception:
                pass
        return matched

    def _extract_suspicious_strings(self, data: bytes) -> List[str]:
        found = []
        try:
            text = data.decode("latin-1", errors="replace")
            for pat in SUSPICIOUS_STRING_PATTERNS:
                m = re.search(pat, text, re.IGNORECASE)
                if m:
                    found.append(m.group(0)[:100])
        except Exception:
            pass
        return list(set(found))[:20]

    def _analyse_pe(self, data: bytes) -> Optional[Dict]:
        if data[:2] != b"MZ":
            return None
        try:
            if len(data) < 0x40:
                return None
            pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
            if pe_offset + 24 > len(data):
                return None
            sig = data[pe_offset:pe_offset + 4]
            if sig != b"PE\x00\x00":
                return None
            characteristics = struct.unpack_from("<H", data, pe_offset + 22)[0]
            opt_magic = struct.unpack_from("<H", data, pe_offset + 24)[0]
            arch = "x86" if opt_magic == 0x10b else "x64" if opt_magic == 0x20b else "unknown"
            is_dll   = bool(characteristics & 0x2000)
            no_reloc = bool(characteristics & 0x0001)
            return {"arch": arch, "is_dll": is_dll, "no_reloc": no_reloc,
                    "suspicious": no_reloc and not is_dll}
        except Exception:
            return None

    def _score_risk(self, result: Dict) -> str:
        score = 0
        if result["entropy"] >= HIGH_ENTROPY_THRESHOLD:
            score += 3
        elif result["entropy"] >= MEDIUM_ENTROPY_THRESHOLD:
            score += 1
        if result["extension"] in DANGEROUS_EXTENSIONS:
            score += 2
        critical_sigs = {"EICAR", "REVERSE_SHELL", "MSFVENOM", "SHELLCODE_NOP", "CREATEREMOTETHREAD"}
        high_sigs     = {"POWERSHELL_ENCODED", "WGET_SH", "CURL_SH", "PE_ANOMALY",
                          "NET_USER_ADD", "SCHTASK_CREATE", "VIRTUALALLOC"}
        for sig in result.get("signatures", []):
            if sig in critical_sigs:
                score += 5
            elif sig in high_sigs:
                score += 3
            else:
                score += 1
        score += min(len(result.get("suspicious_strings", [])), 5)
        if result.get("magic_type") == "OLE2 (Office/macro)":
            score += 2
        if score >= 8:
            return "CRITICAL"
        elif score >= 5:
            return "HIGH"
        elif score >= 2:
            return "MEDIUM"
        elif score >= 1:
            return "LOW"
        return "CLEAN"

    def _save_result(self, result: Dict):
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute("""
                INSERT INTO file_scan_results
                    (file_path, sha256, md5, size, entropy, extension,
                     magic_type, risk_level, signatures, suspicious_strings)
                VALUES (?,?,?,?,?,?,?,?,?,?)
            """, (
                result["filepath"], result["sha256"], result["md5"],
                result["size"], result["entropy"], result["extension"],
                result["magic_type"], result["risk_level"],
                ",".join(result.get("signatures", [])),
                ",".join(result.get("suspicious_strings", [])),
            ))
            conn.commit()
            conn.close()
        except Exception:
            pass

    def get_recent_threats(self, limit: int = 50) -> List[Dict]:
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute("""
                SELECT file_path, sha256, size, entropy, risk_level, signatures, timestamp
                FROM file_scan_results
                WHERE risk_level IN ('HIGH','CRITICAL')
                ORDER BY timestamp DESC LIMIT ?
            """, (limit,))
            rows = c.fetchall()
            conn.close()
            return [{"path": r[0], "sha256": r[1], "size": r[2], "entropy": r[3],
                     "risk": r[4], "signatures": r[5], "ts": r[6]} for r in rows]
        except Exception:
            return []
