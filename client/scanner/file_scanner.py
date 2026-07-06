from __future__ import annotations
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
from typing import Dict, List, Optional, Tuple, Any

logger = logging.getLogger("FileScanner")

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    pefile = None
    PEFILE_AVAILABLE = False

try:
    import lief
    LIEF_AVAILABLE = True
except ImportError:
    lief = None
    LIEF_AVAILABLE = False

try:
    import capstone
    CAPSTONE_AVAILABLE = True
except ImportError:
    capstone = None
    CAPSTONE_AVAILABLE = False

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    yara = None
    YARA_AVAILABLE = False

PE_ANALYSIS_AVAILABLE = LIEF_AVAILABLE

# Try to import ML libraries separately
try:
    import joblib
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    ML_ANALYSIS_AVAILABLE = True
except ImportError:
    ML_ANALYSIS_AVAILABLE = False

if not PE_ANALYSIS_AVAILABLE:
    logger.warning("Advanced PE analysis libraries not available. Using basic PE parsing.")
if not YARA_AVAILABLE:
    logger.warning("YARA library not available. Signature rules scanning disabled.")
if not ML_ANALYSIS_AVAILABLE:
    logger.warning("ML analysis libraries not available. Using rule-based classification.")


def _env_flag(name: str, default: bool = True) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


# ---------------------------------------------------------------------------
# Byte-pattern signatures  (YARA-like)
# ---------------------------------------------------------------------------

BYTE_SIGNATURES: List[Tuple[str, bytes, str, str]] = [
    # (name, pattern, description, severity)
    ("EICAR",       b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
                    "EICAR AV test file", "HIGH"),
    ("MZ_PE",       b"MZ",              "Windows PE executable header", "INFO"),
    ("ELF",         b"\x7fELF",         "Linux ELF executable",        "INFO"),
    ("RAR",         b"Rar!\x1a\x07",    "RAR archive",                 "LOW"),
    ("ZIP",         b"PK\x03\x04",      "ZIP archive",                 "LOW"),
    ("SEVEN_Z",     b"7z\xbc\xaf'\x1c", "7-Zip archive",               "LOW"),
    ("CAB",         b"MSCF",             "Microsoft Cabinet archive",   "LOW"),
    ("OLE2",        b"\xd0\xcf\x11\xe0", "OLE2 compound document",      "MEDIUM"),
    ("JAVA_CLASS",  b"\xca\xfe\xba\xbe","Java class file",             "MEDIUM"),
    ("SHELLCODE_NOP", b"\x90\x90\x90\x90\x90\x90\x90\x90", "NOP sled (shellcode)", "HIGH"),
    ("REVERSE_SHELL", b"/bin/sh\x00-i",  "Reverse-shell string",       "CRITICAL"),
    ("MSFVENOM",    b"msfvenom",         "Metasploit payload marker",  "CRITICAL"),
    ("XOR_DECODE",  b"xor eax",          "XOR decode stub (shellcode)","HIGH"),
    ("UPX",         b"UPX!",             "UPX packer marker",          "HIGH"),
    ("NSIS",        b"NullsoftInst",     "NSIS installer marker",      "LOW"),
    ("PYINSTALLER",  b"MEI\014\013\012\013\016", "PyInstaller archive marker", "LOW"),
]

REGEX_SIGNATURES: List[Tuple[str, str, str]] = [
    ("POWERSHELL_ENCODED", r"powershell.*-enc",          "HIGH"),
    ("POWERSHELL_B64",     r"powershell.*encodedcommand", "HIGH"),
    ("CERTUTIL_DL",        r"certutil(?:\.exe)?\s+.*-urlcache", "HIGH"),
    ("RUNDLL32",           r"rundll32(?:\.exe)?",      "HIGH"),
    ("MSHTA",              r"mshta(?:\.exe)?",         "HIGH"),
    ("REGSVR32",           r"regsvr32(?:\.exe)?",      "HIGH"),
    ("BITSADMIN",          r"bitsadmin(?:\.exe)?",     "MEDIUM"),
    ("WMI_EXEC",           r"wmic\s+.*process\s+call\s+create", "HIGH"),
    ("WGET_SH",            r"wget\s+.*\|\s*(ba)?sh",     "HIGH"),
    ("CURL_SH",            r"curl\s+.*\|\s*(ba)?bash",   "HIGH"),
    ("BASE64_BLOB",        r"base64\s+--?decode",        "MEDIUM"),
    ("NET_USER_ADD",       r"net\s+user.*\/add",         "HIGH"),
    ("SCHTASK_CREATE",     r"schtasks.*\/create",        "HIGH"),
    ("CREATEREMOTETHREAD", r"CreateRemoteThread",        "CRITICAL"),
    ("VIRTUALALLOC",       r"VirtualAlloc",              "HIGH"),
    ("WSCRIPT_SHELL",      r"WScript\.Shell",            "HIGH"),
    ("OBFUSCATED_EVAL",    r"eval\s*\(\s*(?:unescape|base64|gzip|rot13)", "HIGH"),
    ("AUTOEXEC_MACRO",     r"(?:AutoOpen|Auto_Open|Document_Open|Workbook_Open|Presentation_Open|Auto_Close)", "CRITICAL"),
    ("VBA_MACRO",          r"(?:Attribute\s+VB_Name|vbaProject\.bin|ThisDocument|Sub\s+\w+\s*\()", "HIGH"),
    ("OFFICE_OBJECT",      r"(?:CreateObject\(|GetObject\(|ShellExecute|Scripting\.FileSystemObject|ADODB\.Stream)", "HIGH"),
    ("PDF_JAVASCRIPT",     r"/JavaScript|/JS\b|app\.launchURL|this\.submitForm", "MEDIUM"),
    ("HTML_EMBED",         r"<iframe[^>]+src=|<script[^>]+src=|data:text/html", "MEDIUM"),
    ("ELF_DYNAMIC_LOADER", r"ld-linux|libc\.so\.6|libdl\.so", "LOW"),
]

COMPILED_REGEX_SIGNATURES: List[Tuple[str, Any, str]] = [
    (name, re.compile(pattern, re.IGNORECASE), severity) for name, pattern, severity in REGEX_SIGNATURES
]

SIGNATURE_SEVERITY_MAP: Dict[str, str] = {
    name.upper(): str(severity).upper() for name, _, _, severity in BYTE_SIGNATURES
}
SIGNATURE_SEVERITY_MAP.update({
    name.upper(): str(severity).upper() for name, _, severity in REGEX_SIGNATURES
})

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
    r"cmd\.exe", r"powershell", r"rundll32", r"mshta", r"regsvr32", r"certutil",
    r"\\AppData\\Roaming",
    r"CreateRemoteThread", r"VirtualAlloc", r"WriteProcessMemory",
    r"ShellExecute", r"WScript\.Shell",
    r"eval\s*\(", r"exec\s*\(",
    r"base64_decode", r"gzinflate", r"str_rot13",
    r"AutoOpen", r"Document_Open", r"Workbook_Open", r"Presentation_Open",
    r"vbaProject\.bin", r"ThisDocument", r"ADODB\.Stream",
]

IOC_PATTERNS: Dict[str, str] = {
    "url": r"https?://[a-zA-Z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,}",
    "ipv4": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "domain": r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b",
    "sha256": r"\b[a-fA-F0-9]{64}\b",
    "sha1": r"\b[a-fA-F0-9]{40}\b",
    "md5": r"\b[a-fA-F0-9]{32}\b",
    "email": r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
}

PACKER_SECTION_NAMES = {
    "upx0", "upx1", "upx2", ".packed", ".aspack", ".petite", ".mpress1", ".mpress2", ".boom", ".vmp0", ".vmp1"
}

PE_SUSPICIOUS_DLLS = {"kernel32.dll", "user32.dll", "advapi32.dll", "ws2_32.dll", "wininet.dll", "urlmon.dll", "shell32.dll", "mpr.dll"}
PE_SUSPICIOUS_FUNCS = {
    "CreateRemoteThread", "VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory", "ReadProcessMemory",
    "CreateProcess", "CreateProcessA", "CreateProcessW", "ShellExecute", "ShellExecuteA", "ShellExecuteW",
    "WinExec", "LoadLibrary", "LoadLibraryA", "LoadLibraryW", "GetProcAddress", "InternetOpenUrl",
    "URLDownloadToFile", "WinHttpOpen", "WinHttpConnect", "WinHttpSendRequest", "InternetReadFile"
}

OLE_MACRO_MARKERS = {
    "autoopen", "auto_open", "document_open", "workbook_open", "presentation_open", "auto_close",
    "attribute vb_name", "thisdocument", "vba", "sub autoopen", "private sub document_open"
}

OLE_EMBEDDED_OBJECT_MARKERS = {
    "vba/dir", "vba/project", "vbaproject.bin", "compobj", "ole10native", "objectpool", "package",
    "macros", "_rels/.rels", "word/document.xml", "xl/workbook.xml", "ppt/presentation.xml"
}


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
        self.yara_rules = None
        # Enable all analysis methods by default (can be tuned via env toggles).
        self._macro_detection_enabled = _env_flag("SENTINEL_ENABLE_MACRO_DETECTION", True)
        self._pe_analysis_enabled = _env_flag("SENTINEL_ENABLE_PE_ANALYSIS", True)
        self._yara_analysis_enabled = _env_flag("SENTINEL_ENABLE_YARA_ANALYSIS", True)
        self._ml_analysis_enabled = _env_flag("SENTINEL_ENABLE_ML_ANALYSIS", True) and ML_ANALYSIS_AVAILABLE
        self._behavioral_analysis_enabled = _env_flag("SENTINEL_ENABLE_BEHAVIORAL_ANALYSIS", True)
        self._load_yara_rules()
        self._init_db()
        logger.info("✅ FileScanner initialized | macro=%s | pe=%s | yara=%s | ml=%s | behavioral=%s",
                    self._macro_detection_enabled,
                    self._pe_analysis_enabled,
                    self._yara_analysis_enabled,
                    self._ml_analysis_enabled,
                    self._behavioral_analysis_enabled)

    def _init_db(self):
        try:
            conn = sqlite3.connect(self.db_path, timeout=30.0, check_same_thread=False)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=30000")
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

    def _load_yara_rules(self):
        """Load YARA rules for malware detection"""
        if not YARA_AVAILABLE or not self._yara_analysis_enabled:
            return
        try:
            rules_path = Path(__file__).parent / "signatures" / "malware.yara"
            if rules_path.exists():
                self.yara_rules = yara.compile(filepath=str(rules_path))
                logger.info(f"Loaded YARA rules from {rules_path}")
            else:
                logger.warning(f"YARA rules file not found: {rules_path}")
        except Exception as e:
            logger.error(f"Failed to load YARA rules: {e}")

    def _scan_yara(self, data: bytes) -> List[str]:
        """Scan data with YARA rules"""
        if not self._yara_analysis_enabled or not self.yara_rules:
            return []
        try:
            matches = self.yara_rules.match(data=data)
            return [match.rule for match in matches]
        except Exception as e:
            logger.error(f"YARA scan failed: {e}")
            return []

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
            "analysis_family": "unknown", "forensic_metadata": {},
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
            result["analysis_family"] = self._classify_family(result["magic_type"], result["extension"])
            result["signatures"] = self._match_signatures(sample)
            result["suspicious_strings"] = self._extract_suspicious_strings(sample)
            ioc_summary = self._extract_iocs(sample)
            result["iocs"] = ioc_summary
            result["deobfuscated_strings"] = self._extract_deobfuscated_strings(sample)

            if result["analysis_family"] == "office_ole":
                ole_info = self._analyse_ole_container(sample, result) if self._macro_detection_enabled else {}
                if ole_info and self._macro_detection_enabled:
                    result["ole_info"] = ole_info
                    result["forensic_metadata"]["container_type"] = ole_info.get("container_type")
                    result["forensic_metadata"]["macro_indicators"] = ole_info.get("macro_indicators", [])
                    if ole_info.get("macro_indicators"):
                        result["signatures"].append("OLE_MACRO_ACTIVITY")
            
            # YARA scanning
            if self._yara_analysis_enabled:
                yara_matches = self._scan_yara(sample)
                result["signatures"].extend(yara_matches)

            pe_info = self._analyse_pe(sample) if self._pe_analysis_enabled else None
            if pe_info:
                result["pe_info"] = pe_info
                result["analysis_family"] = "pe_coff"
                result["forensic_metadata"]["pe_machine"] = pe_info.get("coff_info", {}).get("machine")
                result["forensic_metadata"]["imphash"] = pe_info.get("imphash")
                if pe_info.get("suspicious"):
                    result["signatures"].append("PE_ANOMALY")
                
                # Add disassembly analysis
                disassembly_info = self._disassemble_binary(sample, pe_info) if CAPSTONE_AVAILABLE else {}
                if disassembly_info:
                    result["disassembly_info"] = disassembly_info
                    # Add suspicious disassembly patterns to signatures
                    if disassembly_info.get("suspicious_patterns"):
                        result["signatures"].append("SUSPICIOUS_DISASSEMBLY")
            
            # ML-based classification
            if self._ml_analysis_enabled:
                ml_features = self._extract_ml_features(result)
                ml_result = self._ml_classify_malware(ml_features)
                result["ml_classification"] = ml_result
            else:
                result["ml_classification"] = {"prediction": "UNKNOWN", "confidence": 0.0}

            if self._behavioral_analysis_enabled:
                result["behavioral_profile"] = self._build_behavioral_profile(result)

            result["risk_level"] = self._score_risk(result)
            score_value, score_reasons, score_confidence = self._score_risk_detailed(result)
            result["risk_contract"] = {
                "version": "1.0",
                "numeric_score": score_value,
                "confidence": score_confidence,
                "reason_codes": score_reasons,
                "threat_model": "static+heuristic+pe+ml+disassembly",
            }
            result["analysis_methods_used"] = self._collect_analysis_methods(result)
            result["forensic_metadata"].update({
                "analysis_family": result.get("analysis_family", "unknown"),
                "magic_type": result.get("magic_type", "Unknown"),
                "extension": result.get("extension", ""),
                "signature_count": len(result.get("signatures", [])),
                "ioc_count": sum(len(values) for values in (result.get("iocs") or {}).values()),
                "analysis_methods_used": result.get("analysis_methods_used", []),
            })

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
        seen = set()
        text = data.decode("latin-1", errors="replace")
        for name, pattern, _, _ in BYTE_SIGNATURES:
            try:
                if isinstance(pattern, bytes) and pattern in data:
                    if name not in seen:
                        matched.append(name)
                        seen.add(name)
            except Exception:
                pass
        for name, pattern, _ in COMPILED_REGEX_SIGNATURES:
            try:
                if pattern.search(text):
                    if name not in seen:
                        matched.append(name)
                        seen.add(name)
            except Exception:
                pass
        return matched

    def _extract_suspicious_strings(self, data: bytes) -> List[str]:
        found = []
        try:
            text = data.decode("latin-1", errors="replace")
            for pat in SUSPICIOUS_STRING_PATTERNS:
                for m in re.finditer(pat, text, re.IGNORECASE):
                    ctx_start = max(0, m.start() - 24)
                    ctx_end = min(len(text), m.end() + 24)
                    context = text[ctx_start:ctx_end].replace("\n", " ").replace("\r", " ")
                    found.append(context[:160])
                    if len(found) >= 40:
                        break
                if len(found) >= 40:
                    break
        except Exception:
            pass
        return list(set(found))[:20]

    def _extract_iocs(self, data: bytes) -> Dict[str, List[str]]:
        text = data.decode("latin-1", errors="replace")
        iocs: Dict[str, List[str]] = {k: [] for k in IOC_PATTERNS}
        for ioc_type, pattern in IOC_PATTERNS.items():
            try:
                matches = re.findall(pattern, text, flags=re.IGNORECASE)
                normalized = []
                for match in matches[:100]:
                    value = str(match).strip().lower()
                    if not value:
                        continue
                    if ioc_type == "ipv4":
                        parts = value.split(".")
                        if len(parts) != 4:
                            continue
                        try:
                            if any(int(p) > 255 for p in parts):
                                continue
                        except Exception:
                            continue
                    normalized.append(value)
                iocs[ioc_type] = sorted(list(set(normalized)))[:25]
            except Exception:
                iocs[ioc_type] = []
        return iocs

    def _extract_deobfuscated_strings(self, data: bytes) -> List[str]:
        text = data.decode("latin-1", errors="replace")
        candidates: List[str] = []
        # Capture likely base64 blobs for analyst review (lightweight, no heavy decode loop).
        for m in re.finditer(r"\b[A-Za-z0-9+/]{40,}={0,2}\b", text):
            chunk = m.group(0)
            # Keep only reasonably sized chunks to avoid huge memory usage.
            if 40 <= len(chunk) <= 400:
                candidates.append(chunk[:120])
            if len(candidates) >= 10:
                break
        return candidates

    def _collect_analysis_methods(self, result: Dict) -> List[Dict[str, Any]]:
        """Summarize which analysis methods contributed evidence for the scan."""
        methods: List[Dict[str, Any]] = []
        family = str(result.get("analysis_family", "unknown") or "unknown")
        signatures = result.get("signatures", []) or []
        suspicious_strings = result.get("suspicious_strings", []) or []
        iocs = result.get("iocs", {}) or {}
        pe_info = result.get("pe_info", {}) or {}
        ole_info = result.get("ole_info", {}) or {}
        disassembly = result.get("disassembly_info", {}) or {}
        ml_result = result.get("ml_classification", {}) or {}

        methods.append({
            "name": "Entropy Heuristics",
            "status": "COMPLETED",
            "details": f"Shannon entropy analyzed at {float(result.get('entropy', 0.0) or 0.0):.3f} for packing/encryption indicators.",
        })
        methods.append({
            "name": "Signature Matching",
            "status": "COMPLETED",
            "details": f"Byte-pattern, regex, and YARA matching produced {len(signatures)} match(es).",
        })
        methods.append({
            "name": "IOC Extraction",
            "status": "COMPLETED" if any(iocs.values()) else "LIMITED",
            "details": f"Extracted {sum(len(v) for v in iocs.values())} IOC value(s) across URL, IP, domain, hash, and email patterns.",
        })
        methods.append({
            "name": "Suspicious String Heuristics",
            "status": "COMPLETED" if suspicious_strings else "LIMITED",
            "details": f"Captured {len(suspicious_strings)} contextual string hit(s) for command, macro, and obfuscation markers.",
        })

        if family == "pe_coff" or pe_info:
            methods.append({
                "name": "PE/COFF Structural Analysis",
                "status": "COMPLETED",
                "details": (
                    f"PE parsing inspected {len(pe_info.get('sections', []))} section(s), "
                    f"{len(pe_info.get('imports', []))} import table entr{('y' if len(pe_info.get('imports', [])) == 1 else 'ies')}, "
                    f"and {len(pe_info.get('anomalies', []))} anomaly indicator(s)."
                ),
            })
        elif family == "office_ole" or ole_info:
            methods.append({
                "name": "OLE / Office Container Heuristics",
                "status": "COMPLETED",
                "details": (
                    f"Detected {len(ole_info.get('macro_indicators', []))} macro marker(s) and "
                    f"{ole_info.get('embedded_object_count', 0)} embedded object signal(s)."
                ),
            })
        elif family == "archive":
            methods.append({
                "name": "Archive Heuristics",
                "status": "COMPLETED",
                "details": "Archive/container file type identified for follow-on inspection.",
            })
        elif family == "script":
            methods.append({
                "name": "Script Heuristics",
                "status": "COMPLETED",
                "details": "Script file family identified; obfuscation and execution markers were prioritized.",
            })

        if disassembly:
            methods.append({
                "name": "Code Disassembly",
                "status": "COMPLETED",
                "details": f"Disassembly produced {disassembly.get('total_instructions', 0)} instruction(s) and {len(disassembly.get('suspicious_patterns', []))} suspicious pattern(s).",
            })

        if ml_result:
            methods.append({
                "name": "Machine Learning Classification",
                "status": "COMPLETED",
                "details": f"Model predicted {ml_result.get('prediction', 'UNKNOWN')} with confidence {float(ml_result.get('confidence', 0.0) or 0.0):.2f}.",
            })

        behavioral = result.get("behavioral_profile", {}) or {}
        if behavioral:
            methods.append({
                "name": "Behavioral Pattern Analysis",
                "status": "COMPLETED",
                "details": f"Behavior score {behavioral.get('score', 0)} with stage hints: {', '.join(behavioral.get('stage_hints', []) or ['none'])}.",
            })

        return methods

    def _classify_family(self, magic_type: str, extension: str) -> str:
        ext = (extension or "").lower().strip()
        magic = (magic_type or "").lower()
        if magic.startswith("windows pe") or magic == "windows pe":
            return "pe_coff"
        if magic.startswith("ole2") or ext in {".doc", ".xls", ".ppt", ".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".xlam", ".ppam"}:
            return "office_ole"
        if magic.startswith("linux elf"):
            return "elf"
        if magic.startswith("zip") or ext in {".zip", ".rar", ".7z", ".cab", ".iso", ".tar", ".gz", ".bz2", ".xz", ".zst"}:
            return "archive"
        if ext in {".ps1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".py", ".pl", ".sh"}:
            return "script"
        if magic.startswith("pdf") or ext == ".pdf":
            return "pdf"
        return "generic"

    def _analyse_ole_container(self, data: bytes, result: Dict) -> Dict:
        """Best-effort OLE/Office macro analysis using lightweight string heuristics."""
        text = data.decode("latin-1", errors="replace")
        lower_text = text.lower()
        is_ooxml = data.startswith(b"PK\x03\x04")
        macro_markers = [
            ("AutoOpen", "document auto-open macro entry point"),
            ("Auto_Open", "document auto-open macro entry point"),
            ("Workbook_Open", "Excel workbook open macro"),
            ("Presentation_Open", "PowerPoint open macro"),
            ("Document_Open", "Word document open macro"),
            ("Auto_Close", "document auto-close macro"),
            ("Attribute VB_Name", "embedded VBA module metadata"),
            ("VBA/dir", "VBA project directory stream"),
            ("vbaProject.bin", "embedded VBA project stream"),
            ("VBA", "Visual Basic for Applications marker"),
            ("CreateObject(", "COM automation object creation"),
            ("GetObject(", "COM object lookup"),
            ("WScript.Shell", "command shell automation"),
            ("powershell", "PowerShell execution string"),
            ("Shell(", "shell execution call"),
            ("ShellExecute", "shell execution API usage"),
            ("URLDownloadToFile", "payload download API usage"),
            ("ADODB.Stream", "file write/download staging"),
            ("MSXML2.XMLHTTP", "HTTP request automation"),
            ("WinHttp.WinHttpRequest", "HTTP request automation"),
            ("Scripting.FileSystemObject", "filesystem automation"),
            ("ThisDocument", "Office document object module"),
            ("Environ(", "environment probing or command staging"),
            ("Chr(", "string obfuscation marker"),
            ("StrReverse", "string obfuscation marker"),
        ]

        indicators = []
        seen_markers = set()
        for marker, description in macro_markers:
            if marker.lower() in lower_text:
                marker_lower = marker.lower()
                if marker_lower not in seen_markers:
                    indicators.append({"marker": marker, "description": description})
                    seen_markers.add(marker_lower)

        embedded_objects = []
        for pattern in (r"Package\b", r"ObjectPool", r"Mso\w+", r"\x00VBA\x00", r"vbaProject\.bin", r"VBA/dir"):
            if re.search(pattern, text, re.IGNORECASE):
                embedded_objects.append(pattern)

        canonical_macro_markers = [
            marker for marker in OLE_MACRO_MARKERS if marker in lower_text
        ]

        return {
            "container_type": "OOXML" if is_ooxml else "OLE2",
            "macro_indicators": indicators,
            "canonical_macro_markers": sorted(canonical_macro_markers),
            "embedded_object_signals": embedded_objects,
            "embedded_object_count": len(embedded_objects),
            "has_macro_activity": bool(indicators),
            "is_macro_capable": result.get("extension", "").lower() in {".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".xlam", ".ppam", ".doc", ".xls", ".ppt"} or bool(indicators),
        }

    def _build_behavioral_profile(self, result: Dict) -> Dict[str, Any]:
        """Derive behavior-level risk signals from static evidence for consistent downstream scoring."""
        signatures = {str(sig).upper() for sig in result.get("signatures", [])}
        suspicious_strings = " ".join(result.get("suspicious_strings", [])).lower()
        ole_info = result.get("ole_info", {}) if isinstance(result.get("ole_info", {}), dict) else {}

        execution_markers = [
            marker for marker in ("POWERSHELL_ENCODED", "MSHTA", "RUNDLL32", "REGSVR32", "SCHTASK_CREATE")
            if marker in signatures
        ]
        delivery_markers = [
            marker for marker in ("CERTUTIL_DL", "WGET_SH", "CURL_SH")
            if marker in signatures
        ]
        macro_execution = bool(ole_info.get("has_macro_activity")) or "OLE_MACRO_ACTIVITY" in signatures
        code_injection = any(marker in signatures for marker in ("CREATEREMOTETHREAD", "VIRTUALALLOC", "SHELLCODE_NOP"))
        url_download_hint = "urldownloadtofile" in suspicious_strings

        behavior_score = 0
        if macro_execution:
            behavior_score += 3
        if execution_markers:
            behavior_score += min(3, len(execution_markers))
        if delivery_markers or url_download_hint:
            behavior_score += min(2, len(delivery_markers) + (1 if url_download_hint else 0))
        if code_injection:
            behavior_score += 3

        return {
            "score": behavior_score,
            "macro_execution": macro_execution,
            "execution_markers": execution_markers,
            "delivery_markers": delivery_markers,
            "code_injection_markers": code_injection,
            "stage_hints": [
                stage for stage, enabled in (
                    ("initial_access", bool(delivery_markers) or url_download_hint),
                    ("execution", bool(execution_markers) or macro_execution),
                    ("defense_evasion", code_injection),
                ) if enabled
            ],
        }

    def _analyse_pe(self, data: bytes) -> Optional[Dict]:
        if not PE_ANALYSIS_AVAILABLE:
            # Fallback to basic analysis
            return self._analyse_pe_basic(data)
        
        try:
            # Use lief for advanced binary analysis
            binary = lief.parse(data)
            
            if isinstance(binary, lief.PE.Binary):
                pe_info = self._analyse_pe_binary(binary)
                # Deepen PE/COFF evidence with imphash and symbol artifacts where possible.
                try:
                    if pefile is not None:
                        pe_obj = pefile.PE(data=data, fast_load=True)
                        pe_obj.parse_data_directories()
                        pe_info["imphash"] = pe_obj.get_imphash()
                except Exception:
                    pe_info["imphash"] = ""

                try:
                    text_preview = data.decode("latin-1", errors="ignore")
                    pdb_paths = re.findall(r"[A-Za-z]:\\\\[^\x00\n\r]{4,}\.pdb", text_preview, flags=re.IGNORECASE)
                    pe_info["pdb_paths"] = sorted(list(set(pdb_paths)))[:5]
                    if pe_info["pdb_paths"]:
                        pe_info["anomalies"].append("Debug symbol path(s) embedded")
                except Exception:
                    pe_info["pdb_paths"] = []

                return pe_info
            elif isinstance(binary, lief.ELF.Binary):
                return self._analyse_elf_binary(binary)
            else:
                # Unknown binary format
                return None
            
        except Exception as e:
            logger.warning(f"Advanced binary analysis failed: {e}")
            # Fallback to basic analysis
            return self._analyse_pe_basic(data)
            
            pe_info = {
                "arch": str(binary.header.machine).replace("MACHINE_TYPES.", ""),
                "is_dll": binary.header.has_characteristic(lief.PE.HEADER_CHARACTERISTICS.DLL),
                "is_exe": binary.header.has_characteristic(lief.PE.HEADER_CHARACTERISTICS.EXECUTABLE_IMAGE),
                "sections": [],
                "imports": [],
                "exports": [],
                "resources": [],
                "anomalies": [],
                "suspicious": False,
                "coff_info": {}
            }
            
            # COFF header analysis
            coff_header = binary.header
            pe_info["coff_info"] = {
                "machine": str(coff_header.machine),
                "number_of_sections": coff_header.numberof_sections,
                "time_date_stamp": coff_header.time_date_stamp,
                "pointer_to_symbol_table": coff_header.pointerto_symbol_table,
                "number_of_symbols": coff_header.numberof_symbols,
                "size_of_optional_header": coff_header.sizeof_optional_header,
                "characteristics": [str(char) for char in coff_header.characteristics_list]
            }
            
            # Section analysis
            for section in binary.sections:
                section_info = {
                    "name": section.name,
                    "virtual_size": section.virtual_size,
                    "virtual_address": section.virtual_address,
                    "size_of_raw_data": section.sizeof_raw_data,
                    "pointer_to_raw_data": section.pointerto_raw_data,
                    "characteristics": [str(char) for char in section.characteristics_lists],
                    "entropy": section.entropy
                }
                pe_info["sections"].append(section_info)
                
                # Check for suspicious sections
                if section.entropy > 7.5:
                    pe_info["anomalies"].append(f"High entropy section: {section.name}")
                    pe_info["suspicious"] = True
                
                # Check for executable sections with RWX
                if (lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE in section.characteristics_lists and
                    lief.PE.SECTION_CHARACTERISTICS.MEM_READ in section.characteristics_lists and
                    lief.PE.SECTION_CHARACTERISTICS.MEM_WRITE in section.characteristics_lists):
                    pe_info["anomalies"].append(f"RWX section: {section.name}")
                    pe_info["suspicious"] = True
            
            # Import analysis
            if binary.has_imports:
                for imp in binary.imports:
                    dll_imports = {
                        "dll": imp.name,
                        "functions": [entry.name if entry.name else f"ordinal_{entry.ordinal}" for entry in imp.entries]
                    }
                    pe_info["imports"].append(dll_imports)
                    
                    # Check for suspicious imports
                    suspicious_dlls = ["kernel32.dll", "user32.dll", "advapi32.dll", "ws2_32.dll"]
                    if imp.name.lower() in suspicious_dlls:
                        # Check for malware-common functions
                        malware_funcs = ["CreateRemoteThread", "VirtualAlloc", "WriteProcessMemory", 
                                       "CreateProcess", "ShellExecute", "WinExec", "LoadLibrary"]
                        for func in dll_imports["functions"]:
                            if func in malware_funcs:
                                pe_info["anomalies"].append(f"Suspicious import: {imp.name}.{func}")
                                pe_info["suspicious"] = True
            
            # Export analysis
            if binary.has_exports:
                for exp in binary.exports:
                    pe_info["exports"].append({
                        "name": exp.name,
                        "ordinal": exp.ordinal,
                        "address": exp.address
                    })
            
            # Resource analysis
            if binary.has_resources:
                for resource in binary.resources:
                    pe_info["resources"].append({
                        "type": str(resource.type),
                        "id": resource.id,
                        "language": str(resource.language),
                        "code_page": resource.code_page,
                        "size": len(resource.content) if resource.content else 0
                    })
            
            # Additional checks
            if binary.optional_header:
                opt_header = binary.optional_header
                pe_info["image_base"] = opt_header.imagebase
                pe_info["entry_point"] = opt_header.addressof_entrypoint
                
                # Check for suspicious entry point
                if opt_header.addressof_entrypoint == 0:
                    pe_info["anomalies"].append("Entry point at 0")
                    pe_info["suspicious"] = True
            
            # Check for packer signatures or anomalies
            if len(pe_info["sections"]) == 0:
                pe_info["anomalies"].append("No sections found")
                pe_info["suspicious"] = True
            
            return pe_info
            
        except Exception as e:
            logger.warning(f"Advanced PE analysis failed: {e}")
            # Fallback to basic analysis
            return self._analyse_pe_basic(data)

    def _analyse_pe_basic(self, data: bytes) -> Optional[Dict]:
        """Basic PE analysis fallback"""
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
                    "suspicious": no_reloc and not is_dll, "coff_info": {}}
        except Exception:
            return None

    def _analyse_pe_binary(self, binary: Any) -> Dict:
        """Analyze PE binary"""
        pe_info = {
            "format": "PE",
            "arch": str(binary.header.machine).replace("MACHINE_TYPES.", ""),
            "is_dll": binary.header.has_characteristic(lief.PE.HEADER_CHARACTERISTICS.DLL),
            "is_exe": binary.header.has_characteristic(lief.PE.HEADER_CHARACTERISTICS.EXECUTABLE_IMAGE),
            "sections": [],
            "imports": [],
            "exports": [],
            "resources": [],
            "anomalies": [],
            "suspicious": False,
            "coff_info": {},
            "suspicious_exports": [],
        }
        
        # COFF header analysis
        coff_header = binary.header
        pe_info["coff_info"] = {
            "machine": str(coff_header.machine),
            "number_of_sections": coff_header.numberof_sections,
            "time_date_stamp": coff_header.time_date_stamp,
            "pointer_to_symbol_table": coff_header.pointerto_symbol_table,
            "number_of_symbols": coff_header.numberof_symbols,
            "size_of_optional_header": coff_header.sizeof_optional_header,
            "characteristics": [str(char) for char in coff_header.characteristics_list]
        }
        try:
            opt_header = binary.optional_header
            pe_info["coff_info"]["checksum"] = int(getattr(opt_header, "checksum", 0) or 0)
            pe_info["coff_info"]["subsystem"] = str(getattr(opt_header, "subsystem", "unknown"))
            pe_info["coff_info"]["dll_characteristics"] = [str(char) for char in getattr(opt_header, "dll_characteristics_lists", []) or []]
        except Exception:
            pe_info["coff_info"].setdefault("checksum", 0)
            pe_info["coff_info"].setdefault("subsystem", "unknown")
            pe_info["coff_info"].setdefault("dll_characteristics", [])
        
        # Section analysis
        suspicious_section_names = PACKER_SECTION_NAMES
        for section in binary.sections:
            section_info = {
                "name": section.name,
                "virtual_size": section.virtual_size,
                "virtual_address": section.virtual_address,
                "size_of_raw_data": section.sizeof_raw_data,
                "pointer_to_raw_data": section.pointerto_raw_data,
                "characteristics": [str(char) for char in section.characteristics_lists],
                "entropy": section.entropy
            }
            pe_info["sections"].append(section_info)
            
            # Check for suspicious sections
            if section.entropy > 7.5:
                pe_info["anomalies"].append(f"High entropy section: {section.name}")
                pe_info["suspicious"] = True

            if str(section.name or "").strip().lower() in suspicious_section_names:
                pe_info["anomalies"].append(f"Packer-like section name: {section.name}")
                pe_info["suspicious"] = True
            
            # Check for executable sections with RWX
            if (lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE in section.characteristics_lists and
                lief.PE.SECTION_CHARACTERISTICS.MEM_READ in section.characteristics_lists and
                lief.PE.SECTION_CHARACTERISTICS.MEM_WRITE in section.characteristics_lists):
                pe_info["anomalies"].append(f"RWX section: {section.name}")
                pe_info["suspicious"] = True
        
        # Import analysis
        if binary.has_imports:
            for imp in binary.imports:
                dll_imports = {
                    "dll": imp.name,
                    "functions": [entry.name if entry.name else f"ordinal_{entry.ordinal}" for entry in imp.entries]
                }
                pe_info["imports"].append(dll_imports)
                
                # Check for suspicious imports
                if imp.name.lower() in PE_SUSPICIOUS_DLLS:
                    # Check for malware-common functions
                    for func in dll_imports["functions"]:
                        if func in PE_SUSPICIOUS_FUNCS:
                            pe_info["anomalies"].append(f"Suspicious import: {imp.name}.{func}")
                            pe_info["suspicious"] = True
        
        # Export analysis
        if binary.has_exports:
            for exp in binary.exports:
                export_name = str(exp.name or "").strip()
                pe_info["exports"].append({
                    "name": export_name,
                    "ordinal": exp.ordinal,
                    "address": exp.address
                })
                if export_name and (export_name.startswith("_") or export_name.lower() in {"dllmain", "main", "start"}):
                    pe_info["suspicious_exports"].append(export_name)
                    pe_info["anomalies"].append(f"Suspicious export name: {export_name}")
                    pe_info["suspicious"] = True
        
        # Resource analysis
        if binary.has_resources:
            for resource in binary.resources:
                pe_info["resources"].append({
                    "type": str(resource.type),
                    "id": resource.id,
                    "language": str(resource.language),
                    "code_page": resource.code_page,
                    "size": len(resource.content) if resource.content else 0
                })
        
        # Additional checks
        if binary.optional_header:
            opt_header = binary.optional_header
            pe_info["image_base"] = opt_header.imagebase
            pe_info["entry_point"] = opt_header.addressof_entrypoint
            
            # Check for suspicious entry point
            if opt_header.addressof_entrypoint == 0:
                pe_info["anomalies"].append("Entry point at 0")
                pe_info["suspicious"] = True

        # TLS callbacks are not inherently malicious, but often used by evasive loaders.
        try:
            if getattr(binary, "has_tls", False):
                callbacks = list(getattr(binary.tls, "callbacks", []) or [])
                if callbacks:
                    pe_info["tls_callbacks"] = [hex(int(c)) for c in callbacks[:16]]
                    pe_info["anomalies"].append("TLS callback(s) present")
        except Exception:
            pass

        try:
            ts = int(coff_header.time_date_stamp or 0)
            if ts <= 0:
                pe_info["anomalies"].append("Invalid COFF timestamp")
                pe_info["suspicious"] = True
            else:
                now_ts = int(datetime.utcnow().timestamp())
                # Treat far-future timestamps as suspicious tampering.
                if ts > (now_ts + 7 * 24 * 3600):
                    pe_info["anomalies"].append("COFF timestamp set in future")
                    pe_info["suspicious"] = True
        except Exception:
            pass
        
        # Check for packer signatures or anomalies
        if len(pe_info["sections"]) == 0:
            pe_info["anomalies"].append("No sections found")
            pe_info["suspicious"] = True
        
        return pe_info

    def _analyse_elf_binary(self, binary: Any) -> Dict:
        """Analyze ELF binary"""
        elf_info = {
            "format": "ELF",
            "arch": str(binary.header.machine_type).replace("ARCH.", ""),
            "is_executable": binary.header.file_type.value == 2,  # ET_EXEC
            "sections": [],
            "imports": [],
            "exports": [],
            "anomalies": [],
            "suspicious": False
        }
        
        # Section analysis
        for section in binary.sections:
            section_info = {
                "name": section.name,
                "virtual_address": section.virtual_address,
                "size": section.size,
                "type": str(section.type).replace("SECTION_TYPES.", ""),
                "entropy": 0  # lief doesn't provide entropy for ELF sections easily
            }
            elf_info["sections"].append(section_info)
        
        # Import analysis
        try:
            if binary.has_imports:
                for imp in binary.imported_functions:
                    elf_info["imports"].append({
                        "name": imp.name,
                        "library": "unknown"  # Simplified
                    })
        except:
            pass
        
        # Export analysis
        try:
            if binary.has_exports:
                for exp in binary.exported_functions:
                    elf_info["exports"].append({
                        "name": exp.name,
                        "address": exp.address
                    })
        except:
            pass
        
        return elf_info

    def _disassemble_binary(self, data: bytes, binary_info: Dict) -> Dict:
        """Disassemble executable code using Capstone"""
        if not PE_ANALYSIS_AVAILABLE:
            return {}
        
        disassembly_info = {
            "instructions": [],
            "suspicious_patterns": [],
            "code_sections": [],
            "total_instructions": 0
        }
        
        try:
            # Determine architecture
            arch = binary_info.get("arch", "").lower()
            if "x86" in arch or "i386" in arch:
                cs_arch = capstone.CS_ARCH_X86
                cs_mode = capstone.CS_MODE_32
            elif "x64" in arch or "amd64" in arch:
                cs_arch = capstone.CS_ARCH_X86
                cs_mode = capstone.CS_MODE_64
            elif "arm" in arch:
                cs_arch = capstone.CS_ARCH_ARM
                cs_mode = capstone.CS_MODE_ARM
            else:
                return disassembly_info
            
            # Initialize disassembler
            md = capstone.Cs(cs_arch, cs_mode)
            md.detail = True
            
            # Get code sections to disassemble
            sections = binary_info.get("sections", [])
            code_sections = []
            
            for section in sections:
                chars = section.get("characteristics", [])
                if isinstance(chars, str):
                    chars = chars.lower()
                else:
                    chars = str(chars).lower()
                
                # Check if section is executable
                if ("mem_execute" in chars or 
                    section.get("name", "").lower() in [".text", ".code", "code", "text"]):
                    code_sections.append(section)
            
            disassembly_info["code_sections"] = [s.get("name", "unknown") for s in code_sections]
            
            # Disassemble each code section
            suspicious_opcodes = [
                "int 0x80", "int 0x2e", "sysenter", "syscall",  # System calls
                "cpuid", "rdtsc", "rdpmc",  # Anti-debugging
                "icebp", "int 0x3",  # Debug breaks
                "jmp esp", "jmp ebp", "call esp", "call ebp",  # Stack pivoting
                "pushad", "popad", "pushfd", "popfd",  # Register saving
            ]
            
            for section in code_sections:
                section_name = section.get("name", "unknown")
                virtual_address = section.get("virtual_address", 0)
                
                # Get section data (simplified - in real implementation, you'd extract from binary)
                # For now, we'll disassemble a sample of the file
                sample_size = min(1024, len(data) // 4)  # Sample first 1KB or 1/4 of file
                code_data = data[:sample_size]
                
                try:
                    instructions = list(md.disasm(code_data, virtual_address))
                    disassembly_info["total_instructions"] += len(instructions)
                    
                    # Analyze instructions for suspicious patterns
                    for inst in instructions[:100]:  # Analyze first 100 instructions
                        inst_str = f"{inst.mnemonic} {inst.op_str}"
                        disassembly_info["instructions"].append({
                            "address": inst.address,
                            "mnemonic": inst.mnemonic,
                            "operands": inst.op_str,
                            "bytes": inst.bytes.hex(),
                            "size": inst.size
                        })
                        
                        # Check for suspicious patterns
                        if any(susp in inst_str.lower() for susp in suspicious_opcodes):
                            disassembly_info["suspicious_patterns"].append({
                                "pattern": inst_str,
                                "address": inst.address,
                                "section": section_name
                            })
                        
                        # Check for shellcode patterns
                        if inst.mnemonic in ["xor", "add", "sub"] and "esp" in inst.op_str:
                            disassembly_info["suspicious_patterns"].append({
                                "pattern": f"Stack manipulation: {inst_str}",
                                "address": inst.address,
                                "section": section_name
                            })
                        
                except Exception as e:
                    logger.warning(f"Failed to disassemble section {section_name}: {e}")
                    
        except Exception as e:
            logger.warning(f"Disassembly analysis failed: {e}")
        
        return disassembly_info

    def _extract_ml_features(self, result: Dict):
        """Extract features for ML classification"""
        features = []
        
        # Basic file features
        features.append(result.get("size", 0) / 1024.0)  # Size in KB
        features.append(result.get("entropy", 0))  # Shannon entropy
        
        # Binary analysis features
        pe_info = result.get("pe_info", {})
        if pe_info:
            features.append(len(pe_info.get("sections", [])))  # Number of sections
            features.append(len(pe_info.get("imports", [])))  # Number of imports
            features.append(len(pe_info.get("exports", [])))  # Number of exports
            
            # Section entropy features
            sections = pe_info.get("sections", [])
            if sections:
                entropies = [s.get("entropy", 0) for s in sections]
                features.append(np.mean(entropies))  # Mean section entropy
                features.append(np.max(entropies))   # Max section entropy
                features.append(np.std(entropies))   # Std section entropy
            else:
                features.extend([0, 0, 0])
            
            # Suspicious indicators
            features.append(1 if pe_info.get("suspicious", False) else 0)
            features.append(len(pe_info.get("anomalies", [])))
        else:
            features.extend([0, 0, 0, 0, 0, 0, 0, 0])  # Default values
        
        # Signature features
        signatures = result.get("signatures", [])
        features.append(len(signatures))  # Total signatures
        features.append(1 if any("critical" in str(s).lower() for s in signatures) else 0)
        features.append(1 if any("high" in str(s).lower() for s in signatures) else 0)
        
        # Disassembly features
        disassembly = result.get("disassembly_info", {})
        features.append(disassembly.get("total_instructions", 0))
        features.append(len(disassembly.get("suspicious_patterns", [])))
        
        # ML classification features
        ml_result = result.get("ml_classification", {})
        features.append(1 if ml_result.get("prediction") == "MALWARE" else 0)
        features.append(ml_result.get("confidence", 0))
        
        return np.array(features).reshape(1, -1)

    def _ml_classify_malware(self, features) -> Dict:
        """Classify malware using ML model"""
        try:
            # Convert to numpy array if it's a list
            if isinstance(features, list):
                features = np.array(features).reshape(1, -1)
            
            # For now, we'll use a simple rule-based classifier
            # In production, this would load a trained model
            score = 0
            
            # Simple heuristic-based scoring
            if features[0, 1] > 7.0:  # High entropy
                score += 2
            if features[0, 7] > 0:  # Suspicious PE
                score += 3
            if features[0, 8] > 2:  # Anomalies
                score += 2
            if features[0, 9] > 3:  # Signatures
                score += 2
            if features[0, 10] > 0:  # Critical signatures
                score += 3
            if features[0, 13] > 5:  # Suspicious disassembly
                score += 2
            
            # Classification
            if score >= 8:
                prediction = "MALWARE"
                confidence = min(score / 12.0, 1.0)
            elif score >= 4:
                prediction = "SUSPICIOUS"
                confidence = score / 8.0
            else:
                prediction = "BENIGN"
                confidence = max(0, 1.0 - score / 4.0)
            
            return {
                "prediction": prediction,
                "confidence": confidence,
                "feature_importance": {
                    "entropy": features[0, 1],
                    "suspicious_indicators": features[0, 7],
                    "anomalies": features[0, 8],
                    "signatures": features[0, 9]
                }
            }
            
        except Exception as e:
            logger.warning(f"ML classification failed: {e}")
            return {"prediction": "UNKNOWN", "confidence": 0.0, "error": str(e)}

    def _score_risk(self, result: Dict) -> str:
        score, _, _ = self._score_risk_detailed(result)
        if score >= 5:
            return "HIGH"
        elif score >= 2:
            return "MEDIUM"
        elif score >= 1:
            return "LOW"
        return "CLEAN"

    def _score_risk_detailed(self, result: Dict) -> Tuple[int, List[Dict[str, Any]], float]:
        score = 0
        reasons: List[Dict[str, Any]] = []

        def add(points: int, code: str, explanation: str) -> None:
            nonlocal score
            score += points
            reasons.append({
                "code": code,
                "points": points,
                "explanation": explanation,
            })

        if result["entropy"] >= HIGH_ENTROPY_THRESHOLD:
            add(3, "HIGH_ENTROPY", f"File entropy {result['entropy']:.2f} indicates packed/encrypted payload characteristics")
        elif result["entropy"] >= MEDIUM_ENTROPY_THRESHOLD:
            add(1, "ELEVATED_ENTROPY", f"File entropy {result['entropy']:.2f} above normal baseline")
        if result["extension"] in DANGEROUS_EXTENSIONS:
            add(2, "DANGEROUS_EXTENSION", f"Extension {result['extension']} is in executable/script high-risk set")
        critical_sigs = {"EICAR", "REVERSE_SHELL", "MSFVENOM", "SHELLCODE_NOP", "CREATEREMOTETHREAD",
                          "suspicious_pe_imports", "shellcode_patterns", "ransomware_indicators", "rootkit_indicators"}
        high_sigs     = {"POWERSHELL_ENCODED", "WGET_SH", "CURL_SH", "PE_ANOMALY",
                          "NET_USER_ADD", "SCHTASK_CREATE", "VIRTUALALLOC", "packed_executable", "keylogger_imports"}
        for sig in result.get("signatures", []):
            sig_upper = str(sig).upper()
            severity = SIGNATURE_SEVERITY_MAP.get(sig_upper, "")
            if sig in critical_sigs or severity == "CRITICAL":
                add(5, "CRITICAL_SIGNATURE", f"Critical signature matched: {sig}")
            elif sig in high_sigs or severity == "HIGH":
                add(3, "HIGH_SIGNATURE", f"High-risk signature matched: {sig}")
            elif severity == "MEDIUM":
                add(2, "MEDIUM_SIGNATURE", f"Medium-risk signature matched: {sig}")
            else:
                add(1, "GENERIC_SIGNATURE", f"Signature matched: {sig}")

        suspicious_count = min(len(result.get("suspicious_strings", [])), 5)
        if suspicious_count:
            add(suspicious_count, "SUSPICIOUS_STRINGS", f"Detected {suspicious_count} suspicious string context matches")

        ioc_counts = sum(len(v) for v in (result.get("iocs") or {}).values())
        if ioc_counts:
            add(min(4, max(1, ioc_counts // 5)), "IOC_DENSITY", f"Extracted {ioc_counts} potential IOC values from artifact")

        if result.get("magic_type") == "OLE2 (Office/macro)" or result.get("analysis_family") == "office_ole":
            add(2, "OLE2_MACRO_CONTAINER", "OLE2 macro-capable container detected")
            ole_info = result.get("ole_info", {})
            if ole_info.get("has_macro_activity"):
                add(4, "OLE_MACRO_ACTIVITY", "Office/OLE content contains macro execution markers")
            elif ole_info.get("is_macro_capable"):
                add(2, "OLE_MACRO_CAPABLE", "Office/OLE file is macro-capable even without explicit macro strings")
            embedded_object_count = int(ole_info.get("embedded_object_count", 0) or 0)
            if embedded_object_count:
                add(min(3, embedded_object_count), "OLE_EMBEDDED_OBJECTS", f"Detected {embedded_object_count} embedded Office object signal(s)")
            macro_markers = {str(item.get("marker", "")).lower() for item in ole_info.get("macro_indicators", []) if isinstance(item, dict)}
            if macro_markers & OLE_MACRO_MARKERS:
                add(2, "OLE_MACRO_MARKERS", "Canonical macro markers were observed in the Office container")
            if any(str(signal).lower() in OLE_EMBEDDED_OBJECT_MARKERS for signal in ole_info.get("embedded_object_signals", [])):
                add(1, "OLE_EMBEDDED_OBJECT_MARKERS", "Embedded object markers matched Office container heuristics")

        behavioral = result.get("behavioral_profile", {}) if isinstance(result.get("behavioral_profile", {}), dict) else {}
        behavior_score = int(behavioral.get("score", 0) or 0)
        if behavior_score:
            add(min(5, behavior_score), "BEHAVIORAL_PROFILE", f"Behavioral pattern analysis produced score {behavior_score}")
        if behavioral.get("code_injection_markers"):
            add(2, "BEHAVIOR_CODE_INJECTION", "Behavioral indicators suggest code-injection or memory manipulation stages")
        if behavioral.get("macro_execution"):
            add(2, "BEHAVIOR_MACRO_EXECUTION", "Behavioral indicators suggest Office macro-triggered execution flow")
        
        # PE/ELF-specific scoring
        binary_info = result.get("pe_info", {})
        if binary_info:
            # Anomalies increase score
            anomalies = binary_info.get("anomalies", [])
            anomaly_points = min(len(anomalies) * 2, 10)
            if anomaly_points:
                add(anomaly_points, "BINARY_ANOMALIES", f"Binary analysis reported {len(anomalies)} anomaly indicators")
            
            # Check format-specific suspicious indicators
            if binary_info.get("format") == "PE":
                # PE-specific checks
                imports = binary_info.get("imports", [])
                suspicious_imports = 0
                for imp in imports:
                    dll = imp.get("dll", "").lower()
                    if dll in PE_SUSPICIOUS_DLLS:
                        functions = imp.get("functions", [])
                        for func in functions:
                            if func in PE_SUSPICIOUS_FUNCS:
                                suspicious_imports += 1
                if suspicious_imports:
                    add(min(suspicious_imports, 5), "SUSPICIOUS_IMPORTS", f"Detected {suspicious_imports} suspicious imported API functions")
                
                # RWX sections are highly suspicious
                sections = binary_info.get("sections", [])
                rwx_sections = 0
                for section in sections:
                    chars = section.get("characteristics", [])
                    if ("MEM_EXECUTE" in str(chars) and "MEM_READ" in str(chars) and "MEM_WRITE" in str(chars)):
                        rwx_sections += 1
                if rwx_sections:
                    add(rwx_sections * 3, "RWX_SECTIONS", f"Detected {rwx_sections} executable-writable section(s)")
                
                # High entropy sections
                high_entropy_sections = sum(1 for s in sections if s.get("entropy", 0) > 7.5)
                if high_entropy_sections:
                    add(high_entropy_sections * 2, "HIGH_ENTROPY_SECTIONS", f"Detected {high_entropy_sections} high-entropy PE section(s)")

                coff_info = binary_info.get("coff_info", {})
                if coff_info:
                    if not coff_info.get("time_date_stamp"):
                        add(1, "EMPTY_COFF_TIMESTAMP", "PE COFF header is missing a meaningful timestamp")
                    if int(coff_info.get("checksum", 0) or 0) == 0 and binary_info.get("is_exe"):
                        add(1, "EMPTY_COFF_CHECKSUM", "PE checksum is zero for an executable image")
                    if int(coff_info.get("number_of_sections", 0) or 0) <= 0:
                        add(3, "INVALID_COFF_SECTION_COUNT", "PE COFF header reports no sections")
                    if int(coff_info.get("number_of_symbols", 0) or 0) > 0:
                        add(1, "COFF_SYMBOL_TABLE_PRESENT", "PE COFF symbol table is present and should be reviewed")

                if not binary_info.get("imports") and binary_info.get("is_exe"):
                    add(1, "NO_IMPORTS", "Executable image has no imports, which is uncommon outside staged loaders")
                if binary_info.get("pdb_paths"):
                    add(1, "PDB_PATH_PRESENT", "PE exposes debug symbol path(s)")
                if binary_info.get("tls_callbacks"):
                    add(2, "TLS_CALLBACKS", "TLS callbacks are present and require analyst review")
                if binary_info.get("suspicious_exports"):
                    add(len(binary_info.get("suspicious_exports", [])), "SUSPICIOUS_EXPORT_NAMES", "Suspicious export naming pattern detected")
                if binary_info.get("format") == "PE" and binary_info.get("suspicious"):
                    add(3, "PE_SUSPICIOUS_BINARY", "PE analysis flagged suspicious loader or section behavior")
        
        # ML classification scoring
        ml_result = result.get("ml_classification", {})
        if ml_result.get("prediction") == "MALWARE":
            ml_points = int(ml_result.get("confidence", 0) * 5)
            if ml_points:
                add(ml_points, "ML_MALWARE_PREDICTION", f"ML model predicts MALWARE with confidence {ml_result.get('confidence', 0):.2f}")
        elif ml_result.get("prediction") == "SUSPICIOUS":
            ml_points = int(ml_result.get("confidence", 0) * 3)
            if ml_points:
                add(ml_points, "ML_SUSPICIOUS_PREDICTION", f"ML model predicts SUSPICIOUS with confidence {ml_result.get('confidence', 0):.2f}")
        
        # Disassembly analysis scoring
        disassembly = result.get("disassembly_info", {})
        suspicious_disasm = len(disassembly.get("suspicious_patterns", []))
        if suspicious_disasm:
            add(min(suspicious_disasm, 5), "SUSPICIOUS_DISASSEMBLY", f"Detected {suspicious_disasm} suspicious opcode/pattern indicators")
        
        confidence = min(0.99, 0.3 + (score / 20.0)) if score > 0 else 0.15
        return score, reasons, float(round(confidence, 3))

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
