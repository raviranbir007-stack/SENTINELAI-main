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
    import lief
    import capstone
    import yara
    PE_ANALYSIS_AVAILABLE = True
except ImportError:
    pefile = None
    lief = None
    capstone = None
    yara = None
    PE_ANALYSIS_AVAILABLE = False

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
if not ML_ANALYSIS_AVAILABLE:
    logger.warning("ML analysis libraries not available. Using rule-based classification.")


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
        self.yara_rules = None
        self._load_yara_rules()
        self._init_db()

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
        if not PE_ANALYSIS_AVAILABLE:
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
        if not self.yara_rules:
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
            
            # YARA scanning
            yara_matches = self._scan_yara(sample)
            result["signatures"].extend(yara_matches)

            pe_info = self._analyse_pe(sample)
            if pe_info:
                result["pe_info"] = pe_info
                if pe_info.get("suspicious"):
                    result["signatures"].append("PE_ANOMALY")
                
                # Add disassembly analysis
                disassembly_info = self._disassemble_binary(sample, pe_info)
                if disassembly_info:
                    result["disassembly_info"] = disassembly_info
                    # Add suspicious disassembly patterns to signatures
                    if disassembly_info.get("suspicious_patterns"):
                        result["signatures"].append("SUSPICIOUS_DISASSEMBLY")
            
            # ML-based classification
            if ML_ANALYSIS_AVAILABLE:
                ml_features = self._extract_ml_features(result)
                ml_result = self._ml_classify_malware(ml_features)
                result["ml_classification"] = ml_result
            else:
                result["ml_classification"] = {"prediction": "UNKNOWN", "confidence": 0.0}

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
        if not PE_ANALYSIS_AVAILABLE:
            # Fallback to basic analysis
            return self._analyse_pe_basic(data)
        
        try:
            # Use lief for advanced binary analysis
            binary = lief.parse(data)
            
            if isinstance(binary, lief.PE.Binary):
                return self._analyse_pe_binary(binary)
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
        score = 0
        if result["entropy"] >= HIGH_ENTROPY_THRESHOLD:
            score += 3
        elif result["entropy"] >= MEDIUM_ENTROPY_THRESHOLD:
            score += 1
        if result["extension"] in DANGEROUS_EXTENSIONS:
            score += 2
        critical_sigs = {"EICAR", "REVERSE_SHELL", "MSFVENOM", "SHELLCODE_NOP", "CREATEREMOTETHREAD",
                          "suspicious_pe_imports", "shellcode_patterns", "ransomware_indicators", "rootkit_indicators"}
        high_sigs     = {"POWERSHELL_ENCODED", "WGET_SH", "CURL_SH", "PE_ANOMALY",
                          "NET_USER_ADD", "SCHTASK_CREATE", "VIRTUALALLOC", "packed_executable", "keylogger_imports"}
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
        
        # PE/ELF-specific scoring
        binary_info = result.get("pe_info", {})
        if binary_info:
            # Anomalies increase score
            anomalies = binary_info.get("anomalies", [])
            score += min(len(anomalies) * 2, 10)  # Up to 10 points for anomalies
            
            # Check format-specific suspicious indicators
            if binary_info.get("format") == "PE":
                # PE-specific checks
                imports = binary_info.get("imports", [])
                suspicious_imports = 0
                for imp in imports:
                    dll = imp.get("dll", "").lower()
                    if dll in ["kernel32.dll", "user32.dll", "advapi32.dll", "ws2_32.dll"]:
                        functions = imp.get("functions", [])
                        malware_funcs = ["CreateRemoteThread", "VirtualAlloc", "WriteProcessMemory", 
                                       "CreateProcess", "ShellExecute", "WinExec", "LoadLibrary"]
                        for func in functions:
                            if func in malware_funcs:
                                suspicious_imports += 1
                score += min(suspicious_imports, 5)
                
                # RWX sections are highly suspicious
                sections = binary_info.get("sections", [])
                rwx_sections = 0
                for section in sections:
                    chars = section.get("characteristics", [])
                    if ("MEM_EXECUTE" in str(chars) and "MEM_READ" in str(chars) and "MEM_WRITE" in str(chars)):
                        rwx_sections += 1
                score += rwx_sections * 3
                
                # High entropy sections
                high_entropy_sections = sum(1 for s in sections if s.get("entropy", 0) > 7.5)
                score += high_entropy_sections * 2
        
        # ML classification scoring
        ml_result = result.get("ml_classification", {})
        if ml_result.get("prediction") == "MALWARE":
            score += int(ml_result.get("confidence", 0) * 5)  # Up to 5 points
        elif ml_result.get("prediction") == "SUSPICIOUS":
            score += int(ml_result.get("confidence", 0) * 3)  # Up to 3 points
        
        # Disassembly analysis scoring
        disassembly = result.get("disassembly_info", {})
        suspicious_disasm = len(disassembly.get("suspicious_patterns", []))
        score += min(suspicious_disasm, 5)  # Up to 5 points for suspicious disassembly
        
        if score >= 5:
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
