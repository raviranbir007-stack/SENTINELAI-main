import random
import hashlib
import importlib.util
import math
import os
import re as _re
import json
import struct
import logging
from collections import defaultdict
from datetime import datetime, timedelta
from io import BytesIO
from pathlib import Path
from typing import Optional, List, Dict

from fastapi import APIRouter, File, HTTPException, UploadFile, Depends
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func, or_

from ..config import settings
from ..core.report_generator import report_generator
from ..core.threat_analyzer import threat_analyzer
from ..database import get_db
from ..models import AttackEvent, ScanHistory, SystemLog

# Initialize the router for all compatibility endpoints
router = APIRouter()

# ─────────────────────────────────────────────────────────────────────────────
# Local file analysis helpers (no external API keys required)
# ─────────────────────────────────────────────────────────────────────────────

_BYTE_SIGS: List[tuple] = [
    # (name, pattern_bytes, description, severity)
    ("EICAR",             b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
                          "EICAR AV test file",          "critical"),
    ("SHELLCODE_NOP",     b"\x90\x90\x90\x90\x90\x90\x90\x90",
                          "NOP sled – shellcode",        "high"),
    ("REVERSE_SHELL",     b"/bin/sh\x00-i",
                          "Reverse-shell string",        "critical"),
    ("MSFVENOM",          b"msfvenom",
                          "Metasploit payload marker",   "critical"),
    ("XOR_DECODE_STUB",   b"xor eax",
                          "XOR decode stub (shellcode)", "high"),
    ("JAVA_CLASS",        b"\xca\xfe\xba\xbe",
                          "Java class file",             "medium"),
]

_REGEX_SIGS: List[tuple] = [
    # (name, pattern, severity)
    ("POWERSHELL_ENC",     r"powershell.*-enc",                          "high"),
    ("WGET_PIPE_SH",       r"wget\s+.*\|\s*(ba)?sh",                    "high"),
    ("CURL_PIPE_BASH",     r"curl\s+.*\|\s*(ba)?bash",                  "high"),
    ("BASE64_DECODE",      r"base64\s+--?decode",                       "medium"),
    ("NET_USER_ADD",       r"net\s+user.*\/add",                        "high"),
    ("SCHTASK_CREATE",     r"schtasks.*\/create",                       "high"),
    ("CREATEREMOTETHREAD", r"CreateRemoteThread",                       "critical"),
    ("VIRTUALALLOC",       r"VirtualAlloc",                             "high"),
    ("WSCRIPT_SHELL",      r"WScript\.Shell",                           "high"),
    ("OBFUSCATED_EVAL",    r"eval\s*\(\s*(?:unescape|base64|gzip|rot13)", "high"),
    ("LINUX_DROPPER",      r"chmod\s+\+x.*&&",                         "high"),
    ("PYTHON_EXEC",        r"exec\s*\(\s*__import__",                  "high"),
]

_MAGIC_MAP: Dict[bytes, tuple] = {
    b"MZ":               ("Windows PE executable",  False),
    b"\x7fELF":          ("Linux ELF executable",   False),
    b"\xca\xfe\xba\xbe": ("Java class file",        True),
    b"#!/":              ("Script file",             False),
    b"PK\x03\x04":       ("ZIP archive",            False),
    b"Rar!":             ("RAR archive",             False),
    b"\x1f\x8b":         ("GZIP compressed",        False),
    b"\xd0\xcf\x11\xe0": ("OLE2 / Office macro",   True),
    b"%PDF":             ("PDF document",            False),
    b"\x89PNG":          ("PNG image",               False),
    b"GIF8":             ("GIF image",               False),
    b"\xff\xd8\xff":     ("JPEG image",              False),
}

_DANGEROUS_EXTS = {
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js",
    ".jse", ".wsf", ".wsh", ".msi", ".scr", ".pif", ".com", ".hta",
    ".cpl", ".reg", ".lnk", ".inf", ".jar", ".docm", ".xlsm",
    ".pptm", ".dotm", ".xltm", ".xlam", ".ppam", ".gadget",
}

_SUSPICIOUS_STR_PATS = [
    r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
    r"/etc/passwd", r"/etc/shadow",
    r"cmd\.exe", r"powershell",
    r"\\AppData\\Roaming",
    r"CreateRemoteThread", r"VirtualAlloc", r"WriteProcessMemory",
    r"ShellExecute", r"WScript\.Shell",
    r"eval\s*\(", r"exec\s*\(",
    r"base64_decode", r"gzinflate", r"str_rot13",
]

_PHISHING_LURE_PATS = [
    ("PHISHING_VERIFY_ACCOUNT", r"verify\s+your\s+account|account\s+verification|confirm\s+your\s+account", "high"),
    ("PHISHING_ACCOUNT_SUSPENDED", r"account\s+(?:has\s+been\s+)?suspended|unusual\s+login\s+attempt", "high"),
    ("PHISHING_PAYMENT_URGENT", r"payment\s+failed|billing\s+issue|update\s+payment\s+method", "high"),
    ("PHISHING_CREDENTIAL_HARVEST", r"(enter|confirm|re-enter)\s+(your\s+)?(password|otp|one-time\s+password|2fa\s+code)", "medium"),
]

_HIGH_ENTROPY  = 7.2
_MED_ENTROPY   = 6.5
_MAX_SAMPLE    = 1 * 1024 * 1024   # 1 MB sample for local analysis
_MAX_FILE_SIZE = 100 * 1024 * 1024 # 100 MB upload limit


def _normalize_verdict(verdict: object, default: str = "unknown") -> str:
    value = verdict if verdict is not None else default
    if hasattr(value, "value"):
        value = getattr(value, "value")
    elif hasattr(value, "name"):
        value = getattr(value, "name")

    normalized = str(value or default).strip().lower()
    if normalized.startswith("threatlevel."):
        normalized = normalized.split(".", 1)[1]

    if normalized == "safe":
        return "clean"
    if normalized == "critical":
        return "malicious"
    return normalized or default


def _calc_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq: Dict[int, int] = defaultdict(int)
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values() if c)


def _identify_magic(data: bytes) -> str:
    for magic, (desc, _) in _MAGIC_MAP.items():
        if data[: len(magic)] == magic:
            return desc
    return "Unknown"


def _analyse_pe(data: bytes) -> Optional[Dict]:
    if data[:2] != b"MZ":
        return None


def _disassembly_info(data: bytes, pe_info: Optional[Dict]) -> Optional[Dict]:
    """Best-effort disassembly metadata for executable-like payloads."""
    if importlib.util.find_spec("capstone") is None:
        return None
    if not data or len(data) < 32:
        return None

    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64  # type: ignore

        arch = str((pe_info or {}).get("arch") or "").lower()
        mode = CS_MODE_64 if arch == "x64" else CS_MODE_32

        md = Cs(CS_ARCH_X86, mode)
        md.detail = False
        instructions = list(md.disasm(data[:256], 0x1000))
        if not instructions:
            return None

        suspicious_mnemonics = {"syscall", "sysenter", "int", "int3", "rdtsc", "cpuid"}
        suspicious_patterns = []
        for ins in instructions:
            mnemonic = str(getattr(ins, "mnemonic", "") or "").lower()
            if mnemonic in suspicious_mnemonics:
                suspicious_patterns.append(
                    {
                        "mnemonic": mnemonic,
                        "op_str": str(getattr(ins, "op_str", "") or ""),
                    }
                )
            if len(suspicious_patterns) >= 8:
                break

        return {
            "engine": "capstone",
            "architecture": "x64" if mode == CS_MODE_64 else "x86",
            "instruction_count": len(instructions),
            "suspicious_patterns": suspicious_patterns,
        }
    except Exception:
        return None


def _ml_classification(entropy: float, signatures: List[Dict], ext: str, pe_info: Optional[Dict]) -> Optional[Dict]:
    """Lightweight ML classification metadata when sklearn is available."""
    if importlib.util.find_spec("sklearn") is None:
        return None

    try:
        import numpy as np  # type: ignore
        from sklearn.linear_model import LogisticRegression  # type: ignore

        feature_vector = np.array(
            [[
                float(entropy),
                float(len(signatures)),
                float(1 if ext in _DANGEROUS_EXTS else 0),
                float(1 if pe_info else 0),
                float(1 if pe_info and pe_info.get("suspicious") else 0),
            ]]
        )

        train_x = np.array(
            [
                [1.2, 0, 0, 0, 0],
                [2.8, 0, 0, 0, 0],
                [4.2, 1, 0, 0, 0],
                [5.6, 1, 1, 0, 0],
                [6.4, 2, 1, 1, 0],
                [7.1, 3, 1, 1, 1],
                [7.8, 4, 1, 1, 1],
                [8.4, 5, 1, 1, 1],
            ],
            dtype=float,
        )
        train_y = np.array([0, 0, 0, 0, 1, 1, 1, 1], dtype=int)

        model = LogisticRegression(max_iter=200, random_state=42)
        model.fit(train_x, train_y)
        malicious_prob = float(model.predict_proba(feature_vector)[0][1])

        if malicious_prob >= 0.65:
            prediction = "MALICIOUS"
        elif malicious_prob >= 0.45:
            prediction = "SUSPICIOUS"
        else:
            prediction = "CLEAN"

        return {
            "model": "logistic_regression_synthetic_baseline",
            "prediction": prediction,
            "confidence": round(malicious_prob, 3),
            "features": {
                "entropy": round(float(entropy), 3),
                "signature_count": int(len(signatures)),
                "dangerous_extension": bool(ext in _DANGEROUS_EXTS),
                "has_pe": bool(pe_info),
                "pe_suspicious": bool(pe_info and pe_info.get("suspicious")),
            },
        }
    except Exception:
        return None
    try:
        if len(data) < 0x40:
            return None
        pe_off = struct.unpack_from("<I", data, 0x3C)[0]
        if pe_off + 24 > len(data):
            return None
        if data[pe_off: pe_off + 4] != b"PE\x00\x00":
            return None
        chars   = struct.unpack_from("<H", data, pe_off + 22)[0]
        opt_mag = struct.unpack_from("<H", data, pe_off + 24)[0]
        arch    = "x86" if opt_mag == 0x10B else "x64" if opt_mag == 0x20B else "unknown"
        is_dll  = bool(chars & 0x2000)
        no_reloc = bool(chars & 0x0001)
        return {"arch": arch, "is_dll": is_dll, "no_reloc": no_reloc,
                "suspicious": no_reloc and not is_dll}
    except Exception:
        return None


def _local_file_analysis(content: bytes, filename: str) -> Dict:
    """
    Perform fast, in-process file analysis (no external API keys needed).
    Returns risk_level in {CRITICAL, HIGH, MEDIUM, LOW, CLEAN} and
    a list of threat_indicators compatible with the rest of the system.
    """
    p   = Path(filename) if filename else Path("unknown")
    ext = p.suffix.lower()
    sample = content[: _MAX_SAMPLE]

    entropy    = _calc_entropy(sample)
    magic_type = _identify_magic(sample)
    pe_info    = _analyse_pe(sample)

    matched_sigs: List[Dict] = []
    text = sample.decode("latin-1", errors="replace")

    # Byte signatures
    for name, pattern, desc, sev in _BYTE_SIGS:
        if isinstance(pattern, bytes) and pattern in sample:
            matched_sigs.append({"name": name, "desc": desc, "severity": sev})

    # Regex signatures
    for name, pattern, sev in _REGEX_SIGS:
        try:
            if _re.search(pattern, text, _re.IGNORECASE):
                matched_sigs.append({"name": name, "desc": name.replace("_", " ").title(), "severity": sev})
        except Exception:
            pass

    # Phishing-kit specific HTML and lure language detection
    text_lower = text.lower()
    has_password_input = bool(_re.search(r"<input[^>]+type\s*=\s*['\"]?password", text, _re.IGNORECASE))
    has_form = "<form" in text_lower
    has_remote_action = bool(_re.search(r"<form[^>]+action\s*=\s*['\"]https?://", text, _re.IGNORECASE))

    if has_form and has_password_input and (has_remote_action or "action=" in text_lower):
        matched_sigs.append({
            "name": "PHISHING_LOGIN_FORM",
            "desc": "Credential login form with explicit action target",
            "severity": "high",
        })

    for name, pattern, sev in _PHISHING_LURE_PATS:
        try:
            if _re.search(pattern, text, _re.IGNORECASE):
                matched_sigs.append({"name": name, "desc": name.replace("_", " ").title(), "severity": sev})
        except Exception:
            pass

    if "window.location" in text_lower and ("atob(" in text_lower or "fromcharcode(" in text_lower):
        matched_sigs.append({
            "name": "OBFUSCATED_REDIRECT",
            "desc": "Obfuscated JavaScript redirect logic",
            "severity": "high",
        })

    # Suspicious strings
    susp_strings: List[str] = []
    for pat in _SUSPICIOUS_STR_PATS:
        m = _re.search(pat, text, _re.IGNORECASE)
        if m:
            susp_strings.append(m.group(0)[:120])
    susp_strings = list(set(susp_strings))[:20]

    # Build threat_indicators
    threat_indicators: List[Dict] = []

    for sig in matched_sigs:
        sev = sig.get("severity", "medium")
        conf = {"critical": 1.0, "high": 0.85, "medium": 0.65}.get(sev, 0.5)
        threat_indicators.append({
            "source": "Local Analysis",
            "severity": sev,
            "indicator": f"Signature match: {sig.get('desc', sig['name'])}",
            "type": sig["name"],
            "confidence": conf,
        })

    if entropy >= _HIGH_ENTROPY:
        threat_indicators.append({
            "source": "Local Analysis",
            "severity": "high",
            "indicator": f"Very high entropy ({entropy:.2f}) — likely encrypted/packed payload",
            "type": "HIGH_ENTROPY",
            "confidence": 0.78,
        })
    elif entropy >= _MED_ENTROPY:
        threat_indicators.append({
            "source": "Local Analysis",
            "severity": "medium",
            "indicator": f"Elevated entropy ({entropy:.2f}) — possible obfuscation",
            "type": "MED_ENTROPY",
            "confidence": 0.55,
        })

    if ext in _DANGEROUS_EXTS:
        threat_indicators.append({
            "source": "Local Analysis",
            "severity": "medium",
            "indicator": f"Potentially dangerous file extension: {ext}",
            "type": "DANGEROUS_EXT",
            "confidence": 0.60,
        })

    if pe_info and pe_info.get("suspicious"):
        threat_indicators.append({
            "source": "Local Analysis",
            "severity": "high",
            "indicator": "PE header anomaly — no relocation, not a DLL (suspicious executable)",
            "type": "PE_ANOMALY",
            "confidence": 0.80,
        })

    if len(susp_strings) >= 3:
        threat_indicators.append({
            "source": "Local Analysis",
            "severity": "medium",
            "indicator": f"Multiple suspicious strings ({len(susp_strings)}): {', '.join(susp_strings[:3])}",
            "type": "SUSPICIOUS_STRINGS",
            "confidence": 0.60,
        })

    # Risk scoring
    _SEV_SCORE = {"critical": 5, "high": 3, "medium": 2, "low": 1}
    score = sum(_SEV_SCORE.get(ind.get("severity", "low"), 1) for ind in threat_indicators)

    if score >= 8:
        risk_level = "CRITICAL"
    elif score >= 5:
        risk_level = "HIGH"
    elif score >= 2:
        risk_level = "MEDIUM"
    elif score >= 1:
        risk_level = "LOW"
    else:
        risk_level = "CLEAN"

    disassembly_info = _disassembly_info(sample, pe_info)
    ml_classification = _ml_classification(entropy, matched_sigs, ext, pe_info)

    return {
        "local_analysis": True,
        "entropy": round(entropy, 3),
        "file_extension": ext,
        "magic_type": magic_type,
        "signatures": [s["name"] for s in matched_sigs],
        "suspicious_strings": susp_strings,
        "pe_info": pe_info,
        "disassembly_info": disassembly_info,
        "ml_classification": ml_classification,
        "risk_score": score,
        "risk_level": risk_level,
        "threat_indicators": threat_indicators,
    }


def _build_file_summary(filename: str, local: Dict, final_verdict: str,
                        all_indicators: List[Dict]) -> str:
    risk   = local.get("risk_level", "CLEAN")
    sigs   = local.get("signatures", [])
    entropy = local.get("entropy", 0.0)
    magic  = local.get("magic_type", "Unknown")

    if final_verdict == "malicious":
        parts = [f"⛔ MALICIOUS: {filename} detected as malicious."]
        if sigs:
            parts.append(f"Signatures matched: {', '.join(sigs)}.")
        parts.append(f"Entropy: {entropy:.2f} | Type: {magic}.")
        parts.append(f"{len(all_indicators)} threat indicator(s) identified.")
        return " ".join(parts)
    elif final_verdict == "suspicious":
        parts = [f"⚠ SUSPICIOUS: {filename} shows suspicious characteristics."]
        if sigs:
            parts.append(f"Matched patterns: {', '.join(sigs)}.")
        parts.append(f"Entropy: {entropy:.2f} | Type: {magic}.")
        return " ".join(parts)
    else:
        return (f"✅ {filename} appears clean. "
                f"Entropy: {entropy:.2f} | Type: {magic} | "
                f"Local risk: {risk}.")

router = APIRouter()
logger = logging.getLogger(__name__)

GENERATED_REPORTS_DIR = Path(__file__).resolve().parents[2] / "generated_reports"
REPORTS_INDEX_FILE = GENERATED_REPORTS_DIR / "reports_index.json"


def _load_persistent_reports() -> list[dict]:
    try:
        if not REPORTS_INDEX_FILE.exists():
            return []
        with REPORTS_INDEX_FILE.open("r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            return data
        return []
    except Exception as e:
        logger.warning(f"Failed to load reports index: {e}")
        return []


def _save_persistent_reports() -> None:
    try:
        GENERATED_REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        with REPORTS_INDEX_FILE.open("w", encoding="utf-8") as f:
            json.dump(REPORTS_STORE, f, ensure_ascii=False, indent=2)
    except Exception as e:
        logger.warning(f"Failed to save reports index: {e}")


def store_report_artifacts(report_meta: dict, pdf_bytes: bytes) -> None:
    """Persist report metadata + PDF to memory and disk."""
    report_id = report_meta.get("report_id")
    if not report_id:
        return

    GENERATED_REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    report_file = GENERATED_REPORTS_DIR / f"{report_id}.pdf"
    report_file.write_bytes(pdf_bytes)

    report_meta = {**report_meta, "report_path": str(report_file)}

    # upsert by report_id
    existing_idx = next((i for i, r in enumerate(REPORTS_STORE) if r.get("report_id") == report_id), None)
    if existing_idx is None:
        REPORTS_STORE.append(report_meta)
    else:
        REPORTS_STORE[existing_idx] = report_meta

    REPORTS_PDF_CACHE[report_id] = pdf_bytes

    # keep only latest N report metadata
    if len(REPORTS_STORE) > 500:
        del REPORTS_STORE[:-500]

    # keep only latest N in-memory PDFs
    if len(REPORTS_PDF_CACHE) > 100:
        oldest_ids = sorted(REPORTS_PDF_CACHE.keys())[:-100]
        for old_id in oldest_ids:
            REPORTS_PDF_CACHE.pop(old_id, None)

    _save_persistent_reports()

# In-memory scan store for compatibility (ephemeral)
SCANS_STORE: list[dict] = []
MAX_STORE = 100

# In-memory reports store
REPORTS_STORE: list[dict] = _load_persistent_reports()
# Report PDF cache (report_id -> pdf_bytes)
REPORTS_PDF_CACHE: dict[str, bytes] = {}


def _is_low_signal_suspicious_ip_scan(scan: ScanHistory) -> bool:
    """Return True for low-confidence single-source suspicious IP scans."""
    level = str(scan.threat_level or "unknown").lower()
    target_type = str(scan.target_type or "unknown").lower()
    if level != "suspicious" or target_type != "ip":
        return False

    try:
        confidence = float(scan.confidence or 0.0)
    except Exception:
        confidence = 0.0

    analysis = scan.analysis_data or {}
    indicators = analysis.get("threat_indicators") or []
    warnings = analysis.get("warnings") or []
    corroboration_count = int(scan.corroboration_count or 0)
    summary_blob = " ".join([
        str(analysis.get("summary", "") or ""),
        " ".join(str(w) for w in warnings),
        " ".join(str(r) for r in (analysis.get("recommendations") or [])),
    ]).lower()

    return (
        confidence < 0.5
        and len(indicators) <= 1
        and len(warnings) <= 1
        and corroboration_count <= 1
        and (
            "single source" in summary_blob
            or "limited corroboration" in summary_blob
            or "minor threat indicators" in summary_blob
        )
    )


async def _save_scan_to_db(scan_data: dict, db: AsyncSession):
    """Save scan result to database for historical reporting"""
    import logging
    logger = logging.getLogger(__name__)

    if os.getenv("PYTEST_CURRENT_TEST"):
        logger.debug("Skipping database persistence for pytest-generated compatibility scan")
        return
    
    try:
        # Extract forensic metadata
        forensic = scan_data.get("forensic_metadata", {})
        evidence_sources = forensic.get("evidence_sources", [])
        corroboration_count = forensic.get("corroboration_count", 0)
        
        logger.debug(f"Saving scan {scan_data.get('scan_id')} - Forensic: count={corroboration_count}, sources={evidence_sources}")
        logger.debug(f"Scan type: {scan_data.get('type')}, confidence: {scan_data.get('confidence')}, threats: {scan_data.get('threats_detected')}")
        
        # Create database record
        scan_record = ScanHistory(
            scan_id=scan_data.get("scan_id"),
            target=scan_data.get("target"),
            target_type=scan_data.get("type", "unknown"),
            target_name=scan_data.get("target", ""),
            threat_level=scan_data.get("threat_level"),
            confidence=scan_data.get("confidence", 0.0),
            threats_detected=scan_data.get("threats_detected", 0),
            analysis_data={
                "verdict": scan_data.get("verdict"),
                "summary": scan_data.get("summary"),
                "api_results": scan_data.get("api_results", {}),
                "threat_indicators": scan_data.get("threat_indicators", []),
                "forensic_metadata": forensic,
            },
            evidence_sources=evidence_sources,
            corroboration_count=corroboration_count,
        )
        
        db.add(scan_record)
        await db.commit()
        await db.refresh(scan_record)
        
        # Log to system logs
        log_entry = SystemLog(
            log_level="INFO",
            component="scanner",
            message=f"Scan completed: {scan_data.get('scan_id')} - {scan_data.get('target')}",
            details={
                "scan_id": scan_data.get("scan_id"),
                "target": scan_data.get("target"),
                "threat_level": scan_data.get("threat_level"),
                "target_type": scan_data.get("type"),
                "threats_detected": scan_data.get("threats_detected", 0),
                "confidence": scan_data.get("confidence", 0.0),
            },
        )
        db.add(log_entry)
        await db.commit()

        try:
            from ..core.security_telemetry import security_telemetry
            security_telemetry.append_immutable_audit(
                event_type="scan_persisted",
                actor="compat_api",
                target=f"{scan_data.get('type', 'unknown')}:{scan_data.get('target', '')}",
                details={
                    "scan_id": scan_data.get("scan_id"),
                    "verdict": scan_data.get("verdict"),
                    "confidence": float(scan_data.get("confidence", 0.0) or 0.0),
                    "threats_detected": int(scan_data.get("threats_detected", 0) or 0),
                },
            )
        except Exception:
            pass

        logger.debug(f"Scan {scan_data.get('scan_id')} saved to database successfully")
        
    except Exception as e:
        logger.error(f"Failed to save scan to database: {e}")
        logger.exception(e)  # Full traceback
        await db.rollback()


class GenericScanRequest(BaseModel):
    type: str
    target: str


# Add OPTIONS handlers for CORS preflight requests
@router.options("/scan")
async def options_scan():
    """Handle CORS preflight for /scan endpoint."""
    return {}


@router.options("/scan/file")
async def options_scan_file():
    """Handle CORS preflight for /scan/file endpoint."""
    return {}


@router.options("/scans")
async def options_scans():
    """Handle CORS preflight for /scans endpoint."""
    return {}


@router.options("/dashboard/stats")
async def options_dashboard_stats():
    """Handle CORS preflight for /dashboard/stats endpoint."""
    return {}


@router.options("/dashboard/summary")
async def options_dashboard_summary():
    """Handle CORS preflight for /dashboard/summary endpoint."""
    return {}


@router.options("/threats")
async def options_threats():
    """Handle CORS preflight for /threats endpoint."""
    return {}


@router.options("/reports")
async def options_reports():
    """Handle CORS preflight for /reports endpoint."""
    return {}


@router.options("/reports/generate")
async def options_reports_generate():
    """Handle CORS preflight for /reports/generate endpoint."""
    return {}

@router.options("/scans/{scan_id}")
async def options_scan_detail():
    """Handle CORS preflight for /scans/{scan_id} endpoint."""
    return {}


@router.options("/reports/{report_id}")
async def options_report_detail():
    """Handle CORS preflight for /reports/{report_id} endpoint."""
    return {}


@router.options("/reports/{report_id}/download")
async def options_report_download():
    """Handle CORS preflight for /reports/{report_id}/download endpoint."""
    return {}

@router.post("/scan")
async def generic_scan(req: GenericScanRequest, db: AsyncSession = Depends(get_db)):
    """Compatibility endpoint: accepts {type, target} and returns a scan result.

    Uses real threat analyzer with VirusTotal, Shodan, URLScan, AbuseIPDB, 
    and Hybrid Analysis to provide actual threat detection.
    """
    import logging
    import time
    logger = logging.getLogger(__name__)
    
    scan_id = f"GEN_{int(datetime.utcnow().timestamp())}_{random.randint(1000, 9999)}"
    logger.debug(f"SCAN {scan_id} started | type={req.type} | target={req.target}")
    
    # Track scan duration
    scan_start_time = time.time()
    
    try:
        # Manual scans should use full external intelligence plus local analysis.
        analysis_result = await threat_analyzer.analyze(req.target, use_external_apis=True)
        scan_duration_ms = int((time.time() - scan_start_time) * 1000)
        
        # Map analyzer verdict to threat_level
        verdict = _normalize_verdict(analysis_result.get("verdict", "unknown"))
        analysis_result["verdict"] = verdict
        threat_level_map = {
            "clean": "safe",
            "suspicious": "suspicious",
            "malicious": "malicious"
        }
        threat_level = threat_level_map.get(verdict, "unknown")
        
        # Count detected threats
        threats_detected = len(analysis_result.get("threat_indicators", []))
        
        # Build scan result with real data
        result = {
            "scan_id": scan_id,
            "target": req.target,
            "type": analysis_result.get("input_type", req.type),
            "status": "complete",
            "threat_level": threat_level,
            "threats_detected": threats_detected,
            "verdict": verdict,
            "confidence": analysis_result.get("confidence", 0.0),
            "summary": analysis_result.get("summary", "Analysis complete"),
            "timestamp": datetime.utcnow().isoformat(),
            # Include API results for detailed view
            "api_results": analysis_result.get("api_results", {}),
            "threat_indicators": analysis_result.get("threat_indicators", []),
            # Include forensic reliability metadata
            "forensic_metadata": analysis_result.get("forensic_metadata", {}),
            # Include AI-enhanced analysis
            "ai_analysis": analysis_result.get("ai_analysis", {}),
            "ai_verdict_adjustment": analysis_result.get("ai_verdict_adjustment"),
        }
        if verdict in {"malicious", "suspicious"} and threats_detected > 0:
            logger.warning(
                "THREAT DETECTED | type=%s | verdict=%s | indicators=%s",
                result.get("type", req.type),
                verdict,
                threats_detected,
            )
        else:
            logger.debug(f"SCAN {scan_id} | lvl={threat_level} | ind={threats_detected}")
    except Exception as e:
        # Fallback if analysis fails
        logger.error(f"SCAN {scan_id} failed | {str(e)}")
        result = {
            "scan_id": scan_id,
            "target": req.target,
            "type": req.type,
            "status": "error",
            "threat_level": "unknown",
            "threats_detected": 0,
            "verdict": "error",
            "confidence": 0.0,
            "summary": f"Analysis failed: {str(e)}",
            "timestamp": datetime.utcnow().isoformat(),
            "error": str(e),
        }

    if not os.getenv("PYTEST_CURRENT_TEST"):
        # prepend to store (most recent first)
        SCANS_STORE.insert(0, result)
        logger.debug(f"Scan {scan_id} stored. Total scans in store: {len(SCANS_STORE)}")
        # trim store
        if len(SCANS_STORE) > MAX_STORE:
            SCANS_STORE.pop()
        
        # Save to database for time-range reports
        await _save_scan_to_db(result, db)
    else:
        logger.debug(f"Skipping in-memory/database storage for pytest-generated scan {scan_id}")
    
    # Log to enhanced activity database with full details
    try:
        from app.core.activity_database import activity_db
        from app.core.terminal_monitor import terminal_monitor
        
        artifact_type = analysis_result.get('input_type', req.type) if 'analysis_result' in locals() else req.type
        corroboration = analysis_result.get('corroboration_analysis', {}) if 'analysis_result' in locals() else {}
        
        # Log comprehensive scan details to activity database
        activity_db.log_threat_scan({
            'artifact_type': artifact_type,
            'artifact_value': req.target,
            'scan_duration_ms': scan_duration_ms if 'scan_duration_ms' in locals() else 0,
            'verdict': verdict,
            'confidence': result.get('confidence', 0.0),
            'threat_level': threat_level,
            'corroboration_level': corroboration.get('corroboration', {}).get('level'),
            'source_count': corroboration.get('corroboration', {}).get('source_count', 0),
            'sources': corroboration.get('corroboration', {}).get('sources', []),
            'api_results': result.get('api_results'),
            'threat_indicators': result.get('threat_indicators', []),
            'recommendations': analysis_result.get('recommendations', []) if 'analysis_result' in locals() else [],
            'flags': analysis_result.get('flags', {}) if 'analysis_result' in locals() else {},
            'is_automated': req.metadata.get('automated', False) if hasattr(req, 'metadata') and req.metadata else False,
            'metadata': req.metadata if hasattr(req, 'metadata') else {}
        })

        try:
            confidence_value = float(result.get('confidence', 0.0) or 0.0)
        except Exception:
            confidence_value = 0.0
        warnings_list = result.get('warnings') or []
        indicators_list = result.get('threat_indicators') or []
        summary_blob = " ".join([
            str(result.get('summary', '') or ''),
            " ".join(str(w) for w in warnings_list),
            " ".join(str(r) for r in (result.get('recommendations') or [])),
        ]).lower()
        low_signal_suspicious_ip = (
            artifact_type == 'ip'
            and str(verdict).lower() == 'suspicious'
            and confidence_value < 0.5
            and len(indicators_list) <= 1
            and len(warnings_list) <= 1
            and 'single source' in summary_blob
        )
        
        # Update terminal monitor for real-time display
        if not low_signal_suspicious_ip:
            terminal_monitor.log_scan_activity(artifact_type, req.target, verdict)
        
        # Log additional activity based on type
        if artifact_type == 'url' or artifact_type == 'domain':
            terminal_monitor.log_website_activity(req.target, threat_level.upper())
        
    except Exception as e:
        logger.error(f"Failed to log to enhanced monitoring: {e}")

    return result


@router.post("/scan/file")
async def scan_file(file: UploadFile = File(...), db: AsyncSession = Depends(get_db)):
    """
    File upload scan endpoint.
    Performs LOCAL analysis (signatures, entropy, magic bytes, PE headers)
    first, then enriches with external API hash lookup when keys are configured.
    Returns a combined verdict — malicious files are detected even without API keys.
    """
    import time
    scan_id = f"GEN_{int(datetime.utcnow().timestamp())}_{random.randint(1000, 9999)}"
    filename = file.filename or "unknown"
    scan_start = time.time()

    try:
        content = await file.read()
        file_size = len(content)

        # ── Size guard ──────────────────────────────────────────────────────
        if file_size > _MAX_FILE_SIZE:
            raise HTTPException(status_code=413, detail="File too large (max 100 MB)")

        # ── Hashing ─────────────────────────────────────────────────────────
        file_hash = hashlib.sha256(content).hexdigest()
        md5_hash  = hashlib.md5(content).hexdigest()

        # ── LOCAL analysis (always runs, no API keys needed) ─────────────
        local = _local_file_analysis(content, filename)

        # ── EXTERNAL API analysis (hash lookup; manual upload should use external APIs)
        try:
            api_result = await threat_analyzer.analyze(file_hash, use_external_apis=True)
        except Exception as api_err:
            logger.warning(f"External API analysis failed for file hash: {api_err}")
            api_result = {"verdict": "clean", "confidence": 0.0,
                          "threat_indicators": [], "api_results": {}, "forensic_metadata": {}}

        # ── Merge indicators ─────────────────────────────────────────────
        api_indicators = api_result.get("threat_indicators", [])
        all_indicators = local["threat_indicators"] + api_indicators

        # ── Determine final verdict (worst of local + API) ────────────────
        _PRIORITY = {"malicious": 3, "suspicious": 2, "clean": 1, "safe": 1, "unknown": 0}

        _LOCAL_VERDICT = {
            "CRITICAL": "malicious", "HIGH": "malicious",
            "MEDIUM":   "suspicious", "LOW": "suspicious", "CLEAN": "clean",
        }
        local_verdict = _LOCAL_VERDICT.get(local["risk_level"], "clean")
        api_verdict   = _normalize_verdict(api_result.get("verdict", "clean"), default="clean")
        api_result["verdict"] = api_verdict

        final_verdict = (
            local_verdict
            if _PRIORITY.get(local_verdict, 0) >= _PRIORITY.get(api_verdict, 0)
            else api_verdict
        )

        _TL_MAP = {"malicious": "malicious", "suspicious": "suspicious",
                   "clean": "safe", "safe": "safe"}
        threat_level = _TL_MAP.get(final_verdict, "unknown")

        # ── Confidence ───────────────────────────────────────────────────
        local_conf = min(local["risk_score"] / 10.0, 1.0) if local["risk_score"] > 0 else 0.0
        api_conf   = float(api_result.get("confidence", 0.0) or 0.0)
        confidence = max(local_conf, api_conf)

        scan_duration_ms = int((time.time() - scan_start) * 1000)

        result = {
            "scan_id":         scan_id,
            "target":          filename,
            "type":            "file",
            "file_size":       file_size,
            "file_hash":       file_hash,
            "md5_hash":        md5_hash,
            "status":          "complete",
            "threat_level":    threat_level,
            "threats_detected": len(all_indicators),
            "verdict":         final_verdict,
            "confidence":      round(confidence, 4),
            "summary":         _build_file_summary(filename, local, final_verdict, all_indicators),
            "timestamp":       datetime.utcnow().isoformat(),
            "scan_duration_ms": scan_duration_ms,
            # Local analysis detail
            "local_analysis": {
                "risk_level":        local["risk_level"],
                "risk_score":        local["risk_score"],
                "entropy":           local["entropy"],
                "magic_type":        local["magic_type"],
                "file_extension":    local["file_extension"],
                "signatures":        local["signatures"],
                "pe_info":           local["pe_info"],
                "disassembly_info":  local.get("disassembly_info"),
                "ml_classification": local.get("ml_classification"),
                "suspicious_strings": local["suspicious_strings"],
            },
            "file_analysis": {
                "entropy": local["entropy"],
                "signatures": local["signatures"],
                "pe_info": local["pe_info"],
                "disassembly_info": local.get("disassembly_info"),
                "ml_classification": local.get("ml_classification"),
            },
            "analysis_data": {
                "file_analysis": {
                    "entropy": local["entropy"],
                    "signatures": local["signatures"],
                    "pe_info": local["pe_info"],
                    "disassembly_info": local.get("disassembly_info"),
                    "ml_classification": local.get("ml_classification"),
                    "suspicious_strings": local["suspicious_strings"],
                },
                "local_analysis": {
                    "risk_level":        local["risk_level"],
                    "risk_score":        local["risk_score"],
                    "entropy":           local["entropy"],
                    "magic_type":        local["magic_type"],
                    "file_extension":    local["file_extension"],
                    "signatures":        local["signatures"],
                    "pe_info":           local["pe_info"],
                    "disassembly_info":  local.get("disassembly_info"),
                    "ml_classification": local.get("ml_classification"),
                    "suspicious_strings": local["suspicious_strings"],
                },
                "analysis_family": result.get("analysis_family", "unknown"),
                "analysis_methods_used": result.get("analysis_methods_used", []),
            },
            # External API results
            "api_results":       api_result.get("api_results", {}),
            "threat_indicators": all_indicators,
            "forensic_metadata": api_result.get("forensic_metadata", {}),
        }

        if final_verdict in {"malicious", "suspicious"} and len(all_indicators) > 0:
            logger.warning(
                "THREAT DETECTED | type=file | file=%s | verdict=%s | indicators=%s",
                Path(filename).name,
                final_verdict,
                len(all_indicators),
            )
        else:
            logger.debug(
                "FILE SCAN %s | file=%s | verdict=%s | local_risk=%s | indicators=%s",
                scan_id,
                Path(filename).name,
                final_verdict,
                local["risk_level"],
                len(all_indicators),
            )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"File scan error for {filename}: {e}")
        result = {
            "scan_id":    scan_id,
            "target":     filename,
            "type":       "file",
            "file_size":  0,
            "status":     "error",
            "threat_level": "unknown",
            "threats_detected": 0,
            "verdict":    "error",
            "confidence": 0.0,
            "summary":    f"File analysis failed: {str(e)}",
            "timestamp":  datetime.utcnow().isoformat(),
            "error":      str(e),
        }

    # ── Persist ──────────────────────────────────────────────────────────
    SCANS_STORE.insert(0, result)
    if len(SCANS_STORE) > MAX_STORE:
        SCANS_STORE.pop()
    await _save_scan_to_db(result, db)

    return result


@router.get("/scans")
async def list_scans(source: Optional[str] = None, db: AsyncSession = Depends(get_db)):
    """Return recent scans from database (fallback to memory).

    Defaults to operator-triggered manual scans only so automated client-side
    protection hash checks do not flood the dashboard history.
    Pass source=all to include every scan source.
    """
    query = select(ScanHistory).order_by(desc(ScanHistory.scan_timestamp)).limit(100)
    if source != "all":
        # Backward compatibility: older records may have NULL scan_source.
        query = query.where(
            or_(
                ScanHistory.scan_source == "manual",
                ScanHistory.scan_source.is_(None),
            )
        )

    result = await db.execute(query)
    scans = result.scalars().all()
    if scans:
        return [
            {
                "scan_id": s.scan_id,
                "target": s.target,
                "type": s.target_type,
                "source": s.scan_source or "manual",
                "status": "complete",
                "threat_level": s.threat_level or "unknown",
                "verdict": (s.analysis_data or {}).get("verdict"),
                "timestamp": s.scan_timestamp.isoformat() if s.scan_timestamp else None,
            }
            for s in scans
        ]

    if source != "all":
        return [s for s in SCANS_STORE if s.get("scan_source", "manual") == "manual"]
    return SCANS_STORE


@router.get("/scans/{scan_id}")
async def get_scan_detail(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Get detailed information about a specific scan."""
    result = await db.execute(select(ScanHistory).where(ScanHistory.scan_id == scan_id))
    scan = result.scalar_one_or_none()
    if scan:
        analysis = scan.analysis_data or {}
        return {
            "scan_id": scan.scan_id,
            "target": scan.target,
            "type": scan.target_type,
            "status": "complete",
            "threat_level": scan.threat_level,
            "verdict": analysis.get("verdict"),
            "confidence": scan.confidence,
            "threats_detected": scan.threats_detected,
            "timestamp": scan.scan_timestamp.isoformat() if scan.scan_timestamp else None,
            "api_results": analysis.get("api_results", {}),
            "threat_indicators": analysis.get("threat_indicators", []),
            "summary": analysis.get("summary"),
            "forensic_metadata": analysis.get("forensic_metadata", {}),
        }
    for scan in SCANS_STORE:
        if scan.get("scan_id") == scan_id:
            return scan
    raise HTTPException(status_code=404, detail="Scan not found")


@router.get("/dashboard/stats")
async def get_dashboard_stats(db: AsyncSession = Depends(get_db)):
    """Get dashboard statistics (compatibility endpoint)."""
    result = await db.execute(select(ScanHistory).order_by(desc(ScanHistory.scan_timestamp)))
    scans = result.scalars().all()
    attack_result = await db.execute(select(AttackEvent).order_by(desc(AttackEvent.detected_at)).limit(1000))
    attacks = attack_result.scalars().all()

    manual_total_result = await db.execute(
        select(func.count(ScanHistory.id)).where(ScanHistory.scan_source == "manual")
    )
    manual_total_scans = int(manual_total_result.scalar() or 0)

    stats = {
        "critical_threats": 0,
        "high_threats": 0,
        "medium_threats": 0,
        "low_threats": 0,
        "files_scanned": 0,
        "urls_scanned": 0,
        "ips_scanned": 0,
        "total_scans": len(scans),
        "manual_total_scans": manual_total_scans,
        "manual_threats_detected": 0,
        "manual_clean_scans": 0,
        "detection_rate_pct": 0.0,
        "attack_events": len(attacks),
        "total_events": len(scans) + len(attacks),
        "active_threats": 0,
    }

    for scan in scans:
        level = (scan.threat_level or "unknown").lower()
        is_manual = (scan.scan_source or "manual") == "manual"

        if level in ["malicious", "critical"]:
            stats["critical_threats"] += 1
        elif level in ["suspicious", "high"]:
            stats["high_threats"] += 1
        elif level in ["safe", "clean", "low"]:
            stats["low_threats"] += 1
        else:
            stats["medium_threats"] += 1

        t = (scan.target_type or "").lower()
        if t in ["file", "hash"]:
            stats["files_scanned"] += 1
        elif t in ["url", "domain"]:
            stats["urls_scanned"] += 1
        elif t == "ip":
            stats["ips_scanned"] += 1

        if level in ["malicious", "critical", "suspicious", "high"]:
            stats["active_threats"] += 1

        if is_manual:
            if level in ["malicious", "critical", "suspicious", "high"]:
                stats["manual_threats_detected"] += 1
            elif level in ["safe", "clean", "low"]:
                stats["manual_clean_scans"] += 1

    for attack in attacks:
        sev = (attack.severity.value if attack.severity else "medium").lower()
        if sev == "critical":
            stats["critical_threats"] += 1
        elif sev == "high":
            stats["high_threats"] += 1
        elif sev == "medium":
            stats["medium_threats"] += 1
        else:
            stats["low_threats"] += 1

        status = str(attack.status or "detected").lower()
        if status in {"detected", "analyzing", "blocked", "mitigated", "active", "quarantined"}:
            stats["active_threats"] += 1

    if stats["manual_total_scans"] > 0:
        stats["detection_rate_pct"] = round(
            (stats["manual_threats_detected"] / stats["manual_total_scans"]) * 100,
            1,
        )

    return stats


@router.get("/dashboard/summary")
async def get_dashboard_summary(db: AsyncSession = Depends(get_db)):
    """Get dashboard summary with recent activity."""
    result = await db.execute(select(ScanHistory).order_by(desc(ScanHistory.scan_timestamp)).limit(1))
    last_scan = result.scalar_one_or_none()

    result_all = await db.execute(select(ScanHistory))
    scans = result_all.scalars().all()
    threats = [s for s in scans if (s.threat_level or "").lower() in ["malicious", "critical", "suspicious", "high"]]

    return {
        "total_scans": len(scans),
        "threats_detected": len(threats),
        "last_scan": last_scan.scan_timestamp.isoformat() if last_scan else None,
        "system_status": "healthy",
    }


@router.get("/threats")
async def get_threats(db: AsyncSession = Depends(get_db)):
    """Get all detected threats (compatibility endpoint).

    Combines scan-based findings and IDS attack events so the dashboard can
    show intrusion attempts (nmap/brute-force/metasploit-like patterns) with
    concise description and mitigation hints.
    """
    scan_result = await db.execute(select(ScanHistory).order_by(desc(ScanHistory.scan_timestamp)).limit(100))
    scans = scan_result.scalars().all()

    attack_result = await db.execute(select(AttackEvent).order_by(desc(AttackEvent.detected_at)).limit(100))
    attacks = attack_result.scalars().all()

    defense_logs_result = await db.execute(
        select(SystemLog)
        .where(SystemLog.component.in_(["defense_event", "defense_response", "client_heartbeat"]))
        .order_by(desc(SystemLog.timestamp))
        .limit(120)
    )
    defense_logs = defense_logs_result.scalars().all()

    def _icon_for(threat_type: str) -> str:
        lowered = str(threat_type or "").lower()
        if "brute" in lowered:
            return "🔐"
        if "metasploit" in lowered or "exploit" in lowered:
            return "💥"
        if "scan" in lowered or "nmap" in lowered or "recon" in lowered:
            return "🛰️"
        if "flood" in lowered or "ddos" in lowered:
            return "🌊"
        return "🚨"

    threats = []

    # Scan-history threats
    for scan in scans:
        level = (scan.threat_level or "unknown").lower()
        if level in ["safe", "clean", "unknown"]:
            continue
        if _is_low_signal_suspicious_ip_scan(scan):
            continue

        severity = "critical" if level in ["malicious", "critical"] else "high" if level in ["suspicious", "high"] else "medium"
        analysis = scan.analysis_data or {}
        summary = analysis.get("summary") or "Threat detected"
        target = scan.target or scan.target_name or "unknown"
        type_label = f"{(scan.target_type or 'scan').lower()}_threat"

        threats.append({
            "id": scan.scan_id,
            "scan_id": scan.scan_id,
            "name": f"{(scan.target_type or 'unknown').upper()} Threat",
            "type": type_label,
            "icon": _icon_for(type_label),
            "target": target,
            "details": summary,
            "description": summary,
            "short_description": summary[:140],
            "severity": severity,
            "confidence": scan.confidence,
            "corroboration_count": scan.corroboration_count or 0,
            "target_type": scan.target_type,
            "source": "Multi-API Scan",
            "location": "Endpoint Scan Pipeline",
            "timestamp": scan.scan_timestamp.isoformat() if scan.scan_timestamp else None,
            "status": "active",
            "scan_source": scan.scan_source or "manual",
            "event_kind": "MANUAL_SCAN_RESULT",
            "prompt_actionable": False,
        })

    # IDS/defense attack events
    for attack in attacks:
        indicators = attack.indicators if isinstance(attack.indicators, dict) else {}
        short_desc = indicators.get("short_description") or attack.description or "Intrusion attempt detected"
        mitigation_commands = indicators.get("mitigation_commands")
        if not isinstance(mitigation_commands, list):
            mitigation_commands = []

        severity = (attack.severity.value if attack.severity else "medium").lower()
        target = attack.source_ip or attack.source_domain or attack.destination_ip or "unknown"
        source_hostname = indicators.get("source_hostname") or attack.source_domain
        target_display = f"{attack.source_ip} ({source_hostname})" if attack.source_ip and source_hostname else target
        type_label = str(attack.attack_type or "intrusion").lower()

        threats.append({
            "id": attack.event_id,
            "event_id": attack.event_id,
            "name": f"Attack Event: {attack.attack_type}",
            "type": type_label,
            "icon": _icon_for(type_label),
            "target": target,
            "target_display": target_display,
            "source_hostname": source_hostname,
            "details": attack.description or short_desc,
            "description": attack.description or short_desc,
            "short_description": short_desc,
            "severity": severity,
            "source": indicators.get("tool_signature") or "Intrusion Detector",
            "location": "Network Intrusion Monitoring",
            "timestamp": attack.detected_at.isoformat() if attack.detected_at else None,
            "status": attack.status or "active",
            "mitigation_commands": mitigation_commands,
            "recommended_action": indicators.get("recommended_action"),
            "attack_family": indicators.get("attack_family"),
            "tool_signature": indicators.get("tool_signature"),
            "prediction_summary": indicators.get("prediction_summary"),
            "predicted_next_step": indicators.get("predicted_next_step"),
            "prediction_confidence": indicators.get("prediction_confidence"),
            "event_kind": indicators.get("event_kind") or "ATTACK_ALERT",
            "prompt_actionable": True,
        })

    # Fallback mapping from structured defense logs to threat cards so dashboard
    # still receives actionable incidents even before full attack correlation.
    existing_ids = {str(item.get("id")) for item in threats if item.get("id")}
    for log in defense_logs:
        details = log.details if isinstance(log.details, dict) else {}
        event_name = str(details.get("event") or details.get("attack_type") or "defense_event")
        attack_type = str(details.get("attack_type") or event_name).lower()
        severity = str(details.get("severity") or log.log_level or "medium").lower()
        if severity not in {"critical", "high", "warning", "error", "medium"}:
            severity = "medium"

        is_actionable = (
            severity in {"critical", "high", "warning", "error"}
            or any(token in attack_type for token in ["attack", "alert", "quarantine", "process", "ddos", "intrusion"])
        )
        if not is_actionable:
            continue

        log_id = f"LOG_{log.id}"
        if log_id in existing_ids:
            continue

        source_ip = details.get("source_ip")
        source_domain = details.get("source_domain")
        target = source_ip or source_domain or details.get("client_id") or "unknown"
        short_desc = str(details.get("description") or log.message or "Security event")

        threats.append({
            "id": log_id,
            "event_id": str(details.get("attack_id") or details.get("event_id") or ""),
            "name": f"Defense Event: {event_name}",
            "type": attack_type,
            "icon": _icon_for(attack_type),
            "target": target,
            "target_display": target,
            "details": short_desc,
            "description": short_desc,
            "short_description": short_desc[:140],
            "severity": "critical" if severity in {"critical", "error"} else ("high" if severity in {"high", "warning"} else "medium"),
            "source": str(log.component or "defense_event"),
            "location": "Live Defense Event Stream",
            "timestamp": log.timestamp.isoformat() if log.timestamp else None,
            "status": "active",
            "mitigation_commands": details.get("payload", {}).get("mitigation_commands") if isinstance(details.get("payload"), dict) else [],
            "recommended_action": details.get("reason") or "Review and respond from dashboard",
            "client_id": details.get("client_id"),
            "event_kind": event_name,
            "prompt_actionable": True,
        })
        existing_ids.add(log_id)

    threats.sort(key=lambda t: t.get("timestamp") or "", reverse=True)
    return threats[:200]


@router.get("/logs")
async def get_logs(db: AsyncSession = Depends(get_db)):
    """Return recent system logs for dashboard."""
    result = await db.execute(select(SystemLog).order_by(desc(SystemLog.timestamp)).limit(50))
    logs = result.scalars().all()
    return [
        {
            "id": log.id,
            "level": log.log_level,
            "component": log.component,
            "message": log.message,
            "details": log.details,
            "timestamp": log.timestamp.isoformat() if log.timestamp else None,
        }
        for log in logs
    ]


@router.get("/dashboard/api-status")
async def get_api_status(db: AsyncSession = Depends(get_db)):
    """Return API live/config/usage status for dashboard (compat)."""

    service_specs = [
        {
            "name": "VirusTotal",
            "key_configured": bool(settings.VIRUSTOTAL_API_KEY),
            "supported_inputs": ["url", "domain", "file_hash"],
            "daily_limit": 1000,
            "rate_limit_per_minute": 4,
        },
        {
            "name": "AbuseIPDB",
            "key_configured": bool(settings.ABUSEIPDB_API_KEY),
            "supported_inputs": ["ip"],
            "daily_limit": 1000,
            "rate_limit_per_minute": 20,
        },
        {
            "name": "Shodan",
            "key_configured": bool(settings.SHODAN_API_KEY),
            "supported_inputs": ["ip"],
            "daily_limit": 500,
            "rate_limit_per_minute": 10,
        },
        {
            "name": "URLScan.io",
            "key_configured": bool(settings.URLSCAN_API_KEY),
            "supported_inputs": ["url", "domain"],
            "daily_limit": 1000,
            "rate_limit_per_minute": 15,
        },
        {
            "name": "Hybrid Analysis",
            "key_configured": bool(settings.HYBRIDANALYSIS_API_KEY),
            "supported_inputs": ["file_hash"],
            "daily_limit": 200,
            "rate_limit_per_minute": 3,
        },
    ]

    alias_map = {
        "virustotal": "VirusTotal",
        "virus_total": "VirusTotal",
        "vt": "VirusTotal",
        "abuseipdb": "AbuseIPDB",
        "shodan": "Shodan",
        "urlscan": "URLScan.io",
        "urlscan.io": "URLScan.io",
        "hybridanalysis": "Hybrid Analysis",
        "hybrid_analysis": "Hybrid Analysis",
        "hybrid analysis": "Hybrid Analysis",
    }

    now = datetime.utcnow()
    # Ensure timezone-aware comparison
    since_24h = now - timedelta(days=1)
    since_1m = now - timedelta(minutes=1)

    usage_daily = defaultdict(int)
    usage_minute = defaultdict(int)

    # Debug: Log the time range being queried
    import logging
    logger = logging.getLogger(__name__)
    logger.debug(f"API Status Query - Now: {now}, Since 24h: {since_24h}")

    result = await db.execute(
        select(ScanHistory)
        .where(ScanHistory.scan_timestamp >= since_24h)
        .where(
            or_(
                ScanHistory.scan_source == "manual",
                ScanHistory.scan_source.is_(None),
            )
        )
        .order_by(desc(ScanHistory.scan_timestamp))
        .limit(5000)
    )
    scans = result.scalars().all()
    logger.debug(f"API Status Query - Found {len(scans)} scans in last 24 hours")

    try:
        from ..core.activity_database import activity_db
        automated_usage = activity_db.get_api_usage_summary(hours=24, minute_window=1)
    except Exception:
        automated_usage = {"daily": {}, "minute": {}}

    for scan in scans:
        ts = scan.scan_timestamp or now
        analysis = scan.analysis_data if isinstance(scan.analysis_data, dict) else {}
        api_results = analysis.get("api_results") if isinstance(analysis, dict) else {}
        if not isinstance(api_results, dict):
            continue

        called = set()

        apis_called = api_results.get("apis_called")
        if isinstance(apis_called, list):
            for name in apis_called:
                n = alias_map.get(str(name or "").strip().lower())
                if n:
                    called.add(n)

        api_status = api_results.get("api_status")
        if isinstance(api_status, dict):
            for key, entry in api_status.items():
                mapped = alias_map.get(str(key or "").strip().lower())
                if mapped:
                    called.add(mapped)
                    continue
                if isinstance(entry, dict):
                    mapped_by_name = alias_map.get(str(entry.get("name") or "").strip().lower())
                    if mapped_by_name:
                        called.add(mapped_by_name)

        for key in ("virustotal", "abuseipdb", "shodan", "urlscan", "hybrid_analysis"):
            if key in api_results and api_results.get(key) is not None:
                mapped = alias_map.get(key)
                if mapped:
                    called.add(mapped)

        for service_name in called:
            usage_daily[service_name] += 1
            if ts >= since_1m:
                usage_minute[service_name] += 1

    for service_name, count in (automated_usage.get("daily") or {}).items():
        usage_daily[service_name] += int(count or 0)

    for service_name, count in (automated_usage.get("minute") or {}).items():
        usage_minute[service_name] += int(count or 0)

    payload = []
    for spec in service_specs:
        name = spec["name"]
        key_configured = bool(spec["key_configured"])
        daily_limit = int(spec["daily_limit"])
        rpm_limit = int(spec["rate_limit_per_minute"])
        daily_used = int(usage_daily.get(name, 0))
        minute_used = int(usage_minute.get(name, 0))

        if not key_configured:
            status = "missing_key"
            live = False
        elif daily_used >= daily_limit:
            status = "quota_exceeded"
            live = False
        elif minute_used >= rpm_limit:
            status = "rate_limited"
            live = False
        else:
            status = "online"
            live = True

        payload.append(
            {
                "name": name,
                "key_configured": key_configured,
                "enabled": key_configured,
                "status": status,
                "live": live,
                "is_live": live,
                "supported_inputs": spec["supported_inputs"],
                "daily_used": daily_used,
                "daily_limit": daily_limit,
                "daily_remaining": max(0, daily_limit - daily_used),
                "rate_limit_per_minute": rpm_limit,
                "minute_used": minute_used,
                "usage": {
                    "used": daily_used,
                    "limit": daily_limit,
                    "remaining": max(0, daily_limit - daily_used),
                    "minute_used": minute_used,
                    "rate_limit_per_minute": rpm_limit,
                },
                "last_checked": now.isoformat(),
            }
        )

    return payload


@router.get("/reports")
async def list_reports():
    """Return all generated reports from store."""
    # refresh from disk if in-memory store is empty (e.g., process started fresh)
    if not REPORTS_STORE:
        REPORTS_STORE.extend(_load_persistent_reports())
    # Return reports in reverse chronological order (newest first)
    return list(reversed(REPORTS_STORE)) if REPORTS_STORE else []


class ReportRequest(BaseModel):
    target: str | None = None
    scan_id: str | None = None
    type: str | None = None
    timeRange: str | None = None
    report_type: str | None = None
    intervals: list[str] | None = None


@router.post("/reports/generate")
async def generate_report(req: ReportRequest):
    """Generate an AI report (PDF) for a target using the Gemini-backed report generator.

    If the Gemini API key is not configured, return a clear 400 error so the frontend
    can display a helpful message.
    """
    # Check Gemini key
    if not getattr(settings, "GEMINI_API_KEY", None):
        raise HTTPException(
            status_code=400,
            detail="Unable to generate report: gemini api key is not given",
        )

    # Generate unique report ID
    now = datetime.utcnow()
    report_id = f"RPT_{int(now.timestamp())}_{random.randint(1000, 9999)}"
    
    target = req.target or "unknown"
    scan_type = req.type or "unknown"
    time_range = req.timeRange or "24h"
    report_type = req.report_type or "executive_summary"
    intervals = req.intervals or [time_range]

    scan_record = None
    if req.scan_id:
        result = await db.execute(select(ScanHistory).where(ScanHistory.scan_id == req.scan_id))
        scan = result.scalar_one_or_none()
        if scan:
            analysis_data = scan.analysis_data if isinstance(scan.analysis_data, dict) else {}
            scan_record = {
                "input": scan.target or scan.target_type or scan.scan_id,
                "input_type": scan.target_type or scan_type,
                "verdict": scan.threat_level or analysis_data.get("verdict", "unknown"),
                "confidence": scan.confidence if scan.confidence is not None else analysis_data.get("confidence", 0.5),
                "threat_indicators": analysis_data.get("threat_indicators", []),
                "api_results": analysis_data.get("api_results", {}),
                "timestamp": scan.scan_timestamp.isoformat() if scan.scan_timestamp else now.isoformat(),
                "report_id": report_id,
                "summary": analysis_data.get("summary", ""),
                "threats_detected": scan.threats_detected or len(analysis_data.get("threat_indicators", [])),
                "forensic_metadata": analysis_data.get("forensic_metadata", {}),
                "scan_id": scan.scan_id,
                "threat_level": scan.threat_level or analysis_data.get("threat_level", "unknown"),
                "status": "complete",
                "report_type": report_type,
                "intervals": intervals,
            }
            target = scan_record["input"]
            scan_type = scan_record["input_type"]
    
    # Get the most recent scan for this target from SCANS_STORE to use its full analysis
    target_scans = [s for s in SCANS_STORE if target and target in s.get("target", "")]

    # Prefer an exact scan lookup when scan_id is provided; it carries the richest analysis payload.
    if scan_record is not None:
        threat_analysis = scan_record
    elif req.scan_id:
        stored_scan = next((s for s in SCANS_STORE if s.get("scan_id") == req.scan_id), None)
        if stored_scan:
            stored_analysis = stored_scan.get("analysis", {}) if isinstance(stored_scan.get("analysis"), dict) else {}
            threat_analysis = {
                "input": stored_scan.get("target") or stored_scan.get("target_name") or stored_scan.get("scan_id") or target,
                "input_type": stored_scan.get("type", scan_type),
                "verdict": stored_scan.get("verdict", stored_analysis.get("verdict", "unknown")),
                "confidence": stored_scan.get("confidence", stored_analysis.get("confidence", 0.5)),
                "threat_indicators": stored_scan.get("threat_indicators", stored_analysis.get("threat_indicators", [])),
                "api_results": stored_scan.get("api_results", stored_analysis.get("api_results", {})),
                "timestamp": stored_scan.get("timestamp", now.isoformat()),
                "report_id": report_id,
                "summary": stored_scan.get("summary", stored_analysis.get("summary", "")),
                "threats_detected": stored_scan.get("threats_detected", len(stored_analysis.get("threat_indicators", []))),
                "forensic_metadata": stored_scan.get("forensic_metadata", stored_analysis.get("forensic_metadata", {})),
                "scan_id": stored_scan.get("scan_id", req.scan_id),
                "threat_level": stored_scan.get("threat_level", stored_analysis.get("threat_level", "unknown")),
                "status": stored_scan.get("status", "complete"),
                "report_type": report_type,
                "intervals": intervals,
            }
        else:
            threat_analysis = None
    
    # If we have a recent scan with full analysis data, use it
    if req.scan_id and threat_analysis is not None:
        pass
    elif target_scans:
        # Use the most recent scan with complete data
        latest_scan = target_scans[-1]
        
        # If scan has api_results and threat_indicators, use them directly
        if "api_results" in latest_scan and "threat_indicators" in latest_scan:
            threat_analysis = {
                "input": target,
                "input_type": latest_scan.get("type", scan_type),
                "verdict": latest_scan.get("verdict", "unknown"),
                "confidence": latest_scan.get("confidence", 0.5),
                "threat_indicators": latest_scan.get("threat_indicators", []),
                "api_results": latest_scan.get("api_results", {}),
                "timestamp": now.isoformat(),
                "report_id": report_id,
                "summary": latest_scan.get("summary", ""),
                "threats_detected": latest_scan.get("threats_detected", 0),
                "forensic_metadata": latest_scan.get("forensic_metadata", {}),
                "scan_id": latest_scan.get("scan_id", ""),
                "threat_level": latest_scan.get("threat_level", "unknown"),
                "status": latest_scan.get("status", "complete"),
                "report_type": report_type,
                "intervals": intervals,
            }
        else:
            # Fallback: perform fresh analysis
            threat_analysis = await threat_analyzer.analyze(target)
            threat_analysis["report_id"] = report_id
            threat_analysis["report_type"] = report_type
            threat_analysis["intervals"] = intervals
    else:
        # No recent scans - perform fresh analysis
        threat_analysis = await threat_analyzer.analyze(target)
        threat_analysis["report_id"] = report_id
        threat_analysis["report_type"] = report_type
        threat_analysis["intervals"] = intervals

    # Generate PDF bytes with full analysis data
    pdf_bytes = await report_generator.generate_analysis_report(threat_analysis)

    if not pdf_bytes:
        raise HTTPException(status_code=500, detail="Report generation failed")

    # Store report metadata using actual analysis data
    report_meta = {
        "report_id": report_id,
        "title": f"Threat Analysis - {target}",
        "target": target,
        "type": threat_analysis.get("input_type", scan_type),
        "time_range": time_range,
        "threats_detected": threat_analysis.get("threats_detected", len(threat_analysis.get("threat_indicators", []))),
        "verdict": threat_analysis.get("verdict", "unknown"),
        "confidence": threat_analysis.get("confidence", 0.5),
        "created": now.isoformat(),
    }
    store_report_artifacts(report_meta, pdf_bytes)

    return StreamingResponse(
        BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={target}_report_{report_id}.pdf"},
    )

@router.get("/reports/{report_id}")
async def get_report(report_id: str):
    """Get report metadata by ID."""
    for report in REPORTS_STORE:
        if report.get("report_id") == report_id:
            return report
    raise HTTPException(status_code=404, detail="Report not found")


@router.get("/reports/{report_id}/download")
async def download_report(report_id: str):
    """Download a specific report PDF by ID."""
    # Check if report exists in cache
    if report_id in REPORTS_PDF_CACHE:
        pdf_bytes = REPORTS_PDF_CACHE[report_id]
    else:
        # fallback to persisted file path
        report_meta = next((r for r in REPORTS_STORE if r.get("report_id") == report_id), None)
        report_path = report_meta.get("report_path") if report_meta else None
        if not report_path or not Path(report_path).exists():
            raise HTTPException(status_code=404, detail="Report not found or expired")
        pdf_bytes = Path(report_path).read_bytes()
        REPORTS_PDF_CACHE[report_id] = pdf_bytes
    
    return StreamingResponse(
        BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={report_id}.pdf"},
    )