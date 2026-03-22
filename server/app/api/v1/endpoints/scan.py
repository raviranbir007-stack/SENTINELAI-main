"""
Threat Scanning Endpoints
Handles threat analysis for IPs, URLs, domains, and file hashes
"""

import hashlib
import asyncio
import logging
import math
import os
import re
import struct
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from pydantic import BaseModel, field_validator
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from ....core.input_detector import InputDetector
from ....core.report_generator import report_generator
from ....core.threat_analyzer import threat_analyzer
from ....database import get_db
from ....models import ClientInstallation, ScanHistory, SystemLog

logger = logging.getLogger(__name__)
router = APIRouter()

# In-memory scan history (in production, use database)
_scan_history = []

# Compiled regex patterns for input validation
_RE_HASH   = re.compile(r'^[a-fA-F0-9]{32,64}$')
_RE_IP     = re.compile(
    r'^(?:(?:25[0-5]|2[0-4]\d|[01]?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d{1,2})$'
)
_RE_DOMAIN = re.compile(r'^[a-zA-Z0-9\-\.]{1,253}$')
_ALLOWED_SCAN_SOURCES = {"manual", "client_protection", "background", "scheduled"}

# ─────────────────────────────────────────────────────────────────────────────
# Local file analysis (mirrors compat.py helpers — no external API keys needed)
# ─────────────────────────────────────────────────────────────────────────────
_BYTE_SIGS_V1 = [
    ("EICAR",             b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
                          "EICAR AV test file",          "critical"),
    ("SHELLCODE_NOP",     b"\x90\x90\x90\x90\x90\x90\x90\x90",
                          "NOP sled – shellcode",        "high"),
    ("REVERSE_SHELL",     b"/bin/sh\x00-i",
                          "Reverse-shell string",        "critical"),
    ("MSFVENOM",          b"msfvenom",
                          "Metasploit payload marker",   "critical"),
    ("XOR_DECODE_STUB",   b"xor eax",
                          "XOR decode stub",             "high"),
    ("JAVA_CLASS",        b"\xca\xfe\xba\xbe",
                          "Java class file",             "medium"),
]
_REGEX_SIGS_V1 = [
    ("POWERSHELL_ENC",     r"powershell.*-enc",                           "high"),
    ("WGET_PIPE_SH",       r"wget\s+.*\|\s*(ba)?sh",                     "high"),
    ("CURL_PIPE_BASH",     r"curl\s+.*\|\s*(ba)?bash",                   "high"),
    ("BASE64_DECODE",      r"base64\s+--?decode",                        "medium"),
    ("NET_USER_ADD",       r"net\s+user.*\/add",                         "high"),
    ("SCHTASK_CREATE",     r"schtasks.*\/create",                        "high"),
    ("CREATEREMOTETHREAD", r"CreateRemoteThread",                        "critical"),
    ("VIRTUALALLOC",       r"VirtualAlloc",                              "high"),
    ("WSCRIPT_SHELL",      r"WScript\.Shell",                            "high"),
    ("OBFUSCATED_EVAL",    r"eval\s*\(\s*(?:unescape|base64|gzip|rot13)", "high"),
]
_MAGIC_MAP_V1: Dict[bytes, str] = {
    b"MZ":               "Windows PE executable",
    b"\x7fELF":          "Linux ELF executable",
    b"\xca\xfe\xba\xbe": "Java class file",
    b"#!/":              "Script file",
    b"PK\x03\x04":       "ZIP archive",
    b"Rar!":             "RAR archive",
    b"\x1f\x8b":         "GZIP compressed",
    b"\xd0\xcf\x11\xe0": "OLE2 / Office macro",
    b"%PDF":             "PDF document",
}
_DANGEROUS_EXTS_V1 = {
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js",
    ".jse", ".wsf", ".wsh", ".msi", ".scr", ".pif", ".com", ".hta",
    ".cpl", ".reg", ".lnk", ".inf", ".jar", ".docm", ".xlsm",
    ".pptm", ".dotm", ".xltm", ".xlam",
}
_HIGH_ENT = 7.2
_MED_ENT  = 6.5
_MAX_FILE_UPLOAD = 100 * 1024 * 1024  # 100 MB

_PHISHING_LURE_PATTERNS_V1 = [
    ("PHISHING_VERIFY_ACCOUNT", r"verify\s+your\s+account|account\s+verification|confirm\s+your\s+account", "high"),
    ("PHISHING_ACCOUNT_SUSPENDED", r"account\s+(?:has\s+been\s+)?suspended|unusual\s+login\s+attempt", "high"),
    ("PHISHING_PAYMENT_URGENT", r"payment\s+failed|billing\s+issue|update\s+payment\s+method", "high"),
    ("PHISHING_CREDENTIAL_HARVEST", r"(enter|confirm|re-enter)\s+(your\s+)?(password|otp|one-time\s+password|2fa\s+code)", "medium"),
    ("PHISHING_WALLET_SEED", r"seed\s+phrase|recovery\s+phrase|wallet\s+verification", "high"),
]


def _entropy_v1(data: bytes) -> float:
    if not data:
        return 0.0
    freq: Dict[int, int] = defaultdict(int)
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values() if c)


def _local_scan_v1(content: bytes, filename: str) -> Dict:
    """Fast in-process file analysis for the v1 /scan/file endpoint."""
    from pathlib import Path as _P
    ext    = _P(filename).suffix.lower() if filename else ""
    sample = content[: 1 * 1024 * 1024]
    entropy = _entropy_v1(sample)

    magic_type = "Unknown"
    for magic, desc in _MAGIC_MAP_V1.items():
        if sample[: len(magic)] == magic:
            magic_type = desc
            break

    text = sample.decode("latin-1", errors="replace")
    matched: List[Dict] = []

    for name, pat, desc, sev in _BYTE_SIGS_V1:
        if isinstance(pat, bytes) and pat in sample:
            matched.append({"name": name, "desc": desc, "severity": sev})
    for name, pat, sev in _REGEX_SIGS_V1:
        try:
            if re.search(pat, text, re.IGNORECASE):
                matched.append({"name": name, "desc": name.replace("_", " ").title(), "severity": sev})
        except Exception:
            pass

    # Phishing-focused text heuristics for workshop kits and credential-harvest pages
    text_lower = text.lower()
    has_password_input = bool(re.search(r"<input[^>]+type\s*=\s*['\"]?password", text, re.IGNORECASE))
    has_form = "<form" in text_lower
    has_remote_action = bool(re.search(r"<form[^>]+action\s*=\s*['\"]https?://", text, re.IGNORECASE))

    if has_form and has_password_input and (has_remote_action or "action=" in text_lower):
        matched.append({
            "name": "PHISHING_LOGIN_FORM",
            "desc": "Credential login form with explicit action target",
            "severity": "high",
        })

    for name, pat, sev in _PHISHING_LURE_PATTERNS_V1:
        try:
            if re.search(pat, text, re.IGNORECASE):
                matched.append({"name": name, "desc": name.replace("_", " ").title(), "severity": sev})
        except Exception:
            pass

    if "window.location" in text_lower and ("atob(" in text_lower or "fromcharcode(" in text_lower):
        matched.append({
            "name": "OBFUSCATED_REDIRECT",
            "desc": "Obfuscated JavaScript redirect logic",
            "severity": "high",
        })

    # PE header
    pe_info = None
    if sample[:2] == b"MZ":
        try:
            if len(sample) >= 0x40:
                pe_off = struct.unpack_from("<I", sample, 0x3C)[0]
                if pe_off + 24 <= len(sample) and sample[pe_off: pe_off + 4] == b"PE\x00\x00":
                    chars   = struct.unpack_from("<H", sample, pe_off + 22)[0]
                    opt_mag = struct.unpack_from("<H", sample, pe_off + 24)[0]
                    is_dll  = bool(chars & 0x2000)
                    no_reloc = bool(chars & 0x0001)
                    pe_info  = {
                        "arch": "x86" if opt_mag == 0x10B else "x64" if opt_mag == 0x20B else "unknown",
                        "is_dll": is_dll,
                        "no_reloc": no_reloc,
                        "suspicious": no_reloc and not is_dll,
                    }
        except Exception:
            pass

    indicators: List[Dict] = []
    _CONF = {"critical": 1.0, "high": 0.85, "medium": 0.65}

    for sig in matched:
        sev  = sig.get("severity", "medium")
        indicators.append({
            "source": "Local Analysis",
            "severity": sev,
            "indicator": f"Signature match: {sig.get('desc', sig['name'])}",
            "type": sig["name"],
            "confidence": _CONF.get(sev, 0.5),
        })

    if entropy >= _HIGH_ENT:
        indicators.append({"source": "Local Analysis", "severity": "high",
                           "indicator": f"Very high entropy ({entropy:.2f}) — likely packed/encrypted",
                           "type": "HIGH_ENTROPY", "confidence": 0.78})
    elif entropy >= _MED_ENT:
        indicators.append({"source": "Local Analysis", "severity": "medium",
                           "indicator": f"Elevated entropy ({entropy:.2f}) — possible obfuscation",
                           "type": "MED_ENTROPY", "confidence": 0.55})

    if ext in _DANGEROUS_EXTS_V1:
        indicators.append({"source": "Local Analysis", "severity": "medium",
                           "indicator": f"Dangerous extension: {ext}",
                           "type": "DANGEROUS_EXT", "confidence": 0.60})

    if pe_info and pe_info.get("suspicious"):
        indicators.append({"source": "Local Analysis", "severity": "high",
                           "indicator": "PE header anomaly — no relocation, not a DLL",
                           "type": "PE_ANOMALY", "confidence": 0.80})

    _SEV_SCORE = {"critical": 5, "high": 3, "medium": 2, "low": 1}
    score = sum(_SEV_SCORE.get(ind.get("severity", "low"), 1) for ind in indicators)

    risk = ("CRITICAL" if score >= 8 else "HIGH" if score >= 5
            else "MEDIUM" if score >= 2 else "LOW" if score >= 1 else "CLEAN")

    _VERDICT = {"CRITICAL": "malicious", "HIGH": "malicious",
                "MEDIUM": "suspicious", "LOW": "suspicious", "CLEAN": "clean"}

    return {
        "risk_level": risk,
        "risk_score": score,
        "entropy": round(entropy, 3),
        "magic_type": magic_type,
        "file_extension": ext,
        "signatures": [s["name"] for s in matched],
        "pe_info": pe_info,
        "threat_indicators": indicators,
        "local_verdict": _VERDICT.get(risk, "clean"),
    }




def _generate_scan_id(prefix: str) -> str:
    """Generate a collision-resistant scan ID suitable for DB unique constraints."""
    ts = datetime.utcnow().strftime("%Y%m%d%H%M%S%f")
    return f"{prefix}_{ts}_{uuid4().hex[:8]}"


def _validate_target(target: str, max_len: int = 2048) -> str:
    """Sanitise and basic-validate a scan target string."""
    target = target.strip()
    if not target:
        raise HTTPException(status_code=400, detail="Target must not be empty")
    if len(target) > max_len:
        raise HTTPException(status_code=400, detail=f"Target exceeds maximum length ({max_len})")
    # Reject obvious shell-injection attempts
    for bad in (";", "&&", "||", "`", "$(",):
        if bad in target:
            raise HTTPException(status_code=400, detail="Invalid characters in target")
    return target


def _normalize_scan_source(scan_source: Optional[str]) -> str:
    """Normalize request scan source to a supported value."""
    if not scan_source:
        return "manual"
    value = scan_source.strip().lower()
    if value not in _ALLOWED_SCAN_SOURCES:
        return "manual"
    return value


def _normalize_verdict(verdict: object, default: str = "unknown") -> str:
    """Normalize threat verdict values from enum/string/object forms."""
    value = verdict if verdict is not None else default
    if hasattr(value, "value"):
        value = getattr(value, "value")
    elif hasattr(value, "name"):
        value = getattr(value, "name")

    normalized = str(value or default).strip().lower()
    if normalized.startswith("threatlevel."):
        normalized = normalized.split(".", 1)[1]

    alias_map = {
        "safe": "clean",
        "benign": "clean",
        "ok": "clean",
        "danger": "malicious",
        "critical": "malicious",
    }
    return alias_map.get(normalized, normalized or default)


def _log_scan_completion(scan_id: str, scan_type: str, result: dict) -> None:
    """Emit concise scan completion logs and suppress benign INFO noise."""
    level = _normalize_verdict(result.get("threat_level", "unknown"))
    indicators = int(result.get("threats_detected", 0) or 0)
    message = f"SCAN {scan_id} | type={scan_type} | lvl={level} | ind={indicators}"
    if level in {"malicious", "critical"} or indicators > 1:
        logger.info(message)
    else:
        logger.debug(message)


def _resolve_external_api_mode(include_external_apis: Optional[bool], scan_source: Optional[str] = None) -> bool:
    """Manual scans use external APIs by default unless explicitly disabled."""
    if include_external_apis is not None:
        return bool(include_external_apis)
    normalized_source = (scan_source or "manual").strip().lower()
    return normalized_source == "manual"


class ThreatScanRequest(BaseModel):
    """Request model for threat scanning"""

    target: str
    include_report: bool = False
    include_external_apis: Optional[bool] = None  # None -> settings.EXTERNAL_APIS_ENABLED
    client_id: Optional[str] = None  # Optional client ID for tracking
    scan_source: Optional[str] = None  # manual | client_protection | background | scheduled

    @field_validator("target")
    @classmethod
    def target_not_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("target must not be empty")
        if len(v) > 2048:
            raise ValueError("target exceeds maximum length of 2048 characters")
        return v

    @field_validator("scan_source")
    @classmethod
    def validate_scan_source(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        value = v.strip().lower()
        if value not in _ALLOWED_SCAN_SOURCES:
            raise ValueError("scan_source must be one of: manual, client_protection, background, scheduled")
        return value


class ScanFeedbackRequest(BaseModel):
    target: str
    input_type: str
    analyst_label: str  # false_positive | true_positive | malicious
    verdict: Optional[str] = None
    weight: float = 1.0

    @field_validator("analyst_label")
    @classmethod
    def validate_label(cls, v: str) -> str:
        value = (v or "").strip().lower()
        if value not in {"false_positive", "true_positive", "malicious"}:
            raise ValueError("analyst_label must be false_positive, true_positive, or malicious")
        return value


class ScanResponse(BaseModel):
    """Response model for scan results"""

    scan_id: str
    target: str
    threat_level: str
    confidence: float
    threats_detected: int
    api_results: dict
    timestamp: str


# CORS preflight handlers
@router.options("/file")
async def options_scan_file():
    """Handle CORS preflight for /file endpoint."""
    return {}


@router.options("/url")
async def options_scan_url():
    """Handle CORS preflight for /url endpoint."""
    return {}


@router.options("/ip")
async def options_scan_ip():
    """Handle CORS preflight for /ip endpoint."""
    return {}


@router.options("/hash")
async def options_scan_hash():
    """Handle CORS preflight for /hash endpoint."""
    return {}


@router.options("/scan")
async def options_universal_scan():
    """Handle CORS preflight for /scan endpoint."""
    return {}


@router.post("/feedback")
async def submit_scan_feedback(payload: ScanFeedbackRequest):
    """Record analyst feedback to improve false-positive suppression over time."""
    try:
        from ....core.security_telemetry import security_telemetry

        fingerprint = f"{payload.input_type.strip().lower()}|{payload.target.strip().lower()}"
        security_telemetry.record_false_positive_feedback(
            fingerprint=fingerprint,
            input_type=payload.input_type.strip().lower(),
            verdict=(payload.verdict or "unknown").strip().lower(),
            analyst_label=payload.analyst_label,
            weight=float(payload.weight or 1.0),
        )
        security_telemetry.append_immutable_audit(
            event_type="analyst_feedback",
            actor="analyst",
            target=f"{payload.input_type}:{payload.target}",
            details={
                "label": payload.analyst_label,
                "verdict": payload.verdict,
                "weight": float(payload.weight or 1.0),
            },
        )
        return {"status": "ok", "message": "feedback recorded"}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to record feedback: {exc}")


async def _store_scan_result(scan_data: dict, db: AsyncSession):
    """Store scan result in history and database"""
    global _scan_history

    if os.getenv("PYTEST_CURRENT_TEST"):
        logger.debug(f"Skipping scan persistence for pytest-generated scan {scan_data.get('scan_id')}")
        return

    _scan_history.insert(0, scan_data)  # Add to front
    # Keep only last 100 scans
    if len(_scan_history) > 100:
        _scan_history = _scan_history[:100]
    
    # Store in database (retry once if scan_id collides)
    try:
        client_id_fk = None
        if scan_data.get("client_id"):
            query = select(ClientInstallation).where(ClientInstallation.client_id == scan_data["client_id"])
            result = await db.execute(query)
            client = result.scalar_one_or_none()
            if client:
                client_id_fk = client.id

        current_scan_id = scan_data["scan_id"]
        id_prefix = current_scan_id.split("_", 1)[0] if "_" in current_scan_id else "SCAN"

        max_attempts = 4
        for attempt in range(max_attempts):
            try:
                scan_record = ScanHistory(
                    scan_id=current_scan_id,
                    target=scan_data.get("target", scan_data.get("filename", "")),
                    target_type=scan_data.get("target_type", "unknown"),
                    threat_level=scan_data.get("threat_level", "unknown"),
                    confidence=scan_data.get("confidence", 0.0),
                    threats_detected=scan_data.get("threats_detected", 0),
                    analysis_data=scan_data.get("analysis", {}),
                    client_id=client_id_fk,
                    report_generated=scan_data.get("report_url") is not None,
                    # Scan origin: 'manual' = user/API, 'background' = auto-monitor
                    scan_source=scan_data.get("scan_source", "manual"),
                    # Forensic Reliability Fields
                    evidence_sources=scan_data.get("forensic_metadata", {}).get("evidence_sources", []),
                    corroboration_count=scan_data.get("forensic_metadata", {}).get("corroboration_count", 0),
                )

                db.add(scan_record)
                db.add(SystemLog(
                    log_level="INFO",
                    component="scanner",
                    message=f"Scan completed: {current_scan_id} - {scan_data.get('target', '')}",
                    details={
                        "scan_id": current_scan_id,
                        "target": scan_data.get("target", scan_data.get("filename", "")),
                        "threat_level": scan_data.get("threat_level"),
                        "target_type": scan_data.get("target_type"),
                        "threats_detected": scan_data.get("threats_detected", 0),
                        "confidence": scan_data.get("confidence", 0.0),
                    },
                ))
                await db.commit()
                scan_data["scan_id"] = current_scan_id

                try:
                    from ....core.security_telemetry import security_telemetry
                    analysis = scan_data.get("analysis") or {}
                    indicators = analysis.get("threat_indicators") or []
                    playbook = []
                    if any("phish" in str(i.get("indicator", "")).lower() for i in indicators if isinstance(i, dict)):
                        playbook.append("phishing_containment")
                    if scan_data.get("target_type") in {"file", "hash", "file_hash"}:
                        playbook.append("download_malware_triage")
                    if scan_data.get("target_type") == "ip":
                        playbook.append("c2_ip_block_and_hunt")

                    security_telemetry.append_immutable_audit(
                        event_type="scan_persisted",
                        actor="v1_scan_api",
                        target=f"{scan_data.get('target_type', 'unknown')}:{scan_data.get('target', scan_data.get('filename', ''))}",
                        details={
                            "scan_id": current_scan_id,
                            "verdict": scan_data.get("threat_level", "unknown"),
                            "confidence": float(scan_data.get("confidence", 0.0) or 0.0),
                            "threats_detected": int(scan_data.get("threats_detected", 0) or 0),
                            "recommended_playbooks": playbook,
                        },
                    )
                except Exception:
                    pass

                logger.debug(f"Scan {current_scan_id} stored in database")
                return
            except IntegrityError as ie:
                await db.rollback()
                if attempt == 0 and "scan_history.scan_id" in str(ie):
                    current_scan_id = _generate_scan_id(id_prefix)
                    logger.warning(
                        "scan_id collision detected; retrying with regenerated id %s",
                        current_scan_id,
                    )
                    continue
                raise
            except OperationalError as oe:
                await db.rollback()
                msg = str(oe).lower()
                locked = "database is locked" in msg or "database table is locked" in msg
                if locked and attempt < (max_attempts - 1):
                    backoff = 0.2 * (attempt + 1)
                    logger.warning(
                        "Database locked while storing scan %s (attempt %s/%s); retrying in %.1fs",
                        current_scan_id,
                        attempt + 1,
                        max_attempts,
                        backoff,
                    )
                    await asyncio.sleep(backoff)
                    continue
                raise
    except Exception as e:
        logger.error(f"Failed to store scan in database: {str(e)}")
        await db.rollback()


@router.get("/history")
async def get_scan_history(
    source: Optional[str] = None,
    limit: int = 100,
):
    """
    Get recent scan history from in-memory cache.
    source=manual (default) | all
    Background auto-monitor scans are NOT stored here — they live in activity_monitoring.db.
    Use GET /api/v1/monitoring/activity for background scan records.
    """
    items = _scan_history
    if source != "all":
        items = [s for s in items if s.get("scan_source", "manual") == "manual"]
    return {
        "total": len(items),
        "source_filter": source or "manual",
        "note": "Background scans are tracked at /api/v1/monitoring/activity",
        "scans": items[:limit],
    }


@router.post("/file")
async def scan_file(
    file: UploadFile = File(...),
    include_report: bool = False,
    include_external_apis: Optional[bool] = None,
    client_id: Optional[str] = None,
    scan_source: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """
    Scan an uploaded file for threats using VirusTotal and Hybrid Analysis

    Args:
        file: File to scan
        include_report: Include PDF report in response
        client_id: Optional client ID for tracking

    Returns:
        Threat analysis results with optional PDF report
    """
    try:
        # Read file content and compute hashes
        file_content = await file.read()
        file_size = len(file_content)

        # Check file size limit (100 MB)
        if file_size > _MAX_FILE_UPLOAD:
            raise HTTPException(status_code=413, detail="File too large (max 100 MB)")

        # Compute SHA256 hash
        file_hash = hashlib.sha256(file_content).hexdigest()
        md5_hash  = hashlib.md5(file_content).hexdigest()

        logger.debug(f"SCAN FILE started | target={file.filename}")

        # ── LOCAL analysis (primary, always runs) ─────────────────────────
        local = _local_scan_v1(file_content, file.filename or "unknown")

        # ── EXTERNAL API hash lookup (secondary, requires API keys) ────────
        try:
            analysis_result = await threat_analyzer.analyze(
                file_hash,
                use_external_apis=_resolve_external_api_mode(include_external_apis, scan_source),
            )
        except Exception as api_err:
            logger.warning(f"External API file-hash lookup failed: {api_err}")
            analysis_result = {"verdict": "clean", "confidence": 0.0,
                               "threat_indicators": [], "api_results": {},
                               "forensic_metadata": {}}

        # ── Merge and determine final verdict ────────────────────────────
        _PRIO = {"malicious": 3, "suspicious": 2, "clean": 1, "safe": 1, "unknown": 0}
        api_verdict    = _normalize_verdict(analysis_result.get("verdict", "clean"), default="clean")
        analysis_result["verdict"] = api_verdict
        local_verdict  = local["local_verdict"]
        final_verdict  = (
            local_verdict
            if _PRIO.get(local_verdict, 0) >= _PRIO.get(api_verdict, 0)
            else api_verdict
        )

        _TL = {"malicious": "malicious", "suspicious": "suspicious",
               "clean": "safe", "safe": "safe"}
        threat_level_str = _TL.get(final_verdict, "unknown")

        all_indicators = local["threat_indicators"] + analysis_result.get("threat_indicators", [])

        local_conf = min(local["risk_score"] / 10.0, 1.0) if local["risk_score"] > 0 else 0.0
        api_conf   = float(analysis_result.get("confidence", 0.0) or 0.0)
        confidence = max(local_conf, api_conf)

        # Add file metadata to analysis result
        analysis_result["file_info"] = {
            "filename": file.filename,
            "size": file_size,
            "content_type": file.content_type,
            "sha256": file_hash,
            "md5": md5_hash,
        }

        scan_id = _generate_scan_id("FILE")
        
        # Generate PDF report if requested
        report_url = None
        try:
            if include_report:
                pdf_bytes = await report_generator.generate_analysis_report(analysis_result)
                if pdf_bytes:
                    report_url = f"/api/v1/reports/download/{scan_id}"
                    if not hasattr(report_generator, '_reports_cache'):
                        report_generator._reports_cache = {}
                    report_generator._reports_cache[scan_id] = pdf_bytes
        except Exception as e:
            logger.error(f"Report generation failed: {str(e)}")
        
        result = {
            "scan_id":          scan_id,
            "filename":         file.filename,
            "file_hash":        file_hash,
            "md5_hash":         md5_hash,
            "status":           "complete",
            "threat_level":     threat_level_str,
            "confidence":       round(confidence, 4),
            "threats_detected": len(all_indicators),
            "verdict":          final_verdict,
            "analysis":         analysis_result,
            "timestamp":        datetime.utcnow().isoformat(),
            "report_url":       report_url,
            "target_type":      "file",
            "target":           file.filename,
            "target_name":      file.filename,
            "client_id":        client_id,
            "scan_source":      _normalize_scan_source(scan_source),
            # Local analysis breakdown
            "local_analysis": {
                "risk_level":     local["risk_level"],
                "risk_score":     local["risk_score"],
                "entropy":        local["entropy"],
                "magic_type":     local["magic_type"],
                "file_extension": local["file_extension"],
                "signatures":     local["signatures"],
                "pe_info":        local["pe_info"],
            },
            "threat_indicators":  all_indicators,
            "forensic_metadata":  analysis_result.get("forensic_metadata", {}),
        }
        
        # Store in scan history and database
        await _store_scan_result(result, db)
        
        _log_scan_completion(scan_id, "file", result)
        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"File scan error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@router.post("/url")
async def scan_url(request: ThreatScanRequest, db: AsyncSession = Depends(get_db)):
    """
    Scan a URL for threats using VirusTotal and URLScan

    Args:
        request: Scan request with target URL

    Returns:
        Threat analysis results
    """
    try:
        url = _validate_target(request.target)
        include_report = request.include_report

        # Ensure URL scheme is present
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        logger.debug(f"SCAN URL started | target={url}")

        # Run threat analysis
        analysis_result = await threat_analyzer.analyze(
            url,
            use_external_apis=_resolve_external_api_mode(request.include_external_apis, request.scan_source),
        )
        normalized_verdict = _normalize_verdict(analysis_result.get("verdict", "unknown"))
        analysis_result["verdict"] = normalized_verdict

        scan_id = _generate_scan_id("URL")
        
        # Generate PDF report if requested
        report_url = None
        try:
            if include_report:
                pdf_bytes = await report_generator.generate_analysis_report(analysis_result)
                if pdf_bytes:
                    report_url = f"/api/v1/reports/download/{scan_id}"
                    # Store report for later retrieval
                    if not hasattr(report_generator, '_reports_cache'):
                        report_generator._reports_cache = {}
                    report_generator._reports_cache[scan_id] = pdf_bytes
        except Exception as e:
            logger.error(f"Report generation failed: {str(e)}")
        
        result = {
            "scan_id": scan_id,
            "url": url,
            "status": "complete",
            "threat_level": normalized_verdict,
            "confidence": analysis_result.get("confidence", 0.0),
            "threats_detected": len(analysis_result.get("threat_indicators", [])),
            "analysis": analysis_result,
            "timestamp": datetime.utcnow().isoformat(),
            "report_url": report_url,
            "target_type": "url",
            "target_name": url,
            "client_id": request.client_id,
            "scan_source": _normalize_scan_source(request.scan_source),
            # Include forensic metadata
            "forensic_metadata": analysis_result.get("forensic_metadata", {}),
        }
        
        # Store in scan history and database
        await _store_scan_result(result, db)
        
        _log_scan_completion(scan_id, "url", result)
        return result

    except Exception as e:
        logger.error(f"URL scan error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@router.post("/ip")
async def scan_ip(request: ThreatScanRequest, db: AsyncSession = Depends(get_db)):
    """
    Scan an IP address for threats using AbuseIPDB and Shodan

    Args:
        request: Scan request with target IP

    Returns:
        Threat analysis results
    """
    try:
        ip = _validate_target(request.target, max_len=45)
        # Basic IP format check
        if not _RE_IP.match(ip):
            raise HTTPException(status_code=400, detail="Invalid IP address format")
        include_report = request.include_report

        logger.debug(f"SCAN IP started | target={ip}")

        # Run threat analysis
        analysis_result = await threat_analyzer.analyze(
            ip,
            use_external_apis=_resolve_external_api_mode(request.include_external_apis, request.scan_source),
        )
        normalized_verdict = _normalize_verdict(analysis_result.get("verdict", "unknown"))
        analysis_result["verdict"] = normalized_verdict

        scan_id = _generate_scan_id("IP")
        
        # Generate PDF report if requested
        report_url = None
        try:
            if include_report:
                pdf_bytes = await report_generator.generate_analysis_report(analysis_result)
                if pdf_bytes:
                    report_url = f"/api/v1/reports/download/{scan_id}"
                    # Store report for later retrieval
                    if not hasattr(report_generator, '_reports_cache'):
                        report_generator._reports_cache = {}
                    report_generator._reports_cache[scan_id] = pdf_bytes
        except Exception as e:
            logger.error(f"Report generation failed: {str(e)}")
        
        result = {
            "scan_id": scan_id,
            "ip": ip,
            "status": "complete",
            "threat_level": normalized_verdict,
            "confidence": analysis_result.get("confidence", 0.0),
            "threats_detected": len(analysis_result.get("threat_indicators", [])),
            "analysis": analysis_result,
            "timestamp": datetime.utcnow().isoformat(),
            "report_url": report_url,
            "target_type": "ip",
            "target_name": ip,
            "client_id": request.client_id,
            "scan_source": _normalize_scan_source(request.scan_source),
            # Include forensic metadata
            "forensic_metadata": analysis_result.get("forensic_metadata", {}),
        }
        
        # Store in scan history and database
        await _store_scan_result(result, db)
        
        _log_scan_completion(scan_id, "ip", result)
        return result

    except Exception as e:
        logger.error(f"IP scan error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@router.post("/hash")
async def scan_hash(request: ThreatScanRequest, db: AsyncSession = Depends(get_db)):
    """
    Scan a file hash for threats using VirusTotal and Hybrid Analysis

    Args:
        request: Scan request with target hash (MD5, SHA1, or SHA256)

    Returns:
        Threat analysis results
    """
    try:
        file_hash = _validate_target(request.target, max_len=128)
        # Accept MD5 (32), SHA1 (40), SHA256 (64) hex strings
        if not _RE_HASH.match(file_hash):
            raise HTTPException(status_code=400, detail="Invalid hash format — expected MD5 (32), SHA1 (40), or SHA256 (64) hex string")
        include_report = request.include_report

        logger.debug(f"SCAN HASH started | target={file_hash[:16]}...")

        # Run threat analysis
        analysis_result = await threat_analyzer.analyze(
            file_hash,
            use_external_apis=_resolve_external_api_mode(request.include_external_apis, request.scan_source),
        )
        normalized_verdict = _normalize_verdict(analysis_result.get("verdict", "unknown"))
        analysis_result["verdict"] = normalized_verdict

        scan_id = _generate_scan_id("HASH")
        
        # Generate PDF report if requested
        report_url = None
        try:
            if include_report:
                pdf_bytes = await report_generator.generate_analysis_report(analysis_result)
                if pdf_bytes:
                    report_url = f"/api/v1/reports/download/{scan_id}"
                    if not hasattr(report_generator, '_reports_cache'):
                        report_generator._reports_cache = {}
                    report_generator._reports_cache[scan_id] = pdf_bytes
        except Exception as e:
            logger.error(f"Report generation failed: {str(e)}")

        result = {
            "scan_id": scan_id,
            "hash": file_hash,
            "status": "complete",
            "threat_level": normalized_verdict,
            "confidence": analysis_result.get("confidence", 0.0),
            "threats_detected": len(analysis_result.get("threat_indicators", [])),
            "analysis": analysis_result,
            "timestamp": datetime.utcnow().isoformat(),
            "report_url": report_url,
            "target_type": "hash",
            "target_name": file_hash,
            "client_id": request.client_id,
            "scan_source": _normalize_scan_source(request.scan_source),
            # Include forensic metadata
            "forensic_metadata": analysis_result.get("forensic_metadata", {}),
        }
        
        # Store in scan history and database
        await _store_scan_result(result, db)
        
        _log_scan_completion(scan_id, "hash", result)
        return result

    except Exception as e:
        logger.error(f"Hash scan error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@router.post("/scan")
async def universal_scan(request: ThreatScanRequest, db: AsyncSession = Depends(get_db)):
    """
    Universal scan endpoint - auto-detects input type and routes to appropriate analyzer

    Args:
        request: Scan request with target (IP, URL, domain, or hash)

    Returns:
        Threat analysis results
    """
    try:
        target = request.target.strip()
        include_report = request.include_report

        # Detect input type
        input_type, metadata = InputDetector.detect(target)

        logger.debug(f"SCAN started | detected_type={input_type.value} | target={target}")

        # Run threat analysis
        analysis_result = await threat_analyzer.analyze(
            target,
            use_external_apis=_resolve_external_api_mode(request.include_external_apis, request.scan_source),
        )
        normalized_verdict = _normalize_verdict(analysis_result.get("verdict", "unknown"))
        analysis_result["verdict"] = normalized_verdict

        scan_id = _generate_scan_id("SCAN")
        
        # Generate PDF report if requested
        report_url = None
        try:
            if include_report:
                pdf_bytes = await report_generator.generate_analysis_report(analysis_result)
                if pdf_bytes:
                    report_url = f"/api/v1/reports/download/{scan_id}"
                    if not hasattr(report_generator, '_reports_cache'):
                        report_generator._reports_cache = {}
                    report_generator._reports_cache[scan_id] = pdf_bytes
        except Exception as e:
            logger.error(f"Report generation failed: {str(e)}")

        result = {
            "scan_id": scan_id,
            "target": target,
            "detected_type": input_type.value,
            "status": "complete",
            "threat_level": normalized_verdict,
            "confidence": analysis_result.get("confidence", 0.0),
            "threats_detected": len(analysis_result.get("threat_indicators", [])),
            "analysis": analysis_result,
            "timestamp": datetime.utcnow().isoformat(),
            "report_url": report_url,
            "target_type": input_type.value,
            "target_name": target,
            "client_id": request.client_id,
            "scan_source": _normalize_scan_source(request.scan_source),
            # Include forensic metadata
            "forensic_metadata": analysis_result.get("forensic_metadata", {}),
            # Include AI analysis if available
            "ai_analysis": analysis_result.get("ai_analysis", {}),
            "ai_verdict_adjustment": analysis_result.get("ai_verdict_adjustment"),
        }
        
        # Store in scan history and database
        await _store_scan_result(result, db)
        
        _log_scan_completion(scan_id, input_type.value, result)
        return result

    except Exception as e:
        logger.error(f"Universal scan error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@router.post("")
@router.post("/")
async def universal_scan_root(request: ThreatScanRequest, db: AsyncSession = Depends(get_db)):
    """Compatibility alias for cleaner route usage: /api/v1/scan"""
    return await universal_scan(request, db)


@router.get("/results/{scan_id}")
async def get_scan_results(scan_id: str):
    """
    Get results of a specific scan

    Note: In production, scan results would be stored in a database
    """
    return {
        "scan_id": scan_id,
        "status": "complete",
        "timestamp": datetime.utcnow().isoformat(),
        "message": "For real-time results, use the /scan endpoint directly",
        "note": "Database integration recommended for production use",
    }
