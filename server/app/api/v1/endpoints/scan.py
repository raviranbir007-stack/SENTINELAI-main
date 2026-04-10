
from fastapi import Body
from fastapi import APIRouter

router = APIRouter()

import logging
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from ....database import get_db

logger = logging.getLogger(__name__)


# In-memory scan history (in production, use database)
_scan_history = []


# Endpoint to mark a scan as read (acknowledged)
@router.post("/mark-read/{scan_id}")
async def mark_scan_as_read(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Mark a scan as read/acknowledged by scan_id (for dashboard health restoration)."""
    # Update in-memory cache
    for scan in _scan_history:
        if scan.get("scan_id") == scan_id:
            scan["is_read"] = True
    # Update DB
    from ....models import ScanHistory
    result = await db.execute(select(ScanHistory).where(ScanHistory.scan_id == scan_id))
    scan_obj = result.scalar_one_or_none()
    if scan_obj:
        scan_obj.is_read = True
        await db.commit()
        return {"status": "ok", "scan_id": scan_id, "is_read": True, "system_health": _get_system_health_status(db)}
    return {"status": "not_found", "scan_id": scan_id, "system_health": _get_system_health_status(db)}

# Endpoint to mark all scans as read (acknowledged)
@router.post("/mark-all-read")
async def mark_all_scans_as_read(db: AsyncSession = Depends(get_db)):
    """Mark all scans as read/acknowledged and restore system health to normal."""
    # Update in-memory cache
    for scan in _scan_history:
        scan["is_read"] = True
    # Update DB
    from ....models import ScanHistory
    result = await db.execute(select(ScanHistory))
    scan_objs = result.scalars().all()
    for scan_obj in scan_objs:
        scan_obj.is_read = True
    await db.commit()
    return {"status": "ok", "all_marked_read": True, "system_health": "normal"}

# Helper to compute system health status
def _get_system_health_status(db):
    # If any scan is not read, health is 'degraded', else 'normal'
    try:
        from ....models import ScanHistory
        # Check in-memory first
        if any(not s.get("is_read", False) for s in _scan_history):
            return "degraded"
        # Check DB
        result = asyncio.get_event_loop().run_until_complete(db.execute(select(ScanHistory)))
        scan_objs = result.scalars().all()
        if any(not s.is_read for s in scan_objs):
            return "degraded"
        return "normal"
    except Exception:
        return "unknown"


import hashlib
import asyncio
import importlib.util
import io
import logging
import math
import os
import re
import struct
import zipfile
from collections import defaultdict
from datetime import datetime, timezone
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
from ....config import settings
from ....database import execute_sqlite_write, get_db
from ....models import ClientInstallation, ScanHistory, SystemLog

logger = logging.getLogger(__name__)

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
# Local file analysis (mirrors compat.py helpers - no external API keys needed)
# ─────────────────────────────────────────────────────────────────────────────
_BYTE_SIGS_V1 = [
    ("EICAR",             b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
                          "EICAR AV test file",          "critical"),
    ("SHELLCODE_NOP",     b"\x90\x90\x90\x90\x90\x90\x90\x90",
                          "NOP sled - shellcode",        "high"),
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
    ".pptm", ".dotm", ".xltm", ".xlam", ".xlsb", ".pptx", ".xlsx",
}
_OFFICE_CONTAINER_EXTS_V1 = {
    ".doc", ".docx", ".docm", ".dot", ".dotx", ".dotm",
    ".xls", ".xlsx", ".xlsm", ".xlsb", ".xltx", ".xltm", ".xlam",
    ".ppt", ".pptx", ".pptm", ".potx", ".potm", ".ppam", ".ppsx", ".ppsm",
    ".odt", ".ods", ".odp",
}
_OFFICE_MACRO_MARKERS_V1 = [
    b"vbaProject.bin",
    b"_VBA_PROJECT",
    b"Auto_Open",
    b"Workbook_Open",
    b"Document_Open",
    b"Presentation_Open",
    b"Shell(",
    b"CreateObject(\"WScript.Shell\")",
    b"CreateObject('WScript.Shell')",
    b"cmd.exe",
    b"powershell",
    b"http://",
    b"https://",
    b"DDE",
]
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


@router.get("/readiness")
async def get_analysis_readiness():
    """Return analysis-phase readiness checklist before scans run."""
    deps = {
        "lief": importlib.util.find_spec("lief") is not None,
        "capstone": importlib.util.find_spec("capstone") is not None,
        "sklearn": importlib.util.find_spec("sklearn") is not None,
        "numpy": importlib.util.find_spec("numpy") is not None,
    }

    api_keys = {
        "virustotal": bool((settings.VIRUSTOTAL_API_KEY or "").strip()),
        "abuseipdb": bool((settings.ABUSEIPDB_API_KEY or "").strip()),
        "shodan": bool((settings.SHODAN_API_KEY or "").strip()),
        "hybridanalysis": bool((settings.HYBRIDANALYSIS_API_KEY or "").strip()),
        "urlscan": bool((settings.URLSCAN_API_KEY or "").strip()),
    }

    input_type_ready = {
        "url": True,
        "ip": True,
        "hash": True,
        "file": True,
    }

    model_ready = {
        "local_heuristics": True,
        "ml_baseline": bool(deps["sklearn"] and deps["numpy"]),
    }

    checklist = [
        {
            "phase": "input_type_readiness",
            "status": "green" if all(input_type_ready.values()) else "red",
            "ready": all(input_type_ready.values()),
            "details": input_type_ready,
            "required": True,
        },
        {
            "phase": "dependency_readiness",
            "status": "green" if deps["lief"] else "red",
            "ready": deps["lief"],
            "details": deps,
            "required": True,
            "note": "lief is required for full PE analysis; capstone/sklearn are optional enrichments.",
        },
        {
            "phase": "model_readiness",
            "status": "green" if model_ready["local_heuristics"] else "red",
            "ready": model_ready["local_heuristics"],
            "details": model_ready,
            "required": True,
            "note": "ML baseline uses sklearn+numpy and degrades gracefully when unavailable.",
        },
        {
            "phase": "api_key_readiness",
            "status": "green" if any(api_keys.values()) else "red",
            "ready": any(api_keys.values()),
            "details": {
                "external_apis_enabled": bool(settings.EXTERNAL_APIS_ENABLED),
                "configured_keys": api_keys,
                "configured_count": sum(1 for v in api_keys.values() if v),
            },
            "required": False,
            "note": "External corroboration is optional; local analysis works without API keys.",
        },
    ]

    overall_ready = all(item["ready"] for item in checklist if item.get("required"))

    return {
        "status": "ready" if overall_ready else "degraded",
        "overall_ready": overall_ready,
        "checklist": checklist,
    }


def _entropy_v1(data: bytes) -> float:
    if not data:
        return 0.0
    freq: Dict[int, int] = defaultdict(int)
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values() if c)


def _disassembly_info_v1(sample: bytes, pe_info: Optional[Dict]) -> Optional[Dict]:
    """Best-effort disassembly metadata for executable-like payloads."""
    if importlib.util.find_spec("capstone") is None:
        return None
    if not sample or len(sample) < 32:
        return None

    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64  # type: ignore

        arch = str((pe_info or {}).get("arch") or "").lower()
        mode = CS_MODE_64 if arch == "x64" else CS_MODE_32

        md = Cs(CS_ARCH_X86, mode)
        md.detail = False
        instructions = list(md.disasm(sample[:256], 0x1000))
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


def _office_document_analysis_v1(content: bytes, filename: str) -> Optional[Dict]:
    """Inspect Office and document containers for macro and e-discovery risk signals."""
    from pathlib import Path as _P

    ext = _P(filename).suffix.lower() if filename else ""
    if ext not in _OFFICE_CONTAINER_EXTS_V1 and b"PK\x03\x04" not in content[:4] and b"\xd0\xcf\x11\xe0" not in content[:4]:
        return None

    sample = content[: 2 * 1024 * 1024]
    text = sample.decode("latin-1", errors="replace")
    signals: List[Dict[str, str]] = []
    macro_capable = ext in {".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".xlam", ".xlsb", ".ppam"}
    archive_layout = None

    macro_hits = 0
    external_link_hits = 0
    embedded_object_hits = 0
    formula_hits = 0
    keyword_hits = 0

    def _add_signal(name: str, desc: str, severity: str) -> None:
        signals.append({"name": name, "desc": desc, "severity": severity})

    if content[:4] == b"PK\x03\x04":
        archive_layout = "ooxml_zip"
        try:
            with zipfile.ZipFile(io.BytesIO(sample)) as zf:
                names = zf.namelist()[:200]
                lower_names = [name.lower() for name in names]
                if any("vbaproject.bin" in name for name in lower_names):
                    macro_capable = True
                    macro_hits += 1
                    _add_signal("OFFICE_VBA_PROJECT", "Embedded VBA project detected", "critical")
                if any(name.endswith(".rels") for name in lower_names):
                    rel_text = ""
                    for rel_name in [name for name in names if name.lower().endswith(".rels")][:20]:
                        try:
                            rel_text += zf.read(rel_name).decode("utf-8", errors="ignore") + "\n"
                        except Exception:
                            continue
                    if any(token in rel_text.lower() for token in ["external", "hyperlink", "targetmode=\"external\"", "targetmode='external'"]):
                        external_link_hits += 1
                        _add_signal("OFFICE_EXTERNAL_RELATIONSHIP", "External relationship target detected", "high")
                xml_text = ""
                for name in names:
                    lowered = name.lower()
                    if lowered.endswith(('.xml', '.vba', '.bin', '.rels')):
                        try:
                            xml_text += zf.read(name).decode("utf-8", errors="ignore") + "\n"
                        except Exception:
                            continue
                lower_xml = xml_text.lower()
                for keyword, sev in [
                    ("auto_open", "critical"),
                    ("workbook_open", "critical"),
                    ("document_open", "high"),
                    ("presentation_open", "high"),
                    ("shell(", "critical"),
                    ("createobject(\"wscript.shell\")", "critical"),
                    ("createobject('wscript.shell')", "critical"),
                    ("powershell", "high"),
                    ("cmd.exe", "high"),
                    ("dde", "high"),
                    ("javascript:", "medium"),
                ]:
                    if keyword in lower_xml:
                        keyword_hits += 1
                        _add_signal("OFFICE_MACRO_BEHAVIOR", f"Suspicious office macro marker: {keyword}", sev)
                for keyword in ["formula", "hyprlink", "weblink", "external link", "r1c1", "indirect(", "get.workbook("]:
                    if keyword in lower_xml:
                        formula_hits += 1
                if formula_hits:
                    _add_signal("OFFICE_FORMULA_RISK", "Spreadsheet formulas or link-driven behaviors detected", "medium")
                if any(name.lower().startswith(("xl/embeddings/", "word/embeddings/", "ppt/embeddings/")) for name in lower_names):
                    embedded_object_hits += 1
                    _add_signal("OFFICE_EMBEDDED_OBJECT", "Embedded object/container detected", "medium")
        except Exception:
            pass
    else:
        lower_text = text.lower()
        if content[:4] == b"\xd0\xcf\x11\xe0":
            archive_layout = "ole2"
            if b"vba" in sample.lower() or b"macro" in sample.lower():
                macro_capable = True
                macro_hits += 1
                _add_signal("OLE_MACRO_MARKER", "OLE macro-capable container marker detected", "high")
            if any(marker.lower() in sample.lower() for marker in [b"auto_open", b"workbook_open", b"document_open", b"cmd.exe", b"powershell"]):
                keyword_hits += 1
                _add_signal("OLE_SUSPICIOUS_MARKER", "Suspicious Office/OLE automation marker detected", "high")
            if b"http://" in sample.lower() or b"https://" in sample.lower():
                external_link_hits += 1
                _add_signal("OLE_EXTERNAL_LINK", "External URL found inside legacy Office container", "medium")
        else:
            if any(token in lower_text for token in ["auto_open", "workbook_open", "document_open", "shell(", "powershell", "cmd.exe"]):
                keyword_hits += 1
                _add_signal("DOCUMENT_SCRIPTING_MARKER", "Document contains scripting or command execution marker", "high")

    if not signals and not macro_capable and not (external_link_hits or embedded_object_hits or keyword_hits):
        return None

    e_discovery = {
        "preserve_original": True,
        "create_legal_hold": macro_capable or keyword_hits > 0 or external_link_hits > 0,
        "isolate_in_sandbox": macro_capable or keyword_hits > 0,
        "collect_hashes": True,
        "review_embedded_objects": bool(embedded_object_hits),
        "review_external_links": bool(external_link_hits),
        "export_chain_of_custody": True,
        "notes": [
            "Preserve the original document and its metadata before remediation.",
            "Review in an isolated environment if the file is macro-capable or contains external links.",
            "Capture hashes and source location for chain-of-custody and e-discovery workflows.",
        ],
        "cost_considerations": [
            "Triage first to reduce full review volume and downstream legal-review cost.",
            "Macro-enabled and link-heavy documents typically require sandbox detonation, which increases review time.",
            "Use deduplication and metadata-first review to minimize analyst hours on repetitive documents.",
        ],
    }

    return {
        "kind": "office_document",
        "extension": ext,
        "archive_layout": archive_layout,
        "macro_capable": macro_capable,
        "macro_hits": macro_hits,
        "external_link_hits": external_link_hits,
        "embedded_object_hits": embedded_object_hits,
        "formula_hits": formula_hits,
        "keyword_hits": keyword_hits,
        "signals": signals,
        "e_discovery": e_discovery,
    }


def _ml_classification_v1(entropy: float, signatures: List[Dict], ext: str, pe_info: Optional[Dict]) -> Optional[Dict]:
    """Lightweight ML classification metadata when sklearn is available."""
    if importlib.util.find_spec("sklearn") is None:
        return None

    try:
        import numpy as np  # type: ignore
        from sklearn.cluster import KMeans  # type: ignore
        from sklearn.ensemble import IsolationForest  # type: ignore
        from sklearn.linear_model import LogisticRegression  # type: ignore
        from sklearn.svm import OneClassSVM  # type: ignore

        is_office_doc = ext in _OFFICE_CONTAINER_EXTS_V1
        macro_signal = 1.0 if ext in {".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".xlam", ".xlsb", ".ppam"} else 0.0
        feature_vector = np.array(
            [[
                float(entropy),
                float(len(signatures)),
                float(1 if ext in _DANGEROUS_EXTS_V1 else 0),
                float(1 if pe_info else 0),
                float(1 if pe_info and pe_info.get("suspicious") else 0),
                float(macro_signal),
                float(1 if is_office_doc else 0),
            ]]
        )

        # Synthetic baseline profiles. The model is trained locally on heuristics, so it stays self-contained.
        normal_profiles = np.array(
            [
                [2.1, 0, 0, 0, 0, 0, 0],
                [2.7, 0, 0, 0, 0, 0, 0],
                [3.2, 0, 0, 0, 0, 0, 1],
                [4.0, 1, 0, 0, 0, 0, 1],
                [4.4, 1, 0, 0, 0, 0, 1],
                [5.1, 1, 0, 0, 0, 0, 0],
                [5.9, 1, 1, 0, 0, 0, 0],
                [6.4, 2, 1, 1, 0, 1, 1],
            ],
            dtype=float,
        )
        suspicious_profiles = np.array(
            [
                [6.8, 2, 1, 1, 0, 1, 1],
                [7.2, 3, 1, 1, 1, 1, 1],
                [7.9, 4, 1, 1, 1, 1, 1],
                [8.3, 5, 1, 1, 1, 1, 1],
            ],
            dtype=float,
        )
        train_x = np.vstack([normal_profiles, suspicious_profiles])
        train_y = np.array([0] * len(normal_profiles) + [1] * len(suspicious_profiles), dtype=int)

        isolation_model = IsolationForest(n_estimators=100, contamination=0.25, random_state=42)
        isolation_model.fit(train_x)
        isolation_score = float(-isolation_model.score_samples(feature_vector)[0])

        svm_model = OneClassSVM(kernel="rbf", gamma="scale", nu=0.18)
        svm_model.fit(normal_profiles)
        svm_prediction = int(svm_model.predict(feature_vector)[0] == -1)

        cluster_model = KMeans(n_clusters=2, random_state=42, n_init=10)
        cluster_model.fit(train_x)
        cluster_center_distances = cluster_model.transform(feature_vector)[0]
        cluster_score = float(min(cluster_center_distances) / max(cluster_center_distances.max(), 1.0))

        logistic_model = LogisticRegression(max_iter=250, random_state=42)
        logistic_model.fit(train_x, train_y)
        logistic_prob = float(logistic_model.predict_proba(feature_vector)[0][1])

        combined_score = (
            (isolation_score * 0.40)
            + (logistic_prob * 0.35)
            + (cluster_score * 0.15)
            + (0.10 if svm_prediction else 0.0)
        )
        combined_score = max(0.0, min(1.0, combined_score))

        if combined_score >= 0.72:
            prediction = "MALICIOUS"
        elif combined_score >= 0.48:
            prediction = "SUSPICIOUS"
        else:
            prediction = "CLEAN"

        return {
            "model": "isolation_forest_svm_kmeans_ensemble",
            "prediction": prediction,
            "confidence": round(combined_score, 3),
            "ensemble": {
                "isolation_forest_score": round(isolation_score, 3),
                "one_class_svm_flagged": bool(svm_prediction),
                "kmeans_cluster_distance_score": round(cluster_score, 3),
                "logistic_probability": round(logistic_prob, 3),
            },
            "features": {
                "entropy": round(float(entropy), 3),
                "signature_count": int(len(signatures)),
                "dangerous_extension": bool(ext in _DANGEROUS_EXTS_V1),
                "office_container": bool(is_office_doc),
                "macro_capable_extension": bool(macro_signal),
                "has_pe": bool(pe_info),
                "pe_suspicious": bool(pe_info and pe_info.get("suspicious")),
            },
            "recommended_algorithm": "IsolationForest",
            "algorithm_rationale": "IsolationForest is the best fit for this project because macro-enabled Office files and mixed document artifacts are usually unlabeled, sparse, and benefit from anomaly detection rather than only supervised classification.",
        }
    except Exception:
        return None


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
                           "indicator": f"Very high entropy ({entropy:.2f}) - likely packed/encrypted",
                           "type": "HIGH_ENTROPY", "confidence": 0.78})
    elif entropy >= _MED_ENT:
        indicators.append({"source": "Local Analysis", "severity": "medium",
                           "indicator": f"Elevated entropy ({entropy:.2f}) - possible obfuscation",
                           "type": "MED_ENTROPY", "confidence": 0.55})

    if ext in _DANGEROUS_EXTS_V1:
        indicators.append({"source": "Local Analysis", "severity": "medium",
                           "indicator": f"Dangerous extension: {ext}",
                           "type": "DANGEROUS_EXT", "confidence": 0.60})

    if pe_info and pe_info.get("suspicious"):
        indicators.append({"source": "Local Analysis", "severity": "high",
                           "indicator": "PE header anomaly - no relocation, not a DLL",
                           "type": "PE_ANOMALY", "confidence": 0.80})

    document_info = _office_document_analysis_v1(content, filename)
    if document_info:
        macro_count = int(document_info.get("macro_hits", 0) or 0)
        link_count = int(document_info.get("external_link_hits", 0) or 0)
        embedded_count = int(document_info.get("embedded_object_hits", 0) or 0)
        keyword_count = int(document_info.get("keyword_hits", 0) or 0)

        if macro_count:
            indicators.append({
                "source": "Local Analysis",
                "severity": "critical" if macro_count >= 2 else "high",
                "indicator": "Macro-capable Office document with VBA markers detected",
                "type": "OFFICE_MACRO_CONTAINER",
                "confidence": 0.95,
            })
        if link_count:
            indicators.append({
                "source": "Local Analysis",
                "severity": "medium",
                "indicator": "External link or remote content target detected in document",
                "type": "OFFICE_EXTERNAL_LINK",
                "confidence": 0.74,
            })
        if embedded_count:
            indicators.append({
                "source": "Local Analysis",
                "severity": "medium",
                "indicator": "Embedded object detected inside document container",
                "type": "OFFICE_EMBEDDED_OBJECT",
                "confidence": 0.68,
            })
        if keyword_count:
            indicators.append({
                "source": "Local Analysis",
                "severity": "high",
                "indicator": "Suspicious Office scripting or automation keywords detected",
                "type": "OFFICE_SCRIPTING_MARKER",
                "confidence": 0.82,
            })

        if document_info.get("e_discovery"):
            indicators.append({
                "source": "Local Analysis",
                "severity": "low",
                "indicator": "E-discovery handling guidance generated for document evidence preservation",
                "type": "EDISCOVERY_GUIDANCE",
                "confidence": 0.5,
            })

    _SEV_SCORE = {"critical": 5, "high": 3, "medium": 2, "low": 1}
    score = sum(_SEV_SCORE.get(ind.get("severity", "low"), 1) for ind in indicators)

    risk = ("CRITICAL" if score >= 8 else "HIGH" if score >= 5
            else "MEDIUM" if score >= 2 else "LOW" if score >= 1 else "CLEAN")

    _VERDICT = {"CRITICAL": "malicious", "HIGH": "malicious",
                "MEDIUM": "suspicious", "LOW": "suspicious", "CLEAN": "clean"}

    disassembly_info = _disassembly_info_v1(sample, pe_info)
    ml_classification = _ml_classification_v1(entropy, matched, ext, pe_info)

    return {
        "risk_level": risk,
        "risk_score": score,
        "entropy": round(entropy, 3),
        "magic_type": magic_type,
        "file_extension": ext,
        "signatures": [s["name"] for s in matched],
        "pe_info": pe_info,
        "disassembly_info": disassembly_info,
        "ml_classification": ml_classification,
        "document_analysis": document_info,
        "threat_indicators": indicators,
        "local_verdict": _VERDICT.get(risk, "clean"),
    }




def _generate_scan_id(prefix: str) -> str:
    """Generate a collision-resistant scan ID suitable for DB unique constraints."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
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


def _normalize_scan_type(scan_type: Optional[str]) -> str:
    """Normalize a requested scan type to a supported routing hint."""
    if not scan_type:
        return ""
    value = scan_type.strip().lower()
    alias_map = {
        "file_type": "file",
        "filehash": "hash",
        "file_hash": "hash",
    }
    value = alias_map.get(value, value)
    if value in {"ip", "domain", "url", "file", "hash"}:
        return value
    return ""


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
    scan_type: Optional[str] = None  # ip | domain | url | file | file_type | hash
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

    @field_validator("scan_type")
    @classmethod
    def validate_scan_type(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        value = v.strip().lower()
        if value not in {"ip", "domain", "url", "file", "file_type", "hash"}:
            raise ValueError("scan_type must be one of: ip, domain, url, file, file_type, hash")
        return value


class ScanFeedbackRequest(BaseModel):
    target: str
    input_type: str
    analyst_label: str  # false_positive | true_positive | malicious | uncertain
    verdict: Optional[str] = None
    weight: float = 1.0

    @field_validator("analyst_label")
    @classmethod
    def validate_label(cls, v: str) -> str:
        value = (v or "").strip().lower()
        if value not in {"false_positive", "true_positive", "malicious", "uncertain"}:
            raise ValueError("analyst_label must be false_positive, true_positive, malicious, or uncertain")
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
        logger.error("Failed to record feedback: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to record feedback")


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
                async def _persist_once():
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
                        scan_source=scan_data.get("scan_source", "manual"),
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

                await execute_sqlite_write(
                    db,
                    f"storing scan {current_scan_id}",
                    _persist_once,
                    max_attempts=4,
                    base_delay=0.2,
                )
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
    except Exception as e:
        logger.error(f"Failed to store scan in database: {str(e)}")
        await db.rollback()


@router.get("/history")
async def get_scan_history(
    source: Optional[str] = None,
    limit: int = 100,
):
    # ...existing code...
    # Get recent scan history from in-memory cache.
    # source=manual (default) | all
    # Background auto-monitor scans are NOT stored here - they live in activity_monitoring.db.
    # Use GET /api/v1/monitoring/activity for background scan records.
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
            analysis_result["api_coverage_explanation"] = (
                f"External file-hash analysis was unavailable ({api_err}); local heuristics, behavioral analysis, "
                "and ML anomaly detection were used to complete the scan."
            )

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
        analysis_result["file_analysis"] = {
            "entropy": local["entropy"],
            "signatures": local["signatures"],
            "pe_info": local["pe_info"],
            "disassembly_info": local.get("disassembly_info"),
            "ml_classification": local.get("ml_classification"),
            "document_analysis": local.get("document_analysis"),
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
            "timestamp":        datetime.now(timezone.utc).isoformat(),
            "report_url":       report_url,
            "target_type":      "file",
            "target":           file.filename,
            "target_name":      file.filename,
            "client_id":        client_id,
            "scan_source":      _normalize_scan_source(scan_source),
            "is_read":          False,
            # Local analysis breakdown
            "local_analysis": {
                "risk_level":     local["risk_level"],
                "risk_score":     local["risk_score"],
                "entropy":        local["entropy"],
                "magic_type":     local["magic_type"],
                "file_extension": local["file_extension"],
                "signatures":     local["signatures"],
                "pe_info":        local["pe_info"],
                "disassembly_info": local.get("disassembly_info"),
                "ml_classification": local.get("ml_classification"),
                "document_analysis": local.get("document_analysis"),
            },
            "document_analysis": local.get("document_analysis"),
            "ediscovery_considerations": (local.get("document_analysis") or {}).get("e_discovery") if isinstance(local.get("document_analysis"), dict) else None,
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
        raise HTTPException(status_code=500, detail="Scan failed due to internal server error")


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
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "report_url": report_url,
            "target_type": "url",
            "target_name": url,
            "client_id": request.client_id,
            "scan_source": _normalize_scan_source(request.scan_source),
            "is_read": False,
            # Top-level API coverage for dashboard
            "api_results": analysis_result.get("api_results", {}),
            "forensic_metadata": analysis_result.get("forensic_metadata", {}),
        }
        
        # Store in scan history and database
        await _store_scan_result(result, db)
        
        _log_scan_completion(scan_id, "url", result)
        return result

    except Exception as e:
        logger.error(f"URL scan error: {str(e)}")
        raise HTTPException(status_code=500, detail="Scan failed due to internal server error")


@router.post("/ip")
async def scan_ip(request: ThreatScanRequest, db: AsyncSession = Depends(get_db)):
    # Scan an IP address for threats using AbuseIPDB and Shodan
    # Args:
    #     request: Scan request with target IP
    # Returns:
    #     Threat analysis results
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
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "report_url": report_url,
            "target_type": "ip",
            "target_name": ip,
            "client_id": request.client_id,
            "scan_source": _normalize_scan_source(request.scan_source),
            "is_read": False,
            # Top-level API coverage for dashboard
            "api_results": analysis_result.get("api_results", {}),
            "forensic_metadata": analysis_result.get("forensic_metadata", {}),
        }
        
        # Store in scan history and database
        await _store_scan_result(result, db)
        
        _log_scan_completion(scan_id, "ip", result)
        return result

    except Exception as e:
        logger.error(f"IP scan error: {str(e)}")
        raise HTTPException(status_code=500, detail="Scan failed due to internal server error")


@router.post("/hash")
async def scan_hash(request: ThreatScanRequest, db: AsyncSession = Depends(get_db)):
    # Scan a file hash for threats using VirusTotal and Hybrid Analysis
    # Args:
    #     request: Scan request with target hash (MD5, SHA1, or SHA256)
    # Returns:
    #     Threat analysis results
    try:
        file_hash = _validate_target(request.target, max_len=128)
        # Accept MD5 (32), SHA1 (40), SHA256 (64) hex strings
        if not _RE_HASH.match(file_hash):
            raise HTTPException(status_code=400, detail="Invalid hash format - expected MD5 (32), SHA1 (40), or SHA256 (64) hex string")
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
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "report_url": report_url,
            "target_type": "hash",
            "target_name": file_hash,
            "client_id": request.client_id,
            "scan_source": _normalize_scan_source(request.scan_source),
            "is_read": False,
            # Top-level API coverage for dashboard
            "api_results": analysis_result.get("api_results", {}),
            "forensic_metadata": analysis_result.get("forensic_metadata", {}),
        }
        
        # Store in scan history and database
        await _store_scan_result(result, db)
        
        _log_scan_completion(scan_id, "hash", result)
        return result

    except Exception as e:
        logger.error(f"Hash scan error: {str(e)}")
        raise HTTPException(status_code=500, detail="Scan failed due to internal server error")


@router.post("/scan")
async def universal_scan(request: ThreatScanRequest, db: AsyncSession = Depends(get_db)):
    # Universal scan endpoint - auto-detects input type and routes to appropriate analyzer
    # Args:
    #     request: Scan request with target (IP, URL, domain, or hash)
    # Returns:
    #     Threat analysis results
    try:
        target = request.target.strip()
        include_report = request.include_report
        requested_scan_type = _normalize_scan_type(request.scan_type)

        analysis_target = target
        if requested_scan_type == "file":
            lowered = target.strip().lower()
            if lowered in {ext.lstrip('.') for ext in InputDetector.FILE_EXTENSIONS}:
                analysis_target = f".{lowered}"

        # Detect input type
        input_type, metadata = InputDetector.detect(analysis_target)

        logger.debug(
            f"SCAN started | detected_type={input_type.value} | requested_type={requested_scan_type or 'auto'} | target={target}"
        )

        # Run threat analysis
        analysis_result = await threat_analyzer.analyze(
            analysis_target,
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
            "requested_scan_type": requested_scan_type or None,
            "status": "complete",
            "threat_level": normalized_verdict,
            "confidence": analysis_result.get("confidence", 0.0),
            "threats_detected": len(analysis_result.get("threat_indicators", [])),
            "analysis": analysis_result,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "report_url": report_url,
            "target_type": input_type.value,
            "target_name": target,
            "client_id": request.client_id,
            "scan_source": _normalize_scan_source(request.scan_source),
            "is_read": False,
            # Top-level API coverage for dashboard
            "api_results": analysis_result.get("api_results", {}),
            "forensic_metadata": analysis_result.get("forensic_metadata", {}),
            # Include AI analysis if available
            "ai_analysis": analysis_result.get("ai_analysis", {}),
            "ai_verdict_adjustment": analysis_result.get("ai_verdict_adjustment"),
        }
        
        # Store in scan history and database
        await _store_scan_result(result, db)
        
        _log_scan_completion(scan_id, requested_scan_type or input_type.value, result)
        return result

    except Exception as e:
        logger.error(f"Universal scan error: {str(e)}")
        raise HTTPException(status_code=500, detail="Scan failed due to internal server error")


@router.post("")
@router.post("/")
async def universal_scan_root(request: ThreatScanRequest, db: AsyncSession = Depends(get_db)):
    # Compatibility alias for cleaner route usage: /api/v1/scan
    return await universal_scan(request, db)


@router.get("/results/{scan_id}")
async def get_scan_results(scan_id: str):
    # Get results of a specific scan
    # Note: In production, scan results would be stored in a database
    # Try to find scan in in-memory cache
    scan = next((s for s in _scan_history if s.get("scan_id") == scan_id), None)
    api_coverage_section = None
    if scan:
        # Use the same logic as report_generator for API coverage
        analysis = scan.get("analysis", {})
        from ....core.threat_analyzer import ALL_EXTERNAL_APIS
        api_results = analysis.get("api_results", {})
        api_status = api_results.get("api_status", {})
        apis_called = api_results.get("apis_called", [])
        apis_expected = api_results.get("apis_expected", [api["name"] for api in ALL_EXTERNAL_APIS])
        explanation = analysis.get("api_coverage_explanation")
        lines = [f"APIs Expected: {', '.join(apis_expected)}"]
        lines.append(f"APIs Called: {', '.join(apis_called)}")
        lines.append("")
        if explanation:
            lines.append(f"API Coverage Note: {explanation}")
        for api in ALL_EXTERNAL_APIS:
            key = api["key"]
            name = api["name"]
            meta = api_status.get(key, {})
            status = str(meta.get("status", "unknown") or "unknown").strip().lower()
            configured = meta.get("configured", False)
            applicable = meta.get("applicable", False)
            error = meta.get("error")
            
            # Build human-readable status message
            if status in {"success", "completed", "ok", "checked", "online", "available", "clean", "no_threat"}:
                status_message = "provider data collected successfully"
            elif explanation and status == "not_applicable":
                status_message = "intelligence fallback active (reason: test/demo domain; provider not queried)"
            elif status == "not_configured":
                status_message = "intelligence fallback active (reason: provider key not configured in environment)"
            elif status == "rate_limited":
                status_message = "intelligence fallback active (reason: provider quota or rate limit reached)"
            elif status == "skipped_local_mode":
                status_message = "intelligence fallback active (reason: external APIs disabled for local-only analysis)"
            elif not applicable:
                status_message = f"intelligence fallback active (reason: indicator type is outside provider coverage)"
            elif status in {"pending", "in_progress", "queued"}:
                status_message = f"intelligence fallback active (reason: provider analysis did not complete in this scan window)"
            elif status in {"timeout", "error", "failed", "not_applicable"}:
                status_message = f"intelligence fallback active (reason: provider request failed during collection)"
            else:
                status_message = f"intelligence fallback active (reason: provider returned unrecognized status: {status})"
            
            lines.append(f"- {name}: {status_message}{' | error: ' + error if error else ''}")
        api_coverage_section = "\n".join(lines)
    return {
        "scan_id": scan_id,
        "status": "complete",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "message": "For real-time results, use the /scan endpoint directly",
        "note": "Database integration recommended for production use",
        "api_coverage": api_coverage_section,
    }
