"""
NIDS/NDR Ingestor
Normalizes Suricata EVE and Zeek records into a common event model
that can be stored as `AttackEvent` records.

This module is intentionally lightweight and dependency-free so it can run
in constrained deployments.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class NormalizedNIDSEvent:
    attack_type: str
    source_ip: Optional[str]
    source_domain: Optional[str]
    destination_ip: Optional[str]
    destination_port: Optional[int]
    severity: str
    confidence: float
    description: str
    indicators: Dict[str, Any]


def _severity_from_suricata(alert_severity: Optional[int]) -> str:
    # Suricata severity: 1=high, 2=medium, 3=low
    if alert_severity is None:
        return "medium"
    if alert_severity <= 1:
        return "high"
    if alert_severity == 2:
        return "medium"
    return "low"


def _confidence_from_signature(sig: str) -> float:
    text = (sig or "").lower()
    if any(k in text for k in ["trojan", "exploit", "malware", "rce", "c2", "command and control"]):
        return 0.9
    if any(k in text for k in ["scan", "brute", "suspicious", "anomaly"]):
        return 0.7
    return 0.55


class NIDSIngestor:
    """Normalization adapter for Suricata/Zeek security events."""

    @staticmethod
    def from_suricata_eve(record: Dict[str, Any]) -> Optional[NormalizedNIDSEvent]:
        if not isinstance(record, dict):
            return None
        event_type = record.get("event_type")
        if event_type not in {"alert", "dns", "http", "tls", "flow"}:
            return None

        src_ip = record.get("src_ip")
        dst_ip = record.get("dest_ip")
        dst_port = record.get("dest_port")

        if event_type == "alert":
            alert = record.get("alert", {}) or {}
            signature = alert.get("signature", "suricata_alert")
            severity = _severity_from_suricata(alert.get("severity"))
            confidence = _confidence_from_signature(signature)
            attack_type = alert.get("category") or signature
            description = f"Suricata alert: {signature}"
        else:
            signature = f"suricata_{event_type}"
            severity = "low"
            confidence = 0.5
            attack_type = signature
            description = f"Suricata {event_type} event"

        return NormalizedNIDSEvent(
            attack_type=attack_type,
            source_ip=src_ip,
            source_domain=None,
            destination_ip=dst_ip,
            destination_port=int(dst_port) if isinstance(dst_port, int) else None,
            severity=severity,
            confidence=confidence,
            description=description,
            indicators={"source": "suricata", "raw": record},
        )

    @staticmethod
    def from_zeek_record(record: Dict[str, Any], log_type: str = "conn") -> Optional[NormalizedNIDSEvent]:
        if not isinstance(record, dict):
            return None

        src_ip = record.get("id.orig_h") or record.get("src") or record.get("orig_h")
        dst_ip = record.get("id.resp_h") or record.get("dst") or record.get("resp_h")
        dst_port = record.get("id.resp_p") or record.get("resp_p")

        severity = "low"
        confidence = 0.45
        attack_type = f"zeek_{log_type}"
        description = f"Zeek {log_type} event"

        if log_type == "notice":
            note = str(record.get("note", "zeek_notice"))
            msg = str(record.get("msg", ""))
            attack_type = note
            description = f"Zeek notice: {msg or note}"
            lowered = f"{note} {msg}".lower()
            if any(k in lowered for k in ["scan", "bruteforce", "password guessing"]):
                severity = "high"
                confidence = 0.8
            elif any(k in lowered for k in ["ssl", "cert", "suspicious", "dns"]):
                severity = "medium"
                confidence = 0.65
            else:
                severity = "medium"
                confidence = 0.6

        return NormalizedNIDSEvent(
            attack_type=attack_type,
            source_ip=src_ip,
            source_domain=record.get("query") or record.get("host") or None,
            destination_ip=dst_ip,
            destination_port=int(dst_port) if isinstance(dst_port, int) else None,
            severity=severity,
            confidence=confidence,
            description=description,
            indicators={"source": "zeek", "log_type": log_type, "raw": record},
        )

    @staticmethod
    def batch_normalize(source: str, records: List[Dict[str, Any]], zeek_log_type: str = "conn") -> List[NormalizedNIDSEvent]:
        normalized: List[NormalizedNIDSEvent] = []
        source_lower = (source or "").strip().lower()

        for item in records or []:
            evt = None
            if source_lower == "suricata":
                evt = NIDSIngestor.from_suricata_eve(item)
            elif source_lower == "zeek":
                evt = NIDSIngestor.from_zeek_record(item, log_type=zeek_log_type)

            if evt:
                normalized.append(evt)

        return normalized
