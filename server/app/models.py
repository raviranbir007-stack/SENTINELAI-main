import enum

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from .database import Base


class ThreatSeverity(enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatStatus(enum.Enum):
    DETECTED = "detected"
    ANALYZING = "analyzing"
    MITIGATED = "mitigated"
    FALSE_POSITIVE = "false_positive"


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(100))
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Relationships
    threats = relationship("Threat", back_populates="detected_by", foreign_keys="[Threat.detected_by_id]")
    overridden_threats = relationship("Threat", foreign_keys="[Threat.analyst_override_by_id]")
    logs = relationship("SystemLog", back_populates="user")
    scan_history = relationship("ScanHistory", back_populates="user")
    attack_events = relationship("AttackEvent", back_populates="detected_by_user")
    acknowledged_alerts = relationship("NetworkAlert", back_populates="acknowledged_by")


class Threat(Base):
    __tablename__ = "threats"

    id = Column(Integer, primary_key=True, index=True)
    threat_id = Column(String(50), unique=True, index=True, nullable=False)
    threat_type = Column(
        String(50), nullable=False
    )  # malware, phishing, intrusion, etc.
    source_ip = Column(String(45))
    source_url = Column(String(500))
    filename = Column(String(255))
    file_hash = Column(String(128))
    description = Column(Text)
    severity = Column(Enum(ThreatSeverity), default=ThreatSeverity.MEDIUM)
    status = Column(Enum(ThreatStatus), default=ThreatStatus.DETECTED)

    # API results
    virus_total_result = Column(JSON)
    abuseipdb_result = Column(JSON)
    shodan_result = Column(JSON)
    hybrid_analysis_result = Column(JSON)
    urlscan_result = Column(JSON)

    # AI Analysis
    ai_confidence = Column(Float)
    ai_analysis = Column(JSON)

    # Forensic Reliability Fields
    evidence_sources = Column(JSON)  # List of sources that confirmed threat with IDs/links
    corroboration_count = Column(Integer, default=0)  # Number of sources confirming threat
    corroboration_threshold_met = Column(Boolean, default=False)  # True if ≥2 sources confirm
    analyst_override = Column(Boolean, default=False)  # True if analyst manually overrode verdict
    analyst_override_notes = Column(Text)  # Analyst's notes for override
    analyst_override_by_id = Column(Integer, ForeignKey("users.id"))  # Who overrode
    analyst_override_at = Column(DateTime(timezone=True))  # When overrode
    original_verdict = Column(String(50))  # Original verdict before override

    # Detection metadata
    detection_time = Column(DateTime(timezone=True), server_default=func.now())
    last_updated = Column(DateTime(timezone=True), onupdate=func.now())

    # Foreign keys
    detected_by_id = Column(Integer, ForeignKey("users.id"))

    # Relationships
    detected_by = relationship("User", back_populates="threats", foreign_keys=[detected_by_id])
    analyst_override_by = relationship("User", back_populates="overridden_threats", foreign_keys=[analyst_override_by_id])
    responses = relationship("ResponseAction", back_populates="threat")


class ResponseAction(Base):
    __tablename__ = "response_actions"

    id = Column(Integer, primary_key=True, index=True)
    action_type = Column(
        String(50), nullable=False
    )  # block_ip, quarantine_file, notify_admin, etc.
    action_details = Column(JSON)
    status = Column(String(20), default="pending")  # pending, completed, failed
    executed_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Foreign keys
    threat_id = Column(Integer, ForeignKey("threats.id"))

    # Relationships
    threat = relationship("Threat", back_populates="responses")


class SystemLog(Base):
    __tablename__ = "system_logs"

    id = Column(Integer, primary_key=True, index=True)
    log_level = Column(String(20), nullable=False)  # INFO, WARNING, ERROR, CRITICAL
    component = Column(String(50), nullable=False)  # api, scanner, ai, dashboard
    message = Column(Text, nullable=False)
    details = Column(JSON)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())

    # Foreign keys
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)

    # Relationships
    user = relationship("User", back_populates="logs")


class APICache(Base):
    __tablename__ = "api_cache"

    id = Column(Integer, primary_key=True, index=True)
    cache_key = Column(String(255), unique=True, index=True, nullable=False)
    service = Column(String(50), nullable=False)  # virus_total, abuseipdb, etc.
    data = Column(JSON, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class ScanHistory(Base):
    """Stores all scan results for historical reporting"""
    __tablename__ = "scan_history"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(String(100), unique=True, index=True, nullable=False)
    target = Column(String(500), nullable=False, index=True)
    target_type = Column(String(50), nullable=False)  # ip, url, domain, file, hash
    target_name = Column(String(255))  # filename or display name
    
    # Scan results
    threat_level = Column(String(50))  # safe, suspicious, malicious, unknown
    confidence = Column(Float, default=0.0)
    threats_detected = Column(Integer, default=0)
    analysis_data = Column(JSON)  # Full analysis result
    
    # Forensic Reliability for Scan History
    evidence_sources = Column(JSON)  # Source evidence for this scan
    corroboration_count = Column(Integer, default=0)
    analyst_notes = Column(Text)  # Optional analyst comments
    analyst_verified = Column(Boolean, default=False)
    
    # Scan source: 'manual' = user/API triggered, 'background' = auto-monitor, 'scheduled' = cron
    scan_source = Column(String(20), default='manual', index=True)

    # Metadata
    scan_timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    client_id = Column(Integer, ForeignKey("client_installations.id"), nullable=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    
    # Report reference
    report_generated = Column(Boolean, default=False)
    report_path = Column(String(500))
    
    # Relationships
    client = relationship("ClientInstallation", back_populates="scans")
    user = relationship("User", back_populates="scan_history")


class ClientInstallation(Base):
    """Tracks client installations across the network"""
    __tablename__ = "client_installations"

    id = Column(Integer, primary_key=True, index=True)
    client_id = Column(String(100), unique=True, index=True, nullable=False)
    
    # Client information
    hostname = Column(String(255), nullable=False)
    ip_address = Column(String(45), nullable=False, index=True)
    mac_address = Column(String(17))
    os_type = Column(String(50))  # Windows, Linux, macOS
    os_version = Column(String(100))
    
    # Network information
    network_segment = Column(String(50))  # e.g., 192.168.1.0/24
    gateway = Column(String(45))
    dns_servers = Column(JSON)
    
    # Installation details
    version = Column(String(50))
    installation_date = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True), onupdate=func.now())
    is_active = Column(Boolean, default=True)
    
    # Security posture
    protection_enabled = Column(Boolean, default=True)
    blocked_ips = Column(JSON)  # List of IPs blocked by this client
    blocked_domains = Column(JSON)  # List of domains blocked
    
    # Relationships
    scans = relationship("ScanHistory", back_populates="client")
    attacks = relationship("AttackEvent", back_populates="target_client")


class AttackEvent(Base):
    """Records detected attacks and suspicious activities"""
    __tablename__ = "attack_events"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(String(100), unique=True, index=True, nullable=False)
    
    # Attack details
    attack_type = Column(String(100), nullable=False)  # DDoS, malware, phishing, intrusion, etc.
    source_ip = Column(String(45), index=True)
    source_domain = Column(String(255))
    destination_ip = Column(String(45))
    destination_port = Column(Integer)
    
    # Detection information
    severity = Column(Enum(ThreatSeverity), default=ThreatSeverity.MEDIUM)
    confidence = Column(Float, default=0.0)
    description = Column(Text)
    indicators = Column(JSON)  # List of threat indicators
    
    # Forensic Reliability for Attack Events
    evidence_sources = Column(JSON)  # Multi-source evidence tracking
    corroboration_count = Column(Integer, default=0)
    analyst_verified = Column(Boolean, default=False)
    analyst_notes = Column(Text)
    
    # Response status
    status = Column(String(50), default="detected")  # detected, analyzing, blocked, mitigated
    blocked = Column(Boolean, default=False)
    blocked_at = Column(DateTime(timezone=True))
    
    # Timestamps
    detected_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    last_updated = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Foreign keys
    target_client_id = Column(Integer, ForeignKey("client_installations.id"))
    detected_by_user_id = Column(Integer, ForeignKey("users.id"))
    
    # Relationships
    target_client = relationship("ClientInstallation", back_populates="attacks")
    detected_by_user = relationship("User", back_populates="attack_events")
    responses = relationship("DefenseAction", back_populates="attack_event")


class DefenseAction(Base):
    """Tracks defense actions taken against threats"""
    __tablename__ = "defense_actions"

    id = Column(Integer, primary_key=True, index=True)
    action_id = Column(String(100), unique=True, index=True, nullable=False)
    
    # Action details
    action_type = Column(String(50), nullable=False)  # block_ip, block_domain, quarantine, alert, etc.
    target = Column(String(500), nullable=False)  # IP, domain, or file being acted upon
    details = Column(JSON)  # Additional action details
    
    # Execution status
    status = Column(String(20), default="pending")  # pending, executed, failed, reverted
    executed_at = Column(DateTime(timezone=True))
    reverted_at = Column(DateTime(timezone=True))
    
    # Effectiveness
    successful = Column(Boolean, default=True)
    error_message = Column(Text)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Foreign keys
    attack_event_id = Column(Integer, ForeignKey("attack_events.id"))
    client_id = Column(Integer, ForeignKey("client_installations.id"))
    
    # Relationships
    attack_event = relationship("AttackEvent", back_populates="responses")
    client = relationship("ClientInstallation")


class NetworkAlert(Base):
    """Network-wide security alerts"""
    __tablename__ = "network_alerts"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(String(100), unique=True, index=True, nullable=False)
    
    # Alert information
    alert_type = Column(String(100), nullable=False)  # attack_pattern, multiple_infections, etc.
    severity = Column(Enum(ThreatSeverity), default=ThreatSeverity.MEDIUM)
    title = Column(String(255), nullable=False)
    description = Column(Text)
    
    # Affected systems
    affected_clients = Column(JSON)  # List of client IDs affected
    affected_count = Column(Integer, default=0)
    
    # Alert status
    status = Column(String(50), default="active")  # active, investigating, resolved
    acknowledged = Column(Boolean, default=False)
    acknowledged_by_id = Column(Integer, ForeignKey("users.id"))
    acknowledged_at = Column(DateTime(timezone=True))
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    resolved_at = Column(DateTime(timezone=True))
    
    # Relationship
    acknowledged_by = relationship("User", back_populates="acknowledged_alerts")
