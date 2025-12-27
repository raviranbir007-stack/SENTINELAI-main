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
    threats = relationship("Threat", back_populates="detected_by")
    logs = relationship("SystemLog", back_populates="user")


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

    # Detection metadata
    detection_time = Column(DateTime(timezone=True), server_default=func.now())
    last_updated = Column(DateTime(timezone=True), onupdate=func.now())

    # Foreign keys
    detected_by_id = Column(Integer, ForeignKey("users.id"))

    # Relationships
    detected_by = relationship("User", back_populates="threats")
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
