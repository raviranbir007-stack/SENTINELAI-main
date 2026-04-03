"""
Minimal CLI Interface - Clean, concise console output
Shows only critical information with emoji indicators
"""

import logging
import sys
import time
from datetime import datetime
from typing import Dict, Optional

logger = logging.getLogger("CLI")
logger.setLevel(logging.INFO)


class MinimalCLI:
    """Minimal CLI interface for SENTINEL-AI"""
    
    def __init__(self):
        self.active_alerts = {}
        self.prompt_history = []
        # Deduplication cache: key -> last_shown_time
        self._prompt_cache: Dict[str, float] = {}
        self._dedup_window = 30  # seconds - prevent duplicate prompts within 30 seconds
    
    def _should_show_prompt(self, key: str) -> bool:
        """Check if prompt should be shown (not recently shown)"""
        now = time.time()
        if key in self._prompt_cache:
            last_shown = self._prompt_cache[key]
            if now - last_shown < self._dedup_window:
                return False
        self._prompt_cache[key] = now
        return True
    
    # ===== PROMPTS (Single-line messages) =====
    
    def prompt_website(self, domain: str):
        """Prompt for website visit"""
        key = f"website_{domain}"
        if self._should_show_prompt(key):
            logger.info(f"🌐 {domain}")
    
    def prompt_threat_safe(self, artifact_type: str, artifact: str):
        """Prompt: Safe"""
        key = f"threat_safe_{artifact_type}_{artifact}"
        if self._should_show_prompt(key):
            logger.info(f"✓ {artifact_type.upper()}: SAFE - {artifact[:40]}")
    
    def prompt_threat_suspicious(self, artifact_type: str, artifact: str):
        """Prompt: Needs verification"""
        key = f"threat_suspicious_{artifact_type}_{artifact}"
        if self._should_show_prompt(key):
            logger.warning(f"⚠️  {artifact_type.upper()}: SUSPICIOUS - {artifact[:40]}")
    
    def prompt_threat_malicious(self, artifact_type: str, artifact: str):
        """Prompt: Malicious - action taken"""
        key = f"threat_malicious_{artifact_type}_{artifact}"
        if self._should_show_prompt(key):
            logger.error(f"🚨 {artifact_type.upper()}: MALICIOUS - {artifact[:40]} [BLOCKED]")

    @staticmethod
    def prompt_scan_result(artifact_type: str, artifact: str, verdict: str, apis_checked: int = 0):
        """Prompt: Scan result summary"""
        verdict_upper = verdict.upper() if verdict else "UNKNOWN"
        suffix = f" | APIs: {apis_checked}/5" if apis_checked else ""
        logger.info(f"🔎 {artifact_type.upper()}: {verdict_upper} - {artifact[:40]}{suffix}")
    
    @staticmethod
    def prompt_attack_detected(attack_type: str, source_ip: str):
        """Prompt: Attack detected"""
        logger.critical(f"🚨 ATTACK: {attack_type} from {source_ip}")
    
    @staticmethod
    def prompt_file_blocked(file_path: str, reason: str):
        """Prompt: File blocked"""
        logger.error(f"🚫 FILE: {file_path} [BLOCKED] - {reason}")
    
    @staticmethod
    def prompt_ip_blocked(ip_address: str):
        """Prompt: IP blocked"""
        logger.warning(f"🔒 IP: {ip_address} [BLOCKED]")
    
    @staticmethod
    def prompt_domain_blocked(domain: str):
        """Prompt: Domain blocked"""
        logger.warning(f"🔒 DOMAIN: {domain} [BLOCKED]")
    
    @staticmethod
    def prompt_scan_starting():
        """Prompt: Scan starting"""
        logger.info(f"🔍 Scan starting...")
    
    @staticmethod
    def prompt_scan_complete(items_scanned: int, threats_found: int):
        """Prompt: Scan complete"""
        if threats_found > 0:
            logger.warning(f"✓ Scan complete: {items_scanned} scanned, {threats_found} threats found")
        else:
            logger.info(f"✓ Scan complete: {items_scanned} scanned, all safe")
    
    @staticmethod
    def prompt_app_started(app_name: str):
        """Prompt: Application started"""
        logger.info(f"📱 {app_name} started")
    
    @staticmethod
    def prompt_network_anomaly(description: str):
        """Prompt: Network anomaly"""
        logger.warning(f"⚠️  ANOMALY: {description}")
    
    @staticmethod
    def prompt_registration_success(client_id: str):
        """Prompt: Registration successful"""
        logger.info(f"✓ Registered: {client_id}")
    
    @staticmethod
    def prompt_registration_failed(reason: str = ""):
        """Prompt: Registration failed"""
        if reason:
            logger.error(f"✗ Registration failed ({reason})")
        else:
            logger.error(f"✗ Registration failed")
    
    @staticmethod
    def prompt_monitoring_started():
        """Prompt: Monitoring started"""
        logger.info(f"▶️  Monitoring active")
    
    @staticmethod
    def prompt_monitoring_stopped():
        """Prompt: Monitoring stopped"""
        logger.info(f"⏹️  Monitoring stopped")
    
    # ===== STATUS SUMMARIES (One-line summaries) =====
    
    @staticmethod
    def show_status_brief(client_id: str, running: bool, threats: int):
        """Show brief status"""
        status = "🟢 ACTIVE" if running else "🔴 INACTIVE"
        logger.info(f"Status: {status} | Client: {client_id[:8]}... | Threats: {threats}")
    
    @staticmethod
    def show_session_summary(websites: int, ips: int, threats_found: int, blocked: int):
        """Show session summary"""
        logger.info(f"📊 Session: {websites} sites | {ips} IPs | {threats_found} threats | {blocked} blocked")
    
    # ===== ERROR HANDLING =====
    
    @staticmethod
    def prompt_error(message: str):
        """Prompt: Error occurred"""
        logger.error(f"ERROR: {message}")
    
    @staticmethod
    def prompt_warning(message: str):
        """Prompt: Warning"""
        logger.warning(f"WARNING: {message}")
    
    @staticmethod
    def prompt_info(message: str):
        """Prompt: Information"""
        logger.info(f"INFO: {message}")
