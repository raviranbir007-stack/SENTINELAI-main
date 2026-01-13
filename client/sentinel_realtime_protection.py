"""
SENTINEL-AI Real-Time Attack Detection & Prevention System
Advanced security client with 5-warning notification system and automatic quarantine
"""

import asyncio
import json
import logging
import platform
import socket
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
import psutil
import requests

# Desktop notification libraries
try:
    if platform.system() == "Windows":
        from win10toast import ToastNotifier
        toaster = ToastNotifier()
    elif platform.system() == "Linux":
        import notify2
        notify2.init("SentinelAI")
    elif platform.system() == "Darwin":  # macOS
        import pync
except ImportError:
    print("Warning: Desktop notification library not available. Install win10toast (Windows) or notify2 (Linux)")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("sentinel_realtime.log"),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("SentinelRT")


class ThreatWarningSystem:
    """Manages the 5-warning notification system before automatic quarantine"""
    
    def __init__(self):
        self.threat_warnings = {}  # threat_id -> warning_count
        self.MAX_WARNINGS = 5
        self.WARNING_INTERVAL = 10  # seconds between warnings
        
    def add_warning(self, threat_id: str, threat_info: Dict) -> int:
        """Add a warning for a threat and return current warning count"""
        if threat_id not in self.threat_warnings:
            self.threat_warnings[threat_id] = {
                "count": 0,
                "last_warning": 0,
                "info": threat_info
            }
        
        current_time = time.time()
        threat = self.threat_warnings[threat_id]
        
        # Check if enough time has passed since last warning
        if current_time - threat["last_warning"] >= self.WARNING_INTERVAL:
            threat["count"] += 1
            threat["last_warning"] = current_time
            
        return threat["count"]
    
    def should_quarantine(self, threat_id: str) -> bool:
        """Check if threat should be quarantined (reached max warnings)"""
        if threat_id in self.threat_warnings:
            return self.threat_warnings[threat_id]["count"] >= self.MAX_WARNINGS
        return False
    
    def reset_warnings(self, threat_id: str):
        """Reset warnings for a threat (after quarantine)"""
        if threat_id in self.threat_warnings:
            del self.threat_warnings[threat_id]


class RealTimeDefenseSystem:
    """Real-time attack detection and prevention system"""
    
    def __init__(self, server_url: str, api_key: str = None):
        self.server_url = server_url.rstrip('/')
        self.api_key = api_key
        self.client_id = self._get_or_create_client_id()
        self.warning_system = ThreatWarningSystem()
        self.running = False
        
        # Defense status
        self.blocked_ips = set()
        self.blocked_domains = set()
        self.quarantined_files = []
        self.active_threats = {}
        
        # Statistics
        self.stats = {
            "attacks_detected": 0,
            "attacks_blocked": 0,
            "files_quarantined": 0,
            "ips_blocked": 0,
            "domains_blocked": 0,
            "warnings_issued": 0
        }
    
    def _get_or_create_client_id(self) -> str:
        """Get or create unique client ID"""
        id_file = Path("client_id.txt")
        if id_file.exists():
            return id_file.read_text().strip()
        else:
            import uuid
            client_id = f"CLIENT_{uuid.uuid4().hex[:12].upper()}"
            id_file.write_text(client_id)
            return client_id
    
    def _get_headers(self) -> Dict[str, str]:
        """Get API request headers"""
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers
    
    def send_desktop_notification(self, title: str, message: str, urgency: str = "normal"):
        """Send desktop notification to user"""
        try:
            system = platform.system()
            if system == "Windows":
                toaster.show_toast(title, message, duration=10, threaded=True)
            elif system == "Linux":
                notification = notify2.Notification(title, message)
                if urgency == "critical":
                    notification.set_urgency(notify2.URGENCY_CRITICAL)
                elif urgency == "high":
                    notification.set_urgency(notify2.URGENCY_NORMAL)
                notification.show()
            elif system == "Darwin":  # macOS
                pync.notify(message, title=title)
        except Exception as e:
            logger.warning(f"Failed to send desktop notification: {e}")
            # Fallback to console
            print(f"\n{'='*60}")
            print(f"🚨 {title}")
            print(f"{message}")
            print(f"{'='*60}\n")
    
    async def scan_target(self, target: str, target_type: str) -> Dict:
        """Scan a target using the server's multi-API analysis"""
        try:
            endpoint = f"{self.server_url}/api/v1/scan/{target_type}"
            
            payload = {
                "target": target,
                "client_id": self.client_id
            }
            
            response = requests.post(
                endpoint,
                json=payload,
                headers=self._get_headers(),
                timeout=30
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"Scan failed: {response.status_code} - {response.text[:200]}")
                return {"error": response.text}
                
        except Exception as e:
            logger.error(f"Scan error: {e}")
            return {"error": str(e)}
    
    async def handle_threat_detected(self, threat_info: Dict):
        """Handle a detected threat with warning system and quarantine"""
        threat_id = threat_info.get("scan_id", f"THR_{int(time.time())}")
        target = threat_info.get("target", "Unknown")
        threat_level = threat_info.get("threat_level", "unknown")
        confidence = threat_info.get("confidence", 0)
        
        # Only handle suspicious and malicious threats
        if threat_level not in ["suspicious", "malicious"]:
            return
        
        self.stats["attacks_detected"] += 1
        self.active_threats[threat_id] = threat_info
        
        # Add warning
        warning_count = self.warning_system.add_warning(threat_id, threat_info)
        self.stats["warnings_issued"] += 1
        
        # Determine urgency
        urgency = "critical" if threat_level == "malicious" else "high"
        
        # Send warning notification
        warning_msg = f"""
⚠️  THREAT DETECTED ({warning_count}/{self.warning_system.MAX_WARNINGS})

Target: {target}
Threat Level: {threat_level.upper()}
Confidence: {confidence*100:.1f}%
Type: {threat_info.get('target_type', 'Unknown').upper()}

{5 - warning_count} warnings remaining before automatic quarantine!
        """.strip()
        
        self.send_desktop_notification(
            f"⚠️  Security Alert #{warning_count}/5",
            warning_msg,
            urgency
        )
        
        logger.warning(f"Threat detected: {target} - {threat_level} - Warning {warning_count}/5")
        
        # Check if should quarantine
        if self.warning_system.should_quarantine(threat_id):
            await self.automatic_quarantine(threat_id, threat_info)
        else:
            # Log that user has time to respond
            remaining = 5 - warning_count
            logger.info(f"{remaining} more warnings before automatic quarantine of {target}")
    
    async def automatic_quarantine(self, threat_id: str, threat_info: Dict):
        """Automatically quarantine threat after 5 warnings"""
        target = threat_info.get("target", "Unknown")
        target_type = threat_info.get("target_type", "unknown")
        
        logger.critical(f"🚨 AUTOMATIC QUARANTINE INITIATED: {target}")
        
        # Send final notification
        self.send_desktop_notification(
            "🚨 AUTOMATIC QUARANTINE",
            f"""
Maximum warnings reached!
Automatically quarantining: {target}

Action: Blocking and isolating threat
Status: In progress...
            """.strip(),
            "critical"
        )
        
        # Execute quarantine based on type
        success = False
        actions_taken = []
        
        if target_type == "ip":
            success = await self.block_ip(target)
            if success:
                actions_taken.append(f"Blocked IP: {target}")
                self.stats["ips_blocked"] += 1
        
        elif target_type == "domain":
            success = await self.block_domain(target)
            if success:
                actions_taken.append(f"Blocked domain: {target}")
                self.stats["domains_blocked"] += 1
        
        elif target_type == "url":
            # Extract domain from URL
            try:
                from urllib.parse import urlparse
                domain = urlparse(target).netloc
                success = await self.block_domain(domain)
                if success:
                    actions_taken.append(f"Blocked domain from URL: {domain}")
                    self.stats["domains_blocked"] += 1
            except:
                pass
        
        elif target_type == "file":
            success = await self.quarantine_file(target)
            if success:
                actions_taken.append(f"Quarantined file: {target}")
                self.stats["files_quarantined"] += 1
        
        # Report to server
        await self.report_defense_action({
            "threat_id": threat_id,
            "target": target,
            "action": "quarantine",
            "success": success,
            "details": actions_taken
        })
        
        # Reset warnings
        self.warning_system.reset_warnings(threat_id)
        
        if threat_id in self.active_threats:
            del self.active_threats[threat_id]
        
        self.stats["attacks_blocked"] += 1
        
        # Send completion notification
        status_msg = "✅ SUCCESS" if success else "⚠️  PARTIAL"
        self.send_desktop_notification(
            f"{status_msg} - Quarantine Complete",
            f"""
Threat neutralized: {target}

Actions taken:
{chr(10).join('• ' + action for action in actions_taken) if actions_taken else '• Threat logged'}

Your system is now protected.
            """.strip(),
            "normal"
        )
        
        logger.info(f"Quarantine completed for {target}: {status_msg}")
    
    async def block_ip(self, ip_address: str) -> bool:
        """Block an IP address using firewall"""
        try:
            system = platform.system()
            
            if system == "Linux":
                # Use iptables
                cmd = f"sudo iptables -A INPUT -s {ip_address} -j DROP"
                subprocess.run(cmd, shell=True, check=True)
            elif system == "Windows":
                # Use Windows Firewall
                cmd = f'netsh advfirewall firewall add rule name="SentinelAI Block {ip_address}" dir=in action=block remoteip={ip_address}'
                subprocess.run(cmd, shell=True, check=True)
            elif system == "Darwin":  # macOS
                # Use pf firewall
                cmd = f"echo 'block drop from {ip_address} to any' | sudo pfctl -ef -"
                subprocess.run(cmd, shell=True, check=True)
            
            self.blocked_ips.add(ip_address)
            logger.info(f"✅ Blocked IP: {ip_address}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to block IP {ip_address}: {e}")
            return False
    
    async def block_domain(self, domain: str) -> bool:
        """Block a domain by adding to hosts file"""
        try:
            system = platform.system()
            
            # Determine hosts file location
            if system == "Windows":
                hosts_file = Path("C:/Windows/System32/drivers/etc/hosts")
            else:  # Linux/macOS
                hosts_file = Path("/etc/hosts")
            
            # Add entry to hosts file
            entry = f"127.0.0.1    {domain}  # SentinelAI block\n"
            
            if system == "Windows":
                # Windows requires admin
                cmd = f'echo {entry} >> {hosts_file}'
                subprocess.run(cmd, shell=True)
            else:
                # Linux/macOS
                cmd = f'echo "{entry}" | sudo tee -a {hosts_file}'
                subprocess.run(cmd, shell=True)
            
            self.blocked_domains.add(domain)
            logger.info(f"✅ Blocked domain: {domain}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to block domain {domain}: {e}")
            return False
    
    async def quarantine_file(self, file_path: str) -> bool:
        """Quarantine a suspicious file"""
        try:
            import shutil
            source = Path(file_path)
            
            if not source.exists():
                logger.warning(f"File not found for quarantine: {file_path}")
                return False
            
            # Create quarantine directory
            quarantine_dir = Path.home() / ".sentinel_quarantine"
            quarantine_dir.mkdir(exist_ok=True)
            
            # Move file to quarantine
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            dest = quarantine_dir / f"{timestamp}_{source.name}"
            shutil.move(str(source), str(dest))
            
            self.quarantined_files.append(str(dest))
            logger.info(f"✅ Quarantined file: {file_path} -> {dest}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to quarantine file {file_path}: {e}")
            return False
    
    async def report_defense_action(self, action_info: Dict):
        """Report defense action to server"""
        try:
            endpoint = f"{self.server_url}/api/v1/network/defense/action"
            
            payload = {
                "action_type": action_info.get("action", "block"),
                "target": action_info.get("target"),
                "client_id": self.client_id,
                "details": {
                    "threat_id": action_info.get("threat_id"),
                    "success": action_info.get("success"),
                    "actions_taken": action_info.get("details", []),
                    "timestamp": datetime.now().isoformat()
                }
            }
            
            response = requests.post(
                endpoint,
                json=payload,
                headers=self._get_headers(),
                timeout=10
            )
            
            if response.status_code == 200:
                logger.info("Defense action reported to server")
            else:
                logger.warning(f"Failed to report action: {response.status_code}")
                
        except Exception as e:
            logger.error(f"Failed to report defense action: {e}")
    
    async def monitor_network_connections(self):
        """Monitor network connections for suspicious activity"""
        logger.info("🔍 Starting network connection monitoring...")
        
        while self.running:
            try:
                connections = psutil.net_connections(kind='inet')
                
                for conn in connections:
                    if conn.status == 'ESTABLISHED' and conn.raddr:
                        remote_ip = conn.raddr.ip
                        
                        # Skip local/private IPs
                        if remote_ip.startswith(('127.', '10.', '192.168.', '172.')):
                            continue
                        
                        # Check if already blocked
                        if remote_ip in self.blocked_ips:
                            continue
                        
                        # Scan the IP
                        result = await self.scan_target(remote_ip, "ip")
                        
                        if result.get("threat_level") in ["suspicious", "malicious"]:
                            await self.handle_threat_detected(result)
                
                await asyncio.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                logger.error(f"Network monitoring error: {e}")
                await asyncio.sleep(60)
    
    async def monitor_file_system(self, watch_dirs: List[str] = None):
        """Monitor file system for malicious files"""
        if not watch_dirs:
            # Default to Downloads and Desktop
            watch_dirs = [
                str(Path.home() / "Downloads"),
                str(Path.home() / "Desktop")
            ]
        
        logger.info(f"📁 Monitoring directories: {watch_dirs}")
        
        # Simple polling-based monitoring
        known_files = set()
        
        while self.running:
            try:
                for watch_dir in watch_dirs:
                    dir_path = Path(watch_dir)
                    if not dir_path.exists():
                        continue
                    
                    for file_path in dir_path.iterdir():
                        if file_path.is_file() and str(file_path) not in known_files:
                            known_files.add(str(file_path))
                            
                            # Scan new file
                            logger.info(f"New file detected: {file_path.name}")
                            result = await self.scan_target(str(file_path), "file")
                            
                            if result.get("threat_level") in ["suspicious", "malicious"]:
                                await self.handle_threat_detected(result)
                
                await asyncio.sleep(10)  # Check every 10 seconds
                
            except Exception as e:
                logger.error(f"File monitoring error: {e}")
                await asyncio.sleep(30)
    
    async def periodic_system_scan(self):
        """Perform periodic full system scan"""
        logger.info("🔄 Starting periodic system scans...")
        
        while self.running:
            try:
                logger.info("Running periodic security scan...")
                
                # Get active processes
                suspicious_processes = []
                for proc in psutil.process_iter(['pid', 'name', 'exe']):
                    try:
                        # Check for known suspicious patterns
                        name = proc.info['name'].lower() if proc.info['name'] else ""
                        if any(pattern in name for pattern in ['miner', 'trojan', 'malware', 'backdoor']):
                            suspicious_processes.append(proc.info)
                    except:
                        pass
                
                if suspicious_processes:
                    logger.warning(f"Found {len(suspicious_processes)} suspicious processes")
                    for proc in suspicious_processes:
                        self.send_desktop_notification(
                            "⚠️  Suspicious Process",
                            f"Process: {proc['name']}\nPID: {proc['pid']}",
                            "high"
                        )
                
                # Wait 5 minutes before next scan
                await asyncio.sleep(300)
                
            except Exception as e:
                logger.error(f"Periodic scan error: {e}")
                await asyncio.sleep(300)
    
    async def start_real_time_protection(self):
        """Start all real-time protection modules"""
        self.running = True
        
        logger.info("="*60)
        logger.info("🛡️  SENTINEL-AI REAL-TIME PROTECTION STARTED")
        logger.info("="*60)
        logger.info(f"Client ID: {self.client_id}")
        logger.info(f"Server: {self.server_url}")
        logger.info(f"Warning System: 5 warnings before auto-quarantine")
        logger.info("="*60)
        
        # Send startup notification
        self.send_desktop_notification(
            "🛡️  SentinelAI Protection Active",
            f"Real-time threat detection enabled\nClient: {self.client_id}",
            "normal"
        )
        
        # Start all monitoring tasks
        tasks = [
            asyncio.create_task(self.monitor_network_connections()),
            asyncio.create_task(self.monitor_file_system()),
            asyncio.create_task(self.periodic_system_scan()),
        ]
        
        try:
            await asyncio.gather(*tasks)
        except KeyboardInterrupt:
            logger.info("Shutdown requested...")
            self.running = False
            await self.shutdown()
    
    async def shutdown(self):
        """Graceful shutdown"""
        logger.info("Shutting down SentinelAI Real-Time Protection...")
        
        # Display final statistics
        logger.info("="*60)
        logger.info("📊 PROTECTION STATISTICS")
        logger.info("="*60)
        for key, value in self.stats.items():
            logger.info(f"{key.replace('_', ' ').title()}: {value}")
        logger.info("="*60)
        
        self.send_desktop_notification(
            "🛡️  SentinelAI Protection Stopped",
            f"Attacks Detected: {self.stats['attacks_detected']}\nAttacks Blocked: {self.stats['attacks_blocked']}",
            "normal"
        )


async def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="SentinelAI Real-Time Protection")
    parser.add_argument("--server", default="http://localhost:8000", help="Server URL")
    parser.add_argument("--api-key", help="API Key (optional)")
    args = parser.parse_args()
    
    system = RealTimeDefenseSystem(args.server, args.api_key)
    await system.start_real_time_protection()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\nShutdown requested by user.")
