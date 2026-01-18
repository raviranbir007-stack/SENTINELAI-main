"""
Prevention System - Proactively blocks threats and warns users
Implements real-time blocking and warning mechanisms
"""

import logging
import os
import platform
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set, Optional

logger = logging.getLogger("PreventionSystem")


class PreventionSystem:
    """
    Proactive prevention system that:
    - Blocks access to malicious websites
    - Prevents execution of malicious files
    - Warns about risky activities
    - Enforces security policies
    """

    def __init__(self, callback=None):
        self.callback = callback
        self.running = False
        
        # Blocked entities
        self.blocked_domains = set()
        self.blocked_ips = set()
        self.blocked_files = set()
        self.blocked_apps = set()
        
        # Warning lists
        self.warned_domains = set()
        self.warned_ips = set()
        
        # System files
        self.hosts_file = self._get_hosts_file()
        self.hosts_backup = Path("/tmp/hosts.backup") if platform.system() != "Windows" else Path("C:\\hosts.backup")
        
        # Firewall rules
        self.firewall_rules = []
        
        # Load existing blocks
        self._load_blocked_entities()

    def start(self):
        """Start the prevention system"""
        if not self.running:
            self.running = True
            
            # Backup hosts file
            self._backup_hosts_file()
            
            logger.info("🛡️  Prevention System started")

    def stop(self):
        """Stop the prevention system"""
        self.running = False
        logger.info("Prevention System stopped")

    def block_domain(self, domain: str, reason: str = "Malicious"):
        """Block a domain by adding it to hosts file"""
        if domain in self.blocked_domains:
            logger.debug(f"Domain already blocked: {domain}")
            return
        
        try:
            self.blocked_domains.add(domain)
            
            # Add to hosts file
            self._add_to_hosts(domain)
            
            logger.warning(f"🚫 Blocked domain: {domain} (Reason: {reason})")
            
            # Notify
            if self.callback:
                self.callback({
                    'event': 'DOMAIN_BLOCKED',
                    'domain': domain,
                    'reason': reason,
                    'timestamp': datetime.now().isoformat()
                })
                
            # Save blocked entities
            self._save_blocked_entities()
            
        except Exception as e:
            logger.error(f"Failed to block domain {domain}: {e}")

    def block_ip(self, ip_address: str, reason: str = "Malicious"):
        """Block an IP address using firewall"""
        if ip_address in self.blocked_ips:
            logger.debug(f"IP already blocked: {ip_address}")
            return
        
        try:
            self.blocked_ips.add(ip_address)
            
            # Add firewall rule
            self._add_firewall_rule(ip_address)
            
            logger.warning(f"🚫 Blocked IP: {ip_address} (Reason: {reason})")
            
            # Notify
            if self.callback:
                self.callback({
                    'event': 'IP_BLOCKED',
                    'ip_address': ip_address,
                    'reason': reason,
                    'timestamp': datetime.now().isoformat()
                })
                
            # Save blocked entities
            self._save_blocked_entities()
            
        except Exception as e:
            logger.error(f"Failed to block IP {ip_address}: {e}")

    def block_file(self, file_path: str, reason: str = "Malware"):
        """Block/quarantine a file"""
        if file_path in self.blocked_files:
            logger.debug(f"File already blocked: {file_path}")
            return
        
        try:
            self.blocked_files.add(file_path)
            
            # Quarantine the file
            self._quarantine_file(file_path)
            
            logger.warning(f"🚫 Blocked file: {file_path} (Reason: {reason})")
            
            # Notify
            if self.callback:
                self.callback({
                    'event': 'FILE_BLOCKED',
                    'file_path': file_path,
                    'reason': reason,
                    'timestamp': datetime.now().isoformat()
                })
                
            # Save blocked entities
            self._save_blocked_entities()
            
        except Exception as e:
            logger.error(f"Failed to block file {file_path}: {e}")

    def block_application(self, app_name: str, reason: str = "Malicious"):
        """Block an application from running"""
        if app_name in self.blocked_apps:
            logger.debug(f"Application already blocked: {app_name}")
            return
        
        try:
            self.blocked_apps.add(app_name)
            
            # Kill running instances
            self._kill_application(app_name)
            
            logger.warning(f"🚫 Blocked application: {app_name} (Reason: {reason})")
            
            # Notify
            if self.callback:
                self.callback({
                    'event': 'APP_BLOCKED',
                    'app_name': app_name,
                    'reason': reason,
                    'timestamp': datetime.now().isoformat()
                })
                
            # Save blocked entities
            self._save_blocked_entities()
            
        except Exception as e:
            logger.error(f"Failed to block application {app_name}: {e}")

    def warn_user(self, warning_type: str, target: str, details: Dict) -> bool:
        """
        Show warning to user and get their decision
        Returns True if user wants to proceed, False if user wants to block
        """
        warning_message = self._generate_warning_message(warning_type, target, details)
        
        # Display warning
        print("\n" + "="*70)
        print(warning_message)
        print("="*70)
        
        # Desktop notification
        self._show_desktop_warning(warning_type, target, details)
        
        # Log warning
        logger.warning(f"⚠️  Warning shown: {warning_type} - {target}")
        
        # In production, this would wait for user input
        # For now, auto-block critical threats
        if details.get('risk_level') == 'CRITICAL':
            logger.warning("Critical threat detected - auto-blocking")
            return False  # Block
        
        # Callback for user decision (could be web interface, GUI, etc.)
        if self.callback:
            self.callback({
                'event': 'USER_WARNING',
                'warning_type': warning_type,
                'target': target,
                'details': details,
                'timestamp': datetime.now().isoformat()
            })
        
        return True  # Allow by default (in production, wait for user decision)

    def _generate_warning_message(self, warning_type: str, target: str, details: Dict) -> str:
        """Generate warning message for user"""
        risk_level = details.get('risk_level', 'UNKNOWN')
        risk_score = details.get('risk_score', 0)
        threats = details.get('threats_detected', [])
        
        icon = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '🟢',
            'UNKNOWN': '⚪'
        }.get(risk_level, '⚪')
        
        message = f"""
{icon} SECURITY WARNING - {risk_level} RISK {icon}

Type: {warning_type}
Target: {target}
Risk Score: {risk_score}/100

Threats Detected:
"""
        
        if threats:
            for threat in threats:
                message += f"  • {threat}\n"
        else:
            message += "  • No specific threats identified\n"
        
        message += f"""
Recommendations:
"""
        recommendations = details.get('recommendations', ['Exercise caution'])
        for rec in recommendations:
            message += f"  • {rec}\n"
        
        return message

    def _show_desktop_warning(self, warning_type: str, target: str, details: Dict):
        """Show desktop notification warning"""
        try:
            risk_level = details.get('risk_level', 'UNKNOWN')
            title = f"⚠️  {risk_level} RISK DETECTED"
            body = f"{warning_type}: {target}"
            
            system = platform.system()
            
            if system == "Linux":
                subprocess.run([
                    'notify-send',
                    '-u', 'critical',
                    '-t', '10000',
                    title,
                    body
                ], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            elif system == "Darwin":
                subprocess.run([
                    'osascript', '-e',
                    f'display notification "{body}" with title "{title}"'
                ], check=False)
            elif system == "Windows":
                # Use PowerShell notification
                pass
                
        except Exception as e:
            logger.debug(f"Desktop warning failed: {e}")

    def _get_hosts_file(self) -> Path:
        """Get path to system hosts file"""
        system = platform.system()
        
        if system == "Windows":
            return Path("C:\\Windows\\System32\\drivers\\etc\\hosts")
        else:  # Linux, macOS
            return Path("/etc/hosts")

    def _backup_hosts_file(self):
        """Backup hosts file"""
        try:
            if not self.hosts_backup.exists():
                import shutil
                shutil.copy2(self.hosts_file, self.hosts_backup)
                logger.info("Hosts file backed up")
        except Exception as e:
            logger.error(f"Failed to backup hosts file: {e}")

    def _add_to_hosts(self, domain: str):
        """Add domain to hosts file to block it"""
        try:
            # Read current hosts file
            with open(self.hosts_file, 'r') as f:
                lines = f.readlines()
            
            # Check if already exists
            sentinel_marker = "# SentinelAI Blocked Domains"
            has_marker = any(sentinel_marker in line for line in lines)
            
            # Add entry
            block_entry = f"127.0.0.1 {domain}\n"
            
            # Append to file
            with open(self.hosts_file, 'a') as f:
                if not has_marker:
                    f.write(f"\n{sentinel_marker}\n")
                if block_entry not in ''.join(lines):
                    f.write(block_entry)
            
            logger.debug(f"Added {domain} to hosts file")
            
        except PermissionError:
            logger.error("Permission denied to modify hosts file. Run with sudo/admin privileges.")
        except Exception as e:
            logger.error(f"Failed to add to hosts file: {e}")

    def _add_firewall_rule(self, ip_address: str):
        """Add firewall rule to block IP"""
        try:
            system = platform.system()
            
            if system == "Linux":
                # Use iptables
                subprocess.run([
                    'sudo', 'iptables', '-A', 'INPUT',
                    '-s', ip_address, '-j', 'DROP'
                ], check=True)
                
                subprocess.run([
                    'sudo', 'iptables', '-A', 'OUTPUT',
                    '-d', ip_address, '-j', 'DROP'
                ], check=True)
                
                logger.debug(f"Added iptables rule for {ip_address}")
                
            elif system == "Darwin":  # macOS
                # Use pf
                subprocess.run([
                    'sudo', 'pfctl', '-t', 'blocklist',
                    '-T', 'add', ip_address
                ], check=True)
                
                logger.debug(f"Added pf rule for {ip_address}")
                
            elif system == "Windows":
                # Use Windows Firewall
                subprocess.run([
                    'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                    f'name=SentinelAI_Block_{ip_address}',
                    'dir=in', 'action=block',
                    f'remoteip={ip_address}'
                ], check=True)
                
                subprocess.run([
                    'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                    f'name=SentinelAI_Block_{ip_address}_Out',
                    'dir=out', 'action=block',
                    f'remoteip={ip_address}'
                ], check=True)
                
                logger.debug(f"Added Windows Firewall rule for {ip_address}")
                
            self.firewall_rules.append(ip_address)
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to add firewall rule: {e}")
        except Exception as e:
            logger.error(f"Error adding firewall rule: {e}")

    def _quarantine_file(self, file_path: str):
        """Quarantine a malicious file"""
        try:
            file_path = Path(file_path)
            
            if not file_path.exists():
                logger.warning(f"File does not exist: {file_path}")
                return
            
            # Create quarantine directory
            quarantine_dir = Path.home() / ".sentinelai_quarantine"
            quarantine_dir.mkdir(exist_ok=True)
            
            # Move file to quarantine
            import shutil
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            quarantine_path = quarantine_dir / f"{timestamp}_{file_path.name}"
            
            shutil.move(str(file_path), str(quarantine_path))
            
            # Remove execute permissions
            os.chmod(quarantine_path, 0o000)
            
            logger.info(f"File quarantined: {file_path} -> {quarantine_path}")
            
        except Exception as e:
            logger.error(f"Failed to quarantine file: {e}")

    def _kill_application(self, app_name: str):
        """Kill running instances of an application"""
        try:
            import psutil
            
            killed_count = 0
            
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    if proc.info['name'].lower() == app_name.lower():
                        proc.kill()
                        killed_count += 1
                        logger.info(f"Killed process: {app_name} (PID: {proc.info['pid']})")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            if killed_count > 0:
                logger.info(f"Killed {killed_count} instances of {app_name}")
            
        except Exception as e:
            logger.error(f"Failed to kill application: {e}")

    def _load_blocked_entities(self):
        """Load previously blocked entities"""
        try:
            blocked_file = Path.home() / ".sentinelai_blocked.json"
            
            if blocked_file.exists():
                import json
                with open(blocked_file, 'r') as f:
                    data = json.load(f)
                    
                self.blocked_domains = set(data.get('domains', []))
                self.blocked_ips = set(data.get('ips', []))
                self.blocked_files = set(data.get('files', []))
                self.blocked_apps = set(data.get('apps', []))
                
                logger.info(f"Loaded {len(self.blocked_domains)} blocked domains, "
                          f"{len(self.blocked_ips)} blocked IPs")
                
        except Exception as e:
            logger.error(f"Failed to load blocked entities: {e}")

    def _save_blocked_entities(self):
        """Save blocked entities to file"""
        try:
            blocked_file = Path.home() / ".sentinelai_blocked.json"
            
            import json
            data = {
                'domains': list(self.blocked_domains),
                'ips': list(self.blocked_ips),
                'files': list(self.blocked_files),
                'apps': list(self.blocked_apps),
                'last_updated': datetime.now().isoformat()
            }
            
            with open(blocked_file, 'w') as f:
                json.dump(data, f, indent=2)
                
            logger.debug("Blocked entities saved")
            
        except Exception as e:
            logger.error(f"Failed to save blocked entities: {e}")

    def unblock_domain(self, domain: str):
        """Unblock a domain"""
        if domain not in self.blocked_domains:
            return
        
        try:
            self.blocked_domains.remove(domain)
            
            # Remove from hosts file
            self._remove_from_hosts(domain)
            
            logger.info(f"✅ Unblocked domain: {domain}")
            
            # Save
            self._save_blocked_entities()
            
        except Exception as e:
            logger.error(f"Failed to unblock domain: {e}")

    def unblock_ip(self, ip_address: str):
        """Unblock an IP address"""
        if ip_address not in self.blocked_ips:
            return
        
        try:
            self.blocked_ips.remove(ip_address)
            
            # Remove firewall rule
            self._remove_firewall_rule(ip_address)
            
            logger.info(f"✅ Unblocked IP: {ip_address}")
            
            # Save
            self._save_blocked_entities()
            
        except Exception as e:
            logger.error(f"Failed to unblock IP: {e}")

    def _remove_from_hosts(self, domain: str):
        """Remove domain from hosts file"""
        try:
            with open(self.hosts_file, 'r') as f:
                lines = f.readlines()
            
            # Filter out the domain
            filtered_lines = [line for line in lines if domain not in line]
            
            with open(self.hosts_file, 'w') as f:
                f.writelines(filtered_lines)
                
        except Exception as e:
            logger.error(f"Failed to remove from hosts file: {e}")

    def _remove_firewall_rule(self, ip_address: str):
        """Remove firewall rule"""
        try:
            system = platform.system()
            
            if system == "Linux":
                subprocess.run([
                    'sudo', 'iptables', '-D', 'INPUT',
                    '-s', ip_address, '-j', 'DROP'
                ], check=False)
                
                subprocess.run([
                    'sudo', 'iptables', '-D', 'OUTPUT',
                    '-d', ip_address, '-j', 'DROP'
                ], check=False)
                
            elif system == "Darwin":
                subprocess.run([
                    'sudo', 'pfctl', '-t', 'blocklist',
                    '-T', 'delete', ip_address
                ], check=False)
                
            elif system == "Windows":
                subprocess.run([
                    'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                    f'name=SentinelAI_Block_{ip_address}'
                ], check=False)
                
        except Exception as e:
            logger.error(f"Failed to remove firewall rule: {e}")

    def get_statistics(self) -> Dict:
        """Get prevention statistics"""
        return {
            'blocked_domains': len(self.blocked_domains),
            'blocked_ips': len(self.blocked_ips),
            'blocked_files': len(self.blocked_files),
            'blocked_apps': len(self.blocked_apps),
            'firewall_rules': len(self.firewall_rules)
        }
