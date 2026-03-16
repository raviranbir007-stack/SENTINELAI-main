"""
Prevention System - Proactively blocks threats and warns users
Implements real-time blocking and warning mechanisms
"""

import logging
import os
import platform
import shutil
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
        
        # Whitelisted IPs (same as intrusion detector)
        self.WHITELISTED_IPS = self._load_ip_whitelist()
        
        # System files
        self.hosts_file = self._get_hosts_file()
        self.hosts_backup = Path("/tmp/hosts.backup") if platform.system() != "Windows" else Path("C:\\hosts.backup")
        self.quarantine_dir = Path.home() / ".sentinelai_quarantine"
        self.quarantine_index = self.quarantine_dir / "quarantine_index.json"
        
        # Firewall rules
        self.firewall_rules = []
        
        # Load existing blocks
        self._load_blocked_entities()

    def _load_ip_whitelist(self) -> set:
        """Load whitelist of IPs that should never be blocked"""
        return {
            '127.0.0.1',
            '::1',
            '0.0.0.0',
            'localhost'
        }
    
    def _is_whitelisted_ip(self, ip: str) -> bool:
        """Check if IP should never be blocked"""
        if not ip:
            return False
            
        if ip in self.WHITELISTED_IPS:
            return True
        
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            
            # Never block private, loopback, or link-local
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                return True

            # Never block reserved/documentation/special-use IPs
            # (RFC 5737 TEST-NETs: 192.0.2.x, 198.51.100.x, 203.0.113.x, etc.)
            if (
                getattr(ip_obj, 'is_reserved', False)
                or getattr(ip_obj, 'is_unspecified', False)
                or getattr(ip_obj, 'is_multicast', False)
            ):
                return True

            # Never block legitimate CDN/services
            legitimate_ranges = [
                '142.250.0.0/15',  # Google
                '172.217.0.0/16',  # Google
                '34.64.0.0/10',    # Google Cloud
                '104.16.0.0/13',   # Cloudflare
                '151.101.0.0/16',  # Fastly CDN
            ]
            
            for range_str in legitimate_ranges:
                try:
                    network = ipaddress.ip_network(range_str)
                    if ip_obj in network:
                        return True
                except ValueError:
                    continue
                    
        except (ValueError, AttributeError):
            pass
        
        return False

    def start(self):
        """Start the prevention system"""
        if not self.running:
            self.running = True
            
            # Backup hosts file
            self._backup_hosts_file()
            
            logger.debug("Protection shield started")

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
        # Skip whitelisted IPs
        if self._is_whitelisted_ip(ip_address):
            logger.info(f"Skipping block for whitelisted IP: {ip_address}")
            return
            
        if ip_address in self.blocked_ips:
            logger.debug(f"IP already blocked: {ip_address}")
            return
        
        try:
            self.blocked_ips.add(ip_address)
            
            # Add firewall rule
            self._add_firewall_rule(ip_address)

            # Persist to quarantine index so the dashboard shows this block
            self._record_ip_block_event(ip_address, reason)

            logger.warning(f"🚫 Blocked IP: {ip_address} (Reason: {reason})")
            
            # Notify
            if self.callback:
                self.callback({
                    'event': 'IP_BLOCKED',
                    'ip': ip_address,
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
                    'event': 'FILE_QUARANTINED',
                    'file': file_path,
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
            # Determine if IPv4 or IPv6
            try:
                import ipaddress
                ip_obj = ipaddress.ip_address(ip_address)
                is_ipv6 = ip_obj.version == 6
            except ValueError:
                logger.error(f"Invalid IP address format: {ip_address}")
                return
            
            system = platform.system()
            
            if system == "Linux":
                # Use iptables for IPv4, ip6tables for IPv6
                if is_ipv6:
                    iptables_cmd = 'ip6tables'
                else:
                    iptables_cmd = 'iptables'
                
                # Block incoming
                subprocess.run([
                    'sudo', iptables_cmd, '-A', 'INPUT',
                    '-s', ip_address, '-j', 'DROP'
                ], check=True, capture_output=True, text=True)
                
                # Block outgoing
                subprocess.run([
                    'sudo', iptables_cmd, '-A', 'OUTPUT',
                    '-d', ip_address, '-j', 'DROP'
                ], check=True, capture_output=True, text=True)
                
                logger.debug(f"Added {iptables_cmd} rule for {ip_address}")
                
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

    def harden_firewall(self, profile: str = "default", high_risk_ports: Optional[List[int]] = None) -> Dict:
        """Apply defensive firewall rules with emphasis on Windows malware exposure."""
        system = platform.system()
        high_risk_ports = high_risk_ports or [135, 137, 138, 139, 445, 3389, 5985, 5986]
        results = {
            'system': system,
            'profile': profile,
            'success': True,
            'actions': [],
            'warnings': [],
        }

        try:
            if system == "Linux":
                if shutil.which('ufw'):
                    subprocess.run(['sudo', 'ufw', '--force', 'enable'], check=False, capture_output=True, text=True)
                    subprocess.run(['sudo', 'ufw', 'default', 'deny', 'incoming'], check=False, capture_output=True, text=True)
                    subprocess.run(['sudo', 'ufw', 'default', 'allow', 'outgoing'], check=False, capture_output=True, text=True)
                    results['actions'].append('Enabled ufw with default deny incoming policy')
                    for port in high_risk_ports:
                        for protocol in ('tcp', 'udp'):
                            subprocess.run(
                                ['sudo', 'ufw', 'deny', f'{port}/{protocol}'],
                                check=False,
                                capture_output=True,
                                text=True,
                            )
                    results['actions'].append('Blocked inbound high-risk Windows service ports via ufw')
                elif shutil.which('iptables'):
                    subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-i', 'lo', '-j', 'ACCEPT'], check=False)
                    subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED', '-j', 'ACCEPT'], check=False)
                    for port in high_risk_ports:
                        subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', str(port), '-j', 'DROP'], check=False)
                        subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-p', 'udp', '--dport', str(port), '-j', 'DROP'], check=False)
                    results['actions'].append('Applied iptables drops for high-risk inbound ports')
                else:
                    results['success'] = False
                    results['warnings'].append('No supported Linux firewall tool detected (ufw/iptables)')

            elif system == "Windows":
                subprocess.run(
                    ['netsh', 'advfirewall', 'set', 'allprofiles', 'state', 'on'],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                results['actions'].append('Enabled Windows Firewall on all profiles')
                for port in high_risk_ports:
                    for protocol in ('TCP', 'UDP'):
                        rule_name = f'SentinelAI_Harden_{protocol}_{port}'
                        subprocess.run(
                            [
                                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                                f'name={rule_name}',
                                'dir=in',
                                'action=block',
                                f'protocol={protocol}',
                                f'localport={port}',
                            ],
                            check=False,
                            capture_output=True,
                            text=True,
                        )
                results['actions'].append('Blocked common Windows malware and lateral-movement ports')

            elif system == "Darwin":
                if shutil.which('pfctl'):
                    subprocess.run(['sudo', 'pfctl', '-e'], check=False, capture_output=True, text=True)
                    results['actions'].append('Ensured pf firewall is enabled')
                else:
                    results['success'] = False
                    results['warnings'].append('pfctl not found; unable to harden firewall')

            self.firewall_rules.extend([f'hardening:{system}:{port}' for port in high_risk_ports])
        except Exception as e:
            results['success'] = False
            results['warnings'].append(str(e))
            logger.error(f"Failed to harden firewall: {e}")

        if self.callback:
            self.callback({
                'event': 'FIREWALL_HARDENED',
                'profile': profile,
                'system': system,
                'timestamp': datetime.now().isoformat(),
                'details': results,
            })

        return results

    def _quarantine_file(self, file_path: str):
        """Quarantine a malicious file"""
        try:
            file_path = Path(file_path)
            
            if not file_path.exists():
                logger.warning(f"File does not exist: {file_path}")
                return
            
            # Create quarantine directory
            self.quarantine_dir.mkdir(exist_ok=True)
            
            # Move file to quarantine
            import shutil
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            quarantine_path = self.quarantine_dir / f"{timestamp}_{file_path.name}"

            sha256_hash = None
            try:
                import hashlib
                digest = hashlib.sha256()
                with open(file_path, 'rb') as handle:
                    for chunk in iter(lambda: handle.read(65536), b''):
                        digest.update(chunk)
                sha256_hash = digest.hexdigest()
            except Exception:
                sha256_hash = None
            
            shutil.move(str(file_path), str(quarantine_path))
            
            # Remove execute permissions
            try:
                os.chmod(quarantine_path, 0o000)
            except Exception:
                pass

            self._record_quarantine_event(file_path, quarantine_path, sha256_hash)
            
            logger.info(f"File quarantined: {file_path} -> {quarantine_path}")
            
        except Exception as e:
            logger.error(f"Failed to quarantine file: {e}")

    def _record_quarantine_event(self, original_path: Path, quarantine_path: Path, sha256_hash: Optional[str]):
        """Persist quarantine metadata for audit and manual restoration."""
        try:
            records = []
            if self.quarantine_index.exists():
                import json
                loaded = json.loads(self.quarantine_index.read_text(encoding='utf-8'))
                records = loaded if isinstance(loaded, list) else []

            records.append({
                'timestamp': datetime.now().isoformat(),
                'original_path': str(original_path),
                'quarantine_path': str(quarantine_path),
                'sha256': sha256_hash,
            })

            import json
            self.quarantine_dir.mkdir(parents=True, exist_ok=True)
            tmp = self.quarantine_index.with_suffix('.json.tmp')
            tmp.write_text(json.dumps(records, indent=2), encoding='utf-8')
            tmp.replace(self.quarantine_index)
        except Exception as e:
            logger.error(f"Failed to record quarantine metadata: {e}")

    def _record_ip_block_event(self, ip_address: str, reason: str):
        """Persist a blocked IP to the quarantine index so the dashboard can see it."""
        try:
            import json as _json
            self.quarantine_dir.mkdir(parents=True, exist_ok=True)
            records = []
            if self.quarantine_index.exists():
                try:
                    records = _json.loads(self.quarantine_index.read_text(encoding='utf-8'))
                    if not isinstance(records, list):
                        records = []
                except Exception:
                    records = []
            ts = datetime.now()
            entry = {
                'quarantine_id': f"IPS_{ts.strftime('%Y%m%d%H%M%S')}_{ip_address.replace('.', '_')}",
                'type': 'ip_block',
                'source': 'prevention_system',
                'source_ip': ip_address,
                'reason': reason,
                'timestamp': ts.isoformat(),
                'action': 'ip_blocked',
            }
            # Avoid duplicate within same minute
            already = any(
                r.get('source_ip') == ip_address and
                r.get('type') == 'ip_block' and
                r.get('timestamp', '')[:16] == entry['timestamp'][:16]
                for r in records
            )
            if not already:
                records.append(entry)
                tmp = self.quarantine_index.with_suffix('.json.tmp')
                tmp.write_text(_json.dumps(records, indent=2), encoding='utf-8')
                tmp.replace(self.quarantine_index)
                logger.info(f"IP block recorded in quarantine index: {ip_address}")
        except Exception as e:
            logger.error(f"Failed to record IP block in quarantine index: {e}")

    def get_quarantine_inventory(self) -> List[Dict]:
        """Return quarantined item metadata."""
        try:
            if self.quarantine_index.exists():
                import json
                data = json.loads(self.quarantine_index.read_text(encoding='utf-8'))
                if isinstance(data, list):
                    return data
        except Exception as e:
            logger.error(f"Failed to load quarantine inventory: {e}")
        return []

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
                
                logger.debug(
                    "Loaded blocked entities | domains=%s ips=%s",
                    len(self.blocked_domains),
                    len(self.blocked_ips),
                )
                
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
        quarantine_count = 0
        try:
            if self.quarantine_index.exists():
                import json
                quarantine_count = len(json.loads(self.quarantine_index.read_text(encoding='utf-8')))
        except Exception:
            quarantine_count = 0

        return {
            'blocked_domains': len(self.blocked_domains),
            'blocked_ips': len(self.blocked_ips),
            'blocked_files': len(self.blocked_files),
            'blocked_apps': len(self.blocked_apps),
            'firewall_rules': len(self.firewall_rules),
            'quarantined_items': quarantine_count
        }
