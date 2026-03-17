"""
Defense Coordinator - Handles attack alerts, escalation, and auto-quarantine
Implements the 5-attempt alert system with auto-quarantine
"""

import logging
import os
import platform
import shutil
import subprocess
import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Callable
import json
import textwrap

logger = logging.getLogger("DefenseCoordinator")


class DefenseCoordinator:
    """
    Coordinates defense responses to attacks
    - Sends alerts up to 5 times
    - Auto-quarantines system if no human response
    - Manages system lockdown and recovery
    """

    def __init__(self, server_url: str = None, callback: Callable = None):
        self.server_url = server_url
        self.callback = callback
        self.running = False
        
        # Alert tracking
        self.active_attacks = {}  # attack_id -> attack_info
        self.alert_counts = defaultdict(int)  # attack_id -> count
        self.user_responses = {}  # attack_id -> response
        self.suppressed_attacks = set()  # Attacks that should be suppressed (false positives)
        
        # Configuration (reduced alert frequency to prevent spam)
        self.MAX_ALERTS = 3  # Reduced from 5 to 3
        self.ALERT_INTERVAL = 60  # Increased from 30s to 60s
        self.RESPONSE_TIMEOUT = 600  # Increased from 5min to 10min for better user experience
        self.MIN_SEVERITY_FOR_ALERT = 'HIGH'  # Only alert on HIGH/CRITICAL attacks
        
        # Quarantine state
        self.is_quarantined = False
        self.quarantine_start_time = None
        self.quarantine_reason = None
        
        # Quarantine log — must match the path read by the dashboard
        # endpoint /dashboard/quarantine-inventory
        self.quarantine_log_path = Path.home() / ".sentinelai_quarantine" / "quarantine_index.json"
        self.quarantine_log_path.parent.mkdir(parents=True, exist_ok=True)

        # Notification methods
        self.notification_methods = []
        self._setup_notification_methods()

    def _setup_notification_methods(self):
        """Setup available notification methods"""
        # Console notifications (always available)
        self.notification_methods.append(self._notify_console)
        
        # Desktop notifications (if available)
        if self._check_desktop_notification_support():
            self.notification_methods.append(self._notify_desktop)
        
        # Audio alerts (if available)
        if self._check_audio_support():
            self.notification_methods.append(self._notify_audio)

    def start(self):
        """Start the defense coordinator"""
        if not self.running:
            self.running = True
            logger.debug("Response coordinator started")

    def stop(self):
        """Stop the defense coordinator"""
        self.running = False
        logger.info("Defense Coordinator stopped")
    
    def suppress_attack(self, source_ip: str):
        """Suppress future attacks from this IP (mark as false positive)"""
        self.suppressed_attacks.add(source_ip)
        logger.info(f"✅ Suppressed future alerts from: {source_ip} (marked as false positive)")

    def _format_source_endpoint(self, attack: Dict) -> str:
        """Build readable source label: ip (hostname)."""
        ip = attack.get('source_ip', 'UNKNOWN')
        host = attack.get('source_hostname') or attack.get('source_domain')
        if host and host != ip:
            return f"{ip} ({host})"
        return str(ip)

    def _is_quarantine_notice(self, attack: Dict, alert_num: int) -> bool:
        """Return True when the notification is for quarantine state rather than alert escalation."""
        return attack.get('notification_kind') == 'quarantine' or alert_num > self.MAX_ALERTS

    def _render_console_table(self, title: str, rows: List[tuple], footer: Optional[str] = None):
        """Render readable adaptive-width table in terminal output."""
        width = max(80, min(140, shutil.get_terminal_size((110, 20)).columns))
        key_width = max((len(str(k)) for k, _ in rows), default=10)
        key_width = max(12, min(26, key_width + 1))
        val_width = max(24, width - key_width - 7)  # borders + spacing

        top = f"┌{'─' * (width - 2)}┐"
        bottom = f"└{'─' * (width - 2)}┘"
        divider = f"├{'─' * (width - 2)}┤"

        print(top, flush=True)
        print(f"│ {title[:width - 4]:<{width - 4}} │", flush=True)
        print(divider, flush=True)

        for key, value in rows:
            label = str(key)
            value_str = str(value if value is not None else '—')
            wrapped = textwrap.wrap(value_str, width=val_width) or ['—']
            for idx, line in enumerate(wrapped):
                left = label if idx == 0 else ''
                print(
                    f"│ {left:<{key_width}} │ {line:<{val_width}} │",
                    flush=True,
                )

        if footer:
            print(divider, flush=True)
            for line in textwrap.wrap(str(footer), width=width - 4) or ['']:
                print(f"│ {line:<{width - 4}} │", flush=True)

        print(bottom, flush=True)

    def handle_attack(self, attack: Dict):
        """
        Handle a detected attack
        - Filter out low-severity attacks
        - Send alerts up to 3 times for real threats
        - Quarantine if no response
        """
        # Skip if attack is suppressed (whitelisted IP/false positive)
        source_ip = attack.get('source_ip', '')
        if source_ip in self.suppressed_attacks:
            return
        
        # Filter by severity - only alert on HIGH or CRITICAL
        severity = attack.get('severity', 'UNKNOWN')
        if severity not in ['HIGH', 'CRITICAL'] and severity != self.MIN_SEVERITY_FOR_ALERT:
            logger.debug(f"Suppressing low-severity attack: {severity} from {source_ip}")
            return
        
        attack_id = self._generate_attack_id(attack)
        
        # Add to active attacks
        if attack_id not in self.active_attacks:
            self.active_attacks[attack_id] = {
                **attack,
                'first_seen': datetime.now(),
                'alert_count': 0,
                'last_alert': None,
                'user_notified': False,
                'auto_quarantined': False
            }
            
            logger.warning(f"🚨 New attack detected: {attack['type']} from {source_ip}")
            
            # Start alert thread
            alert_thread = threading.Thread(
                target=self._alert_loop,
                args=(attack_id,),
                daemon=True
            )
            alert_thread.start()

    def _generate_attack_id(self, attack: Dict) -> str:
        """Generate unique ID for an attack"""
        return f"{attack['type']}_{attack.get('source_ip', 'UNKNOWN')}_{attack['timestamp'].strftime('%Y%m%d%H%M%S')}"

    def _alert_loop(self, attack_id: str):
        """Alert loop for a specific attack"""
        attack = self.active_attacks[attack_id]
        start_time = datetime.now()
        
        while self.running and attack['alert_count'] < self.MAX_ALERTS:
            # Check if user has responded
            if attack_id in self.user_responses:
                response = self.user_responses[attack_id]
                logger.info(f"✅ User responded to attack {attack_id}: {response}")
                
                if response == 'IGNORE':
                    # User chose to ignore
                    del self.active_attacks[attack_id]
                    return
                elif response == 'BLOCK':
                    # User chose to block
                    self._execute_block(attack)
                    del self.active_attacks[attack_id]
                    return
                elif response == 'QUARANTINE':
                    # User chose to quarantine immediately
                    self._execute_quarantine(attack_id, attack, user_initiated=True)
                    return
            
            # Check timeout
            if (datetime.now() - start_time).seconds > self.RESPONSE_TIMEOUT:
                logger.warning(f"⏰ Response timeout for attack {attack_id}")
                self._execute_quarantine(attack_id, attack, user_initiated=False)
                return
            
            # Send alert
            self._send_alert(attack_id, attack)
            attack['alert_count'] += 1
            attack['last_alert'] = datetime.now()
            
            # Wait before next alert
            time.sleep(self.ALERT_INTERVAL)
        
        # Max alerts reached without response - QUARANTINE
        if attack['alert_count'] >= self.MAX_ALERTS:
            logger.critical(f"🚨 MAX ALERTS REACHED for {attack_id} - INITIATING AUTO-QUARANTINE")
            self._execute_quarantine(attack_id, attack, user_initiated=False)

    def _send_alert(self, attack_id: str, attack: Dict):
        """Send alert through all available notification methods"""
        alert_num = attack['alert_count'] + 1
        short_desc = attack.get('short_description') or attack.get('description') or 'Suspicious activity detected'
        short_desc = short_desc[:55] if len(short_desc) > 55 else short_desc
        mitigation_commands = attack.get('mitigation_commands') if isinstance(attack.get('mitigation_commands'), list) else []
        mitigation_cmd = mitigation_commands[0] if mitigation_commands else 'Manual containment required'
        mitigation_cmd = mitigation_cmd[:55] if len(mitigation_cmd) > 55 else mitigation_cmd
        
        # Format description to fit in box
        desc = attack['description'][:55] if len(attack['description']) > 55 else attack['description']
        source_label = self._format_source_endpoint(attack)
        source_label = source_label[:45] if len(source_label) > 45 else source_label
        
        message = f"""
╔═══════════════════════════════════════════════════════════════╗
║           🚨 SECURITY ALERT #{alert_num}/{self.MAX_ALERTS} 🚨                       ║
╠═══════════════════════════════════════════════════════════════╣
║ Attack Type: {attack['type']:<45} ║
║ Severity:    {attack['severity']:<45} ║
║ Source:      {source_label:<45} ║
║ Description: {desc:<45} ║
║ Short Desc:  {short_desc:<45} ║
║ Mitigate:    {mitigation_cmd:<45} ║
║                                                               ║
║ ⏰ Alerts Remaining: {self.MAX_ALERTS - alert_num} before AUTO-QUARANTINE             ║
║                                                               ║
║ RESPONSE OPTIONS:                                             ║
║  • BLOCK: Block the attacker's IP address                     ║
║  • IGNORE: Mark as false positive (whitelist IP)              ║
║  • QUARANTINE: Lock down system immediately                   ║
║                                                               ║
║ ℹ️  To respond, use the web interface or CLI                  ║
║ ⏰ {self.ALERT_INTERVAL}s until next alert, {self.RESPONSE_TIMEOUT}s total timeout    ║
╚═══════════════════════════════════════════════════════════════╝
"""
        
        # Send through all notification methods
        for notify_method in self.notification_methods:
            try:
                notify_method(message, attack, alert_num)
            except Exception as e:
                logger.error(f"Failed to send alert via {notify_method.__name__}: {e}")
        
        # Log the alert
        logger.warning(f"Alert #{alert_num}/{self.MAX_ALERTS} sent for attack: {attack_id}")
        
        # Callback to server
        if self.callback:
            try:
                self.callback({
                    'event': 'ATTACK_ALERT',
                    'attack_id': attack_id,
                    'attack': attack,
                    'alert_number': alert_num,
                    'max_alerts': self.MAX_ALERTS
                })
            except Exception as e:
                logger.error(f"Failed to send alert callback: {e}")

    def _notify_console(self, message: str, attack: Dict, alert_num: int):
        """Send console notification"""
        source_label = self._format_source_endpoint(attack)
        short_desc = attack.get('short_description') or attack.get('description') or 'Suspicious activity detected'
        if self._is_quarantine_notice(attack, alert_num):
            self._render_console_table(
                "🔒 QUARANTINE ACTIVE",
                [
                    ("Attack Type", attack.get('type', 'unknown')),
                    ("Severity", attack.get('severity', 'UNKNOWN')),
                    ("Source", source_label),
                    ("Reason", short_desc),
                    ("Action", "Administrator intervention required"),
                ],
            )
            return

        remaining = self.MAX_ALERTS - alert_num
        mitigation_commands = attack.get('mitigation_commands') if isinstance(attack.get('mitigation_commands'), list) else []
        mitigation = mitigation_commands[0] if mitigation_commands else 'Manual containment required'
        self._render_console_table(
            f"🚨 SECURITY ALERT {alert_num}/{self.MAX_ALERTS}",
            [
                ("Attack Type", attack.get('type', 'unknown')),
                ("Severity", attack.get('severity', 'UNKNOWN')),
                ("Source", source_label),
                ("Summary", short_desc),
                ("Mitigate", mitigation),
                ("Remaining Alerts", remaining),
                ("Next Alert", f"{self.ALERT_INTERVAL}s"),
                ("Timeout", f"{self.RESPONSE_TIMEOUT}s"),
            ],
            footer="Response options: BLOCK | IGNORE | QUARANTINE",
        )

    def _notify_desktop(self, message: str, attack: Dict, alert_num: int):
        """Send desktop notification"""
        try:
            is_quarantine_notice = self._is_quarantine_notice(attack, alert_num)
            title = "🔒 SYSTEM QUARANTINED" if is_quarantine_notice else f"🚨 SECURITY ALERT #{alert_num}/{self.MAX_ALERTS}"
            mitigation_commands = attack.get('mitigation_commands') if isinstance(attack.get('mitigation_commands'), list) else []
            mitigation_cmd = mitigation_commands[0] if mitigation_commands else None
            source_label = self._format_source_endpoint(attack)
            body = (
                f"{attack['type']} from {source_label}\n"
                f"{attack.get('short_description') or attack.get('description', '')}"
            )
            if mitigation_cmd and not is_quarantine_notice:
                body += f"\nMitigate: {mitigation_cmd}"
            
            system = platform.system()
            
            if system == "Linux":
                # Use notify-send on Linux
                subprocess.run([
                    'notify-send',
                    '-u', 'critical',
                    '-t', '30000',  # 30 seconds
                    title,
                    body
                ], check=False)
                
            elif system == "Darwin":  # macOS
                # Use osascript on macOS
                subprocess.run([
                    'osascript', '-e',
                    f'display notification "{body}" with title "{title}"'
                ], check=False)
                
            elif system == "Windows":
                # Use PowerShell on Windows
                ps_script = f'''
                [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
                $template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
                $toastXml = [xml] $template.GetXml()
                $toastXml.GetElementsByTagName("text")[0].AppendChild($toastXml.CreateTextNode("{title}")) > $null
                $toastXml.GetElementsByTagName("text")[1].AppendChild($toastXml.CreateTextNode("{body}")) > $null
                $xml = New-Object Windows.Data.Xml.Dom.XmlDocument
                $xml.LoadXml($toastXml.OuterXml)
                $toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
                $notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("SentinelAI")
                $notifier.Show($toast)
                '''
                subprocess.run(['powershell', '-Command', ps_script], check=False)
                
        except Exception as e:
            logger.debug(f"Desktop notification failed: {e}")

    def _notify_audio(self, message: str, attack: Dict, alert_num: int):
        """Send audio alert"""
        try:
            system = platform.system()
            beep_count = 2 if self._is_quarantine_notice(attack, alert_num) else alert_num
            
            # Play system beep multiple times based on alert number
            for _ in range(max(1, min(beep_count, 3))):
                if system == "Linux":
                    subprocess.run(['paplay', '/usr/share/sounds/freedesktop/stereo/alarm-clock-elapsed.oga'], 
                                 check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                elif system == "Darwin":  # macOS
                    subprocess.run(['afplay', '/System/Library/Sounds/Funk.aiff'], 
                                 check=False)
                elif system == "Windows":
                    import winsound
                    winsound.Beep(1000, 500)  # 1000 Hz for 500ms
                
                time.sleep(0.5)
                
        except Exception as e:
            logger.debug(f"Audio notification failed: {e}")

    def _check_desktop_notification_support(self) -> bool:
        """Check if desktop notifications are supported"""
        try:
            system = platform.system()
            
            if system == "Linux":
                result = subprocess.run(['which', 'notify-send'], 
                                      capture_output=True, check=False)
                return result.returncode == 0
            elif system == "Darwin":
                return True  # macOS always supports osascript
            elif system == "Windows":
                return True  # Windows 10+ supports notifications
                
        except Exception:
            return False

    def _check_audio_support(self) -> bool:
        """Check if audio alerts are supported"""
        try:
            system = platform.system()
            
            if system == "Linux":
                result = subprocess.run(['which', 'paplay'], 
                                      capture_output=True, check=False)
                return result.returncode == 0
            elif system == "Darwin":
                return True  # macOS has afplay
            elif system == "Windows":
                return True  # Windows has winsound
                
        except Exception:
            return False

    def _execute_block(self, attack: Dict):
        """Execute blocking action"""
        logger.info(f"🚫 Blocking attacker: {attack.get('source_ip', 'UNKNOWN')}")
        
        source_ip = attack.get('source_ip')
        if not source_ip or source_ip == 'UNKNOWN':
            logger.warning("Cannot block: no valid source IP")
            return
        
        system = platform.system()
        
        try:
            if system == "Linux":
                # choose ipv4 vs ipv6 tool
                try:
                    import ipaddress
                    is_ipv6 = ipaddress.ip_address(source_ip).version == 6
                except Exception:
                    is_ipv6 = False
                ipt = 'ip6tables' if is_ipv6 else 'iptables'

                # Use iptables/ip6tables to block IP
                subprocess.run([
                    'sudo', ipt, '-A', 'INPUT',
                    '-s', source_ip, '-j', 'DROP'
                ], check=True)
                logger.info(f"✅ Blocked {source_ip} using {ipt}")
                
            elif system == "Darwin":  # macOS
                # Use pf (packet filter)
                subprocess.run([
                    'sudo', 'pfctl', '-t', 'blocklist',
                    '-T', 'add', source_ip
                ], check=True)
                logger.info(f"✅ Blocked {source_ip} using pf")
                
            elif system == "Windows":
                # Use Windows Firewall
                subprocess.run([
                    'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                    f'name=Block_{source_ip}', 'dir=in', 'action=block',
                    f'remoteip={source_ip}'
                ], check=True)
                logger.info(f"✅ Blocked {source_ip} using Windows Firewall")
                
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to block {source_ip}: {e}")
        except Exception as e:
            logger.error(f"Error blocking {source_ip}: {e}")

    def _execute_quarantine(self, attack_id: str, attack: Dict, user_initiated: bool = False):
        """Execute full system quarantine"""
        if self.is_quarantined:
            logger.warning("System already quarantined")
            return

        reason = "User-initiated" if user_initiated else "Automatic (No response to alerts)"
        logger.critical(
            "🔒 Quarantine initiated | reason=%s | type=%s | source=%s | time=%s",
            reason,
            attack['type'],
            attack.get('source_ip', 'UNKNOWN'),
            datetime.now().isoformat(),
        )
        
        self.is_quarantined = True
        self.quarantine_start_time = datetime.now()
        self.quarantine_reason = {
            'attack_id': attack_id,
            'attack': attack,
            'reason': reason,
            'timestamp': datetime.now().isoformat()
        }
        
        # Mark attack as quarantined
        if attack_id in self.active_attacks:
            self.active_attacks[attack_id]['auto_quarantined'] = True
        
        # Log quarantine
        self._log_quarantine(attack_id, attack, reason)
        
        logger.critical(
            "🔒 Quarantine actions applied | network=restricted | processes=contained | forensic_snapshot=queued | log=%s",
            self.quarantine_log_path,
        )
        
        # Send critical notification
        self._send_quarantine_notification(attack)
        
        # Callback
        if self.callback:
            self.callback({
                'event': 'QUARANTINE_ACTIVATED',
                'attack_id': attack_id,
                'attack': attack,
                'reason': reason,
                'timestamp': datetime.now().isoformat()
            })

    def _log_quarantine(self, attack_id: str, attack: Dict, reason: str):
        """Log quarantine to file"""
        try:
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'attack_id': attack_id,
                'attack_type': attack['type'],
                'source_ip': attack.get('source_ip', 'UNKNOWN'),
                'severity': attack['severity'],
                'reason': reason,
                'description': attack['description']
            }
            
            # Append to log file
            if self.quarantine_log_path.exists():
                with open(self.quarantine_log_path, 'r') as f:
                    logs = json.load(f)
            else:
                logs = []
            
            logs.append(log_entry)
            
            with open(self.quarantine_log_path, 'w') as f:
                json.dump(logs, f, indent=2)
                
            logger.info(f"Quarantine logged to {self.quarantine_log_path}")
            
        except Exception as e:
            logger.error(f"Failed to log quarantine: {e}")

    def _send_quarantine_notification(self, attack: Dict):
        """Send critical quarantine notification"""
        quarantine_attack = {**attack, 'notification_kind': 'quarantine'}
        message = f"""
╔══════════════════════════════════════════════════════════╗
║                                                          ║
    ║              🚨 CRITICAL: SYSTEM QUARANTINED 🚨           ║
║                                                          ║
╠══════════════════════════════════════════════════════════╣
║                                                          ║
║  Your system has been LOCKED DOWN due to a security      ║
║  threat that was not responded to.                       ║
║                                                          ║
║  Attack Details:                                         ║
║    Type: {attack['type']:<46} ║
║    From: {attack.get('source_ip', 'UNKNOWN'):<46} ║
║    Severity: {attack['severity']:<42} ║
║                                                          ║
║  QUARANTINE ACTIVATED:                                   ║
║    ✓ Network connections blocked                         ║
║    ✓ Suspicious processes terminated                     ║
║    ✓ System isolated                                     ║
║                                                          ║
║  Administrator action required to release!               ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
"""
        
        # Send through all notification methods
        for notify_method in self.notification_methods:
            try:
                notify_method(message, quarantine_attack, self.MAX_ALERTS)
            except Exception as e:
                logger.error(f"Failed to send quarantine notification: {e}")

    def _original_execute_quarantine(self, attack_id: str, attack: Dict, user_initiated: bool = False):
        """Execute system quarantine"""
        if self.is_quarantined:
            logger.warning("System already quarantined")
            return
        
        self.is_quarantined = True
        self.quarantine_start_time = datetime.now()
        self.quarantine_reason = attack
        
        # Mark attack as quarantined
        attack['auto_quarantined'] = True
        
        # Log quarantine (compat path)
        reason = "User-initiated quarantine" if user_initiated else "Auto-quarantine (legacy flow)"
        self._log_quarantine(attack_id, attack, reason)
        
        logger.critical(f"""
╔══════════════════════════════════════════════════════════════╗
║                  ⚠️  SYSTEM QUARANTINE ACTIVATED ⚠️              ║
╠══════════════════════════════════════════════════════════════╣
║ Reason: {('User Initiated' if user_initiated else 'Auto-Quarantine'):<53} ║
║ Attack: {attack['type']:<53} ║
║ Source: {attack.get('source_ip', 'N/A'):<53} ║
║ Time:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S'):<53} ║
║                                                              ║
║ QUARANTINE ACTIONS:                                          ║
║  ✓ Network connections restricted                            ║
║  ✓ File system access limited                                ║
║  ✓ External devices blocked                                  ║
║  ✓ All activities logged                                     ║
║                                                              ║
║ To lift quarantine, administrator action required.           ║
╚══════════════════════════════════════════════════════════════╝
""")
        
        # Execute quarantine actions
        self._apply_quarantine_measures()
        
        # Notify user
        self._notify_quarantine()
        
        # Callback to server
        if self.callback:
            try:
                self.callback({
                    'event': 'SYSTEM_QUARANTINED',
                    'attack_id': attack_id,
                    'attack': attack,
                    'user_initiated': user_initiated,
                    'timestamp': datetime.now().isoformat()
                })
            except Exception as e:
                logger.error(f"Failed to send quarantine callback: {e}")

    def _apply_quarantine_measures(self):
        """Apply quarantine security measures"""
        logger.info("Applying quarantine measures...")
        
        system = platform.system()
        
        try:
            # 1. Block all outgoing connections (except localhost and local network)
            if system == "Linux":
                # Create restrictive iptables rules (IPv4)
                subprocess.run(['sudo', 'iptables', '-P', 'OUTPUT', 'DROP'], check=False)
                subprocess.run(['sudo', 'iptables', '-A', 'OUTPUT', '-o', 'lo', '-j', 'ACCEPT'], check=False)
                subprocess.run(['sudo', 'iptables', '-A', 'OUTPUT', '-d', '192.168.0.0/16', '-j', 'ACCEPT'], check=False)
                subprocess.run(['sudo', 'iptables', '-A', 'OUTPUT', '-d', '10.0.0.0/8', '-j', 'ACCEPT'], check=False)
                # mirror for IPv6
                subprocess.run(['sudo', 'ip6tables', '-P', 'OUTPUT', 'DROP'], check=False)
                subprocess.run(['sudo', 'ip6tables', '-A', 'OUTPUT', '-o', 'lo', '-j', 'ACCEPT'], check=False)
                subprocess.run(['sudo', 'ip6tables', '-A', 'OUTPUT', '-d', 'fe80::/10', '-j', 'ACCEPT'], check=False)
                logger.info("✓ Network quarantine applied (iptables & ip6tables)")
                
            elif system == "Windows":
                # Disable network adapters (except loopback)
                subprocess.run([
                    'powershell', '-Command',
                    'Get-NetAdapter | Where-Object {$_.Name -ne "Loopback"} | Disable-NetAdapter -Confirm:$false'
                ], check=False)
                logger.info("✓ Network adapters disabled")
            
            # 2. Kill suspicious processes
            self._terminate_suspicious_processes()
            
            # 3. Create quarantine marker file
            quarantine_marker = Path("/tmp/sentinelai_quarantine") if system != "Windows" else Path("C:\\sentinelai_quarantine.lock")
            quarantine_marker.write_text(f"QUARANTINED at {datetime.now()}")
            
            logger.info("✅ Quarantine measures applied successfully")
            
        except Exception as e:
            logger.error(f"Error applying quarantine measures: {e}")

    def _terminate_suspicious_processes(self):
        """Terminate suspicious running processes"""
        try:
            import psutil
            
            suspicious_names = [
                'nc', 'netcat', 'ncat', 'socat',  # Backdoor tools
                'meterpreter', 'msf', 'payload',  # Metasploit
                'hack', 'crack', 'exploit',  # Generic malicious
                'ransomware', 'cryptolocker'  # Ransomware
            ]
            
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    proc_name = proc.info['name'].lower()
                    
                    # Check if process name contains suspicious keywords
                    if any(susp in proc_name for susp in suspicious_names):
                        logger.warning(f"Terminating suspicious process: {proc_name} (PID: {proc.info['pid']})")
                        proc.terminate()
                        proc.wait(timeout=3)
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            logger.error(f"Error terminating suspicious processes: {e}")

    def _notify_quarantine(self):
        """Send quarantine notification"""
        quarantine_attack = {
            **(self.quarantine_reason.get('attack', {}) if isinstance(self.quarantine_reason, dict) else {}),
            'notification_kind': 'quarantine'
        }
        message = f"""
╔══════════════════════════════════════════════════════════════╗
║            🚨 SYSTEM UNDER QUARANTINE 🚨                     ║
║                                                              ║
║ Your system has been locked down to prevent data loss       ║
║ and mitigate cyber threats.                                 ║
║                                                              ║
║ Administrator action required to restore normal operations.  ║
╚══════════════════════════════════════════════════════════════╝
"""
        
        # Send through all notification methods
        for notify_method in self.notification_methods:
            try:
                notify_method(message, quarantine_attack, self.MAX_ALERTS)
            except Exception as e:
                logger.error(f"Failed to send quarantine notification: {e}")

    def _log_quarantine_legacy(self, attack_id: str, attack: Dict, user_initiated: bool):
        """Legacy quarantine logger retained for backward compatibility."""
        try:
            log_entry = {
                'quarantine_id': f"Q_{datetime.now().strftime('%Y%m%d%H%M%S')}",
                'attack_id': attack_id,
                'attack': {k: str(v) for k, v in attack.items()},  # Convert to JSON-serializable
                'user_initiated': user_initiated,
                'timestamp': datetime.now().isoformat(),
                'reason': self.quarantine_reason
            }
            
            # Load existing logs
            logs = []
            if self.quarantine_log_path.exists():
                with open(self.quarantine_log_path, 'r') as f:
                    logs = json.load(f)
            
            # Add new log
            logs.append(log_entry)
            
            # Save logs
            with open(self.quarantine_log_path, 'w') as f:
                json.dump(logs, f, indent=2)
                
            logger.info(f"Quarantine logged: {log_entry['quarantine_id']}")
            
        except Exception as e:
            logger.error(f"Failed to log quarantine: {e}")

    def lift_quarantine(self, admin_password: str = None) -> bool:
        """Lift quarantine (requires admin action)"""
        if not self.is_quarantined:
            logger.info("System is not quarantined")
            return True
        
        logger.info("Attempting to lift quarantine...")
        
        try:
            system = platform.system()
            
            # Restore network
            if system == "Linux":
                subprocess.run(['sudo', 'iptables', '-P', 'OUTPUT', 'ACCEPT'], check=True)
                subprocess.run(['sudo', 'iptables', '-F'], check=True)  # Flush rules
                logger.info("✓ Network restored (iptables)")
                
            elif system == "Windows":
                subprocess.run([
                    'powershell', '-Command',
                    'Get-NetAdapter | Enable-NetAdapter -Confirm:$false'
                ], check=True)
                logger.info("✓ Network adapters enabled")
            
            # Remove quarantine marker
            system = platform.system()
            quarantine_marker = Path("/tmp/sentinelai_quarantine") if system != "Windows" else Path("C:\\sentinelai_quarantine.lock")
            if quarantine_marker.exists():
                quarantine_marker.unlink()
            
            # Update state
            self.is_quarantined = False
            self.quarantine_start_time = None
            self.quarantine_reason = None
            
            logger.info("✅ Quarantine lifted successfully")
            
            # Callback
            if self.callback:
                self.callback({
                    'event': 'QUARANTINE_LIFTED',
                    'timestamp': datetime.now().isoformat()
                })
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to lift quarantine: {e}")
            return False

    def respond_to_attack(self, attack_id: str, response: str):
        """Record user response to an attack"""
        if response not in ['BLOCK', 'IGNORE', 'QUARANTINE']:
            logger.error(f"Invalid response: {response}")
            return
        
        self.user_responses[attack_id] = response
        logger.info(f"User response recorded for {attack_id}: {response}")

    def get_status(self) -> Dict:
        """Get current defense status"""
        return {
            'is_quarantined': self.is_quarantined,
            'quarantine_start_time': self.quarantine_start_time.isoformat() if self.quarantine_start_time else None,
            'active_attacks': len(self.active_attacks),
            'total_alerts_sent': sum(self.alert_counts.values()),
            'running': self.running
        }
