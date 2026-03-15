"""
Terminal Activity Monitor Display
Shows real-time activity monitoring summaries on server terminal
"""

import logging
import sys
import threading
import time
from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Deque, Dict

logger = logging.getLogger("TerminalMonitor")


class TerminalActivityMonitor:
    """
    Real-time terminal display for activity monitoring
    Shows short summaries while the server is running
    """
    
    def __init__(self, update_interval: int = 60):
        self.update_interval = update_interval  # Seconds between updates
        self.running = False
        self.monitor_thread = None
        
        # Activity counters
        self.activity_buffer: Deque[Dict] = deque(maxlen=1000)
        self.stats = {
            'websites_monitored': 0,
            'apps_monitored': 0,
            'connections_monitored': 0,
            'scans_performed': 0,
            'attack_events': 0,
            'threats_detected': 0,
            'last_activity_time': None
        }
        
        # Track last printed stats to detect new activity
        self.last_printed_stats = {
            'websites_monitored': 0,
            'apps_monitored': 0,
            'connections_monitored': 0,
            'scans_performed': 0,
            'attack_events': 0,
            'threats_detected': 0
        }
        
        # Recent activities for display
        self.recent_websites: Deque[str] = deque(maxlen=5)
        self.recent_apps: Deque[str] = deque(maxlen=5)
        self.recent_threats: Deque[Dict] = deque(maxlen=5)
        self.recent_attacks: Deque[Dict] = deque(maxlen=5)
        
        self.start_time = datetime.now(timezone.utc)
        
    def start(self):
        """Start terminal monitoring"""
        if self.running:
            return
        
        self.running = True
        self.start_time = datetime.now(timezone.utc)
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        
        logger.info("📺 Terminal activity monitor started")
    
    def stop(self):
        """Stop terminal monitoring"""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        logger.info("📺 Terminal activity monitor stopped")
    
    def log_website_activity(self, domain: str, risk_level: str = 'LOW'):
        """Log website activity"""
        self.stats['websites_monitored'] += 1
        self.stats['last_activity_time'] = datetime.now(timezone.utc)
        
        activity = f"{domain} [{risk_level}]"
        if activity not in self.recent_websites:
            self.recent_websites.append(activity)
    
    def log_app_activity(self, app_name: str, risk_level: str = 'LOW'):
        """Log application activity"""
        self.stats['apps_monitored'] += 1
        self.stats['last_activity_time'] = datetime.now(timezone.utc)
        
        activity = f"{app_name} [{risk_level}]"
        if activity not in self.recent_apps:
            self.recent_apps.append(activity)
    
    def log_connection_activity(self):
        """Log network connection"""
        self.stats['connections_monitored'] += 1
        self.stats['last_activity_time'] = datetime.now(timezone.utc)
    
    def log_scan_activity(self, artifact_type: str, artifact_value: str, verdict: str):
        """Log threat scan activity"""
        self.stats['scans_performed'] += 1
        self.stats['last_activity_time'] = datetime.now(timezone.utc)

        normalized_type = str(artifact_type or '').lower()
        normalized_verdict = str(verdict or '').lower()

        # Suppress noisy single-signal IP suspicious events from terminal threat ticker.
        # These are already handled by deeper corroboration paths.
        if normalized_type == 'ip' and normalized_verdict == 'suspicious':
            return
        
        if normalized_verdict in ['malicious', 'suspicious', 'critical']:
            self.stats['threats_detected'] += 1
            self.recent_threats.append({
                'type': artifact_type,
                'value': artifact_value,
                'verdict': normalized_verdict,
                'time': datetime.now(timezone.utc)
            })

    def log_attack_activity(
        self,
        attack_type: str,
        source: str = 'unknown',
        severity: str = 'medium',
        description: str = '',
    ):
        """Log endpoint/network attack activity for terminal monitoring."""
        self.stats['attack_events'] += 1
        self.stats['last_activity_time'] = datetime.now(timezone.utc)

        normalized_severity = str(severity or 'medium').lower()
        if normalized_severity in ['high', 'critical']:
            self.stats['threats_detected'] += 1

        attack = {
            'type': str(attack_type or 'unknown_attack'),
            'source': str(source or 'unknown'),
            'severity': normalized_severity,
            'description': str(description or ''),
            'time': datetime.now(timezone.utc),
        }
        self.recent_attacks.append(attack)

        readable_type = attack['type'].replace('_', ' ').strip().title()
        W = 68
        VW = W - 15
        title = "─[ ATTACK DETECTED ]"
        print(f"\n┌{title}{'─' * (W - len(title))}┐", flush=True)
        print(f"│  {'Type':<12} {readable_type[:VW]:<{VW}}│")
        print(f"│  {'Source':<12} {attack['source'][:VW]:<{VW}}│")
        print(f"│  {'Severity':<12} {attack['severity'].upper()[:VW]:<{VW}}│")
        if attack['description']:
            print(f"│  {'Detail':<12} {str(attack['description'])[:VW]:<{VW}}│")
        print(f"└{'─' * W}┘", flush=True)
        sys.stdout.flush()
    
    def _monitor_loop(self):
        """Main monitoring loop that displays updates"""
        # Initial banner
        self._print_banner()
        
        last_print_time = time.time()
        
        while self.running:
            try:
                current_time = time.time()
                
                # Only print update if there's new activity since last print
                if current_time - last_print_time >= self.update_interval:
                    if self._has_new_activity():
                        self._print_update()
                        self._update_last_printed_stats()
                    last_print_time = current_time
                
                time.sleep(5)  # Check every 5 seconds
                
            except Exception as e:
                logger.error(f"Error in terminal monitor loop: {e}")
                time.sleep(10)
    
    def _print_banner(self):
        """Print initial banner"""
        W = 68
        print(f"\n┌{'─' * W}┐", flush=True)
        print(f"│  {'SENTINEL-AI  ·  Activity Monitor  ·  Online':<{W - 2}}│")
        print(f"└{'─' * W}┘", flush=True)
        sys.stdout.flush()
    
    def _has_new_activity(self):
        """Check if there's been any new activity since last print"""
        scans_delta = self.stats['scans_performed'] - self.last_printed_stats['scans_performed']
        connections_delta = self.stats['connections_monitored'] - self.last_printed_stats['connections_monitored']

        # Print immediately for security-relevant events.
        if self.stats['attack_events'] != self.last_printed_stats['attack_events']:
            return True
        if self.stats['threats_detected'] != self.last_printed_stats['threats_detected']:
            return True

        # For routine activity, only print on meaningful deltas.
        return (
            self.stats['websites_monitored'] != self.last_printed_stats['websites_monitored'] or
            self.stats['apps_monitored'] != self.last_printed_stats['apps_monitored'] or
            scans_delta >= 10 or
            connections_delta >= 100
        )
    
    def _update_last_printed_stats(self):
        """Update the last printed stats snapshot"""
        self.last_printed_stats = {
            'websites_monitored': self.stats['websites_monitored'],
            'apps_monitored': self.stats['apps_monitored'],
            'connections_monitored': self.stats['connections_monitored'],
            'scans_performed': self.stats['scans_performed'],
            'attack_events': self.stats['attack_events'],
            'threats_detected': self.stats['threats_detected']
        }
    
    def _print_update(self):
        """Print periodic status update"""
        if (self.stats['websites_monitored'] == 0 and
                self.stats['apps_monitored'] == 0 and
                self.stats['scans_performed'] == 0):
            return

        now = datetime.now(timezone.utc)
        uptime_str = str(now - self.start_time).split('.')[0]

        last_str = "–"
        if self.stats['last_activity_time']:
            delta = (now - self.stats['last_activity_time']).total_seconds()
            if delta < 60:
                last_str = f"{int(delta)}s ago"
            elif delta < 3600:
                last_str = f"{int(delta / 60)}m ago"
            else:
                last_str = f"{int(delta / 3600)}h ago"

        delta_scans = max(0, self.stats['scans_performed'] - self.last_printed_stats['scans_performed'])

        latest = ""
        if self.recent_attacks:
            a = self.recent_attacks[-1]
            latest = f"  ·  {a['type'].replace('_', ' ').title()} / {a['severity'].upper()}"
        elif self.recent_threats:
            t = self.recent_threats[-1]
            latest = f"  ·  {t['type'].upper()} / {t['verdict'].upper()}"
        elif self.recent_websites:
            site = self.recent_websites[-1].split(' [')[0]
            latest = f"  ·  {site}"

        status_parts = [
            f"◈ up {uptime_str}",
            f"scans {self.stats['scans_performed']} (+{delta_scans})",
        ]
        if self.stats['threats_detected'] > 0:
            status_parts.append(f"threats {self.stats['threats_detected']}")
        if self.stats['attack_events'] > 0:
            status_parts.append(f"attacks {self.stats['attack_events']}")
        status_parts.append(f"Δ{last_str}")

        status = " · ".join(status_parts)
        if latest:
            status = f"{status}{latest}"
        print(status, flush=True)
        sys.stdout.flush()
    
    def print_summary(self):
        """Print final summary"""
        duration = datetime.now(timezone.utc) - self.start_time
        duration_str = str(duration).split('.')[0]
        threat_rate = (
            (self.stats['threats_detected'] / self.stats['scans_performed']) * 100
            if self.stats['scans_performed'] > 0 else 0.0
        )
        W = 68
        VW = W - 15
        title = "─[ SESSION SUMMARY ]"
        print(f"\n┌{title}{'─' * (W - len(title))}┐", flush=True)
        print(f"│  {'Duration':<12} {duration_str[:VW]:<{VW}}│")
        print(f"│  {'Websites':<12} {self.stats['websites_monitored']:<{VW}}│")
        print(f"│  {'Scans':<12} {self.stats['scans_performed']:<{VW}}│")
        print(f"│  {'Threats':<12} {self.stats['threats_detected']:<{VW}}│")
        print(f"│  {'Attacks':<12} {self.stats['attack_events']:<{VW}}│")
        rate_str = f"{threat_rate:.1f}%"
        print(f"│  {'Threat Rate':<12} {rate_str[:VW]:<{VW}}│")
        print(f"└{'─' * W}┘", flush=True)
        sys.stdout.flush()


# Global instance (quiet-by-default cadence)
terminal_monitor = TerminalActivityMonitor(update_interval=60)
